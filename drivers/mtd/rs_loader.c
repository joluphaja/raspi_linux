// SPDX-License-Identifier: GPL-2.0
// Minimal RS loader: read-only RS from MTD partition named "rs" at boot.

#define pr_fmt(fmt) "rs_loader: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/workqueue.h> /* added */
#include <linux/atomic.h>

#include <linux/rs_loader.h>

/* Module parameter: domain bit length m (not stored on disk) */
static ushort rs_dom_m;
module_param_named(m, rs_dom_m, ushort, 0444);
MODULE_PARM_DESC(m, "Domain bit length m for RS (not stored on disk)");

static struct rs_state *g_rs;

#define RS_SEED_LEN 16

static inline u16 ceil_div_u16(u16 a, u16 b)
{
	return (a + b - 1) / b;
}

/* Optional auto-create parameters for 'rs' partition (with safe defaults) */
static char *rs_parent = "mtd0"; /* research-default parent */
module_param(rs_parent, charp, 0644);
MODULE_PARM_DESC(rs_parent,
		 "Parent MTD device name to create 'rs' on when missing");

static unsigned long long rs_offset;
module_param_named(rs_offset, rs_offset, ullong, 0644);
MODULE_PARM_DESC(rs_offset, "Offset (bytes) for 'rs' partition on parent MTD");

static unsigned long long rs_size; /* 0 => use one eraseblock */
module_param_named(rs_size, rs_size, ullong, 0644);
MODULE_PARM_DESC(rs_size, "Size (bytes) for 'rs' partition on parent MTD");

/* NEW: wait until this MTD device is registered (e.g., "spi0.0") */
static char *rs_wait_for = "spi0.0";
module_param(rs_wait_for, charp, 0644);
MODULE_PARM_DESC(
	rs_wait_for,
	"MTD device name to wait for before loading RS (e.g., \"spi0.0\")");

static bool is_all_ff(const u8 *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		if (buf[i] != 0xFF)
			return false;
	return true;
}

static int rs_write_initial(struct mtd_info *mtd)
{
	/* Minimal RS: n=1; entry: d=0; no prefix; seed=16 bytes */
	u8 buf[4 + 2 + RS_SEED_LEN];
	struct erase_info instr;
	size_t retlen = 0;
	int ret;

	if (sizeof(buf) > mtd->size)
		return -ENOSPC;

	buf[0] = 1;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0; /* n = 1 (LE) */
	buf[4] = 0;
	buf[5] = 0; /* d = 0 (LE) */
	get_random_bytes(&buf[6], RS_SEED_LEN);

	memset(&instr, 0, sizeof(instr));
	instr.addr = 0;
	instr.len = mtd->erasesize ? mtd->erasesize : (u64)sizeof(buf);
	if (!(mtd->flags & MTD_NO_ERASE)) {
		ret = mtd_erase(mtd, &instr);
		if (ret && ret != -EOPNOTSUPP)
			return ret;
	}

	ret = mtd_write(mtd, 0, sizeof(buf), &retlen, buf);
	if (ret)
		return ret;
	return (retlen == sizeof(buf)) ? 0 : -EIO;
}

static int rs_create_partition_and_init(void)
{
	struct mtd_info *parent;
	int ret;

	if (!rs_parent)
		return -ENODEV;

	parent = get_mtd_device_nm(rs_parent);
	if (IS_ERR(parent))
		return PTR_ERR(parent);

	/* Default rs_size to one eraseblock if not provided */
	if (!rs_size) {
		if (parent->erasesize)
			rs_size = parent->erasesize;
		else
			rs_size = 64 * 1024; /* conservative fallback */
	}

	/* Alignment checks */
	if (!(parent->flags & MTD_NO_ERASE) && parent->erasesize) {
		if ((rs_offset % parent->erasesize) ||
		    (rs_size % parent->erasesize)) {
			pr_warn("'rs' partition not erase-aligned; refusing to create\n");
			put_mtd_device(parent);
			return -EINVAL;
		}
	}

	ret = mtd_add_partition(parent, "rs", rs_offset, rs_size);
	if (ret < 0) {
		pr_warn("failed to add 'rs' partition: %d\n", ret);
		put_mtd_device(parent);
		return ret;
	}
	put_mtd_device(parent);

	/* Open the new partition and initialize */
	{
		struct mtd_info *mtd = get_mtd_device_nm("rs");
		if (IS_ERR(mtd))
			return PTR_ERR(mtd);
		ret = rs_write_initial(mtd);
		put_mtd_device(mtd);
		return ret;
	}
}

static int mtd_read_exact(struct mtd_info *mtd, loff_t from, void *buf,
			  size_t len)
{
	size_t retlen = 0;
	int ret = mtd_read(mtd, from, len, &retlen, buf);
	if (ret && !mtd_is_bitflip(ret))
		return ret;
	return (retlen == len) ? 0 : -EIO;
}

static bool prefix_is_prefix_of(const struct rs_entry *a,
				const struct rs_entry *b)
{
	/* Return true if prefix a is a proper prefix of prefix b (MSB-first) */
	if (a->d >= b->d)
		return false; /* proper prefix requires a shorter than b */

	if (a->d == 0)
		return true; /* empty is prefix of any non-empty */

	u16 full = a->d / 8;
	u16 rem = a->d % 8;

	if (full) {
		if (memcmp(a->prefix, b->prefix, full) != 0)
			return false;
	}
	if (rem) {
		u8 mask = 0xFFu << (8 - rem);
		if ((a->prefix[full] & mask) != (b->prefix[full] & mask))
			return false;
	}
	return true;
}

static int rs_loader_do_load(void)
{
	struct mtd_info *mtd;
	int ret = 0;
	u32 n = 0;
	u64 pos = 0; /* current offset */
	u8 hdrbuf[4];
	char fail[80] = "";
	u16 *dtab = NULL;
	struct rs_state *rs = NULL;
	struct rs_entry *ents = NULL;
	u32 i, j;

	if (!rs_dom_m) {
		/* Research-default domain length if not supplied */
		rs_dom_m = 128;
		pr_info("m not provided; defaulting to %u\n", rs_dom_m);
	}

	mtd = get_mtd_device_nm("rs");
	if (IS_ERR(mtd)) {
		/* Try to create and initialize if params provided */
		ret = rs_create_partition_and_init();
		if (ret) {
			strscpy(fail, "partition 'rs' not found", sizeof(fail));
			goto fail_out;
		}
		mtd = get_mtd_device_nm("rs");
		if (IS_ERR(mtd)) {
			strscpy(fail, "partition 'rs' open failed",
				sizeof(fail));
			ret = PTR_ERR(mtd);
			goto fail_out;
		}
	}

	/* Read header: 4-byte little-endian n */
	pos = 0;
	ret = mtd_read_exact(mtd, pos, hdrbuf, sizeof(hdrbuf));
	if (ret) {
		u8 probe[32];
		/* If blank, initialize minimal RS */
		if (!mtd_read_exact(mtd, 0, probe, sizeof(probe)) &&
		    is_all_ff(probe, sizeof(probe))) {
			ret = rs_write_initial(mtd);
			if (ret) {
				strscpy(fail, "init rs failed", sizeof(fail));
				goto put_mtd_and_fail;
			}
			/* retry header */
			ret = mtd_read_exact(mtd, pos, hdrbuf, sizeof(hdrbuf));
			if (ret) {
				strscpy(fail, "read header failed",
					sizeof(fail));
				goto put_mtd_and_fail;
			}
		} else {
			strscpy(fail, "read header failed", sizeof(fail));
			goto put_mtd_and_fail;
		}
	}
	n = (u32)hdrbuf[0] | ((u32)hdrbuf[1] << 8) | ((u32)hdrbuf[2] << 16) |
	    ((u32)hdrbuf[3] << 24);
	pos += 4;

	if (n == 0) {
		strscpy(fail, "n=0", sizeof(fail));
		ret = -EINVAL;
		goto put_mtd_and_fail;
	}

	/* First pass: read all d to compute total size and validate limits */
	dtab = kmalloc_array(n, sizeof(*dtab), GFP_KERNEL);
	if (!dtab) {
		strscpy(fail, "oom dtab", sizeof(fail));
		ret = -ENOMEM;
		goto put_mtd_and_fail;
	}

	for (i = 0; i < n; i++) {
		u8 dbuf[2];
		u16 d;
		if (pos + 2 > mtd->size) {
			ret = -EINVAL;
			strscpy(fail, "size over d", sizeof(fail));
			goto put_mtd_and_fail;
		}
		ret = mtd_read_exact(mtd, pos, dbuf, sizeof(dbuf));
		if (ret) {
			strscpy(fail, "read d failed", sizeof(fail));
			goto put_mtd_and_fail;
		}
		d = (u16)dbuf[0] | ((u16)dbuf[1] << 8);
		if (d > rs_dom_m) {
			ret = -EINVAL;
			strscpy(fail, "d>m", sizeof(fail));
			goto put_mtd_and_fail;
		}
		dtab[i] = d;
		pos += 2;
		{
			u16 k = ceil_div_u16(d, 8);
			u64 need = (u64)k + RS_SEED_LEN; /* prefix + seed */
			if (pos + need > mtd->size) {
				ret = -EINVAL;
				strscpy(fail, "size over body", sizeof(fail));
				goto put_mtd_and_fail;
			}
			pos += need;
		}
	}

	/* Allocate state */
	rs = kzalloc(sizeof(*rs), GFP_KERNEL);
	if (!rs) {
		ret = -ENOMEM;
		strscpy(fail, "oom state", sizeof(fail));
		goto put_mtd_and_fail;
	}
	rs->n = n;
	rs->m = rs_dom_m;
	ents = kcalloc(n, sizeof(*ents), GFP_KERNEL);
	if (!ents) {
		ret = -ENOMEM;
		strscpy(fail, "oom entries", sizeof(fail));
		goto put_mtd_and_fail;
	}
	rs->entries = ents;

	/* Second pass: read entries */
	pos = 4;
	for (i = 0; i < n; i++) {
		u8 dbuf[2];
		u16 d = dtab[i];
		u16 k = ceil_div_u16(d, 8);
		u8 last_mask = 0;

		ret = mtd_read_exact(mtd, pos, dbuf, sizeof(dbuf));
		if (ret) {
			strscpy(fail, "read d2 failed", sizeof(fail));
			goto put_mtd_and_fail;
		}
		if ((((u16)dbuf[0] | ((u16)dbuf[1] << 8)) != d)) {
			ret = -EINVAL;
			strscpy(fail, "d mismatch", sizeof(fail));
			goto put_mtd_and_fail;
		}
		pos += 2;

		ents[i].d = d;
		if (k) {
			ents[i].prefix = kmalloc(k, GFP_KERNEL);
			if (!ents[i].prefix) {
				ret = -ENOMEM;
				strscpy(fail, "oom prefix", sizeof(fail));
				goto put_mtd_and_fail;
			}
			ret = mtd_read_exact(mtd, pos, ents[i].prefix, k);
			if (ret) {
				strscpy(fail, "read prefix failed",
					sizeof(fail));
				goto put_mtd_and_fail;
			}
			pos += k;
		} else {
			ents[i].prefix = NULL;
		}

		/* bit hygiene: unused low bits of last prefix byte must be 0 */
		if (k) {
			u16 rem = d % 8;
			if (rem) {
				last_mask = (u8)((1u << (8 - rem)) - 1u);
				if ((ents[i].prefix[k - 1] & last_mask) != 0) {
					ret = -EINVAL;
					strscpy(fail, "dirty low bits",
						sizeof(fail));
					goto put_mtd_and_fail;
				}
			}
		}

		ret = mtd_read_exact(mtd, pos, ents[i].seed, RS_SEED_LEN);
		if (ret) {
			strscpy(fail, "read seed failed", sizeof(fail));
			goto put_mtd_and_fail;
		}
		pos += RS_SEED_LEN;
	}

	/* prefix-free validation */
	for (i = 0; i < n; i++) {
		for (j = i + 1; j < n; j++) {
			if (prefix_is_prefix_of(&ents[i], &ents[j]) ||
			    prefix_is_prefix_of(&ents[j], &ents[i])) {
				ret = -EINVAL;
				strscpy(fail, "not prefix-free", sizeof(fail));
				goto put_mtd_and_fail;
			}
		}
	}

	/* Success */
	g_rs = rs;
	pr_info("loaded %u entries (m = %u)\n", rs->n, rs->m);
	kfree(dtab);
	put_mtd_device(mtd);
	return 0;

put_mtd_and_fail:
	if (!IS_ERR(mtd))
		put_mtd_device(mtd);
fail_out:
	if (fail[0])
		pr_warn("%s\n", fail);

	if (ents) {
		for (i = 0; i < n; i++)
			kfree(ents[i].prefix);
	}
	kfree(ents);
	kfree(rs);
	kfree(dtab);
	return ret;
}

const struct rs_state *rs_get_state(void)
{
	return g_rs;
}
EXPORT_SYMBOL_GPL(rs_get_state);

/* --------- NEW: MTD notifier + work to defer load until spi0.0 --------- */

static void rs_load_workfn(struct work_struct *work);
static DECLARE_WORK(rs_load_work, rs_load_workfn);
static atomic_t rs_load_once = ATOMIC_INIT(0);

static void rs_load_workfn(struct work_struct *work)
{
	int ret;

	if (READ_ONCE(g_rs)) {
		pr_info("already loaded; skipping\n");
		return;
	}

	ret = rs_loader_do_load();
	if (ret)
		pr_warn("load failed: %d\n", ret);
}

static void rs_mtd_add(struct mtd_info *mtd)
{
	if (!rs_wait_for || !*rs_wait_for)
		return;

	if (strcmp(mtd->name, rs_wait_for) == 0) {
		if (atomic_xchg(&rs_load_once, 1) == 0) {
			pr_info("saw MTD '%s'; scheduling RS load\n",
				mtd->name);
			schedule_work(&rs_load_work);
		}
	}
}

static void rs_mtd_remove(struct mtd_info *mtd)
{
	/* nothing */
}

static struct mtd_notifier rs_mtd_nb = {
	.add = rs_mtd_add,
	.remove = rs_mtd_remove,
};

/* ---------------------------------------------------------------------- */

static int __init rs_loader_init(void)
{
	/* Register MTD notifier to wait for the parent device (e.g., spi0.0) */
	register_mtd_user(&rs_mtd_nb);

	/*
     * NOTE: register_mtd_user() will invoke .add() for all already
     * registered devices too, so we don't need to probe explicitly here.
     */
	return 0;
}
module_init(rs_loader_init);

#ifdef MODULE
static void __exit rs_loader_exit(void)
{
	u32 i;
	struct rs_state *rs = g_rs;

	unregister_mtd_user(&rs_mtd_nb);
	cancel_work_sync(&rs_load_work);

	if (!rs)
		return;
	if (rs->entries) {
		for (i = 0; i < rs->n; i++)
			kfree(rs->entries[i].prefix);
		kfree(rs->entries);
	}
	kfree(rs);
	g_rs = NULL;
}
module_exit(rs_loader_exit);
#endif

MODULE_DESCRIPTION(
	"Minimal RS loader from MTD partition 'rs' (deferred until spi0.0)");
MODULE_LICENSE("GPL v2");