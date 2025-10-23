// SPDX-License-Identifier: GPL-2.0
/*
 * Deprecated module: mtd_pprf_rs
 * This file is intentionally a no-op to avoid build surprises. The
 * research path now uses drivers/mtd/rs_loader.c instead.
 */
#include <linux/module.h>

static int __init mtd_pprf_rs_init(void)
{
	pr_info("mtd_pprf_rs: deprecated; no-op\n");
	return 0;
}
module_init(mtd_pprf_rs_init);

static void __exit mtd_pprf_rs_exit(void)
{
}
module_exit(mtd_pprf_rs_exit);

MODULE_DESCRIPTION("Deprecated PPRF RS module (no-op)");
MODULE_LICENSE("GPL v2");
// SPDX-License-Identifier: GPL-2.0
/*
 * mtd_pprf_rs.c - Read/initialize PPRF RS in the first three PEBs of SPI-NAND.
 * Target: Winbond W25N01GV (and compatible) SPI-NAND.
 *
 * This module hooks into MTD add/remove notifications. On add:
 * - Identify the primary SPI-NAND device (heuristics + optional module param).
 * - Attempt to read RS from the first three eraseblocks (logical 0..2 on the
 *   master MTD). Use majority-vote and CRC to pick the best.
 * - If none present, create an RS seeded from RNG and write it to first 3 PEBs.
 *
 * RS는 (idx,key) 노드들의 배열로 구성됩니다. 초기화 시 루트 노드(idx=0)를
 * 하나 생성해 기록하고, 상위 레이어가 필요 시 노드를 확장/갱신할 수 있습니다.
 */

#include <linux/crc32.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/pprf_rs.h>

#define DRV_NAME "mtd_pprf_rs"

/* Magic 'PRRS' */
#define PPRF_RS_MAGIC 0x50525253U
#define PPRF_RS_VERSION 1
#define PPRF_RS_COPIES 3

struct pprf_rs_hdr {
	__le32 magic;
	__le16 version;
	__le16 _rsvd;
	__le32 size; /* total bytes including header + nodes */
	__le32 node_count; /* number of nodes following header */
	__le32 crc; /* crc32 over [magic..node_count + nodes...] */
} __packed;

/* In-memory state */
static struct {
	bool ready;
	struct pprf_rs_node nodes[8];
	unsigned int nodes_cnt;
	struct mtd_info *mtd;
	u32 peb_size; /* erasesize */
} g_rs;

/* Optional module parameters */
static char target_name[64];
module_param_string(target_name, target_name, sizeof(target_name), 0644);
MODULE_PARM_DESC(target_name, "Name of MTD device to probe (optional)");

static bool force_init;
module_param(force_init, bool, 0644);
MODULE_PARM_DESC(force_init, "Force re-initialization of RS on add");

/* Exported API */
bool pprf_rs_is_ready(void)
{
	return READ_ONCE(g_rs.ready);
}
EXPORT_SYMBOL_GPL(pprf_rs_is_ready);

int pprf_rs_get_nodes(struct pprf_rs_node *out, size_t max_nodes)
{
	if (!g_rs.ready)
		return -ENODATA;
	if (!out || !max_nodes)
// SPDX-License-Identifier: GPL-2.0
/* Deprecated: this module is now a no-op. Kept only to avoid build surprises. */
#include <linux/module.h>

		static int __init mtd_pprf_rs_init(void)
		{
			pr_info("mtd_pprf_rs: deprecated; no-op\n");
			return 0;
		}
	module_init(mtd_pprf_rs_init);

	static void __exit mtd_pprf_rs_exit(void)
	{
	}
	module_exit(mtd_pprf_rs_exit);

	MODULE_LICENSE("GPL v2");
	MODULE_DESCRIPTION("Deprecated PPRF RS module (no-op)");
	size_t retlen = 0;
	u64 offs = (u64)peb_index * mtd->erasesize;
	int ret;

	if (len > mtd->erasesize)
		len = mtd->erasesize;

	{
		struct erase_info instr;
		memset(&instr, 0, sizeof(instr));
		instr.addr = offs;
		instr.len = mtd->erasesize;
		ret = mtd_erase(mtd, &instr);
	}
	if (ret)
		return ret;
	return mtd_write(mtd, offs, len, &retlen, buf);
}

static bool rs_valid(struct pprf_rs_hdr *hdr)
{
	u32 got;
	if (le32_to_cpu(hdr->magic) != PPRF_RS_MAGIC)
		return false;
	if (le16_to_cpu(hdr->version) != PPRF_RS_VERSION)
		return false;
	if (le32_to_cpu(hdr->size) < sizeof(*hdr))
		return false;
	got = le32_to_cpu(hdr->crc);
	hdr->crc = 0;
	if (crc32_le(~0U, (u8 *)hdr, le32_to_cpu(hdr->size)) != got) {
		hdr->crc = cpu_to_le32(got);
		return false;
	}
	hdr->crc = cpu_to_le32(got);
	return true;
}

static bool is_all_ff(const void *buf, size_t len)
{
	const u8 *p = buf;
	size_t i;
	for (i = 0; i < len; i++)
		if (p[i] != 0xFF)
			return false;
	return true;
}

static void rs_fill_hdr(struct pprf_rs_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = cpu_to_le32(PPRF_RS_MAGIC);
	hdr->version = cpu_to_le16(PPRF_RS_VERSION);
	hdr->node_count = cpu_to_le32(1);
	hdr->size = cpu_to_le32(sizeof(*hdr) + sizeof(struct pprf_rs_node));
	hdr->crc = 0;
	/* CRC will be computed after nodes are appended into a contiguous buffer */
}

static int rs_try_read_three(struct mtd_info *mtd, struct pprf_rs_hdr *out)
{
	void *cand;
	struct pprf_rs_hdr *hdr;
	int i, valid = 0;
	size_t maxsz = sizeof(*out) +
		       sizeof(struct pprf_rs_node) * ARRAY_SIZE(g_rs.nodes);
	cand = kzalloc(maxsz * PPRF_RS_COPIES, GFP_KERNEL);
	if (!cand)
		return -ENOMEM;
	for (i = 0; i < PPRF_RS_COPIES; i++) {
		int ret;
		loff_t offs = (loff_t)i * mtd->erasesize;
		if (mtd_can_have_bb(mtd) && mtd_block_isbad(mtd, offs))
			continue;
		hdr = (struct pprf_rs_hdr *)((u8 *)cand + i * maxsz);
		memset(hdr, 0xFF, maxsz);
		ret = read_peb(mtd, i, hdr, maxsz);
		if (ret == 0 || mtd_is_bitflip(ret)) {
			if (rs_valid(hdr))
				valid++;
		}
	}
	if (!valid) {
		kfree(cand);
		return -ENODATA;
	}
	/* Pick the first valid (could be extended to majority/most recent) */
	for (i = 0; i < PPRF_RS_COPIES; i++) {
		hdr = (struct pprf_rs_hdr *)((u8 *)cand + i * maxsz);
		if (rs_valid(hdr)) {
			size_t sz = le32_to_cpu(hdr->size);
			memcpy(out, hdr, min(sz, maxsz));
			break;
		}
	}
	kfree(cand);
	return 0;
}

static int rs_write_three(struct mtd_info *mtd, const void *buf, size_t len)
{
	int i, ret = 0;
	for (i = 0; i < PPRF_RS_COPIES; i++) {
		loff_t offs = (loff_t)i * mtd->erasesize;
		if (mtd_can_have_bb(mtd) && mtd_block_isbad(mtd, offs))
			continue;
		ret = write_peb(mtd, i, buf, len);
		if (ret)
			return ret;
	}
	return 0;
}

static bool is_target_spinand(struct mtd_info *mtd)
{
	/* Heuristic: SPI-NAND type and optionally name match */
	if (!mtd_type_is_nand(mtd))
		return false;
	if (strlen(target_name))
		return sysfs_streq(mtd->name, target_name);
	/* If no name provided, accept the first NAND we see. */
	return true;
}

static void pprf_rs_on_add(struct mtd_info *mtd)
{
	struct pprf_rs_hdr hdr;
	int ret;

	if (g_rs.ready)
		return; /* already set up */
	if (!is_target_spinand(mtd))
		return;

	g_rs.mtd = mtd_get_master(mtd);
	g_rs.peb_size = g_rs.mtd->erasesize;

	if (!force_init) {
		/* Try read into a temp buffer and deserialize nodes */
		void *tmp = NULL;
		size_t maxsz = sizeof(hdr) + sizeof(struct pprf_rs_node) *
						     ARRAY_SIZE(g_rs.nodes);
		tmp = kzalloc(maxsz, GFP_KERNEL);
		if (!tmp)
			return;
		ret = rs_try_read_three(g_rs.mtd, tmp);
		if (!ret) {
			struct pprf_rs_hdr *rh = tmp;
			u32 cnt = le32_to_cpu(rh->node_count);
			u8 *np = (u8 *)tmp + sizeof(*rh);
			size_t i, avail = min_t(u32, cnt,
						(u32)ARRAY_SIZE(g_rs.nodes));
			for (i = 0; i < avail; i++)
				memcpy(&g_rs.nodes[i],
				       np + i * sizeof(struct pprf_rs_node),
				       sizeof(struct pprf_rs_node));
			g_rs.nodes_cnt = avail;
			WRITE_ONCE(g_rs.ready, true);
			pr_info(DRV_NAME
				": RS loaded from PEBs 0-2 on %s (nodes=%u)\n",
				g_rs.mtd->name, cnt);
			kfree(tmp);
			return;
		}
		kfree(tmp);
	}

	/* Create fresh RS */
	/* Only initialize if blocks appear blank (avoid corrupting existing data). */
	if (!force_init) {
		struct pprf_rs_hdr tmp;
		int blanks = 0;
		for (ret = 0; ret < PPRF_RS_COPIES; ret++) {
			if (mtd_can_have_bb(g_rs.mtd) &&
			    mtd_block_isbad(g_rs.mtd,
					    (loff_t)ret * g_rs.mtd->erasesize))
				continue;
			if (read_peb(g_rs.mtd, ret, &tmp, sizeof(tmp)) == 0 &&
			    is_all_ff(&tmp, sizeof(tmp)))
				blanks++;
		}
		if (blanks == 0) {
			pr_warn(DRV_NAME
				": RS not found and first PEBs are not blank; skip init on %s (set force_init=1 to override)\n",
				g_rs.mtd->name);
			return;
		}
	}

	/* Build a minimal RS: header + 1 root node (idx=0, random key) */
	rs_fill_hdr(&hdr);
	{
		size_t totsz = le32_to_cpu(hdr.size);
		void *buf = kzalloc(totsz, GFP_KERNEL);
		if (!buf)
			return;
		memcpy(buf, &hdr, sizeof(hdr));
		struct pprf_rs_node *nodes =
			(struct pprf_rs_node *)((u8 *)buf + sizeof(hdr));
		nodes[0].idx = cpu_to_le32(0);
		get_random_bytes(nodes[0].key, sizeof(nodes[0].key));
		/* Compute CRC over full size */
		((struct pprf_rs_hdr *)buf)->crc = 0;
		((struct pprf_rs_hdr *)buf)->crc =
			cpu_to_le32(crc32_le(~0U, buf, totsz));
		ret = rs_write_three(g_rs.mtd, buf, totsz);
		if (ret) {
			pr_err(DRV_NAME ": failed to initialize RS on %s: %d\n",
			       g_rs.mtd->name, ret);
			kfree(buf);
			return;
		}
		/* Cache in memory */
		g_rs.nodes[0] = nodes[0];
		g_rs.nodes_cnt = 1;
		kfree(buf);
	}
	if (ret) {
		pr_err(DRV_NAME ": failed to initialize RS on %s: %d\n",
		       g_rs.mtd->name, ret);
		return;
	}
	WRITE_ONCE(g_rs.ready, true);
	pr_warn(DRV_NAME ": RS initialized on %s (PEBs 0-2) nodes=1\n",
		g_rs.mtd->name);
}

static void pprf_rs_on_remove(struct mtd_info *mtd)
{
	if (g_rs.mtd == mtd || g_rs.mtd == mtd_get_master(mtd)) {
		WRITE_ONCE(g_rs.ready, false);
		g_rs.mtd = NULL;
		g_rs.nodes_cnt = 0;
	}
}

static struct mtd_notifier pprf_rs_notifier = {
	.add = pprf_rs_on_add,
	.remove = pprf_rs_on_remove,
};

static int __init mtd_pprf_rs_init(void)
{
	register_mtd_user(&pprf_rs_notifier);
	pr_info(DRV_NAME ": initialized\n");
	return 0;
}
module_init(mtd_pprf_rs_init);

static void __exit mtd_pprf_rs_exit(void)
{
	unregister_mtd_user(&pprf_rs_notifier);
}
module_exit(mtd_pprf_rs_exit);

MODULE_DESCRIPTION(
	"PPRF RS loader/initializer for first three PEBs on SPI-NAND");
MODULE_AUTHOR("GitHub Copilot");
MODULE_LICENSE("GPL v2");
