// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/rawnand.h>
#include <linux/crc32.h>
#include <crypto/hash.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <uapi/linux/nand_kv.h>

#define SUPER_MAGIC 0x524E414E44534E44ull
#define SUPER_VERSION 1
#define SUPER_BYTES 4096 /* write/read full 4KiB (2 * 2KiB pages) */
#define SUPER_SCAN_TRIES 16 /* scan first N eraseblocks for super */

#define NKV_TAG "nand_kv: "

struct super_hdr {
	__le64 magic;
	__le32 version;
	__le32 peb_size;
	__le64 total_size;
	__le32 rs_pebs;
	__le64 rs_region_off;
	__le64 keytab_off;
	__le64 keytab_bytes;
	__le64 data_off;
	__le32 keyblk_count;
	__le32 inodes;
	__le64 tag_counter;
	/* Make super exactly 4096 bytes (2 NAND pages on 2KiB-page devices) */
	u8 reserved[4096 - (8 + 4 + 4 + 8 + 4 + 8 + 8 + 8 + 8 + 4 + 4 +
			    8)]; /* = 4020 */
} __packed;

struct data_hdr {
	__le32 inode;
	__le32 len;
	__le64 nonce; /* 0 => plaintext */
} __packed;

struct rs_mirror {
	__le64 magic;
	__le64 gen;
	u8 RS[32];
	__le64 last_tau;
	__le32 crc;
	u8 pad[4096 - 8 - 8 - 32 - 8 - 4];
} __packed;

#define RS_MAGIC cpu_to_le64(0x52534D4952524F52ull)

static struct mtd_info *kv_mtd;
static struct super_hdr g_super;
static bool g_super_ok;
static loff_t g_super_off; /* where the super actually resides (good EB) */
static bool g_rs_ok;
static u8 g_RS[32];

static int mtd_read_pagewise(loff_t from, u8 *dst, size_t len)
{
	size_t ws = kv_mtd->writesize; /* e.g., 2048 */
	loff_t cur = from;
	size_t left = len;

	while (left) {
		loff_t page_base = round_down(cur, (loff_t)ws);
		size_t page_off = (size_t)(cur - page_base);
		size_t take = min(ws - page_off, left);

		u8 tmp[4096]; /* 충분히 큰 스택 버퍼 (ws<=4096 가정); 더 안전히 하려면 kmalloc(ws) 사용 */
		size_t retlen = 0;
		int err;

		/* 한 페이지 통째로 읽어서 그 중 일부분만 복사 */
		err = mtd_read(kv_mtd, page_base, ws, &retlen, tmp);
		if (err && !mtd_is_bitflip(err))
			return err;
		if (retlen != ws)
			return -EIO;

		memcpy(dst, tmp + page_off, take);
		dst += take;
		cur += take;
		left -= take;
	}
	return 0;
}

static int mtd_read_exact(loff_t from, void *buf, size_t len)
{
	size_t retlen = 0;
	int err = mtd_read(kv_mtd, from, len, &retlen, buf);
	if (err && !mtd_is_bitflip(err))
		return err;
	if (retlen != len)
		return -EIO;
	return 0;
}

static int mtd_write_exact(loff_t to, const void *buf, size_t len)
{
	size_t retlen = 0;
	int err = mtd_write(kv_mtd, to, len, &retlen, buf);
	if (err)
		return err;
	if (retlen != len)
		return -EIO;
	return 0;
}

static int erase_range(loff_t from, size_t len)
{
	struct erase_info ei = { 0 };
	size_t es = kv_mtd->erasesize;
	loff_t start = round_down(from, es);
	loff_t end = round_up(from + len, es);
	int err;

	ei.addr = start;
	ei.len = end - start;
	pr_info(NKV_TAG "erase addr=0x%llx len=0x%llx (es=0x%zx)\n",
		(unsigned long long)ei.addr, (unsigned long long)ei.len, es);
	err = mtd_erase(kv_mtd, &ei);
	if (err)
		pr_err(NKV_TAG "erase failed err=%d at 0x%llx len=0x%llx\n",
		       err, (unsigned long long)ei.addr,
		       (unsigned long long)ei.len);
	return err;
}

static loff_t find_good_eb(loff_t from)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = round_down(from, es);
	while (off < kv_mtd->size) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad; /* propagate error */
		if (!bad)
			return off;
		off += es;
	}
	return -ENOSPC;
}

static loff_t advance_good_ebs(loff_t from, u32 need_good)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = round_down(from, es);

	while (need_good) {
		int bad;
		if (off >= kv_mtd->size)
			return -ENOSPC;
		bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad)
			need_good--;
		off += es;
	}
	return off;
}

static int kv_read_super(void)
{
	int err, tries = SUPER_SCAN_TRIES;
	loff_t off = 0; /* scan from 0 */
	if (!kv_mtd)
		return -ENODEV;
	pr_info(NKV_TAG "scan super: tries=%d es=0x%x\n", tries,
		kv_mtd->erasesize);
	while (tries--) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			err = mtd_read_exact(off, &g_super, SUPER_BYTES);
			if (!err) {
				if (le64_to_cpu(g_super.magic) == SUPER_MAGIC &&
				    le32_to_cpu(g_super.version) ==
					    SUPER_VERSION) {
					pr_info(NKV_TAG
						"found super at 0x%llx (ver=%u)\n",
						(unsigned long long)off,
						le32_to_cpu(g_super.version));
					g_super_ok = true;
					g_super_off = off;
					return 0;
				}
				pr_warn(NKV_TAG
					"no magic at 0x%llx (magic=0x%llx ver=%u)\n",
					(unsigned long long)off,
					(unsigned long long)le64_to_cpu(
						g_super.magic),
					le32_to_cpu(g_super.version));
			} else {
				if (err == -EBADMSG) {
					pr_warn(NKV_TAG
						"EBADMSG reading super at 0x%llx, skip\n",
						(unsigned long long)off);
				} else {
					pr_err(NKV_TAG
					       "read err=%d at 0x%llx\n",
					       err, (unsigned long long)off);
				}
				/* continue scanning */
			}
		}
		off += kv_mtd->erasesize;
	}
	return -ENOENT;
}

/* window helpers are defined after module params */

/* ==== SHA-256 helpers (kernel shash) ==== */

static int sha256_bytes2(struct crypto_shash *tfm, const u8 *a, size_t alen,
			 const u8 *b, size_t blen, u8 out[32])
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;
	desc->tfm = tfm;
	err = crypto_shash_init(desc);
	if (err)
		return err;
	if (a && alen) {
		err = crypto_shash_update(desc, a, alen);
		if (err)
			return err;
	}
	if (b && blen) {
		err = crypto_shash_update(desc, b, blen);
		if (err)
			return err;
	}
	err = crypto_shash_final(desc, out);
	return err;
}

static int prf_k_tau_tfm(struct crypto_shash *tfm, const u8 RS[32], u64 tau,
			 u8 out[32])
{
	__le64 t = cpu_to_le64(tau);
	return sha256_bytes2(tfm, RS, 32, (const u8 *)&t, 8, out);
}

static int keystream_block_tfm(struct crypto_shash *tfm, const u8 filekey[32],
			       u64 nonce, u64 counter, u8 out[32])
{
	u8 tmp[16];
	__le64 n = cpu_to_le64(nonce);
	__le64 c = cpu_to_le64(counter);
	memcpy(tmp, &n, 8);
	memcpy(tmp + 8, &c, 8);
	return sha256_bytes2(tfm, filekey, 32, tmp, 16, out);
}

static int xor_stream_tfm(struct crypto_shash *tfm, u8 *buf, size_t len,
			  const u8 key[32], u64 nonce)
{
	u64 ctr = 0;
	size_t off = 0;
	u8 ks[32];
	int err;
	while (off < len) {
		size_t chunk;
		err = keystream_block_tfm(tfm, key, nonce, ctr++, ks);
		if (err)
			return err;
		chunk = min_t(size_t, len - off, 32);
		for (size_t i = 0; i < chunk; i++)
			buf[off + i] ^= ks[i];
		off += chunk;
	}
	return 0;
}

/* ==== Auto-format support ==== */
static bool auto_format = true;
module_param(auto_format, bool, 0644);
MODULE_PARM_DESC(auto_format, "Auto-format the MTD if no valid super is found");

static unsigned int format_inodes = 512;
module_param(format_inodes, uint, 0644);
MODULE_PARM_DESC(format_inodes, "Number of inodes to allocate on format");

static unsigned int data_stride_mb = 10;
module_param(data_stride_mb, uint, 0644);
MODULE_PARM_DESC(data_stride_mb,
		 "Per-inode data block size in MiB (default 10)");

static unsigned int rs_pebs = 3;
module_param(rs_pebs, uint, 0644);
MODULE_PARM_DESC(rs_pebs,
		 "Number of eraseblocks reserved for RS mirrors (default 3)");

static unsigned int super_copies = 2;
module_param(super_copies, uint, 0644);
MODULE_PARM_DESC(super_copies,
		 "Number of superblock copies to write (default 2)");

/* ==== Window helpers (bad-block aware data layout) ==== */

static size_t stride_bytes(void)
{
	return (size_t)data_stride_mb * 1024u * 1024u;
}
/* ==== RS/keytab helpers for encryption ==== */

/* Scan RS region and load the latest valid mirror into RS_out (or cached g_RS) */
static int load_rs(u8 RS_out[32])
{
	loff_t off;
	unsigned int found = 0;
	u64 best_gen = 0;
	u8 best_RS[32] = { 0 };
	u32 want = le32_to_cpu(g_super.rs_pebs);
	loff_t start = le64_to_cpu(g_super.rs_region_off);
	if (!g_super_ok)
		return -ENOENT;

	if (g_rs_ok) {
		memcpy(RS_out, g_RS, 32);
		return 0;
	}

	off = start;
	while (off < kv_mtd->size && found < want) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			struct rs_mirror *mirr =
				kmalloc(sizeof(*mirr), GFP_KERNEL);
			int err;
			if (!mirr)
				return -ENOMEM;
			err = mtd_read_exact(off, mirr, sizeof(*mirr));
			if (!err && mirr->magic == RS_MAGIC) {
				u32 crc_calc;
				__le32 saved = mirr->crc;
				mirr->crc = 0;
				crc_calc = crc32_le(~0U, (u8 *)mirr,
						    sizeof(*mirr));
				crc_calc ^= ~0U;
				mirr->crc = saved;
				if (cpu_to_le32(crc_calc) == saved) {
					u64 gen = le64_to_cpu(mirr->gen);
					if (!found || gen >= best_gen) {
						best_gen = gen;
						memcpy(best_RS, mirr->RS, 32);
					}
					found++;
				} else {
					pr_warn(NKV_TAG
						"RS crc mismatch at 0x%llx\n",
						(unsigned long long)off);
				}
			}
			kfree(mirr);
		}
		off += kv_mtd->erasesize;
	}

	if (!found)
		return -ENOENT;

	memcpy(g_RS, best_RS, 32);
	g_rs_ok = true;
	memcpy(RS_out, g_RS, 32);
	return 0;
}

/* Map keytab block index 'b' to physical offset (skip bad EBs, 4KiB slots/EB) */
static loff_t keytab_blk_off(u32 b)
{
	loff_t off = le64_to_cpu(g_super.keytab_off);
	u32 es = kv_mtd->erasesize;
	u32 slots = es / 4096u;
	while (off < kv_mtd->size) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			if (b < slots)
				return off + (loff_t)b * 4096;
			b -= slots;
		}
		off += es;
	}
	return -ENOSPC;
}

/* Derive per-inode 32-byte key */
static int get_filekey_for_inode(struct crypto_shash *tfm, u32 inode,
				 u8 out_key[32])
{
	u32 kb_cnt = le32_to_cpu(g_super.keyblk_count);
	u32 b = inode / 127u;
	u32 idx = inode % 127u;
	u8 RS[32];
	u8 k_tau[32];
	loff_t off;
	int err;
	if (b >= kb_cnt)
		return -ERANGE;
	err = load_rs(RS);
	if (err)
		return err;
	err = prf_k_tau_tfm(tfm, RS, b, k_tau);
	if (err)
		return err;
	off = keytab_blk_off(b);
	if (off < 0)
		return (int)off;
	/* Read/decrypt key block */
	{
		struct {
			u8 magic[16];
			__le64 tag_tau;
			u8 keys[127][32];
			u8 pad[4096 - 16 - 8 - 127 * 32];
		} __packed *kb;
		u64 nonce = 0xBADC0FFEEull ^ (u64)b;
		kb = kmalloc(4096, GFP_KERNEL);
		if (!kb)
			return -ENOMEM;
		err = mtd_read_exact(off, kb, 4096);
		if (err) {
			kfree(kb);
			return err;
		}
		if (memcmp(kb->magic, "KEYTABBLK\0\0\0\0\0\0\0\0", 16) != 0) {
			kfree(kb);
			return -EIO;
		}
		if (le64_to_cpu(kb->tag_tau) != (u64)b) {
			kfree(kb);
			return -EIO;
		}
		err = xor_stream_tfm(tfm, (u8 *)kb->keys, sizeof(kb->keys),
				     k_tau, nonce);
		if (!err)
			memcpy(out_key, kb->keys[idx], 32);
		memzero_explicit(kb, 4096);
		kfree(kb);
		memzero_explicit(k_tau, sizeof(k_tau));
		memzero_explicit(RS, sizeof(RS));
		return err;
	}
}

static loff_t data_block_off(u32 inode)
{
	return le64_to_cpu(g_super.data_off) +
	       (loff_t)inode * (loff_t)stride_bytes();
}

/* Count total usable bytes (good eraseblocks only) within a window */
static size_t good_bytes_in_window(loff_t start, size_t window)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = start;
	loff_t end = start + window;
	size_t good = 0;

	while (off < end) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return 0; /* on error, report 0 usable */
		if (!bad)
			good += min_t(size_t, es, (size_t)(end - off));
		off += es;
	}
	return good;
}

/* Read 'len' bytes from compacted good-EB stream within [start, start+window) */
static int read_compact(loff_t start, size_t window, size_t skip, u8 *dst,
			size_t len)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = start;
	loff_t end = start + window;
	size_t left = len;
	size_t to_skip = skip;

	while (off < end && (to_skip || left)) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			size_t use = min_t(size_t, es, (size_t)(end - off));
			if (to_skip >= use) {
				to_skip -= use;
			} else {
				size_t eb_off = to_skip;
				size_t chunk =
					min_t(size_t, use - eb_off, left);
				int err = mtd_read_pagewise(off + eb_off, dst,
							    chunk);
				if (err)
					return err;
				dst += chunk;
				left -= chunk;
				to_skip = 0;
			}
		}
		off += es;
	}
	return left ? -EIO : 0;
}

/* Erase all good EBs within the window */
static int erase_window_good(loff_t start, size_t window)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = start;
	loff_t end = start + window;
	while (off < end) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			int err = erase_range(off, es);
			if (err)
				return err;
		}
		off += es;
	}
	return 0;
}

/* Write 'len' bytes compacted into good EBs within window (erase must be done ahead) */
static int write_compact(loff_t start, size_t window, const u8 *src, size_t len)
{
	size_t es = kv_mtd->erasesize;
	loff_t off = start;
	loff_t end = start + window;
	size_t left = len;

	while (off < end && left) {
		int bad = mtd_block_isbad(kv_mtd, off);
		if (bad < 0)
			return bad;
		if (!bad) {
			size_t use = min_t(size_t, es, (size_t)(end - off));
			size_t chunk = min_t(size_t, use, left);
			int err = mtd_write_exact(off, src, chunk);
			if (err)
				return err;
			src += chunk;
			left -= chunk;
		}
		off += es;
	}
	return left ? -ENOSPC : 0;
}

static int kv_format_layout(void)
{
	struct super_hdr *s; /* allocate on heap to avoid large stack frame */
	struct crypto_shash *tfm = NULL;
	u8 RS[32];
	u64 total = kv_mtd->size;
	u32 es = kv_mtd->erasesize;
	u64 stride = (u64)data_stride_mb * 1024ull * 1024ull;
	u32 kb_cnt;
	u64 kb_bytes;
	u32 kb_ebs; /* keytab size in eraseblocks */
	loff_t super_off; /* first good EB for first super copy */
	loff_t rs_start; /* first EB of RS region (good) */
	loff_t after_rs; /* first byte after RS region (good) */
	loff_t keytab_off; /* first EB of keytab (good) */
	loff_t data_off; /* first EB of data region (good) */
	u32 inodes = format_inodes;
	int err;

	pr_info(NKV_TAG
		"format: total=0x%llx es=0x%x stride=%u MiB inodes=%u rs_pebs=%u\n",
		(unsigned long long)total, es, data_stride_mb, inodes, rs_pebs);

	if (stride < (4 * 1024))
		return -EINVAL;

	/* super must be exactly 4096 bytes */
	BUILD_BUG_ON(sizeof(struct super_hdr) != SUPER_BYTES);

	s = kzalloc(SUPER_BYTES, GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->magic = cpu_to_le64(SUPER_MAGIC);
	s->version = cpu_to_le32(SUPER_VERSION);
	s->peb_size = cpu_to_le32(es);
	s->total_size = cpu_to_le64(total);
	s->rs_pebs = cpu_to_le32(rs_pebs);

	if (super_copies == 0)
		super_copies = 1;
	super_off = find_good_eb(0);
	if (super_off < 0)
		return (int)super_off;
	g_super_off = super_off;
	pr_info(NKV_TAG "format: super_off=0x%llx copies=%u\n",
		(unsigned long long)super_off, super_copies);

	rs_start = advance_good_ebs(super_off, super_copies);
	if (rs_start < 0)
		return (int)rs_start;
	pr_info(NKV_TAG "format: rs_start=0x%llx\n",
		(unsigned long long)rs_start);

	after_rs = advance_good_ebs(rs_start, rs_pebs);
	if (after_rs < 0)
		return (int)after_rs;
	pr_info(NKV_TAG "format: after_rs=0x%llx\n",
		(unsigned long long)after_rs);

	if (inodes == 0)
		inodes = 1;
	kb_cnt = DIV_ROUND_UP(inodes, 127);
	kb_bytes = (u64)kb_cnt * 4096ull;
	kb_ebs = DIV_ROUND_UP(kb_bytes, es);

	keytab_off = find_good_eb(after_rs);
	if (keytab_off < 0)
		return (int)keytab_off;
	pr_info(NKV_TAG
		"format: keytab_off=0x%llx kb_cnt=%u kb_ebs=%u (kb_bytes=0x%llx)\n",
		(unsigned long long)keytab_off, kb_cnt, kb_ebs,
		(unsigned long long)kb_bytes);
	data_off = advance_good_ebs(keytab_off, kb_ebs);
	if (data_off < 0)
		return (int)data_off;
	pr_info(NKV_TAG "format: data_off=0x%llx\n",
		(unsigned long long)data_off);

	while (data_off + (u64)inodes * stride > total) {
		if (inodes <= 1)
			return -ENOSPC;
		inodes--;
		kb_cnt = DIV_ROUND_UP(inodes, 127);
		kb_bytes = (u64)kb_cnt * 4096ull;
		kb_ebs = DIV_ROUND_UP(kb_bytes, es);

		data_off = advance_good_ebs(keytab_off, kb_ebs);
		if (data_off < 0)
			return (int)data_off;
	}

	s->rs_region_off = cpu_to_le64(rs_start);
	s->keytab_off = cpu_to_le64(keytab_off);
	s->keytab_bytes = cpu_to_le64((u64)kb_ebs * es);
	s->data_off = cpu_to_le64(data_off);
	s->keyblk_count = cpu_to_le32(kb_cnt);
	s->inodes = cpu_to_le32(inodes);
	s->tag_counter = cpu_to_le64((u64)kb_cnt);

	{
		unsigned int written = 0;
		loff_t off = super_off;
		while (written < super_copies) {
			int bad;
			if (off >= kv_mtd->size) {
				err = -ENOSPC;
				return err;
			}
			bad = mtd_block_isbad(kv_mtd, off);
			if (bad < 0)
				return bad;
			if (!bad) {
				struct super_hdr *tmp;
				tmp = kmalloc(SUPER_BYTES, GFP_KERNEL);
				if (!tmp)
					return -ENOMEM;
				err = erase_range(off, es);
				if (err) {
					kfree(tmp);
					return err;
				}
				err = mtd_write_exact(off, s, SUPER_BYTES);
				if (err) {
					kfree(tmp);
					return err;
				}
				err = mtd_read_exact(off, tmp, SUPER_BYTES);
				if (!err &&
				    le64_to_cpu(tmp->magic) == SUPER_MAGIC &&
				    le32_to_cpu(tmp->version) ==
					    SUPER_VERSION) {
					pr_info(NKV_TAG
						"format: super copy %u verified at 0x%llx\n",
						written,
						(unsigned long long)off);
					written++;
				} else {
					pr_warn(NKV_TAG
						"format: super verify failed err=%d at 0x%llx, skipping EB\n",
						err, (unsigned long long)off);
					/* don't count this EB, move to next good */
				}
				kfree(tmp);
			}
			off += es;
		}
	}

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	{
		u8 rs_seed[32];
		u32 written = 0;
		loff_t off = rs_start;
		struct rs_mirror *mirror;

		get_random_bytes(rs_seed, sizeof(rs_seed));
		memcpy(RS, rs_seed, 32);

		mirror = kzalloc(sizeof(*mirror), GFP_KERNEL);
		if (!mirror) {
			err = -ENOMEM;
			goto out_tfm;
		}

		while (written < rs_pebs) {
			int bad;
			if (off >= kv_mtd->size) {
				err = -ENOSPC;
				kfree(mirror);
				goto out_tfm;
			}
			bad = mtd_block_isbad(kv_mtd, off);
			if (bad < 0) {
				err = bad;
				kfree(mirror);
				goto out_tfm;
			}
			if (!bad) {
				u32 crc;
				memset(mirror, 0, sizeof(*mirror));
				mirror->magic = RS_MAGIC;
				mirror->gen = cpu_to_le64(1);
				memcpy(mirror->RS, RS, 32);
				mirror->last_tau = cpu_to_le64(0);
				mirror->crc = 0;
				crc = crc32_le(~0U, (u8 *)mirror,
					       sizeof(*mirror));
				crc ^= ~0U;
				mirror->crc = cpu_to_le32(crc);

				err = erase_range(off, es);
				if (err) {
					kfree(mirror);
					goto out_tfm;
				}
				err = mtd_write_exact(off, mirror,
						      sizeof(*mirror));
				if (err) {
					kfree(mirror);
					goto out_tfm;
				}

				written++;
			}
			off += es;
		}

		kfree(mirror);
	}

	{
		u32 b = 0;
		u8 k_tau[32];
		loff_t off = keytab_off;
		u32 slots_per_eb = es / 4096u;

		while (b < kb_cnt) {
			int bad;
			if (off >= kv_mtd->size) {
				err = -ENOSPC;
				goto out_tfm;
			}
			bad = mtd_block_isbad(kv_mtd, off);
			if (bad < 0) {
				err = bad;
				goto out_tfm;
			}
			if (bad) {
				off += es;
				continue;
			}

			/* Good EB: erase once, then fill up to slots_per_eb key blocks */
			err = erase_range(off, es);
			if (err)
				goto out_tfm;

			for (u32 s = 0; s < slots_per_eb && b < kb_cnt;
			     s++, b++) {
				u64 nonce;
				loff_t slot_off = off + (loff_t)s * 4096;
				struct {
					u8 magic[16];
					__le64 tag_tau;
					u8 keys[127][32];
					u8 pad[4096 - 16 - 8 - 127 * 32];
				} __packed *kb;

				kb = kzalloc(4096, GFP_KERNEL);
				if (!kb) {
					err = -ENOMEM;
					goto out_tfm;
				}
				memcpy(kb->magic, "KEYTABBLK\0\0\0\0\0\0\0\0",
				       16);
				kb->tag_tau = cpu_to_le64(b);
				for (int i = 0; i < 127; i++)
					get_random_bytes(kb->keys[i], 32);

				err = prf_k_tau_tfm(tfm, RS, b, k_tau);
				if (err) {
					kfree(kb);
					goto out_tfm;
				}
				nonce = 0xBADC0FFEEull ^ (u64)b;
				err = xor_stream_tfm(tfm, (u8 *)kb->keys,
						     sizeof(kb->keys), k_tau,
						     nonce);
				if (err) {
					kfree(kb);
					goto out_tfm;
				}

				err = mtd_write_exact(slot_off, kb, 4096);
				memzero_explicit(kb, 4096);
				kfree(kb);
				if (err)
					goto out_tfm;
				pr_info(NKV_TAG
					"format: wrote keyblk %u at 0x%llx\n",
					b, (unsigned long long)slot_off);
			}

			off += es;
		}
	}

	{
		u64 erase_len = (u64)inodes * stride;
		pr_info(NKV_TAG
			"format: erase data region start=0x%llx len=0x%llx (stride=%u MiB per inode)\n",
			(unsigned long long)data_off,
			(unsigned long long)erase_len, data_stride_mb);
		err = erase_range(data_off, erase_len);
		if (err)
			goto out_tfm;
	}

out_tfm:
	crypto_free_shash(tfm);
	kfree(s);
	return err;
}

static int do_read(struct nand_kv_rw __user *up)
{
	struct nand_kv_rw p;
	int err;
	u8 hdrbuf[sizeof(struct data_hdr)];
	struct data_hdr *hdr = (struct data_hdr *)hdrbuf;
	size_t win = stride_bytes();
	struct crypto_shash *tfm = NULL;

	if (copy_from_user(&p, up, sizeof(p)))
		return -EFAULT;

	if (!g_super_ok) {
		err = kv_read_super();
		if (err)
			return err;
	}

	if (p.inode >= le32_to_cpu(g_super.inodes))
		return -ERANGE;

	pr_info(NKV_TAG "read inode=%u off=0x%llx win=0x%zx\n", p.inode,
		(unsigned long long)data_block_off(p.inode), win);

	/* Read compacted header */
	err = read_compact(data_block_off(p.inode), win, 0, hdrbuf,
			   sizeof(struct data_hdr));
	if (err)
		return err;

	if (le32_to_cpu(hdr->inode) != p.inode)
		return -ENOENT;

	{
		size_t good =
			good_bytes_in_window(data_block_off(p.inode), win);
		size_t max_payload =
			(good > sizeof(*hdr)) ? (good - sizeof(*hdr)) : 0;
		size_t payload_len = le32_to_cpu(hdr->len);
		if (payload_len > max_payload)
			return -EIO;

		p.len = payload_len;
		p.nonce = le64_to_cpu(hdr->nonce);
		if (copy_to_user(up, &p, sizeof(p)))
			return -EFAULT;

		if (p.len) {
			/* If user didn't provide a buffer, return header only */
			if (p.buf == 0) {
				return 0;
			}
			u8 *payload = vmalloc(p.len);
			if (!payload)
				return -ENOMEM;
			err = read_compact(data_block_off(p.inode), win,
					   sizeof(*hdr), payload, p.len);
			if (!err) {
				if (le64_to_cpu(hdr->nonce) != 0) {
					/* decrypt using filekey */
					u8 key[32];
					tfm = crypto_alloc_shash("sha256", 0,
								 0);
					if (IS_ERR(tfm)) {
						err = PTR_ERR(tfm);
						tfm = NULL;
					} else {
						err = get_filekey_for_inode(
							tfm, p.inode, key);
						if (!err)
							err = xor_stream_tfm(
								tfm, payload,
								p.len, key,
								le64_to_cpu(
									hdr->nonce));
						memzero_explicit(key,
								 sizeof(key));
					}
				}
			}
			if (!err) {
				if (copy_to_user((void __user *)(uintptr_t)p.buf,
						 payload, p.len))
					err = -EFAULT;
			}
			vfree(payload);
			if (tfm)
				crypto_free_shash(tfm);
			return err;
		}
	}
	return 0;
}

static int do_write(struct nand_kv_rw __user *up)
{
	struct nand_kv_rw p;
	int err;
	u8 *buf;
	struct data_hdr *hdr;
	size_t win = stride_bytes();
	struct crypto_shash *tfm = NULL;

	if (copy_from_user(&p, up, sizeof(p)))
		return -EFAULT;

	if (!g_super_ok) {
		err = kv_read_super();
		if (err)
			return err;
	}

	if (p.inode >= le32_to_cpu(g_super.inodes))
		return -ERANGE;
	{
		size_t good =
			good_bytes_in_window(data_block_off(p.inode), win);
		if (p.len > (good > sizeof(struct data_hdr) ?
				     (good - sizeof(struct data_hdr)) :
				     0))
			return -ENOSPC;
	}

	buf = vzalloc(sizeof(struct data_hdr) + p.len);
	if (!buf)
		return -ENOMEM;

	hdr = (struct data_hdr *)buf;
	hdr->inode = cpu_to_le32(p.inode);
	hdr->len = cpu_to_le32(p.len);

	if (p.flags & NAND_KV_F_PLAIN)
		hdr->nonce = cpu_to_le64(0);
	else {
		u64 n;
		get_random_bytes(&n, sizeof(n));
		hdr->nonce = cpu_to_le64(n);
		/* TODO: encryption; for now just mark as non-zero nonce */
	}

	if (copy_from_user(buf + sizeof(*hdr), (void __user *)(uintptr_t)p.buf,
			   p.len)) {
		err = -EFAULT;
		goto out_free;
	}

	/* Encrypt payload if nonce != 0 (i.e., not plaintext mode) */
	if (le64_to_cpu(hdr->nonce) != 0 && p.len) {
		u8 key[32];
		tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			tfm = NULL;
			goto out_free;
		}
		err = get_filekey_for_inode(tfm, p.inode, key);
		if (err) {
			memzero_explicit(key, sizeof(key));
			goto out_free;
		}
		err = xor_stream_tfm(tfm, buf + sizeof(*hdr), p.len, key,
				     le64_to_cpu(hdr->nonce));
		memzero_explicit(key, sizeof(key));
		if (err)
			goto out_free;
	}

	pr_info(NKV_TAG
		"write inode=%u off=0x%llx win=0x%zx flags=0x%x len=%u\n",
		p.inode, (unsigned long long)data_block_off(p.inode), win,
		p.flags, (unsigned)p.len);

	/* Erase all good EBs in the window first */
	err = erase_window_good(data_block_off(p.inode), win);
	if (err)
		goto out_free;

	/* Then write header+payload compacted into good EBs */
	err = write_compact(data_block_off(p.inode), win, buf,
			    sizeof(struct data_hdr) + p.len);

out_free:
	vfree(buf);
	if (tfm)
		crypto_free_shash(tfm);
	return err;
}

static int do_delete(u32 inode)
{
	int err;

	if (!g_super_ok) {
		err = kv_read_super();
		if (err)
			return err;
	}

	if (inode >= le32_to_cpu(g_super.inodes))
		return -ERANGE;

	/* Erase only good EBs in the window */
	pr_info(NKV_TAG "delete inode=%u off=0x%llx win=0x%zx\n", inode,
		(unsigned long long)data_block_off(inode), stride_bytes());
	return erase_window_good(data_block_off(inode), stride_bytes());
}

static long nand_kv_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	switch (cmd) {
	case NAND_KV_IOC_READ:
		return do_read((struct nand_kv_rw __user *)arg);
	case NAND_KV_IOC_WRITE:
		return do_write((struct nand_kv_rw __user *)arg);
	case NAND_KV_IOC_DELETE: {
		u32 inode;
		if (copy_from_user(&inode, (void __user *)arg, sizeof(inode)))
			return -EFAULT;
		return do_delete(inode);
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations nand_kv_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = nand_kv_ioctl,
	.compat_ioctl = nand_kv_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice nand_kv_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "nand_kv",
	.fops = &nand_kv_fops,
	.mode = 0600,
};

static char *parent_mtd = (char *)"mtd0";
module_param(parent_mtd, charp, 0444);
MODULE_PARM_DESC(parent_mtd,
		 "Name of parent MTD (e.g., mtd0 or kv) holding KV layout");

static int kv_probe_parent(void)
{
	kv_mtd = get_mtd_device_nm(parent_mtd);
	if (IS_ERR(kv_mtd))
		return PTR_ERR(kv_mtd);
	pr_info(NKV_TAG
		"parent='%s' size=0x%llx es=0x%x writesize=0x%x oobsize=0x%x type=%d flags=0x%x\n",
		parent_mtd, (unsigned long long)kv_mtd->size, kv_mtd->erasesize,
		kv_mtd->writesize, kv_mtd->oobsize, kv_mtd->type,
		(u32)kv_mtd->flags);
	return 0;
}

static int __init nand_kv_init(void)
{
	int err;

	err = kv_probe_parent();
	if (err)
		return err;

	err = kv_read_super();
	if (err) {
		pr_warn(NKV_TAG "no valid super (%d)\n", err);
		if (auto_format) {
			pr_warn(NKV_TAG "auto-formatting %s...\n", parent_mtd);
			err = kv_format_layout();
			if (err) {
				pr_err(NKV_TAG "format failed: %d\n", err);
				put_mtd_device(kv_mtd);
				return err;
			}
			err = kv_read_super();
			if (err) {
				pr_err(NKV_TAG
				       "super read still failing after format: %d\n",
				       err);
				put_mtd_device(kv_mtd);
				return err;
			}
		}
	}

	err = misc_register(&nand_kv_miscdev);
	if (err) {
		put_mtd_device(kv_mtd);
		return err;
	}

	pr_info(NKV_TAG "registered /dev/nand_kv on %s (super at 0x%llx)\n",
		parent_mtd, (unsigned long long)g_super_off);
	return 0;
}

static void __exit nand_kv_exit(void)
{
	misc_deregister(&nand_kv_miscdev);
	if (kv_mtd && !IS_ERR(kv_mtd))
		put_mtd_device(kv_mtd);
}

module_init(nand_kv_init);
module_exit(nand_kv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(
	"Simple SPI-NAND KV store prototype (good-EB super, 4KiB aligned)");
MODULE_AUTHOR("research");