#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}
static uint64_t le64(uint64_t x)
{
	union {
		uint64_t v;
		unsigned char b[8];
	} u = { x };
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return u.v;
#else
	return ((uint64_t)u.b[0]) | ((uint64_t)u.b[1] << 8) |
	       ((uint64_t)u.b[2] << 16) | ((uint64_t)u.b[3] << 24) |
	       ((uint64_t)u.b[4] << 32) | ((uint64_t)u.b[5] << 40) |
	       ((uint64_t)u.b[6] << 48) | ((uint64_t)u.b[7] << 56);
#endif
}
static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		die("clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint32_t crc32_tab[256];
static void crc32_init()
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
		crc32_tab[i] = c;
	}
}
static uint32_t crc32(const void *buf, size_t len)
{
	const unsigned char *p = (const unsigned char *)buf;
	uint32_t c = ~0u;
	for (size_t i = 0; i < len; i++)
		c = crc32_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
	return ~c;
}

typedef struct {
	uint32_t s[8];
	uint64_t bits;
	unsigned char buf[64];
	size_t len;
} sha256_ctx;
static uint32_t rotr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}
static void sha256_init(sha256_ctx *c)
{
	c->s[0] = 0x6a09e667;
	c->s[1] = 0xbb67ae85;
	c->s[2] = 0x3c6ef372;
	c->s[3] = 0xa54ff53a;
	c->s[4] = 0x510e527f;
	c->s[5] = 0x9b05688c;
	c->s[6] = 0x1f83d9ab;
	c->s[7] = 0x5be0cd19;
	c->bits = 0;
	c->len = 0;
}
static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
	static const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	uint32_t w[64];
	for (int i = 0; i < 16; i++)
		w[i] = (p[4 * i] << 24) | (p[4 * i + 1] << 16) |
		       (p[4 * i + 2] << 8) | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
			      (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = c->s[0], b = c->s[1], d, e, f, g, h;
	uint32_t ccc = c->s[2];
	uint32_t ddd = c->s[3];
	e = c->s[4];
	f = c->s[5];
	g = c->s[6];
	h = c->s[7];
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + S1 + ch + K[i] + w[i];
		uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
		uint32_t maj = (a & ccc) ^ (a & b) ^ (ccc & b);
		uint32_t temp2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = ddd + temp1;
		ddd = ccc;
		ccc = b;
		b = a;
		a = temp1 + temp2;
	}
	c->s[0] += a;
	c->s[1] += b;
	c->s[2] += ccc;
	c->s[3] += ddd;
	c->s[4] += e;
	c->s[5] += f;
	c->s[6] += g;
	c->s[7] += h;
}
static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
	const unsigned char *p = data;
	c->bits += (uint64_t)len * 8;
	while (len--) {
		c->buf[c->len++] = *p++;
		if (c->len == 64) {
			sha256_block(c, c->buf);
			c->len = 0;
		}
	}
}
static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
	size_t i = c->len;
	c->buf[i++] = 0x80;
	while (i % 64 != 56) {
		if (i == 64) {
			sha256_block(c, c->buf);
			i = 0;
		}
		c->buf[i++] = 0;
	}
	uint64_t b = c->bits;
	for (int j = 7; j >= 0; j--)
		c->buf[i++] = (unsigned char)(b >> (8 * j));
	sha256_block(c, c->buf);
	for (int j = 0; j < 8; j++) {
		out[4 * j] = (c->s[j] >> 24) & 0xFF;
		out[4 * j + 1] = (c->s[j] >> 16) & 0xFF;
		out[4 * j + 2] = (c->s[j] >> 8) & 0xFF;
		out[4 * j + 3] = c->s[j] & 0xFF;
	}
}
static void sha256_bytes(const void *a, size_t alen, const void *b, size_t blen,
			 unsigned char out[32])
{
	sha256_ctx c;
	sha256_init(&c);
	if (a && alen)
		sha256_update(&c, a, alen);
	if (b && blen)
		sha256_update(&c, b, blen);
	sha256_final(&c, out);
}

static void prf_k_tau(const unsigned char RS[32], uint64_t tau,
		      unsigned char out[32])
{
	uint64_t t = le64(tau);
	sha256_bytes(RS, 32, &t, 8, out);
}
static void keystream_block(const unsigned char filekey[32], uint64_t nonce,
			    uint64_t counter, unsigned char out[32])
{
	unsigned char tmp[16];
	uint64_t n = le64(nonce), c = le64(counter);
	memcpy(tmp, &n, 8);
	memcpy(tmp + 8, &c, 8);
	sha256_bytes(filekey, 32, tmp, 16, out);
}
static void xor_stream(unsigned char *buf, size_t len,
		       const unsigned char key[32], uint64_t nonce)
{
	uint64_t ctr = 0;
	size_t off = 0;
	unsigned char ks[32];
	while (off < len) {
		keystream_block(key, nonce, ctr++, ks);
		size_t chunk = (len - off < 32) ? (len - off) : 32;
		for (size_t i = 0; i < chunk; i++)
			buf[off + i] ^= ks[i];
		off += chunk;
	}
}

#define SUPER_MAGIC 0x524E414E44534E44ull
#define SUPER_VERSION 1
#pragma pack(push, 1)
typedef struct {
	uint64_t magic;
	uint32_t version;
	uint32_t peb_size;
	uint64_t total_size;
	uint32_t rs_pebs;
	uint64_t rs_region_off;
	uint64_t keytab_off;
	uint64_t keytab_bytes;
	uint64_t data_off;
	uint32_t keyblk_count;
	uint32_t inodes;
	uint64_t tag_counter;
	unsigned char reserved[4000];
} Super;

#define RS_MAGIC 0x52534D4952524F52ull
typedef struct {
	uint64_t magic;
	uint64_t gen;
	unsigned char RS[32];
	uint64_t last_tau;
	uint32_t crc;
	unsigned char pad[4096 - 8 - 8 - 32 - 8 - 4];
} RSMirror;

typedef struct {
	unsigned char magic[16];
	uint64_t tag_tau;
	unsigned char keys[127][32];
	uint8_t pad[4096 - 16 - 8 - 127 * 32];
} KeyBlock;

typedef struct {
	uint32_t inode;
	uint32_t len;
	uint64_t nonce;
} DataHeader;
#pragma pack(pop)

static void pread_all(int fd, void *buf, size_t n, off_t off)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = pread(fd, (char *)buf + got, n - got, off + got);
		if (r < 0)
			die("pread");
		if (r == 0)
			die("short read");
		got += r;
	}
}
static void pwrite_all(int fd, const void *buf, size_t n, off_t off)
{
	size_t put = 0;
	while (put < n) {
		ssize_t r = pwrite(fd, (char *)buf + put, n - put, off + put);
		if (r < 0)
			die("pwrite");
		if (r == 0)
			die("short write");
		put += r;
	}
}
static void fsync_fd(int fd)
{
	if (fsync(fd) < 0)
		die("fsync");
}

static void rand_bytes(void *buf, size_t n)
{
	int f = open("/dev/urandom", O_RDONLY);
	if (f < 0)
		die("urandom");
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(f, (char *)buf + got, n - got);
		if (r < 0)
			die("urandom read");
		got += r;
	}
	close(f);
}

static off_t peb0_off(const Super *s)
{
	(void)s;
	return 4096;
}
static off_t rs_peb_off(const Super *s, int idx)
{
	return peb0_off(s) + (off_t)idx * s->peb_size;
}
static off_t keyblk_off(const Super *s, uint32_t blk_idx)
{
	return s->keytab_off + (off_t)blk_idx * 4096;
}
static void inode_to_keyblk(uint32_t inode, uint32_t *blk, uint32_t *slot)
{
	*blk = inode / 127;
	*slot = inode % 127;
}
static off_t data_block_off(const Super *s, uint32_t inode)
{
	return s->data_off + (off_t)inode * 10 * 1024 * 1024;
}

static int rs_load_best(int fd, const Super *sp, RSMirror *out)
{
	RSMirror best = { 0 };
	int found = 0;
	for (int i = 0; i < (int)sp->rs_pebs; i++) {
		RSMirror m;
		pread_all(fd, &m, sizeof(m), rs_peb_off(sp, i));
		if (m.magic != RS_MAGIC)
			continue;
		uint32_t crc0 = m.crc;
		m.crc = 0;
		uint32_t c = crc32(&m, sizeof(m));
		if (c != crc0)
			continue;
		if (!found || m.gen > best.gen) {
			best = m;
			found = 1;
		}
	}
	if (found) {
		*out = best;
		return 0;
	}
	return -1;
}
static void rs_store_all(int fd, const Super *sp, const RSMirror *rs)
{
	for (int i = 0; i < (int)sp->rs_pebs; i++) {
		RSMirror m = *rs;
		m.crc = 0;
		m.crc = crc32(&m, sizeof(m));
		pwrite_all(fd, &m, sizeof(m), rs_peb_off(sp, i));
	}
}

static void keyblk_encrypt(KeyBlock *kb, const unsigned char k_tau[32])
{
	unsigned char *p = (unsigned char *)kb->keys;
	size_t n = sizeof(kb->keys);
	uint64_t nonce = 0xBADC0FFEEULL ^ kb->tag_tau;
	xor_stream(p, n, k_tau, nonce);
}
static void keyblk_decrypt(KeyBlock *kb, const unsigned char k_tau[32])
{
	keyblk_encrypt(kb, k_tau);
}

static void write_super(int fd, const Super *s)
{
	pwrite_all(fd, s, sizeof(*s), 0);
}
static void read_super(int fd, Super *s)
{
	pread_all(fd, s, sizeof(*s), 0);
	if (s->magic != SUPER_MAGIC || s->version != SUPER_VERSION)
		die("bad super");
}

static void cmd_init(const char *img, uint64_t size_mib, uint32_t peb_kib,
		     uint32_t inodes)
{
	int fd = open(img, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("open img");
	uint64_t total_bytes = size_mib * 1024ull * 1024ull;
	if (ftruncate(fd, total_bytes) < 0)
		die("ftruncate");
	crc32_init();

	Super s = { 0 };
	s.magic = SUPER_MAGIC;
	s.version = SUPER_VERSION;
	s.peb_size = peb_kib * 1024u;
	s.total_size = total_bytes;
	s.rs_pebs = 3;
	s.inodes = inodes;
	s.tag_counter = 0;
	s.rs_region_off = peb0_off(&s);
	uint32_t keyblk_count = (inodes + 126) / 127;
	s.keyblk_count = keyblk_count;
	uint64_t key_bytes = (uint64_t)keyblk_count * 4096ull;
	uint64_t key_bytes_rounded =
		((key_bytes + s.peb_size - 1) / s.peb_size) * s.peb_size;
	s.keytab_off = rs_peb_off(&s, s.rs_pebs);
	s.keytab_bytes = key_bytes_rounded;
	s.data_off = s.keytab_off + key_bytes_rounded;
	if (s.data_off + (uint64_t)inodes * 4096ull > total_bytes) {
		fprintf(stderr, "[init] image too small for geometry\n");
		exit(1);
	}

	write_super(fd, &s);

	RSMirror rs = { 0 };
	rs.magic = RS_MAGIC;
	rs.gen = 1;
	rand_bytes(rs.RS, 32);
	rs.last_tau = 0;
	rs.crc = 0;
	rs.crc = crc32(&rs, sizeof(rs));
	rs_store_all(fd, &s, &rs);

	for (uint32_t b = 0; b < keyblk_count; b++) {
		KeyBlock kb;
		memset(&kb, 0, sizeof(kb));
		memcpy(kb.magic, "KEYTABBLK\0\0\0\0\0\0\0\0", 16);
		kb.tag_tau = b;
		for (int i = 0; i < 127; i++)
			rand_bytes(kb.keys[i], 32);
		unsigned char k_tau[32];
		prf_k_tau(rs.RS, kb.tag_tau, k_tau);
		keyblk_encrypt(&kb, k_tau);
		pwrite_all(fd, &kb, sizeof(kb), keyblk_off(&s, b));
		s.tag_counter = (b + 1);
	}

	unsigned char zero_blk[4096];
	memset(zero_blk, 0, sizeof(zero_blk));
	for (uint32_t i = 0; i < inodes; i++)
		pwrite_all(fd, zero_blk, sizeof(zero_blk),
			   data_block_off(&s, i));

	write_super(fd, &s);
	fsync_fd(fd);
	close(fd);
	fprintf(stderr, "[init] done. key blocks=%u, data blocks(inodes)=%u\n",
		keyblk_count, inodes);
}

static void load_all(int fd, Super *sp, RSMirror *rs)
{
	read_super(fd, sp);
	crc32_init();
	if (rs_load_best(fd, sp, rs) != 0)
		die("no valid RS");
}

static void cmd_info(const char *img)
{
	Super s;
	RSMirror rs;
	int fd = open(img, O_RDONLY);
	if (fd < 0)
		die("open");
	load_all(fd, &s, &rs);
	close(fd);
	printf("Image info:\n  size: %" PRIu64
	       " bytes\n  PEB: %u bytes\n  RS PEBs: %u (offset=%" PRIu64
	       ")\n  key table: off=%" PRIu64 ", bytes=%" PRIu64
	       ", blocks=%u\n  data: off=%" PRIu64
	       ", inodes=%u\n  RS gen=%" PRIu64 ", last_tau=%" PRIu64
	       "\n  next tag_counter=%" PRIu64 "\n",
	       s.total_size, s.peb_size, s.rs_pebs, s.rs_region_off,
	       s.keytab_off, s.keytab_bytes, s.keyblk_count, s.data_off,
	       s.inodes, rs.gen, rs.last_tau, s.tag_counter);
}

static void read_key_for_inode(int fd, const Super *s, const RSMirror *rs,
			       uint32_t inode, unsigned char out_key[32],
			       uint32_t *blk_out)
{
	uint32_t blk, slot;
	inode_to_keyblk(inode, &blk, &slot);
	if (blk >= s->keyblk_count) {
		fprintf(stderr, "inode out of range\n");
		exit(1);
	}
	KeyBlock kb;
	pread_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	unsigned char k_tau[32];
	prf_k_tau(rs->RS, kb.tag_tau, k_tau);
	keyblk_decrypt(&kb, k_tau);
	memcpy(out_key, kb.keys[slot], 32);
	if (blk_out)
		*blk_out = blk;
}

static void write_key_for_inode_and_rotate(int fd, Super *s, RSMirror *rs,
					   uint32_t inode,
					   const unsigned char new_key[32])
{
	uint32_t blk, slot;
	inode_to_keyblk(inode, &blk, &slot);
	KeyBlock kb;
	pread_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	unsigned char k_old_tau[32];
	prf_k_tau(rs->RS, kb.tag_tau, k_old_tau);
	keyblk_decrypt(&kb, k_old_tau);
	memcpy(kb.keys[slot], new_key, 32);
	unsigned char tmp[4 + 8];
	memcpy(tmp, "PUNC", 4);
	uint64_t t = le64(kb.tag_tau);
	memcpy(tmp + 4, &t, 8);
	sha256_bytes(rs->RS, 32, tmp, 12, rs->RS);
	rs->gen++;
	rs->last_tau = kb.tag_tau;
	kb.tag_tau = s->tag_counter++;
	unsigned char k_new_tau[32];
	prf_k_tau(rs->RS, kb.tag_tau, k_new_tau);
	keyblk_encrypt(&kb, k_new_tau);
	pwrite_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	rs_store_all(fd, s, rs);
	write_super(fd, s);
	fsync_fd(fd);
}

static void cmd_write(const char *img, uint32_t inode, const char *input,
		      int plain)
{
	int fd = open(img, O_RDWR);
	if (fd < 0)
		die("open");

	Super s;
	RSMirror rs;
	if (plain)
		read_super(fd, &s);
	else
		load_all(fd, &s, &rs);

	if (inode >= s.inodes) {
		fprintf(stderr, "inode out of range\n");
		exit(1);
	}

	size_t max_payload = (10 * 1024 * 1024) - sizeof(DataHeader);

	// 힙에 10MB 블록 하나 통째로 확보
	unsigned char *block = (unsigned char *)calloc(1, 10 * 1024 * 1024);
	if (!block)
		die("calloc block");

	uint64_t t0 = now_ns();

	FILE *f = fopen(input, "rb");
	if (!f)
		die("open input");
	size_t n = fread(block + sizeof(DataHeader), 1, max_payload, f);
	fclose(f);

	if (n > max_payload) {
		fprintf(stderr, "input too large (max %zu bytes)\n",
			max_payload);
		free(block);
		exit(1);
	}

	DataHeader *hdr = (DataHeader *)block;
	hdr->inode = inode;
	hdr->len = (uint32_t)n;
	if (plain)
		hdr->nonce = 0;
	else
		rand_bytes(&hdr->nonce, 8);

	if (!plain) {
		unsigned char key[32];
		read_key_for_inode(fd, &s, &rs, inode, key, NULL);
		xor_stream(block + sizeof(DataHeader), n, key, hdr->nonce);
	}

	pwrite_all(fd, block, 10 * 1024 * 1024, data_block_off(&s, inode));
	fsync_fd(fd);

	uint64_t t1 = now_ns();
	double ms = (t1 - t0) / 1e6;

	close(fd);
	fprintf(stderr, "[write%s] inode %u wrote %zu bytes (%.3f ms)\n",
		plain ? "(plain)" : "", inode, n, ms);

	free(block);
}

static void cmd_read(const char *img, uint32_t inode, const char *output)
{
	int fd = open(img, O_RDONLY);
	if (fd < 0)
		die("open");
	Super s;
	read_super(fd, &s);
	if (inode >= s.inodes) {
		fprintf(stderr, "inode out of range\n");
		exit(1);
	}

	uint64_t t0 = now_ns();

	// 10MB 블록을 힙에서 확보
	unsigned char *blk = (unsigned char *)malloc(1024 * 1024 * 10);
	if (!blk)
		die("malloc blk");

	// 디스크에서 10MB 전체 블록 읽기
	pread_all(fd, blk, 1024 * 1024 * 10, data_block_off(&s, inode));

	DataHeader *hdr = (DataHeader *)blk;
	if (hdr->inode != inode) {
		free(blk);
		fprintf(stderr, "[read] empty or mismatched inode\n");
		exit(1);
	}

	// len은 uint32_t로 가정 (DataHeader 수정 반영)
	size_t n = (size_t)hdr->len;
	size_t max_payload = 1024 * 1024 * 10 - sizeof(DataHeader);
	if (n > max_payload) {
		free(blk);
		fprintf(stderr, "[read] bad length\n");
		exit(1);
	}

	// 암호화된 경우 복호화
	if (hdr->nonce != 0) {
		unsigned char key[32];
		RSMirror rs;
		load_all(fd, &s, &rs);
		read_key_for_inode(fd, &s, &rs, inode, key, NULL);
		xor_stream(blk + sizeof(DataHeader), n, key, hdr->nonce);
	}

	FILE *f = fopen(output, "wb");
	if (!f) {
		free(blk);
		die("open output");
	}
	fwrite(blk + sizeof(DataHeader), 1, n, f);
	fclose(f);

	close(fd);
	free(blk);

	uint64_t t1 = now_ns();
	double ms = (t1 - t0) / 1e6;
	fprintf(stderr, "[read] inode %u read %zu bytes (%.3f ms)\n", inode, n,
		ms);
}

static void cmd_delete(const char *img, uint32_t inode, int plain)
{
	int fd = open(img, O_RDWR);
	if (fd < 0)
		die("open");
	Super s;
	read_super(fd, &s);
	if (inode >= s.inodes) {
		fprintf(stderr, "inode out of range\n");
		exit(1);
	}
	unsigned char blk[4096];
	pread_all(fd, blk, 4096, data_block_off(&s, inode));
	DataHeader *hdr = (DataHeader *)blk;
	int is_plain = (hdr->nonce == 0);
	if (plain || is_plain) {
		unsigned char zero_blk[4096];
		memset(zero_blk, 0, sizeof(zero_blk));
		pwrite_all(fd, zero_blk, sizeof(zero_blk),
			   data_block_off(&s, inode));
	} else {
		RSMirror rs;
		load_all(fd, &s, &rs);
		unsigned char newk[32];
		rand_bytes(newk, 32);
		write_key_for_inode_and_rotate(fd, &s, &rs, inode, newk);
	}
	close(fd);
	fprintf(stderr,
		(plain || is_plain) ?
			"[delete(plain)] inode %u cleared block\n" :
			"[delete] inode %u: key rotated, RS punctured at previous τ; old data now unrecoverable.\n",
		inode);
}

static int eq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}
int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage:\n  %s init <img> --size-mib N --peb-kib K --inodes I\n  %s info <img>\n  %s write <img> <inode> <input_file> [--plain]\n  %s read  <img> <inode> <output_file>\n  %s delete <img> <inode> [--plain]\n",
			argv[0], argv[0], argv[0], argv[0], argv[0]);
		return 1;
	}
	if (eq(argv[1], "init")) {
		const char *img = argv[2];
		uint64_t size_mib = 64;
		uint32_t peb_kib = 128;
		uint32_t inodes = 4096;
		for (int i = 3; i < argc; i++) {
			if (eq(argv[i], "--size-mib") && i + 1 < argc)
				size_mib = strtoull(argv[++i], 0, 10);
			else if (eq(argv[i], "--peb-kib") && i + 1 < argc)
				peb_kib = strtoul(argv[++i], 0, 10);
			else if (eq(argv[i], "--inodes") && i + 1 < argc)
				inodes = strtoul(argv[++i], 0, 10);
		}
		cmd_init(img, size_mib, peb_kib, inodes);
		return 0;
	} else if (eq(argv[1], "info")) {
		cmd_info(argv[2]);
		return 0;
	} else if (eq(argv[1], "write") && argc >= 5) {
		int plain = (argc >= 6 && eq(argv[5], "--plain"));
		cmd_write(argv[2], (uint32_t)strtoul(argv[3], 0, 10), argv[4],
			  plain);
		return 0;
	} else if (eq(argv[1], "read") && argc >= 5) {
		cmd_read(argv[2], (uint32_t)strtoul(argv[3], 0, 10), argv[4]);
		return 0;
	} else if (eq(argv[1], "delete") && argc >= 4) {
		int plain = (argc >= 5 && eq(argv[4], "--plain"));
		cmd_delete(argv[2], (uint32_t)strtoul(argv[3], 0, 10), plain);
		return 0;
	}
	fprintf(stderr, "bad args\n");
	return 1;
}
