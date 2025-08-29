#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

void die(const char *msg)
{
	perror(msg);
	exit(1);
}

unsigned long long to_le64(unsigned long long x)
{
	union {
		unsigned long long v;
		unsigned char b[8];
	} u = { x };
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return u.v;
#else
	return ((unsigned long long)u.b[0]) |
	       ((unsigned long long)u.b[1] << 8) |
	       ((unsigned long long)u.b[2] << 16) |
	       ((unsigned long long)u.b[3] << 24) |
	       ((unsigned long long)u.b[4] << 32) |
	       ((unsigned long long)u.b[5] << 40) |
	       ((unsigned long long)u.b[6] << 48) |
	       ((unsigned long long)u.b[7] << 56);
#endif
}

/* crc32 */
unsigned int crc_tab[256];
void crc_init(void)
{
	for (unsigned int i = 0; i < 256; i++) {
		unsigned int c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
		crc_tab[i] = c;
	}
}
unsigned int crc_calc(const void *buf, size_t n)
{
	const unsigned char *p = (const unsigned char *)buf;
	unsigned int c = ~0u;
	for (size_t i = 0; i < n; i++)
		c = crc_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
	return ~c;
}

/* sha256 (필요한 만큼만) */
typedef struct {
	unsigned int s[8];
	unsigned long long bits;
	unsigned char buf[64];
	size_t len;
} sha256_ctx;

unsigned int ror(unsigned int x, int n)
{
	return (x >> n) | (x << (32 - n));
}

void sha256_init(sha256_ctx *c)
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
void sha256_block(sha256_ctx *c, const unsigned char *p)
{
	static const unsigned int K[64] = {
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
	unsigned int w[64];
	for (int i = 0; i < 16; i++)
		w[i] = (p[4 * i] << 24) | (p[4 * i + 1] << 16) |
		       (p[4 * i + 2] << 8) | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		unsigned int s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^
				  (w[i - 15] >> 3);
		unsigned int s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^
				  (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	unsigned int a = c->s[0], b = c->s[1], c2 = c->s[2], d = c->s[3],
		     e = c->s[4], f = c->s[5], g = c->s[6], h = c->s[7];
	for (int i = 0; i < 64; i++) {
		unsigned int S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
		unsigned int ch = (e & f) ^ ((~e) & g);
		unsigned int t1 = h + S1 + ch + K[i] + w[i];
		unsigned int S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
		unsigned int maj = (a & b) ^ (a & c2) ^ (b & c2);
		unsigned int t2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c2;
		c2 = b;
		b = a;
		a = t1 + t2;
	}
	c->s[0] += a;
	c->s[1] += b;
	c->s[2] += c2;
	c->s[3] += d;
	c->s[4] += e;
	c->s[5] += f;
	c->s[6] += g;
	c->s[7] += h;
}
void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
	const unsigned char *p = (const unsigned char *)data;
	c->bits += (unsigned long long)n * 8;
	while (n--) {
		c->buf[c->len++] = *p++;
		if (c->len == 64) {
			sha256_block(c, c->buf);
			c->len = 0;
		}
	}
}
void sha256_final(sha256_ctx *c, unsigned char out[32])
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
	unsigned long long b = c->bits;
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
void sha256_bytes(const void *a, size_t alen, const void *b, size_t blen,
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

/* PRF / stream */
void prf_k_tau(const unsigned char RS[32], unsigned long long tau,
	       unsigned char out[32])
{
	unsigned long long t = to_le64(tau);
	sha256_bytes(RS, 32, &t, 8, out);
}
void stream_block(const unsigned char key[32], unsigned long long nonce,
		  unsigned long long ctr, unsigned char out[32])
{
	unsigned char tmp[16];
	unsigned long long n = to_le64(nonce), c = to_le64(ctr);
	memcpy(tmp, &n, 8);
	memcpy(tmp + 8, &c, 8);
	sha256_bytes(key, 32, tmp, 16, out);
}
void xor_stream(unsigned char *buf, size_t n, const unsigned char key[32],
		unsigned long long nonce)
{
	unsigned long long ctr = 0;
	size_t off = 0;
	unsigned char ks[32];
	while (off < n) {
		stream_block(key, nonce, ctr++, ks);
		size_t m = (n - off < 32) ? (n - off) : 32;
		for (size_t i = 0; i < m; i++)
			buf[off + i] ^= ks[i];
		off += m;
	}
}

/* on-disk structs */
#define SUPER_MAGIC 0x524E414E44534E44ull
#define SUPER_VERSION 1

#pragma pack(push, 1)
typedef struct {
	unsigned long long magic;
	unsigned int version;
	unsigned int peb_size;
	unsigned long long total_size;
	unsigned int rs_pebs;
	unsigned long long rs_region_off;
	unsigned long long keytab_off;
	unsigned long long keytab_bytes;
	unsigned long long data_off;
	unsigned int keyblk_count;
	unsigned int inodes;
	unsigned long long tag_counter;
	unsigned char reserved[4000];
} Super;

#define RS_MAGIC 0x52534D4952524F52ull
typedef struct {
	unsigned long long magic;
	unsigned long long gen;
	unsigned char RS[32];
	unsigned long long last_tau;
	unsigned int crc;
	unsigned char pad[4096 - 8 - 8 - 32 - 8 - 4];
} RSMirror;

typedef struct {
	unsigned char magic[16];
	unsigned long long tag_tau;
	unsigned char keys[127][32];
	unsigned char pad[4096 - 16 - 8 - 127 * 32];
} KeyBlock;

typedef struct {
	unsigned int inode;
	unsigned short len;
	unsigned long long nonce;
} DataHeader;
#pragma pack(pop)

/* io */
void read_all(int fd, void *buf, size_t n, off_t off)
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
void write_all(int fd, const void *buf, size_t n, off_t off)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = pwrite(fd, (const char *)buf + done, n - done,
				   off + done);
		if (r < 0)
			die("pwrite");
		if (r == 0)
			die("short write");
		done += r;
	}
}
void sync_fd(int fd)
{
	if (fsync(fd) < 0)
		die("fsync");
}

/* rng */
void rand_bytes(void *buf, size_t n)
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

/* layout helpers */
off_t peb0_off(const Super *s)
{
	(void)s;
	return 4096;
}
off_t rs_off(const Super *s, int i)
{
	return peb0_off(s) + (off_t)i * s->peb_size;
}
off_t keyblk_off(const Super *s, unsigned int b)
{
	return s->keytab_off + (off_t)b * 4096;
}
void ino_to_key(unsigned int ino, unsigned int *blk, unsigned int *slot)
{
	*blk = ino / 127;
	*slot = ino % 127;
}
off_t data_off(const Super *s, unsigned int ino)
{
	return s->data_off + (off_t)ino * 4096;
}

/* rs mirrors */
int rs_load(int fd, const Super *sp, RSMirror *out)
{
	RSMirror best;
	int found = 0;
	for (int i = 0; i < (int)sp->rs_pebs; i++) {
		RSMirror m;
		read_all(fd, &m, sizeof(m), rs_off(sp, i));
		if (m.magic != RS_MAGIC)
			continue;
		unsigned int c0 = m.crc;
		m.crc = 0;
		if (crc_calc(&m, sizeof(m)) != c0)
			continue;
		if (!found || m.gen > best.gen) {
			best = m;
			found = 1;
		}
	}
	if (!found)
		return -1;
	*out = best;
	return 0;
}
void rs_store(int fd, const Super *sp, const RSMirror *rs)
{
	for (int i = 0; i < (int)sp->rs_pebs; i++) {
		RSMirror m = *rs;
		m.crc = 0;
		m.crc = crc_calc(&m, sizeof(m));
		write_all(fd, &m, sizeof(m), rs_off(sp, i));
	}
}

/* keyblock crypto */
void keyblk_xcrypt(KeyBlock *kb, const unsigned char k[32])
{
	unsigned char *p = (unsigned char *)kb->keys;
	size_t n = sizeof(kb->keys);
	unsigned long long nonce = 0xBADC0FFEEULL ^ kb->tag_tau;
	xor_stream(p, n, k, nonce);
}

/* super io */
void super_write(int fd, const Super *s)
{
	write_all(fd, s, sizeof(*s), 0);
}
void super_read(int fd, Super *s)
{
	read_all(fd, s, sizeof(*s), 0);
	if (s->magic != SUPER_MAGIC || s->version != SUPER_VERSION)
		die("bad super");
}

/* logic */
void get_file_key(int fd, const Super *s, const RSMirror *rs, unsigned int ino,
		  unsigned char out[32], unsigned int *blk_out)
{
	unsigned int blk, slot;
	ino_to_key(ino, &blk, &slot);
	if (blk >= s->keyblk_count) {
		fprintf(stderr, "inode oob\n");
		exit(1);
	}
	KeyBlock kb;
	read_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	unsigned char kt[32];
	prf_k_tau(rs->RS, kb.tag_tau, kt);
	keyblk_xcrypt(&kb, kt);
	memcpy(out, kb.keys[slot], 32);
	if (blk_out)
		*blk_out = blk;
}

void rotate_key_and_rs(int fd, Super *s, RSMirror *rs, unsigned int ino,
		       const unsigned char newk[32])
{
	unsigned int blk, slot;
	ino_to_key(ino, &blk, &slot);
	KeyBlock kb;
	read_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	unsigned char k_old[32];
	prf_k_tau(rs->RS, kb.tag_tau, k_old);
	keyblk_xcrypt(&kb, k_old);

	memcpy(kb.keys[slot], newk, 32);

	unsigned char tmp[12];
	memcpy(tmp, "PUNC", 4);
	unsigned long long t = to_le64(kb.tag_tau);
	memcpy(tmp + 4, &t, 8);
	sha256_bytes(rs->RS, 32, tmp, 12, rs->RS);
	rs->gen++;
	rs->last_tau = kb.tag_tau;

	kb.tag_tau = s->tag_counter++;
	unsigned char k_new[32];
	prf_k_tau(rs->RS, kb.tag_tau, k_new);
	keyblk_xcrypt(&kb, k_new);

	write_all(fd, &kb, sizeof(kb), keyblk_off(s, blk));
	rs_store(fd, s, rs);
	super_write(fd, s);
	sync_fd(fd);
}

/* commands */
void cmd_init(const char *img, unsigned long long size_mib,
	      unsigned int peb_kib, unsigned int inodes)
{
	int fd = open(img, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("open");
	unsigned long long total = size_mib * 1024ull * 1024ull;
	if (ftruncate(fd, total) < 0)
		die("ftruncate");

	crc_init();

	Super s;
	memset(&s, 0, sizeof(s));
	s.magic = SUPER_MAGIC;
	s.version = SUPER_VERSION;
	s.peb_size = peb_kib * 1024u;
	s.total_size = total;
	s.rs_pebs = 3;
	s.inodes = inodes;
	s.tag_counter = 0;
	s.rs_region_off = peb0_off(&s);

	unsigned int keyblk_count = (inodes + 126) / 127;
	s.keyblk_count = keyblk_count;
	unsigned long long key_bytes =
		(unsigned long long)keyblk_count * 4096ull;
	unsigned long long key_bytes_round =
		((key_bytes + s.peb_size - 1) / s.peb_size) * s.peb_size;

	s.keytab_off = rs_off(&s, s.rs_pebs);
	s.keytab_bytes = key_bytes_round;
	s.data_off = s.keytab_off + key_bytes_round;

	if (s.data_off + (unsigned long long)inodes * 4096ull > total) {
		fprintf(stderr, "image too small\n");
		exit(1);
	}

	super_write(fd, &s);

	RSMirror r;
	memset(&r, 0, sizeof(r));
	r.magic = RS_MAGIC;
	r.gen = 1;
	r.last_tau = 0;
	rand_bytes(r.RS, 32);
	r.crc = 0;
	r.crc = crc_calc(&r, sizeof(r));
	rs_store(fd, &s, &r);

	for (unsigned int b = 0; b < keyblk_count; b++) {
		KeyBlock kb;
		memset(&kb, 0, sizeof(kb));
		memcpy(kb.magic, "KEYTABBLK\0\0\0\0\0\0\0\0", 16);
		kb.tag_tau = b;
		for (int i = 0; i < 127; i++)
			rand_bytes(kb.keys[i], 32);
		unsigned char kt[32];
		prf_k_tau(r.RS, kb.tag_tau, kt);
		keyblk_xcrypt(&kb, kt);
		write_all(fd, &kb, sizeof(kb), keyblk_off(&s, b));
		s.tag_counter = b + 1;
	}

	unsigned char zero[4096];
	memset(zero, 0, sizeof(zero));
	for (unsigned int i = 0; i < inodes; i++)
		write_all(fd, zero, sizeof(zero), data_off(&s, i));

	super_write(fd, &s);
	sync_fd(fd);
	close(fd);
	fprintf(stderr, "[init] keyblks=%u inodes=%u\n", keyblk_count, inodes);
}

void cmd_info(const char *img)
{
	int fd = open(img, O_RDONLY);
	if (fd < 0)
		die("open");
	Super s;
	RSMirror r;
	super_read(fd, &s);
	crc_init();
	if (rs_load(fd, &s, &r) != 0)
		die("no rs");
	close(fd);

	printf("size=%llu PEB=%u rs_pebs=%u keytab(off=%llu,bytes=%llu,blocks=%u) data_off=%llu inodes=%u gen=%llu last_tau=%llu next_tau=%llu\n",
	       s.total_size, s.peb_size, s.rs_pebs, s.keytab_off,
	       s.keytab_bytes, s.keyblk_count, s.data_off, s.inodes, r.gen,
	       r.last_tau, s.tag_counter);
}

void cmd_write(const char *img, unsigned int ino, const char *input)
{
	int fd = open(img, O_RDWR);
	if (fd < 0)
		die("open");
	Super s;
	RSMirror r;
	super_read(fd, &s);
	crc_init();
	if (rs_load(fd, &s, &r) != 0)
		die("no rs");
	if (ino >= s.inodes) {
		fprintf(stderr, "inode oob\n");
		exit(1);
	}

	unsigned char key[32];
	get_file_key(fd, &s, &r, ino, key, NULL);

	size_t maxp = 4096 - sizeof(DataHeader);
	unsigned char tmp[4096];
	FILE *f = fopen(input, "rb");
	if (!f)
		die("open input");
	size_t n = fread(tmp, 1, maxp, f);
	fclose(f);
	if (n > maxp) {
		fprintf(stderr, "input too large\n");
		exit(1);
	}

	unsigned char blk[4096];
	memset(blk, 0, sizeof(blk));
	DataHeader *h = (DataHeader *)blk;
	h->inode = ino;
	h->len = (unsigned short)n;
	rand_bytes(&h->nonce, 8);
	memcpy(blk + sizeof(DataHeader), tmp, n);
	xor_stream(blk + sizeof(DataHeader), n, key, h->nonce);

	write_all(fd, blk, 4096, data_off(&s, ino));
	sync_fd(fd);
	close(fd);
	fprintf(stderr, "[write] ino=%u bytes=%zu\n", ino, n);
}

void cmd_read(const char *img, unsigned int ino, const char *out)
{
	int fd = open(img, O_RDONLY);
	if (fd < 0)
		die("open");
	Super s;
	RSMirror r;
	super_read(fd, &s);
	crc_init();
	if (rs_load(fd, &s, &r) != 0)
		die("no rs");
	if (ino >= s.inodes) {
		fprintf(stderr, "inode oob\n");
		exit(1);
	}

	unsigned char key[32];
	get_file_key(fd, &s, &r, ino, key, NULL);

	unsigned char blk[4096];
	read_all(fd, blk, 4096, data_off(&s, ino));
	DataHeader *h = (DataHeader *)blk;
	if (h->inode != ino) {
		fprintf(stderr, "empty/mismatch\n");
		exit(1);
	}
	size_t n = h->len;
	if (n > 4096 - sizeof(DataHeader)) {
		fprintf(stderr, "bad len\n");
		exit(1);
	}
	xor_stream(blk + sizeof(DataHeader), n, key, h->nonce);

	FILE *f = fopen(out, "wb");
	if (!f)
		die("open output");
	fwrite(blk + sizeof(DataHeader), 1, n, f);
	fclose(f);
	close(fd);
	fprintf(stderr, "[read] ino=%u bytes=%zu\n", ino, n);
}

void cmd_delete(const char *img, unsigned int ino)
{
	int fd = open(img, O_RDWR);
	if (fd < 0)
		die("open");
	Super s;
	RSMirror r;
	super_read(fd, &s);
	crc_init();
	if (rs_load(fd, &s, &r) != 0)
		die("no rs");
	if (ino >= s.inodes) {
		fprintf(stderr, "inode oob\n");
		exit(1);
	}

	unsigned char newk[32];
	rand_bytes(newk, 32);
	rotate_key_and_rs(fd, &s, &r, ino, newk);
	close(fd);
	fprintf(stderr, "[delete] ino=%u\n", ino);
}

/* cli */
int eq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage:\n"
			"  %s init <img> --size-mib N --peb-kib K --inodes I\n"
			"  %s info <img>\n"
			"  %s write <img> <inode> <input_file>\n"
			"  %s read  <img> <inode> <output_file>\n"
			"  %s delete <img> <inode>\n",
			argv[0], argv[0], argv[0], argv[0], argv[0]);
		return 1;
	}

	if (eq(argv[1], "init")) {
		const char *img = argv[2];
		unsigned long long size_mib = 64;
		unsigned int peb_kib = 128, inodes = 4096;
		for (int i = 3; i < argc; i++) {
			if (eq(argv[i], "--size-mib") && i + 1 < argc)
				size_mib = strtoull(argv[++i], 0, 10);
			else if (eq(argv[i], "--peb-kib") && i + 1 < argc)
				peb_kib = strtoul(argv[++i], 0, 10);
			else if (eq(argv[i], "--inodes") && i + 1 < argc)
				inodes = strtoul(argv[++i], 0, 10);
		}
		cmd_init(img, size_mib, peb_kib, inodes);
	} else if (eq(argv[1], "info")) {
		cmd_info(argv[2]);
	} else if (eq(argv[1], "write") && argc >= 5) {
		cmd_write(argv[2], (unsigned int)strtoul(argv[3], 0, 10),
			  argv[4]);
	} else if (eq(argv[1], "read") && argc >= 5) {
		cmd_read(argv[2], (unsigned int)strtoul(argv[3], 0, 10),
			 argv[4]);
	} else if (eq(argv[1], "delete") && argc >= 5) {
		cmd_delete(argv[2], (unsigned int)strtoul(argv[3], 0, 10));
	} else {
		fprintf(stderr, "bad args\n");
		return 1;
	}
	return 0;
}