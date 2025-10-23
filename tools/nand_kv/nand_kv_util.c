// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/nand_kv.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s write  -i <inode> -f <file> [-n <nonce>] [--plain]\n"
		"  %s read   -i <inode> [-o <out>] [-n <nonce>] [--plain] [--two-phase]\n"
		"  %s delete -i <inode>\n"
		"  %s stat   -i <inode>\n"
		, prog, prog, prog, prog);
}

static int do_delete(int fd, uint32_t inode)
{
	if (ioctl(fd, NAND_KV_IOC_DELETE, &inode) < 0) {
		perror("ioctl(DELETE)");
		return -1;
	}
	return 0;
}

static int read_all(int fd, uint32_t inode, uint64_t nonce, bool plain,
			const char *out_path, bool two_phase)
{
	struct nand_kv_rw rw = {
		.inode = inode,
		.len = 0,
		.nonce = nonce,
		.buf = 0,
		.flags = plain ? NAND_KV_F_PLAIN : 0,
	};
	int outfd = -1;
	int ret = -1;
	uint8_t *buf = NULL;

	if (two_phase || !out_path) {
		/* Phase 1: header-only to get length */
		if (ioctl(fd, NAND_KV_IOC_READ, &rw) < 0) {
			perror("ioctl(READ header)");
			goto out;
		}
		if (rw.len == 0) {
			fprintf(stderr, "inode %u: empty length returned (0)\n", inode);
			goto out;
		}
	}

	if (out_path) {
		outfd = strcmp(out_path, "-") == 0 ? STDOUT_FILENO : open(out_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (outfd < 0) {
			perror("open(out)");
			goto out;
		}
	}

	buf = malloc(rw.len);
	if (!buf) {
		perror("malloc");
		goto out;
	}

	rw.buf = (uintptr_t)buf;
	if (ioctl(fd, NAND_KV_IOC_READ, &rw) < 0) {
		perror("ioctl(READ)");
		goto out;
	}

	if (!out_path) {
		/* print size and hex preview */
		printf("len=%u\n", rw.len);
		ret = 0;
		goto out;
	}

	/* write output */
	{
		ssize_t wr = write(outfd, buf, rw.len);
		if (wr < 0 || (uint32_t)wr != rw.len) {
			perror("write(out)");
			goto out;
		}
	}

	ret = 0;

out:
	if (buf)
		free(buf);
	if (outfd > 0 && outfd != STDOUT_FILENO)
		close(outfd);
	return ret;
}

static int write_all(int fd, uint32_t inode, uint64_t nonce, bool plain, const char *file)
{
	int infd = -1;
	struct stat st;
	uint8_t *buf = NULL;
	struct nand_kv_rw rw = {
		.inode = inode,
		.nonce = nonce,
		.flags = plain ? NAND_KV_F_PLAIN : 0,
	};
	int ret = -1;

	infd = strcmp(file, "-") == 0 ? STDIN_FILENO : open(file, O_RDONLY);
	if (infd < 0) {
		perror("open(in)");
		goto out;
	}
	if (infd != STDIN_FILENO && fstat(infd, &st) < 0) {
		perror("fstat(in)");
		goto out;
	}

	off_t size = 0;
	if (infd == STDIN_FILENO) {
		/* read stdin to buffer */
		size_t cap = 64 * 1024;
		size_t used = 0;
		buf = malloc(cap);
		if (!buf) {
			perror("malloc");
			goto out;
		}
		for (;;) {
			if (used == cap) {
				cap *= 2;
				uint8_t *nb = realloc(buf, cap);
				if (!nb) {
					perror("realloc");
					goto out;
				}
				buf = nb;
			}
			ssize_t rd = read(STDIN_FILENO, buf + used, cap - used);
			if (rd < 0) {
				perror("read(stdin)");
				goto out;
			}
			if (rd == 0)
				break;
			used += rd;
		}
		size = used;
	} else {
		size = st.st_size;
		buf = malloc(size);
		if (!buf) {
			perror("malloc");
			goto out;
		}
		ssize_t rd = read(infd, buf, size);
		if (rd < 0 || rd != size) {
			perror("read(in)");
			goto out;
		}
	}

	rw.len = size;
	rw.buf = (uintptr_t)buf;
	if (ioctl(fd, NAND_KV_IOC_WRITE, &rw) < 0) {
		perror("ioctl(WRITE)");
		goto out;
	}

	ret = 0;

out:
	if (buf)
		free(buf);
	if (infd > 0 && infd != STDIN_FILENO)
		close(infd);
	return ret;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];
	uint32_t inode = 0;
	uint64_t nonce = 0;
	bool plain = false;
	const char *in_path = NULL;
	const char *out_path = NULL;
	bool two_phase = false;
	int fd;

	static const struct option long_opts[] = {
		{"inode", required_argument, NULL, 'i'},
		{"file", required_argument, NULL, 'f'},
		{"out", required_argument, NULL, 'o'},
		{"nonce", required_argument, NULL, 'n'},
		{"plain", no_argument, NULL, 'p'},
		{"two-phase", no_argument, NULL, 't'},
		{0, 0, 0, 0}
	};

	int c, longidx;
	optind = 2; /* start parsing after subcommand */
	while ((c = getopt_long(argc, argv, "i:f:o:n:pt", long_opts, &longidx)) != -1) {
		switch (c) {
		case 'i': inode = strtoul(optarg, NULL, 0); break;
		case 'f': in_path = optarg; break;
		case 'o': out_path = optarg; break;
		case 'n': nonce = strtoull(optarg, NULL, 0); break;
		case 'p': plain = true; break;
		case 't': two_phase = true; break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	fd = open("/dev/nand_kv", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/nand_kv)");
		return 1;
	}

	int ret = 1;
	if (strcmp(cmd, "delete") == 0) {
		if (!inode) { fprintf(stderr, "-i <inode> required\n"); goto out; }
		ret = do_delete(fd, inode);
	} else if (strcmp(cmd, "write") == 0) {
		if (!inode || !in_path) { fprintf(stderr, "-i <inode> and -f <file> required\n"); goto out; }
		ret = write_all(fd, inode, nonce, plain, in_path);
	} else if (strcmp(cmd, "read") == 0) {
		if (!inode) { fprintf(stderr, "-i <inode> required\n"); goto out; }
		ret = read_all(fd, inode, nonce, plain, out_path ? out_path : "-", two_phase);
	} else if (strcmp(cmd, "stat") == 0) {
		if (!inode) { fprintf(stderr, "-i <inode> required\n"); goto out; }
		ret = read_all(fd, inode, nonce, plain, NULL, true);
	} else {
		usage(argv[0]);
	}

out:
	close(fd);
	return ret ? 1 : 0;
}
