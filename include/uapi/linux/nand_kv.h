/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_LINUX_NAND_KV_H
#define _UAPI_LINUX_NAND_KV_H

#include <linux/types.h>

#define NAND_KV_IOC_MAGIC 'K'

struct nand_kv_rw {
	__u32 inode; /* file index */
	__u32 len; /* bytes to write/read */
	__u64 nonce; /* 0 => plaintext; non-zero used for encryption */
	__u64 buf; /* userspace pointer to data */
	__u32 flags; /* NAND_KV_F_* */
	__u32 reserved;
};

#define NAND_KV_F_PLAIN 0x00000001 /* treat as plaintext */

#define NAND_KV_IOC_WRITE _IOW(NAND_KV_IOC_MAGIC, 1, struct nand_kv_rw)
#define NAND_KV_IOC_READ _IOWR(NAND_KV_IOC_MAGIC, 2, struct nand_kv_rw)
#define NAND_KV_IOC_DELETE _IOW(NAND_KV_IOC_MAGIC, 3, __u32 /* inode */)

#endif /* _UAPI_LINUX_NAND_KV_H */
