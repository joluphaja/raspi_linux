/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RS_LOADER_H
#define _LINUX_RS_LOADER_H

#include <linux/types.h>

#define RS_SEED_LEN 16

struct rs_entry {
	u16 d; /* prefix length in bits */
	u8 *prefix; /* kmalloc'ed, size ceil(d/8) */
	u8 seed[RS_SEED_LEN]; /* AES-128 seed */
};

struct rs_state {
	u32 n; /* number of entries */
	u16 m; /* domain bit length (runtime param) */
	struct rs_entry *entries; /* array of n entries */
};

/* Returns NULL if not yet loaded */
const struct rs_state *rs_get_state(void);

#endif /* _LINUX_RS_LOADER_H */
