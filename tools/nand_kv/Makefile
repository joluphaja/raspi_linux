# SPDX-License-Identifier: GPL-2.0-only
include ../scripts/Makefile.include

bindir ?= /usr/bin

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

# Do not use make's built-in rules
# (this improves performance and avoids hard-to-debug behaviour);
MAKEFLAGS += -r

CFLAGS += -O2 -Wall -Wextra -g -D_GNU_SOURCE -I$(OUTPUT)include

ALL_TARGETS := nand-kv
ALL_PROGRAMS := $(patsubst %,$(OUTPUT)%,$(ALL_TARGETS))

all: $(ALL_PROGRAMS)

export srctree OUTPUT CC LD CFLAGS
include $(srctree)/tools/build/Makefile.include

# Prepare uapi header link for userspace build
$(OUTPUT)include/linux: ; mkdir -p $@
$(OUTPUT)include/linux/nand_kv.h: ../../include/uapi/linux/nand_kv.h | $(OUTPUT)include/linux
	ln -sf $(CURDIR)/../../include/uapi/linux/nand_kv.h $@

prepare: $(OUTPUT)include/linux/nand_kv.h

# nand-kv utility
NAND_KV_IN := $(OUTPUT)nand-kv-in.o
$(NAND_KV_IN): prepare FORCE
	$(Q)$(MAKE) $(build)=nand_kv_util
$(OUTPUT)nand-kv: $(NAND_KV_IN)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f $(ALL_PROGRAMS)
	rm -rf $(OUTPUT)include/
	find $(or $(OUTPUT),.) -name '*.o' -delete
	find $(or $(OUTPUT),.) -name '\.*.o.d' -delete
	find $(or $(OUTPUT),.) -name '\.*.o.cmd' -delete

install: $(ALL_PROGRAMS)
	install -d -m 755 $(DESTDIR)$(bindir); \
	for program in $(ALL_PROGRAMS); do \
		install $$program $(DESTDIR)$(bindir); \
	done

FORCE:

.PHONY: all install clean FORCE prepare
