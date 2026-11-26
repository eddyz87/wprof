# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
.DEFAULT_GOAL := all

KERNEL_TAGS := v6.16 v6.18
KERNEL_TARGETS := $(addprefix kernel-,$(KERNEL_TAGS))
COMMON_CONFIGS := kernel/vm.config kernel/features.config
CACHE_DIR ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/wprof-selftests
KERNEL_REPO ?= https://github.com/torvalds/linux.git

ifeq ($(strip $(CACHE_DIR)),)
$(error CACHE_DIR must name a directory)
endif

.PHONY: all wprof kernels list-kernel-tags $(KERNEL_TARGETS)
all: wprof kernels

wprof:
	$(MAKE) -C ../src -j wprof

kernels: $(KERNEL_TARGETS)

list-kernel-tags:
	@printf '%s\n' $(KERNEL_TAGS)

kernel-v6.16: revision := 038d61fd642278bab63ee8ef722c50d10ab01e8f
kernel-v6.16: configs := $(COMMON_CONFIGS) kernel/v6.16/autofdo.config
kernel-v6.16: profile := kernel/v6.16/vfs_write.prof
kernel-v6.16: features := vfs-write-inlined

kernel-v6.18: revision := 7d0a66e4bb9081d75c82ec4957c50034cb0ea449
kernel-v6.18: configs := $(COMMON_CONFIGS)
kernel-v6.18: profile :=
kernel-v6.18: features :=

$(KERNEL_TARGETS): kernel-%:
	@./ci/build-kernels.sh "$(CACHE_DIR)" "$*" "$(KERNEL_REPO)" "$(revision)" "$(profile)" "$(features)" $(configs)

CLEAN_KERNELS := $(addprefix clean-,$(KERNEL_TARGETS))
.PHONY: clean clean-kernels clean-sources clean-all $(CLEAN_KERNELS)

$(CLEAN_KERNELS): clean-kernel-%:
	rm -rf -- "$(CACHE_DIR)/bundles/$*"

clean-kernels: $(CLEAN_KERNELS)

clean-sources:
	rm -rf -- $(foreach tag,$(KERNEL_TAGS),"$(CACHE_DIR)/linux-$(tag)")

clean: clean-kernels
	$(MAKE) -C ../src clean

clean-all: clean-kernels clean-sources
	$(MAKE) -C ../src clean-all
