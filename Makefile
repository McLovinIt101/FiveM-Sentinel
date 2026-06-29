# FiveM-Sentinel build
#
# Targets:
#   make            build the BPF object and the `sentinel` control-plane binary
#   make vmlinux    (re)generate tools/vmlinux.h from the running kernel's BTF
#   make install    install the binary to /usr/local/sbin
#   make clean      remove the build/ directory
#
# Requirements (Debian/Ubuntu): clang llvm libbpf-dev libelf-dev zlib1g-dev
#                               bpftool linux-headers, kernel 6.8+ with BTF.

CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc

SRC   := src
TOOLS := tools
OUT   := build

VMLINUX  := $(TOOLS)/vmlinux.h
BPF_SRC  := $(SRC)/sentinel.bpf.c
BPF_OBJ  := $(OUT)/sentinel.bpf.o
SKEL     := $(OUT)/sentinel.skel.h
USER_SRC := $(SRC)/sentinel.c
BIN      := $(OUT)/sentinel

# Map `uname -m` to the __TARGET_ARCH_* clang expects for CO-RE.
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/;s/s390x/s390/;s/armv7.*/arm/')

CFLAGS     ?= -O2 -g -Wall -Wextra
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC) -I$(TOOLS)
LDLIBS     := -lbpf -lelf -lz

.PHONY: all vmlinux install clean

all: $(BIN)

$(OUT):
	mkdir -p $(OUT)

# 1. Kernel type definitions for CO-RE. Generated once, then reused (delete the
#    file or run `make vmlinux` to refresh it for a different kernel).
$(VMLINUX):
	@mkdir -p $(TOOLS)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux:
	@mkdir -p $(TOOLS)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# 2. Compile the XDP data plane to a BPF object (keeps BTF for CO-RE).
$(BPF_OBJ): $(BPF_SRC) $(SRC)/sentinel.h $(VMLINUX) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

# 3. Generate the libbpf skeleton consumed by the control plane.
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name sentinel > $@

# 4. Build the userspace control plane.
$(BIN): $(USER_SRC) $(SKEL) $(SRC)/sentinel.h | $(OUT)
	$(CC) $(CFLAGS) -I$(OUT) -I$(SRC) $(USER_SRC) -o $@ $(LDLIBS)

install: $(BIN)
	install -d /usr/local/sbin
	install -m0755 $(BIN) /usr/local/sbin/sentinel

clean:
	rm -rf $(OUT)
