# Build the CheckPoint Zero BPF LSM checkpoint.
# Needs: clang/llvm >= 12, bpftool, libbpf-dev, a kernel with BTF (/sys/kernel/btf/vmlinux) and CONFIG_BPF_LSM=y.
# Run:   sudo ./checkpoint-loader [--enforce]

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CLANG ?= clang
BPFTOOL ?= bpftool

all: checkpoint-loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

checkpoint.bpf.o: checkpoint.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

checkpoint.skel.h: checkpoint.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

checkpoint-loader: checkpoint_loader.c checkpoint.skel.h
	$(CC) -O2 -Wall -o $@ $< -lbpf -lelf -lz

clean:
	rm -f vmlinux.h checkpoint.bpf.o checkpoint.skel.h checkpoint-loader

.PHONY: all clean
