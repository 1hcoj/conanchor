BINARY := bin/collector
BPF_SRC := ../../bpf/conanchor.bpf.c
BPF_HEADERS := ../../bpf
VMLINUX := bpf/vmlinux.h
ARCH ?= x86

.PHONY: generate build run clean

generate: $(VMLINUX)
	cd cmd/collector && go run github.com/cilium/ebpf/cmd/bpf2go \
		-target bpfel,bpfeb \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_$(ARCH)" \
		-go-package main \
		conanchor $(BPF_SRC) -- -I$(BPF_HEADERS)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

build:
	go build -o $(BINARY) ./cmd/collector

run: build
	sudo ./$(BINARY)

clean:
	rm -rf bin
	rm -f cmd/collector/conanchor_bpfel.go cmd/collector/conanchor_bpfeb.go
	rm -f cmd/collector/conanchor_bpfel.o cmd/collector/conanchor_bpfeb.o
	rm -f $(VMLINUX)
