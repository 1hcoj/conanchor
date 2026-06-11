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

test:
	go test ./...

demo-generate:
	rm -rf ./data
	go run ./cmd/demo generate --data-dir ./data --container-id demo-container --count 30 --batch-size 10 --workflow-log

demo-verify:
	go run ./cmd/verifier --data-dir ./data --container-instance-id demo-container --from-batch 1 --to-batch 3

demo-attack-modify:
	go run ./cmd/demo attack --data-dir ./data --container-id demo-container --type modify-log

demo-attack-delete:
	go run ./cmd/demo attack --data-dir ./data --container-id demo-container --type delete-log

demo-attack-insert:
	go run ./cmd/demo attack --data-dir ./data --container-id demo-container --type insert-log

demo-attack-reorder:
	go run ./cmd/demo attack --data-dir ./data --container-id demo-container --type reorder-log

demo-attack-rollback:
	go run ./cmd/demo attack --data-dir ./data --container-id demo-container --type rollback-container
