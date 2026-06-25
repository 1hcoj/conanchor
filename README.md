# ConAnchor eBPF

[Korean README](./README.ko.md)

ConAnchor is a runtime security log integrity verification system for container environments. The current system is designed to collect logs with a simple eBPF program, but its final goal is to integrate with production CNCF tools such as Falco or Tetragon and guarantee the integrity of the collected logs.

The core purpose of this project is to create evidence that can detect log tampering. ConAnchor stores that evidence on a blockchain and later verifies whether logs have been damaged through modification, deletion, or similar tampering.

## Architecture

![architecture](./conanchor-architecture.png)

## Build & Usage

### Requirements

- Linux with BTF available at `/sys/kernel/btf/vmlinux`
- Kernel support for BPF LSM
- `clang`, `bpftool`, `make`, and Go
- Root privileges or sufficient capabilities to attach BPF LSM programs

### Build

Generate BPF bindings:

```sh
make generate
```

Build the collector:

```sh
make build
```

### Run The Collector

Run with default local mock ledger settings:

```sh
sudo ./bin/collector
```

or:

```sh
make run
```

Monitor only selected container cgroups:

```sh
sudo ./bin/collector -target-cgroup-id 123456789
```

Multiple cgroup IDs can be comma-separated.

```sh
sudo ./bin/collector -target-cgroup-id 123456789,987654321
```

The same value can be configured with `CONANCHOR_TARGET_CGROUP_ID`. If no target is configured, the collector monitors all cgroups.

### Runtime Event Coverage

The current collector observes the following events.

- `bprm_check_security`: detects `wget` execution
- `file_open`: detects access to Kubernetes service-account secret paths under `/var/run/secrets/` and `/run/secrets/`
- `sb_mount`: detects suspicious mount attempts involving `/proc`, `/sys`, `/host`, `/mnt`, `/var/run`, `proc`, `sysfs`, `cgroup`, `cgroup2`, `overlay`, and related paths or filesystems

### Example Output

```json
{"timestamp_ns":1710000000000000000,"event_type":"exec","pid":1234,"tgid":1234,"uid":0,"gid":0,"comm":"wget","path":"/usr/bin/wget","extra":"","flags":0,"retval":0,"cgroup_id":"123456789","container_id":"cri-containerd-abc123","container_instance_id":"cri-containerd-abc123","risk":"high","policy":"wget-exec"}
```

Example triggers:

```sh
wget http://example.com/test
cat /var/run/secrets/kubernetes.io/serviceaccount/token
mount -t proc proc /somewhere
```

### Stored Data

Raw logs are stored off-chain.

```text
data/logs/<container_instance_id>.jsonl
```

Batch metadata is stored off-chain.

```text
data/batches/<container_instance_id>/batch_<batch_id>.json
```

The mock ledger stores anchor records.

```text
data/ledger/mock_chain.jsonl
```

### Collector Integrity Options

```sh
sudo ./bin/collector \
  --data-dir ./data \
  --batch-size 10 \
  --collector-id collector-1
```

The collector prints event JSONL to stdout, stores raw logs, finalizes batches, and anchors batch commitments. On `SIGINT` or `SIGTERM`, it flushes partial batches.

Human-readable progress logs can be enabled for presentations or demo workflows.

```sh
sudo ./bin/collector \
  --data-dir ./data \
  --batch-size 10 \
  --collector-id collector-1 \
  --workflow-log
```

### Verify Anchored Logs

```sh
go run ./cmd/verifier \
  --data-dir ./data \
  --container-instance-id demo-container \
  --from-batch 1 \
  --to-batch 3
```

If the logs have not been tampered with, the verifier returns `status: "OK"`. If tampering is detected, it returns `status: "FAILED"` with failure types such as `MERKLE_ROOT_MISMATCH`, `EVENT_COUNT_MISMATCH`, `SEQUENCE_GAP`, `BATCH_HASH_MISMATCH`, or `LEDGER_CHAIN_INVALID`.

### Demo Attack Simulation

Generate synthetic logs without eBPF:

```sh
make demo-generate
make demo-verify
```

Attack simulation:

```sh
make demo-attack-modify
make demo-attack-delete
make demo-attack-insert
make demo-attack-reorder
make demo-attack-rollback
```

Example workflow:

```sh
make demo-generate
make demo-verify
make demo-attack-modify
make demo-verify
```

The first verification should be `OK`, and the verification after the attack should be `FAILED`.

### Besu Ledger Backend

ConAnchor can use Hyperledger Besu instead of the local mock ledger. Raw logs remain off-chain under `data/logs`, and Besu stores only anchor commitments through `contracts/AnchorRegistry.sol`.

Run a local Besu dev node:

```sh
./scripts/besu/start_besu_dev.sh ./data/besu-node-1 8545 8546 30303 conanchor-besu-node-1
```

Compile and deploy the anchor contract:

```sh
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_PRIVATE_KEY=<funded-private-key>
./scripts/besu/deploy_anchor_registry.sh
```

Run the collector with Besu anchoring:

```sh
sudo CONANCHOR_BESU_PRIVATE_KEY=$BESU_PRIVATE_KEY ./bin/collector \
  --ledger-backend besu \
  --besu-rpc-url http://127.0.0.1:8545 \
  --besu-chain-id 0 \
  --besu-contract-address <AnchorRegistry-address> \
  --target-cgroup-id 49396 \
  --data-dir ./data \
  --batch-size 1 \
  --collector-id collector-1 \
  --workflow-log
```

Verify against Besu anchors:

```sh
LEDGER_BACKEND=besu \
BESU_RPC_URL=http://127.0.0.1:8545 \
BESU_CONTRACT_ADDRESS=<AnchorRegistry-address> \
./scripts/verify_with_ledger.sh ./data <container_instance_id> 1 0
```
