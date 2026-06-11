# ConAnchor eBPF MVP

ConAnchor is an early runtime security event collector prototype. This stage collects container-related security events with eBPF LSM hooks and prints structured JSONL logs that can later feed a log integrity verification layer.

This MVP does not implement Merkle trees, blockchain anchoring, or event blocking.

## LSM Hooks

- `bprm_check_security`: observes process execution. The MVP detects `wget` execution, including common paths such as `/usr/bin/wget` and `/bin/wget`.
- `file_open`: observes file opens. The MVP detects access to Kubernetes Secret service-account files under `/var/run/secrets/`, including `token`, `ca.crt`, and `namespace`.
- `sb_mount`: observes mount attempts. Mount is useful for container escape detection because exposing `/proc`, `/sys`, cgroup filesystems, host paths, or overlay/cgroup filesystems can weaken the container boundary.

## Container Identity

Events include `cgroup_id` from `bpf_get_current_cgroup_id()`. For this MVP, `cgroup_id` is the only kernel-collected container correlation key. The collector can also configure a kernel-side cgroup allowlist so the eBPF programs emit events only for selected target container cgroup IDs.

The user-space resolver reads `/proc/<pid>/cgroup` and extracts containerd/Kubernetes style IDs on a best-effort basis:

- `cri-containerd-<container-id>.scope`
- `kubepods.slice/.../cri-containerd-<container-id>.scope`
- `kubepods-burstable-pod<poduid>.slice/cri-containerd-<container-id>.scope`
- `kubepods-pod<poduid>.slice:cri-containerd:<container-id>`

If no supported ID is found, both `container_id` and `container_instance_id` are set to `host-or-unknown`. Docker style cgroup paths are intentionally not supported in this version.

`mnt_ns_id` and `pid_ns_id` are excluded to keep the MVP simple and focused on the requested `event -> cgroup_id -> container_id` flow.

## Build

Requirements:

- Linux with BTF available at `/sys/kernel/btf/vmlinux`
- LSM BPF enabled kernel
- `clang`, `bpftool`, `make`, and Go
- root or sufficient capabilities to attach BPF LSM programs

Generate BPF bindings:

```sh
make generate
```

Build the collector:

```sh
make build
```

Run:

```sh
sudo ./bin/collector
```

or:

```sh
make run
```

To record events only for one target container cgroup ID, pass the decimal `cgroup_id` captured from a previous event or obtained from your runtime/cgroup inspection:

```sh
sudo ./bin/collector -target-cgroup-id 123456789
```

Multiple targets can be comma-separated:

```sh
sudo ./bin/collector -target-cgroup-id 123456789,987654321
```

The same value can be configured with `CONANCHOR_TARGET_CGROUP_ID`. When no target is configured, the kernel program monitors all cgroups.

## Example Output

```json
{"timestamp_ns":1710000000000000000,"event_type":"exec","pid":1234,"tgid":1234,"uid":0,"gid":0,"comm":"wget","path":"/usr/bin/wget","extra":"","flags":0,"retval":0,"cgroup_id":"123456789","container_id":"cri-containerd-abc123","container_instance_id":"cri-containerd-abc123","risk":"high","policy":"wget-exec"}
```

Expected triggers:

```sh
wget http://example.com/test
cat /var/run/secrets/kubernetes.io/serviceaccount/token
mount -t proc proc /somewhere
```

## Current Limits

- This stage is a log collection MVP. Merkle tree and blockchain anchoring are not implemented yet.
- LSM BPF requires kernel support and appropriate privileges.
- Container ID resolution is best-effort parsing of containerd/Kubernetes cgroup paths.
- Docker style cgroup paths are not supported in this version.
- Mount namespace and PID namespace based identification are excluded in this version.
- If the kernel is compromised, an attacker may hide evidence before eBPF observes it.
- The implementation is for detection and logging. Blocking policy is not implemented yet.
- Kernel-side path filtering can be limited by verifier constraints, so some filtering and classification is also performed in user space.
- `file_open` and `sb_mount` path collection use `bpf_d_path`, which may vary across kernel versions and BPF verifier behavior.

## Integrity Pipeline

ConAnchor now includes a tamper-evident integrity pipeline for collected runtime logs:

```text
eBPF event -> collector -> cgroup_id container context -> LogEntry -> sequence numbers -> per-log SHA-256 tag -> per-container batch -> Merkle root -> per-container batch hash chain -> file-backed mock private blockchain ledger
```

The eBPF kernel program only observes events and emits `cgroup_id`. Hashing, Merkle root construction, batch hash chaining, off-chain storage, and ledger anchoring are all performed in user space.

## Threat Model

This implementation is tamper-evident, not tamper-proof. It does not prevent an attacker from modifying off-chain log files after storage, but the verifier can detect modification, deletion, insertion, reordering, rollback, and ledger chain tampering when anchors remain intact.

If the kernel is compromised before eBPF observes an event, or if a malicious collector intentionally omits or fabricates events before hashing, this MVP cannot fully solve that problem.

## Raw Logs And Anchors

Raw logs are stored off-chain as JSONL:

```text
data/logs/<container_instance_id>.jsonl
```

Batch metadata is stored off-chain:

```text
data/batches/<container_instance_id>/batch_<batch_id>.json
```

The mock ledger stores only cryptographic commitments, not raw logs:

```text
data/ledger/mock_chain.jsonl
```

## Sequence Numbers

Each `LogEntry` has two sequence numbers:

- `global_seq`: monotonic across the whole collector
- `container_seq`: monotonic per `container_instance_id`

The verifier uses these values to detect missing or reordered logs.

## Hashes, Merkle Roots, And Batch Chains

Each log is deterministically serialized with fixed field ordering and hashed with SHA-256. Per-container batches use those log hashes as Merkle leaves. Each batch also includes `previous_container_batch_hash`, creating an independent hash chain per container. The first previous hash is `GENESIS`.

## Mock Private Blockchain Ledger

The current ledger is a file-backed mock private blockchain. Each appended block includes height, timestamp, previous block hash, block hash, and an anchor record. It is append-only by API design and is verified by recomputing the block hash chain.

A real private blockchain integration can replace this mock ledger later, for example with Hyperledger Fabric or another permissioned blockchain backend.

## Collector Integrity Flags

```sh
sudo ./bin/collector \
  --data-dir ./data \
  --batch-size 10 \
  --collector-id collector-1
```

The collector still prints event JSONL to stdout, and additionally stores raw logs, finalizes batches, and anchors batch commitments to the mock ledger. On SIGINT/SIGTERM it flushes partial batches.

## Verifier

Verify a container's anchored batches:

```sh
go run ./cmd/verifier \
  --data-dir ./data \
  --container-instance-id demo-container \
  --from-batch 1 \
  --to-batch 3
```

An untampered run returns `status: "OK"`. A tampered run returns `status: "FAILED"` with failure types such as `MERKLE_ROOT_MISMATCH`, `EVENT_COUNT_MISMATCH`, `SEQUENCE_GAP`, `BATCH_HASH_MISMATCH`, or `LEDGER_CHAIN_INVALID`.

## Demo Attack Simulation

Generate synthetic logs without eBPF:

```sh
make demo-generate
make demo-verify
```

Simulate attacks:

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

The first verification should be `OK`; after the attack it should be `FAILED`.

## Integrity Limits

- This implementation provides tamper-evident logging, not tamper-proof logging.
- It does not prevent log tampering, but it can verify whether stored logs changed after anchoring.
- If kernel compromise occurs before eBPF collects an event, this may not detect it.
- A malicious collector fabricating logs or intentionally omitting events is not fully solved.
- The current ledger is a file-backed mock ledger, not a real private blockchain.
- Actual private blockchain integration is future work, for example Hyperledger Fabric or another permissioned blockchain backend.
- Raw logs are stored off-chain; the ledger stores only cryptographic commitments.

## Workflow Logging For Presentations

For slide demos, enable human-readable workflow logs with `--workflow-log`. These logs are written to stderr and are emitted only when a container batch is finalized. For example, with `--batch-size 5`, the first workflow appears on the 5th matching event.

```sh
go run ./cmd/demo generate \
  --data-dir /tmp/conanchor-workflow-log \
  --container-id demo-container \
  --count 5 \
  --batch-size 5 \
  --workflow-log
```

Example steps:

```text
[workflow 01/10] synthetic eBPF event source initialized
[workflow 02/10] container context resolved
[workflow 03/10] normalized LogEntry created
[workflow 04/10] sequence assigned
[workflow 05/10] raw log stored off-chain
[workflow 06/10] per-log SHA-256 tag generated
[workflow 07/10] per-container batch finalized
[workflow 08/10] Merkle root generated
[workflow 09/10] container batch hash chain updated
[workflow 10/10] anchor record appended to mock private blockchain ledger
```

The real collector supports the same option:

```sh
sudo ./bin/collector \
  --data-dir ./data \
  --batch-size 10 \
  --collector-id collector-1 \
  --workflow-log
```

## Besu Private Blockchain Backend

ConAnchor can now use Hyperledger Besu as the ledger backend instead of the local mock ledger. Raw logs still remain off-chain under `data/logs`; Besu stores only anchor commitments through `contracts/AnchorRegistry.sol`.

Besu-backed flow:

```text
LogEntry batch -> Merkle root -> container batch hash -> AnchorRegistry smart contract -> Besu transaction/block
```

Run a local Besu dev node:

```sh
./scripts/besu/start_besu_dev.sh ./data/besu-node-1 8545 8546 30303 conanchor-besu-node-1
```

Compile and deploy the anchor contract with `solc` and Foundry `cast`:

```sh
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_PRIVATE_KEY=<funded-private-key>
./scripts/besu/deploy_anchor_registry.sh
```

Run collector with Besu anchoring:

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

The existing `mock` backend remains the default for local demos and tests.
