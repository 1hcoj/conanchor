# ConAnchor eBPF MVP

ConAnchor is an early runtime security event collector prototype. This stage collects container-related security events with eBPF LSM hooks and prints structured JSONL logs that can later feed a log integrity verification layer.

This MVP does not implement Merkle trees, blockchain anchoring, or event blocking.

## LSM Hooks

- `bprm_check_security`: observes process execution. The MVP detects `wget` execution, including common paths such as `/usr/bin/wget` and `/bin/wget`.
- `file_open`: observes file opens. The MVP detects access to Kubernetes Secret service-account files under `/var/run/secrets/`, including `token`, `ca.crt`, and `namespace`.
- `sb_mount`: observes mount attempts. Mount is useful for container escape detection because exposing `/proc`, `/sys`, cgroup filesystems, host paths, or overlay/cgroup filesystems can weaken the container boundary.

## Container Identity

Events include `cgroup_id` from `bpf_get_current_cgroup_id()`. For this MVP, `cgroup_id` is the only kernel-collected container correlation key.

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
