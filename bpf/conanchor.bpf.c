#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "conanchor.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct event *evt, __u32 event_type, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->event_type = event_type;
	evt->pid = (__u32)pid_tgid;
	evt->tgid = pid_tgid >> 32;
	evt->uid = (__u32)uid_gid;
	evt->gid = uid_gid >> 32;
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->retval = ret;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

static __always_inline int starts_with(const char *s, const char *prefix, int prefix_len)
{
#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (i >= prefix_len)
			return 1;
		if (s[i] != prefix[i])
			return 0;
	}
	return 0;
}

static __always_inline int contains_wget(const char *s)
{
#pragma unroll
	for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
		if (s[i] == 0)
			return 0;
		if (s[i] == 'w' && s[i + 1] == 'g' && s[i + 2] == 'e' && s[i + 3] == 't')
			return 1;
	}
	return 0;
}

static __always_inline int path_is_k8s_secret(const char *path)
{
	const char prefix[] = "/var/run/secrets/";

	return starts_with(path, prefix, sizeof(prefix) - 1);
}

static __always_inline int target_is_suspicious(const char *path)
{
	const char proc_prefix[] = "/proc";
	const char sys_prefix[] = "/sys";
	const char host_prefix[] = "/host";
	const char mnt_prefix[] = "/mnt";
	const char varrun_prefix[] = "/var/run";

	if (starts_with(path, proc_prefix, sizeof(proc_prefix) - 1))
		return 1;
	if (starts_with(path, sys_prefix, sizeof(sys_prefix) - 1))
		return 1;
	if (starts_with(path, host_prefix, sizeof(host_prefix) - 1))
		return 1;
	if (starts_with(path, mnt_prefix, sizeof(mnt_prefix) - 1))
		return 1;
	if (starts_with(path, varrun_prefix, sizeof(varrun_prefix) - 1))
		return 1;
	return 0;
}

static __always_inline int fs_name_is_suspicious(const char *fs)
{
	if (starts_with(fs, "proc", 4))
		return 1;
	if (starts_with(fs, "sysfs", 5))
		return 1;
	if (starts_with(fs, "cgroup", 6))
		return 1;
	if (starts_with(fs, "cgroup2", 7))
		return 1;
	if (starts_with(fs, "overlay", 7))
		return 1;
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	const char *filename = NULL;
	char path[MAX_PATH_LEN] = {};

	if (ret)
		return ret;

	filename = BPF_CORE_READ(bprm, filename);
	if (filename)
		bpf_probe_read_kernel_str(path, sizeof(path), filename);

	if (!contains_wget(path))
		return ret;

	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return ret;

	fill_common(evt, EVENT_EXEC, ret);
	__builtin_memcpy(evt->path, path, sizeof(evt->path));
	bpf_ringbuf_submit(evt, 0);
	return ret;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	char path[MAX_PATH_LEN] = {};
	__u32 f_flags = 0;

	if (ret)
		return ret;

	if (file) {
		struct path *f_path = &file->f_path;
		bpf_d_path(f_path, path, sizeof(path));
		f_flags = BPF_CORE_READ(file, f_flags);
	}

	if (!path_is_k8s_secret(path))
		return ret;

	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return ret;

	fill_common(evt, EVENT_FILE_OPEN, ret);
	__builtin_memcpy(evt->path, path, sizeof(evt->path));
	evt->flags = f_flags;
	bpf_ringbuf_submit(evt, 0);
	return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(handle_sb_mount, const char *dev_name, const struct path *path, const char *type,
	     unsigned long flags, void *data, int ret)
{
	int suspicious = 0;

	if (ret)
		return ret;

	struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return ret;

	fill_common(evt, EVENT_MOUNT, ret);
	if (path)
		bpf_d_path((struct path *)path, evt->path, sizeof(evt->path));

	if (type)
		bpf_probe_read_kernel_str(evt->extra, sizeof(evt->extra), type);
	else if (dev_name)
		bpf_probe_read_kernel_str(evt->extra, sizeof(evt->extra), dev_name);

	evt->flags = flags;
	suspicious = target_is_suspicious(evt->path) || fs_name_is_suspicious(evt->extra);
	if (!suspicious) {
		bpf_ringbuf_discard(evt, 0);
		return ret;
	}

	bpf_ringbuf_submit(evt, 0);
	return ret;
}
