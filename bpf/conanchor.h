#ifndef __CONANCHOR_H
#define __CONANCHOR_H

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_EXTRA_LEN 256

#define EVENT_EXEC      1
#define EVENT_FILE_OPEN 2
#define EVENT_MOUNT     3

struct event {
	__u64 timestamp_ns;

	__u32 event_type;

	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;

	__u64 cgroup_id;

	char comm[MAX_COMM_LEN];

	char path[MAX_PATH_LEN];
	char extra[MAX_EXTRA_LEN];

	__u64 flags;
	__s32 retval;
};

typedef struct event event;

#endif
