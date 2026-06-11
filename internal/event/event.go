package event

import "strings"

type EventType string

const (
	EventExec     EventType = "exec"
	EventFileOpen EventType = "file_open"
	EventMount    EventType = "mount"
)

const (
	rawEventExec     = 1
	rawEventFileOpen = 2
	rawEventMount    = 3
)

type Event struct {
	TimestampNS uint64    `json:"timestamp_ns"`
	EventType   EventType `json:"event_type"`

	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`

	Comm   string `json:"comm"`
	Path   string `json:"path"`
	Extra  string `json:"extra"`
	Flags  uint64 `json:"flags"`
	Retval int32  `json:"retval"`

	CgroupID string `json:"cgroup_id"`

	ContainerID         string `json:"container_id"`
	ContainerInstanceID string `json:"container_instance_id"`

	Risk   string `json:"risk,omitempty"`
	Policy string `json:"policy,omitempty"`
}

func Classify(e *Event) {
	switch e.EventType {
	case EventExec:
		if e.Comm == "wget" || strings.HasSuffix(e.Path, "/wget") || e.Path == "wget" {
			e.Risk = "high"
			e.Policy = "wget-exec"
		}
	case EventFileOpen:
		if isK8sSecretPath(e.Path) {
			e.Risk = "high"
			e.Policy = "k8s-secret-access"
		}
	case EventMount:
		if suspiciousMountPath(e.Path) || suspiciousMountExtra(e.Extra) {
			e.Risk = "high"
			e.Policy = "suspicious-mount"
		}
	}
}

func ShouldEmit(e Event) bool {
	switch e.EventType {
	case EventExec:
		return e.Policy == "wget-exec"
	case EventFileOpen:
		return e.Policy == "k8s-secret-access"
	case EventMount:
		return e.Policy == "suspicious-mount" || e.Path != "" || e.Extra != ""
	default:
		return false
	}
}

func isK8sSecretPath(path string) bool {
	return strings.HasPrefix(path, "/var/run/secrets/") || strings.HasPrefix(path, "/run/secrets/")
}

func suspiciousMountPath(path string) bool {
	for _, prefix := range []string{"/proc", "/sys", "/host", "/mnt", "/var/run"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func suspiciousMountExtra(extra string) bool {
	extra = strings.ToLower(extra)
	for _, needle := range []string{"proc", "sysfs", "cgroup", "cgroup2", "overlay"} {
		if strings.Contains(extra, needle) {
			return true
		}
	}
	return false
}

type LogEntry struct {
	GlobalSeq    uint64 `json:"global_seq"`
	ContainerSeq uint64 `json:"container_seq"`

	TimestampNS uint64 `json:"timestamp_ns"`
	EventType   string `json:"event_type"`

	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`

	Comm   string `json:"comm"`
	Path   string `json:"path"`
	Extra  string `json:"extra"`
	Flags  uint64 `json:"flags"`
	Retval int32  `json:"retval"`

	CgroupID            string `json:"cgroup_id"`
	ContainerID         string `json:"container_id"`
	ContainerInstanceID string `json:"container_instance_id"`

	Risk   string `json:"risk,omitempty"`
	Policy string `json:"policy,omitempty"`
}

func NewLogEntry(evt Event, globalSeq, containerSeq uint64) LogEntry {
	return LogEntry{
		GlobalSeq:           globalSeq,
		ContainerSeq:        containerSeq,
		TimestampNS:         evt.TimestampNS,
		EventType:           string(evt.EventType),
		PID:                 evt.PID,
		TGID:                evt.TGID,
		UID:                 evt.UID,
		GID:                 evt.GID,
		Comm:                evt.Comm,
		Path:                evt.Path,
		Extra:               evt.Extra,
		Flags:               evt.Flags,
		Retval:              evt.Retval,
		CgroupID:            evt.CgroupID,
		ContainerID:         evt.ContainerID,
		ContainerInstanceID: evt.ContainerInstanceID,
		Risk:                evt.Risk,
		Policy:              evt.Policy,
	}
}
