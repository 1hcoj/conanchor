package container

import (
	"os"
	"path/filepath"
	"strings"
)

const Unknown = "host-or-unknown"

type Context struct {
	ContainerID         string
	ContainerInstanceID string
}

type Resolver struct {
	ProcRoot string
}

func NewResolver() *Resolver {
	return &Resolver{ProcRoot: "/proc"}
}

func (r *Resolver) Resolve(pid uint32, _ string) Context {
	id := Unknown
	if pid != 0 {
		if data, err := os.ReadFile(filepath.Join(r.ProcRoot, uintToString(pid), "cgroup")); err == nil {
			id = ExtractContainerdID(string(data))
		}
	}
	if id == "" {
		id = Unknown
	}
	return Context{
		ContainerID:         id,
		ContainerInstanceID: id,
	}
}

func ExtractContainerdID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		if id := extractFromLine(line); id != "" {
			return id
		}
	}
	return ""
}

func extractFromLine(line string) string {
	const prefix = "cri-containerd-"
	idx := strings.Index(line, prefix)
	if idx >= 0 {
		rest := line[idx+len(prefix):]
		rest = strings.TrimSuffix(rest, ".scope")
		return trimContainerID(rest)
	}

	const colonPattern = ":cri-containerd:"
	idx = strings.Index(line, colonPattern)
	if idx >= 0 {
		return trimContainerID(line[idx+len(colonPattern):])
	}

	return ""
}

func trimContainerID(s string) string {
	s = strings.TrimSuffix(s, ".scope")
	for _, sep := range []string{"/", ":", "\n", "\r"} {
		if idx := strings.Index(s, sep); idx >= 0 {
			s = s[:idx]
		}
	}
	return strings.Trim(s, " \t")
}

func uintToString(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
