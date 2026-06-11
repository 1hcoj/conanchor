package integrity

import (
	"strconv"
	"strings"

	"github.com/conanchor/conanchor-ebpf/internal/event"
)

func CanonicalLogString(entry event.LogEntry) string {
	fields := []string{
		u64(entry.GlobalSeq),
		u64(entry.ContainerSeq),
		u64(entry.TimestampNS),
		entry.EventType,
		u32(entry.PID),
		u32(entry.TGID),
		u32(entry.UID),
		u32(entry.GID),
		entry.Comm,
		entry.Path,
		entry.Extra,
		u64(entry.Flags),
		i32(entry.Retval),
		entry.CgroupID,
		entry.ContainerID,
		entry.ContainerInstanceID,
		entry.Risk,
		entry.Policy,
	}
	return strings.Join(fields, "\x1f")
}

func canonicalBatchString(batch ContainerBatch) string {
	fields := []string{
		batch.ContainerInstanceID,
		u64(batch.ContainerBatchID),
		u64(batch.FirstContainerSeq),
		u64(batch.LastContainerSeq),
		u64(batch.FirstGlobalSeq),
		u64(batch.LastGlobalSeq),
		u64(batch.EventCount),
		u64(batch.DroppedEventCount),
		u64(batch.StartTimeNS),
		u64(batch.EndTimeNS),
		batch.PreviousContainerBatchHash,
		batch.MerkleRoot,
	}
	return strings.Join(fields, "\x1f")
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }
func u32(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
func i32(v int32) string  { return strconv.FormatInt(int64(v), 10) }
