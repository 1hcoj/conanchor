package storage

import (
	"github.com/conanchor/conanchor-ebpf/internal/event"
	"github.com/conanchor/conanchor-ebpf/internal/integrity"
)

type Storage interface {
	AppendLog(entry event.LogEntry) error
	SaveBatch(batch integrity.ContainerBatch) error
	LoadBatch(containerInstanceID string, batchID uint64) (integrity.ContainerBatch, error)
	LoadLogs(containerInstanceID string, firstSeq uint64, lastSeq uint64) ([]event.LogEntry, error)
	ListBatches(containerInstanceID string) ([]integrity.ContainerBatch, error)
}
