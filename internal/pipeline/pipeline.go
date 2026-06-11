package pipeline

import (
	"fmt"

	"github.com/conanchor/conanchor-ebpf/internal/integrity"
	"github.com/conanchor/conanchor-ebpf/internal/ledger"
	"github.com/conanchor/conanchor-ebpf/internal/storage"
)

type Sink struct {
	Store       storage.Storage
	Ledger      ledger.Ledger
	CollectorID string
}

func (s Sink) CommitBatch(batch integrity.ContainerBatch) error {
	if err := s.Store.SaveBatch(batch); err != nil {
		return fmt.Errorf("save batch: %w", err)
	}
	_, _, err := s.Ledger.AppendAnchor(AnchorFromBatch(batch, s.CollectorID))
	if err != nil {
		return fmt.Errorf("append anchor: %w", err)
	}
	return nil
}

func AnchorFromBatch(batch integrity.ContainerBatch, collectorID string) ledger.AnchorRecord {
	return ledger.AnchorRecord{
		ContainerInstanceID:        batch.ContainerInstanceID,
		ContainerBatchID:           batch.ContainerBatchID,
		FirstContainerSeq:          batch.FirstContainerSeq,
		LastContainerSeq:           batch.LastContainerSeq,
		FirstGlobalSeq:             batch.FirstGlobalSeq,
		LastGlobalSeq:              batch.LastGlobalSeq,
		ContainerMerkleRoot:        batch.MerkleRoot,
		ContainerBatchHash:         batch.ContainerBatchHash,
		PreviousContainerBatchHash: batch.PreviousContainerBatchHash,
		EventCount:                 batch.EventCount,
		DroppedEventCount:          batch.DroppedEventCount,
		StartTimeNS:                batch.StartTimeNS,
		EndTimeNS:                  batch.EndTimeNS,
		CollectorID:                collectorID,
	}
}
