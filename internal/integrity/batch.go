package integrity

import (
	"errors"
	"sync"

	"github.com/conanchor/conanchor-ebpf/internal/event"
)

type LogTag struct {
	GlobalSeq           uint64 `json:"global_seq"`
	ContainerSeq        uint64 `json:"container_seq"`
	ContainerInstanceID string `json:"container_instance_id"`
	Hash                string `json:"hash"`
}

type ContainerBatch struct {
	ContainerInstanceID string `json:"container_instance_id"`
	ContainerBatchID    uint64 `json:"container_batch_id"`

	FirstContainerSeq uint64 `json:"first_container_seq"`
	LastContainerSeq  uint64 `json:"last_container_seq"`

	FirstGlobalSeq uint64 `json:"first_global_seq"`
	LastGlobalSeq  uint64 `json:"last_global_seq"`

	EventCount        uint64 `json:"event_count"`
	DroppedEventCount uint64 `json:"dropped_event_count"`

	StartTimeNS uint64 `json:"start_time_ns"`
	EndTimeNS   uint64 `json:"end_time_ns"`

	PreviousContainerBatchHash string `json:"previous_container_batch_hash"`
	MerkleRoot                 string `json:"merkle_root"`
	ContainerBatchHash         string `json:"container_batch_hash"`

	LogTags []LogTag `json:"log_tags"`
}

type BatchManager struct {
	mu          sync.Mutex
	batchSize   int
	current     map[string]*ContainerBatch
	nextBatchID map[string]uint64
	prevHash    map[string]string
}

func NewBatchManager(batchSize int) *BatchManager {
	if batchSize <= 0 {
		batchSize = 10
	}
	return &BatchManager{
		batchSize:   batchSize,
		current:     make(map[string]*ContainerBatch),
		nextBatchID: make(map[string]uint64),
		prevHash:    make(map[string]string),
	}
}

func (m *BatchManager) Add(entry event.LogEntry, tag LogTag) ([]ContainerBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := entry.ContainerInstanceID
	batch := m.current[id]
	if batch == nil {
		m.nextBatchID[id]++
		prev := m.prevHash[id]
		if prev == "" {
			prev = GenesisHash
		}
		batch = &ContainerBatch{
			ContainerInstanceID:        id,
			ContainerBatchID:           m.nextBatchID[id],
			FirstContainerSeq:          entry.ContainerSeq,
			FirstGlobalSeq:             entry.GlobalSeq,
			StartTimeNS:                entry.TimestampNS,
			PreviousContainerBatchHash: prev,
		}
		m.current[id] = batch
	}

	batch.LastContainerSeq = entry.ContainerSeq
	batch.LastGlobalSeq = entry.GlobalSeq
	batch.EndTimeNS = entry.TimestampNS
	batch.EventCount++
	batch.LogTags = append(batch.LogTags, tag)

	if len(batch.LogTags) >= m.batchSize {
		finalized, err := finalizeBatch(*batch)
		if err != nil {
			return nil, err
		}
		m.prevHash[id] = finalized.ContainerBatchHash
		delete(m.current, id)
		return []ContainerBatch{finalized}, nil
	}
	return nil, nil
}

func (m *BatchManager) FlushAll() ([]ContainerBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	batches := make([]ContainerBatch, 0, len(m.current))
	for id, batch := range m.current {
		finalized, err := finalizeBatch(*batch)
		if err != nil {
			return nil, err
		}
		m.prevHash[id] = finalized.ContainerBatchHash
		batches = append(batches, finalized)
		delete(m.current, id)
	}
	return batches, nil
}

func finalizeBatch(batch ContainerBatch) (ContainerBatch, error) {
	if len(batch.LogTags) == 0 {
		return ContainerBatch{}, errors.New("cannot finalize empty batch")
	}
	leaves := make([]string, 0, len(batch.LogTags))
	for _, tag := range batch.LogTags {
		leaves = append(leaves, tag.Hash)
	}
	root, err := BuildMerkleRoot(leaves)
	if err != nil {
		return ContainerBatch{}, err
	}
	batch.MerkleRoot = root
	hash, err := ComputeContainerBatchHash(batch)
	if err != nil {
		return ContainerBatch{}, err
	}
	batch.ContainerBatchHash = hash
	return batch, nil
}
