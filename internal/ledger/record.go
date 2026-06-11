package ledger

type AnchorRecord struct {
	BlockHeight uint64 `json:"block_height"`
	TxID        string `json:"tx_id"`

	ContainerInstanceID string `json:"container_instance_id"`
	ContainerBatchID    uint64 `json:"container_batch_id"`

	FirstContainerSeq uint64 `json:"first_container_seq"`
	LastContainerSeq  uint64 `json:"last_container_seq"`
	FirstGlobalSeq    uint64 `json:"first_global_seq"`
	LastGlobalSeq     uint64 `json:"last_global_seq"`

	ContainerMerkleRoot        string `json:"container_merkle_root"`
	ContainerBatchHash         string `json:"container_batch_hash"`
	PreviousContainerBatchHash string `json:"previous_container_batch_hash"`

	EventCount        uint64 `json:"event_count"`
	DroppedEventCount uint64 `json:"dropped_event_count"`

	StartTimeNS uint64 `json:"start_time_ns"`
	EndTimeNS   uint64 `json:"end_time_ns"`

	CollectorID        string `json:"collector_id"`
	CollectorSignature string `json:"collector_signature,omitempty"`
}

type Block struct {
	Height            uint64       `json:"height"`
	TimestampNS       uint64       `json:"timestamp_ns"`
	PreviousBlockHash string       `json:"previous_block_hash"`
	BlockHash         string       `json:"block_hash"`
	Anchor            AnchorRecord `json:"anchor"`
}
