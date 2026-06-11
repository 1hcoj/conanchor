package verifier

type VerificationReport struct {
	ContainerInstanceID string              `json:"container_instance_id"`
	FromBatch           uint64              `json:"from_batch"`
	ToBatch             uint64              `json:"to_batch"`
	Status              string              `json:"status"`
	VerifiedBatches     uint64              `json:"verified_batches"`
	Failures            []VerificationError `json:"failures"`
}

type VerificationError struct {
	BatchID uint64 `json:"batch_id"`
	Type    string `json:"type"`
	Message string `json:"message"`
}
