package integrity

const GenesisHash = "GENESIS"

func ComputeContainerBatchHash(batch ContainerBatch) (string, error) {
	return hashString(canonicalBatchString(batch)), nil
}
