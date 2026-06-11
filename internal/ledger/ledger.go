package ledger

type Ledger interface {
	AppendAnchor(record AnchorRecord) (txID string, blockHeight uint64, err error)
	GetAnchor(containerInstanceID string, batchID uint64) (AnchorRecord, error)
	ListAnchors(containerInstanceID string) ([]AnchorRecord, error)
	VerifyLedgerChain() error
}
