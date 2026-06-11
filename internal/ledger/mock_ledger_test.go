package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMockLedgerChainAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	l, err := NewMockLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 2; i++ {
		_, h, err := l.AppendAnchor(AnchorRecord{ContainerInstanceID: "c", ContainerBatchID: i, ContainerMerkleRoot: "m", ContainerBatchHash: "b", CollectorID: "t"})
		if err != nil {
			t.Fatal(err)
		}
		if h != i {
			t.Fatalf("height %d", h)
		}
	}
	if err := l.VerifyLedgerChain(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger", "mock_chain.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"height":999}` + "\n")
	_ = f.Close()
	if err := l.VerifyLedgerChain(); err == nil {
		t.Fatal("expected tamper detection")
	}
}
