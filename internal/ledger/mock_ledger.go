package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conanchor/conanchor-ebpf/internal/integrity"
)

type MockLedger struct {
	path string
	mu   sync.Mutex
}

func NewMockLedger(dataDir string) (*MockLedger, error) {
	path := filepath.Join(dataDir, "ledger", "mock_chain.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &MockLedger{path: path}, nil
}

func (l *MockLedger) AppendAnchor(record AnchorRecord) (string, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	blocks, err := l.loadBlocks()
	if err != nil {
		return "", 0, err
	}
	height := uint64(len(blocks) + 1)
	prev := integrity.GenesisHash
	if len(blocks) > 0 {
		prev = blocks[len(blocks)-1].BlockHash
	}
	txID := fmt.Sprintf("tx-%d", height)
	record.BlockHeight = height
	record.TxID = txID
	block := Block{Height: height, TimestampNS: uint64(time.Now().UnixNano()), PreviousBlockHash: prev, Anchor: record}
	block.BlockHash = computeBlockHash(block)

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(block); err != nil {
		return "", 0, err
	}
	return txID, height, nil
}

func (l *MockLedger) GetAnchor(containerInstanceID string, batchID uint64) (AnchorRecord, error) {
	anchors, err := l.ListAnchors(containerInstanceID)
	if err != nil {
		return AnchorRecord{}, err
	}
	for _, anchor := range anchors {
		if anchor.ContainerBatchID == batchID {
			return anchor, nil
		}
	}
	return AnchorRecord{}, errors.New("anchor not found")
}

func (l *MockLedger) ListAnchors(containerInstanceID string) ([]AnchorRecord, error) {
	blocks, err := l.loadBlocks()
	if err != nil {
		return nil, err
	}
	var anchors []AnchorRecord
	for _, block := range blocks {
		if block.Anchor.ContainerInstanceID == containerInstanceID {
			anchors = append(anchors, block.Anchor)
		}
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].ContainerBatchID < anchors[j].ContainerBatchID })
	return anchors, nil
}

func (l *MockLedger) VerifyLedgerChain() error {
	blocks, err := l.loadBlocks()
	if err != nil {
		return err
	}
	prev := integrity.GenesisHash
	for i, block := range blocks {
		wantHeight := uint64(i + 1)
		if block.Height != wantHeight {
			return fmt.Errorf("invalid block height %d, want %d", block.Height, wantHeight)
		}
		if block.PreviousBlockHash != prev {
			return fmt.Errorf("invalid previous block hash at height %d", block.Height)
		}
		if computeBlockHash(block) != block.BlockHash {
			return fmt.Errorf("invalid block hash at height %d", block.Height)
		}
		prev = block.BlockHash
	}
	return nil
}

func (l *MockLedger) loadBlocks() ([]Block, error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var blocks []Block
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var block Block
		if err := json.Unmarshal(scanner.Bytes(), &block); err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return blocks, scanner.Err()
}

func computeBlockHash(block Block) string {
	anchor := canonicalAnchorString(block.Anchor)
	data := strings.Join([]string{
		strconv.FormatUint(block.Height, 10),
		strconv.FormatUint(block.TimestampNS, 10),
		block.PreviousBlockHash,
		anchor,
	}, "\x1f")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func canonicalAnchorString(a AnchorRecord) string {
	fields := []string{
		strconv.FormatUint(a.BlockHeight, 10), a.TxID, a.ContainerInstanceID,
		strconv.FormatUint(a.ContainerBatchID, 10), strconv.FormatUint(a.FirstContainerSeq, 10),
		strconv.FormatUint(a.LastContainerSeq, 10), strconv.FormatUint(a.FirstGlobalSeq, 10),
		strconv.FormatUint(a.LastGlobalSeq, 10), a.ContainerMerkleRoot, a.ContainerBatchHash,
		a.PreviousContainerBatchHash, strconv.FormatUint(a.EventCount, 10),
		strconv.FormatUint(a.DroppedEventCount, 10), strconv.FormatUint(a.StartTimeNS, 10),
		strconv.FormatUint(a.EndTimeNS, 10), a.CollectorID, a.CollectorSignature,
	}
	return strings.Join(fields, "\x1f")
}
