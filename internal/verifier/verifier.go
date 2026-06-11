package verifier

import (
	"fmt"

	"github.com/conanchor/conanchor-ebpf/internal/integrity"
	"github.com/conanchor/conanchor-ebpf/internal/ledger"
	"github.com/conanchor/conanchor-ebpf/internal/storage"
)

type Verifier struct {
	store  storage.Storage
	ledger ledger.Ledger
}

func New(store storage.Storage, ledger ledger.Ledger) *Verifier {
	return &Verifier{store: store, ledger: ledger}
}

func (v *Verifier) Verify(containerInstanceID string, fromBatch, toBatch uint64) VerificationReport {
	report := VerificationReport{ContainerInstanceID: containerInstanceID, FromBatch: fromBatch, ToBatch: toBatch, Status: "OK"}
	if err := v.ledger.VerifyLedgerChain(); err != nil {
		report.add(0, "LEDGER_CHAIN_INVALID", err.Error())
	}

	batches, err := v.store.ListBatches(containerInstanceID)
	if err != nil {
		report.add(0, "LOG_LOAD_FAILED", err.Error())
		return report.finish()
	}
	if toBatch == 0 {
		for _, b := range batches {
			if b.ContainerBatchID > toBatch {
				toBatch = b.ContainerBatchID
			}
		}
		report.ToBatch = toBatch
	}
	if fromBatch == 0 {
		fromBatch = 1
		report.FromBatch = 1
	}

	var previousHash string
	var previousLastSeq uint64
	for batchID := fromBatch; batchID <= toBatch; batchID++ {
		batch, err := v.store.LoadBatch(containerInstanceID, batchID)
		if err != nil {
			report.add(batchID, "LOG_LOAD_FAILED", err.Error())
			continue
		}
		anchor, err := v.ledger.GetAnchor(containerInstanceID, batchID)
		if err != nil {
			report.add(batchID, "ANCHOR_NOT_FOUND", err.Error())
			continue
		}
		logs, err := v.store.LoadLogs(containerInstanceID, batch.FirstContainerSeq, batch.LastContainerSeq)
		if err != nil {
			report.add(batchID, "LOG_LOAD_FAILED", err.Error())
			continue
		}
		if uint64(len(logs)) != batch.EventCount || uint64(len(logs)) != anchor.EventCount {
			report.add(batchID, "EVENT_COUNT_MISMATCH", "raw log count does not match batch or anchor event count")
		}
		if len(logs) > 0 {
			if logs[0].ContainerSeq != batch.FirstContainerSeq || logs[len(logs)-1].ContainerSeq != batch.LastContainerSeq {
				report.add(batchID, "SEQUENCE_GAP", "raw log sequence range does not match batch metadata")
			}
			for i := 1; i < len(logs); i++ {
				if logs[i].ContainerSeq != logs[i-1].ContainerSeq+1 {
					report.add(batchID, "SEQUENCE_GAP", "container sequence is not continuous")
					break
				}
			}
		}
		leaves := make([]string, 0, len(logs))
		for _, entry := range logs {
			hash, err := integrity.HashLogEntry(entry)
			if err != nil {
				report.add(batchID, "MERKLE_ROOT_MISMATCH", err.Error())
				continue
			}
			leaves = append(leaves, hash)
		}
		if len(leaves) > 0 {
			root, err := integrity.BuildMerkleRoot(leaves)
			if err != nil {
				report.add(batchID, "MERKLE_ROOT_MISMATCH", err.Error())
			} else if root != batch.MerkleRoot || root != anchor.ContainerMerkleRoot {
				report.add(batchID, "MERKLE_ROOT_MISMATCH", "recomputed Merkle root does not match stored batch or anchored Merkle root")
			}
		}
		recomputedHash, err := integrity.ComputeContainerBatchHash(batch)
		if err != nil {
			report.add(batchID, "BATCH_HASH_MISMATCH", err.Error())
		} else if recomputedHash != batch.ContainerBatchHash || recomputedHash != anchor.ContainerBatchHash {
			report.add(batchID, "BATCH_HASH_MISMATCH", "recomputed batch hash does not match stored batch or anchor")
		}
		if batch.PreviousContainerBatchHash != anchor.PreviousContainerBatchHash {
			report.add(batchID, "PREVIOUS_BATCH_HASH_MISMATCH", "batch previous hash does not match anchor")
		}
		if previousHash != "" && batch.PreviousContainerBatchHash != previousHash {
			report.add(batchID, "PREVIOUS_BATCH_HASH_MISMATCH", "batch hash chain is not continuous")
		}
		if previousLastSeq != 0 && batch.FirstContainerSeq != previousLastSeq+1 {
			report.add(batchID, "SEQUENCE_GAP", "batch sequence ranges are not continuous")
		}
		if !anchorMatchesBatch(anchor, batch) {
			report.add(batchID, "ANCHOR_METADATA_MISMATCH", "anchor metadata does not match stored batch metadata")
		}
		previousHash = batch.ContainerBatchHash
		previousLastSeq = batch.LastContainerSeq
		report.VerifiedBatches++
	}
	return report.finish()
}

func anchorMatchesBatch(a ledger.AnchorRecord, b integrity.ContainerBatch) bool {
	return a.ContainerBatchID == b.ContainerBatchID &&
		a.FirstContainerSeq == b.FirstContainerSeq && a.LastContainerSeq == b.LastContainerSeq &&
		a.FirstGlobalSeq == b.FirstGlobalSeq && a.LastGlobalSeq == b.LastGlobalSeq &&
		a.EventCount == b.EventCount && a.DroppedEventCount == b.DroppedEventCount &&
		a.StartTimeNS == b.StartTimeNS && a.EndTimeNS == b.EndTimeNS
}

func (r *VerificationReport) add(batchID uint64, typ, msg string) {
	r.Failures = append(r.Failures, VerificationError{BatchID: batchID, Type: typ, Message: msg})
}

func (r VerificationReport) finish() VerificationReport {
	if len(r.Failures) > 0 {
		r.Status = "FAILED"
	}
	if r.Status == "" {
		r.Status = "OK"
	}
	return r
}

func VerifyDataDir(dataDir, containerInstanceID string, fromBatch, toBatch uint64) (VerificationReport, error) {
	return VerifyDataDirWithLedger(dataDir, containerInstanceID, fromBatch, toBatch, "mock", "", 0, "")
}

func VerifyDataDirWithLedger(dataDir, containerInstanceID string, fromBatch, toBatch uint64, backend string, besuRPCURL string, besuChainID uint64, besuContract string) (VerificationReport, error) {
	store, err := storage.NewFileStorage(dataDir)
	if err != nil {
		return VerificationReport{}, err
	}
	ledg, err := ledger.NewFromConfig(ledger.Config{Backend: ledger.Backend(backend), DataDir: dataDir, BesuRPCURL: besuRPCURL, BesuChainID: besuChainID, BesuContract: besuContract})
	if err != nil {
		return VerificationReport{}, err
	}
	if containerInstanceID == "" {
		return VerificationReport{}, fmt.Errorf("container-instance-id is required")
	}
	return New(store, ledg).Verify(containerInstanceID, fromBatch, toBatch), nil
}
