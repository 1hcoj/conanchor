package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/conanchor/conanchor-ebpf/internal/container"
	"github.com/conanchor/conanchor-ebpf/internal/event"
	"github.com/conanchor/conanchor-ebpf/internal/integrity"
	"github.com/conanchor/conanchor-ebpf/internal/ledger"
	"github.com/conanchor/conanchor-ebpf/internal/output"
	"github.com/conanchor/conanchor-ebpf/internal/pipeline"
	"github.com/conanchor/conanchor-ebpf/internal/sequence"
	"github.com/conanchor/conanchor-ebpf/internal/storage"
)

func main() {
	log.SetFlags(0)
	targetCgroupIDs := flag.String("target-cgroup-id", os.Getenv("CONANCHOR_TARGET_CGROUP_ID"), "comma-separated cgroup IDs to monitor in kernel space; empty monitors all cgroups")
	dataDir := flag.String("data-dir", "./data", "data directory for off-chain logs, batches, and mock ledger")
	batchSize := flag.Int("batch-size", 10, "per-container batch size")
	collectorID := flag.String("collector-id", "collector-1", "collector identity stored in anchor records")
	ledgerBackend := flag.String("ledger-backend", "mock", "ledger backend: mock or besu")
	besuRPCURL := flag.String("besu-rpc-url", "http://127.0.0.1:8545", "Besu JSON-RPC URL")
	besuChainID := flag.Uint64("besu-chain-id", 0, "Besu chain ID; 0 auto-detects")
	besuContract := flag.String("besu-contract-address", "", "AnchorRegistry contract address")
	besuPrivateKey := flag.String("besu-private-key", os.Getenv("CONANCHOR_BESU_PRIVATE_KEY"), "hex private key for Besu transactions")
	besuKeyFile := flag.String("besu-private-key-file", os.Getenv("CONANCHOR_BESU_PRIVATE_KEY_FILE"), "file containing hex private key for Besu transactions")
	workflowLog := flag.Bool("workflow-log", false, "print human-readable integrity workflow logs to stderr")
	flag.Parse()

	ledgerCfg := ledger.Config{Backend: ledger.Backend(*ledgerBackend), DataDir: *dataDir, BesuRPCURL: *besuRPCURL, BesuChainID: *besuChainID, BesuContract: *besuContract, BesuPrivateKey: *besuPrivateKey, BesuKeyFile: *besuKeyFile}
	if err := run(*targetCgroupIDs, *dataDir, *batchSize, *collectorID, ledgerCfg, *workflowLog); err != nil {
		log.Fatalf("collector: %v", err)
	}
}

func run(targetCgroupIDs, dataDir string, batchSize int, collectorID string, ledgerCfg ledger.Config, workflowLog bool) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs conanchorObjects
	if err := loadConanchorObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	if err := configureTargetCgroups(&objs, targetCgroupIDs); err != nil {
		return err
	}

	links, err := attachLSMPrograms(&objs)
	if err != nil {
		return err
	}
	for _, l := range links {
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	ctxResolver := container.NewResolver()
	printer := output.NewPrinter(os.Stdout)
	seqManager := sequence.NewManager()
	batchManager := integrity.NewBatchManager(batchSize)
	fileStore, err := storage.NewFileStorage(dataDir)
	if err != nil {
		return fmt.Errorf("open file storage: %w", err)
	}
	ledgerBackend, err := ledger.NewFromConfig(ledgerCfg)
	if err != nil {
		return fmt.Errorf("open ledger backend: %w", err)
	}
	sink := pipeline.Sink{Store: fileStore, Ledger: ledgerBackend, CollectorID: collectorID}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = rd.Close()
	}()
	defer func() {
		batches, err := batchManager.FlushAll()
		if err != nil {
			log.Printf("flush batches: %v", err)
			return
		}
		for _, batch := range batches {
			if int(batch.EventCount) >= batchSize {
				logFinalizedBatch(workflowLog, batch)
			}
			if err := sink.CommitBatch(batch); err != nil {
				log.Printf("commit flushed batch: %v", err)
			} else if int(batch.EventCount) >= batchSize {
				workflow(workflowLog, 10, "anchor record appended to ledger backend", "backend=%s batch_id=%d", ledgerCfg.Backend, batch.ContainerBatchID)
			}
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		evt, err := event.Decode(record.RawSample)
		if err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		containerCtx := ctxResolver.Resolve(evt.PID, evt.CgroupID)
		evt.ContainerID = containerCtx.ContainerID
		evt.ContainerInstanceID = containerCtx.ContainerInstanceID

		if !event.ShouldEmit(evt) {
			continue
		}

		globalSeq, containerSeq := seqManager.Next(evt.ContainerInstanceID)
		entry := event.NewLogEntry(evt, globalSeq, containerSeq)
		if err := fileStore.AppendLog(entry); err != nil {
			return fmt.Errorf("append raw log: %w", err)
		}
		hash, err := integrity.HashLogEntry(entry)
		if err != nil {
			return fmt.Errorf("hash raw log: %w", err)
		}
		tag := integrity.LogTag{GlobalSeq: entry.GlobalSeq, ContainerSeq: entry.ContainerSeq, ContainerInstanceID: entry.ContainerInstanceID, Hash: hash}
		batches, err := batchManager.Add(entry, tag)
		if err != nil {
			return fmt.Errorf("add batch entry: %w", err)
		}
		for _, batch := range batches {
			logFinalizedBatch(workflowLog, batch)
			if err := sink.CommitBatch(batch); err != nil {
				return err
			}
			workflow(workflowLog, 10, "anchor record appended to ledger backend", "backend=%s batch_id=%d", ledgerCfg.Backend, batch.ContainerBatchID)
		}

		if err := printer.Print(evt); err != nil {
			return err
		}
	}
}

func configureTargetCgroups(objs *conanchorObjects, csv string) error {
	ids, err := parseCgroupIDs(csv)
	if err != nil {
		return err
	}

	var zero uint32
	enabled := uint32(0)
	if len(ids) > 0 {
		enabled = 1
	}
	if err := objs.FilterEnabled.Update(zero, enabled, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure cgroup filter state: %w", err)
	}

	for _, id := range ids {
		allowed := uint8(1)
		if err := objs.TargetCgroups.Update(id, allowed, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure target cgroup %d: %w", id, err)
		}
	}
	return nil
}

func parseCgroupIDs(csv string) ([]uint64, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}

	parts := strings.Split(csv, ",")
	ids := make([]uint64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid cgroup id %q", part)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func attachLSMPrograms(objs *conanchorObjects) ([]link.Link, error) {
	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		{name: "bprm_check_security", prog: objs.HandleBprmCheckSecurity},
		{name: "file_open", prog: objs.HandleFileOpen},
		{name: "sb_mount", prog: objs.HandleSbMount},
	}

	links := make([]link.Link, 0, len(programs))
	for _, p := range programs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			for _, opened := range links {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("attach LSM %s: %w", p.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func workflow(enabled bool, step int, action string, format string, args ...any) {
	if !enabled {
		return
	}
	detail := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[workflow %02d/10] %s | %s\n", step, action, detail)
}

func logFinalizedBatch(enabled bool, batch integrity.ContainerBatch) {
	workflow(enabled, 1, "events collected until batch threshold", "container=%s batch_id=%d event_count=%d", batch.ContainerInstanceID, batch.ContainerBatchID, batch.EventCount)
	workflow(enabled, 2, "container context resolved", "container_instance_id=%s", batch.ContainerInstanceID)
	workflow(enabled, 3, "normalized LogEntry records prepared", "container_seq=%d-%d", batch.FirstContainerSeq, batch.LastContainerSeq)
	workflow(enabled, 4, "global/container sequence range assigned", "global_seq=%d-%d container_seq=%d-%d", batch.FirstGlobalSeq, batch.LastGlobalSeq, batch.FirstContainerSeq, batch.LastContainerSeq)
	workflow(enabled, 5, "raw logs stored off-chain", "event_count=%d", batch.EventCount)
	workflow(enabled, 6, "per-log SHA-256 tags generated", "tag_count=%d first_hash=%s", len(batch.LogTags), firstTagHash(batch))
	workflow(enabled, 7, "per-container batch finalized", "container=%s batch_id=%d events=%d seq=%d-%d", batch.ContainerInstanceID, batch.ContainerBatchID, batch.EventCount, batch.FirstContainerSeq, batch.LastContainerSeq)
	workflow(enabled, 8, "Merkle root generated", "batch_id=%d merkle_root=%s", batch.ContainerBatchID, shortHash(batch.MerkleRoot))
	workflow(enabled, 9, "container batch hash chain updated", "previous=%s current=%s", shortHash(batch.PreviousContainerBatchHash), shortHash(batch.ContainerBatchHash))
}

func firstTagHash(batch integrity.ContainerBatch) string {
	if len(batch.LogTags) == 0 {
		return ""
	}
	return shortHash(batch.LogTags[0].Hash)
}

func shortHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16] + "..."
}
