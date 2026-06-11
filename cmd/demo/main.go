package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/conanchor/conanchor-ebpf/internal/event"
	"github.com/conanchor/conanchor-ebpf/internal/integrity"
	"github.com/conanchor/conanchor-ebpf/internal/ledger"
	"github.com/conanchor/conanchor-ebpf/internal/pipeline"
	"github.com/conanchor/conanchor-ebpf/internal/sequence"
	"github.com/conanchor/conanchor-ebpf/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: demo generate|attack [flags]")
	}
	switch os.Args[1] {
	case "generate":
		generate(os.Args[2:])
	case "attack":
		attack(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func generate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	containerID := fs.String("container-id", "demo-container", "container instance ID")
	count := fs.Int("count", 30, "log count")
	batchSize := fs.Int("batch-size", 10, "batch size")
	workflowLog := fs.Bool("workflow-log", false, "print human-readable integrity workflow logs to stderr")
	_ = fs.Parse(args)

	_ = os.RemoveAll(*dataDir)
	store, err := storage.NewFileStorage(*dataDir)
	must(err)
	ledg, err := ledger.NewMockLedger(*dataDir)
	must(err)
	sink := pipeline.Sink{Store: store, Ledger: ledg, CollectorID: "demo-collector"}
	seq := sequence.NewManager()
	batches := integrity.NewBatchManager(*batchSize)

	for i := 0; i < *count; i++ {
		g, c := seq.Next(*containerID)
		entry := event.LogEntry{GlobalSeq: g, ContainerSeq: c, TimestampNS: uint64(time.Now().UnixNano()) + uint64(i), EventType: string(event.EventExec), PID: uint32(1000 + i), TGID: uint32(1000 + i), UID: 0, GID: 0, Comm: "wget", Path: "/usr/bin/wget", Flags: 0, CgroupID: "demo-cgroup", ContainerID: *containerID, ContainerInstanceID: *containerID, Risk: "high", Policy: "wget-exec"}
		must(store.AppendLog(entry))
		hash, err := integrity.HashLogEntry(entry)
		must(err)
		tag := integrity.LogTag{GlobalSeq: g, ContainerSeq: c, ContainerInstanceID: *containerID, Hash: hash}
		finalized, err := batches.Add(entry, tag)
		must(err)
		for _, batch := range finalized {
			logFinalizedBatch(*workflowLog, batch)
			must(sink.CommitBatch(batch))
			workflow(*workflowLog, 10, "anchor record appended to mock private blockchain ledger", "batch_id=%d ledger=%s", batch.ContainerBatchID, filepath.Join(*dataDir, "ledger", "mock_chain.jsonl"))
		}
	}
	finalized, err := batches.FlushAll()
	must(err)
	for _, batch := range finalized {
		if int(batch.EventCount) >= *batchSize {
			logFinalizedBatch(*workflowLog, batch)
		}
		must(sink.CommitBatch(batch))
		if int(batch.EventCount) >= *batchSize {
			workflow(*workflowLog, 10, "anchor record appended to mock private blockchain ledger", "batch_id=%d ledger=%s", batch.ContainerBatchID, filepath.Join(*dataDir, "ledger", "mock_chain.jsonl"))
		}
	}
}

func attack(args []string) {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	containerID := fs.String("container-id", "demo-container", "container instance ID")
	attackType := fs.String("type", "modify-log", "attack type")
	_ = fs.Parse(args)

	logPath := filepath.Join(*dataDir, "logs", sanitize(*containerID)+".jsonl")
	lines, err := readLines(logPath)
	must(err)
	if len(lines) == 0 {
		log.Fatal("no logs to attack")
	}
	switch *attackType {
	case "modify-log":
		var entry event.LogEntry
		must(json.Unmarshal([]byte(lines[0]), &entry))
		entry.Path = "/tmp/tampered"
		data, err := json.Marshal(entry)
		must(err)
		lines[0] = string(data)
	case "delete-log":
		lines = lines[1:]
	case "insert-log":
		lines = append([]string{lines[0]}, lines...)
	case "reorder-log":
		if len(lines) > 1 {
			lines[0], lines[1] = lines[1], lines[0]
		}
	case "rollback-container":
		removeLastBatch(*dataDir, *containerID)
		if len(lines) > 1 {
			lines = lines[:len(lines)-1]
		}
	default:
		log.Fatalf("unknown attack type %q", *attackType)
	}
	must(writeLines(logPath, lines))
}

func removeLastBatch(dataDir, containerID string) {
	dir := filepath.Join(dataDir, "batches", sanitize(containerID))
	entries, err := os.ReadDir(dir)
	must(err)
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "batch_") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) > 0 {
		must(os.Remove(filepath.Join(dir, names[len(names)-1])))
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func sanitize(name string) string {
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	if name == "" {
		return "host-or-unknown"
	}
	return name
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var _ = fmt.Sprintf

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
