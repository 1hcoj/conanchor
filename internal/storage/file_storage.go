package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/conanchor/conanchor-ebpf/internal/event"
	"github.com/conanchor/conanchor-ebpf/internal/integrity"
)

var safeNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type FileStorage struct {
	baseDir string
	mu      sync.Mutex
}

func NewFileStorage(baseDir string) (*FileStorage, error) {
	fs := &FileStorage{baseDir: baseDir}
	for _, dir := range []string{fs.logsDir(), fs.batchesDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return fs, nil
}

func (s *FileStorage) AppendLog(entry event.LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.logsDir(), sanitize(entry.ContainerInstanceID)+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(entry)
}

func (s *FileStorage) SaveBatch(batch integrity.ContainerBatch) error {
	dir := filepath.Join(s.batchesDir(), sanitize(batch.ContainerInstanceID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("batch_%d.json", batch.ContainerBatchID))
	data, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func (s *FileStorage) LoadBatch(containerInstanceID string, batchID uint64) (integrity.ContainerBatch, error) {
	path := filepath.Join(s.batchesDir(), sanitize(containerInstanceID), fmt.Sprintf("batch_%d.json", batchID))
	data, err := os.ReadFile(path)
	if err != nil {
		return integrity.ContainerBatch{}, err
	}
	var batch integrity.ContainerBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return integrity.ContainerBatch{}, err
	}
	return batch, nil
}

func (s *FileStorage) LoadLogs(containerInstanceID string, firstSeq uint64, lastSeq uint64) ([]event.LogEntry, error) {
	path := filepath.Join(s.logsDir(), sanitize(containerInstanceID)+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var logs []event.LogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry event.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, err
		}
		if entry.ContainerSeq >= firstSeq && entry.ContainerSeq <= lastSeq {
			logs = append(logs, entry)
		}
	}
	return logs, scanner.Err()
}

func (s *FileStorage) ListBatches(containerInstanceID string) ([]integrity.ContainerBatch, error) {
	dir := filepath.Join(s.batchesDir(), sanitize(containerInstanceID))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var batches []integrity.ContainerBatch
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var batch integrity.ContainerBatch
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	sort.Slice(batches, func(i, j int) bool { return batches[i].ContainerBatchID < batches[j].ContainerBatchID })
	return batches, nil
}

func (s *FileStorage) logsDir() string    { return filepath.Join(s.baseDir, "logs") }
func (s *FileStorage) batchesDir() string { return filepath.Join(s.baseDir, "batches") }

func sanitize(name string) string {
	if name == "" {
		return "host-or-unknown"
	}
	return safeNameRE.ReplaceAllString(name, "_")
}
