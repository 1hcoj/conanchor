package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/conanchor/conanchor-ebpf/internal/event"
)

func sampleEntry() event.LogEntry {
	return event.LogEntry{GlobalSeq: 1, ContainerSeq: 1, TimestampNS: 10, EventType: "exec", PID: 1, TGID: 1, UID: 0, GID: 0, Comm: "wget", Path: "/usr/bin/wget", CgroupID: "42", ContainerID: "c", ContainerInstanceID: "c", Risk: "high", Policy: "wget-exec"}
}

func TestCanonicalDeterministicAndHash(t *testing.T) {
	a := sampleEntry()
	b := sampleEntry()
	if CanonicalLogString(a) != CanonicalLogString(b) {
		t.Fatal("canonical serialization is not deterministic")
	}
	ha, _ := HashLogEntry(a)
	hb, _ := HashLogEntry(b)
	if ha != hb {
		t.Fatal("same entry hash mismatch")
	}
	b.Path = "/bin/sh"
	hc, _ := HashLogEntry(b)
	if ha == hc {
		t.Fatal("hash did not change after field mutation")
	}
}

func TestBuildMerkleRoot(t *testing.T) {
	root, err := BuildMerkleRoot([]string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("ab"))
	if root != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected root %s", root)
	}
}

func TestBuildMerkleRootOddDuplicatesLast(t *testing.T) {
	left := sha256.Sum256([]byte("ab"))
	right := sha256.Sum256([]byte("cc"))
	wantSum := sha256.Sum256([]byte(hex.EncodeToString(left[:]) + hex.EncodeToString(right[:])))
	got, err := BuildMerkleRoot([]string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("got %s", got)
	}
}

func TestBatchHashIncludesPreviousHash(t *testing.T) {
	batch := ContainerBatch{ContainerInstanceID: "c", ContainerBatchID: 1, FirstContainerSeq: 1, LastContainerSeq: 1, FirstGlobalSeq: 1, LastGlobalSeq: 1, EventCount: 1, PreviousContainerBatchHash: GenesisHash, MerkleRoot: "root"}
	a, _ := ComputeContainerBatchHash(batch)
	batch.PreviousContainerBatchHash = "other"
	b, _ := ComputeContainerBatchHash(batch)
	if a == b {
		t.Fatal("batch hash did not include previous hash")
	}
}
