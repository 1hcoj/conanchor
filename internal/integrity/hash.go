package integrity

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/conanchor/conanchor-ebpf/internal/event"
)

func HashLogEntry(entry event.LogEntry) (string, error) {
	sum := sha256.Sum256([]byte(CanonicalLogString(entry)))
	return hex.EncodeToString(sum[:]), nil
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
