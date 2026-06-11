package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func BuildMerkleRoot(leaves []string) (string, error) {
	if len(leaves) == 0 {
		return "", errors.New("merkle root requires at least one leaf")
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]string, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			sum := sha256.Sum256([]byte(level[i] + level[i+1]))
			next = append(next, hex.EncodeToString(sum[:]))
		}
		level = next
	}
	return level[0], nil
}

// Merkle proofs are intentionally left for a later phase; the batch metadata
// keeps ordered LogTags so proof generation can be added without changing logs.
