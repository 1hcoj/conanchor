#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${1:-$ROOT_DIR/data/tamper-demo}"
CONTAINER_ID="${2:-demo-container}"
ATTACK_TYPE="${3:-modify-log}"
BATCH_SIZE="${BATCH_SIZE:-10}"
COUNT="${COUNT:-30}"

cd "$ROOT_DIR"

echo "[1/5] Generate clean synthetic logs and ledger anchors"
rm -rf "$DATA_DIR"
go run ./cmd/demo generate \
  --data-dir "$DATA_DIR" \
  --container-id "$CONTAINER_ID" \
  --count "$COUNT" \
  --batch-size "$BATCH_SIZE" \
  --workflow-log

echo "[2/5] Verify clean logs. Expected status: OK"
go run ./cmd/verifier \
  --data-dir "$DATA_DIR" \
  --container-instance-id "$CONTAINER_ID" \
  --from-batch 1 \
  --to-batch 0

echo "[3/5] Apply attack: $ATTACK_TYPE"
go run ./cmd/demo attack \
  --data-dir "$DATA_DIR" \
  --container-id "$CONTAINER_ID" \
  --type "$ATTACK_TYPE"

echo "[4/5] Verify tampered logs. Expected status: FAILED"
go run ./cmd/verifier \
  --data-dir "$DATA_DIR" \
  --container-instance-id "$CONTAINER_ID" \
  --from-batch 1 \
  --to-batch 0

echo "[5/5] Evidence locations"
echo "  Raw logs:      $DATA_DIR/logs/$CONTAINER_ID.jsonl"
echo "  Batch hashes:  $DATA_DIR/batches/$CONTAINER_ID/"
echo "  Ledger chain:  $DATA_DIR/ledger/mock_chain.jsonl"
