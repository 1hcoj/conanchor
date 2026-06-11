#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${1:-$ROOT_DIR/data}"
CONTAINER_ID="${2:-demo-container}"
FROM_BATCH="${3:-1}"
TO_BATCH="${4:-0}"
LEDGER_BACKEND="${LEDGER_BACKEND:-mock}"
BESU_RPC_URL="${BESU_RPC_URL:-http://127.0.0.1:8545}"
BESU_CHAIN_ID="${BESU_CHAIN_ID:-0}"
BESU_CONTRACT_ADDRESS="${BESU_CONTRACT_ADDRESS:-}"

LEDGER_FILE="$DATA_DIR/ledger/mock_chain.jsonl"
LOG_FILE="$DATA_DIR/logs/$CONTAINER_ID.jsonl"
BATCH_DIR="$DATA_DIR/batches/$CONTAINER_ID"

if [[ "$LEDGER_BACKEND" == "mock" && ! -f "$LEDGER_FILE" ]]; then
  echo "error: ledger file not found: $LEDGER_FILE" >&2
  exit 1
fi
if [[ "$LEDGER_BACKEND" == "besu" && -z "$BESU_CONTRACT_ADDRESS" ]]; then
  echo "error: BESU_CONTRACT_ADDRESS is required when LEDGER_BACKEND=besu" >&2
  exit 1
fi
if [[ ! -f "$LOG_FILE" ]]; then
  echo "error: raw log file not found: $LOG_FILE" >&2
  exit 1
fi
if [[ ! -d "$BATCH_DIR" ]]; then
  echo "error: batch directory not found: $BATCH_DIR" >&2
  exit 1
fi

echo "[verify] verifying raw logs against blockchain ledger anchors"
echo "  data_dir:     $DATA_DIR"
echo "  container_id: $CONTAINER_ID"
echo "  raw_logs:     $LOG_FILE"
echo "  batches:      $BATCH_DIR"
echo "  ledger:       $LEDGER_FILE"
echo "  range:        $FROM_BATCH..$TO_BATCH"
echo

go run ./cmd/verifier \
  --data-dir "$DATA_DIR" \
  --container-instance-id "$CONTAINER_ID" \
  --from-batch "$FROM_BATCH" \
  --to-batch "$TO_BATCH"
