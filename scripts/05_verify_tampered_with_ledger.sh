#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${1:-$ROOT_DIR/data}"
CONTAINER_ID="${2:-}"
FROM_BATCH="${3:-1}"
TO_BATCH="${4:-0}"

if [[ -z "$CONTAINER_ID" ]]; then
  mapfile -t logs < <(find "$DATA_DIR/logs" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null | sort)
  if [[ "${#logs[@]}" -eq 0 ]]; then
    echo "error: no raw log files found under $DATA_DIR/logs" >&2
    exit 1
  fi
  if [[ "${#logs[@]}" -gt 1 ]]; then
    echo "error: multiple containers found. Pass container-id explicitly:" >&2
    printf '  %s\n' "${logs[@]##*/}" >&2
    exit 1
  fi
  CONTAINER_ID="$(basename "${logs[0]}" .jsonl)"
fi

echo "[step 5] tamper verification using blockchain ledger"
echo "[step 5] expected status: FAILED"
exec "$ROOT_DIR/scripts/verify_with_ledger.sh" "$DATA_DIR" "$CONTAINER_ID" "$FROM_BATCH" "$TO_BATCH"
