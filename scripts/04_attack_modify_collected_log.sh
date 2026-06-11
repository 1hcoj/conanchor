#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${1:-$ROOT_DIR/data}"
CONTAINER_ID="${2:-}"
LINE_NO="${3:-1}"
FIELD="${4:-path}"
VALUE="${5:-/tmp/attacker-modified-wget}"

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

echo "[step 4] attacker modifies collected raw log"
exec "$ROOT_DIR/scripts/attack_modify_log.sh" "$DATA_DIR" "$CONTAINER_ID" "$LINE_NO" "$FIELD" "$VALUE"
