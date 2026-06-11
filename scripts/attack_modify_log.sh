#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${1:-$ROOT_DIR/data}"
CONTAINER_ID="${2:-demo-container}"
LINE_NO="${3:-1}"
FIELD="${4:-path}"
VALUE="${5:-/tmp/attacker-modified-payload}"

LOG_FILE="$DATA_DIR/logs/$CONTAINER_ID.jsonl"

if [[ ! -f "$LOG_FILE" ]]; then
  echo "error: raw log file not found: $LOG_FILE" >&2
  echo "usage: $0 [data-dir] [container-id] [line-no] [field] [value]" >&2
  exit 1
fi

if ! [[ "$LINE_NO" =~ ^[0-9]+$ ]] || [[ "$LINE_NO" -lt 1 ]]; then
  echo "error: line-no must be a positive integer" >&2
  exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

python3 - "$LOG_FILE" "$TMP_FILE" "$LINE_NO" "$FIELD" "$VALUE" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
line_no = int(sys.argv[3])
field = sys.argv[4]
value = sys.argv[5]

allowed = {"comm", "path", "extra", "risk", "policy", "container_id", "container_instance_id"}
if field not in allowed:
    raise SystemExit(f"unsupported field {field!r}; allowed={sorted(allowed)}")

lines = src.read_text().splitlines()
if line_no > len(lines):
    raise SystemExit(f"line {line_no} does not exist; file has {len(lines)} lines")

entry = json.loads(lines[line_no - 1])
old = entry.get(field, "")
entry[field] = value
lines[line_no - 1] = json.dumps(entry, separators=(",", ":"), sort_keys=False)
dst.write_text("\n".join(lines) + "\n")
print(f"modified {src}:{line_no} field={field} old={old!r} new={value!r}", file=sys.stderr)
PY

cp "$TMP_FILE" "$LOG_FILE"

echo "[attack] raw log modified"
echo "  file:  $LOG_FILE"
echo "  line:  $LINE_NO"
echo "  field: $FIELD"
echo "  value: $VALUE"
echo "[attack] ledger was not updated, so verifier should report FAILED"
