#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPC_URL="${BESU_RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${BESU_PRIVATE_KEY:-}"
OUT_DIR="$ROOT_DIR/build/contracts"
CONTRACT="$ROOT_DIR/contracts/AnchorRegistry.sol"

if [[ -z "$PRIVATE_KEY" ]]; then
  echo "error: BESU_PRIVATE_KEY is required" >&2
  exit 1
fi
if ! command -v solc >/dev/null 2>&1; then
  echo "error: solc is required to compile AnchorRegistry.sol" >&2
  exit 1
fi
if ! command -v cast >/dev/null 2>&1; then
  echo "error: cast is required to deploy the contract" >&2
  echo "Install Foundry or deploy the compiled bytecode with another Ethereum transaction tool." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
solc --abi --bin --overwrite -o "$OUT_DIR" "$CONTRACT" >/dev/null
BYTECODE="$(cat "$OUT_DIR/AnchorRegistry.bin")"

ADDR="$(cast send --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --create "0x$BYTECODE" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["contractAddress"])')"

echo "$ADDR" > "$OUT_DIR/AnchorRegistry.address"
echo "AnchorRegistry deployed: $ADDR"
echo "Set collector/verifier flag: --besu-contract-address $ADDR"
