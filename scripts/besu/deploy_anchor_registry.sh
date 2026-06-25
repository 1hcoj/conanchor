#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPC_URL="${BESU_RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${BESU_PRIVATE_KEY:-}"
CHAIN_ID="${BESU_CHAIN_ID:-0}"
GAS_PRICE="${BESU_GAS_PRICE:-0}"
DEPLOY_TIMEOUT="${BESU_DEPLOY_TIMEOUT:-5m}"
OUT_DIR="$ROOT_DIR/build/contracts"
CONTRACT_DIR="$ROOT_DIR/contracts"
CONTRACT_NAME="AnchorRegistry.sol"
SOLC_IMAGE="${SOLC_DOCKER_IMAGE:-ethereum/solc:stable}"

if [[ -z "$PRIVATE_KEY" ]]; then
  echo "error: BESU_PRIVATE_KEY is required" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required for Solidity compilation fallback" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "[deploy] compiling AnchorRegistry.sol with Docker image $SOLC_IMAGE"
docker run --rm \
  -v "$CONTRACT_DIR:/contracts:ro" \
  -v "$OUT_DIR:/out" \
  "$SOLC_IMAGE" \
  --evm-version berlin --via-ir --optimize --abi --bin --overwrite -o /out "/contracts/$CONTRACT_NAME" >/dev/null

BYTECODE_FILE="$OUT_DIR/AnchorRegistry.bin"
if [[ ! -s "$BYTECODE_FILE" ]]; then
  echo "error: bytecode file not generated: $BYTECODE_FILE" >&2
  exit 1
fi

echo "[deploy] deploying AnchorRegistry to $RPC_URL"
ADDR="$(go run ./cmd/deploy-besu \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --chain-id "$CHAIN_ID" \
  --gas-price "$GAS_PRICE" \
  --timeout "$DEPLOY_TIMEOUT" \
  --bytecode "@$BYTECODE_FILE")"

echo "$ADDR" > "$OUT_DIR/AnchorRegistry.address"
echo "AnchorRegistry deployed: $ADDR"
echo "Set collector/verifier flag: --besu-contract-address $ADDR"
