#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-./data/besu-dev}"
RPC_PORT="${2:-${BESU_RPC_PORT:-8545}}"
WS_PORT="${3:-${BESU_WS_PORT:-8546}}"
P2P_PORT="${4:-${BESU_P2P_PORT:-30303}}"
CONTAINER_NAME="${5:-${BESU_CONTAINER_NAME:-conanchor-besu-dev}}"
IMAGE="${BESU_DOCKER_IMAGE:-hyperledger/besu:latest}"

mkdir -p "$DATA_DIR"
DATA_DIR_ABS="$(cd "$DATA_DIR" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker binary not found in PATH" >&2
  exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  echo "error: docker container already exists: $CONTAINER_NAME" >&2
  echo "remove it first with: docker rm -f $CONTAINER_NAME" >&2
  exit 1
fi

echo "[besu] starting Docker Besu node"
echo "  image:          $IMAGE"
echo "  container:      $CONTAINER_NAME"
echo "  data dir:       $DATA_DIR_ABS"
echo "  JSON-RPC port:  127.0.0.1:$RPC_PORT -> 8545"
echo "  WS port:        127.0.0.1:$WS_PORT -> 8546"
echo "  P2P port:       0.0.0.0:$P2P_PORT -> 30303"

exec docker run --name "$CONTAINER_NAME" --rm \
  -p "$RPC_PORT:8545" \
  -p "$WS_PORT:8546" \
  -p "$P2P_PORT:30303" \
  -v "$DATA_DIR_ABS:/var/lib/besu" \
  "$IMAGE" \
  --network=dev \
  --data-path=/var/lib/besu \
  --rpc-http-enabled \
  --rpc-http-host=0.0.0.0 \
  --rpc-http-port=8545 \
  --rpc-http-api=ETH,NET,WEB3 \
  --rpc-ws-enabled \
  --rpc-ws-host=0.0.0.0 \
  --rpc-ws-port=8546 \
  --rpc-ws-api=ETH,NET,WEB3 \
  --host-allowlist='*' \
  --p2p-port=30303
