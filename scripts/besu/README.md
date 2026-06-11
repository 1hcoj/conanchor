# Besu MVP Notes

This directory contains lightweight helper scripts for the Besu backend.

Besu is started with Docker using `hyperledger/besu:latest` by default. The script maps host ports to container ports using this shape:

```sh
docker run \
  -p <localportJSON-RPC>:8545 \
  -p <localportWS>:8546 \
  -p <localportP2P>:30303 \
  hyperledger/besu:latest \
  --rpc-http-enabled \
  --rpc-ws-enabled
```

The helper also mounts a host data directory to `/var/lib/besu` so the node database and node identity persist.

Start a local Besu dev node:

```sh
./scripts/besu/start_besu_dev.sh ./data/besu-node-1 8545 8546 30303 conanchor-besu-node-1
```

Arguments:

```text
1. data directory
2. local JSON-RPC port
3. local WebSocket port
4. local P2P port
5. Docker container name
```

To run additional worker-style nodes on the same host, use different data directories and ports:

```sh
./scripts/besu/start_besu_dev.sh ./data/besu-worker-1 8547 8548 30304 conanchor-besu-worker-1
./scripts/besu/start_besu_dev.sh ./data/besu-worker-2 8549 8550 30305 conanchor-besu-worker-2
```

In another terminal, deploy the contract with a funded Besu account key:

```sh
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_PRIVATE_KEY=<hex-private-key>
./scripts/besu/deploy_anchor_registry.sh
```

Then run collector with:

```sh
sudo CONANCHOR_BESU_PRIVATE_KEY=$BESU_PRIVATE_KEY ./bin/collector \
  --ledger-backend besu \
  --besu-rpc-url http://127.0.0.1:8545 \
  --besu-chain-id 0 \
  --besu-contract-address <contract-address> \
  --data-dir ./data \
  --batch-size 1 \
  --collector-id collector-1
```
