package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	verifierpkg "github.com/conanchor/conanchor-ebpf/internal/verifier"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "data directory")
	containerID := flag.String("container-instance-id", "", "container instance ID")
	fromBatch := flag.Uint64("from-batch", 1, "first batch ID")
	toBatch := flag.Uint64("to-batch", 0, "last batch ID, 0 means latest")
	ledgerBackend := flag.String("ledger-backend", "mock", "ledger backend: mock or besu")
	besuRPCURL := flag.String("besu-rpc-url", "http://127.0.0.1:8545", "Besu JSON-RPC URL")
	besuChainID := flag.Uint64("besu-chain-id", 0, "Besu chain ID; 0 auto-detects")
	besuContract := flag.String("besu-contract-address", "", "AnchorRegistry contract address")
	flag.Parse()

	report, err := verifierpkg.VerifyDataDirWithLedger(*dataDir, *containerID, *fromBatch, *toBatch, *ledgerBackend, *besuRPCURL, *besuChainID, *besuContract)
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatal(err)
	}
}
