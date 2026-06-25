package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	rpcURL := flag.String("rpc-url", getenv("BESU_RPC_URL", "http://127.0.0.1:8545"), "Besu JSON-RPC URL")
	privateKeyHex := flag.String("private-key", os.Getenv("BESU_PRIVATE_KEY"), "hex private key for deployment")
	bytecodeHex := flag.String("bytecode", "", "contract bytecode hex string or @file")
	chainIDFlag := flag.Uint64("chain-id", 0, "chain ID; 0 auto-detects")
	gasPriceFlag := flag.Uint64("gas-price", 0, "gas price in wei; 0 is useful for private networks configured with --min-gas-price=0")
	timeoutFlag := flag.Duration("timeout", 5*time.Minute, "deployment mining timeout")
	flag.Parse()

	if *privateKeyHex == "" {
		log.Fatal("private key is required")
	}
	bytecode, err := loadBytecode(*bytecodeHex)
	if err != nil {
		log.Fatal(err)
	}
	key, err := parsePrivateKey(*privateKeyHex)
	if err != nil {
		log.Fatal(err)
	}
	client, err := ethclient.Dial(*rpcURL)
	if err != nil {
		log.Fatalf("connect rpc: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()
	chainID := new(big.Int).SetUint64(*chainIDFlag)
	if *chainIDFlag == 0 {
		chainID, err = client.ChainID(ctx)
		if err != nil {
			log.Fatalf("get chain id: %v", err)
		}
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		log.Fatal(err)
	}
	auth.Context = ctx
	auth.GasPrice = new(big.Int).SetUint64(*gasPriceFlag)
	addr, tx, _, err := bind.DeployContract(auth, abi.ABI{}, common.FromHex(bytecode), client)
	if err != nil {
		log.Fatalf("deploy contract: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[deploy] tx_hash=%s expected_contract=%s timeout=%s\n", tx.Hash().Hex(), addr.Hex(), timeoutFlag.String())
	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		log.Fatalf("wait deployment mined: %v", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		log.Fatalf("deployment reverted: tx=%s", tx.Hash().Hex())
	}
	fmt.Printf("%s\n", addr.Hex())
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadBytecode(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("bytecode is required")
	}
	if strings.HasPrefix(value, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(value, "@"))
		if err != nil {
			return "", err
		}
		value = string(data)
	}
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return "", fmt.Errorf("bytecode is empty")
	}
	return "0x" + value, nil
}

func parsePrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	hexKey = strings.TrimPrefix(strings.TrimSpace(hexKey), "0x")
	return crypto.HexToECDSA(hexKey)
}
