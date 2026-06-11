package ledger

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const anchorRegistryABI = `[
  {"inputs":[{"internalType":"string","name":"containerInstanceID","type":"string"},{"internalType":"uint64","name":"containerBatchID","type":"uint64"},{"internalType":"uint64","name":"firstContainerSeq","type":"uint64"},{"internalType":"uint64","name":"lastContainerSeq","type":"uint64"},{"internalType":"uint64","name":"firstGlobalSeq","type":"uint64"},{"internalType":"uint64","name":"lastGlobalSeq","type":"uint64"},{"internalType":"string","name":"containerMerkleRoot","type":"string"},{"internalType":"string","name":"containerBatchHash","type":"string"},{"internalType":"string","name":"previousContainerBatchHash","type":"string"},{"internalType":"uint64","name":"eventCount","type":"uint64"},{"internalType":"uint64","name":"droppedEventCount","type":"uint64"},{"internalType":"uint64","name":"startTimeNS","type":"uint64"},{"internalType":"uint64","name":"endTimeNS","type":"uint64"},{"internalType":"string","name":"collectorID","type":"string"}],"name":"appendAnchor","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"string","name":"containerInstanceID","type":"string"},{"internalType":"uint64","name":"containerBatchID","type":"uint64"}],"name":"getAnchor","outputs":[{"internalType":"uint64","name":"blockHeight","type":"uint64"},{"internalType":"string","name":"txID","type":"string"},{"internalType":"string","name":"outContainerInstanceID","type":"string"},{"internalType":"uint64","name":"outContainerBatchID","type":"uint64"},{"internalType":"uint64","name":"firstContainerSeq","type":"uint64"},{"internalType":"uint64","name":"lastContainerSeq","type":"uint64"},{"internalType":"uint64","name":"firstGlobalSeq","type":"uint64"},{"internalType":"uint64","name":"lastGlobalSeq","type":"uint64"},{"internalType":"string","name":"containerMerkleRoot","type":"string"},{"internalType":"string","name":"containerBatchHash","type":"string"},{"internalType":"string","name":"previousContainerBatchHash","type":"string"},{"internalType":"uint64","name":"eventCount","type":"uint64"},{"internalType":"uint64","name":"droppedEventCount","type":"uint64"},{"internalType":"uint64","name":"startTimeNS","type":"uint64"},{"internalType":"uint64","name":"endTimeNS","type":"uint64"},{"internalType":"string","name":"collectorID","type":"string"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"string","name":"containerInstanceID","type":"string"}],"name":"getContainerBatchCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"string","name":"containerInstanceID","type":"string"},{"internalType":"uint256","name":"index","type":"uint256"}],"name":"getContainerBatchID","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}
]`

type BesuLedger struct {
	client   *ethclient.Client
	contract common.Address
	abi      abi.ABI
	chainID  *big.Int
	key      *ecdsa.PrivateKey
}

func NewBesuLedger(cfg Config) (*BesuLedger, error) {
	if cfg.BesuRPCURL == "" {
		return nil, errors.New("besu rpc url is required")
	}
	if !common.IsHexAddress(cfg.BesuContract) {
		return nil, fmt.Errorf("invalid besu contract address %q", cfg.BesuContract)
	}
	client, err := ethclient.Dial(cfg.BesuRPCURL)
	if err != nil {
		return nil, fmt.Errorf("connect besu rpc: %w", err)
	}
	parsedABI, err := abi.JSON(strings.NewReader(anchorRegistryABI))
	if err != nil {
		return nil, err
	}
	chainID := new(big.Int).SetUint64(cfg.BesuChainID)
	if cfg.BesuChainID == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		chainID, err = client.ChainID(ctx)
		if err != nil {
			return nil, fmt.Errorf("get besu chain id: %w", err)
		}
	}
	key, err := loadPrivateKey(cfg.BesuPrivateKey, cfg.BesuKeyFile)
	if err != nil {
		return nil, err
	}
	return &BesuLedger{client: client, contract: common.HexToAddress(cfg.BesuContract), abi: parsedABI, chainID: chainID, key: key}, nil
}

func (l *BesuLedger) AppendAnchor(record AnchorRecord) (string, uint64, error) {
	if l.key == nil {
		return "", 0, errors.New("besu private key is required for AppendAnchor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	auth, err := bind.NewKeyedTransactorWithChainID(l.key, l.chainID)
	if err != nil {
		return "", 0, err
	}
	auth.Context = ctx
	contract := bind.NewBoundContract(l.contract, l.abi, l.client, l.client, l.client)
	tx, err := contract.Transact(auth, "appendAnchor",
		record.ContainerInstanceID,
		record.ContainerBatchID,
		record.FirstContainerSeq,
		record.LastContainerSeq,
		record.FirstGlobalSeq,
		record.LastGlobalSeq,
		record.ContainerMerkleRoot,
		record.ContainerBatchHash,
		record.PreviousContainerBatchHash,
		record.EventCount,
		record.DroppedEventCount,
		record.StartTimeNS,
		record.EndTimeNS,
		record.CollectorID,
	)
	if err != nil {
		return "", 0, fmt.Errorf("submit anchor tx: %w", err)
	}
	receipt, err := bind.WaitMined(ctx, l.client, tx)
	if err != nil {
		return tx.Hash().Hex(), 0, fmt.Errorf("wait anchor tx mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return tx.Hash().Hex(), receipt.BlockNumber.Uint64(), fmt.Errorf("anchor tx reverted: %s", tx.Hash().Hex())
	}
	return tx.Hash().Hex(), receipt.BlockNumber.Uint64(), nil
}

func (l *BesuLedger) GetAnchor(containerInstanceID string, batchID uint64) (AnchorRecord, error) {
	var out []interface{}
	if err := l.call(&out, "getAnchor", containerInstanceID, batchID); err != nil {
		return AnchorRecord{}, err
	}
	if len(out) != 16 {
		return AnchorRecord{}, fmt.Errorf("unexpected getAnchor output count %d", len(out))
	}
	return anchorFromContractOutput(out)
}

func (l *BesuLedger) ListAnchors(containerInstanceID string) ([]AnchorRecord, error) {
	var countOut []interface{}
	if err := l.call(&countOut, "getContainerBatchCount", containerInstanceID); err != nil {
		return nil, err
	}
	if len(countOut) != 1 {
		return nil, fmt.Errorf("unexpected batch count output count %d", len(countOut))
	}
	count := countOut[0].(*big.Int).Uint64()
	anchors := make([]AnchorRecord, 0, count)
	for i := uint64(0); i < count; i++ {
		var idOut []interface{}
		if err := l.call(&idOut, "getContainerBatchID", containerInstanceID, new(big.Int).SetUint64(i)); err != nil {
			return nil, err
		}
		batchID := idOut[0].(uint64)
		anchor, err := l.GetAnchor(containerInstanceID, batchID)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, anchor)
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].ContainerBatchID < anchors[j].ContainerBatchID })
	return anchors, nil
}

func (l *BesuLedger) VerifyLedgerChain() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := l.client.HeaderByNumber(ctx, nil)
	return err
}

func (l *BesuLedger) call(out *[]interface{}, method string, args ...interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	input, err := l.abi.Pack(method, args...)
	if err != nil {
		return err
	}
	msg := ethereum.CallMsg{To: &l.contract, Data: input}
	result, err := l.client.CallContract(ctx, msg, nil)
	if err != nil {
		return err
	}
	values, err := l.abi.Unpack(method, result)
	if err != nil {
		return err
	}
	*out = values
	return nil
}

func anchorFromContractOutput(out []interface{}) (AnchorRecord, error) {
	return AnchorRecord{
		BlockHeight:                out[0].(uint64),
		TxID:                       out[1].(string),
		ContainerInstanceID:        out[2].(string),
		ContainerBatchID:           out[3].(uint64),
		FirstContainerSeq:          out[4].(uint64),
		LastContainerSeq:           out[5].(uint64),
		FirstGlobalSeq:             out[6].(uint64),
		LastGlobalSeq:              out[7].(uint64),
		ContainerMerkleRoot:        out[8].(string),
		ContainerBatchHash:         out[9].(string),
		PreviousContainerBatchHash: out[10].(string),
		EventCount:                 out[11].(uint64),
		DroppedEventCount:          out[12].(uint64),
		StartTimeNS:                out[13].(uint64),
		EndTimeNS:                  out[14].(uint64),
		CollectorID:                out[15].(string),
	}, nil
}

func loadPrivateKey(hexKey, keyFile string) (*ecdsa.PrivateKey, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		hexKey = strings.TrimSpace(string(data))
	}
	if hexKey == "" {
		return nil, nil
	}
	hexKey = strings.TrimPrefix(strings.TrimSpace(hexKey), "0x")
	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		return nil, fmt.Errorf("parse besu private key: %w", err)
	}
	return key, nil
}
