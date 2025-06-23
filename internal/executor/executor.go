package executor

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Executor handles contract deployment and transaction execution
type Executor struct {
	client     *ethclient.Client
	privateKey *ecdsa.PrivateKey
	address    common.Address
	nonce      uint64
}

// ExecutionResult represents the result of a transaction execution
type ExecutionResult struct {
	Success     bool   `json:"success"`
	TxHash      string `json:"tx_hash,omitempty"`
	Error       string `json:"error,omitempty"`
	GasUsed     uint64 `json:"gas_used,omitempty"`
	BlockNumber uint64 `json:"block_number,omitempty"`
}

// NewExecutor creates a new executor instance
func NewExecutor(client *ethclient.Client, privateKeyHex string) (*Executor, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get current nonce
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	return &Executor{
		client:     client,
		privateKey: privateKey,
		address:    address,
		nonce:      nonce,
	}, nil
}

// DeployContract deploys a contract to the network
func (e *Executor) DeployContract(bytecode string, abiData []byte, constructorArgs ...interface{}) (string, error) {
	// Parse ABI
	contractABI, err := abi.JSON(strings.NewReader(string(abiData)))
	if err != nil {
		return "", fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack constructor arguments
	input, err := contractABI.Pack("", constructorArgs...)
	if err != nil {
		return "", fmt.Errorf("failed to pack constructor arguments: %w", err)
	}

	// Combine bytecode with constructor arguments
	data := append(common.FromHex(bytecode), input...)

	// Get gas price
	gasPrice, err := e.client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get gas price: %w", err)
	}

	// Estimate gas
	gasLimit, err := e.client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:  e.address,
		Data:  data,
		Value: big.NewInt(0),
	})
	if err != nil {
		return "", fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Create transaction
	tx := types.NewContractCreation(e.nonce, big.NewInt(0), gasLimit, gasPrice, data)

	// Sign transaction
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, e.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	err = e.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for transaction receipt
	receipt, err := e.waitForTransaction(signedTx.Hash())
	if err != nil {
		return "", fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	if receipt.Status == 0 {
		return "", fmt.Errorf("contract deployment failed")
	}

	e.nonce++ // Increment nonce for next transaction

	return receipt.ContractAddress.Hex(), nil
}

// ExecuteFunction executes a function on a deployed contract
func (e *Executor) ExecuteFunction(contractAddress string, abiData []byte, functionName string, args ...interface{}) (*ExecutionResult, error) {
	// Parse ABI
	contractABI, err := abi.JSON(strings.NewReader(string(abiData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack function arguments
	input, err := contractABI.Pack(functionName, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack function arguments: %w", err)
	}

	// Get gas price
	gasPrice, err := e.client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}

	// Estimate gas
	gasLimit, err := e.client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:  e.address,
		To:    &common.Address{},
		Data:  input,
		Value: big.NewInt(0),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Create transaction
	to := common.HexToAddress(contractAddress)
	tx := types.NewTransaction(e.nonce, to, big.NewInt(0), gasLimit, gasPrice, input)

	// Sign transaction
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, e.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	err = e.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for transaction receipt
	receipt, err := e.waitForTransaction(signedTx.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	e.nonce++ // Increment nonce for next transaction

	result := &ExecutionResult{
		Success:     receipt.Status == 1,
		TxHash:      receipt.TxHash.Hex(),
		GasUsed:     receipt.GasUsed,
		BlockNumber: receipt.BlockNumber.Uint64(),
	}

	if receipt.Status == 0 {
		result.Error = "Transaction reverted"
	}

	return result, nil
}

// CallFunction makes a read-only call to a contract function
func (e *Executor) CallFunction(contractAddress string, abiData []byte, functionName string, args ...interface{}) ([]interface{}, error) {
	// Parse ABI
	contractABI, err := abi.JSON(strings.NewReader(string(abiData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack function arguments
	input, err := contractABI.Pack(functionName, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack function arguments: %w", err)
	}

	// Make call
	to := common.HexToAddress(contractAddress)
	msg := ethereum.CallMsg{
		From:  e.address,
		To:    &to,
		Data:  input,
		Value: big.NewInt(0),
	}

	result, err := e.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call contract: %w", err)
	}

	// Unpack result
	outputs, err := contractABI.Unpack(functionName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack result: %w", err)
	}

	return outputs, nil
}

// waitForTransaction waits for a transaction to be mined
func (e *Executor) waitForTransaction(hash common.Hash) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		receipt, err := e.client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for transaction")
		case <-time.After(1 * time.Second):
			continue
		}
	}
}

// GetBalance returns the balance of the executor's address
func (e *Executor) GetBalance() (*big.Int, error) {
	return e.client.BalanceAt(context.Background(), e.address, nil)
}

// GetAddress returns the executor's address
func (e *Executor) GetAddress() common.Address {
	return e.address
}
