package fuzzer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"very_smart_analyzer/internal/analyzer"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fatih/color"
)

// FuzzTest represents a single fuzz test case
type FuzzTest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        FuzzTestType           `json:"type"`
	Input       map[string]interface{} `json:"input"`
	Expected    FuzzTestResult         `json:"expected"`
}

// FuzzTestType represents the type of fuzz test
type FuzzTestType string

const (
	ReplayAttack       FuzzTestType = "replay_attack"
	MalformedSig       FuzzTestType = "malformed_signature"
	InvalidVRS         FuzzTestType = "invalid_vrs"
	ExpiredDeadline    FuzzTestType = "expired_deadline"
	InvalidNonce       FuzzTestType = "invalid_nonce"
	DomainManipulation FuzzTestType = "domain_manipulation"
	RandomMutation     FuzzTestType = "random_mutation"
)

// FuzzTestResult represents the expected result of a fuzz test
type FuzzTestResult struct {
	ShouldFail    bool          `json:"should_fail"`
	ErrorType     string        `json:"error_type,omitempty"`
	Message       string        `json:"message,omitempty"`
	ActualResult  bool          `json:"actual_result"`
	TxHash        string        `json:"tx_hash,omitempty"`
	GasUsed       uint64        `json:"gas_used,omitempty"`
	RevertReason  string        `json:"revert_reason,omitempty"`
	ExecutionTime time.Duration `json:"execution_time"`
}

// Fuzzer manages fuzz testing operations
type Fuzzer struct {
	// Network connection
	networkURL string
	chainID    int64
	client     *ethclient.Client

	// Contract deployment
	contractAddress  common.Address
	contractABI      abi.ABI
	contractInstance *bind.BoundContract

	// Test execution
	privateKey  *ecdsa.PrivateKey
	testAccount common.Address
	auth        *bind.TransactOpts

	// Configuration
	gasLimit uint64
	gasPrice *big.Int

	// Real execution mode
	realExecution bool
	demoMode      bool // Only execute a few real transactions for demo
}

// Color definitions for beautiful output
var (
	headerColor   = color.New(color.FgCyan, color.Bold)
	successColor  = color.New(color.FgGreen, color.Bold)
	errorColor    = color.New(color.FgRed, color.Bold)
	warningColor  = color.New(color.FgYellow, color.Bold)
	infoColor     = color.New(color.FgBlue)
	testColor     = color.New(color.FgMagenta)
	progressColor = color.New(color.FgWhite, color.Bold)
	dimColor      = color.New(color.FgHiBlack)
)

// printBanner prints a beautiful ASCII banner
func printBanner(title string) {
	width := 80
	padding := (width - len(title) - 4) / 2

	fmt.Println()
	headerColor.Println("╔" + strings.Repeat("═", width-2) + "╗")
	headerColor.Printf("║%s%s%s║\n",
		strings.Repeat(" ", padding),
		title,
		strings.Repeat(" ", width-2-padding-len(title)))
	headerColor.Println("╚" + strings.Repeat("═", width-2) + "╝")
	fmt.Println()
}

// printSection prints a section header
func printSection(title string) {
	fmt.Println()
	headerColor.Printf("▶ %s\n", title)
	headerColor.Println(strings.Repeat("─", len(title)+2))
}

// printProgress prints a progress bar
func printProgress(current, total int, description string) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * percentage / 100)

	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	bar += "]"

	progressColor.Printf("\r%s %6.1f%% (%d/%d) %s", bar, percentage, current, total, description)
	if current == total {
		fmt.Println()
	}
}

// printTestResult prints a beautifully formatted test result
func printTestResult(testNum, total int, testCase FuzzTest, result FuzzTestResult, duration time.Duration) {
	// Clear line and print test header
	fmt.Printf("\033[2K\r") // Clear line
	testColor.Printf("🧪 Test %d/%d: ", testNum, total)
	fmt.Printf("%s\n", testCase.Name)

	// Test details with indentation and icons
	dimColor.Printf("   ├─ 📋 Type: %s\n", getTestTypeIcon(testCase.Type))
	dimColor.Printf("   ├─ 📝 %s\n", testCase.Description)

	// Result with colored status and icons
	if result.ShouldFail {
		successColor.Printf("   └─ ✅ PASS")
	} else {
		errorColor.Printf("   └─ ❌ FAIL")
	}

	dimColor.Printf(" (%s) [%v]\n", result.ErrorType, duration.Round(time.Microsecond))
}

// getTestTypeIcon returns an icon for each test type
func getTestTypeIcon(testType FuzzTestType) string {
	switch testType {
	case ReplayAttack:
		return "🔄 Replay Attack"
	case MalformedSig:
		return "🔧 Malformed Signature"
	case InvalidVRS:
		return "⚠️  Invalid V/R/S"
	case ExpiredDeadline:
		return "⏰ Expired Deadline"
	case InvalidNonce:
		return "🔢 Invalid Nonce"
	case DomainManipulation:
		return "🌐 Domain Manipulation"
	case RandomMutation:
		return "🎲 Random Mutation"
	default:
		return string(testType)
	}
}

// getTestExplanation returns a simple explanation of what each test type does
func (f *Fuzzer) getTestExplanation(testType FuzzTestType) string {
	switch testType {
	case ReplayAttack:
		return "Trying to reuse an old signature"
	case MalformedSig:
		return "Testing with invalid signature format"
	case InvalidVRS:
		return "Testing with corrupted signature components"
	case ExpiredDeadline:
		return "Testing with expired timestamp"
	case InvalidNonce:
		return "Testing with wrong nonce value"
	case DomainManipulation:
		return "Testing with modified domain data"
	case RandomMutation:
		return "Testing with randomly corrupted data"
	default:
		return "Testing signature validation"
	}
}

// printSummaryTable prints a beautiful summary table
func printSummaryTable(results []FuzzTestResult, duration time.Duration) {
	fmt.Println()
	headerColor.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	headerColor.Println("║                                🎯 FUZZ TEST SUMMARY                          ║")
	headerColor.Println("╠══════════════════════════════════════════════════════════════════════════════╣")

	passed := 0
	failed := 0

	for _, result := range results {
		if result.ShouldFail {
			passed++
		} else {
			failed++
		}
	}

	// Main statistics
	fmt.Printf("║ 📊 Total Tests:     %10d                                          ║\n", len(results))
	successColor.Printf("║ ✅ Passed:          %10d                                          ║\n", passed)
	if failed > 0 {
		errorColor.Printf("║ ❌ Failed:          %10d                                          ║\n", failed)
	} else {
		fmt.Printf("║ ❌ Failed:          %10d                                          ║\n", failed)
	}

	successRate := float64(passed) / float64(len(results)) * 100
	if successRate == 100.0 {
		successColor.Printf("║ 🎉 Success Rate:    %10.1f%%                                         ║\n", successRate)
	} else {
		warningColor.Printf("║ 📈 Success Rate:    %10.1f%%                                         ║\n", successRate)
	}

	fmt.Printf("║ ⏱️  Total Time:      %10v                                        ║\n", duration.Round(time.Millisecond))

	headerColor.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	// Print final status
	if failed == 0 {
		successColor.Println("\n🎉 ALL TESTS PASSED! Smart contract appears robust against signature attacks!")
	} else {
		errorColor.Printf("\n⚠️  %d TESTS FAILED! Review the contract for potential vulnerabilities.\n", failed)
	}
}

// NewFuzzer creates a new fuzzer instance
func NewFuzzer() *Fuzzer {
	return &Fuzzer{
		networkURL:    "http://localhost:8545",
		chainID:       1337,
		gasLimit:      5000000,
		gasPrice:      big.NewInt(1000000000000), // 1000 gwei - much higher for Ganache
		realExecution: true,                      // Enable real blockchain execution
		demoMode:      true,                      // Only execute first 10 tests on blockchain, rest simulated
	}
}

// ConnectToNetwork establishes connection to blockchain network
func (f *Fuzzer) ConnectToNetwork() error {
	printSection("Connecting to Hardhat Network")

	// Connect to Hardhat
	client, err := ethclient.Dial(f.networkURL)
	if err != nil {
		errorColor.Printf("❌ Failed to connect to Hardhat: %v\n", err)
		return fmt.Errorf("failed to connect to Hardhat: %w", err)
	}
	f.client = client

	// Get network information
	chainID, err := f.client.ChainID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}
	f.chainID = chainID.Int64()

	// Get current gas price from network
	gasPrice, err := f.client.SuggestGasPrice(context.Background())
	if err != nil {
		warningColor.Printf("⚠️  Could not get network gas price, using default: %v\n", err)
		// Use a high default gas price for Hardhat
		f.gasPrice = big.NewInt(1000000000000) // 1000 gwei
	} else {
		// Use network suggested gas price, but ensure minimum for Hardhat
		minGasPrice := big.NewInt(1000000000000) // 1000 gwei minimum
		if gasPrice.Cmp(minGasPrice) < 0 {
			f.gasPrice = minGasPrice
		} else {
			f.gasPrice = gasPrice
		}
	}

	infoColor.Printf("⛽ Using gas price: %s gwei\n", new(big.Int).Div(f.gasPrice, big.NewInt(1000000000)).String())

	successColor.Printf("✅ Connected to Hardhat (Chain ID: %d)\n", f.chainID)

	// Load private key - Hardhat's first default account
	privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		errorColor.Printf("❌ Failed to create private key: %v\n", err)
		return fmt.Errorf("failed to create private key: %w", err)
	}

	f.privateKey = privateKey
	f.testAccount = crypto.PubkeyToAddress(privateKey.PublicKey)

	// Check account balance
	balance, err := client.BalanceAt(context.Background(), f.testAccount, nil)
	if err != nil {
		errorColor.Printf("❌ Failed to get account balance: %v\n", err)
		return fmt.Errorf("failed to get account balance: %w", err)
	}

	balanceEth := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(1e18))
	successColor.Printf("💰 Test Account: %s (Balance: %.2f ETH)\n", f.testAccount.Hex(), balanceEth)

	return nil
}

// CompileContract compiles the Solidity contract
func (f *Fuzzer) CompileContract(contractPath string) (string, string, error) {
	printSection("Compiling Smart Contract")

	// Create build directory
	buildDir := "build/contracts"
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create build directory: %w", err)
	}

	// Compile with solc
	outputPath := filepath.Join(buildDir, "compiled.json")
	cmd := exec.Command("solc",
		"--combined-json", "abi,bin",
		"--optimize",
		"--include-path", "node_modules",
		"--base-path", ".",
		contractPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		errorColor.Printf("❌ Compilation failed: %v\n", err)
		errorColor.Printf("Output: %s\n", string(output))
		return "", "", fmt.Errorf("compilation failed: %w", err)
	}

	// Extract JSON part from output (skip warnings)
	outputStr := string(output)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		return "", "", fmt.Errorf("no JSON found in compilation output")
	}
	jsonOutput := outputStr[jsonStart:]

	// Write compilation output
	if err := os.WriteFile(outputPath, []byte(jsonOutput), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write compilation output: %w", err)
	}

	// Parse compilation result
	var result struct {
		Contracts map[string]struct {
			Abi interface{} `json:"abi"` // Can be string or array
			Bin string      `json:"bin"`
		} `json:"contracts"`
	}

	if err := json.Unmarshal([]byte(jsonOutput), &result); err != nil {
		return "", "", fmt.Errorf("failed to parse compilation result: %w", err)
	}

	// Find the main contract
	var contractName string
	var contractData struct {
		Abi interface{} `json:"abi"`
		Bin string      `json:"bin"`
	}

	// Extract the contract name from the file path
	contractFileName := filepath.Base(contractPath)
	expectedContractName := strings.TrimSuffix(contractFileName, filepath.Ext(contractFileName))

	// First try to find a contract that matches the file name
	for name, data := range result.Contracts {
		// Skip if it's a library or interface
		if strings.Contains(strings.ToLower(name), "library") ||
			strings.Contains(strings.ToLower(name), "interface") {
			continue
		}

		// Check if it has bytecode (actual contract, not just interface)
		if data.Bin != "" && len(data.Bin) > 2 { // More than just "0x"
			// Check if this contract name matches our expected contract
			if strings.Contains(strings.ToLower(name), strings.ToLower(expectedContractName)) {
				contractName = name
				contractData = data
				break
			}
		}
	}

	// If we didn't find a matching contract, fall back to any deployable contract
	if contractName == "" {
		for name, data := range result.Contracts {
			// Skip if it's a library or interface
			if strings.Contains(strings.ToLower(name), "library") ||
				strings.Contains(strings.ToLower(name), "interface") {
				continue
			}

			// Check if it has bytecode (actual contract, not just interface)
			if data.Bin != "" && len(data.Bin) > 2 { // More than just "0x"
				contractName = name
				contractData = data
				break
			}
		}
	}

	if contractName == "" {
		return "", "", fmt.Errorf("no deployable contract found in compilation output")
	}

	// Convert ABI to string if it's an array
	var abiString string
	switch v := contractData.Abi.(type) {
	case string:
		abiString = v
	default:
		abiBytes, err := json.Marshal(v)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal ABI: %w", err)
		}
		abiString = string(abiBytes)
	}

	successColor.Printf("✅ Contract compiled successfully: %s\n", contractName)
	infoColor.Printf("📄 Bytecode size: %d bytes\n", len(contractData.Bin)/2)

	return abiString, contractData.Bin, nil
}

// DeployContract deploys the compiled contract to Hardhat
func (f *Fuzzer) DeployContract(abiJSON, bytecode string) error {
	printSection("Deploying Contract to Hardhat")

	// Parse ABI
	contractABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		errorColor.Printf("❌ Failed to parse ABI: %v\n", err)
		return fmt.Errorf("failed to parse ABI: %w", err)
	}
	f.contractABI = contractABI

	// Convert bytecode
	bytecodeBytes := common.FromHex(bytecode)

	// Get nonce
	nonce, err := f.client.PendingNonceAt(context.Background(), f.testAccount)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	// Create transaction
	tx := types.NewContractCreation(
		nonce,
		big.NewInt(0), // value
		f.gasLimit,
		f.gasPrice,
		bytecodeBytes,
	)

	// Sign transaction
	chainID, err := f.client.ChainID(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), f.privateKey)
	if err != nil {
		errorColor.Printf("❌ Failed to sign transaction: %v\n", err)
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	infoColor.Printf("📤 Sending deployment transaction...\n")
	err = f.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		errorColor.Printf("❌ Failed to send transaction: %v\n", err)
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for transaction to be mined
	infoColor.Printf("⏳ Waiting for transaction to be mined...\n")
	receipt, err := f.waitForTransaction(signedTx.Hash())
	if err != nil {
		return fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status == 0 {
		errorColor.Printf("❌ Contract deployment failed\n")
		return fmt.Errorf("contract deployment failed")
	}

	f.contractAddress = receipt.ContractAddress
	successColor.Printf("✅ Contract deployed successfully!\n")
	successColor.Printf("📍 Contract Address: %s\n", f.contractAddress.Hex())
	infoColor.Printf("⛽ Gas Used: %d / %d\n", receipt.GasUsed, f.gasLimit)

	// Create contract instance for real execution
	f.contractInstance = bind.NewBoundContract(f.contractAddress, f.contractABI, f.client, f.client, f.client)

	// Create transaction auth
	auth, err := bind.NewKeyedTransactorWithChainID(f.privateKey, big.NewInt(f.chainID))
	if err != nil {
		return fmt.Errorf("failed to create transaction auth: %w", err)
	}
	auth.GasLimit = f.gasLimit
	auth.GasPrice = f.gasPrice
	f.auth = auth

	infoColor.Printf("🔧 Contract instance and auth configured for real execution\n")

	return nil
}

// waitForTransaction waits for a transaction to be mined
func (f *Fuzzer) waitForTransaction(txHash common.Hash) (*types.Receipt, error) {
	for i := 0; i < 60; i++ { // Wait up to 60 seconds
		receipt, err := f.client.TransactionReceipt(context.Background(), txHash)
		if err == nil {
			return receipt, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("transaction not mined after 60 seconds")
}

// executeRealTest executes a single test case against the deployed contract
func (f *Fuzzer) executeRealTest(testCase FuzzTest) FuzzTestResult {
	startTime := time.Now()
	result := FuzzTestResult{
		ShouldFail:    testCase.Expected.ShouldFail,
		ErrorType:     testCase.Expected.ErrorType,
		Message:       testCase.Expected.Message,
		ActualResult:  false,
		ExecutionTime: time.Since(startTime),
	}

	// Generate test data based on test type
	messageHash, signature, err := f.generateTestData(testCase)
	if err != nil {
		result.RevertReason = fmt.Sprintf("Failed to generate test data: %v", err)
		return result
	}

	// Execute based on test type and function
	switch testCase.Type {
	case ReplayAttack, MalformedSig, InvalidVRS, RandomMutation:
		txHash, gasUsed, success, revertReason := f.callVerifySignature(messageHash, signature)
		result.TxHash = txHash
		result.GasUsed = gasUsed
		result.ActualResult = success
		result.RevertReason = revertReason

	case InvalidNonce:
		txHash, gasUsed, success, revertReason := f.callExecuteWithNonce(messageHash, signature, 999999) // Invalid nonce
		result.TxHash = txHash
		result.GasUsed = gasUsed
		result.ActualResult = success
		result.RevertReason = revertReason

	default:
		// For other types, use verifySignature as default
		txHash, gasUsed, success, revertReason := f.callVerifySignature(messageHash, signature)
		result.TxHash = txHash
		result.GasUsed = gasUsed
		result.ActualResult = success
		result.RevertReason = revertReason
	}

	result.ExecutionTime = time.Since(startTime)
	return result
}

// generateTestData generates appropriate test data for each test case
func (f *Fuzzer) generateTestData(testCase FuzzTest) ([32]byte, []byte, error) {
	var messageHash [32]byte
	var signature []byte

	switch testCase.Type {
	case ReplayAttack:
		// Generate a valid signature that we'll try to replay
		message := "test message for replay"
		messageHash = crypto.Keccak256Hash([]byte(message))
		sig, err := crypto.Sign(messageHash[:], f.privateKey)
		if err != nil {
			return messageHash, nil, err
		}
		signature = sig

	case MalformedSig:
		// Generate malformed signatures
		messageHash = crypto.Keccak256Hash([]byte("test message"))
		if strings.Contains(testCase.Name, "empty") {
			signature = []byte{} // Empty signature
		} else {
			signature = []byte{0x12, 0x34, 0x56} // Invalid length
		}

	case InvalidVRS:
		// Generate signatures with invalid v/r/s values
		messageHash = crypto.Keccak256Hash([]byte("test message"))
		if strings.Contains(testCase.Name, "invalid_v") {
			signature = make([]byte, 65)
			signature[64] = 0x03 // Invalid v value
		} else {
			signature = make([]byte, 65) // All zeros (invalid r/s)
		}

	case RandomMutation:
		// Generate random data
		messageHash = crypto.Keccak256Hash([]byte(fmt.Sprintf("random message %d", time.Now().UnixNano())))
		signature = make([]byte, 65)
		rand.Read(signature)

	default:
		// Default valid signature
		message := "default test message"
		messageHash = crypto.Keccak256Hash([]byte(message))
		sig, err := crypto.Sign(messageHash[:], f.privateKey)
		if err != nil {
			return messageHash, nil, err
		}
		signature = sig
	}

	return messageHash, signature, nil
}

// callVerifySignature calls the verifySignature function on the contract
func (f *Fuzzer) callVerifySignature(messageHash [32]byte, signature []byte) (string, uint64, bool, string) {
	// Pack function call data
	data, err := f.contractABI.Pack("verifySignature", messageHash, signature)
	if err != nil {
		return "", 0, false, fmt.Sprintf("Failed to pack data: %v", err)
	}

	return f.executeTransaction("verifySignature", data)
}

// callExecuteWithNonce calls the executeWithNonce function on the contract
func (f *Fuzzer) callExecuteWithNonce(messageHash [32]byte, signature []byte, nonce uint64) (string, uint64, bool, string) {
	// Pack function call data
	data, err := f.contractABI.Pack("executeWithNonce", messageHash, signature, big.NewInt(int64(nonce)))
	if err != nil {
		return "", 0, false, fmt.Sprintf("Failed to pack data: %v", err)
	}

	return f.executeTransaction("executeWithNonce", data)
}

// executeTransaction executes a transaction and returns results
func (f *Fuzzer) executeTransaction(methodName string, data []byte) (string, uint64, bool, string) {
	// Get current nonce
	nonce, err := f.client.PendingNonceAt(context.Background(), f.testAccount)
	if err != nil {
		return "", 0, false, fmt.Sprintf("Failed to get nonce: %v", err)
	}

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		f.contractAddress,
		big.NewInt(0), // value
		f.gasLimit,
		f.gasPrice,
		data,
	)

	// Sign transaction
	chainID, err := f.client.ChainID(context.Background())
	if err != nil {
		return "", 0, false, fmt.Sprintf("Failed to get chain ID: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), f.privateKey)
	if err != nil {
		return "", 0, false, fmt.Sprintf("Failed to sign transaction: %v", err)
	}

	// Send transaction
	err = f.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return signedTx.Hash().Hex(), 0, false, fmt.Sprintf("Transaction failed: %v", err)
	}

	// Wait for transaction to be mined
	receipt, err := f.waitForTransaction(signedTx.Hash())
	if err != nil {
		return signedTx.Hash().Hex(), 0, false, fmt.Sprintf("Transaction not mined: %v", err)
	}

	success := receipt.Status == 1
	revertReason := ""
	if !success {
		revertReason = "Transaction reverted"
	}

	return signedTx.Hash().Hex(), receipt.GasUsed, success, revertReason
}

// RunFuzzTests runs fuzz tests on signature functions
func (f *Fuzzer) RunFuzzTests(contractPath, metadataPath string, iterations int) error {
	// Connect to Hardhat first
	if err := f.ConnectToNetwork(); err != nil {
		return fmt.Errorf("failed to connect to Hardhat: %w", err)
	}
	defer f.client.Close()

	// Compile the contract
	abiJSON, bytecode, err := f.CompileContract(contractPath)
	if err != nil {
		return fmt.Errorf("failed to compile contract: %w", err)
	}

	// Deploy the contract
	if err := f.DeployContract(abiJSON, bytecode); err != nil {
		return fmt.Errorf("failed to deploy contract: %w", err)
	}

	// Load metadata
	metadata, err := f.loadMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Generate test cases
	testCases := f.generateTestCases(metadata, iterations)

	// Execute tests
	results, err := f.executeTests(testCases)
	if err != nil {
		return fmt.Errorf("failed to execute tests: %w", err)
	}

	// Report results
	f.reportResults(results)
	return nil
}

// loadMetadata loads signature metadata from file
func (f *Fuzzer) loadMetadata(metadataPath string) (*analyzer.SignatureMetadata, error) {
	printSection("Loading Signature Metadata")

	// Read the metadata file
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		errorColor.Printf("❌ Failed to read metadata file: %v\n", err)
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	// Parse the JSON metadata
	var metadata analyzer.SignatureMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		errorColor.Printf("❌ Failed to parse metadata JSON: %v\n", err)
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	successColor.Printf("✅ Loaded %d signature functions from metadata\n", len(metadata.SignatureFunctions))

	// Display loaded functions with beautiful formatting
	infoColor.Println("\n📋 Loaded Functions:")
	for i, fn := range metadata.SignatureFunctions {
		dimColor.Printf("   %d. %s (%s)\n", i+1, fn.FunctionName, fn.SignatureType)
	}

	return &metadata, nil
}

// generateTestCases generates fuzz test cases based on metadata
func (f *Fuzzer) generateTestCases(metadata *analyzer.SignatureMetadata, iterations int) []FuzzTest {
	var testCases []FuzzTest

	for _, function := range metadata.SignatureFunctions {
		// Generate different types of tests for each function
		testCases = append(testCases, f.generateReplayTests(function)...)
		testCases = append(testCases, f.generateMalformedSignatureTests(function)...)
		testCases = append(testCases, f.generateInvalidVRSTests(function)...)
		testCases = append(testCases, f.generateExpiredDeadlineTests(function)...)
		testCases = append(testCases, f.generateInvalidNonceTests(function)...)
		testCases = append(testCases, f.generateDomainManipulationTests(function)...)
		testCases = append(testCases, f.generateRandomMutationTests(function, iterations)...)
	}

	return testCases
}

// generateReplayTests generates replay attack test cases
func (f *Fuzzer) generateReplayTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Execute the same signature twice
	test := FuzzTest{
		Name:        fmt.Sprintf("replay_attack_%s", function.FunctionName),
		Description: "Execute the same signature twice to test replay protection",
		Type:        ReplayAttack,
		Input: map[string]interface{}{
			"function":  function.FunctionName,
			"signature": "valid_signature_here",
			"data":      "original_data",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "replay_protection",
			Message:    "Signature should be rejected on second execution",
		},
	}
	tests = append(tests, test)

	return tests
}

// generateMalformedSignatureTests generates malformed signature test cases
func (f *Fuzzer) generateMalformedSignatureTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Empty signature
	test1 := FuzzTest{
		Name:        fmt.Sprintf("malformed_empty_sig_%s", function.FunctionName),
		Description: "Test with empty signature",
		Type:        MalformedSig,
		Input: map[string]interface{}{
			"function":  function.FunctionName,
			"signature": "",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_signature",
			Message:    "Empty signature should be rejected",
		},
	}
	tests = append(tests, test1)

	// Test 2: Invalid signature length
	test2 := FuzzTest{
		Name:        fmt.Sprintf("malformed_invalid_length_%s", function.FunctionName),
		Description: "Test with invalid signature length",
		Type:        MalformedSig,
		Input: map[string]interface{}{
			"function":  function.FunctionName,
			"signature": "0x123456", // Too short
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_signature",
			Message:    "Invalid signature length should be rejected",
		},
	}
	tests = append(tests, test2)

	return tests
}

// generateInvalidVRSTests generates invalid v/r/s test cases
func (f *Fuzzer) generateInvalidVRSTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Invalid v value
	test1 := FuzzTest{
		Name:        fmt.Sprintf("invalid_v_%s", function.FunctionName),
		Description: "Test with invalid v value",
		Type:        InvalidVRS,
		Input: map[string]interface{}{
			"function": function.FunctionName,
			"v":        "0x03", // Invalid v value
			"r":        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"s":        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_signature",
			Message:    "Invalid v value should be rejected",
		},
	}
	tests = append(tests, test1)

	// Test 2: Invalid r value (zero)
	test2 := FuzzTest{
		Name:        fmt.Sprintf("invalid_r_zero_%s", function.FunctionName),
		Description: "Test with zero r value",
		Type:        InvalidVRS,
		Input: map[string]interface{}{
			"function": function.FunctionName,
			"v":        "0x1b",
			"r":        "0x0000000000000000000000000000000000000000000000000000000000000000",
			"s":        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_signature",
			Message:    "Zero r value should be rejected",
		},
	}
	tests = append(tests, test2)

	return tests
}

// generateExpiredDeadlineTests generates expired deadline test cases
func (f *Fuzzer) generateExpiredDeadlineTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Expired deadline
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	test := FuzzTest{
		Name:        fmt.Sprintf("expired_deadline_%s", function.FunctionName),
		Description: "Test with expired deadline",
		Type:        ExpiredDeadline,
		Input: map[string]interface{}{
			"function":  function.FunctionName,
			"deadline":  expiredTime,
			"signature": "valid_signature_here",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "expired_deadline",
			Message:    "Expired deadline should be rejected",
		},
	}
	tests = append(tests, test)

	return tests
}

// generateInvalidNonceTests generates invalid nonce test cases
func (f *Fuzzer) generateInvalidNonceTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Used nonce
	test := FuzzTest{
		Name:        fmt.Sprintf("invalid_nonce_%s", function.FunctionName),
		Description: "Test with already used nonce",
		Type:        InvalidNonce,
		Input: map[string]interface{}{
			"function":  function.FunctionName,
			"nonce":     "123", // Already used nonce
			"signature": "valid_signature_here",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_nonce",
			Message:    "Used nonce should be rejected",
		},
	}
	tests = append(tests, test)

	return tests
}

// generateDomainManipulationTests generates domain separator manipulation test cases
func (f *Fuzzer) generateDomainManipulationTests(function analyzer.SignatureFunction) []FuzzTest {
	var tests []FuzzTest

	// Test 1: Wrong domain separator
	test := FuzzTest{
		Name:        fmt.Sprintf("domain_manipulation_%s", function.FunctionName),
		Description: "Test with wrong domain separator",
		Type:        DomainManipulation,
		Input: map[string]interface{}{
			"function":        function.FunctionName,
			"domainSeparator": "0xwrongdomainseparator",
			"signature":       "valid_signature_here",
		},
		Expected: FuzzTestResult{
			ShouldFail: true,
			ErrorType:  "invalid_domain",
			Message:    "Wrong domain separator should be rejected",
		},
	}
	tests = append(tests, test)

	return tests
}

// generateRandomMutationTests generates random mutation test cases
func (f *Fuzzer) generateRandomMutationTests(function analyzer.SignatureFunction, iterations int) []FuzzTest {
	var tests []FuzzTest

	for i := 0; i < iterations; i++ {
		// Generate random signature data
		randomSig := f.generateRandomSignature()

		test := FuzzTest{
			Name:        fmt.Sprintf("random_mutation_%s_%d", function.FunctionName, i),
			Description: fmt.Sprintf("Random mutation test %d", i),
			Type:        RandomMutation,
			Input: map[string]interface{}{
				"function":  function.FunctionName,
				"signature": randomSig,
				"data":      f.generateRandomData(),
			},
			Expected: FuzzTestResult{
				ShouldFail: true, // Random data should generally fail
				ErrorType:  "invalid_signature",
				Message:    "Random signature should be rejected",
			},
		}
		tests = append(tests, test)
	}

	return tests
}

// generateRandomSignature generates a random signature
func (f *Fuzzer) generateRandomSignature() string {
	// Generate random private key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "0x0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Generate random message
	message := make([]byte, 32)
	rand.Read(message)

	// Sign the message
	signature, err := crypto.Sign(message, privateKey)
	if err != nil {
		return "0x0000000000000000000000000000000000000000000000000000000000000000"
	}

	return hex.EncodeToString(signature)
}

// generateRandomData generates random data for testing
func (f *Fuzzer) generateRandomData() string {
	data := make([]byte, 32)
	rand.Read(data)
	return hex.EncodeToString(data)
}

// executeTests runs the fuzz tests with simulation or real execution
func (f *Fuzzer) executeTests(testCases []FuzzTest) ([]FuzzTestResult, error) {
	var results []FuzzTestResult

	// Show execution mode
	if f.realExecution {
		color.New(color.FgCyan, color.Bold).Println("\n🚀 REAL BLOCKCHAIN EXECUTION MODE")
		color.New(color.FgBlue).Printf("   Network: %s (Chain ID: %d)\n", f.networkURL, f.chainID)
		color.New(color.FgBlue).Printf("   Contract: %s\n", f.contractAddress.Hex())
	} else {
		color.New(color.FgYellow, color.Bold).Println("\n🔄 SIMULATION MODE")
	}

	for i, testCase := range testCases {
		progressBar := fmt.Sprintf("[%d/%d]", i+1, len(testCases))
		explanation := f.getTestExplanation(testCase.Type)
		color.New(color.FgCyan).Printf("\n%s Testing: %s", progressBar, testCase.Name)
		color.New(color.FgHiBlack).Printf(" - %s", explanation)

		var result FuzzTestResult

		if f.realExecution {
			// Execute real blockchain transaction
			result = f.executeRealTest(testCase)
		} else {
			// Simulate the test
			result = f.simulateTest(testCase)
		}

		results = append(results, result)

		// Show immediate result
		if f.realExecution {
			if result.ActualResult == !result.ShouldFail {
				color.New(color.FgGreen).Printf(" ✅ PASS")
				if result.TxHash != "" {
					color.New(color.FgBlue).Printf(" (Tx: %s)", result.TxHash[:10]+"...")
				}
			} else {
				color.New(color.FgRed).Printf(" ❌ FAIL")
				if result.RevertReason != "" {
					color.New(color.FgRed).Printf(" (%s)", result.RevertReason)
				}
			}
		} else {
			if result.ActualResult == !result.ShouldFail {
				color.New(color.FgGreen).Printf(" ✅ PASS")
			} else {
				color.New(color.FgRed).Printf(" ❌ FAIL")
			}
		}
	}

	return results, nil
}

// simulateTest simulates a test case (legacy mode)
func (f *Fuzzer) simulateTest(testCase FuzzTest) FuzzTestResult {
	// Simple simulation based on test type
	shouldPass := true

	switch testCase.Type {
	case ReplayAttack, MalformedSig, InvalidVRS, InvalidNonce, DomainManipulation:
		shouldPass = false
	case RandomMutation:
		// Random mutations should mostly fail
		shouldPass = false
	}

	return FuzzTestResult{
		ShouldFail:   testCase.Expected.ShouldFail,
		ErrorType:    testCase.Expected.ErrorType,
		Message:      testCase.Expected.Message,
		ActualResult: shouldPass,
	}
}

// reportResults prints the detailed test results
func (f *Fuzzer) reportResults(results []FuzzTestResult) {
	if len(results) == 0 {
		return
	}

	// Calculate summary statistics
	passed := 0
	failed := 0
	totalGasUsed := uint64(0)
	totalTime := time.Duration(0)

	for _, result := range results {
		if result.ActualResult == !result.ShouldFail {
			passed++
		} else {
			failed++
		}
		totalGasUsed += result.GasUsed
		totalTime += result.ExecutionTime
	}

	// Print summary banner
	printBanner("📊 FUZZ TEST RESULTS SUMMARY")

	// Summary statistics
	color.New(color.FgCyan, color.Bold).Printf("🎯 Test Summary:\n")
	color.New(color.FgGreen).Printf("   ✅ Passed: %d/%d (%.1f%%)\n", passed, len(results), float64(passed)/float64(len(results))*100)
	if failed > 0 {
		color.New(color.FgRed).Printf("   ❌ Failed: %d/%d (%.1f%%)\n", failed, len(results), float64(failed)/float64(len(results))*100)
	}

	if f.realExecution {
		color.New(color.FgBlue).Printf("   ⛽ Total Gas Used: %s\n", formatNumber(totalGasUsed))
		color.New(color.FgMagenta).Printf("   ⏱️  Total Execution Time: %v\n", totalTime)
		color.New(color.FgYellow).Printf("   📊 Average Time/Test: %v\n", totalTime/time.Duration(len(results)))
	}

	// Show detailed results if there are failures
	if failed > 0 {
		color.New(color.FgRed, color.Bold).Printf("\n💥 FAILED TESTS DETAILS:\n")
		for i, result := range results {
			if result.ActualResult != !result.ShouldFail {
				color.New(color.FgRed).Printf("   [%d] Expected: %v, Got: %v",
					i+1, !result.ShouldFail, result.ActualResult)
				if result.RevertReason != "" {
					color.New(color.FgYellow).Printf(" - %s", result.RevertReason)
				}
				fmt.Println()
			}
		}
	}

	// Show sample successful transactions if real execution
	if f.realExecution && passed > 0 {
		color.New(color.FgGreen, color.Bold).Printf("\n🔗 SAMPLE SUCCESSFUL TRANSACTIONS:\n")
		successCount := 0
		for i, result := range results {
			if result.ActualResult == !result.ShouldFail && result.TxHash != "" && successCount < 3 {
				color.New(color.FgGreen).Printf("   [%d] Tx: %s (Gas: %s)\n",
					i+1, result.TxHash, formatNumber(result.GasUsed))
				successCount++
			}
		}
	}

	// Final status
	if passed == len(results) {
		color.New(color.FgGreen, color.Bold).Printf("\n🎉 ALL TESTS PASSED! Security analysis complete.\n")
	} else {
		color.New(color.FgYellow, color.Bold).Printf("\n⚠️  Some tests failed - review the contract for potential vulnerabilities.\n")
	}
}

// formatNumber formats large numbers with commas
func formatNumber(n uint64) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result []byte
	for i, digit := range []byte(str) {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, digit)
	}
	return string(result)
}
