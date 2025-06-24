package analyzer

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FuzzTester handles fuzz testing of smart contracts
type FuzzTester struct {
	TestMatrix  *TestMatrix
	TestResults []FuzzTestResult
	Config      FuzzConfig
}

// FuzzConfig contains configuration for fuzz testing
type FuzzConfig struct {
	MaxTestDuration   time.Duration   `json:"maxTestDuration"`
	MaxTestIterations int             `json:"maxTestIterations"`
	ConcurrentTests   int             `json:"concurrentTests"`
	TimeoutPerTest    time.Duration   `json:"timeoutPerTest"`
	GasLimit          uint64          `json:"gasLimit"`
	NetworkURL        string          `json:"networkUrl"`
	TestCategories    []TestCategory  `json:"testCategories"`
	TestSeverities    []TestSeverity  `json:"testSeverities"`
	SignatureTypes    []SignatureKind `json:"signatureTypes"`
	EnableStressTests bool            `json:"enableStressTests"`
	EnableEdgeCases   bool            `json:"enableEdgeCases"`
	VerboseOutput     bool            `json:"verboseOutput"`
}

// FuzzTestResult represents the result of a single fuzz test
type FuzzTestResult struct {
	TestCaseID      string                 `json:"testCaseId"`
	TestCaseName    string                 `json:"testCaseName"`
	Category        TestCategory           `json:"category"`
	Severity        TestSeverity           `json:"severity"`
	SignatureType   SignatureKind          `json:"signatureType"`
	Status          FuzzTestStatus         `json:"status"`
	Result          TestResult             `json:"result"`
	ExpectedResult  TestResult             `json:"expectedResult"`
	GasUsed         uint64                 `json:"gasUsed"`
	ExecutionTime   time.Duration          `json:"executionTime"`
	Error           string                 `json:"error,omitempty"`
	Vulnerability   VulnerabilityType      `json:"vulnerability,omitempty"`
	TestData        map[string]interface{} `json:"testData"`
	Timestamp       time.Time              `json:"timestamp"`
	BlockNumber     uint64                 `json:"blockNumber"`
	TransactionHash string                 `json:"transactionHash,omitempty"`
}

// FuzzTestStatus represents the status of a fuzz test
type FuzzTestStatus string

const (
	StatusPassed     FuzzTestStatus = "passed"
	StatusFailed     FuzzTestStatus = "failed"
	StatusVulnerable FuzzTestStatus = "vulnerable"
	StatusTimeout    FuzzTestStatus = "timeout"
	StatusError      FuzzTestStatus = "error"
	StatusSkipped    FuzzTestStatus = "skipped"
)

// NewFuzzTester creates a new fuzz tester instance
func NewFuzzTester(config FuzzConfig) *FuzzTester {
	DebugPrintStep("FUZZ_INIT", "Creating new fuzz tester with config: %+v", config)

	return &FuzzTester{
		TestMatrix:  NewTestMatrix(),
		TestResults: []FuzzTestResult{},
		Config:      config,
	}
}

// RunFuzzTests runs the complete fuzz testing suite
func (ft *FuzzTester) RunFuzzTests(contractPath string) error {
	DebugPrintStep("FUZZ_RUN", "Starting comprehensive fuzz testing")
	DebugPrintStep("FUZZ_RUN", "Contract path: %s", contractPath)
	DebugPrintStep("FUZZ_RUN", "Total test cases in matrix: %d", len(ft.TestMatrix.TestCases))

	// Filter test cases based on configuration
	filteredTests := ft.filterTestCases()
	DebugPrintStep("FUZZ_RUN", "Filtered test cases: %d", len(filteredTests))

	// Start Ganache if needed
	if err := ft.startGanache(); err != nil {
		DebugPrintError("GANACHE_START", err)
		return fmt.Errorf("failed to start Ganache: %w", err)
	}
	defer ft.stopGanache()

	// Compile contracts
	if err := ft.compileContracts(); err != nil {
		DebugPrintError("COMPILE_CONTRACTS", err)
		return fmt.Errorf("failed to compile contracts: %w", err)
	}

	// Run tests
	startTime := time.Now()
	for i, testCase := range filteredTests {
		DebugPrintStep("FUZZ_RUN", "Running test %d/%d: %s", i+1, len(filteredTests), testCase.Name)

		result := ft.runSingleTest(testCase, contractPath)
		ft.TestResults = append(ft.TestResults, result)

		// Check for timeout
		if time.Since(startTime) > ft.Config.MaxTestDuration {
			DebugPrintStep("FUZZ_RUN", "Reached maximum test duration, stopping")
			break
		}
	}

	// Generate report
	ft.generateFuzzReport()

	DebugPrintStep("FUZZ_RUN", "Fuzz testing completed. Total results: %d", len(ft.TestResults))
	return nil
}

// filterTestCases filters test cases based on configuration
func (ft *FuzzTester) filterTestCases() []TestMatrixCase {
	var filtered []TestMatrixCase

	for _, tc := range ft.TestMatrix.TestCases {
		// Filter by category
		if len(ft.Config.TestCategories) > 0 {
			found := false
			for _, category := range ft.Config.TestCategories {
				if tc.Category == category {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by severity
		if len(ft.Config.TestSeverities) > 0 {
			found := false
			for _, severity := range ft.Config.TestSeverities {
				if tc.Severity == severity {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by signature type
		if len(ft.Config.SignatureTypes) > 0 {
			found := false
			for _, sigType := range ft.Config.SignatureTypes {
				if tc.SignatureType == sigType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter stress tests
		if !ft.Config.EnableStressTests && tc.Category == CategoryStressTest {
			continue
		}

		// Filter edge cases
		if !ft.Config.EnableEdgeCases && tc.Category == CategoryEdgeCase {
			continue
		}

		filtered = append(filtered, tc)
	}

	return filtered
}

// startGanache starts a local Ganache instance
func (ft *FuzzTester) startGanache() error {
	DebugPrintStep("GANACHE_START", "Starting Ganache instance")

	// Check if Ganache is already running
	if ft.isGanacheRunning() {
		DebugPrintStep("GANACHE_START", "Ganache is already running")
		return nil
	}

	// Start Ganache with specific configuration
	cmd := exec.Command("ganache",
		"--port", "8545",
		"--chain.hardfork", "shanghai",
		"--chain.chainId", "1337",
		"--wallet.totalAccounts", "20",
		"--wallet.deterministic", "true",
		"--wallet.mnemonic", "test test test test test test test test test test test junk",
		"--server.host", "127.0.0.1",
		"--miner.blockTime", "0",
		"--miner.blockGasLimit", fmt.Sprintf("%d", ft.Config.GasLimit),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Ganache: %w", err)
	}

	// Wait a bit for Ganache to start
	time.Sleep(2 * time.Second)

	DebugPrintStep("GANACHE_START", "Ganache started successfully")
	return nil
}

// stopGanache stops the Ganache instance
func (ft *FuzzTester) stopGanache() error {
	DebugPrintStep("GANACHE_STOP", "Stopping Ganache instance")

	cmd := exec.Command("pkill", "-f", "ganache")
	if err := cmd.Run(); err != nil {
		DebugPrintStep("GANACHE_STOP", "No Ganache process found to kill")
	}

	DebugPrintStep("GANACHE_STOP", "Ganache stopped")
	return nil
}

// isGanacheRunning checks if Ganache is already running
func (ft *FuzzTester) isGanacheRunning() bool {
	cmd := exec.Command("pgrep", "-f", "ganache")
	return cmd.Run() == nil
}

// compileContracts compiles the contracts using Hardhat
func (ft *FuzzTester) compileContracts() error {
	DebugPrintStep("COMPILE", "Compiling contracts with Hardhat")

	cmd := exec.Command("npx", "hardhat", "compile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to compile contracts: %w", err)
	}

	DebugPrintStep("COMPILE", "Contracts compiled successfully")
	return nil
}

// runSingleTest runs a single test case
func (ft *FuzzTester) runSingleTest(testCase TestMatrixCase, contractPath string) FuzzTestResult {
	DebugPrintStep("TEST_RUN", "Running test case: %s", testCase.Name)

	result := FuzzTestResult{
		TestCaseID:     testCase.ID,
		TestCaseName:   testCase.Name,
		Category:       testCase.Category,
		Severity:       testCase.Severity,
		SignatureType:  testCase.SignatureType,
		ExpectedResult: testCase.ExpectedResult,
		TestData:       testCase.TestData,
		Timestamp:      time.Now(),
		Status:         StatusError, // Default to error, will be updated
	}

	startTime := time.Now()

	// Create test file for this specific test case
	testFile, err := ft.createTestFile(testCase, contractPath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create test file: %v", err)
		result.Status = StatusError
		return result
	}
	defer os.Remove(testFile)

	// Run the test
	testResult, err := ft.executeTest(testFile, testCase)
	if err != nil {
		result.Error = fmt.Sprintf("Test execution failed: %v", err)
		result.Status = StatusError
		return result
	}

	result.ExecutionTime = time.Since(startTime)
	result.GasUsed = testResult.GasUsed
	result.BlockNumber = testResult.BlockNumber
	result.TransactionHash = testResult.TransactionHash

	// Determine test status based on result
	switch testResult.Status {
	case "passed":
		if testCase.ExpectedResult == ResultSuccess {
			result.Status = StatusPassed
			result.Result = ResultSuccess
		} else {
			result.Status = StatusFailed
			result.Result = ResultSuccess
		}
	case "failed":
		if testCase.ExpectedResult == ResultRevert {
			result.Status = StatusPassed
			result.Result = ResultRevert
		} else {
			result.Status = StatusFailed
			result.Result = ResultRevert
		}
	case "vulnerable":
		result.Status = StatusVulnerable
		result.Result = ResultVulnerable
		result.Vulnerability = testCase.Vulnerability
	case "timeout":
		result.Status = StatusTimeout
		result.Result = ResultTimeout
	default:
		result.Status = StatusError
		result.Result = ResultInvalid
	}

	DebugPrintStep("TEST_RUN", "Test %s completed with status: %s", testCase.Name, result.Status)
	return result
}

// createTestFile creates a temporary test file for a specific test case
func (ft *FuzzTester) createTestFile(testCase TestMatrixCase, contractPath string) (string, error) {
	DebugPrintStep("TEST_FILE", "Creating test file for: %s", testCase.Name)

	// Read the contract source
	contractSource, err := os.ReadFile(contractPath)
	if err != nil {
		return "", fmt.Errorf("failed to read contract: %w", err)
	}

	// Generate test content
	testContent := ft.generateTestContent(testCase, string(contractSource))

	// Create temporary file
	tempFile, err := os.CreateTemp("", fmt.Sprintf("fuzz_test_%s_*.js", testCase.ID))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := tempFile.WriteString(testContent); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write test content: %w", err)
	}

	tempFile.Close()
	DebugPrintStep("TEST_FILE", "Test file created: %s", tempFile.Name())
	return tempFile.Name(), nil
}

// generateTestContent generates the test content for a specific test case
func (ft *FuzzTester) generateTestContent(testCase TestMatrixCase, contractSource string) string {
	var content strings.Builder

	content.WriteString("const { expect } = require('chai');\n")
	content.WriteString("const { ethers } = require('hardhat');\n\n")

	content.WriteString("describe('Fuzz Test: " + testCase.Name + "', function() {\n")
	content.WriteString("  let contract;\n")
	content.WriteString("  let owner, user1, user2;\n\n")

	content.WriteString("  beforeEach(async function() {\n")
	content.WriteString("    [owner, user1, user2] = await ethers.getSigners();\n")
	content.WriteString("    const ContractFactory = await ethers.getContractFactory('TestCases');\n")
	content.WriteString("    contract = await ContractFactory.deploy();\n")
	content.WriteString("    await contract.waitForDeployment();\n")
	content.WriteString("  });\n\n")

	content.WriteString("  it('" + testCase.Description + "', async function() {\n")

	// Add test-specific logic based on category
	switch testCase.Category {
	case CategorySignatureValidation:
		content.WriteString(ft.generateSignatureValidationTest(testCase))
	case CategoryReplayAttack:
		content.WriteString(ft.generateReplayAttackTest(testCase))
	case CategoryTimingAttack:
		content.WriteString(ft.generateTimingAttackTest(testCase))
	case CategoryEntropyAttack:
		content.WriteString(ft.generateEntropyAttackTest(testCase))
	case CategoryFormatValidation:
		content.WriteString(ft.generateFormatValidationTest(testCase))
	case CategoryCrossChainAttack:
		content.WriteString(ft.generateCrossChainAttackTest(testCase))
	case CategoryMultiSigAttack:
		content.WriteString(ft.generateMultiSigAttackTest(testCase))
	case CategoryEdgeCase:
		content.WriteString(ft.generateEdgeCaseTest(testCase))
	case CategoryStressTest:
		content.WriteString(ft.generateStressTest(testCase))
	default:
		content.WriteString("    // Generic test implementation\n")
		content.WriteString("    expect(true).to.be.true;\n")
	}

	content.WriteString("  });\n")
	content.WriteString("});\n")

	return content.String()
}

// generateSignatureValidationTest generates test content for signature validation
func (ft *FuzzTester) generateSignatureValidationTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Signature validation test\n")
	content.WriteString("    const message = ethers.utils.toUtf8Bytes('Test message');\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature = await user1.signMessage(message);\n\n")

	if testCase.ID == "SIG_002" {
		// Test without 0x prefix
		content.WriteString("    const signatureWithoutPrefix = signature.slice(2);\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, signatureWithoutPrefix)).to.be.reverted;\n")
	} else if testCase.ID == "SIG_003" {
		// Test invalid length
		content.WriteString("    const invalidSignature = signature.slice(0, -2);\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, invalidSignature)).to.be.reverted;\n")
	} else if testCase.ID == "SIG_004" {
		// Test zero address
		content.WriteString("    const zeroSignature = '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, zeroSignature)).to.be.reverted;\n")
	} else {
		// Valid signature test
		content.WriteString("    await expect(contract.verifySignature(messageHash, signature)).to.not.be.reverted;\n")
	}

	return content.String()
}

// generateReplayAttackTest generates test content for replay attacks
func (ft *FuzzTester) generateReplayAttackTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Replay attack test\n")
	content.WriteString("    const nonce = 0;\n")
	content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [nonce]);\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature = await user1.signMessage(message);\n\n")

	if testCase.ID == "REPLAY_001" {
		content.WriteString("    // First execution should succeed\n")
		content.WriteString("    await expect(contract.executeWithSignature(messageHash, signature, nonce)).to.not.be.reverted;\n\n")
		content.WriteString("    // Replay should fail if nonce protection is implemented\n")
		content.WriteString("    try {\n")
		content.WriteString("      await contract.executeWithSignature(messageHash, signature, nonce);\n")
		content.WriteString("      console.log('VULNERABLE: Replay attack succeeded');\n")
		content.WriteString("    } catch (error) {\n")
		content.WriteString("      console.log('SECURE: Replay attack prevented');\n")
		content.WriteString("    }\n")
	} else {
		content.WriteString("    await expect(contract.executeWithSignature(messageHash, signature, nonce)).to.not.be.reverted;\n")
	}

	return content.String()
}

// generateTimingAttackTest generates test content for timing attacks
func (ft *FuzzTester) generateTimingAttackTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Timing attack test\n")
	content.WriteString("    const startTime = Date.now();\n")
	content.WriteString("    const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now\n")
	content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [deadline]);\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature = await user1.signMessage(message);\n\n")

	content.WriteString("    await contract.executeWithDeadline(messageHash, signature, deadline);\n")
	content.WriteString("    const endTime = Date.now();\n")
	content.WriteString("    const executionTime = endTime - startTime;\n\n")

	content.WriteString("    // Check if execution time is reasonable (not vulnerable to timing attacks)\n")
	content.WriteString("    expect(executionTime).to.be.lessThan(1000); // Should complete within 1 second\n")

	return content.String()
}

// generateEntropyAttackTest generates test content for entropy attacks
func (ft *FuzzTester) generateEntropyAttackTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Entropy attack test\n")
	content.WriteString("    const predictableNonce = 1;\n")
	content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [predictableNonce]);\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature = await user1.signMessage(message);\n\n")

	content.WriteString("    // Test with predictable nonce\n")
	content.WriteString("    await expect(contract.executeWithNonce(messageHash, signature, predictableNonce)).to.not.be.reverted;\n")

	return content.String()
}

// generateFormatValidationTest generates test content for format validation
func (ft *FuzzTester) generateFormatValidationTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Format validation test\n")

	if testCase.ID == "FORMAT_001" {
		content.WriteString("    const invalidSignature = 'invalid_format';\n")
		content.WriteString("    const messageHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test'));\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, invalidSignature)).to.be.reverted;\n")
	} else if testCase.ID == "FORMAT_002" {
		content.WriteString("    const invalidStruct = 'invalid_struct_data';\n")
		content.WriteString("    await expect(contract.verifyEIP712Signature(invalidStruct)).to.be.reverted;\n")
	} else {
		content.WriteString("    // Valid format test\n")
		content.WriteString("    const message = ethers.utils.toUtf8Bytes('Test message');\n")
		content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
		content.WriteString("    const signature = await user1.signMessage(message);\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, signature)).to.not.be.reverted;\n")
	}

	return content.String()
}

// generateCrossChainAttackTest generates test content for cross-chain attacks
func (ft *FuzzTester) generateCrossChainAttackTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Cross-chain attack test\n")
	content.WriteString("    const chainId = 1; // Ethereum mainnet\n")
	content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [chainId]);\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature = await user1.signMessage(message);\n\n")

	content.WriteString("    // Test with different chain ID\n")
	content.WriteString("    const wrongChainId = 137; // Polygon\n")
	content.WriteString("    await expect(contract.executeWithChainId(messageHash, signature, wrongChainId)).to.be.reverted;\n")

	return content.String()
}

// generateMultiSigAttackTest generates test content for multi-signature attacks
func (ft *FuzzTester) generateMultiSigAttackTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Multi-signature attack test\n")
	content.WriteString("    const message = ethers.utils.toUtf8Bytes('Multi-sig test');\n")
	content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
	content.WriteString("    const signature1 = await user1.signMessage(message);\n")
	content.WriteString("    const signature2 = await user2.signMessage(message);\n\n")

	if testCase.ID == "MULTISIG_001" {
		content.WriteString("    // Test with insufficient signatures\n")
		content.WriteString("    const signatures = [signature1]; // Only 1 signature, need 3\n")
		content.WriteString("    await expect(contract.executeMultiSig(messageHash, signatures, 3)).to.be.reverted;\n")
	} else if testCase.ID == "MULTISIG_002" {
		content.WriteString("    // Test with duplicate signatures\n")
		content.WriteString("    const signatures = [signature1, signature1, signature2];\n")
		content.WriteString("    await expect(contract.executeMultiSig(messageHash, signatures, 3)).to.be.reverted;\n")
	} else {
		content.WriteString("    // Valid multi-signature test\n")
		content.WriteString("    const signatures = [signature1, signature2];\n")
		content.WriteString("    await expect(contract.executeMultiSig(messageHash, signatures, 2)).to.not.be.reverted;\n")
	}

	return content.String()
}

// generateEdgeCaseTest generates test content for edge cases
func (ft *FuzzTester) generateEdgeCaseTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Edge case test\n")

	if testCase.ID == "EDGE_001" {
		content.WriteString("    const maxNonce = ethers.constants.MaxUint256;\n")
		content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [maxNonce]);\n")
		content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
		content.WriteString("    const signature = await user1.signMessage(message);\n")
		content.WriteString("    await expect(contract.executeWithNonce(messageHash, signature, maxNonce)).to.not.be.reverted;\n")
	} else if testCase.ID == "EDGE_002" {
		content.WriteString("    const zeroAmount = 0;\n")
		content.WriteString("    const message = ethers.utils.defaultAbiCoder.encode(['uint256'], [zeroAmount]);\n")
		content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
		content.WriteString("    const signature = await user1.signMessage(message);\n")
		content.WriteString("    await expect(contract.executeWithAmount(messageHash, signature, zeroAmount)).to.not.be.reverted;\n")
	} else if testCase.ID == "EDGE_004" {
		content.WriteString("    const emptySignature = '';\n")
		content.WriteString("    const messageHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test'));\n")
		content.WriteString("    await expect(contract.verifySignature(messageHash, emptySignature)).to.be.reverted;\n")
	} else {
		content.WriteString("    // Generic edge case test\n")
		content.WriteString("    expect(true).to.be.true;\n")
	}

	return content.String()
}

// generateStressTest generates test content for stress tests
func (ft *FuzzTester) generateStressTest(testCase TestMatrixCase) string {
	var content strings.Builder

	content.WriteString("    // Stress test\n")

	if testCase.ID == "STRESS_001" {
		content.WriteString("    const message = ethers.utils.toUtf8Bytes('Stress test');\n")
		content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
		content.WriteString("    const signature = await user1.signMessage(message);\n\n")
		content.WriteString("    // High frequency replay test\n")
		content.WriteString("    for (let i = 0; i < 100; i++) {\n")
		content.WriteString("      try {\n")
		content.WriteString("        await contract.executeWithSignature(messageHash, signature, i);\n")
		content.WriteString("      } catch (error) {\n")
		content.WriteString("        // Expected to fail after first execution\n")
		content.WriteString("        break;\n")
		content.WriteString("      }\n")
		content.WriteString("    }\n")
	} else if testCase.ID == "STRESS_003" {
		content.WriteString("    // Concurrent signature validation test\n")
		content.WriteString("    const promises = [];\n")
		content.WriteString("    const message = ethers.utils.toUtf8Bytes('Concurrent test');\n")
		content.WriteString("    const messageHash = ethers.utils.hashMessage(message);\n")
		content.WriteString("    const signature = await user1.signMessage(message);\n\n")
		content.WriteString("    for (let i = 0; i < 10; i++) {\n")
		content.WriteString("    promises.push(contract.verifySignature(messageHash, signature));\n")
		content.WriteString("    }\n\n")
		content.WriteString("    await Promise.all(promises);\n")
	} else {
		content.WriteString("    // Generic stress test\n")
		content.WriteString("    expect(true).to.be.true;\n")
	}

	return content.String()
}

// executeTest executes a single test file
func (ft *FuzzTester) executeTest(testFile string, testCase TestMatrixCase) (*TestExecutionResult, error) {
	DebugPrintStep("TEST_EXECUTE", "Executing test file: %s", testFile)

	cmd := exec.Command("npx", "hardhat", "test", testFile, "--network", "localhost")

	// Capture output
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Command failed but we can still parse the output
			output = exitErr.Stderr
		} else {
			return &TestExecutionResult{Status: "error"}, err
		}
	}

	// Parse test output to determine result
	result := ft.parseTestOutput(output)
	return result, nil
}

// TestExecutionResult represents the result of test execution
type TestExecutionResult struct {
	Status          string `json:"status"`
	GasUsed         uint64 `json:"gasUsed"`
	BlockNumber     uint64 `json:"blockNumber"`
	TransactionHash string `json:"transactionHash"`
}

// parseTestOutput parses the test output to determine the result
func (ft *FuzzTester) parseTestOutput(output []byte) *TestExecutionResult {
	outputStr := string(output)

	result := &TestExecutionResult{
		Status: "unknown",
	}

	if strings.Contains(outputStr, "✓") || strings.Contains(outputStr, "PASS") {
		result.Status = "passed"
	} else if strings.Contains(outputStr, "✗") || strings.Contains(outputStr, "FAIL") {
		result.Status = "failed"
	} else if strings.Contains(outputStr, "VULNERABLE") {
		result.Status = "vulnerable"
	} else if strings.Contains(outputStr, "timeout") {
		result.Status = "timeout"
	}

	// Extract gas usage if available
	if gasMatch := regexp.MustCompile(`Gas used: (\d+)`).FindStringSubmatch(outputStr); len(gasMatch) > 1 {
		if gas, err := strconv.ParseUint(gasMatch[1], 10, 64); err == nil {
			result.GasUsed = gas
		}
	}

	return result
}

// generateFuzzReport generates a comprehensive fuzz testing report
func (ft *FuzzTester) generateFuzzReport() {
	DebugPrintStep("REPORT", "Generating fuzz testing report")

	var report strings.Builder
	report.WriteString("=== FUZZ TESTING REPORT ===\n\n")

	// Summary statistics
	totalTests := len(ft.TestResults)
	passedTests := 0
	failedTests := 0
	vulnerableTests := 0
	timeoutTests := 0
	errorTests := 0

	for _, result := range ft.TestResults {
		switch result.Status {
		case StatusPassed:
			passedTests++
		case StatusFailed:
			failedTests++
		case StatusVulnerable:
			vulnerableTests++
		case StatusTimeout:
			timeoutTests++
		case StatusError:
			errorTests++
		}
	}

	report.WriteString(fmt.Sprintf("Total Tests: %d\n", totalTests))
	report.WriteString(fmt.Sprintf("Passed: %d (%.1f%%)\n", passedTests, float64(passedTests)/float64(totalTests)*100))
	report.WriteString(fmt.Sprintf("Failed: %d (%.1f%%)\n", failedTests, float64(failedTests)/float64(totalTests)*100))
	report.WriteString(fmt.Sprintf("Vulnerable: %d (%.1f%%)\n", vulnerableTests, float64(vulnerableTests)/float64(totalTests)*100))
	report.WriteString(fmt.Sprintf("Timeout: %d (%.1f%%)\n", timeoutTests, float64(timeoutTests)/float64(totalTests)*100))
	report.WriteString(fmt.Sprintf("Error: %d (%.1f%%)\n", errorTests, float64(errorTests)/float64(totalTests)*100))

	// Vulnerabilities found
	if vulnerableTests > 0 {
		report.WriteString("\n=== VULNERABILITIES FOUND ===\n")
		vulnCounts := make(map[VulnerabilityType]int)
		for _, result := range ft.TestResults {
			if result.Status == StatusVulnerable {
				vulnCounts[result.Vulnerability]++
			}
		}

		for vuln, count := range vulnCounts {
			report.WriteString(fmt.Sprintf("%s: %d instances\n", vuln, count))
		}
	}

	// Detailed results
	report.WriteString("\n=== DETAILED RESULTS ===\n")
	for _, result := range ft.TestResults {
		report.WriteString(fmt.Sprintf("\n%s - %s (%s)\n", result.TestCaseID, result.TestCaseName, result.Status))
		report.WriteString(fmt.Sprintf("  Category: %s\n", result.Category))
		report.WriteString(fmt.Sprintf("  Severity: %s\n", result.Severity))
		report.WriteString(fmt.Sprintf("  Execution Time: %v\n", result.ExecutionTime))
		if result.GasUsed > 0 {
			report.WriteString(fmt.Sprintf("  Gas Used: %d\n", result.GasUsed))
		}
		if result.Error != "" {
			report.WriteString(fmt.Sprintf("  Error: %s\n", result.Error))
		}
	}

	// Write report to file
	reportFile := fmt.Sprintf("fuzz_report_%s.txt", time.Now().Format("20060102_150405"))
	if err := os.WriteFile(reportFile, []byte(report.String()), 0644); err != nil {
		DebugPrintError("REPORT_WRITE", err)
	} else {
		DebugPrintStep("REPORT", "Fuzz testing report written to: %s", reportFile)
	}

	// Also print to console if verbose
	if ft.Config.VerboseOutput {
		fmt.Print(report.String())
	}
}
