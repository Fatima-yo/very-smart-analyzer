package analyzer

import (
	"fmt"
	"strings"
)

// TestCase represents a generated test case
type TestCase struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Vulnerability  VulnerabilityType      `json:"vulnerability"`
	FunctionName   string                 `json:"functionName"`
	TestType       string                 `json:"testType"`
	TestData       map[string]interface{} `json:"testData"`
	ExpectedResult string                 `json:"expectedResult"`
	Severity       string                 `json:"severity"`
}

// TestSuite represents a collection of test cases for a function
type TestSuite struct {
	FunctionName    string     `json:"functionName"`
	SignatureType   string     `json:"signatureType"`
	TestCases       []TestCase `json:"testCases"`
	TotalTests      int        `json:"totalTests"`
	VulnerableTests int        `json:"vulnerableTests"`
}

// TestGenerator handles test case generation
type TestGenerator struct {
	// In-memory storage for generated tests
	GeneratedTests map[string]*TestSuite
}

// NewTestGenerator creates a new test generator
func NewTestGenerator() *TestGenerator {
	return &TestGenerator{
		GeneratedTests: make(map[string]*TestSuite),
	}
}

// GenerateTestCases generates comprehensive test cases for a function
func (tg *TestGenerator) GenerateTestCases(fn *SignatureFunction) *TestSuite {
	DebugPrintStep("TEST_GENERATION", "Generating test cases for function: %s", fn.FunctionName)

	testSuite := &TestSuite{
		FunctionName:  fn.FunctionName,
		SignatureType: string(fn.SignatureType.Kind),
		TestCases:     []TestCase{},
	}

	// Generate tests based on signature type
	tg.generateSignatureTypeTests(fn, testSuite)

	// Generate tests based on detected vulnerabilities
	tg.generateVulnerabilityTests(fn, testSuite)

	// Generate tests based on security checks
	tg.generateSecurityCheckTests(fn, testSuite)

	// Generate tests based on signature complexity
	tg.generateComplexityTests(fn, testSuite)

	// Calculate statistics
	testSuite.TotalTests = len(testSuite.TestCases)
	testSuite.VulnerableTests = tg.countVulnerableTests(testSuite.TestCases)

	// Store in memory
	tg.GeneratedTests[fn.FunctionName] = testSuite

	DebugPrintStep("TEST_GENERATION", "Generated %d test cases for function %s (%d vulnerable)",
		testSuite.TotalTests, fn.FunctionName, testSuite.VulnerableTests)

	return testSuite
}

// generateSignatureTypeTests generates tests specific to signature types
func (tg *TestGenerator) generateSignatureTypeTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating signature type tests for: %s", fn.FunctionName)

	switch fn.SignatureType.Kind {
	case EIP712:
		tg.generateEIP712Tests(fn, suite)
	case ETHSign:
		tg.generateETHSignTests(fn, suite)
	case EIP191Personal:
		tg.generateEIP191Tests(fn, suite)
	case EIP2612:
		tg.generateEIP2612Tests(fn, suite)
	case EIP1271:
		tg.generateEIP1271Tests(fn, suite)
	case CustomSig:
		tg.generateCustomTests(fn, suite)
	}
}

// generateEIP712Tests generates EIP712 specific tests
func (tg *TestGenerator) generateEIP712Tests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating EIP712 tests for function: %s", fn.FunctionName)

	// Test 1: Valid EIP712 signature
	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_EIP712_Signature",
		Description: "Test with valid EIP712 signature and all required fields",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature": "valid_signature_bytes",
			"structData": map[string]interface{}{
				"owner":    "0x1234567890123456789012345678901234567890",
				"spender":  "0x0987654321098765432109876543210987654321",
				"value":    "1000000000000000000",
				"nonce":    "0",
				"deadline": "9999999999",
			},
		},
		ExpectedResult: "success",
		Severity:       "low",
	})

	// Test 2: Invalid domain separator
	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Invalid_Domain_Separator",
		Description: "Test with invalid domain separator",
		TestType:    "negative",
		TestData: map[string]interface{}{
			"signature":       "valid_signature_bytes",
			"domainSeparator": "invalid_domain",
		},
		ExpectedResult: "revert",
		Severity:       "high",
	})

	// Test 3: Expired deadline
	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Expired_Deadline",
		Description: "Test with expired deadline",
		TestType:    "negative",
		TestData: map[string]interface{}{
			"signature": "valid_signature_bytes",
			"deadline":  "1", // Expired
		},
		ExpectedResult: "revert",
		Severity:       "medium",
	})
}

// generateETHSignTests generates ETH_SIGN specific tests
func (tg *TestGenerator) generateETHSignTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating ETH_SIGN tests for function: %s", fn.FunctionName)

	// Test 1: Valid ETH_SIGN signature
	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_ETH_SIGN_Signature",
		Description: "Test with valid ETH_SIGN signature",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature": "valid_signature_bytes",
			"message":   "test_message",
		},
		ExpectedResult: "success",
		Severity:       "low",
	})

	// Test 2: Replay attack (if no nonce)
	if fn.Nonce == nil {
		suite.TestCases = append(suite.TestCases, TestCase{
			Name:          "Replay_Attack_No_Nonce",
			Description:   "Test replay attack vulnerability due to missing nonce",
			TestType:      "negative",
			Vulnerability: VulnMissingNonce,
			TestData: map[string]interface{}{
				"signature":   "valid_signature_bytes",
				"replayCount": 5,
			},
			ExpectedResult: "vulnerable",
			Severity:       "critical",
		})
	}

	// Test 3: Invalid signature format
	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Invalid_Signature_Format",
		Description: "Test with malformed signature",
		TestType:    "negative",
		TestData: map[string]interface{}{
			"signature": "invalid_signature_format",
		},
		ExpectedResult: "revert",
		Severity:       "medium",
	})
}

// generateVulnerabilityTests generates tests based on detected vulnerabilities
func (tg *TestGenerator) generateVulnerabilityTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating vulnerability tests for function: %s", fn.FunctionName)

	for _, vuln := range fn.Vulnerabilities {
		switch vuln {
		case VulnMissingNonce:
			tg.generateMissingNonceTests(fn, suite)
		case VulnMissingDeadline:
			tg.generateMissingDeadlineTests(fn, suite)
		case VulnMissingTimestamp:
			tg.generateMissingTimestampTests(fn, suite)
		case VulnMissingChainID:
			tg.generateMissingChainIDTests(fn, suite)
		case VulnMissingDomainSeparator:
			tg.generateMissingDomainSeparatorTests(fn, suite)
		case VulnWeakSignerValidation:
			tg.generateWeakSignerValidationTests(fn, suite)
		case VulnUnsafeSignatureRecovery:
			tg.generateUnsafeRecoveryTests(fn, suite)
		case VulnInsufficientEntropy:
			tg.generateInsufficientEntropyTests(fn, suite)
		}
	}
}

// generateMissingNonceTests generates tests for missing nonce vulnerability
func (tg *TestGenerator) generateMissingNonceTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating missing nonce tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Replay_Attack_Missing_Nonce",
		Description:   "Test replay attack due to missing nonce validation",
		TestType:      "negative",
		Vulnerability: VulnMissingNonce,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"replayAttempts":   []int{1, 2, 3, 4, 5},
			"expectedBehavior": "all_should_succeed",
		},
		ExpectedResult: "vulnerable",
		Severity:       "critical",
	})

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Cross_Chain_Replay_Missing_Nonce",
		Description:   "Test cross-chain replay attack due to missing nonce",
		TestType:      "negative",
		Vulnerability: VulnMissingNonce,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"sourceChain":      "ethereum_mainnet",
			"targetChain":      "polygon",
			"expectedBehavior": "replay_successful",
		},
		ExpectedResult: "vulnerable",
		Severity:       "critical",
	})
}

// generateMissingDeadlineTests generates tests for missing deadline vulnerability
func (tg *TestGenerator) generateMissingDeadlineTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating missing deadline tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Expired_Signature_No_Deadline_Check",
		Description:   "Test that expired signatures are accepted due to missing deadline check",
		TestType:      "negative",
		Vulnerability: VulnMissingDeadline,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"signatureAge":     "1_year_old",
			"expectedBehavior": "should_accept_expired",
		},
		ExpectedResult: "vulnerable",
		Severity:       "high",
	})
}

// generateSecurityCheckTests generates tests based on security checks
func (tg *TestGenerator) generateSecurityCheckTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating security check tests for function: %s", fn.FunctionName)

	// Test signer validation
	if !fn.SecurityChecks.SignerValidation {
		suite.TestCases = append(suite.TestCases, TestCase{
			Name:        "Zero_Address_Signer",
			Description: "Test with zero address as signer",
			TestType:    "negative",
			TestData: map[string]interface{}{
				"signer":           "0x0000000000000000000000000000000000000000",
				"expectedBehavior": "should_accept_zero_address",
			},
			ExpectedResult: "vulnerable",
			Severity:       "high",
		})
	}

	// Test replay protection
	if !fn.SecurityChecks.ReplayProtection {
		suite.TestCases = append(suite.TestCases, TestCase{
			Name:        "Replay_Protection_Missing",
			Description: "Test that replay protection is missing",
			TestType:    "negative",
			TestData: map[string]interface{}{
				"signature":        "valid_signature_bytes",
				"replayCount":      10,
				"expectedBehavior": "all_replays_successful",
			},
			ExpectedResult: "vulnerable",
			Severity:       "critical",
		})
	}
}

// generateComplexityTests generates tests based on signature complexity
func (tg *TestGenerator) generateComplexityTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating complexity tests for function: %s", fn.FunctionName)

	complexity := fn.SignatureComplexity

	// Test nested structs
	if complexity.HasNestedStructs {
		suite.TestCases = append(suite.TestCases, TestCase{
			Name:        "Nested_Struct_Validation",
			Description: "Test validation of nested struct fields",
			TestType:    "positive",
			TestData: map[string]interface{}{
				"structDepth":  complexity.StructDepth,
				"nestedFields": "validate_all_levels",
			},
			ExpectedResult: "success",
			Severity:       "medium",
		})
	}

	// Test arrays
	if complexity.HasArrays {
		suite.TestCases = append(suite.TestCases, TestCase{
			Name:        "Array_Length_Validation",
			Description: "Test array length validation",
			TestType:    "negative",
			TestData: map[string]interface{}{
				"arrayLength":   complexity.ArrayLength,
				"invalidLength": complexity.ArrayLength + 1,
			},
			ExpectedResult: "revert",
			Severity:       "medium",
		})
	}
}

// countVulnerableTests counts the number of vulnerable test cases
func (tg *TestGenerator) countVulnerableTests(testCases []TestCase) int {
	count := 0
	for _, tc := range testCases {
		if tc.ExpectedResult == "vulnerable" {
			count++
		}
	}
	return count
}

// GetTestSuite retrieves a test suite for a function
func (tg *TestGenerator) GetTestSuite(functionName string) (*TestSuite, bool) {
	suite, exists := tg.GeneratedTests[functionName]
	return suite, exists
}

// GetAllTestSuites retrieves all generated test suites
func (tg *TestGenerator) GetAllTestSuites() map[string]*TestSuite {
	return tg.GeneratedTests
}

// GenerateTestReport generates a comprehensive test report
func (tg *TestGenerator) GenerateTestReport() string {
	DebugPrintStep("TEST_REPORT", "Generating comprehensive test report")

	var report strings.Builder
	report.WriteString("=== SIGNATURE TEST GENERATION REPORT ===\n\n")

	totalFunctions := len(tg.GeneratedTests)
	totalTests := 0
	totalVulnerableTests := 0

	for functionName, suite := range tg.GeneratedTests {
		report.WriteString(fmt.Sprintf("Function: %s\n", functionName))
		report.WriteString(fmt.Sprintf("  Signature Type: %s\n", suite.SignatureType))
		report.WriteString(fmt.Sprintf("  Total Tests: %d\n", suite.TotalTests))
		report.WriteString(fmt.Sprintf("  Vulnerable Tests: %d\n", suite.VulnerableTests))
		report.WriteString(fmt.Sprintf("  Test Coverage: %.1f%%\n", float64(suite.TotalTests)/10*100))
		report.WriteString("\n")

		totalTests += suite.TotalTests
		totalVulnerableTests += suite.VulnerableTests
	}

	report.WriteString(fmt.Sprintf("SUMMARY:\n"))
	report.WriteString(fmt.Sprintf("  Total Functions Tested: %d\n", totalFunctions))
	report.WriteString(fmt.Sprintf("  Total Test Cases Generated: %d\n", totalTests))
	report.WriteString(fmt.Sprintf("  Total Vulnerable Test Cases: %d\n", totalVulnerableTests))
	report.WriteString(fmt.Sprintf("  Average Tests per Function: %.1f\n", float64(totalTests)/float64(totalFunctions)))

	DebugPrintStep("TEST_REPORT", "Test report generated with %d functions, %d total tests", totalFunctions, totalTests)

	return report.String()
}

// generateEIP191Tests generates EIP191 personal sign tests
func (tg *TestGenerator) generateEIP191Tests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating EIP191 tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_EIP191_Signature",
		Description: "Test with valid EIP191 personal sign signature",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature": "valid_signature_bytes",
			"message":   "test_message",
		},
		ExpectedResult: "success",
		Severity:       "low",
	})
}

// generateEIP2612Tests generates EIP2612 permit tests
func (tg *TestGenerator) generateEIP2612Tests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating EIP2612 tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_EIP2612_Permit",
		Description: "Test with valid EIP2612 permit signature",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature": "valid_signature_bytes",
			"permit": map[string]interface{}{
				"owner":    "0x1234567890123456789012345678901234567890",
				"spender":  "0x0987654321098765432109876543210987654321",
				"value":    "1000000000000000000",
				"nonce":    "0",
				"deadline": "9999999999",
			},
		},
		ExpectedResult: "success",
		Severity:       "low",
	})
}

// generateEIP1271Tests generates EIP1271 contract signature tests
func (tg *TestGenerator) generateEIP1271Tests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating EIP1271 tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_EIP1271_Contract_Signature",
		Description: "Test with valid EIP1271 contract signature",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature":      "valid_signature_bytes",
			"contractSigner": "0x1234567890123456789012345678901234567890",
		},
		ExpectedResult: "success",
		Severity:       "low",
	})
}

// generateCustomTests generates custom signature tests
func (tg *TestGenerator) generateCustomTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating custom signature tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:        "Valid_Custom_Signature",
		Description: "Test with valid custom signature format",
		TestType:    "positive",
		TestData: map[string]interface{}{
			"signature":    "valid_signature_bytes",
			"customFormat": "custom_format_data",
		},
		ExpectedResult: "success",
		Severity:       "low",
	})
}

// generateMissingTimestampTests generates tests for missing timestamp vulnerability
func (tg *TestGenerator) generateMissingTimestampTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating missing timestamp tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Missing_Timestamp_Validation",
		Description:   "Test that timestamp validation is missing",
		TestType:      "negative",
		Vulnerability: VulnMissingTimestamp,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"expectedBehavior": "no_timestamp_check",
		},
		ExpectedResult: "vulnerable",
		Severity:       "medium",
	})
}

// generateMissingChainIDTests generates tests for missing chain ID vulnerability
func (tg *TestGenerator) generateMissingChainIDTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating missing chain ID tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Cross_Chain_Replay_No_ChainID",
		Description:   "Test cross-chain replay attack due to missing chain ID",
		TestType:      "negative",
		Vulnerability: VulnMissingChainID,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"sourceChain":      "ethereum_mainnet",
			"targetChain":      "bsc",
			"expectedBehavior": "replay_successful",
		},
		ExpectedResult: "vulnerable",
		Severity:       "high",
	})
}

// generateMissingDomainSeparatorTests generates tests for missing domain separator vulnerability
func (tg *TestGenerator) generateMissingDomainSeparatorTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating missing domain separator tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Missing_Domain_Separator",
		Description:   "Test that domain separator validation is missing",
		TestType:      "negative",
		Vulnerability: VulnMissingDomainSeparator,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"expectedBehavior": "no_domain_validation",
		},
		ExpectedResult: "vulnerable",
		Severity:       "high",
	})
}

// generateWeakSignerValidationTests generates tests for weak signer validation vulnerability
func (tg *TestGenerator) generateWeakSignerValidationTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating weak signer validation tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Weak_Signer_Validation",
		Description:   "Test that signer validation is weak or missing",
		TestType:      "negative",
		Vulnerability: VulnWeakSignerValidation,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"expectedBehavior": "weak_validation",
		},
		ExpectedResult: "vulnerable",
		Severity:       "high",
	})
}

// generateUnsafeRecoveryTests generates tests for unsafe signature recovery vulnerability
func (tg *TestGenerator) generateUnsafeRecoveryTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating unsafe recovery tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Unsafe_Signature_Recovery",
		Description:   "Test unsafe signature recovery without proper validation",
		TestType:      "negative",
		Vulnerability: VulnUnsafeSignatureRecovery,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"expectedBehavior": "unsafe_recovery",
		},
		ExpectedResult: "vulnerable",
		Severity:       "high",
	})
}

// generateInsufficientEntropyTests generates tests for insufficient entropy vulnerability
func (tg *TestGenerator) generateInsufficientEntropyTests(fn *SignatureFunction, suite *TestSuite) {
	DebugPrintAnalysis("Generating insufficient entropy tests for function: %s", fn.FunctionName)

	suite.TestCases = append(suite.TestCases, TestCase{
		Name:          "Insufficient_Entropy",
		Description:   "Test that signature scheme has insufficient entropy",
		TestType:      "negative",
		Vulnerability: VulnInsufficientEntropy,
		TestData: map[string]interface{}{
			"signature":        "valid_signature_bytes",
			"expectedBehavior": "low_entropy",
		},
		ExpectedResult: "vulnerable",
		Severity:       "medium",
	})
}
