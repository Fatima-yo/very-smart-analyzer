package analyzer

import (
	"fmt"
	"strings"
)

// TestMatrix defines all the test cases we want to run
type TestMatrix struct {
	TestCases []TestMatrixCase
}

// TestMatrixCase represents a single test case in the matrix
type TestMatrixCase struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Category       TestCategory           `json:"category"`
	Severity       TestSeverity           `json:"severity"`
	Description    string                 `json:"description"`
	Vulnerability  VulnerabilityType      `json:"vulnerability"`
	TestData       map[string]interface{} `json:"testData"`
	ExpectedResult TestResult             `json:"expectedResult"`
	SignatureType  SignatureKind          `json:"signatureType"`
	Complexity     TestComplexity         `json:"complexity"`
}

// TestCategory represents the category of a test
type TestCategory string

const (
	CategorySignatureValidation TestCategory = "signature_validation"
	CategoryReplayAttack        TestCategory = "replay_attack"
	CategoryTimingAttack        TestCategory = "timing_attack"
	CategoryEntropyAttack       TestCategory = "entropy_attack"
	CategoryFormatValidation    TestCategory = "format_validation"
	CategoryCrossChainAttack    TestCategory = "cross_chain_attack"
	CategoryMultiSigAttack      TestCategory = "multisig_attack"
	CategoryEdgeCase            TestCategory = "edge_case"
	CategoryStressTest          TestCategory = "stress_test"
)

// TestSeverity represents the severity of a test
type TestSeverity string

const (
	SeverityLow      TestSeverity = "low"
	SeverityMedium   TestSeverity = "medium"
	SeverityHigh     TestSeverity = "high"
	SeverityCritical TestSeverity = "critical"
)

// TestResult represents the expected result of a test
type TestResult string

const (
	ResultSuccess    TestResult = "success"
	ResultRevert     TestResult = "revert"
	ResultVulnerable TestResult = "vulnerable"
	ResultTimeout    TestResult = "timeout"
	ResultInvalid    TestResult = "invalid"
)

// TestComplexity represents the complexity of a test
type TestComplexity string

const (
	ComplexityBasic    TestComplexity = "basic"
	ComplexityMedium   TestComplexity = "medium"
	ComplexityAdvanced TestComplexity = "advanced"
	ComplexityExpert   TestComplexity = "expert"
)

// NewTestMatrix creates a comprehensive test matrix
func NewTestMatrix() *TestMatrix {
	matrix := &TestMatrix{
		TestCases: []TestMatrixCase{},
	}

	// Add all test cases
	matrix.addSignatureValidationTests()
	matrix.addReplayAttackTests()
	matrix.addTimingAttackTests()
	matrix.addEntropyAttackTests()
	matrix.addFormatValidationTests()
	matrix.addCrossChainAttackTests()
	matrix.addMultiSigAttackTests()
	matrix.addEdgeCaseTests()
	matrix.addStressTests()

	return matrix
}

// addSignatureValidationTests adds basic signature validation tests
func (tm *TestMatrix) addSignatureValidationTests() {
	tests := []TestMatrixCase{
		{
			ID:          "SIG_001",
			Name:        "Valid_Signature_0x_Prefix",
			Category:    CategorySignatureValidation,
			Severity:    SeverityLow,
			Description: "Test signature with valid 0x prefix",
			TestData: map[string]interface{}{
				"signature":        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b",
				"expectedBehavior": "should_accept",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "SIG_002",
			Name:        "Invalid_Signature_No_0x_Prefix",
			Category:    CategorySignatureValidation,
			Severity:    SeverityMedium,
			Description: "Test signature without 0x prefix",
			TestData: map[string]interface{}{
				"signature":        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b",
				"expectedBehavior": "should_reject",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "SIG_003",
			Name:        "Invalid_Signature_Length",
			Category:    CategorySignatureValidation,
			Severity:    SeverityMedium,
			Description: "Test signature with invalid length",
			TestData: map[string]interface{}{
				"signature":        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"expectedBehavior": "should_reject",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "SIG_004",
			Name:        "Zero_Address_Signer",
			Category:    CategorySignatureValidation,
			Severity:    SeverityHigh,
			Description: "Test signature that recovers to zero address",
			TestData: map[string]interface{}{
				"signature":        "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"expectedBehavior": "should_reject_zero_address",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "SIG_005",
			Name:        "Invalid_V_Value",
			Category:    CategorySignatureValidation,
			Severity:    SeverityMedium,
			Description: "Test signature with invalid v value",
			TestData: map[string]interface{}{
				"v":                30, // Invalid v value
				"r":                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"s":                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"expectedBehavior": "should_reject_invalid_v",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addReplayAttackTests adds replay attack tests
func (tm *TestMatrix) addReplayAttackTests() {
	tests := []TestMatrixCase{
		{
			ID:            "REPLAY_001",
			Name:          "Replay_Attack_Same_Nonce",
			Category:      CategoryReplayAttack,
			Severity:      SeverityCritical,
			Description:   "Test replay attack with same nonce",
			Vulnerability: VulnMissingNonce,
			TestData: map[string]interface{}{
				"signature":        "valid_signature_bytes",
				"nonce":            "0",
				"replayCount":      5,
				"expectedBehavior": "all_should_succeed_if_vulnerable",
			},
			ExpectedResult: ResultVulnerable,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
		{
			ID:            "REPLAY_002",
			Name:          "Replay_Attack_Different_Nonce",
			Category:      CategoryReplayAttack,
			Severity:      SeverityCritical,
			Description:   "Test replay attack with different nonce",
			Vulnerability: VulnMissingNonce,
			TestData: map[string]interface{}{
				"signature":        "valid_signature_bytes",
				"nonce":            "1",
				"expectedBehavior": "should_reject_different_nonce",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
		{
			ID:            "REPLAY_003",
			Name:          "Cross_Chain_Replay_Attack",
			Category:      CategoryReplayAttack,
			Severity:      SeverityCritical,
			Description:   "Test cross-chain replay attack",
			Vulnerability: VulnMissingChainID,
			TestData: map[string]interface{}{
				"signature":        "valid_signature_bytes",
				"sourceChain":      "ethereum_mainnet",
				"targetChain":      "polygon",
				"chainId":          "137",
				"expectedBehavior": "should_reject_wrong_chain",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityAdvanced,
		},
		{
			ID:            "REPLAY_004",
			Name:          "Replay_Attack_Expired_Deadline",
			Category:      CategoryReplayAttack,
			Severity:      SeverityHigh,
			Description:   "Test replay attack with expired deadline",
			Vulnerability: VulnMissingDeadline,
			TestData: map[string]interface{}{
				"signature":        "valid_signature_bytes",
				"deadline":         "1", // Expired
				"expectedBehavior": "should_reject_expired",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addTimingAttackTests adds timing attack tests
func (tm *TestMatrix) addTimingAttackTests() {
	tests := []TestMatrixCase{
		{
			ID:            "TIMING_001",
			Name:          "Timing_Attack_Deadline_Validation",
			Category:      CategoryTimingAttack,
			Severity:      SeverityHigh,
			Description:   "Test timing attack on deadline validation",
			Vulnerability: VulnMissingDeadline,
			TestData: map[string]interface{}{
				"deadline":         "9999999999",
				"currentTime":      "9999999998",
				"expectedBehavior": "should_accept_valid_deadline",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityAdvanced,
		},
		{
			ID:            "TIMING_002",
			Name:          "Timing_Attack_Nonce_Validation",
			Category:      CategoryTimingAttack,
			Severity:      SeverityHigh,
			Description:   "Test timing attack on nonce validation",
			Vulnerability: VulnMissingNonce,
			TestData: map[string]interface{}{
				"nonce":            "0",
				"expectedNonce":    "0",
				"expectedBehavior": "should_accept_valid_nonce",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityAdvanced,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addEntropyAttackTests adds entropy attack tests
func (tm *TestMatrix) addEntropyAttackTests() {
	tests := []TestMatrixCase{
		{
			ID:            "ENTROPY_001",
			Name:          "Low_Entropy_Nonce",
			Category:      CategoryEntropyAttack,
			Severity:      SeverityMedium,
			Description:   "Test low entropy nonce generation",
			Vulnerability: VulnInsufficientEntropy,
			TestData: map[string]interface{}{
				"nonce":            "1",
				"entropySource":    "sequential",
				"expectedBehavior": "should_have_sufficient_entropy",
			},
			ExpectedResult: ResultVulnerable,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
		{
			ID:            "ENTROPY_002",
			Name:          "Predictable_Timestamp",
			Category:      CategoryEntropyAttack,
			Severity:      SeverityMedium,
			Description:   "Test predictable timestamp usage",
			Vulnerability: VulnInsufficientEntropy,
			TestData: map[string]interface{}{
				"timestamp":        "1640995200", // Predictable
				"entropySource":    "timestamp_only",
				"expectedBehavior": "should_have_sufficient_entropy",
			},
			ExpectedResult: ResultVulnerable,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addFormatValidationTests adds format validation tests
func (tm *TestMatrix) addFormatValidationTests() {
	tests := []TestMatrixCase{
		{
			ID:          "FORMAT_001",
			Name:        "Invalid_Signature_Format",
			Category:    CategoryFormatValidation,
			Severity:    SeverityMedium,
			Description: "Test invalid signature format",
			TestData: map[string]interface{}{
				"signature":        "invalid_format",
				"expectedBehavior": "should_reject_invalid_format",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "FORMAT_002",
			Name:        "Invalid_Struct_Format",
			Category:    CategoryFormatValidation,
			Severity:    SeverityMedium,
			Description: "Test invalid struct format for EIP712",
			TestData: map[string]interface{}{
				"structData":       "invalid_struct",
				"expectedBehavior": "should_reject_invalid_struct",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  EIP712,
			Complexity:     ComplexityMedium,
		},
		{
			ID:            "FORMAT_003",
			Name:          "Invalid_Domain_Separator",
			Category:      CategoryFormatValidation,
			Severity:      SeverityHigh,
			Description:   "Test invalid domain separator",
			Vulnerability: VulnMissingDomainSeparator,
			TestData: map[string]interface{}{
				"domainSeparator":  "invalid_domain",
				"expectedBehavior": "should_reject_invalid_domain",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  EIP712,
			Complexity:     ComplexityMedium,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addCrossChainAttackTests adds cross-chain attack tests
func (tm *TestMatrix) addCrossChainAttackTests() {
	tests := []TestMatrixCase{
		{
			ID:            "CROSSCHAIN_001",
			Name:          "Cross_Chain_Replay_No_ChainID",
			Category:      CategoryCrossChainAttack,
			Severity:      SeverityCritical,
			Description:   "Test cross-chain replay without chain ID",
			Vulnerability: VulnMissingChainID,
			TestData: map[string]interface{}{
				"sourceChain":      "ethereum_mainnet",
				"targetChain":      "bsc",
				"chainId":          "56",
				"expectedBehavior": "should_reject_wrong_chain",
			},
			ExpectedResult: ResultVulnerable,
			SignatureType:  ETHSign,
			Complexity:     ComplexityAdvanced,
		},
		{
			ID:          "CROSSCHAIN_002",
			Name:        "Cross_Chain_Replay_With_ChainID",
			Category:    CategoryCrossChainAttack,
			Severity:    SeverityHigh,
			Description: "Test cross-chain replay with chain ID validation",
			TestData: map[string]interface{}{
				"sourceChain":      "ethereum_mainnet",
				"targetChain":      "polygon",
				"chainId":          "137",
				"expectedBehavior": "should_reject_wrong_chain",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityAdvanced,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addMultiSigAttackTests adds multi-signature attack tests
func (tm *TestMatrix) addMultiSigAttackTests() {
	tests := []TestMatrixCase{
		{
			ID:          "MULTISIG_001",
			Name:        "MultiSig_Threshold_Attack",
			Category:    CategoryMultiSigAttack,
			Severity:    SeverityCritical,
			Description: "Test multi-signature threshold attack",
			TestData: map[string]interface{}{
				"requiredSignatures": 3,
				"providedSignatures": 2,
				"expectedBehavior":   "should_reject_insufficient_signatures",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  EIP712,
			Complexity:     ComplexityAdvanced,
		},
		{
			ID:          "MULTISIG_002",
			Name:        "MultiSig_Duplicate_Signatures",
			Category:    CategoryMultiSigAttack,
			Severity:    SeverityHigh,
			Description: "Test multi-signature with duplicate signatures",
			TestData: map[string]interface{}{
				"signatures":       []string{"sig1", "sig1", "sig2"},
				"expectedBehavior": "should_reject_duplicate_signatures",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  EIP712,
			Complexity:     ComplexityAdvanced,
		},
		{
			ID:          "MULTISIG_003",
			Name:        "MultiSig_Invalid_Signer",
			Category:    CategoryMultiSigAttack,
			Severity:    SeverityHigh,
			Description: "Test multi-signature with invalid signer",
			TestData: map[string]interface{}{
				"signers":          []string{"0x1234", "0x5678", "0x0000"},
				"expectedBehavior": "should_reject_invalid_signer",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  EIP712,
			Complexity:     ComplexityAdvanced,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addEdgeCaseTests adds edge case tests
func (tm *TestMatrix) addEdgeCaseTests() {
	tests := []TestMatrixCase{
		{
			ID:          "EDGE_001",
			Name:        "Maximum_Nonce_Value",
			Category:    CategoryEdgeCase,
			Severity:    SeverityMedium,
			Description: "Test maximum nonce value",
			TestData: map[string]interface{}{
				"nonce":            "115792089237316195423570985008687907853269984665640564039457584007913129639935", // max uint256
				"expectedBehavior": "should_handle_max_nonce",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
		{
			ID:          "EDGE_002",
			Name:        "Zero_Amount_Transfer",
			Category:    CategoryEdgeCase,
			Severity:    SeverityLow,
			Description: "Test zero amount transfer",
			TestData: map[string]interface{}{
				"amount":           "0",
				"expectedBehavior": "should_handle_zero_amount",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "EDGE_003",
			Name:        "Maximum_Deadline",
			Category:    CategoryEdgeCase,
			Severity:    SeverityMedium,
			Description: "Test maximum deadline value",
			TestData: map[string]interface{}{
				"deadline":         "9999999999999999999999999999999999999999999999999999999999999999",
				"expectedBehavior": "should_handle_max_deadline",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityMedium,
		},
		{
			ID:          "EDGE_004",
			Name:        "Empty_Signature",
			Category:    CategoryEdgeCase,
			Severity:    SeverityMedium,
			Description: "Test empty signature",
			TestData: map[string]interface{}{
				"signature":        "",
				"expectedBehavior": "should_reject_empty_signature",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
		{
			ID:          "EDGE_005",
			Name:        "Null_Signature",
			Category:    CategoryEdgeCase,
			Severity:    SeverityMedium,
			Description: "Test null signature",
			TestData: map[string]interface{}{
				"signature":        "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"expectedBehavior": "should_reject_null_signature",
			},
			ExpectedResult: ResultRevert,
			SignatureType:  ETHSign,
			Complexity:     ComplexityBasic,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// addStressTests adds stress tests
func (tm *TestMatrix) addStressTests() {
	tests := []TestMatrixCase{
		{
			ID:            "STRESS_001",
			Name:          "High_Frequency_Replay",
			Category:      CategoryStressTest,
			Severity:      SeverityHigh,
			Description:   "Test high frequency replay attacks",
			Vulnerability: VulnMissingNonce,
			TestData: map[string]interface{}{
				"replayCount":      1000,
				"frequency":        "high",
				"expectedBehavior": "should_handle_high_frequency",
			},
			ExpectedResult: ResultVulnerable,
			SignatureType:  ETHSign,
			Complexity:     ComplexityExpert,
		},
		{
			ID:          "STRESS_002",
			Name:        "Large_Struct_Validation",
			Category:    CategoryStressTest,
			Severity:    SeverityMedium,
			Description: "Test large struct validation",
			TestData: map[string]interface{}{
				"structSize":       "large",
				"fieldCount":       100,
				"expectedBehavior": "should_handle_large_struct",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  EIP712,
			Complexity:     ComplexityExpert,
		},
		{
			ID:          "STRESS_003",
			Name:        "Concurrent_Signature_Validation",
			Category:    CategoryStressTest,
			Severity:    SeverityHigh,
			Description: "Test concurrent signature validation",
			TestData: map[string]interface{}{
				"concurrentCount":  50,
				"expectedBehavior": "should_handle_concurrent_validation",
			},
			ExpectedResult: ResultSuccess,
			SignatureType:  ETHSign,
			Complexity:     ComplexityExpert,
		},
	}

	tm.TestCases = append(tm.TestCases, tests...)
}

// GetTestCasesByCategory returns test cases filtered by category
func (tm *TestMatrix) GetTestCasesByCategory(category TestCategory) []TestMatrixCase {
	var filtered []TestMatrixCase
	for _, tc := range tm.TestCases {
		if tc.Category == category {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}

// GetTestCasesBySeverity returns test cases filtered by severity
func (tm *TestMatrix) GetTestCasesBySeverity(severity TestSeverity) []TestMatrixCase {
	var filtered []TestMatrixCase
	for _, tc := range tm.TestCases {
		if tc.Severity == severity {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}

// GetTestCasesBySignatureType returns test cases filtered by signature type
func (tm *TestMatrix) GetTestCasesBySignatureType(sigType SignatureKind) []TestMatrixCase {
	var filtered []TestMatrixCase
	for _, tc := range tm.TestCases {
		if tc.SignatureType == sigType {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}

// GetTestCasesByVulnerability returns test cases filtered by vulnerability
func (tm *TestMatrix) GetTestCasesByVulnerability(vuln VulnerabilityType) []TestMatrixCase {
	var filtered []TestMatrixCase
	for _, tc := range tm.TestCases {
		if tc.Vulnerability == vuln {
			filtered = append(filtered, tc)
		}
	}
	return filtered
}

// GenerateTestReport generates a comprehensive test matrix report
func (tm *TestMatrix) GenerateTestReport() string {
	var report strings.Builder
	report.WriteString("=== COMPREHENSIVE TEST MATRIX REPORT ===\n\n")

	// Summary statistics
	totalTests := len(tm.TestCases)
	report.WriteString(fmt.Sprintf("Total Test Cases: %d\n", totalTests))

	// Count by category
	categoryCounts := make(map[TestCategory]int)
	severityCounts := make(map[TestSeverity]int)
	signatureTypeCounts := make(map[SignatureKind]int)

	for _, tc := range tm.TestCases {
		categoryCounts[tc.Category]++
		severityCounts[tc.Severity]++
		signatureTypeCounts[tc.SignatureType]++
	}

	report.WriteString("\nBy Category:\n")
	for category, count := range categoryCounts {
		report.WriteString(fmt.Sprintf("  %s: %d tests\n", category, count))
	}

	report.WriteString("\nBy Severity:\n")
	for severity, count := range severityCounts {
		report.WriteString(fmt.Sprintf("  %s: %d tests\n", severity, count))
	}

	report.WriteString("\nBy Signature Type:\n")
	for sigType, count := range signatureTypeCounts {
		report.WriteString(fmt.Sprintf("  %s: %d tests\n", sigType, count))
	}

	// List all test cases
	report.WriteString("\nDetailed Test Cases:\n")
	for _, tc := range tm.TestCases {
		report.WriteString(fmt.Sprintf("\n%s - %s (%s)\n", tc.ID, tc.Name, tc.Severity))
		report.WriteString(fmt.Sprintf("  Category: %s\n", tc.Category))
		report.WriteString(fmt.Sprintf("  Description: %s\n", tc.Description))
		report.WriteString(fmt.Sprintf("  Expected Result: %s\n", tc.ExpectedResult))
		if tc.Vulnerability != "" {
			report.WriteString(fmt.Sprintf("  Vulnerability: %s\n", tc.Vulnerability))
		}
	}

	return report.String()
}
