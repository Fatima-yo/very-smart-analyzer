package fuzzer

import (
	"fmt"
	"strings"
	"text/template"
)

// TestCase represents a single test case configuration
type TestCase struct {
	Name            string
	SignatureType   SignatureType
	Encoding        Encoding
	Arity           Arity
	Location        Location
	Vulnerabilities []Vulnerability
	EdgeCases       []EdgeCase
	Complexity      Complexity
}

// SignatureType represents different signature verification methods
type SignatureType string

const (
	EIP712  SignatureType = "EIP712"
	ETHSign SignatureType = "ETH_SIGN"
	EIP2612 SignatureType = "EIP2612"
	EIP1271 SignatureType = "EIP1271"
	Custom  SignatureType = "CUSTOM"
	Mixed   SignatureType = "MIXED"
)

// Encoding represents signature encoding methods
type Encoding string

const (
	Combined Encoding = "Combined"
	Split    Encoding = "Split"
	Both     Encoding = "Both"
)

// Arity represents number of signatures
type Arity string

const (
	Single   Arity = "Single"
	Multiple Arity = "Multiple"
)

// Location represents where signatures are placed
type Location string

const (
	Parameter    Location = "Parameter"
	StructField  Location = "StructField"
	ArrayElement Location = "ArrayElement"
	Nested       Location = "Nested"
	DeepNested   Location = "DeepNested"
	ComplexLoc   Location = "Complex"
	Recursive    Location = "Recursive"
)

// Vulnerability represents security vulnerability types
type Vulnerability string

const (
	MissingNonce            Vulnerability = "MissingNonce"
	MissingDeadline         Vulnerability = "MissingDeadline"
	MissingTimestamp        Vulnerability = "MissingTimestamp"
	MissingChainID          Vulnerability = "MissingChainID"
	MissingDomainSeparator  Vulnerability = "MissingDomainSeparator"
	WeakSignerValidation    Vulnerability = "WeakSignerValidation"
	UnsafeSignatureRecovery Vulnerability = "UnsafeSignatureRecovery"
	MissingVersion          Vulnerability = "MissingVersion"
	InsufficientEntropy     Vulnerability = "InsufficientEntropy"
	NoThresholdCheck        Vulnerability = "NoThresholdCheck"
	ReplayAttackVuln        Vulnerability = "ReplayAttack"
	CrossFunctionReplay     Vulnerability = "CrossFunctionReplay"
	ReentrancySignature     Vulnerability = "ReentrancySignature"
	TimestampManipulation   Vulnerability = "TimestampManipulation"
	MultipleVulnerabilities Vulnerability = "MultipleVulnerabilities"
)

// EdgeCase represents boundary conditions and edge cases
type EdgeCase string

const (
	EmptyArrays            EdgeCase = "EmptyArrays"
	ZeroAddresses          EdgeCase = "ZeroAddresses"
	MaximumValues          EdgeCase = "MaximumValues"
	ZeroValues             EdgeCase = "ZeroValues"
	InvalidSignatureValues EdgeCase = "InvalidSignatureValues"
	EmptyBytesStrings      EdgeCase = "EmptyBytesStrings"
	BoundaryValues         EdgeCase = "BoundaryValues"
	ExtremeStructValues    EdgeCase = "ExtremeStructValues"
	ExpiredDeadlines       EdgeCase = "ExpiredDeadlines"
	DuplicateSignatures    EdgeCase = "DuplicateSignatures"
	MalleableSignatures    EdgeCase = "MalleableSignatures"
	InvalidEIP712Domain    EdgeCase = "InvalidEIP712Domain"
	OverflowValues         EdgeCase = "OverflowValues"
	UnderflowValues        EdgeCase = "UnderflowValues"
	MixedEdgeCases         EdgeCase = "MixedEdgeCases"
)

// Complexity represents the complexity level of the test case
type Complexity string

const (
	Simple  Complexity = "Simple"
	Medium  Complexity = "Medium"
	Complex Complexity = "Complex"
	Extreme Complexity = "Extreme"
)

// TestGenerator is the main test case generator
type TestGenerator struct {
	templates map[string]*template.Template
	config    *TestConfig
}

// TestConfig holds configuration for test generation
type TestConfig struct {
	MaxFunctionsPerContract int
	IncludeComments         bool
	AddVulnerabilities      bool
	AddEdgeCases            bool
	ComplexityLevel         Complexity
	SignatureTypes          []SignatureType
	Encodings               []Encoding
	Arities                 []Arity
	Locations               []Location
}

// NewTestGenerator creates a new test generator
func NewTestGenerator(config *TestConfig) *TestGenerator {
	tg := &TestGenerator{
		templates: make(map[string]*template.Template),
		config:    config,
	}
	tg.loadTemplates()
	return tg
}

// GenerateTestCase generates a complete test case contract
func (tg *TestGenerator) GenerateTestCase(testCase *TestCase) (string, error) {
	// Get the appropriate signature pattern
	patternRegistry := NewSignaturePatternRegistry()
	patternName := tg.getPatternName(testCase)

	pattern, err := patternRegistry.GetPattern(patternName)
	if err != nil {
		// Fallback to basic pattern
		pattern, err = patternRegistry.GetPattern("missing_nonce")
		if err != nil {
			return "", fmt.Errorf("no suitable pattern found for test case %s", testCase.Name)
		}
	}

	// Create template data
	data := map[string]interface{}{
		"Name":            testCase.Name,
		"Functions":       pattern.Functions,
		"Structs":         pattern.Structs,
		"Imports":         pattern.Imports,
		"Vulnerabilities": testCase.Vulnerabilities,
		"EdgeCases":       testCase.EdgeCases,
	}

	// Execute the pattern template
	var result strings.Builder
	tmpl := template.Must(template.New("contract").Parse(pattern.Template))
	err = tmpl.Execute(&result, data)
	if err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return result.String(), nil
}

// getPatternName determines the appropriate pattern name based on test case
func (tg *TestGenerator) getPatternName(testCase *TestCase) string {
	// Check for specific vulnerability patterns first
	for _, vuln := range testCase.Vulnerabilities {
		switch vuln {
		case MissingNonce:
			return "missing_nonce"
		case MissingDeadline:
			return "missing_deadline"
		}
	}

	// Check signature type and encoding
	switch testCase.SignatureType {
	case EIP712:
		if testCase.Arity == Multiple {
			return "eip712_combined_multiple"
		}
		return "eip712_combined_single"
	case ETHSign:
		return "eth_sign_combined_single"
	default:
		return "missing_nonce" // Default fallback
	}
}

// GenerateTestSuite generates a complete test suite
func (tg *TestGenerator) GenerateTestSuite(testCases []*TestCase) (map[string]string, error) {
	results := make(map[string]string)

	for _, testCase := range testCases {
		contractCode, err := tg.GenerateTestCase(testCase)
		if err != nil {
			return nil, fmt.Errorf("failed to generate test case %s: %w", testCase.Name, err)
		}
		results[testCase.Name] = contractCode
	}

	return results, nil
}

// GenerateRandomTestCase generates a random test case
func (tg *TestGenerator) GenerateRandomTestCase() (*TestCase, error) {
	// This will be implemented to generate random test cases
	// for fuzz testing purposes
	return nil, fmt.Errorf("not implemented yet")
}

// selectTemplate chooses the appropriate template based on test case characteristics
func (tg *TestGenerator) selectTemplate(testCase *TestCase) string {
	// Template selection logic based on signature type, encoding, etc.
	switch testCase.SignatureType {
	case EIP712:
		if testCase.Encoding == Split {
			return "eip712_split"
		}
		return "eip712_combined"
	case ETHSign:
		return "eth_sign"
	case EIP2612:
		return "eip2612"
	case EIP1271:
		return "eip1271"
	case Custom:
		return "custom"
	case Mixed:
		return "mixed"
	default:
		return "basic"
	}
}

// prepareTemplateData prepares data for template execution
func (tg *TestGenerator) prepareTemplateData(testCase *TestCase) map[string]interface{} {
	return map[string]interface{}{
		"TestCase":         testCase,
		"Config":           tg.config,
		"HasVulnerability": tg.hasVulnerability(testCase),
		"HasEdgeCase":      tg.hasEdgeCase(testCase),
		"ComplexityLevel":  testCase.Complexity,
		"Functions":        tg.generateFunctions(testCase),
		"Structs":          tg.generateStructs(testCase),
		"Imports":          tg.generateImports(testCase),
	}
}

// loadTemplates loads all available templates
func (tg *TestGenerator) loadTemplates() {
	// Load different template types
	tg.templates["basic"] = template.Must(template.New("basic").Parse(basicTemplate))
	tg.templates["eip712_combined"] = template.Must(template.New("eip712_combined").Parse(eip712CombinedTemplate))
	tg.templates["eip712_split"] = template.Must(template.New("eip712_split").Parse(eip712SplitTemplate))
	tg.templates["eth_sign"] = template.Must(template.New("eth_sign").Parse(ethSignTemplate))
	tg.templates["eip2612"] = template.Must(template.New("eip2612").Parse(eip2612Template))
	tg.templates["eip1271"] = template.Must(template.New("eip1271").Parse(eip1271Template))
	tg.templates["custom"] = template.Must(template.New("custom").Parse(customTemplate))
	tg.templates["mixed"] = template.Must(template.New("mixed").Parse(mixedTemplate))
}

// Helper methods
func (tg *TestGenerator) hasVulnerability(testCase *TestCase) bool {
	return len(testCase.Vulnerabilities) > 0
}

func (tg *TestGenerator) hasEdgeCase(testCase *TestCase) bool {
	return len(testCase.EdgeCases) > 0
}

func (tg *TestGenerator) generateFunctions(testCase *TestCase) []string {
	// Generate function implementations based on test case
	// This will be implemented to create actual vulnerable functions
	return []string{}
}

func (tg *TestGenerator) generateStructs(testCase *TestCase) []string {
	// Generate struct definitions based on test case
	return []string{}
}

func (tg *TestGenerator) generateImports(testCase *TestCase) []string {
	// Generate import statements based on test case
	imports := []string{
		"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
	}

	if testCase.SignatureType == EIP712 {
		imports = append(imports, "@openzeppelin/contracts/utils/cryptography/EIP712.sol")
	}

	return imports
}

// Template strings (these will be moved to separate files)
const basicTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

{{range .Imports}}
import "{{.}}";
{{end}}

/**
 * Test Case: {{.TestCase.Name}}
 * Signature Type: {{.TestCase.SignatureType}}
 * Encoding: {{.TestCase.Encoding}}
 * Arity: {{.TestCase.Arity}}
 * Location: {{.TestCase.Location}}
 * Complexity: {{.TestCase.Complexity}}
 */

contract {{.TestCase.Name}} {
    // Implementation will be generated based on test case characteristics
}
`

const eip712CombinedTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract {{.TestCase.Name}} is EIP712 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("{{.TestCase.Name}}", "1") {}

    // Generated functions will be added here
}
`

// Additional templates will be added for other signature types...
const eip712SplitTemplate = ``
const ethSignTemplate = ``
const eip2612Template = ``
const eip1271Template = ``
const customTemplate = ``
const mixedTemplate = ``
