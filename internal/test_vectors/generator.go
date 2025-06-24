package test_vectors

import (
	"fmt"
	"math/rand"
	"time"

	"very_smart_analyzer/internal/fuzzer"
)

// TestVectorGenerator is the main orchestrator for generating test vectors
type TestVectorGenerator struct {
	patternRegistry *fuzzer.SignaturePatternRegistry
	config          *GeneratorConfig
}

// GeneratorConfig holds configuration for test vector generation
type GeneratorConfig struct {
	MaxTestCases           int
	IncludeVulnerabilities bool
	IncludeEdgeCases       bool
	ComplexityLevel        fuzzer.Complexity
	RandomSeed             int64
	OutputDirectory        string
}

// NewTestVectorGenerator creates a new test vector generator
func NewTestVectorGenerator(config *GeneratorConfig) *TestVectorGenerator {
	if config.RandomSeed == 0 {
		config.RandomSeed = time.Now().UnixNano()
	}
	rand.Seed(config.RandomSeed)

	return &TestVectorGenerator{
		patternRegistry: fuzzer.NewSignaturePatternRegistry(),
		config:          config,
	}
}

// GenerateComprehensiveTestSuite generates a complete test suite with all patterns
func (tvg *TestVectorGenerator) GenerateComprehensiveTestSuite() (map[string]string, error) {
	// Get all available patterns
	patterns := tvg.patternRegistry.ListPatterns()

	// Generate test cases for each pattern
	testCases := make([]*fuzzer.TestCase, 0)

	for _, patternName := range patterns {
		pattern, err := tvg.patternRegistry.GetPattern(patternName)
		if err != nil {
			return nil, fmt.Errorf("failed to get pattern %s: %w", patternName, err)
		}

		// Generate test case for this pattern
		testCase := tvg.generateTestCaseFromPattern(pattern, patternName)
		testCases = append(testCases, testCase)

		// Generate additional variants if needed
		if tvg.config.IncludeVulnerabilities {
			vulnerableVariants := tvg.generateVulnerableVariants(pattern, patternName)
			testCases = append(testCases, vulnerableVariants...)
		}

		if tvg.config.IncludeEdgeCases {
			edgeCaseVariants := tvg.generateEdgeCaseVariants(pattern, patternName)
			testCases = append(testCases, edgeCaseVariants...)
		}
	}

	// Generate the actual contracts
	generator := fuzzer.NewTestGenerator(&fuzzer.TestConfig{
		MaxFunctionsPerContract: 10,
		IncludeComments:         true,
		AddVulnerabilities:      tvg.config.IncludeVulnerabilities,
		AddEdgeCases:            tvg.config.IncludeEdgeCases,
		ComplexityLevel:         tvg.config.ComplexityLevel,
	})

	return generator.GenerateTestSuite(testCases)
}

// GenerateRandomTestSuite generates a random test suite for fuzz testing
func (tvg *TestVectorGenerator) GenerateRandomTestSuite() (map[string]string, error) {
	testCases := make([]*fuzzer.TestCase, 0)

	for i := 0; i < tvg.config.MaxTestCases; i++ {
		testCase := tvg.generateRandomTestCase()
		testCases = append(testCases, testCase)
	}

	generator := fuzzer.NewTestGenerator(&fuzzer.TestConfig{
		MaxFunctionsPerContract: 5,
		IncludeComments:         true,
		AddVulnerabilities:      tvg.config.IncludeVulnerabilities,
		AddEdgeCases:            tvg.config.IncludeEdgeCases,
		ComplexityLevel:         tvg.config.ComplexityLevel,
	})

	return generator.GenerateTestSuite(testCases)
}

// GenerateTargetedTestSuite generates test cases targeting specific vulnerabilities
func (tvg *TestVectorGenerator) GenerateTargetedTestSuite(targetVulnerabilities []fuzzer.Vulnerability) (map[string]string, error) {
	testCases := make([]*fuzzer.TestCase, 0)

	for _, vuln := range targetVulnerabilities {
		// Generate test cases specifically for this vulnerability
		vulnTestCases := tvg.generateVulnerabilityTestCases(vuln)
		testCases = append(testCases, vulnTestCases...)
	}

	generator := fuzzer.NewTestGenerator(&fuzzer.TestConfig{
		MaxFunctionsPerContract: 8,
		IncludeComments:         true,
		AddVulnerabilities:      true,
		AddEdgeCases:            false,
		ComplexityLevel:         tvg.config.ComplexityLevel,
	})

	return generator.GenerateTestSuite(testCases)
}

// generateTestCaseFromPattern creates a test case from a signature pattern
func (tvg *TestVectorGenerator) generateTestCaseFromPattern(pattern *fuzzer.SignaturePattern, patternName string) *fuzzer.TestCase {
	return &fuzzer.TestCase{
		Name:            fmt.Sprintf("%s_%s", patternName, "basic"),
		SignatureType:   tvg.determineSignatureType(patternName),
		Encoding:        tvg.determineEncoding(patternName),
		Arity:           tvg.determineArity(patternName),
		Location:        fuzzer.Parameter,
		Vulnerabilities: []fuzzer.Vulnerability{},
		EdgeCases:       []fuzzer.EdgeCase{},
		Complexity:      fuzzer.Simple,
	}
}

// generateVulnerableVariants creates vulnerable variants of a pattern
func (tvg *TestVectorGenerator) generateVulnerableVariants(pattern *fuzzer.SignaturePattern, patternName string) []*fuzzer.TestCase {
	variants := make([]*fuzzer.TestCase, 0)

	// Common vulnerabilities to test
	vulnerabilities := []fuzzer.Vulnerability{
		fuzzer.MissingNonce,
		fuzzer.MissingDeadline,
		fuzzer.WeakSignerValidation,
		fuzzer.ReplayAttackVuln,
		fuzzer.CrossFunctionReplay,
	}

	for i, vuln := range vulnerabilities {
		variant := &fuzzer.TestCase{
			Name:            fmt.Sprintf("%s_%s_%d", patternName, "vulnerable", i),
			SignatureType:   tvg.determineSignatureType(patternName),
			Encoding:        tvg.determineEncoding(patternName),
			Arity:           tvg.determineArity(patternName),
			Location:        fuzzer.Parameter,
			Vulnerabilities: []fuzzer.Vulnerability{vuln},
			EdgeCases:       []fuzzer.EdgeCase{},
			Complexity:      fuzzer.Medium,
		}
		variants = append(variants, variant)
	}

	return variants
}

// generateEdgeCaseVariants creates edge case variants of a pattern
func (tvg *TestVectorGenerator) generateEdgeCaseVariants(pattern *fuzzer.SignaturePattern, patternName string) []*fuzzer.TestCase {
	variants := make([]*fuzzer.TestCase, 0)

	// Common edge cases to test
	edgeCases := []fuzzer.EdgeCase{
		fuzzer.ZeroAddresses,
		fuzzer.EmptyBytesStrings,
		fuzzer.MaximumValues,
		fuzzer.ZeroValues,
		fuzzer.ExpiredDeadlines,
	}

	for i, edgeCase := range edgeCases {
		variant := &fuzzer.TestCase{
			Name:            fmt.Sprintf("%s_%s_%d", patternName, "edge", i),
			SignatureType:   tvg.determineSignatureType(patternName),
			Encoding:        tvg.determineEncoding(patternName),
			Arity:           tvg.determineArity(patternName),
			Location:        fuzzer.Parameter,
			Vulnerabilities: []fuzzer.Vulnerability{},
			EdgeCases:       []fuzzer.EdgeCase{edgeCase},
			Complexity:      fuzzer.Medium,
		}
		variants = append(variants, variant)
	}

	return variants
}

// generateVulnerabilityTestCases creates test cases for a specific vulnerability
func (tvg *TestVectorGenerator) generateVulnerabilityTestCases(vuln fuzzer.Vulnerability) []*fuzzer.TestCase {
	testCases := make([]*fuzzer.TestCase, 0)

	// Generate test cases for different signature types with this vulnerability
	signatureTypes := []fuzzer.SignatureType{
		fuzzer.EIP712,
		fuzzer.ETHSign,
		fuzzer.EIP2612,
	}

	for i, sigType := range signatureTypes {
		testCase := &fuzzer.TestCase{
			Name:            fmt.Sprintf("%s_%s_%d", string(vuln), string(sigType), i),
			SignatureType:   sigType,
			Encoding:        fuzzer.Combined,
			Arity:           fuzzer.Single,
			Location:        fuzzer.Parameter,
			Vulnerabilities: []fuzzer.Vulnerability{vuln},
			EdgeCases:       []fuzzer.EdgeCase{},
			Complexity:      fuzzer.Medium,
		}
		testCases = append(testCases, testCase)
	}

	return testCases
}

// generateRandomTestCase creates a random test case
func (tvg *TestVectorGenerator) generateRandomTestCase() *fuzzer.TestCase {
	signatureTypes := []fuzzer.SignatureType{fuzzer.EIP712, fuzzer.ETHSign, fuzzer.EIP2612, fuzzer.EIP1271, fuzzer.Custom}
	encodings := []fuzzer.Encoding{fuzzer.Combined, fuzzer.Split, fuzzer.Both}
	arities := []fuzzer.Arity{fuzzer.Single, fuzzer.Multiple}
	locations := []fuzzer.Location{fuzzer.Parameter, fuzzer.StructField, fuzzer.ArrayElement, fuzzer.Nested}
	vulnerabilities := []fuzzer.Vulnerability{
		fuzzer.MissingNonce, fuzzer.MissingDeadline, fuzzer.WeakSignerValidation,
		fuzzer.ReplayAttackVuln, fuzzer.CrossFunctionReplay, fuzzer.TimestampManipulation,
	}
	edgeCases := []fuzzer.EdgeCase{
		fuzzer.ZeroAddresses, fuzzer.EmptyBytesStrings, fuzzer.MaximumValues,
		fuzzer.ZeroValues, fuzzer.ExpiredDeadlines, fuzzer.DuplicateSignatures,
	}

	return &fuzzer.TestCase{
		Name:            fmt.Sprintf("random_%d", rand.Intn(10000)),
		SignatureType:   signatureTypes[rand.Intn(len(signatureTypes))],
		Encoding:        encodings[rand.Intn(len(encodings))],
		Arity:           arities[rand.Intn(len(arities))],
		Location:        locations[rand.Intn(len(locations))],
		Vulnerabilities: tvg.randomSubsetVulnerabilities(vulnerabilities, 1, 3),
		EdgeCases:       tvg.randomSubsetEdgeCases(edgeCases, 0, 2),
		Complexity:      fuzzer.Complexity(rand.Intn(4)),
	}
}

// Helper methods for determining test case characteristics
func (tvg *TestVectorGenerator) determineSignatureType(patternName string) fuzzer.SignatureType {
	switch {
	case contains(patternName, "eip712"):
		return fuzzer.EIP712
	case contains(patternName, "eth_sign"):
		return fuzzer.ETHSign
	case contains(patternName, "eip2612"):
		return fuzzer.EIP2612
	case contains(patternName, "eip1271"):
		return fuzzer.EIP1271
	case contains(patternName, "custom"):
		return fuzzer.Custom
	default:
		return fuzzer.ETHSign
	}
}

func (tvg *TestVectorGenerator) determineEncoding(patternName string) fuzzer.Encoding {
	switch {
	case contains(patternName, "split"):
		return fuzzer.Split
	case contains(patternName, "both"):
		return fuzzer.Both
	default:
		return fuzzer.Combined
	}
}

func (tvg *TestVectorGenerator) determineArity(patternName string) fuzzer.Arity {
	switch {
	case contains(patternName, "multiple"):
		return fuzzer.Multiple
	default:
		return fuzzer.Single
	}
}

// Utility functions
func randomSubset[T any](slice []T, min, max int) []T {
	if len(slice) == 0 {
		return []T{}
	}

	count := rand.Intn(max-min+1) + min
	if count > len(slice) {
		count = len(slice)
	}

	result := make([]T, 0, count)
	indices := rand.Perm(len(slice))

	for i := 0; i < count; i++ {
		result = append(result, slice[indices[i]])
	}

	return result
}

func (tvg *TestVectorGenerator) randomSubsetVulnerabilities(slice []fuzzer.Vulnerability, min, max int) []fuzzer.Vulnerability {
	return randomSubset(slice, min, max)
}

func (tvg *TestVectorGenerator) randomSubsetEdgeCases(slice []fuzzer.EdgeCase, min, max int) []fuzzer.EdgeCase {
	return randomSubset(slice, min, max)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
