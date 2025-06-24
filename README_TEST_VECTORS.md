# Go-Based Test Vector Generation System

This document describes the new Go-based test vector generation system that replaces the static Solidity files with a dynamic, extensible framework for generating signature verification test cases.

## Overview

The new system provides:

1. **Dynamic Test Generation**: Generate test cases programmatically in Go
2. **Extensible Framework**: Easy to add new vulnerability patterns and signature types
3. **Comprehensive Coverage**: Support for all major signature verification patterns
4. **AI Integration**: Designed to work seamlessly with the AI analyzer
5. **Fuzz Testing Ready**: Generate test cases optimized for fuzz testing tools

## Architecture

```
internal/
├── fuzzer/
│   ├── test_generator.go      # Core test case generation
│   └── signature_patterns.go  # Signature pattern definitions
├── test_vectors/
│   └── generator.go           # Main test vector orchestrator
└── analyzer/
    └── analyzer.go           # Your existing AI analyzer

cmd/
└── generate_test_vectors/
    └── main.go               # Command-line tool
```

## Key Components

### 1. Test Generator (`internal/fuzzer/test_generator.go`)

The core test case generator that:
- Defines test case structures and types
- Manages template-based code generation
- Handles different signature types and encodings
- Supports vulnerability and edge case injection

**Key Types:**
- `TestCase`: Represents a single test case configuration
- `SignatureType`: EIP712, ETH_SIGN, EIP2612, EIP1271, Custom, Mixed
- `Encoding`: Combined, Split, Both
- `Arity`: Single, Multiple
- `Vulnerability`: MissingNonce, MissingDeadline, ReplayAttack, etc.
- `EdgeCase`: ZeroAddresses, EmptyBytesStrings, MaximumValues, etc.

### 2. Signature Patterns (`internal/fuzzer/signature_patterns.go`)

Defines reusable signature verification patterns:
- **EIP712 Combined Single**: Standard EIP712 permit with combined encoding
- **EIP712 Combined Multiple**: Multiple EIP712 signatures
- **ETH Sign Combined Single**: Ethereum personal message signing
- **Missing Nonce**: Vulnerability pattern without nonce protection
- **Missing Deadline**: Vulnerability pattern without deadline validation

Each pattern includes:
- Function implementations with actual vulnerabilities
- Struct definitions
- Import statements
- Template strings for code generation

### 3. Test Vector Generator (`internal/test_vectors/generator.go`)

The main orchestrator that:
- Generates comprehensive test suites
- Creates random test cases for fuzz testing
- Targets specific vulnerabilities
- Manages test case variants and combinations

**Generation Modes:**
- `GenerateComprehensiveTestSuite()`: All patterns with variants
- `GenerateRandomTestSuite()`: Random test cases for fuzz testing
- `GenerateTargetedTestSuite()`: Specific vulnerability targeting

### 4. Command-Line Tool (`cmd/generate_test_vectors/main.go`)

Easy-to-use CLI for generating test vectors:

```bash
# Generate comprehensive test suite
go run cmd/generate_test_vectors/main.go comprehensive

# Generate random test suite for fuzz testing
go run cmd/generate_test_vectors/main.go random

# Generate targeted test suite for specific vulnerabilities
go run cmd/generate_test_vectors/main.go targeted

# List available signature patterns
go run cmd/generate_test_vectors/main.go patterns
```

## Usage Examples

### Basic Usage

```go
package main

import (
    "very_smart_analyzer/internal/fuzzer"
    "very_smart_analyzer/internal/test_vectors"
)

func main() {
    // Configure test vector generation
    config := &test_vectors.GeneratorConfig{
        MaxTestCases:         20,
        IncludeVulnerabilities: true,
        IncludeEdgeCases:     true,
        ComplexityLevel:      fuzzer.Medium,
        OutputDirectory:      "generated_tests",
    }

    // Create generator
    generator := test_vectors.NewTestVectorGenerator(config)

    // Generate comprehensive test suite
    contracts, err := generator.GenerateComprehensiveTestSuite()
    if err != nil {
        log.Fatal(err)
    }

    // Use generated contracts
    for name, code := range contracts {
        fmt.Printf("Generated: %s\n", name)
        // Pass to analyzer or save to file
    }
}
```

### Integration with Analyzer

```go
// Generate test cases for analysis
generator := test_vectors.NewTestVectorGenerator(config)
contracts, err := generator.GenerateTargetedTestSuite([]fuzzer.Vulnerability{
    fuzzer.MissingNonce,
    fuzzer.ReplayAttackVuln,
})

// Analyze each generated contract
analyzer := analyzer.NewAnalyzer()
for name, code := range contracts {
    results, err := analyzer.AnalyzeContract(code)
    if err != nil {
        log.Printf("Failed to analyze %s: %v", name, err)
        continue
    }
    
    // Process analysis results
    fmt.Printf("Analysis of %s: %+v\n", name, results)
}
```

### Adding New Patterns

```go
// In signature_patterns.go
func (spr *SignaturePatternRegistry) registerPatterns() {
    // Add new pattern
    spr.patterns["new_vulnerability"] = &SignaturePattern{
        Name:        "New Vulnerability",
        Description: "Description of the new vulnerability",
        Template:    newVulnerabilityTemplate,
        Functions: []FunctionPattern{
            {
                Name: "vulnerableFunction",
                Parameters: []FunctionParameter{
                    {Name: "param1", Type: "address"},
                    {Name: "param2", Type: "uint256"},
                },
                Implementation: `// VULNERABLE: Description of vulnerability
// Actual vulnerable code here`,
                Vulnerabilities: []Vulnerability{fuzzer.NewVulnerability},
                EdgeCases:      []EdgeCase{fuzzer.ZeroAddresses},
            },
        },
        Imports: []string{
            "@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
        },
    }
}
```

## Generated Test Cases

The system generates test cases covering:

### Signature Types
- **EIP712**: Typed structured data signing
- **ETH_SIGN**: Ethereum personal message signing
- **EIP2612**: Gasless permit standard
- **EIP1271**: Contract signature verification
- **Custom**: Proprietary signature schemes
- **Mixed**: Combinations of different types

### Vulnerability Patterns
- **Missing Controls**: Nonce, deadline, timestamp, chain ID validation
- **Weak Validation**: Insufficient signer verification
- **Replay Attacks**: Cross-function and cross-contract replay
- **Reentrancy**: Signature-based reentrancy vulnerabilities
- **Timestamp Manipulation**: Malleable timestamp attacks

### Edge Cases
- **Zero Values**: Zero addresses, amounts, nonces
- **Empty Values**: Empty arrays, bytes, strings
- **Maximum Values**: Type maximums and overflow conditions
- **Boundary Values**: Type boundaries and edge conditions
- **Expired Values**: Expired deadlines and timestamps

## Benefits Over Static Files

1. **Dynamic Generation**: Create test cases on-demand with specific characteristics
2. **Extensibility**: Easy to add new patterns without modifying existing code
3. **Configuration**: Fine-grained control over test case generation
4. **Integration**: Seamless integration with Go-based tools and analyzers
5. **Maintenance**: Centralized pattern definitions and templates
6. **Randomization**: Generate random test cases for comprehensive fuzz testing
7. **Targeting**: Focus on specific vulnerabilities or edge cases

## Future Enhancements

1. **More Patterns**: Additional signature verification patterns
2. **Complex Scenarios**: Multi-signature, governance, time-lock patterns
3. **Integration**: Direct integration with fuzz testing tools (Foundry, Echidna)
4. **Metrics**: Test coverage and effectiveness metrics
5. **Customization**: User-defined vulnerability patterns
6. **Performance**: Optimized generation for large test suites

## Migration from Static Files

The old static file approach has been replaced with this dynamic system. Benefits:

- **No more 67 static files** to maintain
- **Programmatic generation** of exactly the test cases you need
- **Easy extension** with new patterns and vulnerabilities
- **Better integration** with your Go-based analyzer
- **More flexible** test case creation

This new system provides the foundation for comprehensive, AI-assisted signature verification vulnerability detection with maximum flexibility and extensibility. 