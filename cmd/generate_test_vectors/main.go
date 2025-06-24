package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"very_smart_analyzer/internal/fuzzer"
	"very_smart_analyzer/internal/test_vectors"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: generate_test_vectors <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  comprehensive - Generate comprehensive test suite")
		fmt.Println("  random        - Generate random test suite")
		fmt.Println("  targeted      - Generate targeted test suite for specific vulnerabilities")
		fmt.Println("  patterns      - List available signature patterns")
		os.Exit(1)
	}

	command := os.Args[1]

	// Create output directory
	outputDir := "generated_test_vectors"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize test vector generator
	config := &test_vectors.GeneratorConfig{
		MaxTestCases:           20,
		IncludeVulnerabilities: true,
		IncludeEdgeCases:       true,
		ComplexityLevel:        fuzzer.Medium,
		OutputDirectory:        outputDir,
	}

	generator := test_vectors.NewTestVectorGenerator(config)

	switch command {
	case "comprehensive":
		generateComprehensiveTestSuite(generator, outputDir)
	case "random":
		generateRandomTestSuite(generator, outputDir)
	case "targeted":
		generateTargetedTestSuite(generator, outputDir)
	case "patterns":
		listPatterns()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func generateComprehensiveTestSuite(generator *test_vectors.TestVectorGenerator, outputDir string) {
	fmt.Println("Generating comprehensive test suite...")

	contracts, err := generator.GenerateComprehensiveTestSuite()
	if err != nil {
		log.Fatalf("Failed to generate comprehensive test suite: %v", err)
	}

	fmt.Printf("Generated %d contracts\n", len(contracts))

	for name, code := range contracts {
		filename := filepath.Join(outputDir, fmt.Sprintf("%s.sol", name))
		if err := os.WriteFile(filename, []byte(code), 0644); err != nil {
			log.Printf("Failed to write %s: %v", filename, err)
		} else {
			fmt.Printf("  - %s\n", filename)
		}
	}

	fmt.Printf("Test suite written to %s/\n", outputDir)
}

func generateRandomTestSuite(generator *test_vectors.TestVectorGenerator, outputDir string) {
	fmt.Println("Generating random test suite...")

	contracts, err := generator.GenerateRandomTestSuite()
	if err != nil {
		log.Fatalf("Failed to generate random test suite: %v", err)
	}

	fmt.Printf("Generated %d contracts\n", len(contracts))

	for name, code := range contracts {
		filename := filepath.Join(outputDir, fmt.Sprintf("%s.sol", name))
		if err := os.WriteFile(filename, []byte(code), 0644); err != nil {
			log.Printf("Failed to write %s: %v", filename, err)
		} else {
			fmt.Printf("  - %s\n", filename)
		}
	}

	fmt.Printf("Random test suite written to %s/\n", outputDir)
}

func generateTargetedTestSuite(generator *test_vectors.TestVectorGenerator, outputDir string) {
	fmt.Println("Generating targeted test suite...")

	// Target specific vulnerabilities
	targetVulnerabilities := []fuzzer.Vulnerability{
		fuzzer.MissingNonce,
		fuzzer.MissingDeadline,
		fuzzer.ReplayAttackVuln,
		fuzzer.WeakSignerValidation,
	}

	contracts, err := generator.GenerateTargetedTestSuite(targetVulnerabilities)
	if err != nil {
		log.Fatalf("Failed to generate targeted test suite: %v", err)
	}

	fmt.Printf("Generated %d contracts targeting specific vulnerabilities\n", len(contracts))

	for name, code := range contracts {
		filename := filepath.Join(outputDir, fmt.Sprintf("%s.sol", name))
		if err := os.WriteFile(filename, []byte(code), 0644); err != nil {
			log.Printf("Failed to write %s: %v", filename, err)
		} else {
			fmt.Printf("  - %s\n", filename)
		}
	}

	fmt.Printf("Targeted test suite written to %s/\n", outputDir)
}

func listPatterns() {
	fmt.Println("Available signature patterns:")

	registry := fuzzer.NewSignaturePatternRegistry()
	patterns := registry.ListPatterns()

	for _, pattern := range patterns {
		fmt.Printf("  - %s\n", pattern)
	}
}
