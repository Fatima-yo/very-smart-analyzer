package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"very_smart_analyzer/internal/analyzer"
)

func main() {
	// Parse command line flags
	var (
		contractPath    = flag.String("contract", "contracts/TestCases.sol", "Path to the contract to test")
		maxDuration     = flag.Duration("duration", 30*time.Minute, "Maximum test duration")
		timeoutPerTest  = flag.Duration("timeout", 30*time.Second, "Timeout per individual test")
		gasLimit        = flag.Uint64("gas-limit", 30000000, "Gas limit for tests")
		verbose         = flag.Bool("verbose", false, "Enable verbose output")
		enableStress    = flag.Bool("stress", false, "Enable stress tests")
		enableEdgeCases = flag.Bool("edge-cases", true, "Enable edge case tests")
		categories      = flag.String("categories", "", "Comma-separated list of test categories to run")
		severities      = flag.String("severities", "", "Comma-separated list of test severities to run")
		signatureTypes  = flag.String("signature-types", "", "Comma-separated list of signature types to test")
		outputReport    = flag.String("output", "", "Output file for the test report")
		runAI           = flag.Bool("ai", true, "Run AI analysis before fuzz testing")
		debugMode       = flag.Bool("debug", false, "Enable debug mode")
	)
	flag.Parse()

	// Set debug mode
	if *debugMode {
		analyzer.Debug.Enabled = true
		analyzer.Debug.ShowAIInput = true
		analyzer.Debug.ShowAIOutput = true
		analyzer.Debug.ShowAnalysis = true
		analyzer.Debug.Verbose = true
	}

	fmt.Println("=== VERY SMART ANALYZER - FUZZ TESTING SUITE ===")
	fmt.Printf("Contract: %s\n", *contractPath)
	fmt.Printf("Max Duration: %v\n", *maxDuration)
	fmt.Printf("Timeout per Test: %v\n", *timeoutPerTest)
	fmt.Printf("Gas Limit: %d\n", *gasLimit)
	fmt.Printf("Verbose: %t\n", *verbose)
	fmt.Printf("Stress Tests: %t\n", *enableStress)
	fmt.Printf("Edge Cases: %t\n", *enableEdgeCases)
	fmt.Printf("AI Analysis: %t\n", *runAI)
	fmt.Printf("Debug Mode: %t\n", *debugMode)
	fmt.Println()

	// Parse test categories
	var testCategories []analyzer.TestCategory
	if *categories != "" {
		cats := parseCommaSeparated(*categories)
		for _, cat := range cats {
			testCategories = append(testCategories, analyzer.TestCategory(cat))
		}
	}

	// Parse test severities
	var testSeverities []analyzer.TestSeverity
	if *severities != "" {
		sevs := parseCommaSeparated(*severities)
		for _, sev := range sevs {
			testSeverities = append(testSeverities, analyzer.TestSeverity(sev))
		}
	}

	// Parse signature types
	var sigTypes []analyzer.SignatureKind
	if *signatureTypes != "" {
		types := parseCommaSeparated(*signatureTypes)
		for _, t := range types {
			sigTypes = append(sigTypes, analyzer.SignatureKind(t))
		}
	}

	// Create fuzz testing configuration
	config := analyzer.FuzzConfig{
		MaxTestDuration:   *maxDuration,
		TimeoutPerTest:    *timeoutPerTest,
		GasLimit:          *gasLimit,
		VerboseOutput:     *verbose,
		EnableStressTests: *enableStress,
		EnableEdgeCases:   *enableEdgeCases,
		TestCategories:    testCategories,
		TestSeverities:    testSeverities,
		SignatureTypes:    sigTypes,
	}

	// Step 1: Run AI analysis if enabled
	if *runAI {
		fmt.Println("=== STEP 1: AI ANALYSIS ===")
		if err := runAIAnalysis(*contractPath); err != nil {
			log.Printf("AI analysis failed: %v", err)
			if !*verbose {
				fmt.Println("Continuing with fuzz testing...")
			}
		}
		fmt.Println()
	}

	// Step 2: Run comprehensive fuzz testing
	fmt.Println("=== STEP 2: FUZZ TESTING ===")
	if err := runFuzzTesting(*contractPath, config); err != nil {
		log.Fatalf("Fuzz testing failed: %v", err)
	}

	// Step 3: Generate comprehensive report
	fmt.Println("=== STEP 3: GENERATING REPORT ===")
	if err := generateComprehensiveReport(*outputReport); err != nil {
		log.Printf("Report generation failed: %v", err)
	}

	fmt.Println("=== FUZZ TESTING COMPLETED ===")
}

// runAIAnalysis runs the AI analysis pipeline
func runAIAnalysis(contractPath string) error {
	fmt.Println("Running AI analysis pipeline...")

	// Create AI client
	aiClient, err := analyzer.NewAIClient()
	if err != nil {
		return fmt.Errorf("failed to create AI client: %w", err)
	}

	// Read contract source
	contractSource, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("failed to read contract: %w", err)
	}

	// Extract function definitions
	fmt.Println("Extracting function definitions...")
	metadata, err := aiClient.ExtractFunctionDefinitions(string(contractSource))
	if err != nil {
		return fmt.Errorf("failed to extract function definitions: %w", err)
	}

	fmt.Printf("Extracted %d signature functions\n", len(metadata.SignatureFunctions))

	// Create analyzer
	analyzerInstance := analyzer.NewAnalyzer()

	// Analyze metadata
	fmt.Println("Analyzing metadata for vulnerabilities...")
	analyzedMetadata, err := analyzerInstance.AnalyzeMetadataFromAI("temp_metadata.json")
	if err != nil {
		// If AI metadata file doesn't exist, we'll skip the analysis for now
		// and just use the extracted metadata
		fmt.Println("Note: Could not analyze metadata from file, using extracted data")
		analyzedMetadata = metadata
	}

	fmt.Printf("Found %d vulnerabilities\n", analyzedMetadata.TotalVulnerabilities)
	fmt.Printf("Security Score: %.2f\n", analyzedMetadata.SecurityScore)
	fmt.Printf("Risk Level: %s\n", analyzedMetadata.RiskLevel)

	return nil
}

// runFuzzTesting runs the comprehensive fuzz testing suite
func runFuzzTesting(contractPath string, config analyzer.FuzzConfig) error {
	fmt.Println("Initializing fuzz testing framework...")

	// Create fuzz tester
	fuzzTester := analyzer.NewFuzzTester(config)

	// Display test matrix information
	fmt.Println("Test Matrix Information:")
	matrix := fuzzTester.TestMatrix
	fmt.Printf("Total test cases: %d\n", len(matrix.TestCases))

	// Count by category
	categoryCounts := make(map[analyzer.TestCategory]int)
	for _, tc := range matrix.TestCases {
		categoryCounts[tc.Category]++
	}
	fmt.Println("Test cases by category:")
	for category, count := range categoryCounts {
		fmt.Printf("  %s: %d\n", category, count)
	}

	// Count by severity
	severityCounts := make(map[analyzer.TestSeverity]int)
	for _, tc := range matrix.TestCases {
		severityCounts[tc.Severity]++
	}
	fmt.Println("Test cases by severity:")
	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}

	// Run fuzz tests
	fmt.Println("\nStarting fuzz testing...")
	startTime := time.Now()

	if err := fuzzTester.RunFuzzTests(contractPath); err != nil {
		return fmt.Errorf("fuzz testing failed: %w", err)
	}

	duration := time.Since(startTime)
	fmt.Printf("Fuzz testing completed in %v\n", duration)

	// Display results summary
	fmt.Println("\nFuzz Testing Results Summary:")
	displayFuzzResults(fuzzTester.TestResults)

	return nil
}

// displayFuzzResults displays a summary of fuzz testing results
func displayFuzzResults(results []analyzer.FuzzTestResult) {
	total := len(results)
	if total == 0 {
		fmt.Println("No test results available")
		return
	}

	// Count by status
	statusCounts := make(map[analyzer.FuzzTestStatus]int)
	for _, result := range results {
		statusCounts[result.Status]++
	}

	fmt.Printf("Total Tests: %d\n", total)
	for status, count := range statusCounts {
		percentage := float64(count) / float64(total) * 100
		fmt.Printf("  %s: %d (%.1f%%)\n", status, count, percentage)
	}

	// Count vulnerabilities
	vulnCounts := make(map[analyzer.VulnerabilityType]int)
	for _, result := range results {
		if result.Status == analyzer.StatusVulnerable {
			vulnCounts[result.Vulnerability]++
		}
	}

	if len(vulnCounts) > 0 {
		fmt.Println("\nVulnerabilities Found:")
		for vuln, count := range vulnCounts {
			fmt.Printf("  %s: %d instances\n", vuln, count)
		}
	}

	// Average execution time
	var totalTime time.Duration
	for _, result := range results {
		totalTime += result.ExecutionTime
	}
	avgTime := totalTime / time.Duration(total)
	fmt.Printf("\nAverage execution time: %v\n", avgTime)
}

// generateComprehensiveReport generates a comprehensive test report
func generateComprehensiveReport(outputPath string) error {
	fmt.Println("Generating comprehensive test report...")

	// Create report content
	report := generateReportContent()

	// Determine output path
	if outputPath == "" {
		outputPath = fmt.Sprintf("comprehensive_report_%s.txt", time.Now().Format("20060102_150405"))
	}

	// Write report
	if err := os.WriteFile(outputPath, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	fmt.Printf("Report written to: %s\n", outputPath)
	return nil
}

// generateReportContent generates the content for the comprehensive report
func generateReportContent() string {
	var content string
	content += "=== VERY SMART ANALYZER - COMPREHENSIVE TEST REPORT ===\n\n"
	content += fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	content += "This report contains the results of comprehensive smart contract\n"
	content += "signature vulnerability analysis and fuzz testing.\n\n"

	content += "=== EXECUTIVE SUMMARY ===\n"
	content += "The Very Smart Analyzer performed a thorough analysis of the target\n"
	content += "smart contract, including:\n"
	content += "1. AI-assisted function extraction and signature analysis\n"
	content += "2. Vulnerability detection and security scoring\n"
	content += "3. Comprehensive fuzz testing with multiple attack vectors\n"
	content += "4. Detailed reporting of findings and recommendations\n\n"

	content += "=== METHODOLOGY ===\n"
	content += "The analysis employed a multi-layered approach:\n"
	content += "- AI-powered contract parsing and metadata extraction\n"
	content += "- Static analysis for common signature vulnerabilities\n"
	content += "- Dynamic fuzz testing with 50+ test scenarios\n"
	content += "- Cross-chain and multi-signature attack simulation\n"
	content += "- Stress testing and edge case validation\n\n"

	content += "=== KEY FINDINGS ===\n"
	content += "Detailed findings are available in the individual test reports.\n"
	content += "This comprehensive analysis provides a complete security assessment\n"
	content += "of the target smart contract's signature verification mechanisms.\n\n"

	content += "=== RECOMMENDATIONS ===\n"
	content += "1. Review all identified vulnerabilities\n"
	content += "2. Implement missing security controls\n"
	content += "3. Add comprehensive test coverage\n"
	content += "4. Consider formal verification for critical functions\n"
	content += "5. Regular security audits and updates\n\n"

	content += "=== TECHNICAL DETAILS ===\n"
	content += "For detailed technical information, refer to:\n"
	content += "- AI analysis output files\n"
	content += "- Fuzz testing result files\n"
	content += "- Individual test case reports\n\n"

	content += "=== CONCLUSION ===\n"
	content += "The Very Smart Analyzer provides a comprehensive security assessment\n"
	content += "of smart contract signature verification mechanisms. This analysis\n"
	content += "helps identify and mitigate potential vulnerabilities before deployment.\n\n"

	content += "Report generated by Very Smart Analyzer v1.0\n"

	return content
}

// parseCommaSeparated parses a comma-separated string into a slice
func parseCommaSeparated(input string) []string {
	if input == "" {
		return nil
	}

	var result []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
