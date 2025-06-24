package main

import (
	"fmt"
	"log"

	"very_smart_analyzer/internal/analyzer"
)

func main() {
	// Initialize debug mode
	analyzer.InitDebug()

	fmt.Println("Testing AI Extraction and Go Analysis Pipeline")
	fmt.Println("==============================================")

	if analyzer.Debug.Enabled {
		fmt.Printf("🔍 Debug mode enabled: %+v\n", analyzer.Debug)
	}

	// Step 1: Test AI extraction
	fmt.Println("\n1. Testing AI extraction...")
	analyzer.DebugPrintStep("PIPELINE", "Starting AI extraction test")

	err := analyzer.TestAIClient()
	if err != nil {
		analyzer.DebugPrintError("PIPELINE_AI_EXTRACTION", err)
		log.Fatalf("AI extraction failed: %v", err)
	}
	fmt.Println("✅ AI extraction completed successfully")
	analyzer.DebugPrintStep("PIPELINE", "AI extraction test completed successfully")

	// Step 2: Test Go security analysis
	fmt.Println("\n2. Testing Go security analysis...")
	analyzer.DebugPrintStep("PIPELINE", "Starting Go security analysis test")

	analyzerInstance := analyzer.NewAnalyzer()
	analyzer.DebugPrintStep("PIPELINE", "Analyzer instance created")

	// Read the extracted metadata
	analyzer.DebugPrintStep("PIPELINE", "Reading extracted metadata from file")
	metadata, err := analyzerInstance.AnalyzeMetadataFromAI("extracted_metadata.json")
	if err != nil {
		analyzer.DebugPrintError("PIPELINE_SECURITY_ANALYSIS", err)
		log.Fatalf("Security analysis failed: %v", err)
	}
	analyzer.DebugPrintStep("PIPELINE", "Security analysis completed successfully")

	// Print security analysis results
	fmt.Printf("✅ Security analysis completed\n")
	fmt.Printf("   Total functions analyzed: %d\n", len(metadata.SignatureFunctions))
	fmt.Printf("   Total vulnerabilities found: %d\n", metadata.TotalVulnerabilities)
	fmt.Printf("   Security score: %.2f\n", metadata.SecurityScore)
	fmt.Printf("   Risk level: %s\n", metadata.RiskLevel)

	analyzer.DebugPrintStep("PIPELINE", "Analysis results - Functions: %d, Vulnerabilities: %d, Score: %.2f, Risk: %s",
		len(metadata.SignatureFunctions), metadata.TotalVulnerabilities, metadata.SecurityScore, metadata.RiskLevel)

	// Print detailed vulnerability information
	fmt.Println("\n3. Detailed vulnerability analysis:")
	analyzer.DebugPrintStep("PIPELINE", "Starting detailed vulnerability analysis")

	for i, fn := range metadata.SignatureFunctions {
		analyzer.DebugPrintStep("PIPELINE", "Analyzing function %d/%d: %s", i+1, len(metadata.SignatureFunctions), fn.FunctionName)

		fmt.Printf("\nFunction: %s\n", fn.FunctionName)
		fmt.Printf("  Signature Type: %s\n", fn.SignatureType.Kind)
		fmt.Printf("  Vulnerabilities: %d\n", len(fn.Vulnerabilities))

		if len(fn.Vulnerabilities) > 0 {
			fmt.Printf("  Issues found:\n")
			for _, vuln := range fn.Vulnerabilities {
				fmt.Printf("    - %s\n", vuln)
			}
		}

		// Print security checks
		fmt.Printf("  Security Checks:\n")
		fmt.Printf("    - Replay Protection: %t\n", fn.SecurityChecks.ReplayProtection)
		fmt.Printf("    - Deadline Check: %t\n", fn.SecurityChecks.DeadlineCheck)
		fmt.Printf("    - Nonce Check: %t\n", fn.SecurityChecks.NonceCheck)
		fmt.Printf("    - Chain ID Check: %t\n", fn.SecurityChecks.ChainIDCheck)
		fmt.Printf("    - Domain Validation: %t\n", fn.SecurityChecks.DomainValidation)
		fmt.Printf("    - Signer Validation: %t\n", fn.SecurityChecks.SignerValidation)

		analyzer.DebugPrintStep("PIPELINE", "Function %s analysis completed", fn.FunctionName)
	}

	// Generate security report
	fmt.Println("\n4. Generating security report...")
	analyzer.DebugPrintStep("PIPELINE", "Generating security report")

	report := analyzerInstance.GenerateSecurityReport(metadata)
	fmt.Println(report)

	analyzer.DebugPrintStep("PIPELINE", "Security report generated")

	// Step 5: Generate test cases
	fmt.Println("\n5. Generating test cases...")
	analyzer.DebugPrintStep("PIPELINE", "Starting test case generation")

	testGenerator := analyzer.NewTestGenerator()
	analyzer.DebugPrintStep("PIPELINE", "Test generator created")

	totalTestCases := 0
	totalVulnerableTests := 0

	for i, fn := range metadata.SignatureFunctions {
		analyzer.DebugPrintStep("PIPELINE", "Generating tests for function %d/%d: %s", i+1, len(metadata.SignatureFunctions), fn.FunctionName)

		testSuite := testGenerator.GenerateTestCases(&fn)
		totalTestCases += testSuite.TotalTests
		totalVulnerableTests += testSuite.VulnerableTests

		fmt.Printf("\nFunction: %s\n", fn.FunctionName)
		fmt.Printf("  Signature Type: %s\n", testSuite.SignatureType)
		fmt.Printf("  Test Cases Generated: %d\n", testSuite.TotalTests)
		fmt.Printf("  Vulnerable Test Cases: %d\n", testSuite.VulnerableTests)

		// Show some example test cases
		if len(testSuite.TestCases) > 0 {
			fmt.Printf("  Example Tests:\n")
			for j, tc := range testSuite.TestCases {
				if j >= 3 { // Show only first 3 tests
					break
				}
				fmt.Printf("    - %s (%s): %s\n", tc.Name, tc.Severity, tc.Description)
			}
		}

		analyzer.DebugPrintStep("PIPELINE", "Test generation completed for function %s", fn.FunctionName)
	}

	// Generate test report
	fmt.Printf("\nTest Generation Summary:\n")
	fmt.Printf("  Total Functions: %d\n", len(metadata.SignatureFunctions))
	fmt.Printf("  Total Test Cases: %d\n", totalTestCases)
	fmt.Printf("  Total Vulnerable Tests: %d\n", totalVulnerableTests)
	fmt.Printf("  Average Tests per Function: %.1f\n", float64(totalTestCases)/float64(len(metadata.SignatureFunctions)))

	// Generate detailed test report
	testReport := testGenerator.GenerateTestReport()
	fmt.Println("\n" + testReport)

	analyzer.DebugPrintStep("PIPELINE", "Test generation completed")

	fmt.Println("\n✅ Pipeline test completed successfully!")
	analyzer.DebugPrintStep("PIPELINE", "Pipeline test completed successfully")
}
