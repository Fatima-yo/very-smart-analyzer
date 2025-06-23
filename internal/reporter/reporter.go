package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Report represents a comprehensive analysis report
type Report struct {
	Timestamp       time.Time             `json:"timestamp"`
	ContractPath    string                `json:"contract_path"`
	Analysis        AnalysisReport        `json:"analysis"`
	FuzzTests       FuzzTestReport        `json:"fuzz_tests"`
	Vulnerabilities []VulnerabilityReport `json:"vulnerabilities"`
	Summary         SummaryReport         `json:"summary"`
}

// AnalysisReport contains contract analysis results
type AnalysisReport struct {
	SignatureFunctions int      `json:"signature_functions"`
	MissingNonce       []string `json:"missing_nonce"`
	MissingTimestamp   []string `json:"missing_timestamp"`
	MissingDeadline    []string `json:"missing_deadline"`
	MissingDomain      []string `json:"missing_domain"`
	Warnings           []string `json:"warnings"`
}

// FuzzTestReport contains fuzz testing results
type FuzzTestReport struct {
	TotalTests     int                    `json:"total_tests"`
	PassedTests    int                    `json:"passed_tests"`
	FailedTests    int                    `json:"failed_tests"`
	TestResults    []FuzzTestResult       `json:"test_results"`
	TestCategories map[string]TestSummary `json:"test_categories"`
}

// FuzzTestResult represents a single fuzz test result
type FuzzTestResult struct {
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	Success       bool          `json:"success"`
	Expected      bool          `json:"expected"`
	Error         string        `json:"error,omitempty"`
	GasUsed       uint64        `json:"gas_used,omitempty"`
	ExecutionTime time.Duration `json:"execution_time,omitempty"`
}

// TestSummary summarizes test results by category
type TestSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// VulnerabilityReport represents a discovered vulnerability
type VulnerabilityReport struct {
	Severity       string `json:"severity"`
	Type           string `json:"type"`
	Function       string `json:"function"`
	Description    string `json:"description"`
	Impact         string `json:"impact"`
	Recommendation string `json:"recommendation"`
	Evidence       string `json:"evidence,omitempty"`
}

// SummaryReport provides an executive summary
type SummaryReport struct {
	RiskLevel      string `json:"risk_level"`
	CriticalIssues int    `json:"critical_issues"`
	HighIssues     int    `json:"high_issues"`
	MediumIssues   int    `json:"medium_issues"`
	LowIssues      int    `json:"low_issues"`
	OverallScore   int    `json:"overall_score"`
}

// Reporter handles report generation and output
type Reporter struct {
	outputDir string
}

// NewReporter creates a new reporter instance
func NewReporter(outputDir string) *Reporter {
	return &Reporter{
		outputDir: outputDir,
	}
}

// GenerateReport generates a comprehensive report
func (r *Reporter) GenerateReport(contractPath string, analysis *AnalysisReport, fuzzTests *FuzzTestReport, vulnerabilities []VulnerabilityReport) (*Report, error) {
	report := &Report{
		Timestamp:       time.Now(),
		ContractPath:    contractPath,
		Analysis:        *analysis,
		FuzzTests:       *fuzzTests,
		Vulnerabilities: vulnerabilities,
		Summary:         r.generateSummary(vulnerabilities, fuzzTests),
	}

	return report, nil
}

// WriteReport writes the report to file
func (r *Reporter) WriteReport(report *Report, filename string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write JSON report
	jsonPath := fmt.Sprintf("%s/%s.json", r.outputDir, filename)
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	// Write human-readable report
	textPath := fmt.Sprintf("%s/%s.txt", r.outputDir, filename)
	textContent := r.generateTextReport(report)
	if err := os.WriteFile(textPath, []byte(textContent), 0644); err != nil {
		return fmt.Errorf("failed to write text report: %w", err)
	}

	fmt.Printf("Reports written to:\n")
	fmt.Printf("  JSON: %s\n", jsonPath)
	fmt.Printf("  Text: %s\n", textPath)

	return nil
}

// generateSummary generates an executive summary
func (r *Reporter) generateSummary(vulnerabilities []VulnerabilityReport, fuzzTests *FuzzTestReport) SummaryReport {
	summary := SummaryReport{
		CriticalIssues: 0,
		HighIssues:     0,
		MediumIssues:   0,
		LowIssues:      0,
	}

	// Count vulnerabilities by severity
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		case "low":
			summary.LowIssues++
		}
	}

	// Calculate risk level
	if summary.CriticalIssues > 0 {
		summary.RiskLevel = "CRITICAL"
		summary.OverallScore = 0
	} else if summary.HighIssues > 0 {
		summary.RiskLevel = "HIGH"
		summary.OverallScore = 25
	} else if summary.MediumIssues > 0 {
		summary.RiskLevel = "MEDIUM"
		summary.OverallScore = 50
	} else if summary.LowIssues > 0 {
		summary.RiskLevel = "LOW"
		summary.OverallScore = 75
	} else {
		summary.RiskLevel = "SAFE"
		summary.OverallScore = 100
	}

	return summary
}

// generateTextReport generates a human-readable text report
func (r *Reporter) generateTextReport(report *Report) string {
	content := fmt.Sprintf(`SMART CONTRACT SECURITY ANALYSIS REPORT
==================================================

Contract: %s
Analysis Date: %s
Risk Level: %s
Overall Score: %d/100

EXECUTIVE SUMMARY
================
Critical Issues: %d
High Issues: %d
Medium Issues: %d
Low Issues: %d

CONTRACT ANALYSIS
================
Signature Functions Found: %d

Missing Security Controls:
- Nonce: %d functions
- Timestamp: %d functions
- Deadline: %d functions
- Domain Separator: %d functions

Warnings:
`,
		report.ContractPath,
		report.Timestamp.Format("2006-01-02 15:04:05"),
		report.Summary.RiskLevel,
		report.Summary.OverallScore,
		report.Summary.CriticalIssues,
		report.Summary.HighIssues,
		report.Summary.MediumIssues,
		report.Summary.LowIssues,
		report.Analysis.SignatureFunctions,
		len(report.Analysis.MissingNonce),
		len(report.Analysis.MissingTimestamp),
		len(report.Analysis.MissingDeadline),
		len(report.Analysis.MissingDomain),
	)

	for _, warning := range report.Analysis.Warnings {
		content += fmt.Sprintf("- %s\n", warning)
	}

	content += fmt.Sprintf(`
FUZZ TESTING RESULTS
===================
Total Tests: %d
Passed: %d
Failed: %d

Test Categories:
`,
		report.FuzzTests.TotalTests,
		report.FuzzTests.PassedTests,
		report.FuzzTests.FailedTests,
	)

	for category, summary := range report.FuzzTests.TestCategories {
		content += fmt.Sprintf("- %s: %d/%d passed\n", category, summary.Passed, summary.Total)
	}

	content += "\nVULNERABILITIES\n==============\n"
	for i, vuln := range report.Vulnerabilities {
		content += fmt.Sprintf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.Type)
		content += fmt.Sprintf("   Function: %s\n", vuln.Function)
		content += fmt.Sprintf("   Description: %s\n", vuln.Description)
		content += fmt.Sprintf("   Impact: %s\n", vuln.Impact)
		content += fmt.Sprintf("   Recommendation: %s\n", vuln.Recommendation)
		if vuln.Evidence != "" {
			content += fmt.Sprintf("   Evidence: %s\n", vuln.Evidence)
		}
		content += "\n"
	}

	content += "\nRECOMMENDATIONS\n==============\n"
	if report.Summary.CriticalIssues > 0 {
		content += "CRITICAL: Address all critical vulnerabilities immediately before deployment.\n"
	}
	if report.Summary.HighIssues > 0 {
		content += "HIGH: Fix high-severity issues before production deployment.\n"
	}
	if len(report.Analysis.MissingNonce) > 0 {
		content += "Add nonce protection to prevent replay attacks.\n"
	}
	if len(report.Analysis.MissingDeadline) > 0 {
		content += "Add deadline protection to prevent stale signature attacks.\n"
	}
	if report.FuzzTests.FailedTests > 0 {
		content += "Review failed fuzz tests and improve signature validation.\n"
	}

	return content
}

// PrintSummary prints a brief summary to stdout
func (r *Reporter) PrintSummary(report *Report) {
	fmt.Printf("\n=== ANALYSIS SUMMARY ===\n")
	fmt.Printf("Contract: %s\n", report.ContractPath)
	fmt.Printf("Risk Level: %s (Score: %d/100)\n", report.Summary.RiskLevel, report.Summary.OverallScore)
	fmt.Printf("Signature Functions: %d\n", report.Analysis.SignatureFunctions)
	fmt.Printf("Vulnerabilities: %d critical, %d high, %d medium, %d low\n",
		report.Summary.CriticalIssues, report.Summary.HighIssues,
		report.Summary.MediumIssues, report.Summary.LowIssues)
	fmt.Printf("Fuzz Tests: %d total, %d passed, %d failed\n",
		report.FuzzTests.TotalTests, report.FuzzTests.PassedTests, report.FuzzTests.FailedTests)
	fmt.Printf("========================\n\n")
}
