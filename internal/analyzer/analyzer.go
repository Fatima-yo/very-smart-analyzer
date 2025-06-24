package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SignatureKind represents the type of signature verification
type SignatureKind string

const (
	EIP712         SignatureKind = "EIP712"
	ETHSign        SignatureKind = "ETH_SIGN"
	EIP191Personal SignatureKind = "EIP191_PERSONAL_SIGN"
	EIP2612        SignatureKind = "EIP2612"
	EIP1271        SignatureKind = "EIP1271"
	CustomSig      SignatureKind = "CUSTOM"
)

// ValidationType represents how a field is validated
type ValidationType string

const (
	ValidationExplicit ValidationType = "explicit"
	ValidationImplicit ValidationType = "implicit"
	ValidationNone     ValidationType = "none"
	ValidationMissing  ValidationType = "missing"
)

// SourceType represents where a field comes from
type SourceType string

const (
	SourceParameter    SourceType = "parameter"
	SourceStructField  SourceType = "structField"
	SourceArrayElement SourceType = "arrayElement"
	SourceMappingKey   SourceType = "mappingKey"
	SourceMappingValue SourceType = "mappingValue"
	SourceStateVar     SourceType = "stateVariable"
	SourceConstant     SourceType = "constant"
)

// VulnerabilityType represents different types of security vulnerabilities
type VulnerabilityType string

const (
	VulnMissingNonce            VulnerabilityType = "MISSING_NONCE"
	VulnMissingDeadline         VulnerabilityType = "MISSING_DEADLINE"
	VulnMissingTimestamp        VulnerabilityType = "MISSING_TIMESTAMP"
	VulnMissingChainID          VulnerabilityType = "MISSING_CHAIN_ID"
	VulnMissingDomainSeparator  VulnerabilityType = "MISSING_DOMAIN_SEPARATOR"
	VulnWeakSignerValidation    VulnerabilityType = "WEAK_SIGNER_VALIDATION"
	VulnNoThresholdCheck        VulnerabilityType = "NO_THRESHOLD_CHECK"
	VulnUnsafeSignatureRecovery VulnerabilityType = "UNSAFE_SIGNATURE_RECOVERY"
	VulnMissingVersion          VulnerabilityType = "MISSING_VERSION"
	VulnInsufficientEntropy     VulnerabilityType = "INSUFFICIENT_ENTROPY"
)

// SignatureField represents a field in the signature data
type SignatureField struct {
	Name             string     `json:"name"`
	SolType          string     `json:"solType"`
	Source           SourceType `json:"source,omitempty"`
	SignerRole       string     `json:"signerRole,omitempty"`
	ParentStruct     string     `json:"parentStruct,omitempty"`
	ArrayIndex       string     `json:"arrayIndex,omitempty"`
	MappingKey       string     `json:"mappingKey,omitempty"`
	IsNested         bool       `json:"isNested,omitempty"`
	NestedStructName string     `json:"nestedStructName,omitempty"`
}

// ControlField represents a security-critical control field
type ControlField struct {
	Name           string         `json:"name"`
	SolType        string         `json:"solType"`
	Source         SourceType     `json:"source"`
	ValidationType ValidationType `json:"validationType"`
}

// SignatureFieldsStruct describes the structure of signed data
type SignatureFieldsStruct struct {
	Structured bool             `json:"structured"`
	StructName string           `json:"structName,omitempty"`
	Fields     []SignatureField `json:"fields"`
}

// SecurityChecks represents security validation checks
type SecurityChecks struct {
	ReplayProtection    bool `json:"replayProtection"`
	DeadlineCheck       bool `json:"deadlineCheck"`
	NonceCheck          bool `json:"nonceCheck"`
	ChainIDCheck        bool `json:"chainIdCheck"`
	DomainValidation    bool `json:"domainValidation"`
	SignerValidation    bool `json:"signerValidation"`
	ThresholdValidation bool `json:"thresholdValidation"`
}

// SignatureComplexity represents the complexity of the signature scheme
type SignatureComplexity struct {
	HasNestedStructs bool `json:"hasNestedStructs"`
	HasArrays        bool `json:"hasArrays"`
	HasMappings      bool `json:"hasMappings"`
	StructDepth      int  `json:"structDepth"`
	ArrayLength      int  `json:"arrayLength"`
	TotalFields      int  `json:"totalFields"`
}

// SignatureType describes the signature scheme used
type SignatureType struct {
	Kind        SignatureKind `json:"kind"`
	Description string        `json:"description"`
}

// FunctionContext represents function metadata
type FunctionContext struct {
	Visibility      string   `json:"visibility"`
	StateMutability string   `json:"stateMutability"`
	AccessControl   []string `json:"accessControl"`
}

// SignatureFunction represents a function that uses signature verification
type SignatureFunction struct {
	FunctionName     string          `json:"functionName"`
	FunctionSelector string          `json:"functionSelector"`
	SignatureType    SignatureType   `json:"signatureType"`
	FunctionContext  FunctionContext `json:"functionContext"`

	// Control fields with enhanced metadata (only if present in contract)
	Nonce           *ControlField `json:"nonce,omitempty"`
	Timestamp       *ControlField `json:"timestamp,omitempty"`
	Deadline        *ControlField `json:"deadline,omitempty"`
	ChainID         *ControlField `json:"chainId,omitempty"`
	Version         *ControlField `json:"version,omitempty"`
	DomainSeparator *ControlField `json:"domainSeparator,omitempty"`
	Salt            *ControlField `json:"salt,omitempty"`

	// Signature data
	SignatureFields SignatureFieldsStruct `json:"signatureFields"`
	Signature       []SignatureField      `json:"signature,omitempty"`
	V               []SignatureField      `json:"v,omitempty"`
	R               []SignatureField      `json:"r,omitempty"`
	S               []SignatureField      `json:"s,omitempty"`

	// Signature complexity (structural information)
	SignatureComplexity SignatureComplexity `json:"signatureComplexity"`

	// Security analysis fields (generated by Go, not AI)
	SecurityChecks  SecurityChecks      `json:"securityChecks,omitempty"`
	Vulnerabilities []VulnerabilityType `json:"vulnerabilities,omitempty"`
}

// SignatureMetadata contains all signature functions found in a contract
type SignatureMetadata struct {
	SignatureFunctions   []SignatureFunction `json:"signatureFunctions"`
	TotalVulnerabilities int                 `json:"totalVulnerabilities"`
	SecurityScore        float64             `json:"securityScore"`
	RiskLevel            string              `json:"riskLevel"`
}

// Analyzer handles contract analysis
type Analyzer struct {
	// TODO: Add fields for contract parsing, AI integration, etc.
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer() *Analyzer {
	DebugPrintStep("ANALYZER_INIT", "Creating new analyzer instance")
	return &Analyzer{}
}

// AnalyzeContract analyzes a Solidity contract and generates metadata
func (a *Analyzer) AnalyzeContract(contractPath, outputPath string) error {
	// Read the contract file
	contractData, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("failed to read contract file: %w", err)
	}

	// TODO: Implement actual contract parsing logic
	// For now, we'll create a placeholder implementation
	metadata := a.parseContract(string(contractData))

	// Write the metadata to output file
	outputData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Analysis complete. Results written to: %s\n", outputPath)
	return nil
}

// parseContract parses the contract source and extracts signature functions
func (a *Analyzer) parseContract(source string) SignatureMetadata {
	// TODO: Implement actual parsing logic
	// This is a placeholder that will be replaced with real parsing

	metadata := SignatureMetadata{
		SignatureFunctions: []SignatureFunction{},
	}

	// Basic heuristic: look for common signature verification patterns
	lines := strings.Split(source, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for function definitions that might use signatures
		if strings.Contains(line, "function") &&
			(strings.Contains(line, "bytes") ||
				strings.Contains(line, "uint8") ||
				strings.Contains(line, "bytes32")) {

			// TODO: Extract function details and signature information
			// For now, we'll add a placeholder
			if strings.Contains(line, "sig") || strings.Contains(line, "sign") {
				// This is a very basic heuristic - needs proper parsing
				fmt.Printf("Found potential signature function: %s\n", line)
			}
		}
	}

	return metadata
}

// AnalyzeMetadataFromAI analyzes metadata extracted by AI
func (a *Analyzer) AnalyzeMetadataFromAI(metadataPath string) (*SignatureMetadata, error) {
	DebugPrintStep("ANALYZE_METADATA", "Starting metadata analysis from AI output")
	DebugPrintStep("ANALYZE_METADATA", "Reading metadata from: %s", metadataPath)

	// Read the metadata file
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		DebugPrintError("METADATA_READ", err)
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}
	DebugPrintStep("ANALYZE_METADATA", "Metadata file read (size: %d bytes)", len(metadataData))

	// Parse the metadata
	var metadata SignatureMetadata
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		DebugPrintError("METADATA_PARSE", err)
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	DebugPrintStep("ANALYZE_METADATA", "Metadata parsed successfully")
	DebugPrintStep("ANALYZE_METADATA", "Found %d signature functions to analyze", len(metadata.SignatureFunctions))

	// Perform security analysis
	DebugPrintStep("ANALYZE_METADATA", "Starting security analysis...")
	a.performSecurityAnalysis(&metadata)
	DebugPrintStep("ANALYZE_METADATA", "Security analysis completed")

	// Calculate security score
	DebugPrintStep("ANALYZE_METADATA", "Calculating security score...")
	metadata.SecurityScore = a.calculateSecurityScore(&metadata)
	DebugPrintStep("ANALYZE_METADATA", "Security score calculated: %.2f", metadata.SecurityScore)

	// Determine risk level
	metadata.RiskLevel = a.determineRiskLevel(metadata.SecurityScore)
	DebugPrintStep("ANALYZE_METADATA", "Risk level determined: %s", metadata.RiskLevel)

	DebugPrintStep("ANALYZE_METADATA", "Metadata analysis completed successfully")
	return &metadata, nil
}

// performSecurityAnalysis performs security analysis on the metadata
func (a *Analyzer) performSecurityAnalysis(metadata *SignatureMetadata) {
	DebugPrintStep("SECURITY_ANALYSIS", "Starting security analysis on %d functions", len(metadata.SignatureFunctions))

	totalVulns := 0
	for i, fn := range metadata.SignatureFunctions {
		DebugPrintStep("SECURITY_ANALYSIS", "Analyzing function %d/%d: %s", i+1, len(metadata.SignatureFunctions), fn.FunctionName)

		// Analyze vulnerabilities
		vulns := a.analyzeFunctionVulnerabilities(&fn)
		fn.Vulnerabilities = vulns
		totalVulns += len(vulns)
		DebugPrintStep("SECURITY_ANALYSIS", "Function %s: found %d vulnerabilities", fn.FunctionName, len(vulns))

		// Update security checks
		a.updateSecurityChecks(&fn)
		DebugPrintStep("SECURITY_ANALYSIS", "Security checks updated for function %s", fn.FunctionName)

		// Calculate signature complexity
		a.calculateSignatureComplexity(&fn)
		DebugPrintStep("SECURITY_ANALYSIS", "Signature complexity calculated for function %s", fn.FunctionName)

		// Update the function in the metadata
		metadata.SignatureFunctions[i] = fn
	}

	metadata.TotalVulnerabilities = totalVulns
	DebugPrintStep("SECURITY_ANALYSIS", "Security analysis completed. Total vulnerabilities: %d", totalVulns)
}

// analyzeFunctionVulnerabilities analyzes a single function for vulnerabilities
func (a *Analyzer) analyzeFunctionVulnerabilities(fn *SignatureFunction) []VulnerabilityType {
	DebugPrintStep("VULNERABILITY_ANALYSIS", "Analyzing vulnerabilities for function: %s", fn.FunctionName)

	var vulnerabilities []VulnerabilityType

	// Check for missing nonce
	if fn.Nonce == nil {
		DebugPrintAnalysis("Function %s: Missing nonce field", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingNonce)
	} else if fn.Nonce.ValidationType == ValidationMissing {
		DebugPrintAnalysis("Function %s: Nonce present but not validated", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingNonce)
	}

	// Check for missing deadline
	if fn.Deadline == nil {
		DebugPrintAnalysis("Function %s: Missing deadline field", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingDeadline)
	} else if fn.Deadline.ValidationType == ValidationMissing {
		DebugPrintAnalysis("Function %s: Deadline present but not validated", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingDeadline)
	}

	// Check for missing timestamp
	if fn.Timestamp == nil {
		DebugPrintAnalysis("Function %s: Missing timestamp field", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingTimestamp)
	}

	// Check for missing chain ID
	if fn.ChainID == nil {
		DebugPrintAnalysis("Function %s: Missing chain ID field", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingChainID)
	}

	// Check for missing domain separator
	if fn.DomainSeparator == nil {
		DebugPrintAnalysis("Function %s: Missing domain separator", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnMissingDomainSeparator)
	}

	// Check for weak signer validation
	if !a.hasStrongSignerValidation(fn) {
		DebugPrintAnalysis("Function %s: Weak signer validation", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnWeakSignerValidation)
	}

	// Check for unsafe signature recovery
	if a.hasUnsafeSignatureRecovery(fn) {
		DebugPrintAnalysis("Function %s: Unsafe signature recovery", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnUnsafeSignatureRecovery)
	}

	// Check for insufficient entropy
	if a.hasInsufficientEntropy(fn) {
		DebugPrintAnalysis("Function %s: Insufficient entropy", fn.FunctionName)
		vulnerabilities = append(vulnerabilities, VulnInsufficientEntropy)
	}

	DebugPrintStep("VULNERABILITY_ANALYSIS", "Function %s: Found %d vulnerabilities", fn.FunctionName, len(vulnerabilities))
	return vulnerabilities
}

// updateSecurityChecks updates the security checks for a function
func (a *Analyzer) updateSecurityChecks(fn *SignatureFunction) {
	DebugPrintStep("SECURITY_CHECKS", "Updating security checks for function: %s", fn.FunctionName)

	// Check for replay protection (nonce validation)
	fn.SecurityChecks.ReplayProtection = fn.Nonce != nil && fn.Nonce.ValidationType == ValidationExplicit
	DebugPrintAnalysis("Function %s: Replay protection = %t", fn.FunctionName, fn.SecurityChecks.ReplayProtection)

	// Check for deadline validation
	fn.SecurityChecks.DeadlineCheck = fn.Deadline != nil && fn.Deadline.ValidationType == ValidationExplicit
	DebugPrintAnalysis("Function %s: Deadline check = %t", fn.FunctionName, fn.SecurityChecks.DeadlineCheck)

	// Check for nonce validation
	fn.SecurityChecks.NonceCheck = fn.Nonce != nil && fn.Nonce.ValidationType == ValidationExplicit
	DebugPrintAnalysis("Function %s: Nonce check = %t", fn.FunctionName, fn.SecurityChecks.NonceCheck)

	// Check for chain ID validation
	fn.SecurityChecks.ChainIDCheck = fn.ChainID != nil && fn.ChainID.ValidationType == ValidationExplicit
	DebugPrintAnalysis("Function %s: Chain ID check = %t", fn.FunctionName, fn.SecurityChecks.ChainIDCheck)

	// Check for domain validation
	fn.SecurityChecks.DomainValidation = fn.DomainSeparator != nil && fn.DomainSeparator.ValidationType == ValidationExplicit
	DebugPrintAnalysis("Function %s: Domain validation = %t", fn.FunctionName, fn.SecurityChecks.DomainValidation)

	// Check for signer validation
	fn.SecurityChecks.SignerValidation = a.hasStrongSignerValidation(fn)
	DebugPrintAnalysis("Function %s: Signer validation = %t", fn.FunctionName, fn.SecurityChecks.SignerValidation)

	// Check for threshold validation
	fn.SecurityChecks.ThresholdValidation = a.hasThresholdValidation(fn)
	DebugPrintAnalysis("Function %s: Threshold validation = %t", fn.FunctionName, fn.SecurityChecks.ThresholdValidation)

	DebugPrintStep("SECURITY_CHECKS", "Security checks updated for function: %s", fn.FunctionName)
}

// calculateSignatureComplexity calculates the complexity metrics for a function
func (a *Analyzer) calculateSignatureComplexity(fn *SignatureFunction) {
	DebugPrintStep("COMPLEXITY_CALC", "Calculating signature complexity for function: %s", fn.FunctionName)

	fn.SignatureComplexity.HasNestedStructs = a.hasNestedStructs(fn)
	fn.SignatureComplexity.HasArrays = a.hasArrays(fn)
	fn.SignatureComplexity.HasMappings = a.hasMappings(fn)
	fn.SignatureComplexity.StructDepth = a.calculateStructDepth(fn)
	fn.SignatureComplexity.ArrayLength = a.calculateArrayLength(fn)
	fn.SignatureComplexity.TotalFields = a.calculateTotalFields(fn)

	DebugPrintAnalysis("Function %s: Complexity - NestedStructs=%t, Arrays=%t, Mappings=%t, Depth=%d, ArrayLength=%d, TotalFields=%d",
		fn.FunctionName,
		fn.SignatureComplexity.HasNestedStructs,
		fn.SignatureComplexity.HasArrays,
		fn.SignatureComplexity.HasMappings,
		fn.SignatureComplexity.StructDepth,
		fn.SignatureComplexity.ArrayLength,
		fn.SignatureComplexity.TotalFields)

	DebugPrintStep("COMPLEXITY_CALC", "Signature complexity calculated for function: %s", fn.FunctionName)
}

// Helper methods for complexity analysis
func (a *Analyzer) hasNestedStructs(fn *SignatureFunction) bool {
	for _, field := range fn.SignatureFields.Fields {
		if field.Name == "isNested" && field.SolType == "bool" {
			return true
		}
	}
	return false
}

func (a *Analyzer) hasArrays(fn *SignatureFunction) bool {
	return len(fn.Signature) > 0 || len(fn.V) > 0 || len(fn.R) > 0 || len(fn.S) > 0
}

func (a *Analyzer) hasMappings(fn *SignatureFunction) bool {
	for _, field := range fn.SignatureFields.Fields {
		if strings.Contains(field.SolType, "mapping") {
			return true
		}
	}
	return false
}

func (a *Analyzer) calculateStructDepth(fn *SignatureFunction) int {
	// TODO: Implement proper struct depth calculation
	return 1
}

func (a *Analyzer) calculateArrayLength(fn *SignatureFunction) int {
	return len(fn.Signature) + len(fn.V) + len(fn.R) + len(fn.S)
}

func (a *Analyzer) calculateTotalFields(fn *SignatureFunction) int {
	return len(fn.SignatureFields.Fields) + len(fn.Signature) + len(fn.V) + len(fn.R) + len(fn.S)
}

func (a *Analyzer) hasThresholdValidation(fn *SignatureFunction) bool {
	// TODO: Implement threshold validation detection
	return false
}

func (a *Analyzer) hasUnsafeSignatureRecovery(fn *SignatureFunction) bool {
	// TODO: Implement unsafe signature recovery detection
	return false
}

func (a *Analyzer) hasInsufficientEntropy(fn *SignatureFunction) bool {
	// TODO: Implement entropy analysis
	return false
}

// hasStrongSignerValidation checks if the function has strong signer validation
func (a *Analyzer) hasStrongSignerValidation(fn *SignatureFunction) bool {
	// Check if there are signature fields present
	if len(fn.Signature) == 0 && len(fn.V) == 0 && len(fn.R) == 0 && len(fn.S) == 0 {
		return false
	}

	// TODO: Implement more sophisticated signer validation checks
	// For now, we consider it strong if signature fields are present
	return true
}

// calculateSecurityScore calculates an overall security score
func (a *Analyzer) calculateSecurityScore(metadata *SignatureMetadata) float64 {
	if len(metadata.SignatureFunctions) == 0 {
		return 100.0
	}

	totalPossibleVulns := len(metadata.SignatureFunctions) * 10 // Assume 10 possible vulns per function
	score := float64(totalPossibleVulns-metadata.TotalVulnerabilities) / float64(totalPossibleVulns) * 100.0

	if score < 0 {
		score = 0
	}

	return score
}

// determineRiskLevel determines the risk level based on security score
func (a *Analyzer) determineRiskLevel(score float64) string {
	switch {
	case score >= 90:
		return "LOW"
	case score >= 70:
		return "MEDIUM"
	case score >= 50:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// CheckControlFields analyzes a function for missing security controls
func (a *Analyzer) CheckControlFields(fn SignatureFunction) []string {
	var warnings []string

	if fn.Nonce == nil {
		warnings = append(warnings, "Missing nonce field")
	}
	if fn.Timestamp == nil {
		warnings = append(warnings, "Missing timestamp field")
	}
	if fn.Deadline == nil {
		warnings = append(warnings, "Missing deadline field")
	}
	if fn.ChainID == nil {
		warnings = append(warnings, "Missing chainId field")
	}
	if fn.DomainSeparator == nil {
		warnings = append(warnings, "Missing domainSeparator field")
	}
	if fn.Version == nil && fn.SignatureType.Kind == EIP712 {
		warnings = append(warnings, "Missing version field for EIP712")
	}

	return warnings
}

// CheckSignaturePresence validates that signature inputs are properly defined
func (a *Analyzer) CheckSignaturePresence(fn SignatureFunction) []string {
	var warnings []string

	signatureParts := [][]SignatureField{fn.Signature, fn.V, fn.R, fn.S}
	empty := true
	for _, part := range signatureParts {
		if len(part) > 0 {
			empty = false
			break
		}
	}

	if empty {
		warnings = append(warnings, "No signature input found")
	}

	return warnings
}

// GenerateSecurityReport generates a comprehensive security report
func (a *Analyzer) GenerateSecurityReport(metadata *SignatureMetadata) string {
	var report strings.Builder

	report.WriteString("=== SIGNATURE SECURITY ANALYSIS REPORT ===\n\n")

	report.WriteString(fmt.Sprintf("Total Functions Analyzed: %d\n", len(metadata.SignatureFunctions)))
	report.WriteString(fmt.Sprintf("Total Vulnerabilities Found: %d\n", metadata.TotalVulnerabilities))
	report.WriteString(fmt.Sprintf("Security Score: %.2f%%\n", metadata.SecurityScore))
	report.WriteString(fmt.Sprintf("Risk Level: %s\n\n", metadata.RiskLevel))

	// Function-by-function analysis
	for i, fn := range metadata.SignatureFunctions {
		report.WriteString(fmt.Sprintf("Function %d: %s\n", i+1, fn.FunctionName))
		report.WriteString(fmt.Sprintf("  Signature Type: %s\n", fn.SignatureType.Kind))
		report.WriteString(fmt.Sprintf("  Vulnerabilities: %d\n", len(fn.Vulnerabilities)))

		if len(fn.Vulnerabilities) > 0 {
			report.WriteString("  Issues Found:\n")
			for _, vuln := range fn.Vulnerabilities {
				report.WriteString(fmt.Sprintf("    - %s\n", vuln))
			}
		}

		report.WriteString("  Security Checks:\n")
		report.WriteString(fmt.Sprintf("    - Replay Protection: %t\n", fn.SecurityChecks.ReplayProtection))
		report.WriteString(fmt.Sprintf("    - Deadline Check: %t\n", fn.SecurityChecks.DeadlineCheck))
		report.WriteString(fmt.Sprintf("    - Nonce Check: %t\n", fn.SecurityChecks.NonceCheck))
		report.WriteString(fmt.Sprintf("    - Chain ID Check: %t\n", fn.SecurityChecks.ChainIDCheck))
		report.WriteString(fmt.Sprintf("    - Domain Validation: %t\n", fn.SecurityChecks.DomainValidation))
		report.WriteString(fmt.Sprintf("    - Signer Validation: %t\n", fn.SecurityChecks.SignerValidation))
		report.WriteString(fmt.Sprintf("    - Threshold Validation: %t\n", fn.SecurityChecks.ThresholdValidation))

		report.WriteString("\n")
	}

	return report.String()
}
