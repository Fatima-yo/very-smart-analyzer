package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// ClaudeAPIRequest represents the request to Claude API
type ClaudeAPIRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	Messages    []Message `json:"messages"`
}

// ClaudeAPIResponse represents the response from Claude API
type ClaudeAPIResponse struct {
	Content []Content `json:"content"`
}

// Message represents a message in the conversation
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Content represents content in the response
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AIClient handles communication with Claude API
type AIClient struct {
	APIKey string
	Client *http.Client
}

// RequestSplitter handles splitting large contracts into manageable chunks
type RequestSplitter struct {
	MaxChunkSize int
	OverlapSize  int
}

// NewAIClient creates a new AI client
func NewAIClient() (*AIClient, error) {
	DebugPrintStep("AI_CLIENT_INIT", "Initializing AI client")

	// Load .env file
	if err := godotenv.Load(); err != nil {
		DebugPrintError("ENV_LOAD", err)
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}
	DebugPrintStep("AI_CLIENT_INIT", "Environment file loaded successfully")

	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		DebugPrintError("ENV_MISSING", fmt.Errorf("CLAUDE_API_KEY not found"))
		return nil, fmt.Errorf("CLAUDE_API_KEY environment variable not set")
	}
	DebugPrintStep("AI_CLIENT_INIT", "API key loaded (length: %d)", len(apiKey))

	return &AIClient{
		APIKey: apiKey,
		Client: &http.Client{},
	}, nil
}

// NewRequestSplitter creates a new request splitter
func NewRequestSplitter() *RequestSplitter {
	return &RequestSplitter{
		MaxChunkSize: 4000, // Claude's sweet spot for analysis
		OverlapSize:  200,  // Overlap to ensure function boundaries aren't cut
	}
}

// SplitContract splits a large contract into manageable chunks
func (rs *RequestSplitter) SplitContract(contractSource string) []string {
	DebugPrintStep("REQUEST_SPLIT", "Splitting contract of size %d characters", len(contractSource))

	if len(contractSource) <= rs.MaxChunkSize {
		DebugPrintStep("REQUEST_SPLIT", "Contract fits in single request")
		return []string{contractSource}
	}

	var chunks []string
	lines := strings.Split(contractSource, "\n")
	currentChunk := ""

	for i, line := range lines {
		// Check if adding this line would exceed the limit
		if len(currentChunk)+len(line)+1 > rs.MaxChunkSize && currentChunk != "" {
			// Add overlap from previous chunk
			if len(chunks) > 0 {
				overlapLines := strings.Split(chunks[len(chunks)-1], "\n")
				if len(overlapLines) > rs.OverlapSize/50 { // Rough estimate
					overlapStart := len(overlapLines) - rs.OverlapSize/50
					if overlapStart > 0 {
						currentChunk = strings.Join(overlapLines[overlapStart:], "\n") + "\n" + currentChunk
					}
				}
			}

			chunks = append(chunks, currentChunk)
			currentChunk = line
		} else {
			if currentChunk != "" {
				currentChunk += "\n"
			}
			currentChunk += line
		}

		// If this is the last line, add the final chunk
		if i == len(lines)-1 && currentChunk != "" {
			chunks = append(chunks, currentChunk)
		}
	}

	DebugPrintStep("REQUEST_SPLIT", "Split contract into %d chunks", len(chunks))
	for i, chunk := range chunks {
		DebugPrintStep("REQUEST_SPLIT", "Chunk %d: %d characters", i+1, len(chunk))
	}

	return chunks
}

// ExtractFunctionDefinitions extracts function definitions from a contract, handling large contracts
func (c *AIClient) ExtractFunctionDefinitions(contractSource string) (*SignatureMetadata, error) {
	DebugPrintStep("EXTRACT_FUNCTIONS", "Starting function extraction")
	DebugPrintStep("EXTRACT_FUNCTIONS", "Contract source length: %d characters", len(contractSource))

	// Split contract if it's too large
	splitter := NewRequestSplitter()
	chunks := splitter.SplitContract(contractSource)

	if len(chunks) == 1 {
		// Single chunk - use existing logic
		return c.extractFromSingleChunk(contractSource)
	}

	// Multiple chunks - process each and merge results
	DebugPrintStep("EXTRACT_FUNCTIONS", "Processing %d chunks separately", len(chunks))

	var allFunctions []SignatureFunction

	for i, chunk := range chunks {
		DebugPrintStep("EXTRACT_FUNCTIONS", "Processing chunk %d/%d (%d characters)", i+1, len(chunks), len(chunk))

		chunkMetadata, err := c.extractFromSingleChunk(chunk)
		if err != nil {
			DebugPrintError("CHUNK_EXTRACTION", err)
			DebugPrintStep("EXTRACT_FUNCTIONS", "Skipping chunk %d due to error", i+1)
			continue
		}

		// Add chunk identifier to function names to avoid conflicts
		for j := range chunkMetadata.SignatureFunctions {
			chunkMetadata.SignatureFunctions[j].FunctionName = fmt.Sprintf("%s_chunk%d",
				chunkMetadata.SignatureFunctions[j].FunctionName, i+1)
		}

		allFunctions = append(allFunctions, chunkMetadata.SignatureFunctions...)
		DebugPrintStep("EXTRACT_FUNCTIONS", "Chunk %d: extracted %d functions", i+1, len(chunkMetadata.SignatureFunctions))
	}

	// Remove duplicate functions (same name and selector)
	uniqueFunctions := c.removeDuplicateFunctions(allFunctions)

	DebugPrintStep("EXTRACT_FUNCTIONS", "Total unique functions extracted: %d", len(uniqueFunctions))

	return &SignatureMetadata{
		SignatureFunctions: uniqueFunctions,
		TotalFunctions:     len(uniqueFunctions),
		ExtractionTime:     time.Now().Format(time.RFC3339),
	}, nil
}

// extractFromSingleChunk extracts functions from a single contract chunk
func (c *AIClient) extractFromSingleChunk(contractSource string) (*SignatureMetadata, error) {
	// Load the query template
	queryTemplate, err := os.ReadFile("ai_query.txt")
	if err != nil {
		DebugPrintError("QUERY_TEMPLATE_READ", err)
		return nil, fmt.Errorf("failed to read query template: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "Query template loaded (length: %d characters)", len(queryTemplate))

	// Prepare the prompt
	prompt := fmt.Sprintf("%s\n\nHere is the Solidity contract to analyze:\n\n```solidity\n%s\n```",
		string(queryTemplate), contractSource)
	DebugPrintStep("EXTRACT_FUNCTIONS", "Prompt prepared (total length: %d characters)", len(prompt))

	// Check if prompt is too large
	if len(prompt) > 8000 {
		DebugPrintStep("EXTRACT_FUNCTIONS", "Warning: Large prompt (%d characters), may need further splitting", len(prompt))
	}

	// Make the API request
	response, err := c.makeAPIRequest(prompt)
	if err != nil {
		DebugPrintError("API_REQUEST", err)
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	// Parse the response
	metadata, err := c.parseAPIResponse(response)
	if err != nil {
		DebugPrintError("RESPONSE_PARSE", err)
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	return metadata, nil
}

// removeDuplicateFunctions removes duplicate functions based on name and selector
func (c *AIClient) removeDuplicateFunctions(functions []SignatureFunction) []SignatureFunction {
	seen := make(map[string]bool)
	var unique []SignatureFunction

	for _, fn := range functions {
		key := fn.FunctionName + ":" + fn.FunctionSelector
		if !seen[key] {
			seen[key] = true
			unique = append(unique, fn)
		}
	}

	return unique
}

// TestAIClient tests the AI client functionality
func TestAIClient() error {
	DebugPrintStep("TEST_AI_CLIENT", "Starting AI client test")

	// Create AI client
	client, err := NewAIClient()
	if err != nil {
		DebugPrintError("AI_CLIENT_CREATE", err)
		return fmt.Errorf("failed to create AI client: %w", err)
	}
	DebugPrintStep("TEST_AI_CLIENT", "AI client created successfully")

	// Read test contract
	contractPath := "contracts/TestCases.sol"
	contractData, err := os.ReadFile(contractPath)
	if err != nil {
		DebugPrintError("CONTRACT_READ", err)
		return fmt.Errorf("failed to read test contract: %w", err)
	}
	DebugPrintStep("TEST_AI_CLIENT", "Test contract read (length: %d characters)", len(contractData))

	// Extract function definitions
	DebugPrintStep("TEST_AI_CLIENT", "Calling AI to extract function definitions...")
	metadata, err := client.ExtractFunctionDefinitions(string(contractData))
	if err != nil {
		DebugPrintError("FUNCTION_EXTRACTION", err)
		return fmt.Errorf("failed to extract function definitions: %w", err)
	}
	DebugPrintStep("TEST_AI_CLIENT", "Function extraction completed")

	// Display results
	fmt.Printf("Extracted %d signature functions:\n\n", len(metadata.SignatureFunctions))

	for i, fn := range metadata.SignatureFunctions {
		fmt.Printf("Function %d:\n", i+1)
		fmt.Printf("  Name: %s\n", fn.FunctionName)
		fmt.Printf("  Selector: %s\n", fn.FunctionSelector)
		fmt.Printf("  Signature Type: %s\n", fn.SignatureType.Kind)
		fmt.Printf("  Structured: %t\n", fn.SignatureFields.Structured)
		fmt.Printf("  Fields: %d\n", len(fn.SignatureFields.Fields))
		DebugPrintStep("TEST_AI_CLIENT", "Function %d details extracted", i+1)
	}

	// Save metadata to file
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		DebugPrintError("METADATA_MARSHAL", err)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	DebugPrintStep("TEST_AI_CLIENT", "Metadata marshaled for output")

	if err := os.WriteFile("extracted_metadata.json", metadataJSON, 0644); err != nil {
		DebugPrintError("METADATA_SAVE", err)
		return fmt.Errorf("failed to save metadata: %w", err)
	}
	DebugPrintStep("TEST_AI_CLIENT", "Metadata saved to extracted_metadata.json")

	fmt.Println("\nMetadata saved to extracted_metadata.json")
	DebugPrintStep("TEST_AI_CLIENT", "AI client test completed successfully")

	return nil
}
