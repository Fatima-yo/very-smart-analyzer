package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
		SignatureFunctions:   uniqueFunctions,
		TotalVulnerabilities: 0,   // Will be calculated later by analyzer
		SecurityScore:        0.0, // Will be calculated later by analyzer
		RiskLevel:            "",  // Will be calculated later by analyzer
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
	responseText, err := c.makeAPIRequest(prompt)
	if err != nil {
		DebugPrintError("API_REQUEST", err)
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}

	// Parse the response
	metadata, err := c.parseAPIResponse(responseText)
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

// makeAPIRequest makes a single API request to Claude
func (c *AIClient) makeAPIRequest(prompt string) (string, error) {
	if Debug.ShowAIInput {
		DebugPrintAI("Full prompt being sent to AI:")
		DebugPrintJSON("PROMPT", prompt)
	}

	// Get model from env or use default
	model := os.Getenv("CLAUDE_MODEL")
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "Using model: %s", model)

	// Create the API request
	request := ClaudeAPIRequest{
		Model:       model,
		MaxTokens:   8000, // Model limit is 8192
		Temperature: 0.1,  // Low temperature for consistent parsing
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "API request prepared")

	// Marshal the request
	requestBody, err := json.Marshal(request)
	if err != nil {
		DebugPrintError("REQUEST_MARSHAL", err)
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "Request marshaled (size: %d bytes)", len(requestBody))

	// Create HTTP request
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(requestBody))
	if err != nil {
		DebugPrintError("HTTP_REQUEST_CREATE", err)
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "HTTP request created")

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	DebugPrintStep("EXTRACT_FUNCTIONS", "Headers set")

	// Make the request
	DebugPrintStep("EXTRACT_FUNCTIONS", "Making API request to Claude...")
	resp, err := c.Client.Do(req)
	if err != nil {
		DebugPrintError("HTTP_REQUEST_SEND", err)
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()
	DebugPrintStep("EXTRACT_FUNCTIONS", "API request completed (status: %d)", resp.StatusCode)

	// Read the response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		DebugPrintError("RESPONSE_READ", err)
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "Response body read (size: %d bytes)", len(responseBody))

	// Check for errors
	if resp.StatusCode != 200 {
		DebugPrintError("API_ERROR", fmt.Errorf("status %d: %s", resp.StatusCode, string(responseBody)))
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Parse the response
	var apiResponse ClaudeAPIResponse
	if err := json.Unmarshal(responseBody, &apiResponse); err != nil {
		DebugPrintError("RESPONSE_UNMARSHAL", err)
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "API response parsed")

	// Extract the JSON from the response
	if len(apiResponse.Content) == 0 {
		DebugPrintError("EMPTY_RESPONSE", fmt.Errorf("no content in API response"))
		return "", fmt.Errorf("no content in API response")
	}

	responseText := apiResponse.Content[0].Text
	DebugPrintStep("EXTRACT_FUNCTIONS", "Raw AI response length: %d characters", len(responseText))

	if Debug.ShowAIOutput {
		DebugPrintAI("Raw AI response:")
		DebugPrintJSON("AI_RESPONSE", responseText)
	}

	return responseText, nil
}

// parseAPIResponse parses the API response and extracts metadata
func (c *AIClient) parseAPIResponse(responseText string) (*SignatureMetadata, error) {
	// Extract JSON from the response (remove any markdown formatting)
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")

	if jsonStart == -1 || jsonEnd == -1 {
		DebugPrintError("JSON_EXTRACTION", fmt.Errorf("no JSON found in response"))
		DebugPrintAI("Response text that couldn't be parsed:")
		DebugPrintJSON("FAILED_RESPONSE", responseText)
		return nil, fmt.Errorf("no JSON found in response: %s", responseText)
	}

	jsonStr := responseText[jsonStart : jsonEnd+1]
	DebugPrintStep("EXTRACT_FUNCTIONS", "JSON extracted (length: %d characters)", len(jsonStr))

	if Debug.ShowAIOutput {
		DebugPrintAI("Extracted JSON:")
		DebugPrintJSON("EXTRACTED_JSON", jsonStr)
	}

	// Parse the extracted metadata
	var metadata SignatureMetadata
	if err := json.Unmarshal([]byte(jsonStr), &metadata); err != nil {
		DebugPrintError("METADATA_PARSE", err)
		DebugPrintAI("Failed to parse JSON string:")
		DebugPrintJSON("FAILED_JSON", jsonStr)
		return nil, fmt.Errorf("failed to parse extracted JSON: %w", err)
	}
	DebugPrintStep("EXTRACT_FUNCTIONS", "Metadata parsed successfully")
	DebugPrintStep("EXTRACT_FUNCTIONS", "Found %d signature functions", len(metadata.SignatureFunctions))

	return &metadata, nil
}
