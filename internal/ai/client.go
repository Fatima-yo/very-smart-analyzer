package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// OpenAIClient handles communication with OpenAI API
type OpenAIClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents a request to the OpenAI API
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

// ChatResponse represents a response from the OpenAI API
type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewClient creates a new OpenAI client
func NewClient(apiKey string) *OpenAIClient {
	return &OpenAIClient{
		apiKey:     apiKey,
		httpClient: &http.Client{},
		baseURL:    "https://api.openai.com/v1",
	}
}

// AnalyzeContract uses AI to analyze a Solidity contract
func (c *OpenAIClient) AnalyzeContract(contractPath string) error {
	// Read the contract file
	contractData, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("failed to read contract file: %w", err)
	}

	// Load the AI query template
	queryTemplate, err := os.ReadFile("ai_query.txt")
	if err != nil {
		return fmt.Errorf("failed to read AI query template: %w", err)
	}

	// Prepare the prompt
	prompt := string(queryTemplate) + "\n\nSolidity input:\n\n" + string(contractData)

	// Send request to OpenAI
	response, err := c.sendChatRequest(prompt)
	if err != nil {
		return fmt.Errorf("failed to get AI response: %w", err)
	}

	// Parse and validate the response
	metadata, err := c.parseAIResponse(response)
	if err != nil {
		return fmt.Errorf("failed to parse AI response: %w", err)
	}

	// Write the results
	outputPath := strings.TrimSuffix(contractPath, ".sol") + "_ai_analysis.json"
	outputData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("AI analysis complete. Results written to: %s\n", outputPath)
	return nil
}

// sendChatRequest sends a request to the OpenAI API
func (c *OpenAIClient) sendChatRequest(prompt string) (string, error) {
	request := ChatRequest{
		Model: "gpt-4",
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a smart contract security expert specializing in signature verification analysis.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   4000,
		Temperature: 0.1,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/chat/completions", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var chatResponse ChatResponse
	if err := json.Unmarshal(body, &chatResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if chatResponse.Error != nil {
		return "", fmt.Errorf("OpenAI API error: %s", chatResponse.Error.Message)
	}

	if len(chatResponse.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI API")
	}

	return chatResponse.Choices[0].Message.Content, nil
}

// parseAIResponse parses the AI response and extracts metadata
func (c *OpenAIClient) parseAIResponse(response string) (map[string]interface{}, error) {
	// Try to extract JSON from the response
	// The AI might wrap the JSON in markdown or other formatting
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no valid JSON found in AI response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from AI response: %w", err)
	}

	return metadata, nil
}

// GenerateFuzzTestPlan generates a fuzz testing plan for signature functions
func (c *OpenAIClient) GenerateFuzzTestPlan(metadata map[string]interface{}) (string, error) {
	prompt := fmt.Sprintf(`
Generate a comprehensive fuzz testing plan for the following signature functions metadata:

%s

The plan should include:
1. Replay attack tests
2. Malformed signature tests
3. Invalid v/r/s value tests
4. Expired deadline tests
5. Invalid nonce tests
6. Domain separator manipulation tests

Return the plan in a structured format.
`, metadata)

	response, err := c.sendChatRequest(prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate fuzz test plan: %w", err)
	}

	return response, nil
}
