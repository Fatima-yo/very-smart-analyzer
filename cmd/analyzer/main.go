package main

import (
	"encoding/json"
	"fmt"
	"os"

	"very_smart_analyzer/internal/ai"
	"very_smart_analyzer/internal/analyzer"
	"very_smart_analyzer/internal/fuzzer"
	"very_smart_analyzer/internal/network"

	"github.com/spf13/cobra"
)

var (
	configFile string
	verbose    bool
	debug      bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "very_smart_analyzer",
		Short: "Smart fuzz-testing tool for Ethereum smart contracts",
		Long: `A comprehensive tool for analyzing and fuzz-testing Ethereum smart contracts,
with a focus on signature verification vulnerabilities and AI-assisted analysis.

The tool follows a clear separation of concerns:
- AI: Extracts function signatures and metadata from Solidity contracts
- Go: Performs security analysis and generates targeted fuzz tests
- No mixing of responsibilities between AI and Go components`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "configs/config.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug mode")

	// Add subcommands
	rootCmd.AddCommand(aiCmd())
	rootCmd.AddCommand(securityCmd())
	rootCmd.AddCommand(fuzzCmd())
	rootCmd.AddCommand(networkCmd())
	rootCmd.AddCommand(pipelineCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func aiCmd() *cobra.Command {
	var contractPath string
	var apiKey string
	var outputPath string

	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-assisted contract analysis",
		Long:  "Use AI to extract function signatures and metadata from Solidity contracts. NO security analysis is performed by AI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				analyzer.InitDebug()
			}

			aiClient := ai.NewClient(apiKey)
			return aiClient.AnalyzeContract(contractPath)
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file (required)")
	cmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "OpenAI API key (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file for AI analysis (default: contract_ai_analysis.json)")
	cmd.MarkFlagRequired("contract")
	cmd.MarkFlagRequired("api-key")

	return cmd
}

func securityCmd() *cobra.Command {
	var metadataPath string
	var outputPath string

	cmd := &cobra.Command{
		Use:   "security",
		Short: "Perform security analysis on AI-extracted metadata",
		Long:  "Analyze metadata extracted by AI to identify vulnerabilities and generate security reports.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				analyzer.InitDebug()
			}

			analyzerInstance := analyzer.NewAnalyzer()
			metadata, err := analyzerInstance.AnalyzeMetadataFromAI(metadataPath)
			if err != nil {
				return err
			}

			// Write the security analysis results
			outputData, err := json.MarshalIndent(metadata, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal security analysis: %w", err)
			}

			if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}

			fmt.Printf("Security analysis complete. Results written to: %s\n", outputPath)
			fmt.Printf("Found %d vulnerabilities, Security Score: %.2f, Risk Level: %s\n",
				metadata.TotalVulnerabilities, metadata.SecurityScore, metadata.RiskLevel)
			return nil
		},
	}

	cmd.Flags().StringVarP(&metadataPath, "metadata", "m", "", "path to AI-extracted metadata file (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "security_analysis.json", "output file for security analysis results")
	cmd.MarkFlagRequired("metadata")

	return cmd
}

func fuzzCmd() *cobra.Command {
	var contractPath string
	var metadataPath string
	var iterations int
	var outputPath string

	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Run fuzz tests on signature functions",
		Long:  "Generate and execute fuzz tests for signature verification functions, including replay attacks and malformed signatures.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				analyzer.InitDebug()
			}

			fuzzer := fuzzer.NewFuzzer()
			return fuzzer.RunFuzzTests(contractPath, metadataPath, iterations)
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file")
	cmd.Flags().StringVarP(&metadataPath, "metadata", "m", "", "path to contract metadata file")
	cmd.Flags().IntVarP(&iterations, "iterations", "i", 100, "number of fuzz test iterations")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "build/reports/fuzz_report.txt", "output file for fuzz test results")

	return cmd
}

func networkCmd() *cobra.Command {
	var port int
	var chainId int64

	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage private network",
		Long:  "Launch and manage a private Ethereum network for testing.",
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start private network",
		RunE: func(cmd *cobra.Command, args []string) error {
			network := network.NewNetwork()
			return network.Start(port, chainId)
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop private network",
		RunE: func(cmd *cobra.Command, args []string) error {
			network := network.NewNetwork()
			return network.Stop()
		},
	}

	startCmd.Flags().IntVarP(&port, "port", "p", 8545, "network port")
	startCmd.Flags().Int64VarP(&chainId, "chain-id", "i", 1337, "chain ID")

	cmd.AddCommand(startCmd, stopCmd)
	return cmd
}

func pipelineCmd() *cobra.Command {
	var contractPath string
	var apiKey string
	var runAI bool

	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Run complete analysis pipeline",
		Long:  "Run the complete pipeline: AI extraction → Security analysis → Fuzz testing",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				analyzer.InitDebug()
			}

			fmt.Println("=== VERY SMART ANALYZER - COMPLETE PIPELINE ===")

			// Step 1: AI Analysis
			if runAI {
				fmt.Println("=== STEP 1: AI ANALYSIS ===")
				aiClient := ai.NewClient(apiKey)
				if err := aiClient.AnalyzeContract(contractPath); err != nil {
					return fmt.Errorf("AI analysis failed: %w", err)
				}
				fmt.Println("✅ AI analysis completed")
			}

			// Step 2: Security Analysis
			fmt.Println("=== STEP 2: SECURITY ANALYSIS ===")
			metadataPath := fmt.Sprintf("%s_ai_analysis.json", contractPath[:len(contractPath)-4])
			analyzerInstance := analyzer.NewAnalyzer()
			metadata, err := analyzerInstance.AnalyzeMetadataFromAI(metadataPath)
			if err != nil {
				return fmt.Errorf("security analysis failed: %w", err)
			}
			fmt.Printf("✅ Security analysis completed - Found %d vulnerabilities\n", metadata.TotalVulnerabilities)

			// Step 3: Fuzz Testing
			fmt.Println("=== STEP 3: FUZZ TESTING ===")
			fuzzer := fuzzer.NewFuzzer()
			if err := fuzzer.RunFuzzTests(contractPath, metadataPath, 100); err != nil {
				return fmt.Errorf("fuzz testing failed: %w", err)
			}
			fmt.Println("✅ Fuzz testing completed")

			fmt.Println("=== PIPELINE COMPLETED SUCCESSFULLY ===")
			return nil
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file (required)")
	cmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "OpenAI API key (required for AI analysis)")
	cmd.Flags().BoolVarP(&runAI, "ai", "a", true, "run AI analysis step")
	cmd.MarkFlagRequired("contract")

	return cmd
}
