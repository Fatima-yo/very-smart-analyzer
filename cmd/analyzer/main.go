package main

import (
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
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "very_smart_analyzer",
		Short: "Smart fuzz-testing tool for Ethereum smart contracts",
		Long: `A comprehensive tool for analyzing and fuzz-testing Ethereum smart contracts,
with a focus on signature verification vulnerabilities and AI-assisted analysis.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "configs/config.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(analyzeCmd())
	rootCmd.AddCommand(fuzzCmd())
	rootCmd.AddCommand(networkCmd())
	rootCmd.AddCommand(aiCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func analyzeCmd() *cobra.Command {
	var contractPath string
	var outputPath string

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze a smart contract for signature functions",
		Long:  "Parse and analyze a Solidity contract to identify signature verification functions and potential vulnerabilities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			analyzer := analyzer.NewAnalyzer()
			return analyzer.AnalyzeContract(contractPath, outputPath)
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file (required)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "analysis_result.json", "output file for analysis results")
	cmd.MarkFlagRequired("contract")

	return cmd
}

func fuzzCmd() *cobra.Command {
	var contractPath string
	var metadataPath string
	var iterations int

	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Run fuzz tests on signature functions",
		Long:  "Generate and execute fuzz tests for signature verification functions, including replay attacks and malformed signatures.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fuzzer := fuzzer.NewFuzzer()
			return fuzzer.RunFuzzTests(contractPath, metadataPath, iterations)
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file")
	cmd.Flags().StringVarP(&metadataPath, "metadata", "m", "", "path to contract metadata file")
	cmd.Flags().IntVarP(&iterations, "iterations", "i", 100, "number of fuzz test iterations")

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

func aiCmd() *cobra.Command {
	var contractPath string
	var apiKey string

	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-assisted contract analysis",
		Long:  "Use AI to analyze contracts and identify signature functions and vulnerabilities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			aiClient := ai.NewClient(apiKey)
			return aiClient.AnalyzeContract(contractPath)
		},
	}

	cmd.Flags().StringVarP(&contractPath, "contract", "c", "", "path to Solidity contract file (required)")
	cmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "OpenAI API key (required)")
	cmd.MarkFlagRequired("contract")
	cmd.MarkFlagRequired("api-key")

	return cmd
}
