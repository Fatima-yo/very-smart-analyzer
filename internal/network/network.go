package network

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Network manages a private Ethereum network
type Network struct {
	client    *ethclient.Client
	rpcClient *rpc.Client
	process   *exec.Cmd
	dataDir   string
	port      int
	chainID   int64
	isRunning bool
}

// NetworkConfig holds network configuration
type NetworkConfig struct {
	Port      int    `json:"port"`
	ChainID   int64  `json:"chain_id"`
	DataDir   string `json:"data_dir"`
	Accounts  int    `json:"accounts"`
	BlockTime int    `json:"block_time"`
	GasLimit  int64  `json:"gas_limit"`
}

// NewNetwork creates a new network manager
func NewNetwork() *Network {
	return &Network{
		dataDir:   "network_data",
		port:      8545,
		chainID:   1337,
		isRunning: false,
	}
}

// Start launches a private network
func (n *Network) Start(port int, chainID int64) error {
	if n.isRunning {
		return fmt.Errorf("network is already running")
	}

	n.port = port
	n.chainID = chainID

	// Create data directory
	if err := os.MkdirAll(n.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Check if ganache-cli is available
	if err := n.checkGanacheAvailability(); err != nil {
		return fmt.Errorf("ganache-cli not available: %w", err)
	}

	// Start ganache-cli
	if err := n.startGanache(); err != nil {
		return fmt.Errorf("failed to start ganache: %w", err)
	}

	// Wait for network to be ready
	if err := n.waitForNetwork(); err != nil {
		return fmt.Errorf("network failed to start: %w", err)
	}

	fmt.Printf("Private network started on port %d (Chain ID: %d)\n", n.port, n.chainID)
	fmt.Printf("RPC URL: http://localhost:%d\n", n.port)

	n.isRunning = true
	return nil
}

// Stop shuts down the private network
func (n *Network) Stop() error {
	if !n.isRunning {
		return fmt.Errorf("network is not running")
	}

	if n.process != nil && n.process.Process != nil {
		if err := n.process.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill network process: %w", err)
		}
	}

	if n.client != nil {
		n.client.Close()
	}

	if n.rpcClient != nil {
		n.rpcClient.Close()
	}

	n.isRunning = false
	fmt.Println("Private network stopped")
	return nil
}

// GetClient returns the Ethereum client
func (n *Network) GetClient() (*ethclient.Client, error) {
	if !n.isRunning {
		return nil, fmt.Errorf("network is not running")
	}
	return n.client, nil
}

// GetRPCClient returns the RPC client
func (n *Network) GetRPCClient() (*rpc.Client, error) {
	if !n.isRunning {
		return nil, fmt.Errorf("network is not running")
	}
	return n.rpcClient, nil
}

// IsRunning returns whether the network is currently running
func (n *Network) IsRunning() bool {
	return n.isRunning
}

// checkGanacheAvailability checks if ganache-cli is installed
func (n *Network) checkGanacheAvailability() error {
	cmd := exec.Command("ganache-cli", "--version")
	if err := cmd.Run(); err != nil {
		// Try alternative command
		cmd = exec.Command("npx", "ganache-cli", "--version")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ganache-cli not found. Please install it with: npm install -g ganache-cli")
		}
	}
	return nil
}

// startGanache starts the ganache-cli process
func (n *Network) startGanache() error {
	args := []string{
		"--port", strconv.Itoa(n.port),
		"--chain.hardfork", "shanghai",
		"--chain.chainId", strconv.FormatInt(n.chainID, 10),
		"--database.dbPath", filepath.Join(n.dataDir, "chaindata"),
		"--wallet.deterministic", "true",
		"--wallet.totalAccounts", "10",
		"--miner.blockTime", "1",
		"--miner.blockGasLimit", "8000000",
		"--server.host", "0.0.0.0",
	}

	// Try ganache-cli first, then npx ganache-cli
	cmd := exec.Command("ganache-cli", args...)
	if err := cmd.Start(); err != nil {
		// Fallback to npx
		args = append([]string{"ganache-cli"}, args...)
		cmd = exec.Command("npx", args...)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start ganache-cli: %w", err)
		}
	}

	n.process = cmd

	// Start goroutine to handle process output
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Ganache process error: %v\nOutput: %s", err, string(output))
		}
	}()

	return nil
}

// waitForNetwork waits for the network to be ready
func (n *Network) waitForNetwork() error {
	// Wait a bit for ganache to start
	time.Sleep(2 * time.Second)

	// Try to connect to the network
	for i := 0; i < 30; i++ { // 30 second timeout
		client, err := ethclient.Dial(fmt.Sprintf("http://localhost:%d", n.port))
		if err == nil {
			// Test the connection
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err = client.BlockNumber(ctx)
			if err == nil {
				n.client = client

				// Also create RPC client
				rpcClient, err := rpc.Dial(fmt.Sprintf("http://localhost:%d", n.port))
				if err == nil {
					n.rpcClient = rpcClient
				}

				return nil
			}
			client.Close()
		}

		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for network to be ready")
}

// GetNetworkInfo returns information about the current network
func (n *Network) GetNetworkInfo() map[string]interface{} {
	info := map[string]interface{}{
		"running":  n.isRunning,
		"port":     n.port,
		"chain_id": n.chainID,
		"data_dir": n.dataDir,
	}

	if n.isRunning && n.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if blockNumber, err := n.client.BlockNumber(ctx); err == nil {
			info["latest_block"] = blockNumber
		}
	}

	return info
}

// DeployContract deploys a contract to the network
func (n *Network) DeployContract(bytecode string, abi interface{}, constructorArgs ...interface{}) (string, error) {
	if !n.isRunning {
		return "", fmt.Errorf("network is not running")
	}

	// TODO: Implement contract deployment
	// This would involve:
	// 1. Creating a transaction with the bytecode
	// 2. Signing it with a test account
	// 3. Sending it to the network
	// 4. Waiting for confirmation
	// 5. Returning the contract address

	return "", fmt.Errorf("contract deployment not yet implemented")
}
