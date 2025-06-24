# Very Smart Analyzer

A comprehensive smart contract fuzz-testing tool for analyzing Ethereum smart contracts, with a focus on signature verification vulnerabilities and AI-assisted analysis.

## 🎯 **Core Philosophy**

This tool follows a **clear separation of concerns**:
- **AI**: Extracts function signatures and metadata from Solidity contracts
- **Go**: Performs security analysis and generates targeted fuzz tests
- **No mixing** of responsibilities between AI and Go components

## 🏗️ **Architecture**

```
very_smart_analyzer/
├── cmd/analyzer/          # Main CLI application
├── internal/
│   ├── analyzer/          # Security analysis engine + Claude AI integration
│   ├── network/          # Private network management
│   ├── fuzzer/           # Fuzz testing engine
│   ├── executor/         # Contract execution engine
│   └── reporter/         # Results and reporting
├── contracts/            # Test contracts and fixtures
├── configs/              # Configuration files
├── build/                # Build artifacts (gitignored)
│   ├── artifacts/        # Hardhat artifacts
│   ├── cache/           # Build cache
│   ├── reports/         # Generated reports
│   └── test_vectors/    # Generated test vectors
└── docs/                 # Documentation
```

## 🚀 **Installation**

1. **Prerequisites**:
   - Go 1.19 or later
   - Node.js (for Hardhat)
   - Claude API key (for AI analysis)

2. **Install dependencies**:
   ```bash
   go mod tidy
   npm install
   ```

3. **Build the application**:
   ```bash
   go build -o bin/analyzer cmd/analyzer/main.go
   ```

## 📖 **Usage**

### **1. AI Analysis (Extraction Only)**
```bash
./bin/analyzer ai --contract contracts/TestCases.sol --api-key YOUR_CLAUDE_API_KEY
```
- **AI extracts** function signatures and metadata using Claude
- **NO security analysis** performed by AI
- Outputs: `extracted_metadata.json`

### **2. Security Analysis**
```bash
./bin/analyzer security --metadata TestCases_ai_analysis.json --output security_report.json
```
- **Go analyzes** AI-extracted metadata for vulnerabilities
- **NO contract parsing** in Go
- Outputs: `security_report.json`

### **3. Fuzz Testing**
```bash
./bin/analyzer fuzz --contract contracts/TestCases.sol --metadata security_report.json --iterations 100
```
- Uses both contract and security analysis for test generation
- Generates targeted fuzz tests based on vulnerabilities

### **4. Complete Pipeline**
```bash
./bin/analyzer pipeline --contract contracts/TestCases.sol --api-key YOUR_CLAUDE_API_KEY --debug
```
- Runs the complete workflow: AI → Security → Fuzz Testing
- Includes debug output for troubleshooting

### **5. Network Management**
```bash
./bin/analyzer network start --port 8545 --chain-id 1337
./bin/analyzer network stop
```

## 🔧 **Configuration**

The application uses a YAML configuration file (`configs/config.yaml`) for settings:

```yaml
# Network settings
network:
  port: 8545
  chain_id: 1337
  data_dir: "build/network_data"

# AI settings (Claude)
ai:
  model: "claude"
  max_tokens: 4000
  temperature: 0.1

# Fuzz testing settings
fuzzer:
  default_iterations: 100
  max_gas_limit: 5000000
```

**Note**: The tool currently uses Claude for AI analysis. The CLI requires a Claude API key.

## 🧪 **Test Contracts**

The `