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
│   ├── analyzer/          # Security analysis engine
│   ├── ai/               # AI integration layer
│   ├── network/          # Private network management
│   ├── fuzzer/           # Fuzz testing engine
│   ├── executor/         # Contract execution engine
│   ├── reporter/         # Results and reporting
│   └── test_vectors/     # Test vector generation
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
   - OpenAI API key

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
./bin/analyzer ai --contract contracts/TestCases.sol --api-key YOUR_OPENAI_API_KEY
```
- **AI extracts** function signatures and metadata
- **NO security analysis** performed by AI
- Outputs: `TestCases_ai_analysis.json`

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
./bin/analyzer pipeline --contract contracts/TestCases.sol --api-key YOUR_KEY --debug
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

# AI settings
ai:
  model: "gpt-4"
  max_tokens: 4000
  temperature: 0.1

# Fuzz testing settings
fuzzer:
  default_iterations: 100
  max_gas_limit: 5000000
```

## 🧪 **Test Contracts**

The `contracts/` directory contains sample contracts for testing:

- `TestCases.sol`: Comprehensive test contract with various signature functions
- `VulnerableReplay.sol.bak`: Backup of vulnerable contract examples

## 🔍 **Vulnerability Detection**

The tool detects the following vulnerabilities:

- **Missing nonce** (replay attack protection)
- **Missing deadline** (timestamp validation)
- **Missing chain ID** (cross-chain replay protection)
- **Missing domain separator** (EIP712 security)
- **Weak signer validation**
- **Unsafe signature recovery**

## 🎯 **Fuzz Testing Types**

- **Replay attacks** (execute same signature twice)
- **Malformed signatures** (invalid formats)
- **Invalid V/R/S values** (signature components)
- **Expired deadlines** (timestamp validation)
- **Invalid nonces** (replay protection)
- **Domain manipulation** (EIP712 attacks)
- **Random mutations** (comprehensive testing)

## 📊 **Reports**

The tool generates comprehensive reports in the `build/reports/` directory:

- **AI Analysis**: Function extraction results
- **Security Analysis**: Vulnerability findings and risk assessment
- **Fuzz Testing**: Test execution results and coverage

## 🛠️ **Development**

### **Project Structure**
- **cmd/analyzer/**: Single CLI application with all commands
- **internal/**: Private packages for core functionality
- **contracts/**: Test contracts and fixtures
- **build/**: All generated artifacts (gitignored)

### **Adding New Features**
1. **New Analysis Types**: Extend the `analyzer` package
2. **New Fuzz Tests**: Add to the `fuzzer` package
3. **New AI Prompts**: Modify the `ai` package
4. **New Report Formats**: Extend the `reporter` package

### **Testing**
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/analyzer
```

## 🔒 **Security Considerations**

- The tool is designed for testing and analysis purposes
- Never use test private keys in production
- Always review AI-generated analysis results
- The tool may generate false positives - manual verification is recommended

## 📝 **License**

This project is licensed under the MIT License - see the LICENSE file for details. 