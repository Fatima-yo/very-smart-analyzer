# Very Smart Analyzer

A comprehensive smart contract fuzz-testing tool for analyzing Ethereum smart contracts, with a focus on signature verification vulnerabilities and AI-assisted analysis.

## Features

- **Contract Analysis**: Parse and analyze Solidity contracts for signature functions
- **AI Integration**: Use OpenAI GPT-4 for intelligent contract analysis and vulnerability detection
- **Fuzz Testing**: Generate and execute comprehensive fuzz tests for signature verification
- **Private Network**: Launch and manage private Ethereum networks for testing
- **Execution Testing**: Deploy contracts and execute transactions for real-world testing
- **Comprehensive Reporting**: Generate detailed security reports in JSON and text formats

## Architecture

```
very_smart_analyzer/
├── cmd/analyzer/          # Main CLI application
├── internal/
│   ├── analyzer/          # Contract analysis logic
│   ├── ai/               # AI integration layer
│   ├── network/          # Private network management
│   ├── fuzzer/           # Fuzz testing engine
│   ├── executor/         # Contract execution engine
│   └── reporter/         # Results and reporting
├── pkg/                   # Public packages
├── configs/              # Configuration files
├── tests/                # Test contracts and fixtures
└── docs/                 # Documentation
```

## Installation

1. **Prerequisites**:
   - Go 1.19 or later
   - Node.js (for ganache-cli)
   - OpenAI API key

2. **Install dependencies**:
   ```bash
   go mod tidy
   npm install -g ganache-cli
   ```

3. **Build the application**:
   ```bash
   go build -o bin/analyzer cmd/analyzer/main.go
   ```

## Usage

### Basic Analysis

Analyze a smart contract for signature functions:

```bash
./bin/analyzer analyze --contract tests/test_contract.sol
```

### AI-Assisted Analysis

Use AI to analyze contracts and identify vulnerabilities:

```bash
./bin/analyzer ai --contract tests/test_contract.sol --api-key YOUR_OPENAI_API_KEY
```

### Fuzz Testing

Run fuzz tests on signature functions:

```bash
./bin/analyzer fuzz --contract tests/test_contract.sol --metadata analysis_result.json --iterations 100
```

### Network Management

Start a private network for testing:

```bash
./bin/analyzer network start --port 8545 --chain-id 1337
```

Stop the network:

```bash
./bin/analyzer network stop
```

## Configuration

The application uses a YAML configuration file (`configs/config.yaml`) for settings:

```yaml
# Network settings
network:
  port: 8545
  chain_id: 1337
  data_dir: "network_data"

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

## Test Contracts

The `tests/` directory contains sample contracts for testing:

- `test_contract.sol`: Contains various signature functions with and without vulnerabilities
- Includes functions with missing nonce protection, deadline checks, etc.

## Fuzz Testing Types

The tool generates several types of fuzz tests:

1. **Replay Attacks**: Execute the same signature twice
2. **Malformed Signatures**: Test with invalid signature formats
3. **Invalid V/R/S Values**: Test with invalid signature components
4. **Expired Deadlines**: Test with expired timestamps
5. **Invalid Nonces**: Test with already-used nonces
6. **Domain Manipulation**: Test with wrong domain separators
7. **Random Mutations**: Generate random signature data

## Reports

The tool generates comprehensive reports including:

- **JSON Report**: Machine-readable format for further processing
- **Text Report**: Human-readable format with executive summary
- **Vulnerability Analysis**: Detailed security findings
- **Fuzz Test Results**: Test execution outcomes
- **Risk Assessment**: Overall security score and recommendations

## Development

### Project Structure

- **cmd/analyzer/**: Main CLI application with Cobra commands
- **internal/**: Private packages for core functionality
- **pkg/**: Public packages that can be imported by other projects
- **configs/**: Configuration files and templates
- **tests/**: Test contracts and fixtures

### Adding New Features

1. **New Analysis Types**: Extend the `analyzer` package
2. **New Fuzz Tests**: Add to the `fuzzer` package
3. **New AI Prompts**: Modify the `ai` package
4. **New Report Formats**: Extend the `reporter` package

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/analyzer
```

## Security Considerations

- The tool is designed for testing and analysis purposes
- Never use test private keys in production
- Always review AI-generated analysis results
- The tool may generate false positives - manual verification is recommended

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Roadmap

- [ ] Enhanced Solidity parsing
- [ ] Support for more signature schemes
- [ ] Integration with other AI models
- [ ] Web interface for results visualization
- [ ] CI/CD pipeline integration
- [ ] Support for other blockchain networks 