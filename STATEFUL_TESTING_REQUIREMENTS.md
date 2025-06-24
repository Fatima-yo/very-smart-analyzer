# Stateful Testing and AI Test Flow Generation Requirements

## Overview

Enhancement requirements for implementing realistic, stateful smart contract testing with AI-driven test flow generation. This addresses the gap between signature validation testing and real-world contract behavior testing.

## Current Limitations Identified

### 1. **Missing Contract State Management**
- No support for contract deployment with initial state
- No handling of prerequisites for function execution
- No state-dependent testing scenarios
- Tests are isolated and stateless

### 2. **Lack of Business Logic Understanding**
- Tool focuses on technical signature validation only
- No understanding of contract business logic
- No realistic attack vector identification
- Missing context-aware testing

### 3. **No Test Flow Planning**
- No AI step to analyze required test sequences
- No identification of operation dependencies
- No realistic scenario generation
- Missing setup/teardown procedures

## Required Enhancements

### 1. **AI Test Flow Planner (New Component)**

**Location**: `internal/planner/`

**Purpose**: Analyze contracts and generate realistic test scenarios

**Functionality**:
- Analyze contract business logic beyond signature functions
- Identify operation dependencies (e.g., deposit before withdraw)
- Generate step-by-step test flows
- Create realistic attack scenarios
- Determine required setup/teardown procedures

**AI Prompt Strategy**:
```
Input: Contract code + signature function analysis
Task: Generate comprehensive test scenarios including:
- Required setup steps (funding, initialization)
- Valid operation sequences 
- Invalid scenarios to test
- Realistic attack vectors
- State dependencies and prerequisites
Output: Structured test flow definitions
```

### 2. **Contract State Manager (New Component)**

**Location**: `internal/state/`

**Purpose**: Manage contract deployment and state throughout testing

**Functionality**:
- Deploy contracts with initial state (funding, configuration)
- Handle setup transactions before tests
- Manage test account balances and permissions
- Reset state between test scenarios
- Monitor contract storage changes
- Validate state transitions

**Key Features**:
- Multi-account management (owner, users, attackers)
- Balance tracking and funding
- State snapshots and rollback
- Transaction dependency handling

### 3. **Scenario-Based Testing Engine (Enhancement)**

**Location**: `internal/scenarios/` (new) + enhancements to `internal/fuzzer/`

**Purpose**: Execute complex, multi-step test scenarios

**Functionality**:
- Execute test flows with multiple transactions
- Validate business logic beyond signature checks
- Test realistic user workflows
- Simulate attack sequences
- Verify state consistency

**Test Types**:
- **Setup Tests**: Contract initialization and funding
- **Workflow Tests**: Complete user journeys (deposit → withdraw)
- **Edge Case Tests**: Boundary conditions and error cases
- **Attack Tests**: Realistic attack simulations
- **State Tests**: Storage and balance validation

### 4. **Enhanced Executor (Modifications)**

**Location**: `internal/executor/executor.go` (enhance existing)

**New Capabilities**:
- Multi-step transaction execution
- State monitoring between calls
- Account balance management
- Storage change tracking
- Transaction dependency resolution
- Rollback and reset functionality

### 5. **Test Flow Definition Format**

**Location**: `pkg/testflow/` (new public package)

**Purpose**: Define structured test scenario format

**Structure**:
```go
type TestFlow struct {
    Name         string           `json:"name"`
    Description  string           `json:"description"`
    Setup        []SetupStep      `json:"setup"`
    Scenarios    []TestScenario   `json:"scenarios"`
    Validation   []ValidationStep `json:"validation"`
    Cleanup      []CleanupStep    `json:"cleanup"`
}

type SetupStep struct {
    Action      string                 `json:"action"`
    Parameters  map[string]interface{} `json:"parameters"`
    Expected    ExpectedResult         `json:"expected"`
}

type TestScenario struct {
    Name        string                 `json:"name"`
    Steps       []TransactionStep      `json:"steps"`
    ExpectedEnd ExpectedState          `json:"expected_end"`
    ShouldFail  bool                  `json:"should_fail"`
}
```

## Implementation Plan

### Phase 1: Core Infrastructure
1. **Contract State Manager**: Basic deployment and state management
2. **Enhanced Executor**: Multi-step transaction support
3. **Test Flow Definitions**: Basic data structures

### Phase 2: AI Integration
1. **AI Test Flow Planner**: Contract analysis and scenario generation
2. **Prompt Engineering**: Develop effective prompts for test planning
3. **Response Parsing**: Parse AI-generated test flows

### Phase 3: Scenario Engine
1. **Scenario Executor**: Multi-step test execution
2. **State Validation**: Verify contract state changes
3. **Result Aggregation**: Collect and analyze results

### Phase 4: Integration
1. **CLI Updates**: New commands for stateful testing
2. **Configuration**: Settings for stateful testing
3. **Reporting**: Enhanced reports with state analysis

## Example Test Case: Vault Contract

### Contract Requirements
- Vault with owner signature-based withdrawals
- EIP712 signatures with struct parameters (owner, amount)
- Requires funding before withdrawals possible
- Owner can withdraw any amount up to balance

### Generated Test Flow Example
```yaml
name: "Vault Withdrawal Testing"
setup:
  - action: "deploy_contract"
    parameters:
      initial_funding: "10 ETH"
      owner: "0x123..."
  - action: "fund_vault"
    parameters:
      amount: "5 ETH"
      from: "user1"

scenarios:
  - name: "Valid withdrawal"
    steps:
      - action: "sign_withdrawal"
        parameters:
          owner: "0x123..."
          amount: "1 ETH"
      - action: "execute_withdrawal"
        expected: "success"
  
  - name: "Withdrawal without funds"
    steps:
      - action: "sign_withdrawal"
        parameters:
          amount: "100 ETH"
      - action: "execute_withdrawal"
        expected: "revert"
```

## Integration Points

### 1. **Modified Analysis Flow**
```
Contract Analysis → Signature Detection → AI Test Flow Planning → Stateful Testing → Reporting
```

### 2. **CLI Commands**
```bash
# Generate test flows
./bin/analyzer plan --contract vault.sol --scenarios realistic

# Execute stateful tests
./bin/analyzer test-flows --contract vault.sol --flows vault_flows.json

# Full analysis with stateful testing
./bin/analyzer analyze --contract vault.sol --stateful --ai-flows
```

### 3. **Configuration Updates**
```yaml
stateful_testing:
  enable: true
  max_setup_time: 60
  state_reset_between_tests: true
  account_funding: "100 ETH"

test_flow_planner:
  enable_ai_planning: true
  scenario_types: ["valid", "invalid", "attack", "edge_case"]
  max_scenarios: 20
```

## Success Criteria

### 1. **Functional Requirements**
- [ ] Deploy contracts with initial state
- [ ] Execute multi-step test scenarios
- [ ] Generate realistic test flows with AI
- [ ] Validate business logic beyond signatures
- [ ] Handle state dependencies correctly

### 2. **Quality Requirements**
- [ ] Tests reflect real-world usage patterns
- [ ] AI generates relevant attack scenarios
- [ ] State management is reliable and consistent
- [ ] Performance suitable for complex contracts
- [ ] Results are actionable and detailed

### 3. **Integration Requirements**
- [ ] Seamless integration with existing components
- [ ] Backward compatibility with current signature testing
- [ ] Enhanced reporting includes state analysis
- [ ] CLI provides intuitive stateful testing commands

## Future Enhancements

### 1. **Advanced AI Capabilities**
- Multi-contract interaction testing
- Economic attack simulation
- Gas optimization analysis
- Upgrade pattern testing

### 2. **Extended State Management**
- Cross-contract state dependencies
- Time-based state changes
- External oracle integration
- Multi-chain testing support

### 3. **Performance Optimizations**
- Parallel test execution
- State caching and optimization
- Selective test execution
- Result memoization

## Notes

This enhancement addresses the critical gap between technical signature validation and real-world contract behavior testing. The AI-driven test flow generation will make the tool significantly more valuable for practical security analysis by understanding and testing actual contract usage patterns and attack vectors.

The stateful testing capability will enable detection of vulnerabilities that only emerge through realistic usage sequences, making this a more comprehensive security analysis tool. 