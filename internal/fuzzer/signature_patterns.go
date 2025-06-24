package fuzzer

import (
	"fmt"
)

// SignaturePattern defines a specific signature verification pattern
type SignaturePattern struct {
	Name        string
	Description string
	Template    string
	Functions   []FunctionPattern
	Structs     []StructPattern
	Imports     []string
}

// FunctionPattern defines a function with specific vulnerabilities
type FunctionPattern struct {
	Name            string
	Parameters      []FunctionParameter
	ReturnType      string
	Implementation  string
	Vulnerabilities []Vulnerability
	EdgeCases       []EdgeCase
}

// FunctionParameter defines a function parameter
type FunctionParameter struct {
	Name string
	Type string
}

// StructPattern defines a struct with specific characteristics
type StructPattern struct {
	Name   string
	Fields []FunctionParameter
}

// SignaturePatternRegistry holds all available signature patterns
type SignaturePatternRegistry struct {
	patterns map[string]*SignaturePattern
}

// NewSignaturePatternRegistry creates a new pattern registry
func NewSignaturePatternRegistry() *SignaturePatternRegistry {
	spr := &SignaturePatternRegistry{
		patterns: make(map[string]*SignaturePattern),
	}
	spr.registerPatterns()
	return spr
}

// GetPattern retrieves a pattern by name
func (spr *SignaturePatternRegistry) GetPattern(name string) (*SignaturePattern, error) {
	pattern, exists := spr.patterns[name]
	if !exists {
		return nil, fmt.Errorf("pattern %s not found", name)
	}
	return pattern, nil
}

// ListPatterns returns all available patterns
func (spr *SignaturePatternRegistry) ListPatterns() []string {
	patterns := make([]string, 0, len(spr.patterns))
	for name := range spr.patterns {
		patterns = append(patterns, name)
	}
	return patterns
}

// registerPatterns registers all available signature patterns
func (spr *SignaturePatternRegistry) registerPatterns() {
	// EIP712 Combined Single
	spr.patterns["eip712_combined_single"] = &SignaturePattern{
		Name:        "EIP712 Combined Single",
		Description: "EIP712 signature with combined encoding and single signature",
		Template:    eip712CombinedSingleTemplate,
		Functions: []FunctionPattern{
			{
				Name: "permit",
				Parameters: []FunctionParameter{
					{Name: "permit", Type: "Permit memory"},
					{Name: "signature", Type: "bytes memory"},
				},
				ReturnType: "",
				Implementation: `require(permit.deadline >= block.timestamp, "Permit expired");

bytes32 structHash = keccak256(
    abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
);
bytes32 hash = _hashTypedDataV4(structHash);

address signer = hash.recover(signature);
require(signer == permit.owner, "Invalid signature");`,
				Vulnerabilities: []Vulnerability{},
				EdgeCases:       []EdgeCase{},
			},
		},
		Structs: []StructPattern{
			{
				Name: "Permit",
				Fields: []FunctionParameter{
					{Name: "owner", Type: "address"},
					{Name: "spender", Type: "address"},
					{Name: "value", Type: "uint256"},
					{Name: "nonce", Type: "uint256"},
					{Name: "deadline", Type: "uint256"},
				},
			},
		},
		Imports: []string{
			"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
			"@openzeppelin/contracts/utils/cryptography/EIP712.sol",
		},
	}

	// EIP712 Combined Multiple
	spr.patterns["eip712_combined_multiple"] = &SignaturePattern{
		Name:        "EIP712 Combined Multiple",
		Description: "EIP712 signature with combined encoding and multiple signatures",
		Template:    eip712CombinedMultipleTemplate,
		Functions: []FunctionPattern{
			{
				Name: "permitMultiple",
				Parameters: []FunctionParameter{
					{Name: "permit1", Type: "Permit memory"},
					{Name: "permit2", Type: "Permit memory"},
					{Name: "signature1", Type: "bytes memory"},
					{Name: "signature2", Type: "bytes memory"},
				},
				ReturnType: "",
				Implementation: `require(permit1.deadline >= block.timestamp, "Permit1 expired");
require(permit2.deadline >= block.timestamp, "Permit2 expired");

bytes32 structHash1 = keccak256(
    abi.encode(PERMIT_TYPEHASH, permit1.owner, permit1.spender, permit1.value, nonces[permit1.owner]++, permit1.deadline)
);
bytes32 hash1 = _hashTypedDataV4(structHash1);

bytes32 structHash2 = keccak256(
    abi.encode(PERMIT_TYPEHASH, permit2.owner, permit2.spender, permit2.value, nonces[permit2.owner]++, permit2.deadline)
);
bytes32 hash2 = _hashTypedDataV4(structHash2);

address signer1 = hash1.recover(signature1);
address signer2 = hash2.recover(signature2);

require(signer1 == permit1.owner, "Invalid signature1");
require(signer2 == permit2.owner, "Invalid signature2");`,
				Vulnerabilities: []Vulnerability{},
				EdgeCases:       []EdgeCase{},
			},
		},
		Structs: []StructPattern{
			{
				Name: "Permit",
				Fields: []FunctionParameter{
					{Name: "owner", Type: "address"},
					{Name: "spender", Type: "address"},
					{Name: "value", Type: "uint256"},
					{Name: "nonce", Type: "uint256"},
					{Name: "deadline", Type: "uint256"},
				},
			},
		},
		Imports: []string{
			"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
			"@openzeppelin/contracts/utils/cryptography/EIP712.sol",
		},
	}

	// ETH Sign Combined Single
	spr.patterns["eth_sign_combined_single"] = &SignaturePattern{
		Name:        "ETH Sign Combined Single",
		Description: "Ethereum personal message signing with combined encoding",
		Template:    ethSignCombinedSingleTemplate,
		Functions: []FunctionPattern{
			{
				Name: "approve",
				Parameters: []FunctionParameter{
					{Name: "spender", Type: "address"},
					{Name: "amount", Type: "uint256"},
					{Name: "signature", Type: "bytes memory"},
				},
				ReturnType: "",
				Implementation: `bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
address signer = ethSignedMessageHash.recover(signature);

// VULNERABLE: No validation of signer or replay protection`,
				Vulnerabilities: []Vulnerability{WeakSignerValidation, ReplayAttackVuln},
				EdgeCases:       []EdgeCase{ZeroAddresses, EmptyBytesStrings},
			},
		},
		Structs: []StructPattern{},
		Imports: []string{
			"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
		},
	}

	// Missing Nonce Vulnerability
	spr.patterns["missing_nonce"] = &SignaturePattern{
		Name:        "Missing Nonce",
		Description: "Signature verification without nonce protection",
		Template:    missingNonceTemplate,
		Functions: []FunctionPattern{
			{
				Name: "vulnerableApprove",
				Parameters: []FunctionParameter{
					{Name: "spender", Type: "address"},
					{Name: "amount", Type: "uint256"},
					{Name: "signature", Type: "bytes memory"},
				},
				ReturnType: "",
				Implementation: `// VULNERABLE: No nonce check - replay attack possible
bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
address signer = ethSignedMessageHash.recover(signature);

// No replay protection - signature can be used multiple times`,
				Vulnerabilities: []Vulnerability{MissingNonce, ReplayAttackVuln},
				EdgeCases:       []EdgeCase{ZeroAddresses, DuplicateSignatures},
			},
		},
		Structs: []StructPattern{},
		Imports: []string{
			"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
		},
	}

	// Missing Deadline Vulnerability
	spr.patterns["missing_deadline"] = &SignaturePattern{
		Name:        "Missing Deadline",
		Description: "EIP712 permit without deadline validation",
		Template:    missingDeadlineTemplate,
		Functions: []FunctionPattern{
			{
				Name: "vulnerablePermit",
				Parameters: []FunctionParameter{
					{Name: "permit", Type: "Permit memory"},
					{Name: "signature", Type: "bytes memory"},
				},
				ReturnType: "",
				Implementation: `// VULNERABLE: No deadline validation
bytes32 structHash = keccak256(
    abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
);
bytes32 hash = _hashTypedDataV4(structHash);

address signer = hash.recover(signature);
require(signer == permit.owner, "Invalid signature");

// Missing: require(permit.deadline >= block.timestamp, "Permit expired");`,
				Vulnerabilities: []Vulnerability{MissingDeadline},
				EdgeCases:       []EdgeCase{ExpiredDeadlines},
			},
		},
		Structs: []StructPattern{
			{
				Name: "Permit",
				Fields: []FunctionParameter{
					{Name: "owner", Type: "address"},
					{Name: "spender", Type: "address"},
					{Name: "value", Type: "uint256"},
					{Name: "nonce", Type: "uint256"},
					{Name: "deadline", Type: "uint256"},
				},
			},
		},
		Imports: []string{
			"@openzeppelin/contracts/utils/cryptography/ECDSA.sol",
			"@openzeppelin/contracts/utils/cryptography/EIP712.sol",
		},
	}
}

// Template strings for different patterns
const eip712CombinedSingleTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract {{.Name}} is EIP712 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("{{.Name}}", "1") {}

    {{range .Functions}}
    function {{.Name}}({{range $i, $param := .Parameters}}{{if $i}}, {{end}}{{$param.Type}} {{$param.Name}}{{end}}) external {{if .ReturnType}}returns ({{.ReturnType}}){{end}} {
        {{.Implementation}}
    }
    {{end}}
}`

const eip712CombinedMultipleTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract {{.Name}} is EIP712 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("{{.Name}}", "1") {}

    {{range .Functions}}
    function {{.Name}}({{range $i, $param := .Parameters}}{{if $i}}, {{end}}{{$param.Type}} {{$param.Name}}{{end}}) external {{if .ReturnType}}returns ({{.ReturnType}}){{end}} {
        {{.Implementation}}
    }
    {{end}}
}`

const ethSignCombinedSingleTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract {{.Name}} {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    {{range .Functions}}
    function {{.Name}}({{range $i, $param := .Parameters}}{{if $i}}, {{end}}{{$param.Type}} {{$param.Name}}{{end}}) external {{if .ReturnType}}returns ({{.ReturnType}}){{end}} {
        {{.Implementation}}
    }
    {{end}}
}`

const missingNonceTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract {{.Name}} {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    {{range .Functions}}
    function {{.Name}}({{range $i, $param := .Parameters}}{{if $i}}, {{end}}{{$param.Type}} {{$param.Name}}{{end}}) external {{if .ReturnType}}returns ({{.ReturnType}}){{end}} {
        {{.Implementation}}
    }
    {{end}}
}`

const missingDeadlineTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract {{.Name}} is EIP712 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    {{range .Structs}}
    struct {{.Name}} {
        {{range $i, $field := .Fields}}{{if $i}}
        {{end}}        {{$field.Type}} {{$field.Name}};{{end}}
    }
    {{end}}

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("{{.Name}}", "1") {}

    {{range .Functions}}
    function {{.Name}}({{range $i, $param := .Parameters}}{{if $i}}, {{end}}{{$param.Type}} {{$param.Name}}{{end}}) external {{if .ReturnType}}returns ({{.ReturnType}}){{end}} {
        {{.Implementation}}
    }
    {{end}}
}`
