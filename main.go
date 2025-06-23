package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type SignatureKind string

const (
	EIP712    SignatureKind = "EIP712"
	ETHSign   SignatureKind = "ETH_SIGN"
	EIP191    SignatureKind = "EIP191"
	CustomSig SignatureKind = "CUSTOM"
)

type TypedField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type SignatureType struct {
	Kind        SignatureKind `json:"kind"`
	Description string        `json:"description"`
}

type SignatureFunction struct {
	FunctionName      string        `json:"functionName"`
	SignatureType     SignatureType `json:"signatureType"`
	Nonce             *TypedField   `json:"nonce,omitempty"`
	Timestamp         *TypedField   `json:"timestamp,omitempty"`
	Deadline          *TypedField   `json:"deadline,omitempty"`
	DomainSeparator   *TypedField   `json:"domainSeparator,omitempty"`
	SignatureFields   []TypedField  `json:"signatureFields"`
	SignatureVariable TypedField    `json:"signatureVariable"`
}

type SignatureMetadata struct {
	SignatureFunctions []SignatureFunction `json:"signatureFunctions"`
}

func main() {
	jsonData, err := os.ReadFile("example_metadata.json")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	var metadata SignatureMetadata
	err = json.Unmarshal(jsonData, &metadata)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	for _, fn := range metadata.SignatureFunctions {
		fmt.Printf("Analyzing function: %s\n", fn.FunctionName)
		if fn.Nonce == nil {
			fmt.Println("  ⚠️  Missing nonce field")
		}
		if fn.Timestamp == nil {
			fmt.Println("  ⚠️  Missing timestamp field")
		}
		if fn.Deadline == nil {
			fmt.Println("  ⚠️  Missing deadline field")
		}
		if fn.DomainSeparator == nil {
			fmt.Println("  ⚠️  Missing domainSeparator field")
		}
		fmt.Println()
	}
}
