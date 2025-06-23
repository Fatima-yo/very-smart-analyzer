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

type SignatureType struct {
	Kind        SignatureKind `json:"kind"`
	Description string        `json:"description"`
}

type SignatureField struct {
	Name         string `json:"name"`
	SolType      string `json:"solType"`
	Source       string `json:"source,omitempty"`
	SignerRole   string `json:"signerRole,omitempty"`
	ParentStruct string `json:"parentStruct,omitempty"`
}

type SignatureFieldsStruct struct {
	Structured bool             `json:"structured"`
	StructName string           `json:"structName,omitempty"`
	Fields     []SignatureField `json:"fields"`
}

type SignatureFunction struct {
	FunctionName     string                `json:"functionName"`
	FunctionSelector string                `json:"functionSelector"`
	SignatureType    SignatureType         `json:"signatureType"`
	Nonce            *SignatureField       `json:"nonce,omitempty"`
	Timestamp        *SignatureField       `json:"timestamp,omitempty"`
	Deadline         *SignatureField       `json:"deadline,omitempty"`
	DomainSeparator  *SignatureField       `json:"domainSeparator,omitempty"`
	SignatureFields  SignatureFieldsStruct `json:"signatureFields"`
	Signature        []SignatureField      `json:"signature,omitempty"`
	V                []SignatureField      `json:"v,omitempty"`
	R                []SignatureField      `json:"r,omitempty"`
	S                []SignatureField      `json:"s,omitempty"`
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
		if len(fn.Signature) == 0 && len(fn.V) == 0 && len(fn.R) == 0 && len(fn.S) == 0 {
			fmt.Println("  ⚠️  No signature input found")
		}
		fmt.Println()
	}
}
