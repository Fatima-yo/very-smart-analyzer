// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * Struct Location Variations Test Contract
 * Covers: Parameter, Struct Field, Array Element, Nested Structs
 * Locations: Direct parameter, Inside struct, Inside array, Nested levels
 */

contract StructLocationVariations is EIP712 {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;

    // ===== BASIC STRUCTS =====
    struct BasicPermit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureData {
        bytes signature;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // ===== NESTED STRUCTS =====
    struct NestedPermit {
        BasicPermit permit;
        uint256 extraData;
        uint256 timestamp;
    }

    struct DeepNested {
        NestedPermit nested;
        string metadata;
        uint256 version;
    }

    // ===== ARRAY STRUCTS =====
    struct ArrayElement {
        address recipient;
        uint256 amount;
        bytes signature;
    }

    struct BatchPermit {
        BasicPermit[] permits;
        bytes[] signatures;
        uint256 batchId;
    }

    // ===== COMPLEX STRUCTS =====
    struct ComplexStruct {
        BasicPermit permit;
        SignatureData sigData;
        uint256[] amounts;
        address[] recipients;
        bytes signature;
    }

    struct MultiLevelNested {
        DeepNested deep;
        ComplexStruct complex;
        uint256 salt;
        bytes signature;
    }

    bytes32 public constant BASIC_PERMIT_TYPEHASH = keccak256(
        "BasicPermit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant NESTED_PERMIT_TYPEHASH = keccak256(
        "NestedPermit(BasicPermit permit,uint256 extraData,uint256 timestamp)BasicPermit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant DEEP_NESTED_TYPEHASH = keccak256(
        "DeepNested(NestedPermit nested,string metadata,uint256 version)NestedPermit(BasicPermit permit,uint256 extraData,uint256 timestamp)BasicPermit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("StructLocationVariations", "1") {}

    // ===== CASE 1: SIGNATURE AS DIRECT PARAMETER =====
    function signatureAsParameter(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    function splitSignatureAsParameters(
        address spender,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== CASE 2: SIGNATURE INSIDE STRUCT FIELD =====
    function signatureInStructField(
        SignatureData memory sigData,
        address spender,
        uint256 amount
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(sigData.signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    function splitSignatureInStructField(
        SignatureData memory sigData,
        address spender,
        uint256 amount
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ecrecover(ethSignedMessageHash, sigData.v, sigData.r, sigData.s);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== CASE 3: SIGNATURE IN ARRAY ELEMENT =====
    function signatureInArrayElement(
        ArrayElement[] memory elements
    ) external {
        for (uint i = 0; i < elements.length; i++) {
            bytes32 messageHash = keccak256(abi.encodePacked(elements[i].recipient, elements[i].amount));
            bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
            address signer = ethSignedMessageHash.recover(elements[i].signature);
            
            require(!usedHashes[messageHash], "Signature already used");
            usedHashes[messageHash] = true;
        }
    }

    // ===== CASE 4: NESTED STRUCT WITH SIGNATURE =====
    function nestedStructWithSignature(
        NestedPermit memory nested,
        bytes memory signature
    ) external {
        require(nested.timestamp >= block.timestamp, "Timestamp expired");
        
        bytes32 permitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, nested.permit.owner, nested.permit.spender, nested.permit.value, nonces[nested.permit.owner]++, nested.permit.deadline)
        );
        
        bytes32 structHash = keccak256(
            abi.encode(NESTED_PERMIT_TYPEHASH, permitHash, nested.extraData, nested.timestamp)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == nested.permit.owner, "Invalid signature");
    }

    // ===== CASE 5: DEEP NESTED STRUCT =====
    function deepNestedStruct(
        DeepNested memory deep,
        bytes memory signature
    ) external {
        bytes32 permitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, deep.nested.permit.owner, deep.nested.permit.spender, deep.nested.permit.value, nonces[deep.nested.permit.owner]++, deep.nested.permit.deadline)
        );
        
        bytes32 nestedHash = keccak256(
            abi.encode(NESTED_PERMIT_TYPEHASH, permitHash, deep.nested.extraData, deep.nested.timestamp)
        );
        
        bytes32 structHash = keccak256(
            abi.encode(DEEP_NESTED_TYPEHASH, nestedHash, keccak256(bytes(deep.metadata)), deep.version)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == deep.nested.permit.owner, "Invalid signature");
    }

    // ===== CASE 6: COMPLEX STRUCT WITH MULTIPLE SIGNATURES =====
    function complexStructWithMultipleSignatures(
        ComplexStruct memory complex,
        bytes memory additionalSignature
    ) external {
        // First signature validation
        bytes32 permitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, complex.permit.owner, complex.permit.spender, complex.permit.value, nonces[complex.permit.owner]++, complex.permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(permitHash);
        address signer1 = hash.recover(complex.signature);
        require(signer1 == complex.permit.owner, "Invalid permit signature");
        
        // Second signature validation (split)
        bytes32 dataHash = keccak256(abi.encodePacked(complex.amounts, complex.recipients));
        bytes32 ethSignedMessageHash = dataHash.toEthSignedMessageHash();
        address signer2 = ecrecover(ethSignedMessageHash, complex.sigData.v, complex.sigData.r, complex.sigData.s);
        
        // Third signature validation
        address signer3 = ethSignedMessageHash.recover(additionalSignature);
        
        require(!usedHashes[dataHash], "Signature already used");
        usedHashes[dataHash] = true;
    }

    // ===== CASE 7: MULTI-LEVEL NESTED WITH SIGNATURE =====
    function multiLevelNestedWithSignature(
        MultiLevelNested memory multi,
        bytes memory signature
    ) external {
        // Validate deep nested permit
        bytes32 permitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, multi.deep.nested.permit.owner, multi.deep.nested.permit.spender, multi.deep.nested.permit.value, nonces[multi.deep.nested.permit.owner]++, multi.deep.nested.permit.deadline)
        );
        
        bytes32 nestedHash = keccak256(
            abi.encode(NESTED_PERMIT_TYPEHASH, permitHash, multi.deep.nested.extraData, multi.deep.nested.timestamp)
        );
        
        bytes32 deepHash = keccak256(
            abi.encode(DEEP_NESTED_TYPEHASH, nestedHash, keccak256(bytes(multi.deep.metadata)), multi.deep.version)
        );
        
        // Validate complex struct permit
        bytes32 complexPermitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, multi.complex.permit.owner, multi.complex.permit.spender, multi.complex.permit.value, nonces[multi.complex.permit.owner]++, multi.complex.permit.deadline)
        );
        
        // Combine all hashes
        bytes32 finalHash = keccak256(abi.encodePacked(deepHash, complexPermitHash, multi.salt));
        bytes32 ethSignedMessageHash = finalHash.toEthSignedMessageHash();
        
        address signer = ethSignedMessageHash.recover(signature);
        require(signer == multi.deep.nested.permit.owner, "Invalid signature");
    }

    // ===== CASE 8: BATCH PERMIT WITH ARRAY SIGNATURES =====
    function batchPermitWithArraySignatures(
        BatchPermit memory batch
    ) external {
        require(batch.permits.length == batch.signatures.length, "Length mismatch");
        
        for (uint i = 0; i < batch.permits.length; i++) {
            require(batch.permits[i].deadline >= block.timestamp, "Permit expired");
            
            bytes32 structHash = keccak256(
                abi.encode(BASIC_PERMIT_TYPEHASH, batch.permits[i].owner, batch.permits[i].spender, batch.permits[i].value, nonces[batch.permits[i].owner]++, batch.permits[i].deadline)
            );
            bytes32 hash = _hashTypedDataV4(structHash);
            
            address signer = hash.recover(batch.signatures[i]);
            require(signer == batch.permits[i].owner, "Invalid signature");
        }
    }

    // ===== CASE 9: MIXED LOCATION SIGNATURES =====
    function mixedLocationSignatures(
        BasicPermit memory permit,
        SignatureData memory sigData,
        ArrayElement[] memory elements,
        bytes memory directSignature
    ) external {
        // Direct parameter signature
        bytes32 directHash = keccak256(abi.encodePacked(permit.owner, permit.spender));
        bytes32 directEthHash = directHash.toEthSignedMessageHash();
        address directSigner = directEthHash.recover(directSignature);
        
        // Struct field signature (split)
        bytes32 structHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address structSigner = ecrecover(hash, sigData.v, sigData.r, sigData.s);
        
        // Array element signatures
        for (uint i = 0; i < elements.length; i++) {
            bytes32 arrayHash = keccak256(abi.encodePacked(elements[i].recipient, elements[i].amount));
            bytes32 arrayEthHash = arrayHash.toEthSignedMessageHash();
            address arraySigner = arrayEthHash.recover(elements[i].signature);
            
            require(!usedHashes[arrayHash], "Signature already used");
            usedHashes[arrayHash] = true;
        }
        
        require(directSigner == permit.owner, "Invalid direct signature");
        require(structSigner == permit.owner, "Invalid struct signature");
    }

    // ===== CASE 10: RECURSIVE NESTED STRUCTS =====
    struct RecursiveStruct {
        RecursiveStruct[] children;
        BasicPermit permit;
        bytes signature;
        uint256 depth;
    }

    function recursiveNestedStructs(
        RecursiveStruct memory recursive
    ) external {
        // Validate the permit at current level
        bytes32 permitHash = keccak256(
            abi.encode(BASIC_PERMIT_TYPEHASH, recursive.permit.owner, recursive.permit.spender, recursive.permit.value, nonces[recursive.permit.owner]++, recursive.permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(permitHash);
        address signer = hash.recover(recursive.signature);
        require(signer == recursive.permit.owner, "Invalid signature");
        
        // Recursively validate children (simplified for gas)
        if (recursive.children.length > 0 && recursive.depth < 3) {
            // In real implementation, would recursively call this function
            // For now, just validate the first child
            RecursiveStruct memory child = recursive.children[0];
            // Recursive validation would happen here
        }
    }
} 