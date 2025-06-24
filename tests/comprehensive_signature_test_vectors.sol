// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * Comprehensive Test Vector Contract
 * Covers all signature verification patterns for fuzz testing
 */

contract ComprehensiveSignatureTestVectors is EIP712 {
    using ECDSA for bytes32;

    // State variables for tracking
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public timestamps;

    // ===== EIP712 STRUCTS =====
    
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    struct MultiSig {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
    }

    struct NestedStruct {
        Permit permit;
        uint256 extraData;
        uint256 timestamp;
    }

    struct ArrayStruct {
        address[] recipients;
        uint256[] amounts;
        uint256 nonce;
        uint256 deadline;
    }

    // Type hashes
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant MULTISIG_TYPEHASH = keccak256(
        "MultiSig(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant NESTED_TYPEHASH = keccak256(
        "NestedStruct(Permit permit,uint256 extraData,uint256 timestamp)Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant ARRAY_STRUCT_TYPEHASH = keccak256(
        "ArrayStruct(address[] recipients,uint256[] amounts,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("ComprehensiveSignatureTestVectors", "1") {}

    // ===== CASE 1: COMBINED SIGNATURE (bytes) =====

    // Single signature, parameter location
    function singleCombinedSignature(
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

    // Multiple signatures, parameter location
    function multipleCombinedSignatures(
        address spender,
        uint256 amount,
        bytes memory signature1,
        bytes memory signature2
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ethSignedMessageHash.recover(signature1);
        address signer2 = ethSignedMessageHash.recover(signature2);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // Single signature, struct field location
    struct CombinedSignatureStruct {
        address spender;
        uint256 amount;
        bytes signature;
    }

    function combinedSignatureInStruct(
        CombinedSignatureStruct memory data
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(data.spender, data.amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(data.signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== CASE 2: SPLIT SIGNATURE (v, r, s) =====

    // Single split signature, parameter location
    function singleSplitSignature(
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

    // Multiple split signatures, parameter location
    function multipleSplitSignatures(
        address spender,
        uint256 amount,
        uint8 v1, bytes32 r1, bytes32 s1,
        uint8 v2, bytes32 r2, bytes32 s2
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ecrecover(ethSignedMessageHash, v1, r1, s1);
        address signer2 = ecrecover(ethSignedMessageHash, v2, r2, s2);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // Split signature in struct
    struct SplitSignatureStruct {
        address spender;
        uint256 amount;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    function splitSignatureInStruct(
        SplitSignatureStruct memory data
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(data.spender, data.amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ecrecover(ethSignedMessageHash, data.v, data.r, data.s);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== CASE 3: EIP712 STRUCTURED SIGNATURES =====

    // EIP712 with combined signature
    function eip712Combined(
        Permit memory permit,
        bytes memory signature
    ) external {
        require(permit.deadline >= block.timestamp, "Permit expired");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // EIP712 with split signature
    function eip712Split(
        Permit memory permit,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(permit.deadline >= block.timestamp, "Permit expired");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = ecrecover(hash, v, r, s);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== CASE 4: ARRAY OF STRUCTS =====

    // Array of structs with signatures
    struct ArrayElementStruct {
        address recipient;
        uint256 amount;
        bytes signature;
    }

    function arrayOfStructsWithSignatures(
        ArrayElementStruct[] memory elements
    ) external {
        for (uint i = 0; i < elements.length; i++) {
            bytes32 messageHash = keccak256(abi.encodePacked(elements[i].recipient, elements[i].amount));
            bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
            address signer = ethSignedMessageHash.recover(elements[i].signature);
            
            require(!usedHashes[messageHash], "Signature already used");
            usedHashes[messageHash] = true;
        }
    }

    // ===== CASE 5: NESTED STRUCTS =====

    // Nested struct with signature
    function nestedStructWithSignature(
        NestedStruct memory nested
    ) external {
        require(nested.timestamp >= block.timestamp, "Timestamp expired");
        
        bytes32 permitHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, nested.permit.owner, nested.permit.spender, nested.permit.value, nonces[nested.permit.owner]++, nested.permit.deadline)
        );
        
        bytes32 structHash = keccak256(
            abi.encode(NESTED_TYPEHASH, permitHash, nested.extraData, nested.timestamp)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        // Note: This would need a signature parameter - adding for completeness
        // address signer = hash.recover(signature);
    }

    // ===== CASE 6: VULNERABLE FUNCTIONS (Missing Controls) =====

    // Missing nonce protection
    function vulnerableNoNonce(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // VULNERABLE: No nonce check - replay attack possible
    }

    // Missing deadline protection
    function vulnerableNoDeadline(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // VULNERABLE: No deadline check - signature never expires
    }

    // Missing timestamp protection
    function vulnerableNoTimestamp(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // VULNERABLE: No timestamp check - no time-based validation
    }

    // Missing domain separator
    function vulnerableNoDomainSeparator(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // VULNERABLE: No domain separator - cross-contract replay possible
    }

    // ===== CASE 7: COMPLEX MULTI-SIGNATURE SCENARIOS =====

    // Multi-signature with threshold
    function multiSigThreshold(
        MultiSig memory multiSig,
        bytes[] memory signatures
    ) external {
        require(multiSig.deadline >= block.timestamp, "MultiSig expired");
        require(signatures.length >= multiSig.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(MULTISIG_TYPEHASH, multiSig.signers, multiSig.threshold, nonces[address(this)]++, multiSig.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        // Verify threshold and unique signers
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < multiSig.signers.length; j++) {
                if (recoveredSigners[i] == multiSig.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= multiSig.threshold, "Threshold not met");
        nonces[address(this)]++;
    }

    // ===== CASE 8: ARRAY STRUCT WITH SIGNATURES =====

    // Array struct with combined signatures
    function arrayStructWithCombinedSignatures(
        ArrayStruct memory arrayStruct,
        bytes[] memory signatures
    ) external {
        require(arrayStruct.deadline >= block.timestamp, "ArrayStruct expired");
        require(arrayStruct.recipients.length == arrayStruct.amounts.length, "Length mismatch");
        require(arrayStruct.recipients.length == signatures.length, "Signature count mismatch");
        
        for (uint i = 0; i < arrayStruct.recipients.length; i++) {
            bytes32 messageHash = keccak256(
                abi.encode(arrayStruct.recipients[i], arrayStruct.amounts[i], arrayStruct.nonce, arrayStruct.deadline)
            );
            bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
            address signer = ethSignedMessageHash.recover(signatures[i]);
            
            require(!usedHashes[messageHash], "Signature already used");
            usedHashes[messageHash] = true;
        }
    }

    // ===== CASE 9: CUSTOM SIGNATURE SCHEMES =====

    // Custom signature with additional data
    function customSignatureScheme(
        address spender,
        uint256 amount,
        uint256 customNonce,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount, customNonce));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== CASE 10: MIXED SIGNATURE TYPES =====

    // Function with both combined and split signatures
    function mixedSignatureTypes(
        address spender,
        uint256 amount,
        bytes memory combinedSignature,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ethSignedMessageHash.recover(combinedSignature);
        address signer2 = ecrecover(ethSignedMessageHash, v, r, s);
        
        require(signer1 == signer2, "Signatures must be from same signer");
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }
} 