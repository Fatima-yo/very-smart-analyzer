// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * Basic Signature Types Test Contract
 * Covers: EIP712, ETH_SIGN, EIP191_PERSONAL_SIGN, EIP2612, EIP1271, CUSTOM
 * Encodings: Combined (bytes), Split (v,r,s)
 * Arity: Single, Multiple
 */

contract BasicSignatureTypes is EIP712 {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;

    // ===== EIP712 STRUCTS =====
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    struct MultiPermit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
        uint256 salt;
    }

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant MULTI_PERMIT_TYPEHASH = keccak256(
        "MultiPermit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline,uint256 salt)"
    );

    constructor() EIP712("BasicSignatureTypes", "1") {}

    // ===== EIP712 - COMBINED SIGNATURE =====
    function eip712CombinedSingle(
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

    function eip712CombinedMultiple(
        Permit memory permit1,
        Permit memory permit2,
        bytes memory signature1,
        bytes memory signature2
    ) external {
        require(permit1.deadline >= block.timestamp, "Permit1 expired");
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
        require(signer2 == permit2.owner, "Invalid signature2");
    }

    // ===== EIP712 - SPLIT SIGNATURE =====
    function eip712SplitSingle(
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

    function eip712SplitMultiple(
        Permit memory permit1,
        Permit memory permit2,
        uint8 v1, bytes32 r1, bytes32 s1,
        uint8 v2, bytes32 r2, bytes32 s2
    ) external {
        require(permit1.deadline >= block.timestamp, "Permit1 expired");
        require(permit2.deadline >= block.timestamp, "Permit2 expired");
        
        bytes32 structHash1 = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit1.owner, permit1.spender, permit1.value, nonces[permit1.owner]++, permit1.deadline)
        );
        bytes32 hash1 = _hashTypedDataV4(structHash1);
        
        bytes32 structHash2 = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit2.owner, permit2.spender, permit2.value, nonces[permit2.owner]++, permit2.deadline)
        );
        bytes32 hash2 = _hashTypedDataV4(structHash2);
        
        address signer1 = ecrecover(hash1, v1, r1, s1);
        address signer2 = ecrecover(hash2, v2, r2, s2);
        
        require(signer1 == permit1.owner, "Invalid signature1");
        require(signer2 == permit2.owner, "Invalid signature2");
    }

    // ===== ETH_SIGN - COMBINED SIGNATURE =====
    function ethSignCombinedSingle(
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

    function ethSignCombinedMultiple(
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

    // ===== ETH_SIGN - SPLIT SIGNATURE =====
    function ethSignSplitSingle(
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

    function ethSignSplitMultiple(
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

    // ===== EIP2612 - PERMIT PATTERN =====
    function eip2612Permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(deadline >= block.timestamp, "Permit expired");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
    }

    // ===== EIP1271 - CONTRACT SIGNATURE =====
    function eip1271ContractSignature(
        address contractSigner,
        bytes memory data,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(data);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Simulate EIP1271 validation
        require(contractSigner != address(0), "Invalid contract signer");
        // In real implementation, would call isValidSignature on the contract
    }

    // ===== CUSTOM SIGNATURE SCHEME =====
    function customSignatureScheme(
        address spender,
        uint256 amount,
        uint256 customNonce,
        uint256 salt,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount, customNonce, salt));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== MIXED SIGNATURE TYPES =====
    function mixedSignatureTypes(
        Permit memory permit,
        address spender,
        uint256 amount,
        bytes memory eip712Signature,
        bytes memory ethSignature
    ) external {
        require(permit.deadline >= block.timestamp, "Permit expired");
        
        // EIP712 validation
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address eip712Signer = hash.recover(eip712Signature);
        require(eip712Signer == permit.owner, "Invalid EIP712 signature");
        
        // ETH_SIGN validation
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address ethSigner = ethSignedMessageHash.recover(ethSignature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }
} 