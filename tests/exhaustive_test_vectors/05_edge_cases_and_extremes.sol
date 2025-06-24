// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * Edge Cases and Extremes Test Contract
 * Covers: Empty arrays, maximum values, zero addresses, invalid signatures
 * Scenarios: Boundary conditions, error cases, extreme inputs
 */

contract EdgeCasesAndExtremes is EIP712 {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    struct ExtremeStruct {
        uint256 maxValue;
        uint256 zeroValue;
        address zeroAddress;
        address maxAddress;
        bytes emptyBytes;
        string emptyString;
    }

    struct BoundaryStruct {
        uint8 minUint8;
        uint8 maxUint8;
        uint256 minUint256;
        uint256 maxUint256;
        int256 minInt256;
        int256 maxInt256;
    }

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public constant EXTREME_STRUCT_TYPEHASH = keccak256(
        "ExtremeStruct(uint256 maxValue,uint256 zeroValue,address zeroAddress,address maxAddress,bytes emptyBytes,string emptyString)"
    );

    bytes32 public constant BOUNDARY_STRUCT_TYPEHASH = keccak256(
        "BoundaryStruct(uint8 minUint8,uint8 maxUint8,uint256 minUint256,uint256 maxUint256,int256 minInt256,int256 maxInt256)"
    );

    constructor() EIP712("EdgeCasesAndExtremes", "1") {}

    // ===== EDGE CASE 1: EMPTY ARRAYS =====
    
    function emptyArraySignatures(
        bytes[] memory signatures
    ) external {
        // EDGE CASE: Empty array of signatures
        require(signatures.length == 0, "Expected empty array");
        // This should be handled gracefully
    }

    function emptyArraySigners(
        address[] memory signers,
        bytes[] memory signatures
    ) external {
        // EDGE CASE: Empty array of signers
        require(signers.length == 0, "Expected empty signers");
        require(signatures.length == 0, "Expected empty signatures");
        // Should handle gracefully
    }

    // ===== EDGE CASE 2: ZERO ADDRESSES =====
    
    function zeroAddressSigner(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        // EDGE CASE: Zero address as signer
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // signer could be address(0) - should be validated
        require(signer != address(0), "Invalid signer");
    }

    function zeroAddressInStruct(
        Permit memory permit,
        bytes memory signature
    ) external {
        // EDGE CASE: Zero address in struct
        require(permit.owner != address(0), "Invalid owner");
        require(permit.spender != address(0), "Invalid spender");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== EDGE CASE 3: MAXIMUM VALUES =====
    
    function maximumValues(
        uint256 maxAmount,
        bytes memory signature
    ) external {
        // EDGE CASE: Maximum uint256 value
        require(maxAmount == type(uint256).max, "Expected max value");
        
        bytes32 messageHash = keccak256(abi.encodePacked(maxAmount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    function maximumAddress(
        address maxAddr,
        uint256 amount,
        bytes memory signature
    ) external {
        // EDGE CASE: Maximum address value
        require(maxAddr == address(type(uint160).max), "Expected max address");
        
        bytes32 messageHash = keccak256(abi.encodePacked(maxAddr, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== EDGE CASE 4: ZERO VALUES =====
    
    function zeroValues(
        uint256 zeroAmount,
        bytes memory signature
    ) external {
        // EDGE CASE: Zero values
        require(zeroAmount == 0, "Expected zero value");
        
        bytes32 messageHash = keccak256(abi.encodePacked(zeroAmount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    function zeroNonce(
        Permit memory permit,
        bytes memory signature
    ) external {
        // EDGE CASE: Zero nonce
        require(permit.nonce == 0, "Expected zero nonce");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== EDGE CASE 5: INVALID SIGNATURE VALUES =====
    
    function invalidSignatureValues(
        address spender,
        uint256 amount,
        uint8 invalidV,
        bytes32 r,
        bytes32 s
    ) external {
        // EDGE CASE: Invalid v value
        require(invalidV != 27 && invalidV != 28, "Expected invalid v");
        
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ecrecover(ethSignedMessageHash, invalidV, r, s);
        
        // signer could be address(0) - should be validated
        require(signer != address(0), "Invalid signature");
    }

    function zeroSignatureComponents(
        address spender,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // EDGE CASE: Zero r or s values
        require(r != bytes32(0), "Expected non-zero r");
        require(s != bytes32(0), "Expected non-zero s");
        
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        require(signer != address(0), "Invalid signature");
    }

    // ===== EDGE CASE 6: EMPTY BYTES AND STRINGS =====
    
    function emptyBytesSignature(
        bytes memory emptySignature
    ) external {
        // EDGE CASE: Empty signature bytes
        require(emptySignature.length == 0, "Expected empty signature");
        
        // This should be handled gracefully or rejected
        // In practice, empty signatures are invalid
    }

    function emptyStringInStruct(
        Permit memory permit,
        string memory emptyString,
        bytes memory signature
    ) external {
        // EDGE CASE: Empty string in struct
        require(bytes(emptyString).length == 0, "Expected empty string");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== EDGE CASE 7: BOUNDARY VALUES =====
    
    function boundaryValues(
        BoundaryStruct memory boundary,
        bytes memory signature
    ) external {
        // EDGE CASE: Boundary values
        require(boundary.minUint8 == 0, "Expected min uint8");
        require(boundary.maxUint8 == 255, "Expected max uint8");
        require(boundary.minUint256 == 0, "Expected min uint256");
        require(boundary.maxUint256 == type(uint256).max, "Expected max uint256");
        require(boundary.minInt256 == type(int256).min, "Expected min int256");
        require(boundary.maxInt256 == type(int256).max, "Expected max int256");
        
        bytes32 structHash = keccak256(
            abi.encode(BOUNDARY_STRUCT_TYPEHASH, boundary.minUint8, boundary.maxUint8, boundary.minUint256, boundary.maxUint256, boundary.minInt256, boundary.maxInt256)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer != address(0), "Invalid signature");
    }

    // ===== EDGE CASE 8: EXTREME STRUCT VALUES =====
    
    function extremeStructValues(
        ExtremeStruct memory extreme,
        bytes memory signature
    ) external {
        // EDGE CASE: Extreme struct values
        require(extreme.maxValue == type(uint256).max, "Expected max value");
        require(extreme.zeroValue == 0, "Expected zero value");
        require(extreme.zeroAddress == address(0), "Expected zero address");
        require(extreme.maxAddress == address(type(uint160).max), "Expected max address");
        require(extreme.emptyBytes.length == 0, "Expected empty bytes");
        require(bytes(extreme.emptyString).length == 0, "Expected empty string");
        
        bytes32 structHash = keccak256(
            abi.encode(EXTREME_STRUCT_TYPEHASH, extreme.maxValue, extreme.zeroValue, extreme.zeroAddress, extreme.maxAddress, keccak256(extreme.emptyBytes), keccak256(bytes(extreme.emptyString)))
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer != address(0), "Invalid signature");
    }

    // ===== EDGE CASE 9: EXPIRED DEADLINES =====
    
    function expiredDeadline(
        Permit memory permit,
        bytes memory signature
    ) external {
        // EDGE CASE: Expired deadline
        require(permit.deadline < block.timestamp, "Expected expired deadline");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
        // Should reject due to expired deadline
    }

    function farFutureDeadline(
        Permit memory permit,
        bytes memory signature
    ) external {
        // EDGE CASE: Far future deadline
        require(permit.deadline > block.timestamp + 365 days, "Expected far future deadline");
        
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== EDGE CASE 10: DUPLICATE SIGNATURES =====
    
    function duplicateSignatures(
        address spender,
        uint256 amount,
        bytes memory signature1,
        bytes memory signature2
    ) external {
        // EDGE CASE: Duplicate signatures
        require(keccak256(signature1) == keccak256(signature2), "Expected duplicate signatures");
        
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ethSignedMessageHash.recover(signature1);
        address signer2 = ethSignedMessageHash.recover(signature2);
        
        require(signer1 == signer2, "Signers should be identical");
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== EDGE CASE 11: MALLEABLE SIGNATURES =====
    
    function malleableSignatures(
        address spender,
        uint256 amount,
        uint8 v1, bytes32 r1, bytes32 s1,
        uint8 v2, bytes32 r2, bytes32 s2
    ) external {
        // EDGE CASE: Malleable signature pairs
        require(r1 == r2, "Expected same r");
        require(s1 != s2, "Expected different s");
        require(v1 != v2, "Expected different v");
        
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ecrecover(ethSignedMessageHash, v1, r1, s1);
        address signer2 = ecrecover(ethSignedMessageHash, v2, r2, s2);
        
        require(signer1 == signer2, "Malleable signatures should have same signer");
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== EDGE CASE 12: INVALID EIP712 DOMAIN =====
    
    function invalidEIP712Domain(
        Permit memory permit,
        bytes memory signature
    ) external {
        // EDGE CASE: Invalid EIP712 domain
        // This would require a different contract with different domain
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = hash.recover(signature);
        require(signer == permit.owner, "Invalid signature");
    }

    // ===== EDGE CASE 13: OVERFLOW VALUES =====
    
    function overflowValues(
        uint256 overflowAmount,
        bytes memory signature
    ) external {
        // EDGE CASE: Values that could cause overflow
        require(overflowAmount > type(uint256).max - 1, "Expected overflow-prone value");
        
        bytes32 messageHash = keccak256(abi.encodePacked(overflowAmount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== EDGE CASE 14: UNDERFLOW VALUES =====
    
    function underflowValues(
        int256 underflowAmount,
        bytes memory signature
    ) external {
        // EDGE CASE: Values that could cause underflow
        require(underflowAmount < type(int256).min + 1, "Expected underflow-prone value");
        
        bytes32 messageHash = keccak256(abi.encodePacked(underflowAmount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }

    // ===== EDGE CASE 15: MIXED EDGE CASES =====
    
    function mixedEdgeCases(
        address[] memory emptySigners,
        bytes[] memory emptySignatures,
        uint256 maxValue,
        uint256 zeroValue,
        address zeroAddr,
        bytes memory signature
    ) external {
        // EDGE CASE: Multiple edge cases combined
        require(emptySigners.length == 0, "Expected empty signers");
        require(emptySignatures.length == 0, "Expected empty signatures");
        require(maxValue == type(uint256).max, "Expected max value");
        require(zeroValue == 0, "Expected zero value");
        require(zeroAddr == address(0), "Expected zero address");
        
        bytes32 messageHash = keccak256(abi.encodePacked(maxValue, zeroValue, zeroAddr));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(signer != address(0), "Invalid signature");
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
    }
} 