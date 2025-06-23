// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract TestSignatureContract is EIP712 {
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

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    constructor() EIP712("TestSignatureContract", "1") {}

    // Function with combined signature parameter
    function approveWithSignature(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // Check if signature is already used
        require(!usedHashes[messageHash], "Signature already used");
        usedHashes[messageHash] = true;
        
        // Approve the spender
        // This is a simplified version - in real contracts you'd have actual approval logic
    }

    // Function with EIP712 permit
    function permit(
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
        
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        
        // Approve the spender
        // This is a simplified version - in real contracts you'd have actual approval logic
    }

    // Function with missing nonce protection (vulnerable)
    function vulnerableApprove(
        address spender,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // Missing nonce check - vulnerable to replay attacks
        // Approve the spender
    }

    // Function with missing deadline protection (vulnerable)
    function vulnerablePermit(
        address owner,
        address spender,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, 0) // No deadline
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        
        // Approve the spender
    }
} 