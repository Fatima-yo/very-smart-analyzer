// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestSignatureContract {
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;

    event SignatureVerified(address signer, bytes32 messageHash);
    
    constructor() {}

    // Simple signature verification function
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature
    ) external returns (bool) {
        // Check if signature is already used (replay protection)
        require(!usedHashes[messageHash], "Signature already used");
        
        // Mark signature as used
        usedHashes[messageHash] = true;
        
        // Extract signature components
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Recover signer address
        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        
        emit SignatureVerified(signer, messageHash);
        return true;
    }

    // Function with nonce-based protection
    function executeWithNonce(
        bytes32 messageHash,
        bytes memory signature,
        uint256 nonce
    ) external returns (bool) {
        // Check nonce
        require(nonces[msg.sender] == nonce, "Invalid nonce");
        nonces[msg.sender]++;
        
        // Verify signature (inline to avoid recursion)
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        
        emit SignatureVerified(signer, messageHash);
        return true;
    }

    // Vulnerable function without replay protection
    function vulnerableVerify(
        bytes32 messageHash,
        bytes memory signature
    ) external returns (bool) {
        // No replay protection - vulnerable!
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        address signer = ecrecover(messageHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        
        return true;
    }
    
    // Get current nonce for an address
    function getCurrentNonce(address account) external view returns (uint256) {
        return nonces[account];
    }
} 