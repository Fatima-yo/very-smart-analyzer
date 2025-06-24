// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestCases {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedSignatures;

    // Basic signature verification function for testing
    function verifySignature(bytes32 messageHash, bytes memory signature) public pure returns (address) {
        if (signature.length == 0) {
            revert("Empty signature");
        }
        // If signature is not 65 bytes, revert (mimic ECDSA)
        if (signature.length != 65) {
            revert("Invalid signature length");
        }
        // If all bytes are zero, revert (zero address)
        bool allZero = true;
        for (uint i = 0; i < signature.length; i++) {
            if (signature[i] != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            revert("Zero address signature");
        }
        // For testing, return a pseudo address based on the hash of the signature
        return address(uint160(uint256(keccak256(signature))));
    }

    // Function to execute with signature (for replay attack testing)
    function executeWithSignature(bytes32 messageHash, bytes memory signature, uint256 nonce) public {
        address signer = verifySignature(messageHash, signature);
        
        require(signer != address(0), "Invalid signer");
        
        // Check for replay attack
        bytes32 signatureHash = keccak256(signature);
        require(!usedSignatures[signatureHash], "Signature already used");
        usedSignatures[signatureHash] = true;
        
        // Missing nonce check - vulnerable to replay attacks
    }

    // Function to execute with deadline (for timing attack testing)
    function executeWithDeadline(bytes32 messageHash, bytes memory signature, uint256 deadline) public {
        address signer = verifySignature(messageHash, signature);
        
        require(signer != address(0), "Invalid signer");
        
        // Check deadline
        require(deadline >= block.timestamp, "Deadline expired");
    }

    // Function to execute with nonce (for entropy attack testing)
    function executeWithNonce(bytes32 messageHash, bytes memory signature, uint256 nonce) public {
        address signer = verifySignature(messageHash, signature);
        
        require(signer != address(0), "Invalid signer");
        
        // Check nonce
        require(nonce == nonces[signer], "Invalid nonce");
        nonces[signer]++;
    }

    // Function to execute with chain ID (for cross-chain attack testing)
    function executeWithChainId(bytes32 messageHash, bytes memory signature, uint256 chainId) public {
        address signer = verifySignature(messageHash, signature);
        
        require(signer != address(0), "Invalid signer");
        
        // Check chain ID (hardcoded for testing)
        require(chainId == 1337, "Invalid chain ID");
    }

    // Function to execute with amount (for edge case testing)
    function executeWithAmount(bytes32 messageHash, bytes memory signature, uint256 amount) public {
        address signer = verifySignature(messageHash, signature);
        
        require(signer != address(0), "Invalid signer");
        
        // Check amount
        require(amount > 0, "Amount must be greater than 0");
    }

    // Function to execute multi-sig (for multi-sig attack testing)
    function executeMultiSig(bytes32 messageHash, bytes[] memory signatures, uint256 requiredSignatures) public {
        require(signatures.length >= requiredSignatures, "Insufficient signatures");
        
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            signers[i] = verifySignature(messageHash, signatures[i]);
            require(signers[i] != address(0), "Invalid signer");
        }
        
        // Check for duplicate signers
        for (uint256 i = 0; i < signers.length; i++) {
            for (uint256 j = i + 1; j < signers.length; j++) {
                require(signers[i] != signers[j], "Duplicate signer");
            }
        }
    }

    // Function to verify EIP712 signature (for format validation testing)
    function verifyEIP712Signature(bytes memory structData) public pure returns (address) {
        // This is a simplified version - in real implementation would use EIP712
        if (structData.length == 0) {
            revert("Empty struct data");
        }
        
        bytes32 hash = keccak256(structData);
        return address(uint160(uint256(hash)));
    }

    // VULNERABLE: No nonce check - replay attack possible
    function deposit(address to, uint256 amount, bytes memory signature) public {
        address signer = verifySignature(keccak256(abi.encodePacked(to, amount)), signature);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
        // Missing: nonces[signer]++ or replay protection
    }

    // VULNERABLE: Missing deadline check
    function permit(address owner, address spender, uint256 value, uint256 nonce, uint256 deadline, bytes memory signature) public {
        bytes32 structHash = keccak256(abi.encode(owner, spender, value, nonce, deadline));
        address signer = verifySignature(structHash, signature);
        
        require(signer == owner, "Invalid signature");
        require(nonce == nonces[owner], "Invalid nonce");
        nonces[owner]++;
        
        // Missing: require(deadline >= block.timestamp, "Permit expired");
    }

    // VULNERABLE: Weak signer validation
    function approve(address spender, uint256 amount, bytes memory signature) public {
        address signer = verifySignature(keccak256(abi.encodePacked(spender, amount)), signature);
        
        // Missing: require(signer != address(0), "Invalid signer");
        // Missing: require(signer == msg.sender, "Invalid signer");
        
        // No validation at all - any valid signature works
    }
} 