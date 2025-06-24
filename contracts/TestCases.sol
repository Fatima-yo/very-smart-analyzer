// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestCases {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;
    
    // Test Case 1: SECURE - EIP712-style with all protections
    struct SecurePermit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
    
    function securePermit(SecurePermit memory permit, bytes memory signature) public {
        require(permit.deadline >= block.timestamp, "Permit expired");
        require(permit.nonce == nonces[permit.owner], "Invalid nonce");
        
        bytes32 structHash = keccak256(abi.encode(permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(structHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == permit.owner, "Invalid signature");
        require(signer != address(0), "Invalid signer");
        
        nonces[permit.owner]++;
        balances[permit.owner] += permit.value;
    }
    
    // Test Case 2: VULNERABLE - Missing nonce check (replay attack)
    function vulnerableDeposit(address to, uint256 amount, bytes memory signature) public {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
        // Missing: nonces[signer]++ or replay protection
    }
    
    // Test Case 3: VULNERABLE - Missing deadline check
    struct VulnerablePermit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
    
    function vulnerablePermit(VulnerablePermit memory permit, bytes memory signature) public {
        require(permit.nonce == nonces[permit.owner], "Invalid nonce");
        // Missing: require(permit.deadline >= block.timestamp, "Permit expired");
        
        bytes32 structHash = keccak256(abi.encode(permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(structHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == permit.owner, "Invalid signature");
        nonces[permit.owner]++;
    }
    
    // Test Case 4: VULNERABLE - Weak signer validation
    function weakApproval(address spender, uint256 amount, bytes memory signature) public {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        // Missing: require(signer != address(0), "Invalid signer");
        // Missing: require(signer == msg.sender, "Invalid signer");
        
        // No validation at all - any valid signature works
    }
    
    // Test Case 5: SECURE - EIP191 personal sign with nonce
    function securePersonalSign(address to, uint256 amount, uint256 nonce, bytes memory signature) public {
        require(nonce == nonces[to], "Invalid nonce");
        
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount, nonce));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == to, "Invalid signature");
        require(signer != address(0), "Invalid signer");
        
        nonces[to]++;
        balances[to] += amount;
    }
    
    // Test Case 6: VULNERABLE - No chain ID protection
    function noChainIdProtection(address to, uint256 amount, bytes memory signature) public {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
        // Missing: chain ID validation for cross-chain replay protection
    }
    
    // Test Case 7: SECURE - EIP2612-style permit with domain separator
    struct EIP2612Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
    
    function eip2612Permit(EIP2612Permit memory permit, bytes memory signature) public {
        require(permit.deadline >= block.timestamp, "Permit expired");
        require(permit.nonce == nonces[permit.owner], "Invalid nonce");
        
        bytes32 structHash = keccak256(abi.encode(permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(structHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == permit.owner, "Invalid signature");
        require(signer != address(0), "Invalid signer");
        
        nonces[permit.owner]++;
    }
    
    // Test Case 8: VULNERABLE - Unsafe signature recovery
    function unsafeRecovery(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        
        // Unsafe: no validation of v, r, s values
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
    }
    
    // Test Case 9: SECURE - Multi-signature with threshold
    struct MultiSigRequest {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        bytes data;
    }
    
    function multiSigExecute(MultiSigRequest memory request, bytes[] memory signatures) public {
        require(request.deadline >= block.timestamp, "Request expired");
        require(request.nonce == nonces[address(this)], "Invalid nonce");
        require(signatures.length >= request.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("MultiSigRequest(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,bytes data)"),
            keccak256(abi.encodePacked(request.signers)),
            request.threshold,
            request.nonce,
            request.deadline,
            keccak256(request.data)
        ));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = recover(ethSignedMessageHash, signatures[i]);
            require(recoveredSigners[i] != address(0), "Invalid signer");
        }
        
        // Verify threshold and unique signers
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            bool isValidSigner = false;
            for (uint j = 0; j < request.signers.length; j++) {
                if (recoveredSigners[i] == request.signers[j]) {
                    isValidSigner = true;
                    break;
                }
            }
            if (isValidSigner) validSigners++;
        }
        
        require(validSigners >= request.threshold, "Insufficient valid signatures");
        nonces[address(this)]++;
    }
    
    // Test Case 10: VULNERABLE - Insufficient entropy in signature scheme
    function lowEntropySignature(address to, uint256 amount, uint256 timestamp, bytes memory signature) public {
        // Low entropy: only timestamp as entropy source
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount, timestamp));
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        address signer = recover(ethSignedMessageHash, signature);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
        // Missing: nonce, chain ID, or other entropy sources
    }
    
    // Helper function for EIP191 personal sign
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    
    // Helper function for signature recovery
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature 'v' value");
        
        return ecrecover(hash, v, r, s);
    }
} 