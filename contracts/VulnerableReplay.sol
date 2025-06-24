// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VulnerableReplay {
    using ECDSA for bytes32;
    
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    // VULNERABLE: No nonce check - replay attack possible
    function deposit(address to, uint256 amount, bytes memory signature) public {
        bytes32 messageHash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(signer == to, "Invalid signature");
        balances[to] += amount;
        // Missing: nonces[signer]++ or replay protection
    }

    // VULNERABLE: Missing deadline check
    function permit(Permit memory permit, bytes memory signature) public {
        bytes32 structHash = keccak256(
            abi.encode(permit.owner, permit.spender, permit.value, permit.nonce, permit.deadline)
        );
        bytes32 ethSignedMessageHash = structHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        require(signer == permit.owner, "Invalid signature");
        require(permit.nonce == nonces[permit.owner], "Invalid nonce");
        nonces[permit.owner]++;
        
        // Missing: require(permit.deadline >= block.timestamp, "Permit expired");
    }

    // VULNERABLE: Weak signer validation
    function approve(address spender, uint256 amount, bytes memory signature) public {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        
        // Missing: require(signer != address(0), "Invalid signer");
        // Missing: require(signer == msg.sender, "Invalid signer");
        
        // No validation at all - any valid signature works
    }
} 