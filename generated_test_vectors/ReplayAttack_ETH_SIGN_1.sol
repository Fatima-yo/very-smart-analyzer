// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ReplayAttack_ETH_SIGN_1 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    
    function approve(address spender, uint256 amount, bytes memory signature) external  {
        bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
address signer = ethSignedMessageHash.recover(signature);

// VULNERABLE: No validation of signer or replay protection
    }
    
}