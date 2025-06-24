// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract WeakSignerValidation_EIP2612_2 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

    
    function vulnerableApprove(address spender, uint256 amount, bytes memory signature) external  {
        // VULNERABLE: No nonce check - replay attack possible
bytes32 messageHash = keccak256(abi.encodePacked(spender, amount));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
address signer = ethSignedMessageHash.recover(signature);

// No replay protection - signature can be used multiple times
    }
    
}