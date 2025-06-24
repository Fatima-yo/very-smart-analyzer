// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract WeakSignerValidation_EIP712_0 is EIP712 {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;

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

    constructor() EIP712("WeakSignerValidation_EIP712_0", "1") {}

    
    function permit(Permit memory permit, bytes memory signature) external  {
        require(permit.deadline >= block.timestamp, "Permit expired");

bytes32 structHash = keccak256(
    abi.encode(PERMIT_TYPEHASH, permit.owner, permit.spender, permit.value, nonces[permit.owner]++, permit.deadline)
);
bytes32 hash = _hashTypedDataV4(structHash);

address signer = hash.recover(signature);
require(signer == permit.owner, "Invalid signature");
    }
    
}