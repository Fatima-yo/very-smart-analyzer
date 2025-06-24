// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract StatelessVault is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    string private constant SIGNING_DOMAIN = "Vault";
    string private constant SIGNATURE_VERSION = "1";

    mapping(address => uint256) public nonces;

    event Withdrawn(address indexed owner, address indexed to, uint256 amount);

    struct WithdrawRequest {
        address owner;
        address to;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("WithdrawRequest(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    constructor() payable EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
    }

    function withdraw(WithdrawRequest calldata req, bytes calldata signature) external nonReentrant {
        require(req.deadline >= block.timestamp, "Request expired");
        require(nonces[req.owner] == req.nonce, "Invalid nonce");

        bytes32 structHash = keccak256(abi.encode(
            WITHDRAW_TYPEHASH,
            req.owner,
            req.to,
            req.amount,
            req.nonce,
            req.deadline
        ));

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        require(signer == req.owner, "Invalid signature");

        // Increment nonce
        nonces[req.owner]++;

        emit Withdrawn(req.owner, req.to, req.amount);
    }

    // Allow deposits
    receive() external payable {}
}
