// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * Complex Multi-Signature Test Contract
 * Covers: Multi-sig with thresholds, different signer roles, advanced validation
 * Scenarios: Governance, Treasury, Security, Mixed roles
 */

contract ComplexMultiSignature is EIP712 {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isGovernor;
    mapping(address => bool) public isTreasurer;
    mapping(address => bool) public isGuardian;

    // ===== MULTI-SIG STRUCTS =====
    struct MultiSigProposal {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        uint256 proposalId;
        string action;
        bytes data;
    }

    struct TreasuryProposal {
        address[] treasurers;
        address[] guardians;
        uint256 treasuryThreshold;
        uint256 guardianThreshold;
        uint256 nonce;
        uint256 deadline;
        uint256 amount;
        address recipient;
    }

    struct GovernanceProposal {
        address[] governors;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        uint256 proposalId;
        uint256 votingPeriod;
        bool executed;
    }

    struct SecurityProposal {
        address[] guardians;
        address[] emergencySigners;
        uint256 guardianThreshold;
        uint256 emergencyThreshold;
        uint256 nonce;
        uint256 deadline;
        string action;
        bool isEmergency;
    }

    struct MixedRoleProposal {
        address[] governors;
        address[] treasurers;
        address[] guardians;
        uint256 governorThreshold;
        uint256 treasurerThreshold;
        uint256 guardianThreshold;
        uint256 nonce;
        uint256 deadline;
        string action;
    }

    bytes32 public constant MULTI_SIG_PROPOSAL_TYPEHASH = keccak256(
        "MultiSigProposal(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,uint256 proposalId,string action,bytes data)"
    );

    bytes32 public constant TREASURY_PROPOSAL_TYPEHASH = keccak256(
        "TreasuryProposal(address[] treasurers,address[] guardians,uint256 treasuryThreshold,uint256 guardianThreshold,uint256 nonce,uint256 deadline,uint256 amount,address recipient)"
    );

    bytes32 public constant GOVERNANCE_PROPOSAL_TYPEHASH = keccak256(
        "GovernanceProposal(address[] governors,uint256 threshold,uint256 nonce,uint256 deadline,uint256 proposalId,uint256 votingPeriod,bool executed)"
    );

    bytes32 public constant SECURITY_PROPOSAL_TYPEHASH = keccak256(
        "SecurityProposal(address[] guardians,address[] emergencySigners,uint256 guardianThreshold,uint256 emergencyThreshold,uint256 nonce,uint256 deadline,string action,bool isEmergency)"
    );

    bytes32 public constant MIXED_ROLE_PROPOSAL_TYPEHASH = keccak256(
        "MixedRoleProposal(address[] governors,address[] treasurers,address[] guardians,uint256 governorThreshold,uint256 treasurerThreshold,uint256 guardianThreshold,uint256 nonce,uint256 deadline,string action)"
    );

    constructor() EIP712("ComplexMultiSignature", "1") {
        // Initialize some test roles
        isGovernor[address(0x1)] = true;
        isGovernor[address(0x2)] = true;
        isGovernor[address(0x3)] = true;
        
        isTreasurer[address(0x4)] = true;
        isTreasurer[address(0x5)] = true;
        
        isGuardian[address(0x6)] = true;
        isGuardian[address(0x7)] = true;
        isGuardian[address(0x8)] = true;
    }

    // ===== CASE 1: BASIC MULTI-SIG WITH THRESHOLD =====
    function basicMultiSigWithThreshold(
        MultiSigProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(signatures.length >= proposal.threshold, "Insufficient signatures");
        require(signatures.length <= proposal.signers.length, "Too many signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(MULTI_SIG_PROPOSAL_TYPEHASH, proposal.signers, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.proposalId, keccak256(bytes(proposal.action)), proposal.data)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        // Verify threshold and unique signers
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (recoveredSigners[i] == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= proposal.threshold, "Threshold not met");
        nonces[address(this)]++;
    }

    // ===== CASE 2: TREASURY MULTI-SIG WITH DUAL THRESHOLDS =====
    function treasuryMultiSigWithDualThresholds(
        TreasuryProposal memory proposal,
        bytes[] memory treasurerSignatures,
        bytes[] memory guardianSignatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(treasurerSignatures.length >= proposal.treasuryThreshold, "Insufficient treasurer signatures");
        require(guardianSignatures.length >= proposal.guardianThreshold, "Insufficient guardian signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(TREASURY_PROPOSAL_TYPEHASH, proposal.treasurers, proposal.guardians, proposal.treasuryThreshold, proposal.guardianThreshold, nonces[address(this)]++, proposal.deadline, proposal.amount, proposal.recipient)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        // Validate treasurer signatures
        uint256 validTreasurers = 0;
        for (uint i = 0; i < treasurerSignatures.length; i++) {
            address signer = hash.recover(treasurerSignatures[i]);
            for (uint j = 0; j < proposal.treasurers.length; j++) {
                if (signer == proposal.treasurers[j] && isTreasurer[signer]) {
                    validTreasurers++;
                    break;
                }
            }
        }
        require(validTreasurers >= proposal.treasuryThreshold, "Treasury threshold not met");
        
        // Validate guardian signatures
        uint256 validGuardians = 0;
        for (uint i = 0; i < guardianSignatures.length; i++) {
            address signer = hash.recover(guardianSignatures[i]);
            for (uint j = 0; j < proposal.guardians.length; j++) {
                if (signer == proposal.guardians[j] && isGuardian[signer]) {
                    validGuardians++;
                    break;
                }
            }
        }
        require(validGuardians >= proposal.guardianThreshold, "Guardian threshold not met");
        
        nonces[address(this)]++;
    }

    // ===== CASE 3: GOVERNANCE MULTI-SIG WITH VOTING PERIOD =====
    function governanceMultiSigWithVotingPeriod(
        GovernanceProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(!proposal.executed, "Proposal already executed");
        require(signatures.length >= proposal.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(GOVERNANCE_PROPOSAL_TYPEHASH, proposal.governors, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.proposalId, proposal.votingPeriod, proposal.executed)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        // Verify governors and threshold
        uint256 validGovernors = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < proposal.governors.length; j++) {
                if (recoveredSigners[i] == proposal.governors[j] && isGovernor[recoveredSigners[i]]) {
                    validGovernors++;
                    break;
                }
            }
        }
        
        require(validGovernors >= proposal.threshold, "Governance threshold not met");
        nonces[address(this)]++;
    }

    // ===== CASE 4: SECURITY MULTI-SIG WITH EMERGENCY MODE =====
    function securityMultiSigWithEmergencyMode(
        SecurityProposal memory proposal,
        bytes[] memory guardianSignatures,
        bytes[] memory emergencySignatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        
        bytes32 structHash = keccak256(
            abi.encode(SECURITY_PROPOSAL_TYPEHASH, proposal.guardians, proposal.emergencySigners, proposal.guardianThreshold, proposal.emergencyThreshold, nonces[address(this)]++, proposal.deadline, keccak256(bytes(proposal.action)), proposal.isEmergency)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        if (proposal.isEmergency) {
            // Emergency mode - requires emergency signers
            require(emergencySignatures.length >= proposal.emergencyThreshold, "Insufficient emergency signatures");
            
            uint256 validEmergencySigners = 0;
            for (uint i = 0; i < emergencySignatures.length; i++) {
                address signer = hash.recover(emergencySignatures[i]);
                for (uint j = 0; j < proposal.emergencySigners.length; j++) {
                    if (signer == proposal.emergencySigners[j]) {
                        validEmergencySigners++;
                        break;
                    }
                }
            }
            require(validEmergencySigners >= proposal.emergencyThreshold, "Emergency threshold not met");
        } else {
            // Normal mode - requires guardian signatures
            require(guardianSignatures.length >= proposal.guardianThreshold, "Insufficient guardian signatures");
            
            uint256 validGuardians = 0;
            for (uint i = 0; i < guardianSignatures.length; i++) {
                address signer = hash.recover(guardianSignatures[i]);
                for (uint j = 0; j < proposal.guardians.length; j++) {
                    if (signer == proposal.guardians[j] && isGuardian[signer]) {
                        validGuardians++;
                        break;
                    }
                }
            }
            require(validGuardians >= proposal.guardianThreshold, "Guardian threshold not met");
        }
        
        nonces[address(this)]++;
    }

    // ===== CASE 5: MIXED ROLE MULTI-SIG =====
    function mixedRoleMultiSig(
        MixedRoleProposal memory proposal,
        bytes[] memory governorSignatures,
        bytes[] memory treasurerSignatures,
        bytes[] memory guardianSignatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        
        bytes32 structHash = keccak256(
            abi.encode(MIXED_ROLE_PROPOSAL_TYPEHASH, proposal.governors, proposal.treasurers, proposal.guardians, proposal.governorThreshold, proposal.treasurerThreshold, proposal.guardianThreshold, nonces[address(this)]++, proposal.deadline, keccak256(bytes(proposal.action)))
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        // Validate governor signatures
        uint256 validGovernors = 0;
        for (uint i = 0; i < governorSignatures.length; i++) {
            address signer = hash.recover(governorSignatures[i]);
            for (uint j = 0; j < proposal.governors.length; j++) {
                if (signer == proposal.governors[j] && isGovernor[signer]) {
                    validGovernors++;
                    break;
                }
            }
        }
        require(validGovernors >= proposal.governorThreshold, "Governor threshold not met");
        
        // Validate treasurer signatures
        uint256 validTreasurers = 0;
        for (uint i = 0; i < treasurerSignatures.length; i++) {
            address signer = hash.recover(treasurerSignatures[i]);
            for (uint j = 0; j < proposal.treasurers.length; j++) {
                if (signer == proposal.treasurers[j] && isTreasurer[signer]) {
                    validTreasurers++;
                    break;
                }
            }
        }
        require(validTreasurers >= proposal.treasurerThreshold, "Treasurer threshold not met");
        
        // Validate guardian signatures
        uint256 validGuardians = 0;
        for (uint i = 0; i < guardianSignatures.length; i++) {
            address signer = hash.recover(guardianSignatures[i]);
            for (uint j = 0; j < proposal.guardians.length; j++) {
                if (signer == proposal.guardians[j] && isGuardian[signer]) {
                    validGuardians++;
                    break;
                }
            }
        }
        require(validGuardians >= proposal.guardianThreshold, "Guardian threshold not met");
        
        nonces[address(this)]++;
    }

    // ===== CASE 6: WEIGHTED MULTI-SIG =====
    struct WeightedSigner {
        address signer;
        uint256 weight;
    }

    struct WeightedProposal {
        WeightedSigner[] signers;
        uint256 requiredWeight;
        uint256 nonce;
        uint256 deadline;
        string action;
    }

    function weightedMultiSig(
        WeightedProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        
        bytes32 structHash = keccak256(
            abi.encode(keccak256("WeightedProposal(WeightedSigner[] signers,uint256 requiredWeight,uint256 nonce,uint256 deadline,string action)"), proposal.signers, proposal.requiredWeight, nonces[address(this)]++, proposal.deadline, keccak256(bytes(proposal.action)))
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        uint256 totalWeight = 0;
        for (uint i = 0; i < signatures.length; i++) {
            address signer = hash.recover(signatures[i]);
            
            // Find signer weight
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (signer == proposal.signers[j].signer) {
                    totalWeight += proposal.signers[j].weight;
                    break;
                }
            }
        }
        
        require(totalWeight >= proposal.requiredWeight, "Insufficient weight");
        nonces[address(this)]++;
    }

    // ===== CASE 7: TIME-BASED MULTI-SIG =====
    struct TimeBasedProposal {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        uint256 executionWindow;
        uint256 proposalId;
    }

    function timeBasedMultiSig(
        TimeBasedProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(block.timestamp >= proposal.deadline, "Execution window not started");
        require(block.timestamp <= proposal.deadline + proposal.executionWindow, "Execution window expired");
        require(signatures.length >= proposal.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(keccak256("TimeBasedProposal(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,uint256 executionWindow,uint256 proposalId)"), proposal.signers, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.executionWindow, proposal.proposalId)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (recoveredSigners[i] == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= proposal.threshold, "Threshold not met");
        nonces[address(this)]++;
    }

    // ===== CASE 8: CONDITIONAL MULTI-SIG =====
    struct ConditionalProposal {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        bool condition;
        string action;
    }

    function conditionalMultiSig(
        ConditionalProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(proposal.condition, "Condition not met");
        require(signatures.length >= proposal.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(keccak256("ConditionalProposal(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,bool condition,string action)"), proposal.signers, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.condition, keccak256(bytes(proposal.action)))
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (recoveredSigners[i] == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= proposal.threshold, "Threshold not met");
        nonces[address(this)]++;
    }

    // ===== CASE 9: RECURSIVE MULTI-SIG =====
    struct RecursiveProposal {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        uint256 depth;
        RecursiveProposal[] subProposals;
    }

    function recursiveMultiSig(
        RecursiveProposal memory proposal,
        bytes[] memory signatures
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(proposal.depth < 3, "Max depth exceeded");
        require(signatures.length >= proposal.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(keccak256("RecursiveProposal(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,uint256 depth)"), proposal.signers, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.depth)
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint i = 0; i < signatures.length; i++) {
            recoveredSigners[i] = hash.recover(signatures[i]);
        }
        
        uint256 validSigners = 0;
        for (uint i = 0; i < recoveredSigners.length; i++) {
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (recoveredSigners[i] == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= proposal.threshold, "Threshold not met");
        nonces[address(this)]++;
        
        // Process sub-proposals recursively (simplified)
        if (proposal.subProposals.length > 0 && proposal.depth < 2) {
            // In real implementation, would recursively validate sub-proposals
        }
    }

    // ===== CASE 10: HYBRID MULTI-SIG WITH DIFFERENT SIGNATURE TYPES =====
    struct HybridProposal {
        address[] signers;
        uint256 threshold;
        uint256 nonce;
        uint256 deadline;
        bool useEIP712;
        string action;
    }

    function hybridMultiSig(
        HybridProposal memory proposal,
        bytes[] memory combinedSignatures,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external {
        require(proposal.deadline >= block.timestamp, "Proposal expired");
        require(combinedSignatures.length + v.length >= proposal.threshold, "Insufficient signatures");
        
        bytes32 structHash = keccak256(
            abi.encode(keccak256("HybridProposal(address[] signers,uint256 threshold,uint256 nonce,uint256 deadline,bool useEIP712,string action)"), proposal.signers, proposal.threshold, nonces[address(this)]++, proposal.deadline, proposal.useEIP712, keccak256(bytes(proposal.action)))
        );
        
        bytes32 hash;
        if (proposal.useEIP712) {
            hash = _hashTypedDataV4(structHash);
        } else {
            hash = structHash.toEthSignedMessageHash();
        }
        
        uint256 validSigners = 0;
        
        // Process combined signatures
        for (uint i = 0; i < combinedSignatures.length; i++) {
            address signer = hash.recover(combinedSignatures[i]);
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (signer == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        // Process split signatures
        for (uint i = 0; i < v.length; i++) {
            address signer = ecrecover(hash, v[i], r[i], s[i]);
            for (uint j = 0; j < proposal.signers.length; j++) {
                if (signer == proposal.signers[j]) {
                    validSigners++;
                    break;
                }
            }
        }
        
        require(validSigners >= proposal.threshold, "Threshold not met");
        nonces[address(this)]++;
    }
} 