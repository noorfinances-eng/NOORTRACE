// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../CuratorSet.sol";
import "../ThresholdSignatures.sol";

/// @title ThresholdSignaturesHarness
/// @notice Contrat de test : expose la bibliothèque interne
///         `ThresholdSignatures` pour que ses règles (préfixe EIP-191,
///         unicité, appartenance au jeu, arrêt au seuil) soient vérifiées
///         isolément des registres. Ne fait partie d'aucun déploiement.
contract ThresholdSignaturesHarness {
    function prefixed(bytes32 digest) external pure returns (bytes32) {
        return ThresholdSignatures.prefixed(digest);
    }

    function countSigners(
        CuratorSet curatorSet,
        bytes32 prefixedHash,
        ThresholdSignatures.Signature[] calldata sigs,
        uint256 threshold
    ) external view returns (uint256) {
        return ThresholdSignatures.countSigners(curatorSet, prefixedHash, sigs, threshold);
    }

    function meetsThreshold(
        CuratorSet curatorSet,
        bytes32 digest,
        ThresholdSignatures.Signature[] calldata sigs,
        uint256 threshold
    ) external view returns (bool) {
        return ThresholdSignatures.meetsThreshold(curatorSet, digest, sigs, threshold);
    }
}
