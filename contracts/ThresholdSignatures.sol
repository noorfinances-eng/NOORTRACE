// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CuratorSet.sol";

/// @title ThresholdSignatures
/// @notice Bibliothèque interne de NOORTRACE : compte les signatures EIP-191
///         valides, uniques et membres d'un jeu d'approbateurs (`CuratorSet`)
///         sur un condensé donné, et s'arrête dès que le seuil est atteint.
///
/// @dev La boucle reprend celle de `PoSSRegistry.submitSnapshot` de
///      noorchain-core : chaque signature est recouvrée par `ecrecover` sur le
///      hachage PRÉFIXÉ EIP-191 (`personal_sign`), un signataire qui n'est pas
///      membre du jeu ne compte pas, un signataire déjà compté ne compte pas une
///      seconde fois. Les registres de NOORTRACE (`PeriodRegistry`,
///      `RecorderRegistry`) l'emploient tous les deux pour que la règle
///      d'autorisation soit écrite une seule fois.
///
///      Deux règles s'ajoutent à la boucle d'origine :
///        - seule la forme CANONIQUE d'une signature est examinée (`s` dans la
///          moitié basse de l'ordre de secp256k1, `v` égal à 27 ou 28, la règle
///          d'OpenZeppelin ECDSA) ; la forme malléable (v ^ 1, r, n - s)
///          recouvre la même adresse et ne menaçait pas le compte, qui porte sur
///          les adresses, mais une signature n'a ainsi qu'une seule écriture
///          valable, au cas où ses octets serviraient un jour d'identifiant ;
///        - un seuil nul ne s'atteint jamais : `meetsThreshold(…, 0)` rend faux,
///          quel que soit le jeu de signatures, pour que la bibliothèque ne
///          laisse pas cette garde à chaque appelant (les registres gardent
///          leur `require(threshold > 0)` pour leurs messages propres).
///
///      Le relayeur qui soumet la transaction ne détient aucune autorité : il
///      transporte des signatures qu'il ne peut ni fabriquer ni réassembler sur
///      un autre condensé. C'est le condensé, construit par le contrat appelant
///      (chaîne, adresse du registre, étiquette, champs signés), qui ferme le
///      rejeu.
library ThresholdSignatures {
    /// @notice Une signature ECDSA au format (v, r, s), telle que la produit
    ///         `signer.signMessage(getBytes(digest))` côté client.
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @dev Borne haute de `s` : n / 2 pour secp256k1. Au-dessus, la signature
    ///      est la forme malléable d'une signature canonique et est ignorée.
    uint256 private constant S_MAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Applique le préfixe EIP-191 (`"\x19Ethereum Signed Message:\n32"`)
    ///         à un condensé de 32 octets.
    /// @dev Une signature sur le condensé nu (sans préfixe) ne vérifie pas : c'est
    ///      ce qui interdit la réutilisation accidentelle d'une signature produite
    ///      pour un autre protocole.
    function prefixed(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }

    /// @notice Compte les signataires valides, uniques et membres de `curatorSet`
    ///         sur le hachage préfixé `prefixedHash`, et s'arrête au `threshold`.
    /// @param curatorSet Le jeu d'approbateurs de l'organisation concernée.
    /// @param prefixedHash Le hachage EIP-191 (voir `prefixed`) que les
    ///        approbateurs ont signé.
    /// @param sigs Les signatures relayées, dans n'importe quel ordre. Une
    ///        signature non canonique (s haut, v hors {27, 28}) est ignorée.
    /// @param threshold Le nombre de signataires distincts requis ; la boucle
    ///        s'arrête dès qu'il est atteint, le reste n'est pas examiné.
    /// @return validCount Le nombre de signataires retenus, au plus `threshold`.
    function countSigners(
        CuratorSet curatorSet,
        bytes32 prefixedHash,
        Signature[] calldata sigs,
        uint256 threshold
    ) internal view returns (uint256 validCount) {
        address[] memory seen = new address[](sigs.length);

        for (uint256 i = 0; i < sigs.length; i++) {
            // Forme canonique seulement.
            if (uint256(sigs[i].s) > S_MAX) continue;
            if (sigs[i].v != 27 && sigs[i].v != 28) continue;

            address signer = ecrecover(prefixedHash, sigs[i].v, sigs[i].r, sigs[i].s);
            if (signer == address(0)) continue;

            // Doit être membre du jeu.
            if (!curatorSet.isCurator(signer)) continue;

            // Doit être unique : une même clé ne vaut qu'une voix.
            bool dup = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == signer) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            seen[validCount] = signer;
            validCount += 1;

            if (validCount >= threshold) break;
        }
    }

    /// @notice Vrai si `sigs` contient au moins `threshold` signatures valides,
    ///         uniques et membres de `curatorSet`, sur le condensé `digest`
    ///         (préfixé ici, avant recouvrement). Toujours faux pour un seuil nul.
    function meetsThreshold(
        CuratorSet curatorSet,
        bytes32 digest,
        Signature[] calldata sigs,
        uint256 threshold
    ) internal view returns (bool) {
        if (threshold == 0) return false;
        return countSigners(curatorSet, prefixed(digest), sigs, threshold) >= threshold;
    }
}
