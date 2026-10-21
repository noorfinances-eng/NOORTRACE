// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CuratorSet.sol";
import "./CuratorSetRegistry.sol";
import "./ThresholdSignatures.sol";

/// @title RecorderRegistry
/// @notice Registre des clés d'enregistreur de NOORTRACE, par organisation.
///         L'enregistreur déployé chez le client signe chaque événement du
///         journal en Ed25519 (clé conservée dans le HSM, le KMS ou la puce TPM
///         du client) et ancre les racines de période avec une clé de chaîne.
///         Ce registre publie, pour chaque organisation, quelles clés sont
///         reconnues et depuis quand, pour qu'un vérificateur sache quelle clé
///         publique Ed25519 attendre sur un événement et quelle clé de chaîne
///         attendre sur une ancre.
///
/// @dev CE REGISTRE EST UN COMPOSANT D'EXPLOITATION, PAS LA PREUVE. Il ne
///      contient que des identifiants et des clés publiques : ni événement, ni
///      document, ni nom. La preuve tient dans le dossier exporté chez le
///      client ; le registre dit seulement quelle clé valait à quel moment.
///
/// @dev L'inscription et la révocation sont autorisées par signatures au seuil
///      du jeu d'approbateurs de l'organisation (`CuratorSet`, résolu par
///      `CuratorSetRegistry.requireCuratorSet(orgId)`), même mécanique que
///      `PeriodRegistry`. Chaque condensé lie la chaîne, ce registre, une
///      étiquette propre à l'opération et les champs concernés, puis reçoit le
///      préfixe EIP-191 : une signature d'inscription ne révoque jamais, une
///      signature pour une organisation ne vaut rien pour une autre, et une
///      signature pour un autre registre (ou une autre chaîne) est refusée.
///
/// @dev L'état est indexé par (orgId, clé de chaîne) : la révocation et le
///      compte des clés actives portent sur la clé de chaîne. Une clé de chaîne
///      révoquée ne se réinscrit pas : la rotation se fait avec une NOUVELLE clé
///      de chaîne, et l'historique d'une clé reste lisible (`registeredAt`,
///      `revokedAt`) pour dater les événements qu'elle a signés. La clé Ed25519
///      est indexée à l'inverse (`recorderByPubKey`) : chez une organisation,
///      elle n'est active que sous UNE clé de chaîne à la fois ; une fois cette
///      clé de chaîne révoquée, la même clé Ed25519 peut être inscrite sous une
///      nouvelle clé de chaîne (rotation de la clé de chaîne seule), et
///      l'index désigne alors la plus récente. L'historique complet d'une clé
///      Ed25519 se lit dans les événements `RecorderRegistered`.
///
/// @dev ÉCHÉANCE DES AUTORISATIONS. Une signature d'inscription ne porte ni
///      nonce ni date limite : elle reste relayable tant que (orgId, chainKey)
///      n'est pas inscrite, et ne sert qu'une fois puisqu'une clé ne s'inscrit
///      qu'une fois. Une signature de révocation, elle, est liée à l'inscription
///      qu'elle vise : son condensé inclut `registeredAt`, de sorte qu'une
///      révocation signée alors que la clé était inconnue (registeredAt = 0) ne
///      vaut plus rien une fois la clé inscrite.
contract RecorderRegistry {
    using ThresholdSignatures for CuratorSet;

    /// @notice Une clé d'enregistreur inscrite pour une organisation.
    struct Recorder {
        // Clé de chaîne de l'enregistreur : celle qui signe les ancres
        // (`AttestationRegistry.anchor`) et relaie les clôtures.
        address chainKey;
        // Clé publique Ed25519 qui signe les événements du journal. Jamais zéro.
        bytes32 ed25519PubKey;
        // Le journal que cet enregistreur alimente. Jamais zéro.
        bytes32 journalId;
        // Instants d'inscription et de révocation (0 : jamais révoquée).
        uint64 registeredAt;
        uint64 revokedAt;
    }

    string private constant TAG_INSCRIT = "noortrace-enregistreur-inscrit";
    string private constant TAG_REVOQUE = "noortrace-enregistreur-revoque";

    CuratorSetRegistry public immutable curatorSetRegistry;

    // orgId -> chainKey -> enregistreur.
    mapping(bytes32 => mapping(address => Recorder)) private _recorders;
    // orgId -> ed25519PubKey -> la clé de chaîne sous laquelle elle est (ou a
    // été en dernier) inscrite ; address(0) : jamais inscrite.
    mapping(bytes32 => mapping(bytes32 => address)) private _chainKeyOfPubKey;
    // orgId -> nombre de clés de chaîne actives.
    mapping(bytes32 => uint256) private _activeCount;

    event RecorderRegistered(
        bytes32 indexed orgId,
        address indexed chainKey,
        bytes32 indexed journalId,
        bytes32 ed25519PubKey,
        address publisher
    );
    event RecorderRevoked(bytes32 indexed orgId, address indexed chainKey, address publisher);

    constructor(address curatorSetRegistryAddress) {
        require(curatorSetRegistryAddress != address(0), "RecorderRegistry: curatorSetRegistry=0");
        curatorSetRegistry = CuratorSetRegistry(curatorSetRegistryAddress);
    }

    /// @notice Le jeu d'approbateurs qui gouverne `orgId`. Révoque avec
    ///         `UnknownOrganization` quand aucun jeu n'est assigné.
    function curatorSetFor(bytes32 orgId) public view returns (CuratorSet) {
        return curatorSetRegistry.requireCuratorSet(orgId);
    }

    /// @notice Le condensé interne (avant préfixe EIP-191) que les approbateurs
    ///         signent pour inscrire `chainKey` / `ed25519PubKey` sur le journal
    ///         `journalId` de `orgId`.
    function registerDigest(bytes32 orgId, bytes32 journalId, address chainKey, bytes32 ed25519PubKey)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(block.chainid, address(this), TAG_INSCRIT, orgId, journalId, chainKey, ed25519PubKey)
        );
    }

    /// @notice Le condensé interne (avant préfixe EIP-191) que les approbateurs
    ///         signent pour révoquer `chainKey` chez `orgId`, telle qu'elle est
    ///         inscrite MAINTENANT : le condensé inclut `registeredAt` lu dans
    ///         l'état, donc une signature produite avant l'inscription (ou pour
    ///         une inscription antérieure) ne vérifie pas.
    function revokeDigest(bytes32 orgId, address chainKey) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(block.chainid, address(this), TAG_REVOQUE, orgId, chainKey, _recorders[orgId][chainKey].registeredAt)
        );
    }

    /// @notice Inscrit l'enregistreur (`chainKey`, `ed25519PubKey`) sur le
    ///         journal `journalId` de `orgId`, sous `sigs` (signatures au seuil
    ///         sur `registerDigest`). Relayé par n'importe qui.
    function registerRecorder(
        bytes32 orgId,
        bytes32 journalId,
        address chainKey,
        bytes32 ed25519PubKey,
        ThresholdSignatures.Signature[] calldata sigs
    ) external {
        require(orgId != bytes32(0), "RecorderRegistry: orgId=0");
        require(journalId != bytes32(0), "RecorderRegistry: journalId=0");
        require(chainKey != address(0), "RecorderRegistry: chainKey=0");
        require(ed25519PubKey != bytes32(0), "RecorderRegistry: ed25519PubKey=0");

        Recorder storage r = _recorders[orgId][chainKey];
        require(r.revokedAt == 0, "RecorderRegistry: cle revoquee");
        require(r.registeredAt == 0, "RecorderRegistry: cle deja active");

        // La clé Ed25519 n'est active que sous une clé de chaîne à la fois.
        address porteuse = _chainKeyOfPubKey[orgId][ed25519PubKey];
        require(porteuse == address(0) || _recorders[orgId][porteuse].revokedAt != 0, "RecorderRegistry: cle Ed25519 deja active");

        _requireThreshold(orgId, registerDigest(orgId, journalId, chainKey, ed25519PubKey), sigs);

        r.chainKey = chainKey;
        r.ed25519PubKey = ed25519PubKey;
        r.journalId = journalId;
        r.registeredAt = uint64(block.timestamp);
        _chainKeyOfPubKey[orgId][ed25519PubKey] = chainKey;
        _activeCount[orgId] += 1;

        emit RecorderRegistered(orgId, chainKey, journalId, ed25519PubKey, msg.sender);
    }

    /// @notice Révoque l'enregistreur `chainKey` de `orgId`, sous `sigs`
    ///         (signatures au seuil sur `revokeDigest`). Relayé par n'importe qui.
    function revokeRecorder(bytes32 orgId, address chainKey, ThresholdSignatures.Signature[] calldata sigs) external {
        Recorder storage r = _recorders[orgId][chainKey];
        require(r.registeredAt != 0, "RecorderRegistry: cle inconnue");
        require(r.revokedAt == 0, "RecorderRegistry: cle deja revoquee");

        _requireThreshold(orgId, revokeDigest(orgId, chainKey), sigs);

        r.revokedAt = uint64(block.timestamp);
        _activeCount[orgId] -= 1;

        emit RecorderRevoked(orgId, chainKey, msg.sender);
    }

    /// @notice Vrai si `chainKey` est inscrite chez `orgId` et non révoquée.
    function isActiveRecorder(bytes32 orgId, address chainKey) external view returns (bool) {
        Recorder storage r = _recorders[orgId][chainKey];
        return r.registeredAt != 0 && r.revokedAt == 0;
    }

    /// @notice L'enregistreur `chainKey` de `orgId` ; tous les champs à zéro
    ///         quand il est inconnu.
    function recorderOf(bytes32 orgId, address chainKey) external view returns (Recorder memory) {
        return _recorders[orgId][chainKey];
    }

    /// @notice L'enregistreur de `orgId` qui porte (ou a porté en dernier) la
    ///         clé Ed25519 `ed25519PubKey` : c'est ce qu'un vérificateur qui
    ///         tient `sig.key_id` consulte pour savoir si la clé vaut encore.
    ///         Tous les champs à zéro quand elle n'a jamais été inscrite.
    function recorderByPubKey(bytes32 orgId, bytes32 ed25519PubKey) external view returns (Recorder memory) {
        return _recorders[orgId][_chainKeyOfPubKey[orgId][ed25519PubKey]];
    }

    /// @notice Le nombre de clés de chaîne d'enregistreur actives chez `orgId`.
    function activeRecorderCount(bytes32 orgId) external view returns (uint256) {
        return _activeCount[orgId];
    }

    /// @dev Autorisation par signatures au seuil du jeu de l'organisation,
    ///      identique à celle de `PeriodRegistry`.
    function _requireThreshold(bytes32 orgId, bytes32 digest, ThresholdSignatures.Signature[] calldata sigs) private view {
        CuratorSet curatorSet = curatorSetFor(orgId);
        uint256 threshold = curatorSet.getThreshold();
        require(threshold > 0, "RecorderRegistry: seuil=0");
        require(sigs.length >= threshold, "RecorderRegistry: signatures insuffisantes");
        require(curatorSet.meetsThreshold(digest, sigs, threshold), "RecorderRegistry: seuil non atteint");
    }
}
