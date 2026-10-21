// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CuratorSet.sol";
import "./CuratorSetRegistry.sol";
import "./ThresholdSignatures.sol";

/// @title PeriodRegistry
/// @notice Registre des périodes de journal de NOORTRACE. Chaque heure,
///         l'enregistreur déployé chez le client construit l'arbre de Merkle des
///         événements de la période et un manifeste canonique ; les approbateurs
///         de l'organisation signent la clôture (EIP-191, au seuil de leur
///         `CuratorSet`), et n'importe qui relaie la transaction. Le registre
///         garde l'ordre des périodes et leur consultation : l'empreinte du
///         manifeste, la racine, les bornes de temps et de séquence. Jamais un
///         événement, jamais un argument, jamais un document.
///
/// @dev CE REGISTRE EST UN COMPOSANT D'EXPLOITATION, PAS LA PREUVE. La preuve
///      d'un événement tient dans le dossier exporté chez le client (chaîne
///      d'événements, chemin de Merkle, jeton d'horodatage qualifié, preuve
///      d'ancrage public). Le registre donne à un nœud suiveur l'ordre des
///      périodes et un point de relecture ; il est substituable.
///
/// @dev Dérivé de `PoSSRegistry` de noorchain-core, sans le hachage des
///      paiements (propre au PoSS). Trois différences de fond :
///        - le condensé signé lie TOUS les champs du manifeste
///          (`keccak256(abi.encode(meta))`), pour qu'un relayeur ne puisse pas
///          enregistrer des bornes, une racine ou une URI différentes de celles
///          que les approbateurs ont signées ;
///        - la continuité est vérifiée par journal (`orgId`, `journalId`) :
///          chaque période commence où la précédente s'arrête, en temps comme en
///          numéro de séquence, de sorte qu'une période ne peut être ni sautée
///          ni insérée ;
///        - l'unicité d'un `periodHash` est cloisonnée PAR ORGANISATION (là où
///          `PoSSRegistry` tient une table globale) : une organisation ne peut
///          pas, en enregistrant la première l'empreinte d'une autre, bloquer la
///          clôture de celle-ci. Le registre est partagé entre clients ; c'est
///          ce cloisonnement qui rend l'isolation par organisation effective.
///
/// @dev Le jeu d'approbateurs est résolu PAR ORGANISATION via
///      `CuratorSetRegistry.requireCuratorSet(orgId)`, qui révoque quand
///      l'organisation n'a pas de jeu assigné, plutôt que de lire « aucun
///      approbateur, donc aucun seuil à atteindre ».
///
/// @dev AUTORISATIONS SANS ÉCHÉANCE. Une clôture signée ne porte ni nonce ni
///      date limite : elle reste relayable tant que l'état du journal l'admet
///      (empreinte inconnue de l'organisation, continuité respectée). Une
///      clôture abandonnée (manifeste refait) est donc neutralisée par
///      l'enregistrement de la version voulue, qui occupe sa place dans la
///      continuité ; mais si elle est relayée AVANT, le journal continue sur ses
///      bornes et aucune voie de correction n'existe. L'enregistreur ne doit
///      faire signer qu'un seul manifeste par position de journal, et le
///      manifeste porte un nonce pour que deux clôtures d'une même heure
///      n'aient jamais la même empreinte.
contract PeriodRegistry {
    using ThresholdSignatures for CuratorSet;

    /// @notice Les champs signés par les approbateurs pour clôturer une période.
    struct PeriodMeta {
        // L'organisation : keccak256(bytes(slug)). Sélectionne le jeu d'approbateurs.
        bytes32 orgId;
        // Le journal de l'organisation auquel la période appartient. Jamais zéro.
        bytes32 journalId;
        // keccak256 du manifeste canonique de la période. Jamais zéro.
        bytes32 periodHash;
        // Racine de Merkle des événements de la période (RFC 6962). Exigée NULLE
        // pour une période vide (convention fixée par le contrat), non nulle sinon.
        bytes32 root;
        // Bornes de temps, secondes UNIX, start < end < 2^64 - 1.
        uint64 periodStart;
        uint64 periodEnd;
        // Bornes de séquence. Une période vide se signale par
        // lastSeq + 1 == firstSeq ; sinon firstSeq <= lastSeq < 2^64 - 1. La
        // numérotation d'un journal commence donc au plus tôt à 1, pour qu'une
        // première période vide (firstSeq = 1, lastSeq = 0) reste exprimable.
        uint64 firstSeq;
        uint64 lastSeq;
        // Version du format de manifeste.
        uint32 version;
        // Emplacement du manifeste (CID, URL), peut être vide.
        string uri;
    }

    /// @notice Une période enregistrée : les champs signés, plus l'instant
    ///         d'enregistrement et le relayeur qui a payé le gaz.
    struct Period {
        bytes32 orgId;
        bytes32 journalId;
        bytes32 periodHash;
        bytes32 root;
        uint64 periodStart;
        uint64 periodEnd;
        uint64 firstSeq;
        uint64 lastSeq;
        uint64 publishedAt;
        uint32 version;
        address publisher;
        string uri;
    }

    /// @dev Étiquette de domaine du condensé : une signature de clôture ne vaut
    ///      que pour une période, jamais pour une inscription d'enregistreur.
    string private constant TAG_PERIODE = "noortrace-periode";

    CuratorSetRegistry public immutable curatorSetRegistry;
    uint256 public periodCount;

    mapping(uint256 => Period) private _periods;
    // orgId -> periodHash -> déjà enregistré. Cloisonné par organisation : la
    // même empreinte peut exister chez deux organisations, jamais deux fois
    // chez la même.
    mapping(bytes32 => mapping(bytes32 => bool)) private _knownPeriodHash;
    // (orgId, journalId) -> id de la dernière période enregistrée (0 : aucune).
    mapping(bytes32 => mapping(bytes32 => uint256)) private _latestOf;

    /// @notice Émis à chaque période enregistrée, avec TOUT ce que `getPeriod`
    ///         rend (URI et instant d'enregistrement compris), pour qu'un nœud
    ///         suiveur reconstitue l'état à partir des seuls événements.
    event PeriodSubmitted(
        uint256 indexed id,
        bytes32 indexed periodHash,
        bytes32 orgId,
        bytes32 journalId,
        bytes32 root,
        uint64 periodStart,
        uint64 periodEnd,
        uint64 firstSeq,
        uint64 lastSeq,
        uint32 version,
        address indexed publisher,
        string uri,
        uint64 publishedAt
    );

    constructor(address curatorSetRegistryAddress) {
        require(curatorSetRegistryAddress != address(0), "PeriodRegistry: curatorSetRegistry=0");
        curatorSetRegistry = CuratorSetRegistry(curatorSetRegistryAddress);
    }

    /// @notice Le jeu d'approbateurs qui gouverne `orgId`. Révoque avec
    ///         `UnknownOrganization` quand aucun jeu n'est assigné.
    function curatorSetFor(bytes32 orgId) public view returns (CuratorSet) {
        return curatorSetRegistry.requireCuratorSet(orgId);
    }

    /// @notice Le condensé interne (avant préfixe EIP-191) que les approbateurs
    ///         signent pour clôturer `meta` :
    ///         keccak256(chainid || this || "noortrace-periode" || keccak256(abi.encode(meta))).
    /// @dev Donné par le contrat pour que les clients n'aient pas à recalculer
    ///      l'encodage eux-mêmes : une divergence d'encodage se verrait en
    ///      production sous la forme d'un « seuil non atteint » intraçable.
    ///      Le client signe ensuite `signMessage(getBytes(digest))`.
    function periodDigest(PeriodMeta calldata meta) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.chainid, address(this), TAG_PERIODE, keccak256(abi.encode(meta))));
    }

    /// @notice Enregistre la période `meta`, autorisée par `sigs` (signatures au
    ///         seuil du jeu d'approbateurs de `meta.orgId`). Relayé par n'importe qui.
    /// @dev Le contrat est la dernière barrière contre un manifeste malformé que
    ///      les approbateurs auraient signé tel que l'enregistreur le leur a
    ///      présenté : toute borne refusée l'est par un `require` nommé, jamais
    ///      par une panique arithmétique. En particulier `lastSeq` et `periodEnd`
    ///      sont bornés strictement sous 2^64 - 1 : sinon `lastSeq + 1` (ou le
    ///      `periodStart` de la période suivante) ne serait plus représentable
    ///      et le journal serait figé sans recours, la continuité n'admettant ni
    ///      saut ni correction.
    /// @return id L'identifiant croissant attribué à la période.
    function submitPeriod(PeriodMeta calldata meta, ThresholdSignatures.Signature[] calldata sigs)
        external
        returns (uint256 id)
    {
        require(meta.orgId != bytes32(0), "PeriodRegistry: orgId=0");
        require(meta.journalId != bytes32(0), "PeriodRegistry: journalId=0");
        require(meta.periodHash != bytes32(0), "PeriodRegistry: periodHash=0");
        require(meta.periodStart < meta.periodEnd, "PeriodRegistry: periode invalide");
        require(meta.periodEnd < type(uint64).max, "PeriodRegistry: periodEnd hors plage");
        require(meta.lastSeq < type(uint64).max, "PeriodRegistry: lastSeq hors plage");

        // Période vide : lastSeq + 1 == firstSeq, calculé en uint256 (ni
        // soustraction, ni débordement). Sa racine est nulle par convention.
        bool empty = uint256(meta.lastSeq) + 1 == uint256(meta.firstSeq);
        if (empty) {
            require(meta.root == bytes32(0), "PeriodRegistry: root d'une periode vide != 0");
        } else {
            require(meta.firstSeq <= meta.lastSeq, "PeriodRegistry: sequence invalide");
            require(meta.root != bytes32(0), "PeriodRegistry: root=0");
        }

        require(!_knownPeriodHash[meta.orgId][meta.periodHash], "PeriodRegistry: doublon");

        // Continuité par journal : la première période est libre ; ensuite la
        // période commence exactement où la précédente s'arrête. Comparaison en
        // uint256 pour qu'un écart soit toujours un refus nommé.
        uint256 previousId = _latestOf[meta.orgId][meta.journalId];
        if (previousId != 0) {
            Period storage previous = _periods[previousId];
            require(meta.periodStart == previous.periodEnd, "PeriodRegistry: discontinuite temporelle");
            require(uint256(meta.firstSeq) == uint256(previous.lastSeq) + 1, "PeriodRegistry: discontinuite de sequence");
        }

        _requireThreshold(meta.orgId, periodDigest(meta), sigs);

        periodCount += 1;
        id = periodCount;

        _knownPeriodHash[meta.orgId][meta.periodHash] = true;
        _latestOf[meta.orgId][meta.journalId] = id;

        Period storage p = _periods[id];
        p.orgId = meta.orgId;
        p.journalId = meta.journalId;
        p.periodHash = meta.periodHash;
        p.root = meta.root;
        p.periodStart = meta.periodStart;
        p.periodEnd = meta.periodEnd;
        p.firstSeq = meta.firstSeq;
        p.lastSeq = meta.lastSeq;
        p.publishedAt = uint64(block.timestamp);
        p.version = meta.version;
        p.publisher = msg.sender;
        p.uri = meta.uri;

        emit PeriodSubmitted(
            id,
            meta.periodHash,
            meta.orgId,
            meta.journalId,
            meta.root,
            meta.periodStart,
            meta.periodEnd,
            meta.firstSeq,
            meta.lastSeq,
            meta.version,
            msg.sender,
            meta.uri,
            p.publishedAt
        );
    }

    /// @notice La période d'identifiant `id` (1 ≤ id ≤ periodCount).
    function getPeriod(uint256 id) external view returns (Period memory) {
        require(id >= 1 && id <= periodCount, "PeriodRegistry: id invalide");
        return _periods[id];
    }

    /// @notice L'identifiant de la dernière période enregistrée, toutes
    ///         organisations confondues (0 : aucune).
    function latestPeriodId() external view returns (uint256) {
        return periodCount;
    }

    /// @notice L'identifiant de la dernière période du journal (`orgId`,
    ///         `journalId`), ou 0 si ce journal n'a encore aucune période.
    function latestPeriodOf(bytes32 orgId, bytes32 journalId) external view returns (uint256) {
        return _latestOf[orgId][journalId];
    }

    /// @notice Vrai si l'organisation `orgId` a déjà enregistré un manifeste
    ///         d'empreinte `periodHash`.
    /// @dev L'unicité est par organisation : la même empreinte chez une autre
    ///      organisation ne rend pas vrai ici, et ne l'empêche pas d'être
    ///      enregistrée chez `orgId`.
    function isKnown(bytes32 orgId, bytes32 periodHash) external view returns (bool) {
        return _knownPeriodHash[orgId][periodHash];
    }

    /// @dev Autorisation par signatures au seuil du jeu de l'organisation. Le
    ///      seuil doit être strictement positif, le nombre de signatures
    ///      relayées au moins égal au seuil, et le nombre de signataires
    ///      valides, uniques et membres du jeu au moins égal au seuil.
    function _requireThreshold(bytes32 orgId, bytes32 digest, ThresholdSignatures.Signature[] calldata sigs) private view {
        CuratorSet curatorSet = curatorSetFor(orgId);
        uint256 threshold = curatorSet.getThreshold();
        require(threshold > 0, "PeriodRegistry: seuil=0");
        require(sigs.length >= threshold, "PeriodRegistry: signatures insuffisantes");
        require(curatorSet.meetsThreshold(digest, sigs, threshold), "PeriodRegistry: seuil non atteint");
    }
}
