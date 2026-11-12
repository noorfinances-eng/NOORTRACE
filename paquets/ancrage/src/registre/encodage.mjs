// Conventions du registre calculées hors chaîne (CT-4 §6.4 à §6.7) :
// `docType` (RG-3), empreinte d'ancre (RG-4), champs d'une clôture (RG-5),
// condensés internes et hachage signé EIP-191 (RG-6, RG-9 ; §6.6.3),
// signature canonique et jeu de signatures (RG-12, RG-13), données d'appel
// ABI (RG-14) des fonctions que le composant d'ancrage écrit ou lit, et
// disposition des journaux d'événements (CT-6 EX-11.9).
//
// Tout se calcule depuis le texte de CT-4 : sélecteurs et sujets sont des
// keccak256 des signatures de 6.7.1 et 5.7, recalculés au chargement.

import { empreinteAncre as empreinteAncreNoyau, keccak256, messageEip191, utf8 } from "@noortrace/noyau";
import { recouvrerSignataire } from "./cle-chaine.mjs";
import {
  concatener, entierVersOctets, estHexOctets, estOctets, hexVersOctets, octetsVersEntier, octetsVersHex,
  u256, versEntier,
} from "./octets.mjs";

/** Libellés de `docType` de la table de CT-4 §6.4. */
export const LIBELLE_PERIODE = "noortrace/periode/v0";
export const LIBELLE_POINT_DE_CONTROLE = "noortrace/point-de-controle/v0";

const MOTIF_LIBELLE = /^noortrace\/[a-z0-9][a-z0-9-]{0,31}\/v(0|[1-9][0-9]{0,2})$/;

function keccakHex(texte) {
  return octetsVersHex(keccak256(utf8(texte)));
}

/** `docType = keccak256(utf8(libellé))` (RG-3). */
export const DOC_TYPE_PERIODE = keccakHex(LIBELLE_PERIODE);
export const DOC_TYPE_POINT_DE_CONTROLE = keccakHex(LIBELLE_POINT_DE_CONTROLE);

/** Table des `docType` admis (libellé → valeur). */
export const TABLE_DOC_TYPES = Object.freeze(new Map([
  [LIBELLE_PERIODE, DOC_TYPE_PERIODE],
  [LIBELLE_POINT_DE_CONTROLE, DOC_TYPE_POINT_DE_CONTROLE],
]));

export const ZERO32 = "0x" + "00".repeat(32);

/**
 * RG-3 : vérifie un libellé ou une valeur de `docType`.
 * @param {{label?: string, doc_type?: string}} entree
 * @returns {{statut: "reussi"|"echoue", motif: string|null, label: string|null, doc_type: string|null}}
 */
export function verifierDocType(entree) {
  const echec = (motif) => ({ statut: "echoue", motif, label: null, doc_type: null });
  if (entree && typeof entree.label === "string") {
    if (!MOTIF_LIBELLE.test(entree.label)) return echec("libelle_invalide");
    const valeur = TABLE_DOC_TYPES.get(entree.label);
    if (!valeur) return echec("libelle_hors_table");
    return { statut: "reussi", motif: null, label: entree.label, doc_type: valeur };
  }
  if (entree && typeof entree.doc_type === "string") {
    if (!estHexOctets(entree.doc_type, 32)) return echec("doctype_hors_table");
    if (entree.doc_type === ZERO32) return echec("doctype_nul");
    for (const [label, valeur] of TABLE_DOC_TYPES) if (valeur === entree.doc_type) return { statut: "reussi", motif: null, label, doc_type: valeur };
    return echec("doctype_hors_table");
  }
  return echec("libelle_invalide");
}

/** Libellé d'une valeur de `docType` de la table, ou null. */
export function libelleDocType(valeur) {
  const r = verifierDocType({ doc_type: valeur });
  return r.statut === "reussi" ? r.label : null;
}

/**
 * RG-4 : empreinte d'ancre `keccak256(org_id ‖ journal_id ‖ hash)` (CT-1 §10.4
 * pour `periodHash`, §10.6 pour `checkpointHash`), avec la préimage de 96
 * octets ; `entree_nulle` si l'un des trois est nul ou mal formé,
 * `empreinte_differente` si une empreinte déclarée ne l'égale pas.
 */
export function empreinteAncre(orgId, journalId, hash, declaree = null) {
  const echec = (motif) => ({ statut: "echoue", motif, fingerprint: null, preimage: null });
  for (const v of [orgId, journalId, hash]) if (!estHexOctets(v, 32) || v === ZERO32) return echec("entree_nulle");
  const preimage = octetsVersHex(concatener(hexVersOctets(orgId), hexVersOctets(journalId), hexVersOctets(hash)));
  const fingerprint = empreinteAncreNoyau(orgId, journalId, hash);
  if (declaree !== null && declaree !== fingerprint) return echec("empreinte_differente");
  return { statut: "reussi", motif: null, fingerprint, preimage };
}

// ----------------------------------------------------------- PeriodMeta

const MAX_U64 = (1n << 64n) - 1n;
const MAX_U32 = (1n << 32n) - 1n;

/**
 * Lit un `PeriodMeta` au format `meta_periode` (clés en anglais, entiers
 * décimaux en chaîne) ; rend les champs en `bigint`, ou null si une forme est
 * refusée.
 */
export function lirePeriodMeta(meta) {
  if (!meta || typeof meta !== "object") return null;
  const champs = ["org_id", "journal_id", "period_hash", "root"];
  for (const c of champs) if (!estHexOctets(meta[c], 32)) return null;
  const entiers = {};
  for (const c of ["period_start", "period_end", "first_seq", "last_seq"]) {
    const x = versEntier(meta[c]);
    if (x === null || x > MAX_U64) return null;
    entiers[c] = x;
  }
  const version = versEntier(meta.version);
  if (version === null || version > MAX_U32 || typeof meta.version !== "number") return null;
  if (typeof meta.uri !== "string") return null;
  return {
    org_id: meta.org_id, journal_id: meta.journal_id, period_hash: meta.period_hash, root: meta.root,
    ...entiers, version, uri: meta.uri,
  };
}

/**
 * RG-5 : champs d'une clôture (CT-4 EX-6.8). `precedente` est le `PeriodMeta`
 * de la période précédente du journal quand elle est connue.
 */
export function verifierPeriodMeta(meta, precedente = null, { slug = null, nomJournal = null } = {}) {
  const echec = (motif) => ({ statut: "echoue", motif, meta: null });
  const m = lirePeriodMeta(meta);
  if (!m) return echec("periode_invalide");
  if (m.org_id === ZERO32 || m.journal_id === ZERO32 || m.period_hash === ZERO32) return echec("periode_invalide");
  if (!(m.period_start < m.period_end && m.period_end < MAX_U64)) return echec("periode_invalide");
  if (!(m.last_seq < MAX_U64)) return echec("periode_invalide");
  if (m.last_seq + 1n === m.first_seq) {
    if (m.root !== ZERO32) return echec("periode_invalide");
  } else {
    if (!(m.first_seq <= m.last_seq) || m.root === ZERO32) return echec("periode_invalide");
  }
  if (m.uri.length > 64 || !/^[ -~]*$/.test(m.uri)) return echec("periode_invalide");
  // L'URI est publique : elle ne porte ni le slug ni le nom du journal (EX-6.8).
  if (typeof slug === "string" && slug.length > 0 && m.uri.includes(slug)) return echec("periode_invalide");
  if (typeof nomJournal === "string" && nomJournal.length > 0 && m.uri.includes(nomJournal)) return echec("periode_invalide");
  if (precedente) {
    // La période précédente peut être réduite à `period_end` et `last_seq`
    // (forme des vecteurs de CT-4), ou être un `PeriodMeta` complet.
    const fin = versEntier(precedente.period_end);
    const dernier = versEntier(precedente.last_seq);
    if (fin === null || dernier === null || fin > MAX_U64 || dernier > MAX_U64) return echec("periode_invalide");
    if (m.period_start !== fin) return echec("discontinuite_temporelle");
    if (m.first_seq !== dernier + 1n) return echec("discontinuite_sequence");
  }
  return { statut: "reussi", motif: null, meta: m };
}

/** `T(meta)` de CT-4 §6.7.2, règle 4 (en-tête du tuple, `uri` en queue à 0x140). */
export function encoderTuplePeriodMeta(meta) {
  const m = lirePeriodMeta(meta);
  if (!m) throw new TypeError("PeriodMeta mal formé");
  const uri = utf8(m.uri);
  const rembourrage = (32 - (uri.length % 32)) % 32;
  return concatener(
    hexVersOctets(m.org_id), hexVersOctets(m.journal_id), hexVersOctets(m.period_hash), hexVersOctets(m.root),
    u256(m.period_start), u256(m.period_end), u256(m.first_seq), u256(m.last_seq), u256(m.version),
    u256(0x140n), u256(BigInt(uri.length)), uri, new Uint8Array(rembourrage),
  );
}

/** `E(meta) = abi.encode(meta) = u256(0x20) ‖ T(meta)`. */
export function encoderPeriodMeta(meta) {
  return concatener(u256(0x20n), encoderTuplePeriodMeta(meta));
}

// ------------------------------------------------------------ Condensés

const ETIQUETTES = Object.freeze({
  periode: utf8("noortrace-periode"),
  inscription: utf8("noortrace-enregistreur-inscrit"),
  revocationEnregistreur: utf8("noortrace-enregistreur-revoque"),
  ancre: utf8("noor-attestation-ancre"),
  revocationAncre: utf8("noor-attestation-revoque"),
});

function a20(adresse) {
  if (!estHexOctets(adresse, 20)) throw new TypeError("adresse de 20 octets attendue");
  return hexVersOctets(adresse);
}

function b32(valeur) {
  if (!estHexOctets(valeur, 32)) throw new TypeError("valeur de 32 octets attendue");
  return hexVersOctets(valeur);
}

function chainId(evmChainId) {
  const x = versEntier(evmChainId);
  if (x === null || x < 1n || x > 2147483647n) throw new TypeError("identifiant EVM hors de [1, 2^31 − 1]");
  return u256(x);
}

/** RG-6 : `periodDigest(meta)`, condensé interne de 32 octets (hexadécimal). */
export function periodDigest(evmChainId, periodRegistry, meta) {
  const preimage = concatener(chainId(evmChainId), a20(periodRegistry), ETIQUETTES.periode, keccak256(encoderPeriodMeta(meta)));
  return octetsVersHex(keccak256(preimage));
}

/** RG-9 : `anchorDigest(fingerprint, docType)`. */
export function anchorDigest(evmChainId, attestationRegistry, fingerprint, docType) {
  const preimage = concatener(chainId(evmChainId), a20(attestationRegistry), ETIQUETTES.ancre, b32(fingerprint), b32(docType));
  return octetsVersHex(keccak256(preimage));
}

/** RG-7 : `registerDigest(orgId, journalId, chainKey, ed25519PubKey)`. */
export function registerDigest(evmChainId, recorderRegistry, orgId, journalId, chainKey, ed25519PubKey) {
  const preimage = concatener(chainId(evmChainId), a20(recorderRegistry), ETIQUETTES.inscription, b32(orgId), b32(journalId), a20(chainKey), b32(ed25519PubKey));
  return octetsVersHex(keccak256(preimage));
}

/** RG-10 : `revokeDigest(fingerprint)` d'`AttestationRegistry`. */
export function revokeDigestAncre(evmChainId, attestationRegistry, fingerprint) {
  const preimage = concatener(chainId(evmChainId), a20(attestationRegistry), ETIQUETTES.revocationAncre, b32(fingerprint));
  return octetsVersHex(keccak256(preimage));
}

/** RG-8 : `revokeDigest(orgId, chainKey)` de `RecorderRegistry` ; `registeredAt` non nul (EX-6.11). */
export function revokeDigestEnregistreur(evmChainId, recorderRegistry, orgId, chainKey, registeredAt) {
  const t = versEntier(registeredAt);
  if (t === null || t === 0n || t > MAX_U64) return null;
  const preimage = concatener(chainId(evmChainId), a20(recorderRegistry), ETIQUETTES.revocationEnregistreur, b32(orgId), a20(chainKey), entierVersOctets(t, 8));
  return octetsVersHex(keccak256(preimage));
}

/** Opérations signées d'un `CuratorSet` (CT-4 §6.6.2) : `op = keccak256(utf8(nom))`. */
export const OPERATIONS_JEU = Object.freeze(Object.fromEntries(
  ["CuratorSet.addCurator", "CuratorSet.removeCurator", "CuratorSet.setThreshold", "CuratorSet.proposeAdmin", "CuratorSet.acceptAdmin"]
    .map((nom) => [nom, keccakHex(nom)]),
));

/** RG-11 : `adminOpDigest(op, arg, nonce)` ; null si l'opération est inconnue (EX-6.14). */
export function adminOpDigest(evmChainId, curatorSet, op, arg, nonce) {
  const code = OPERATIONS_JEU[op];
  const n = versEntier(nonce);
  if (!code || n === null) return null;
  const preimage = concatener(chainId(evmChainId), a20(curatorSet), hexVersOctets(code), b32(arg), u256(n));
  return octetsVersHex(keccak256(preimage));
}

const MOTIF_SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const MOTIF_SLUG_PRODUCTION = /^o-[0-9a-f]{32}$/;

/** RG-1 : slug et `org_id = keccak256(utf8(slug))` ; en production, `o-` et 32 chiffres hexadécimaux (EX-6.2). */
export function verifierSlug(slug, { production = false } = {}) {
  if (typeof slug !== "string" || !MOTIF_SLUG.test(slug) || (production && !MOTIF_SLUG_PRODUCTION.test(slug))) {
    return { statut: "echoue", motif: "slug_invalide", org_id: null };
  }
  return { statut: "reussi", motif: null, org_id: keccakHex(slug) };
}

/** RG-2 : nom de journal et `journal_id = keccak256(utf8(nom))` (EX-6.4). */
export function verifierNomJournal(nom) {
  if (typeof nom !== "string" || !MOTIF_SLUG.test(nom)) return { statut: "echoue", motif: "nom_journal_invalide", journal_id: null };
  return { statut: "reussi", motif: null, journal_id: keccakHex(nom) };
}

/** Hachage signé EIP-191 d'un condensé interne (CT-4 §6.6.3), en octets. */
export function hachageSigne(condense) {
  return messageEip191(estOctets(condense) ? condense : b32(condense));
}

/**
 * RG-12 : une signature `{ signer, v, r, s }` est canonique et recouvre son
 * signataire sur le hachage signé du condensé interne.
 */
export function verifierSignatureCondense(condense, signature, { hachageSigneDeclare = null } = {}) {
  const echec = (motif) => ({ statut: "echoue", motif, recovered: null });
  if (!signature || typeof signature !== "object") return echec("signature_non_canonique");
  const h = hachageSigne(condense);
  const recovered = recouvrerSignataire(h, signature);
  if (recovered === null) return echec("signature_non_canonique");
  if (typeof signature.signer === "string" && signature.signer !== recovered) return echec("signataire_different");
  if (hachageSigneDeclare !== null && hachageSigneDeclare !== octetsVersHex(h)) return echec("hachage_signe_different");
  return { statut: "reussi", motif: null, recovered };
}

/**
 * RG-13 : jeu de `t` signatures de signataires distincts, membres du jeu,
 * rangées par adresse croissante ; chaque signature passe RG-12 d'abord.
 */
export function verifierJeuSignatures(condense, signatures, { membres = null, seuil }) {
  const echec = (motif, check = "RG-13") => ({ statut: "echoue", motif, check, signers: null });
  if (!Array.isArray(signatures)) return echec("nombre_signatures");
  const signers = [];
  for (const s of signatures) {
    const r = verifierSignatureCondense(condense, s);
    if (r.statut !== "reussi") return echec(r.motif, "RG-12");
    signers.push(r.recovered);
  }
  if (membres) for (const a of signers) if (!membres.includes(a)) return echec("signataire_hors_jeu");
  if (new Set(signers).size !== signers.length) return echec("signataire_double");
  for (let k = 1; k < signers.length; k++) if (!(signers[k - 1] < signers[k])) return echec("ordre_signatures");
  if (typeof seuil === "number" && signers.length !== seuil) return echec("nombre_signatures");
  return { statut: "reussi", motif: null, check: null, signers };
}

// ---------------------------------------------------------- Sélecteurs

/** Signatures des fonctions de CT-4 §6.7.1 que ce module encode ou lit. */
export const SIGNATURES_FONCTIONS = Object.freeze({
  anchor: "anchor(bytes32,bytes32,address,(uint8,bytes32,bytes32))",
  revoke: "revoke(bytes32,(uint8,bytes32,bytes32))",
  submitPeriod: "submitPeriod((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string),(uint8,bytes32,bytes32)[])",
  registerRecorder: "registerRecorder(bytes32,bytes32,address,bytes32,(uint8,bytes32,bytes32)[])",
  revokeRecorder: "revokeRecorder(bytes32,address,(uint8,bytes32,bytes32)[])",
  setCuratorSet: "setCuratorSet(bytes32,address)",
  periodDigest: "periodDigest((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string))",
  anchorDigest: "anchorDigest(bytes32,bytes32)",
  lookup: "lookup(bytes32)",
  isAnchored: "isAnchored(bytes32)",
  getPeriod: "getPeriod(uint256)",
  latestPeriodOf: "latestPeriodOf(bytes32,bytes32)",
  isKnown: "isKnown(bytes32,bytes32)",
  isActiveRecorder: "isActiveRecorder(bytes32,address)",
  recorderOf: "recorderOf(bytes32,address)",
  recorderByPubKey: "recorderByPubKey(bytes32,bytes32)",
  curatorSetOf: "curatorSetOf(bytes32)",
  getThreshold: "getThreshold()",
  isCurator: "isCurator(address)",
});

/** Sélecteurs : quatre premiers octets de `keccak256(utf8(signature))`. */
export const SELECTEURS = Object.freeze(Object.fromEntries(
  Object.entries(SIGNATURES_FONCTIONS).map(([nom, sig]) => [nom, octetsVersHex(keccak256(utf8(sig)).subarray(0, 4))]),
));

/** Signatures des événements de CT-4 §5.7 lus par le composant. */
export const SIGNATURES_EVENEMENTS = Object.freeze({
  PeriodSubmitted: "PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)",
  Anchored: "Anchored(bytes32,address,bytes32)",
  Revoked: "Revoked(bytes32,address)",
  RecorderRegistered: "RecorderRegistered(bytes32,address,bytes32,bytes32,address)",
  RecorderRevoked: "RecorderRevoked(bytes32,address,address)",
  CuratorSetAssigned: "CuratorSetAssigned(bytes32,address,address)",
  AdminOpRelayed: "AdminOpRelayed(bytes32,address,uint256)",
});

/** `topics[0]` de chaque événement. */
export const SUJETS = Object.freeze(Object.fromEntries(
  Object.entries(SIGNATURES_EVENEMENTS).map(([nom, sig]) => [nom, keccakHex(sig)]),
));

/** Événement attendu et contrat de chaque rôle d'index de capture (CP-5). */
export const EVENEMENT_PAR_ROLE = Object.freeze({
  inscription: "RecorderRegistered",
  revocation: "RecorderRevoked",
  ancre: "Anchored",
  cloture: "PeriodSubmitted",
  assignation: "CuratorSetAssigned",
  reassignation: "CuratorSetAssigned",
  administration_jeu: "AdminOpRelayed",
});

// ---------------------------------------------------------- Encodage ABI

function motSignature(sig) {
  if (!sig || typeof sig !== "object") throw new TypeError("signature {v, r, s} attendue");
  const v = versEntier(sig.v);
  if (v === null || v > 255n || typeof sig.v !== "number") throw new TypeError("v hors de uint8");
  return concatener(u256(v), b32(sig.r), b32(sig.s));
}

function motAdresse(adresse) {
  return concatener(new Uint8Array(12), a20(adresse));
}

function sel(nom) {
  return hexVersOctets(SELECTEURS[nom]);
}

/**
 * RG-14 : données d'appel d'`anchor(fingerprint, docType, issuer, sig)`,
 * 196 octets.
 */
export function encoderAnchor({ fingerprint, doc_type, issuer, signature }) {
  return concatener(sel("anchor"), b32(fingerprint), b32(doc_type), motAdresse(issuer), motSignature(signature));
}

/**
 * RG-14 : données d'appel de `submitPeriod(meta, sigs)` : `0x8af03732 ‖
 * u256(0x40) ‖ u256(0x40 + L) ‖ T(meta) ‖ u256(k) ‖ k × (v ‖ r ‖ s)`.
 */
export function encoderSubmitPeriod({ period_meta, signatures }) {
  if (!Array.isArray(signatures)) throw new TypeError("tableau de signatures attendu");
  const tuple = encoderTuplePeriodMeta(period_meta);
  return concatener(
    sel("submitPeriod"), u256(0x40n), u256(BigInt(0x40 + tuple.length)), tuple,
    u256(BigInt(signatures.length)), ...signatures.map(motSignature),
  );
}

/**
 * RG-14 : données d'appel de `registerRecorder(orgId, journalId, chainKey,
 * ed25519PubKey, sigs)`.
 */
export function encoderRegisterRecorder({ org_id, journal_id, chain_key, ed25519_public_key, signatures }) {
  if (!Array.isArray(signatures)) throw new TypeError("tableau de signatures attendu");
  return concatener(
    sel("registerRecorder"), b32(org_id), b32(journal_id), motAdresse(chain_key), b32(ed25519_public_key),
    u256(0xa0n), u256(BigInt(signatures.length)), ...signatures.map(motSignature),
  );
}

/**
 * RG-14 : données d'appel de `revokeRecorder(orgId, chainKey, sigs)` (CT-4
 * §8.4, EX-8.7 ; étape 7, rotation de la clé de chaîne relayée par le démon).
 */
export function encoderRevokeRecorder({ org_id, chain_key, signatures }) {
  if (!Array.isArray(signatures)) throw new TypeError("tableau de signatures attendu");
  return concatener(
    sel("revokeRecorder"), b32(org_id), motAdresse(chain_key),
    u256(0x60n), u256(BigInt(signatures.length)), ...signatures.map(motSignature),
  );
}

/** Données d'appel des lectures par `eth_call`. */
export const encoderLookup = (fingerprint) => concatener(sel("lookup"), b32(fingerprint));
export const encoderIsAnchored = (fingerprint) => concatener(sel("isAnchored"), b32(fingerprint));
export const encoderAnchorDigest = (fingerprint, docType) => concatener(sel("anchorDigest"), b32(fingerprint), b32(docType));
export const encoderPeriodDigest = (meta) => concatener(sel("periodDigest"), encoderPeriodMeta(meta));
export const encoderIsActiveRecorder = (orgId, chainKey) => concatener(sel("isActiveRecorder"), b32(orgId), motAdresse(chainKey));
export const encoderRecorderOf = (orgId, chainKey) => concatener(sel("recorderOf"), b32(orgId), motAdresse(chainKey));
export const encoderRecorderByPubKey = (orgId, pubKey) => concatener(sel("recorderByPubKey"), b32(orgId), b32(pubKey));
export const encoderIsKnown = (orgId, periodHash) => concatener(sel("isKnown"), b32(orgId), b32(periodHash));
export const encoderLatestPeriodOf = (orgId, journalId) => concatener(sel("latestPeriodOf"), b32(orgId), b32(journalId));
export const encoderGetPeriod = (id) => concatener(sel("getPeriod"), u256(versEntier(id)));

// ---------------------------------------------------------- Décodage ABI

/** Découpe une donnée hexadécimale en mots de 32 octets ; null si la longueur n'est pas un multiple de 32. */
export function mots(hex) {
  if (typeof hex !== "string" || !/^0x([0-9a-f]{2})*$/.test(hex)) return null;
  const octets = hexVersOctets(hex);
  if (octets.length % 32 !== 0) return null;
  const sortie = [];
  for (let k = 0; k < octets.length; k += 32) sortie.push(octets.subarray(k, k + 32));
  return sortie;
}

function motVersAdresse(mot) {
  for (let k = 0; k < 12; k++) if (mot[k] !== 0) return null;
  return octetsVersHex(mot.subarray(12));
}

function motVersEntier(mot, max) {
  const x = octetsVersEntier(mot);
  return x > max ? null : x;
}

/** Retour de `lookup(bytes32)` : `(issuer, docType, issuedAt, revokedAt)`. */
export function decoderLookup(hex) {
  const m = mots(hex);
  if (!m || m.length !== 4) return null;
  const issuer = motVersAdresse(m[0]);
  const issuedAt = motVersEntier(m[2], MAX_U64);
  const revokedAt = motVersEntier(m[3], MAX_U64);
  if (issuer === null || issuedAt === null || revokedAt === null) return null;
  return { issuer, docType: octetsVersHex(m[1]), issuedAt, revokedAt };
}

/** Retour de `recorderOf` et `recorderByPubKey` : `(chainKey, ed25519PubKey, journalId, registeredAt, revokedAt)`. */
export function decoderRecorder(hex) {
  const m = mots(hex);
  if (!m || m.length !== 5) return null;
  const chainKey = motVersAdresse(m[0]);
  const registeredAt = motVersEntier(m[3], MAX_U64);
  const revokedAt = motVersEntier(m[4], MAX_U64);
  if (chainKey === null || registeredAt === null || revokedAt === null) return null;
  return { chainKey, ed25519PubKey: octetsVersHex(m[1]), journalId: octetsVersHex(m[2]), registeredAt, revokedAt };
}

/** Retour d'une fonction qui rend `bool`. */
export function decoderBool(hex) {
  const m = mots(hex);
  if (!m || m.length !== 1) return null;
  const x = octetsVersEntier(m[0]);
  if (x === 0n) return false;
  if (x === 1n) return true;
  return null;
}

/** Retour d'une fonction qui rend `bytes32`. */
export function decoderBytes32(hex) {
  const m = mots(hex);
  return m && m.length === 1 ? octetsVersHex(m[0]) : null;
}

/** Retour d'une fonction qui rend `uint256`. */
export function decoderUint(hex) {
  const m = mots(hex);
  return m && m.length === 1 ? octetsVersEntier(m[0]) : null;
}

/**
 * Retour de `getPeriod(uint256)` : tuple dynamique `(orgId, journalId,
 * periodHash, root, periodStart, periodEnd, firstSeq, lastSeq, publishedAt,
 * version, publisher, uri)`.
 */
export function decoderGetPeriod(hex) {
  const m = mots(hex);
  if (!m || m.length < 13) return null;
  const position = motVersEntier(m[0], 0x1000n);
  if (position !== 0x20n) return null;
  const t = m.slice(1);
  const uriPos = motVersEntier(t[11], BigInt(32 * t.length));
  if (uriPos !== 0x180n) return null;
  const longueur = motVersEntier(t[12], 4096n);
  if (longueur === null) return null;
  const octets = hexVersOctets(hex).subarray(32 + 0x180 + 32);
  if (octets.length < Number(longueur)) return null;
  const publisher = motVersAdresse(t[10]);
  if (publisher === null) return null;
  const entier = (k, max) => motVersEntier(t[k], max);
  const champs = {
    orgId: octetsVersHex(t[0]), journalId: octetsVersHex(t[1]), periodHash: octetsVersHex(t[2]), root: octetsVersHex(t[3]),
    periodStart: entier(4, MAX_U64), periodEnd: entier(5, MAX_U64), firstSeq: entier(6, MAX_U64), lastSeq: entier(7, MAX_U64),
    publishedAt: entier(8, MAX_U64), version: entier(9, MAX_U32), publisher,
    uri: new TextDecoder("utf-8", { fatal: false }).decode(octets.subarray(0, Number(longueur))),
  };
  for (const v of Object.values(champs)) if (v === null) return null;
  return champs;
}

// ------------------------------------------------- Journaux d'événements

function sujetAdresse(sujet) {
  const m = mots(sujet);
  return m && m.length === 1 ? motVersAdresse(m[0]) : null;
}

/**
 * Décode le journal prouvé d'un rôle selon CT-6 EX-11.9 (`ancre`,
 * `ancre_point_de_controle`, `cloture`, `inscription`) ; null si la forme
 * (nombre de sujets, `topics[0]`, longueur et remplissage des données) n'est
 * pas celle du rôle.
 */
export function decoderJournal(role, journal) {
  if (!journal || typeof journal !== "object" || !Array.isArray(journal.topics)) return null;
  const topics = journal.topics;
  if (!topics.every((t) => estHexOctets(t, 32))) return null;
  if (typeof journal.data !== "string" || !/^0x([0-9a-f]{2})*$/.test(journal.data)) return null;
  if (role === "ancre" || role === "ancre_point_de_controle") {
    if (topics.length !== 3 || topics[0] !== SUJETS.Anchored) return null;
    const issuer = sujetAdresse(topics[2]);
    if (issuer === null || !estHexOctets(journal.data, 32)) return null;
    // R-11, règle 1 : l'entrée d'un point porte le docType du point, jamais celui de la période ni un autre.
    if (role === "ancre_point_de_controle" && journal.data !== DOC_TYPE_POINT_DE_CONTROLE) return null;
    return { name: "Anchored", fingerprint: topics[1], issuer, docType: journal.data };
  }
  if (role === "inscription") {
    if (topics.length !== 4 || topics[0] !== SUJETS.RecorderRegistered) return null;
    const chainKey = sujetAdresse(topics[2]);
    const m = mots(journal.data);
    if (chainKey === null || !m || m.length !== 2) return null;
    const publisher = motVersAdresse(m[1]);
    if (publisher === null) return null;
    return { name: "RecorderRegistered", orgId: topics[1], chainKey, journalId: topics[3], ed25519PubKey: octetsVersHex(m[0]), publisher };
  }
  if (role === "revocation") {
    if (topics.length !== 3 || topics[0] !== SUJETS.RecorderRevoked) return null;
    const chainKey = sujetAdresse(topics[2]);
    const m = mots(journal.data);
    if (chainKey === null || !m || m.length !== 1) return null;
    const publisher = motVersAdresse(m[0]);
    if (publisher === null) return null;
    return { name: "RecorderRevoked", orgId: topics[1], chainKey, publisher };
  }
  if (role === "cloture") {
    if (topics.length !== 4 || topics[0] !== SUJETS.PeriodSubmitted) return null;
    const relayeur = sujetAdresse(topics[3]);
    const m = mots(journal.data);
    if (relayeur === null || !m || m.length < 11) return null;
    const w = (k, max) => motVersEntier(m[k], max);
    const position = w(8, 0x1000n);
    if (position !== 0x140n) return null;
    const longueur = w(10, 4096n);
    if (longueur === null) return null;
    const attendu = 11 + Math.ceil(Number(longueur) / 32);
    if (m.length !== attendu) return null;
    const octetsUri = hexVersOctets(journal.data).subarray(11 * 32);
    for (let k = Number(longueur); k < octetsUri.length; k++) if (octetsUri[k] !== 0) return null;
    const champs = {
      name: "PeriodSubmitted", id: octetsVersEntier(hexVersOctets(topics[1])), periodHash: topics[2], publisher: relayeur,
      orgId: octetsVersHex(m[0]), journalId: octetsVersHex(m[1]), root: octetsVersHex(m[2]),
      periodStart: w(3, MAX_U64), periodEnd: w(4, MAX_U64), firstSeq: w(5, MAX_U64), lastSeq: w(6, MAX_U64), version: w(7, MAX_U32),
      publishedAt: w(9, MAX_U64), uri: new TextDecoder("utf-8", { fatal: false }).decode(octetsUri.subarray(0, Number(longueur))),
    };
    for (const v of Object.values(champs)) if (v === null) return null;
    return champs;
  }
  return null;
}

/** Met une adresse servie en casse mixte (EIP-55) en minuscules ; null si ce n'est pas une adresse. */
export function adresseMinuscule(v) {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(v)) return null;
  return v.toLowerCase();
}

/** Entier `uint8`, `uint64`, `uint256` en mot de 32 octets (pour les tests et les fixtures). */
export function motEntier(x, octets = 32) {
  return entierVersOctets(versEntier(x), octets);
}
