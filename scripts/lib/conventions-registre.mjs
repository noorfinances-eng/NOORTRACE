// Conventions du registre (spec/CT-4-registre.md) : tout ce qui se calcule
// hors chaîne, sans réseau ni système de fichiers, pour les outils de
// référence (scripts/registre/noortrace-registre.mjs), le générateur des
// vecteurs (scripts/vecteurs/generer-ct4.mjs) et les tests.
//
//   RG-1 à RG-3    identifiants org_id, journal_id, docType (6.2 à 6.4) ;
//   RG-4           empreinte d'ancre (6.5) ;
//   RG-5 à RG-13   champs d'une clôture, six condensés internes, hachage signé,
//                  signatures et jeu de signatures au seuil (6.6) ;
//   RG-14, RG-15   données d'appel (ABI, 6.7.2) et transactions de type 2
//                  (RLP, EIP-1559, 6.7.3) ;
//   RG-16 à RG-20  manifeste d'instance (4.8, 6.8) ;
//   OP-4, OP-6,    vérifications des outils qui se calculent hors chaîne
//   OP-7           (dossier d'inscription, demande de signature, 7.3) ;
//   CP-2 à CP-6    capture d'une transaction, relue sur ses fichiers (9.4) ;
//   export         parties registre.json, certificat-commit.json et
//                  validateurs.json d'un dossier (9.6).
//
// Chaque vérification rend { check, status: "reussi" | "echoue", code, detail,
// valeurs } : `code` est nul quand elle réussit ; pour une RG- c'est un motif
// stable (table MOTIFS_RG), pour une OP- ou une CP- le code d'erreur de la
// spécification (7.11, 9.3). Les octets sont écrits en hexadécimal minuscule
// préfixé 0x (CT-1 §3) ; les entiers de 64 bits et plus, en BigInt dans le
// code et en chaînes décimales dans les documents.
//
// Les encodages (ABI, RLP) suivent la spécification pas à pas, sans
// l'encodeur d'ethers : test/registreCt4.test.js les confronte à ethers et aux
// transactions réelles de la capture de CT-6. ethers ne sert qu'à keccak256 et
// à secp256k1 (signature RFC 6979, recouvrement).

import { SigningKey, computeAddress, getAddress, keccak256 } from "ethers";
import { chargerJeuValidateurs, hachageJeuValidateurs, quorum, verifierCertificat, analyserEnveloppe } from "./certificat-commit.mjs";
import { hachageManifeste, sha256 as sha256Journal, validerSchema, egalJSON } from "./journal.mjs";
import { decoderJournal, entreeRegistre, hachageBlocBFT, octetsEntier, racineRecus, racineTrie, rlp } from "./registre.mjs";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

export const ID_SCHEMA_INSTANCE = "https://noortrace.example/schemas/v0/instance-registre.schema.json";
export const ID_SCHEMA_INSCRIPTION = "https://noortrace.example/schemas/v0/inscription-client.schema.json";
export const ID_SCHEMA_OPERATIONS = "https://noortrace.example/schemas/v0/operations-registre.schema.json";

/** Réseau de développement de chain/ (chain/README.md, « Identifiants ») et réseau Hardhat en mémoire des tests (EX-A.6). */
export const RESEAU_DEVELOPPEMENT = Object.freeze({ evm_chain_id: 2124, bft_chain_id: "noortrace-2124-dev" });
export const RESEAU_ESSAI = Object.freeze({ evm_chain_id: 31337, bft_chain_id: "noortrace-31337-essai" });

export const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const MOITIE_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
export const U64_MAX = (1n << 64n) - 1n;
export const HACHAGE_NUL = "0x" + "00".repeat(32);
export const ADRESSE_NULLE = "0x" + "00".repeat(20);

/** Préfixe EIP-191 de 28 octets (6.6.3). */
export const PREFIXE_EIP191 = "\x19Ethereum Signed Message:\n32";

/** Étiquettes de domaine des condensés internes (6.6.2). */
export const ETIQUETTES = Object.freeze({
  periode: "noortrace-periode",
  inscription: "noortrace-enregistreur-inscrit",
  revocation: "noortrace-enregistreur-revoque",
  ancre: "noor-attestation-ancre",
  revocation_ancre: "noor-attestation-revoque",
});

/** Grammaire du slug et du nom de journal (EX-6.2, EX-6.4). */
export const RE_NOM = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
/** Slug d'une organisation de production : « o- » et 32 chiffres hexadécimaux (EX-6.2). */
export const RE_SLUG_PRODUCTION = /^o-[0-9a-f]{32}$/;
/** Grammaire d'un libellé de docType (EX-6.5). */
export const RE_LIBELLE_DOCTYPE = /^noortrace\/[a-z0-9][a-z0-9-]{0,31}\/v(0|[1-9][0-9]{0,2})$/;
/** URI d'une clôture : vide ou au plus 64 caractères ASCII imprimables (EX-6.8). */
export const RE_URI = /^[\x20-\x7e]{0,64}$/;

/** Table des docType de CT-4 (EX-6.5) : libellé, valeur, usage. */
export const DOCTYPES = Object.freeze([
  Object.freeze({ label: "noortrace/periode/v0", doc_type: "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee", usage: "ancre de la période d'un journal (6.5)" }),
]);

/** Opérations signées d'un CuratorSet (6.6.2) : op = keccak256(utf8(nom)), fonction relayée. */
export const OPERATIONS_JEU = Object.freeze({
  "CuratorSet.addCurator": { fonction: "addCuratorSigned", argument: "adresse" },
  "CuratorSet.removeCurator": { fonction: "removeCuratorSigned", argument: "adresse" },
  "CuratorSet.setThreshold": { fonction: "setThresholdSigned", argument: "entier" },
  "CuratorSet.proposeAdmin": { fonction: "proposeAdminSigned", argument: "adresse" },
  "CuratorSet.acceptAdmin": { fonction: "acceptAdminSigned", argument: "aucun" },
});

/** Signatures des fonctions appelées ou lues par les outils (6.7.1). */
export const SIGNATURES_FONCTIONS = Object.freeze({
  anchor: "anchor(bytes32,bytes32,address,(uint8,bytes32,bytes32))",
  revoke: "revoke(bytes32,(uint8,bytes32,bytes32))",
  submitPeriod: "submitPeriod((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string),(uint8,bytes32,bytes32)[])",
  registerRecorder: "registerRecorder(bytes32,bytes32,address,bytes32,(uint8,bytes32,bytes32)[])",
  revokeRecorder: "revokeRecorder(bytes32,address,(uint8,bytes32,bytes32)[])",
  setCuratorSet: "setCuratorSet(bytes32,address)",
  proposeAdmin: "proposeAdmin(address)",
  acceptAdmin: "acceptAdmin()",
  addCuratorSigned: "addCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
  removeCuratorSigned: "removeCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
  setThresholdSigned: "setThresholdSigned(uint256,uint256,(uint8,bytes32,bytes32))",
  proposeAdminSigned: "proposeAdminSigned(address,uint256,(uint8,bytes32,bytes32))",
  acceptAdminSigned: "acceptAdminSigned(uint256,(uint8,bytes32,bytes32))",
});

/** Sélecteurs attendus (table de 6.7.1), confrontés au recalcul au chargement. */
export const SELECTEURS = Object.freeze({
  anchor: "0x73deb4ad",
  revoke: "0x7e9d5abd",
  submitPeriod: "0x8af03732",
  registerRecorder: "0x982f962e",
  revokeRecorder: "0x7b2025ea",
  setCuratorSet: "0x53823884",
  proposeAdmin: "0x147bf6c4",
  acceptAdmin: "0x0e18b681",
  addCuratorSigned: "0xd3dc8837",
  removeCuratorSigned: "0xa7484439",
  setThresholdSigned: "0xf4db2a99",
  proposeAdminSigned: "0x34e182a6",
  acceptAdminSigned: "0x7af25fd9",
});

/** Événements du registre (5.7) : signature et topics[0]. */
export const EVENEMENTS = Object.freeze({
  PeriodSubmitted: { signature: "PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)", topic: "0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba" },
  Anchored: { signature: "Anchored(bytes32,address,bytes32)", topic: "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e" },
  Revoked: { signature: "Revoked(bytes32,address)", topic: "0x5bc2baf870c5baf189838b5e0b0e3b04a3263e2df5d305d1c15f3e6022f5dc45" },
  RecorderRegistered: { signature: "RecorderRegistered(bytes32,address,bytes32,bytes32,address)", topic: "0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec" },
  RecorderRevoked: { signature: "RecorderRevoked(bytes32,address,address)", topic: "0x74ae31d8dbb96eed3dc2e0064cb3b980f6289d88b35c82b2863e40705567fa74" },
  CuratorSetAssigned: { signature: "CuratorSetAssigned(bytes32,address,address)", topic: "0xe3dc53929964ea6820df23c3069981538b21f654bd176471a4befe2eb6da9b23" },
  CuratorAdded: { signature: "CuratorAdded(address)", topic: "0x18c43d122320e51fe6358fec30ac29762ead2d8f27e59d405344cb9e09b68b5c" },
  CuratorRemoved: { signature: "CuratorRemoved(address)", topic: "0x94444aede86802e5301b671c64873189b3e1ab371ad0dbf9eb182b71de1bf2fc" },
  ThresholdUpdated: { signature: "ThresholdUpdated(uint256)", topic: "0xadfa8ecb21b6962ebcd0adbd9ab985b7b4c5b5eb3b0dead683171565c7bfe171" },
  AdminProposed: { signature: "AdminProposed(address,address)", topic: "0xfd22260ca7b3d2a5f6332770491ab546b6235bc73909c334f5e304d2fae455b1" },
  AdminAccepted: { signature: "AdminAccepted(address,address)", topic: "0x12309f939c005790a0458600b5b21d505bb0d61ad30e57962e52c68748788bdc" },
  AdminOpRelayed: { signature: "AdminOpRelayed(bytes32,address,uint256)", topic: "0x2e0e19053817f36938ec18c54c0901f672942223a90e78527399eb1b1db54b0a" },
});

/** Événement prouvé par rôle d'un index de capture (9.4, CP-5) ; null : pas de journal prouvé (log_index nul). */
export const EVENEMENT_DU_ROLE = Object.freeze({
  deploiement: null,
  jeu_approbateurs: null,
  approvisionnement: null,
  assignation: "CuratorSetAssigned",
  reassignation: "CuratorSetAssigned",
  inscription: "RecorderRegistered",
  revocation: "RecorderRevoked",
  ancre: "Anchored",
  cloture: "PeriodSubmitted",
  administration_jeu: "AdminOpRelayed",
});

/** Rôles des index de capture (operations-registre-v0). */
export const ROLES_CAPTURE = Object.keys(EVENEMENT_DU_ROLE);

/** Frais par défaut du manifeste (4.8, EX-4.15 à EX-4.19). */
export const FRAIS_DEFAUT = Object.freeze({
  transaction_type: 2,
  max_fee_per_gas_wei: "1",
  max_priority_fee_per_gas_wei: "1",
  gas_limit: 3000000,
  gas_limit_max: 16777216,
  provision_days: 30,
  refill_below_days: 7,
});

/** Gaz de référence des opérations (table d'EX-4.19). */
export const GAZ_REFERENCE = Object.freeze({ anchor: 100000, submitPeriod: 350000, registerRecorder: 200000, revokeRecorder: 200000 });

/** Budget journalier par défaut : un journal horaire, 24 × (ancre + clôture) (7.5). */
export const BUDGET_JOUR_DEFAUT = 24 * (GAZ_REFERENCE.anchor + GAZ_REFERENCE.submitPeriod);

/** Motifs d'échec des vérifications RG- (codes de `refusal` des vecteurs). */
export const MOTIFS_RG = Object.freeze({
  "RG-1": ["slug_invalide"],
  "RG-2": ["nom_journal_invalide"],
  "RG-3": ["libelle_invalide", "libelle_hors_table", "doctype_nul", "doctype_hors_table"],
  "RG-4": ["entree_nulle", "empreinte_differente"],
  "RG-5": ["periode_invalide", "discontinuite_temporelle", "discontinuite_sequence"],
  "RG-6": ["entree_invalide", "condense_different"],
  "RG-7": ["entree_invalide", "condense_different"],
  "RG-8": ["entree_invalide", "condense_different"],
  "RG-9": ["entree_invalide", "condense_different"],
  "RG-10": ["entree_invalide", "condense_different"],
  "RG-11": ["entree_invalide", "condense_different"],
  "RG-12": ["signature_non_canonique", "signataire_different", "hachage_signe_different"],
  "RG-13": ["signataire_hors_jeu", "signataire_double", "ordre_signatures", "nombre_signatures"],
  "RG-14": ["entree_invalide", "donnees_differentes"],
  "RG-15": ["transaction_illisible", "type_non_admis", "chaine_differente", "frais_non_conformes", "limite_gaz", "liste_acces", "signature_non_canonique", "objet_non_conforme"],
  "RG-16": ["schema", "revision_mal_chainee"],
  "RG-17": ["genese_differente", "genese_invalide", "regles_invalides", "ligne_regles_differente", "identifiants_incoherents", "offre_differente"],
  "RG-18": ["jeu_invalide", "valset_hash_different", "operateurs_incoherents", "intervalles_incoherents", "domaine_de_panne"],
  "RG-19": ["adresse_creation", "arguments_constructeur", "contrats_en_service", "preuve_absente", "preuve_invalide"],
  "RG-20": ["ancre_differente", "derivation_impossible"],
});

// ---------------------------------------------------------------------------
// Octets
// ---------------------------------------------------------------------------

/** Octets d'une chaîne 0x… (longueur paire) ; `longueur` facultative exigée. */
export function octets(h, longueur = null, nom = "valeur") {
  if (typeof h !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(h)) throw new Error(`${nom} : hexadécimal 0x… attendu`);
  const b = Buffer.from(h.slice(2), "hex");
  if (longueur !== null && b.length !== longueur) throw new Error(`${nom} : ${longueur} octets attendus, ${b.length} reçus`);
  return b;
}

/** 0x… minuscule d'octets. */
export function hex(b) {
  return "0x" + Buffer.from(b).toString("hex");
}

/** keccak256 en Buffer. */
export function keccak(b) {
  return Buffer.from(keccak256(b).slice(2), "hex");
}

/** u256(x) : 32 octets grand-boutistes. */
export function u256(x) {
  const v = BigInt(x);
  if (v < 0n || v >= 1n << 256n) throw new Error("u256 : hors de [0, 2^256)");
  return Buffer.from(v.toString(16).padStart(64, "0"), "hex");
}

/** u64(x) : 8 octets grand-boutistes. */
export function u64(x) {
  const v = BigInt(x);
  if (v < 0n || v > U64_MAX) throw new Error("u64 : hors de [0, 2^64)");
  return Buffer.from(v.toString(16).padStart(16, "0"), "hex");
}

/** a20 : les 20 octets d'une adresse (casse indifférente). */
export function a20(a) {
  return octets(String(a).toLowerCase(), 20, "adresse");
}

/** b32 : 32 octets tels quels. */
export function b32(h, nom = "bytes32") {
  return octets(String(h).toLowerCase(), 32, nom);
}

/** Adresse en minuscules (une adresse EIP-55 est ramenée en minuscules, section 0). */
export function adresseMinuscule(a) {
  if (typeof a !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error(`adresse invalide : ${String(a).slice(0, 60)}`);
  return a.toLowerCase();
}

export function estNul(h) {
  return /^0x0*$/.test(String(h));
}

/** Quantité JSON-RPC sans zéro de tête (section 0). */
export function quantiteRPC(n) {
  return "0x" + BigInt(n).toString(16);
}

/** Entier décimal d'une valeur (nombre, chaîne décimale, BigInt) ; erreur sinon. */
export function entier(v, nom = "entier") {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === "string" && /^(0|[1-9][0-9]{0,77})$/.test(v)) return BigInt(v);
  throw new Error(`${nom} : entier décimal attendu`);
}

/** Entier JSON de section 0 : nombre jusqu'à 2^53 − 1, chaîne décimale au-delà. */
export function entierJSON(n) {
  const v = BigInt(n);
  return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString();
}

function sha256Hex(octetsBruts) {
  return sha256Journal(octetsBruts);
}

// ---------------------------------------------------------------------------
// Résultats des vérifications
// ---------------------------------------------------------------------------

/** Erreur portée par une vérification : son identifiant et son code. */
export class EchecVerification extends Error {
  constructor(check, code, message) {
    super(message);
    this.check = check;
    this.code = code;
  }
}

export function reussite(check, valeurs = {}, detail = "") {
  return { check, status: "reussi", code: null, detail, valeurs };
}

export function echec(check, code, detail) {
  return { check, status: "echoue", code, detail, valeurs: null };
}

/** Exécute `f` (qui lève EchecVerification) et rend une vérification. */
export function verifier(check, f) {
  try {
    return reussite(check, f());
  } catch (err) {
    if (err instanceof EchecVerification) return echec(err.check, err.code, err.message);
    return echec(check, MOTIFS_RG[check]?.[0] ?? "entree_invalide", err.message);
  }
}

function exiger(condition, check, code, message) {
  if (!condition) throw new EchecVerification(check, code, message);
}

// ---------------------------------------------------------------------------
// RG-1, RG-2 : org_id et journal_id (6.2, 6.3)
// ---------------------------------------------------------------------------

/** keccak256(utf8(s)). */
export function keccakTexte(s) {
  return keccak256(Buffer.from(s, "utf8"));
}

/** RG-1 : slug conforme et org_id = keccak256(utf8(slug)). `production` exige la forme « o- » et 32 chiffres hexadécimaux. */
export function orgIdDuSlug(slug, { production = false } = {}) {
  exiger(typeof slug === "string" && RE_NOM.test(slug), "RG-1", "slug_invalide", `slug ${JSON.stringify(slug)} hors de la grammaire ^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`);
  if (production) exiger(RE_SLUG_PRODUCTION.test(slug), "RG-1", "slug_invalide", `slug de production ${JSON.stringify(slug)} : « o- » et 32 chiffres hexadécimaux attendus`);
  const org_id = keccakTexte(slug);
  exiger(!estNul(org_id), "RG-1", "slug_invalide", "org_id nul");
  return org_id;
}

/** RG-2 : nom de journal conforme et journal_id = keccak256(utf8(nom)). */
export function journalIdDuNom(nom) {
  exiger(typeof nom === "string" && RE_NOM.test(nom), "RG-2", "nom_journal_invalide", `nom de journal ${JSON.stringify(nom)} hors de la grammaire du slug`);
  const journal_id = keccakTexte(nom);
  exiger(!estNul(journal_id), "RG-2", "nom_journal_invalide", "journal_id nul");
  return journal_id;
}

// ---------------------------------------------------------------------------
// RG-3 : docType (6.4)
// ---------------------------------------------------------------------------

/** RG-3 depuis un libellé : grammaire, au plus 47 caractères, présence dans la table ; rend la valeur. */
export function docTypeDuLibelle(label) {
  exiger(typeof label === "string" && label.length <= 47 && RE_LIBELLE_DOCTYPE.test(label), "RG-3", "libelle_invalide", `libellé ${JSON.stringify(label)} hors de la grammaire ^noortrace/[a-z0-9][a-z0-9-]{0,31}/v(0|[1-9][0-9]{0,2})$`);
  const doc_type = keccakTexte(label);
  const ligne = DOCTYPES.find((d) => d.label === label);
  exiger(ligne, "RG-3", "libelle_hors_table", `libellé ${label} absent de la table de EX-6.5 (keccak256 ${doc_type})`);
  exiger(ligne.doc_type === doc_type, "RG-3", "libelle_hors_table", `valeur de la table différente du recalcul pour ${label}`);
  return doc_type;
}

/** RG-3 depuis une valeur de 32 octets : non nulle, dans la table ; rend le libellé. */
export function libelleDuDocType(doc_type) {
  const v = String(doc_type).toLowerCase();
  octets(v, 32, "docType");
  exiger(!estNul(v), "RG-3", "doctype_nul", "la valeur nulle n'est jamais un docType (EX-6.6)");
  const ligne = DOCTYPES.find((d) => d.doc_type === v);
  exiger(ligne, "RG-3", "doctype_hors_table", `docType ${v} absent de la table de EX-6.5`);
  return ligne.label;
}

/** docType des ancres de période (EX-6.6). */
export const DOC_TYPE_PERIODE = DOCTYPES[0].doc_type;

/**
 * docType des ancres d'un point de contrôle du journal (CT-4 §6.4 révision 0.3,
 * CT-1 §10.6, CT-5 §9) : keccak256(UTF-8("noortrace/point-de-controle/v0")).
 * Constante à part : la table DOCTYPES et le vecteur doctypes.json de CT-4
 * restent ceux de la révision 0.2 de CT-4 jusqu'à sa prochaine révision.
 */
export const DOC_TYPE_POINT_DE_CONTROLE = "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178";
if (keccakTexte("noortrace/point-de-controle/v0") !== DOC_TYPE_POINT_DE_CONTROLE) throw new Error("DOC_TYPE_POINT_DE_CONTROLE : valeur différente du recalcul");

// ---------------------------------------------------------------------------
// RG-4 : empreinte d'ancre (6.5)
// ---------------------------------------------------------------------------

/** RG-4 : préimage de 96 octets et empreinte ; `declaree` facultative doit être égale. */
export function empreinteAncre({ org_id, journal_id, period_hash, declaree = null }) {
  let pre;
  try {
    pre = Buffer.concat([b32(org_id, "org_id"), b32(journal_id, "journal_id"), b32(period_hash, "periodHash")]);
  } catch (err) {
    throw new EchecVerification("RG-4", "entree_nulle", err.message);
  }
  exiger(!estNul(org_id) && !estNul(journal_id) && !estNul(period_hash), "RG-4", "entree_nulle", "org_id, journal_id et periodHash ne sont jamais nuls");
  const fingerprint = hex(keccak(pre));
  exiger(!estNul(fingerprint), "RG-4", "empreinte_differente", "empreinte nulle");
  if (declaree !== null && declaree !== undefined) exiger(String(declaree).toLowerCase() === fingerprint, "RG-4", "empreinte_differente", `empreinte déclarée ${declaree} ≠ recalculée ${fingerprint}`);
  return { preimage: hex(pre), fingerprint };
}

// ---------------------------------------------------------------------------
// RG-5 : PeriodMeta d'une clôture (6.6.1)
// ---------------------------------------------------------------------------

/**
 * PeriodMeta d'un manifeste de période (CT-1 §10.4), forme de
 * operations-registre-v0#/$defs/meta_periode : periodHash recalculé
 * (CT-1 §10.2), bornes en chaînes décimales.
 */
export function metaDuManifeste(manifeste, uri = "") {
  return {
    org_id: String(manifeste.org_id).toLowerCase(),
    journal_id: String(manifeste.journal_id).toLowerCase(),
    period_hash: hachageManifeste(manifeste),
    root: String(manifeste.root).toLowerCase(),
    period_start: String(manifeste.period_start),
    period_end: String(manifeste.period_end),
    first_seq: String(manifeste.first_seq),
    last_seq: String(manifeste.last_seq),
    version: manifeste.version,
    uri,
  };
}

/** Lecture typée d'un PeriodMeta (meta_periode) : BigInt pour les bornes. */
export function metaTypee(meta) {
  const m = {
    orgId: b32(meta.org_id, "org_id"),
    journalId: b32(meta.journal_id, "journal_id"),
    periodHash: b32(meta.period_hash, "period_hash"),
    root: b32(meta.root, "root"),
    periodStart: entier(meta.period_start, "period_start"),
    periodEnd: entier(meta.period_end, "period_end"),
    firstSeq: entier(meta.first_seq, "first_seq"),
    lastSeq: entier(meta.last_seq, "last_seq"),
    version: entier(meta.version, "version"),
    uri: meta.uri,
  };
  for (const k of ["periodStart", "periodEnd", "firstSeq", "lastSeq"]) if (m[k] > U64_MAX) throw new Error(`${k} : hors de uint64`);
  if (m.version >= 1n << 32n) throw new Error("version : hors de uint32");
  if (typeof m.uri !== "string") throw new Error("uri : chaîne attendue");
  return m;
}

/**
 * RG-5 : ce que submitPeriod refuserait (contracts/PeriodRegistry.sol:176-203),
 * dans l'ordre du contrat, puis l'URI (EX-6.8). `precedente` : { period_end,
 * last_seq } de la dernière période du journal, si elle est connue ; `slug`,
 * `nom_journal` : préimages que l'URI ne doit pas contenir.
 */
export function verifierChampsCloture(meta, { precedente = null, slug = null, nom_journal = null } = {}) {
  let m;
  try {
    m = metaTypee(meta);
  } catch (err) {
    throw new EchecVerification("RG-5", "periode_invalide", err.message);
  }
  const C = (cond, msg) => exiger(cond, "RG-5", "periode_invalide", msg);
  C(!estNul(hex(m.orgId)), "orgId nul");
  C(!estNul(hex(m.journalId)), "journalId nul");
  C(!estNul(hex(m.periodHash)), "periodHash nul");
  C(m.periodStart < m.periodEnd, "periodStart ≥ periodEnd");
  C(m.periodEnd < U64_MAX, "periodEnd hors plage (2^64 − 1)");
  C(m.lastSeq < U64_MAX, "lastSeq hors plage (2^64 − 1)");
  const vide = m.lastSeq + 1n === m.firstSeq;
  if (vide) C(estNul(hex(m.root)), "racine non nulle d'une période vide");
  else {
    C(m.firstSeq <= m.lastSeq, "firstSeq > lastSeq + 1");
    C(!estNul(hex(m.root)), "racine nulle d'une période non vide");
  }
  if (precedente) {
    exiger(m.periodStart === entier(precedente.period_end, "period_end précédent"), "RG-5", "discontinuite_temporelle", `periodStart ${m.periodStart} ≠ periodEnd ${precedente.period_end} de la période précédente`);
    exiger(m.firstSeq === entier(precedente.last_seq, "last_seq précédent") + 1n, "RG-5", "discontinuite_sequence", `firstSeq ${m.firstSeq} ≠ lastSeq + 1 de la période précédente (${entier(precedente.last_seq) + 1n})`);
  }
  C(RE_URI.test(m.uri), "uri : chaîne vide ou au plus 64 caractères ASCII imprimables");
  if (slug) C(!m.uri.includes(slug), "uri : contient le slug de l'organisation");
  if (nom_journal) C(!m.uri.includes(nom_journal), "uri : contient le nom du journal");
  return { period_meta: { ...meta, org_id: hex(m.orgId), journal_id: hex(m.journalId), period_hash: hex(m.periodHash), root: hex(m.root), period_start: m.periodStart.toString(), period_end: m.periodEnd.toString(), first_seq: m.firstSeq.toString(), last_seq: m.lastSeq.toString(), version: Number(m.version), uri: m.uri }, empty: vide };
}

// ---------------------------------------------------------------------------
// Encodage ABI (6.7.2)
// ---------------------------------------------------------------------------

/** Encodage d'une string : u256(longueur) ‖ octets complétés à un multiple de 32. */
export function encoderChaine(s) {
  const o = Buffer.from(s, "utf8");
  const reste = o.length % 32 === 0 ? 0 : 32 - (o.length % 32);
  return Buffer.concat([u256(o.length), o, Buffer.alloc(reste)]);
}

/** Mot d'une adresse : 12 octets nuls ‖ a20. */
export function motAdresse(a) {
  return Buffer.concat([Buffer.alloc(12), a20(a)]);
}

/** Tuple Signature (v, r, s) : trois mots en place. */
export function motsSignature(sig) {
  const v = Number(sig.v);
  if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error("v : uint8 attendu");
  return Buffer.concat([u256(v), b32(sig.r, "r"), b32(sig.s, "s")]);
}

/** Tableau Signature[] : u256(k) ‖ k tuples. */
export function encoderSignatures(sigs) {
  return Buffer.concat([u256(sigs.length), ...sigs.map(motsSignature)]);
}

/** T(meta) : 352 + 32 × ⌈longueur(uri)/32⌉ octets (6.7.2, règle 4). */
export function tupleMeta(meta) {
  const m = metaTypee(meta);
  return Buffer.concat([m.orgId, m.journalId, m.periodHash, m.root, u256(m.periodStart), u256(m.periodEnd), u256(m.firstSeq), u256(m.lastSeq), u256(m.version), u256(0x140), encoderChaine(m.uri)]);
}

/** E(meta) = abi.encode(meta) = u256(0x20) ‖ T(meta). */
export function encoderMeta(meta) {
  return Buffer.concat([u256(0x20), tupleMeta(meta)]);
}

/** Sélecteur : 4 premiers octets de keccak256(utf8(signature)). */
export function selecteur(signature) {
  return keccak(Buffer.from(signature, "utf8")).subarray(0, 4);
}

for (const [nom, sig] of Object.entries(SIGNATURES_FONCTIONS)) {
  if (hex(selecteur(sig)) !== SELECTEURS[nom]) throw new Error(`sélecteur de ${nom} différent de la table de 6.7.1`);
}
for (const [nom, e] of Object.entries(EVENEMENTS)) {
  if (keccakTexte(e.signature) !== e.topic) throw new Error(`topics[0] de ${nom} différent de la table de 5.7`);
}

/** Argument `arg` d'une opération du jeu (table de 6.6.2). */
export function argumentOperationJeu(op, valeur) {
  const d = OPERATIONS_JEU[op];
  if (!d) throw new Error(`opération du jeu inconnue : ${op}`);
  if (d.argument === "adresse") return hex(motAdresse(valeur));
  if (d.argument === "entier") return hex(u256(entier(valeur, "seuil")));
  return HACHAGE_NUL;
}

/**
 * RG-14 : données d'appel d'une fonction du registre (table de 6.7.2).
 * `args` : objet nommé, octets en 0x…, entiers en nombre, chaîne ou BigInt,
 * signatures {v, r, s}, PeriodMeta au format meta_periode.
 */
export function donneesAppel(fonction, args) {
  const sel = SELECTEURS[fonction];
  if (!sel) throw new Error(`fonction inconnue : ${fonction}`);
  const s = octets(sel, 4);
  switch (fonction) {
    case "anchor":
      return hex(Buffer.concat([s, b32(args.fingerprint), b32(args.doc_type), motAdresse(args.issuer), motsSignature(args.signature)]));
    case "revoke":
      return hex(Buffer.concat([s, b32(args.fingerprint), motsSignature(args.signature)]));
    case "registerRecorder":
      return hex(Buffer.concat([s, b32(args.org_id), b32(args.journal_id), motAdresse(args.chain_key), b32(args.ed25519_public_key), u256(0xa0), encoderSignatures(args.signatures)]));
    case "revokeRecorder":
      return hex(Buffer.concat([s, b32(args.org_id), motAdresse(args.chain_key), u256(0x60), encoderSignatures(args.signatures)]));
    case "submitPeriod": {
      const T = tupleMeta(args.period_meta);
      return hex(Buffer.concat([s, u256(0x40), u256(0x40 + T.length), T, encoderSignatures(args.signatures)]));
    }
    case "setCuratorSet":
      return hex(Buffer.concat([s, b32(args.org_id), motAdresse(args.curator_set)]));
    case "proposeAdmin":
      return hex(Buffer.concat([s, motAdresse(args.new_admin)]));
    case "acceptAdmin":
      return hex(s);
    case "addCuratorSigned":
    case "removeCuratorSigned":
      return hex(Buffer.concat([s, motAdresse(args.curator), u256(entier(args.nonce, "nonce")), motsSignature(args.signature)]));
    case "proposeAdminSigned":
      return hex(Buffer.concat([s, motAdresse(args.new_admin), u256(entier(args.nonce, "nonce")), motsSignature(args.signature)]));
    case "setThresholdSigned":
      return hex(Buffer.concat([s, u256(entier(args.threshold, "seuil")), u256(entier(args.nonce, "nonce")), motsSignature(args.signature)]));
    case "acceptAdminSigned":
      return hex(Buffer.concat([s, u256(entier(args.nonce, "nonce")), motsSignature(args.signature)]));
    default:
      throw new Error(`fonction sans encodage : ${fonction}`);
  }
}

/** Fonction relayée et arguments d'appel d'une opération signée du jeu. */
export function appelOperationJeu(op, valeur, nonce, signature) {
  const d = OPERATIONS_JEU[op];
  if (!d) throw new Error(`opération du jeu inconnue : ${op}`);
  switch (d.fonction) {
    case "addCuratorSigned":
    case "removeCuratorSigned":
      return { fonction: d.fonction, args: { curator: valeur, nonce, signature } };
    case "proposeAdminSigned":
      return { fonction: d.fonction, args: { new_admin: valeur, nonce, signature } };
    case "setThresholdSigned":
      return { fonction: d.fonction, args: { threshold: valeur, nonce, signature } };
    default:
      return { fonction: d.fonction, args: { nonce, signature } };
  }
}

/**
 * Arguments de constructeur (6.7.2, dernier paragraphe) : la suite des
 * arguments, à ajouter au code de création. CuratorSet(address, address[],
 * uint256) ; CuratorSetRegistry(address) ; PeriodRegistry(address) ;
 * RecorderRegistry(address) ; AttestationRegistry() : aucun.
 */
export function argumentsConstructeur(contrat, args) {
  switch (contrat) {
    case "AttestationRegistry":
      return "0x";
    case "CuratorSetRegistry":
      return hex(motAdresse(args.initial_admin));
    case "PeriodRegistry":
    case "RecorderRegistry":
      return hex(motAdresse(args.curator_set_registry));
    case "CuratorSet":
      return hex(Buffer.concat([motAdresse(args.initial_admin), u256(0x60), u256(entier(args.threshold, "seuil")), u256(args.members.length), ...args.members.map(motAdresse)]));
    default:
      throw new Error(`contrat inconnu : ${contrat}`);
  }
}

/** RG-14 : données d'appel recalculées égales aux données déclarées. */
export function verifierDonneesAppel(fonction, args, declarees = null) {
  let calldata;
  try {
    calldata = donneesAppel(fonction, args);
  } catch (err) {
    throw new EchecVerification("RG-14", "entree_invalide", err.message);
  }
  if (declarees !== null) exiger(String(declarees).toLowerCase() === calldata, "RG-14", "donnees_differentes", `données déclarées (${(String(declarees).length - 2) / 2} octets) différentes de l'encodage de 6.7.2 (${(calldata.length - 2) / 2} octets)`);
  return { calldata, length: (calldata.length - 2) / 2 };
}

// ---------------------------------------------------------------------------
// RG-6 à RG-11 : condensés internes (6.6.2)
// ---------------------------------------------------------------------------

function entete(chain_id, contrat) {
  return Buffer.concat([u256(entier(chain_id, "chain_id")), a20(contrat)]);
}

function condenseDe(check, construire, declare) {
  let pre;
  try {
    pre = construire();
  } catch (err) {
    if (err instanceof EchecVerification) throw err;
    throw new EchecVerification(check, "entree_invalide", err.message);
  }
  const digest = hex(keccak(pre));
  if (declare !== null && declare !== undefined) exiger(String(declare).toLowerCase() === digest, check, "condense_different", `condensé déclaré ${declare} ≠ recalculé ${digest}`);
  return { preimage: hex(pre), preimage_length: pre.length, digest, eip191_digest: hachageSigne(digest) };
}

/** RG-6 : periodDigest(meta) ; préimage de 101 octets. */
export function condenseCloture({ chain_id, contract, period_meta, digest = null }) {
  return condenseDe(
    "RG-6",
    () => {
      const E = encoderMeta(period_meta);
      return Buffer.concat([entete(chain_id, contract), Buffer.from(ETIQUETTES.periode, "utf8"), keccak(E)]);
    },
    digest,
  );
}

/** RG-7 : registerDigest ; préimage de 198 octets ; aucun des quatre champs nul. */
export function condenseInscription({ chain_id, contract, org_id, journal_id, chain_key, ed25519_public_key, digest = null }) {
  return condenseDe(
    "RG-7",
    () => {
      exiger(!estNul(org_id) && !estNul(journal_id) && !estNul(chain_key) && !estNul(ed25519_public_key), "RG-7", "entree_invalide", "org_id, journal_id, clé de chaîne et clé Ed25519 ne sont jamais nuls (contracts/RecorderRegistry.sol:135-138)");
      return Buffer.concat([entete(chain_id, contract), Buffer.from(ETIQUETTES.inscription, "utf8"), b32(org_id), b32(journal_id), a20(chain_key), b32(ed25519_public_key)]);
    },
    digest,
  );
}

/** RG-8 : revokeDigest d'enregistreur ; préimage de 142 octets ; registeredAt non nul. */
export function condenseRevocation({ chain_id, contract, org_id, chain_key, registered_at, digest = null }) {
  return condenseDe(
    "RG-8",
    () => {
      const t = entier(registered_at, "registered_at");
      exiger(t !== 0n, "RG-8", "entree_invalide", "registeredAt nul : révocation avant l'inscription (EX-6.11)");
      return Buffer.concat([entete(chain_id, contract), Buffer.from(ETIQUETTES.revocation, "utf8"), b32(org_id), a20(chain_key), u64(t)]);
    },
    digest,
  );
}

/** RG-9 : anchorDigest ; préimage de 138 octets. */
export function condenseAncre({ chain_id, contract, fingerprint, doc_type, digest = null }) {
  return condenseDe("RG-9", () => Buffer.concat([entete(chain_id, contract), Buffer.from(ETIQUETTES.ancre, "utf8"), b32(fingerprint), b32(doc_type)]), digest);
}

/** RG-10 : revokeDigest d'attestation ; préimage de 108 octets. */
export function condenseRevocationAncre({ chain_id, contract, fingerprint, digest = null }) {
  return condenseDe("RG-10", () => Buffer.concat([entete(chain_id, contract), Buffer.from(ETIQUETTES.revocation_ancre, "utf8"), b32(fingerprint)]), digest);
}

/** RG-11 : adminOpDigest ; préimage de 148 octets. */
export function condenseOperationJeu({ chain_id, contract, op, arg, nonce, digest = null }) {
  return condenseDe(
    "RG-11",
    () => {
      exiger(Object.hasOwn(OPERATIONS_JEU, op), "RG-11", "entree_invalide", `opération du jeu inconnue : ${op}`);
      return Buffer.concat([entete(chain_id, contract), keccak(Buffer.from(op, "utf8")), b32(arg), u256(entier(nonce, "nonce"))]);
    },
    digest,
  );
}

// ---------------------------------------------------------------------------
// RG-12, RG-13 : hachage signé et signatures (6.6.3)
// ---------------------------------------------------------------------------

/** Hachage signé : keccak256(préfixe EIP-191 ‖ condensé interne). */
export function hachageSigne(digest) {
  return hex(keccak(Buffer.concat([Buffer.from(PREFIXE_EIP191, "latin1"), b32(digest, "condensé")])));
}

/** Clé secp256k1 de 32 octets (0x…) en SigningKey. */
export function cleSigne(clePrivee) {
  return clePrivee instanceof SigningKey ? clePrivee : new SigningKey(clePrivee);
}

/** Adresse (minuscules) d'une clé privée. */
export function adresseDe(clePrivee) {
  return computeAddress(cleSigne(clePrivee).publicKey).toLowerCase();
}

/** Signature EIP-191 d'un condensé interne (RFC 6979, s bas) : { signer, v, r, s }. */
export function signerCondense(clePrivee, digest) {
  const k = cleSigne(clePrivee);
  const sig = k.sign(hachageSigne(digest));
  return { signer: computeAddress(k.publicKey).toLowerCase(), v: 27 + sig.yParity, r: sig.r.toLowerCase(), s: sig.s.toLowerCase() };
}

/** Signature en 65 octets r ‖ s ‖ u8(v) (6.6.3). */
export function signature65(sig) {
  return hex(Buffer.concat([b32(sig.r), b32(sig.s), Buffer.from([Number(sig.v)])]));
}

/** Signature {v, r, s} depuis 65 octets r ‖ s ‖ u8(v). */
export function signatureDe65(h) {
  const b = octets(h, 65, "signature");
  return { v: b[64], r: hex(b.subarray(0, 32)), s: hex(b.subarray(32, 64)) };
}

/**
 * RG-12 : forme canonique (r dans [1, n − 1], s dans [1, n/2], v ∈ {27, 28})
 * et signataire recouvré du hachage signé égal à `signer`. `eip191_digest`
 * facultatif : doit être le hachage signé du condensé.
 */
export function verifierSignature({ digest, signature, eip191_digest = null }) {
  const H = hachageSigne(digest);
  if (eip191_digest !== null && eip191_digest !== undefined) exiger(String(eip191_digest).toLowerCase() === H, "RG-12", "hachage_signe_different", `hachage signé déclaré ${eip191_digest} ≠ ${H}`);
  const v = Number(signature.v);
  let r;
  let s;
  try {
    r = BigInt(hex(b32(signature.r, "r")));
    s = BigInt(hex(b32(signature.s, "s")));
  } catch (err) {
    throw new EchecVerification("RG-12", "signature_non_canonique", err.message);
  }
  exiger(v === 27 || v === 28, "RG-12", "signature_non_canonique", `v = ${signature.v} hors de {27, 28}`);
  exiger(r >= 1n && r < N_SECP256K1, "RG-12", "signature_non_canonique", "r hors de [1, n − 1]");
  exiger(s >= 1n && s <= MOITIE_N, "RG-12", "signature_non_canonique", "s hors de [1, n/2] (s haut)");
  let recouvre;
  try {
    recouvre = computeAddress(SigningKey.recoverPublicKey(H, { r: hex(b32(signature.r)), s: hex(b32(signature.s)), v })).toLowerCase();
  } catch (err) {
    throw new EchecVerification("RG-12", "signataire_different", `aucune clé ne se recouvre : ${err.message}`);
  }
  if (signature.signer !== undefined && signature.signer !== null) exiger(recouvre === String(signature.signer).toLowerCase(), "RG-12", "signataire_different", `signataire recouvré ${recouvre} ≠ déclaré ${signature.signer}`);
  return { eip191_digest: H, recovered: recouvre, signature65: signature65(signature) };
}

/** Range des signatures par adresse de signataire croissante (RG-13). */
export function rangerSignatures(sigs) {
  return [...sigs].sort((a, b) => (a.signer.toLowerCase() < b.signer.toLowerCase() ? -1 : a.signer.toLowerCase() > b.signer.toLowerCase() ? 1 : 0));
}

/**
 * RG-13 : chaque signature passe RG-12 ; signataires distincts, membres de
 * `membres` (si fourni), rangés par adresse croissante ; exactement `seuil`
 * (`exact`) ou au moins `seuil` signatures.
 */
export function verifierJeuSignatures({ digest, signatures, membres = null, seuil, exact = true }) {
  const vus = new Set();
  let precedent = null;
  for (const [i, sig] of signatures.entries()) {
    const r = verifier("RG-12", () => verifierSignature({ digest, signature: sig }));
    if (r.status !== "reussi") throw new EchecVerification("RG-12", r.code, `signature ${i} : ${r.detail}`);
    const a = r.valeurs.recovered;
    exiger(!vus.has(a), "RG-13", "signataire_double", `signataire ${a} présent deux fois`);
    vus.add(a);
    if (membres) exiger(membres.map((m) => m.toLowerCase()).includes(a), "RG-13", "signataire_hors_jeu", `signataire ${a} hors du jeu`);
    exiger(precedent === null || precedent < a, "RG-13", "ordre_signatures", `signatures non rangées par adresse croissante (${precedent} puis ${a})`);
    precedent = a;
  }
  const t = Number(seuil);
  exiger(Number.isInteger(t) && t >= 1, "RG-13", "nombre_signatures", "seuil nul : jamais atteint");
  if (exact) exiger(signatures.length === t, "RG-13", "nombre_signatures", `${signatures.length} signature(s) pour un seuil de ${t} : exactement ${t} attendues`);
  else exiger(signatures.length >= t, "RG-13", "nombre_signatures", `${signatures.length} signature(s) pour un seuil de ${t}`);
  return { signers: signatures.map((s) => s.signer.toLowerCase()) };
}

// ---------------------------------------------------------------------------
// RLP et transactions de type 2 (6.7.3)
// ---------------------------------------------------------------------------

/** Décode un élément RLP canonique ; rend { valeur (Buffer | tableau), fin }. */
export function decoderRLP(b, debut = 0, profondeur = 0) {
  if (profondeur > 16) throw new Error("RLP : imbrication trop profonde");
  if (debut >= b.length) throw new Error("RLP : fin inattendue");
  const p = b[debut];
  const longueurLongue = (n) => {
    if (debut + 1 + n > b.length) throw new Error("RLP : fin inattendue");
    const L = b.subarray(debut + 1, debut + 1 + n);
    if (L[0] === 0) throw new Error("RLP : longueur à zéro de tête");
    const v = Number(BigInt(hex(L)));
    if (v <= 55) throw new Error("RLP : longueur longue pour une charge courte");
    return v;
  };
  if (p < 0x80) return { valeur: b.subarray(debut, debut + 1), fin: debut + 1 };
  if (p <= 0xb7) {
    const n = p - 0x80;
    if (debut + 1 + n > b.length) throw new Error("RLP : fin inattendue");
    const v = b.subarray(debut + 1, debut + 1 + n);
    if (n === 1 && v[0] < 0x80) throw new Error("RLP : octet seul encodé comme chaîne");
    return { valeur: v, fin: debut + 1 + n };
  }
  if (p <= 0xbf) {
    const nl = p - 0xb7;
    const n = longueurLongue(nl);
    const d = debut + 1 + nl;
    if (d + n > b.length) throw new Error("RLP : fin inattendue");
    return { valeur: b.subarray(d, d + n), fin: d + n };
  }
  let d;
  let n;
  if (p <= 0xf7) {
    n = p - 0xc0;
    d = debut + 1;
  } else {
    const nl = p - 0xf7;
    n = longueurLongue(nl);
    d = debut + 1 + nl;
  }
  if (d + n > b.length) throw new Error("RLP : fin inattendue");
  const liste = [];
  let i = d;
  while (i < d + n) {
    const e = decoderRLP(b, i, profondeur + 1);
    liste.push(e.valeur);
    i = e.fin;
  }
  if (i !== d + n) throw new Error("RLP : liste mal bornée");
  return { valeur: liste, fin: d + n };
}

/** Entier RLP canonique (octets minimaux, sans zéro de tête). */
function entierRLP(o, nom) {
  if (!Buffer.isBuffer(o)) throw new Error(`${nom} : chaîne RLP attendue`);
  if (o.length > 0 && o[0] === 0) throw new Error(`${nom} : entier à zéro de tête`);
  if (o.length > 32) throw new Error(`${nom} : entier de plus de 32 octets`);
  return o.length === 0 ? 0n : BigInt(hex(o));
}

/** Charge à signer d'une transaction de type 2 : 0x02 ‖ RLP([chainId, nonce, prio, max, gas, to, value, data, []]). */
export function chargeTransaction(tx) {
  const champs = [
    octetsEntier(entier(tx.chain_id, "chain_id")),
    octetsEntier(entier(tx.nonce, "nonce")),
    octetsEntier(entier(tx.max_priority_fee_per_gas, "max_priority_fee_per_gas")),
    octetsEntier(entier(tx.max_fee_per_gas, "max_fee_per_gas")),
    octetsEntier(entier(tx.gas_limit, "gas_limit")),
    tx.to === null || tx.to === undefined ? Buffer.alloc(0) : a20(tx.to),
    octetsEntier(entier(tx.value ?? 0, "value")),
    octets(tx.data ?? "0x"),
    [],
  ];
  return { champs, charge: Buffer.concat([Buffer.from([0x02]), rlp(champs)]) };
}

/** Signe une transaction de type 2 (RFC 6979, s bas) ; rend payload, hash à signer, signature, octets et hachage. */
export function signerTransaction(tx, clePrivee) {
  const { champs, charge } = chargeTransaction(tx);
  const aSigner = hex(keccak(charge));
  const sig = cleSigne(clePrivee).sign(aSigner);
  const brut = Buffer.concat([Buffer.from([0x02]), rlp([...champs, octetsEntier(sig.yParity), octetsEntier(BigInt(sig.r)), octetsEntier(BigInt(sig.s))])]);
  return {
    signing_payload: hex(charge),
    signing_hash: aSigner,
    y_parity: sig.yParity,
    r: sig.r.toLowerCase(),
    s: sig.s.toLowerCase(),
    raw_transaction: hex(brut),
    transaction_hash: hex(keccak(brut)),
    from: adresseDe(clePrivee),
  };
}

/** Décode une transaction de type 2 sérialisée et recouvre son expéditeur. */
export function decoderTransaction(brutHex) {
  const b = octets(brutHex, null, "transaction");
  if (b.length === 0 || b[0] !== 0x02) throw new EchecVerification("RG-15", "type_non_admis", `type ${b.length ? "0x" + b[0].toString(16).padStart(2, "0") : "absent"} : seul le type 2 est admis (EX-4.8)`);
  let d;
  try {
    d = decoderRLP(b, 1);
  } catch (err) {
    throw new EchecVerification("RG-15", "transaction_illisible", err.message);
  }
  exiger(d.fin === b.length, "RG-15", "transaction_illisible", "octets après la liste RLP");
  const L = d.valeur;
  exiger(Array.isArray(L) && L.length === 12, "RG-15", "transaction_illisible", "liste de 12 champs attendue");
  let tx;
  try {
    tx = {
      chain_id: entierRLP(L[0], "chainId"),
      nonce: entierRLP(L[1], "nonce"),
      max_priority_fee_per_gas: entierRLP(L[2], "maxPriorityFeePerGas"),
      max_fee_per_gas: entierRLP(L[3], "maxFeePerGas"),
      gas_limit: entierRLP(L[4], "gasLimit"),
      to: null,
      value: entierRLP(L[6], "value"),
      data: null,
      access_list: L[8],
      y_parity: entierRLP(L[9], "yParity"),
      r: entierRLP(L[10], "r"),
      s: entierRLP(L[11], "s"),
    };
    if (!Buffer.isBuffer(L[5]) || (L[5].length !== 0 && L[5].length !== 20)) throw new Error("to : 0 ou 20 octets attendus");
    tx.to = L[5].length === 0 ? null : hex(L[5]);
    if (!Buffer.isBuffer(L[7])) throw new Error("data : chaîne attendue");
    tx.data = hex(L[7]);
  } catch (err) {
    throw new EchecVerification("RG-15", "transaction_illisible", err.message);
  }
  const charge = Buffer.concat([Buffer.from([0x02]), rlp(L.slice(0, 9).map((e) => (Array.isArray(e) ? e : Buffer.from(e))))]);
  tx.signing_hash = hex(keccak(charge));
  tx.transaction_hash = hex(keccak(b));
  return tx;
}

/** Adresse créée par `deployer` à son nonce `nonce` : keccak256(RLP([a20, nonce]))[12:]. */
export function adresseCreation(deployer, nonce) {
  return hex(keccak(rlp([a20(deployer), octetsEntier(entier(nonce, "nonce"))])).subarray(12));
}

/** p' = ⌈1,1 × p⌉ (EX-4.15) pour le remplacement d'une transaction au même nonce. */
export function fraisRemplacement(p) {
  const v = entier(p, "frais");
  return (11n * v + 9n) / 10n;
}

/**
 * RG-15 : transaction sérialisée conforme. `contexte` : { evm_chain_id, fees
 * (du manifeste), objet: "appel" | "deploiement" | "approvisionnement", to
 * (contrat visé ou destinataire), data (données attendues, facultatives),
 * code_creation (pour un déploiement, facultatif), provision (plafond de
 * value pour un approvisionnement), remplace (frais p de la transaction
 * remplacée, facultatif), from (expéditeur attendu, facultatif) }.
 */
export function verifierTransaction(brutHex, contexte) {
  const tx = decoderTransaction(brutHex);
  const fees = contexte.fees ?? FRAIS_DEFAUT;
  exiger(tx.chain_id === BigInt(contexte.evm_chain_id), "RG-15", "chaine_differente", `chainId ${tx.chain_id} ≠ evm_chain_id ${contexte.evm_chain_id}`);
  const attendu = contexte.remplace !== undefined && contexte.remplace !== null ? fraisRemplacement(contexte.remplace) : BigInt(fees.max_fee_per_gas_wei);
  exiger(tx.max_fee_per_gas === tx.max_priority_fee_per_gas, "RG-15", "frais_non_conformes", `maxFeePerGas ${tx.max_fee_per_gas} ≠ maxPriorityFeePerGas ${tx.max_priority_fee_per_gas}`);
  exiger(tx.max_fee_per_gas === attendu, "RG-15", "frais_non_conformes", `champs de frais ${tx.max_fee_per_gas} au lieu de ${attendu} wei`);
  exiger(tx.gas_limit === BigInt(fees.gas_limit) && tx.gas_limit <= 1n << 24n, "RG-15", "limite_gaz", `gasLimit ${tx.gas_limit} au lieu de fees.gas_limit ${fees.gas_limit} (au plus 2^24)`);
  exiger(Array.isArray(tx.access_list) && tx.access_list.length === 0, "RG-15", "liste_acces", "liste d'accès non vide");
  exiger(tx.y_parity === 0n || tx.y_parity === 1n, "RG-15", "signature_non_canonique", "yParity hors de {0, 1}");
  exiger(tx.r >= 1n && tx.r < N_SECP256K1 && tx.s >= 1n && tx.s <= MOITIE_N, "RG-15", "signature_non_canonique", "r ou s hors de la forme canonique");
  let from;
  try {
    from = computeAddress(SigningKey.recoverPublicKey(tx.signing_hash, { r: quantite32(tx.r), s: quantite32(tx.s), yParity: Number(tx.y_parity) })).toLowerCase();
  } catch (err) {
    throw new EchecVerification("RG-15", "signature_non_canonique", err.message);
  }
  if (contexte.from) exiger(from === contexte.from.toLowerCase(), "RG-15", "signature_non_canonique", `expéditeur recouvré ${from} ≠ ${contexte.from}`);
  const O = (cond, msg) => exiger(cond, "RG-15", "objet_non_conforme", msg);
  switch (contexte.objet) {
    case "appel":
      O(tx.to !== null && (!contexte.to || tx.to === contexte.to.toLowerCase()), `destinataire ${tx.to} au lieu du contrat ${contexte.to}`);
      O(tx.value === 0n, "value non nul pour un appel");
      if (contexte.data) O(tx.data === contexte.data.toLowerCase(), "data différentes des données d'appel de RG-14");
      break;
    case "deploiement":
      O(tx.to === null, "déploiement avec destinataire");
      O(tx.value === 0n, "value non nul pour un déploiement");
      if (contexte.data) O(tx.data === contexte.data.toLowerCase(), "data différentes du code de création suivi des arguments");
      break;
    case "approvisionnement":
      O(tx.to !== null && (!contexte.to || tx.to === contexte.to.toLowerCase()), `destinataire ${tx.to} au lieu de ${contexte.to}`);
      O(tx.data === "0x", "données non vides pour un approvisionnement");
      if (contexte.provision !== undefined && contexte.provision !== null) O(tx.value <= entier(contexte.provision), `value ${tx.value} au-delà de la provision ${contexte.provision}`);
      break;
    default:
      throw new EchecVerification("RG-15", "objet_non_conforme", `objet inconnu : ${contexte.objet}`);
  }
  return {
    from,
    nonce: entierJSON(tx.nonce),
    to: tx.to,
    value: tx.value.toString(),
    transaction_hash: tx.transaction_hash,
    signing_hash: tx.signing_hash,
  };
}

function quantite32(n) {
  return "0x" + BigInt(n).toString(16).padStart(64, "0");
}

// ---------------------------------------------------------------------------
// Provision (EX-4.19, EX-4.20)
// ---------------------------------------------------------------------------

/** P_k = provision_days × b_k + gas_limit ; seuil de recomplément refill_below_days × b_k + gas_limit. */
export function provision(fees, budgetJour) {
  const b = entier(budgetJour, "budget journalier");
  if (b <= 0n) throw new Error("budget journalier : entier positif attendu");
  const g = BigInt(fees.gas_limit);
  return { provision_wei: BigInt(fees.provision_days) * b + g, refill_below_wei: BigInt(fees.refill_below_days) * b + g };
}

/** Coût maximal d'une transaction : gasLimit × maxFeePerGas + value (EX-4.18). */
export function coutMaximal(fees, value = 0n, prix = null) {
  return BigInt(fees.gas_limit) * BigInt(prix ?? fees.max_fee_per_gas_wei) + BigInt(value);
}

// ---------------------------------------------------------------------------
// Genèse et manifeste d'instance (4.2, 4.8, 6.8)
// ---------------------------------------------------------------------------

/** Ligne de règles d'un document de genèse (EX-4.3). */
export function ligneRegles(genese) {
  const r = genese.rules;
  const champ = (v) => (typeof v === "boolean" ? String(v) : typeof v === "number" ? String(v) : String(v));
  return [
    `chainId=${champ(r.chainId)}`,
    `evmChainId=${champ(genese.chainId)}`,
    `possEnabled=${champ(r.possEnabled)}`,
    `possRewards=${champ(r.possRewards)}`,
    `possCapWei=${champ(r.possCapWei)}`,
    `possGenesisUnix=${champ(r.possGenesisUnix)}`,
    `possHalvingSec=${champ(r.possHalvingSec)}`,
    `possSubperiodSec=${champ(r.possSubperiodSec)}`,
    `possEmissionModel=${champ(r.possEmissionModel)}`,
  ].join(" ");
}

/** Section rules exigée par EX-4.2, hors chainId. */
export const REGLES_SANS_EMISSION = Object.freeze({
  possEnabled: false,
  possRewards: ADRESSE_NULLE,
  possCapWei: "0",
  possGenesisUnix: 0,
  possHalvingSec: 0,
  possSubperiodSec: 0,
  possEmissionModel: "noormint/v1",
});

/** Nombre que porte un identifiant BFT noortrace-<n>-<suffixe> (EX-4.6), ou null. */
export function nombreBFT(bft) {
  const m = /^noortrace-([1-9][0-9]{0,9})-([a-z0-9]{1,16})$/.exec(String(bft));
  return m ? Number(m[1]) : null;
}

/** Ancre `registry` du fichier d'ancres de CT-6 dérivée du manifeste (RG-20, EX-6.23). */
export function ancreRegistreDuManifeste(manifeste, source = null) {
  const enService = (nom) => {
    const c = manifeste.contracts.filter((x) => x.name === nom && x.to_height === null);
    if (c.length !== 1) throw new EchecVerification("RG-20", "derivation_impossible", `${c.length} contrat(s) ${nom} en service au lieu d'un`);
    return c[0].address;
  };
  return {
    chain_id: manifeste.bft_chain_id,
    contracts: { period_registry: enService("PeriodRegistry"), attestation_registry: enService("AttestationRegistry"), recorder_registry: enService("RecorderRegistry") },
    validator_sets: manifeste.validator_sets.map((j) => ({ from_height: j.from_height, to_height: j.to_height, validators: j.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source: j.source })),
    source: source ?? `dérivée du manifeste d'instance ${manifeste.bft_chain_id}, révision ${manifeste.revision} (CT-4 RG-20) : à recouper (CT-6 §12.5)`,
  };
}

/** Jeu du manifeste valable à la hauteur h. */
export function jeuPourHauteur(manifeste, h) {
  const H = BigInt(h);
  return manifeste.validator_sets.find((j) => BigInt(j.from_height) <= H && (j.to_height === null || H <= BigInt(j.to_height))) ?? null;
}

/** Jeu en vigueur (to_height nul, sinon le dernier). */
export function jeuEnVigueur(manifeste) {
  return manifeste.validator_sets.find((j) => j.to_height === null) ?? manifeste.validator_sets[manifeste.validator_sets.length - 1];
}

/** Contrat en service d'un nom (to_height nul). */
export function contratEnService(manifeste, nom) {
  return manifeste.contracts.find((c) => c.name === nom && c.to_height === null) ?? null;
}

/** Compte d'un rôle valable à la tête (to_height nul). */
export function compteDuRole(manifeste, role) {
  return manifeste.accounts.find((a) => a.role === role && a.to_height === null) ?? null;
}

/**
 * Vérifie un manifeste d'instance : RG-16 à RG-20. `entrees` : { octets
 * (Buffer du manifeste), precedent (Buffer de la révision précédente ou null),
 * genese (Buffer du document de genèse), lireCapture(nom) (Buffer d'un
 * fichier du répertoire des preuves, ou null), ancre (ancre registry à
 * comparer, facultative), schemas }. Rend { verdicts: {RG-16..RG-20}, checks
 * (détails), registry (ancre dérivée ou null) }.
 */
export function verifierManifesteInstance({ octets: octetsManifeste, precedent = null, genese, lireCapture = () => null, ancre = null, schemas }) {
  const checks = [];
  let manifeste = null;
  let formeLisible = false;
  const poser = (r) => {
    checks.push(r);
    return r.status === "reussi";
  };
  // RG-16 : forme et révisions.
  poser(
    verifier("RG-16", () => {
      try {
        manifeste = JSON.parse(Buffer.from(octetsManifeste).toString("utf8"));
      } catch (err) {
        throw new EchecVerification("RG-16", "schema", `JSON illisible : ${err.message}`);
      }
      const erreurs = validerSchema(manifeste, schemas[ID_SCHEMA_INSTANCE], { registre: schemas });
      exiger(erreurs.length === 0, "RG-16", "schema", `non conforme à instance-registre-v0 : ${erreurs.slice(0, 3).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
      for (const nom of ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]) exiger(manifeste.contracts.some((c) => c.name === nom), "RG-16", "schema", `contrat ${nom} absent (contains)`);
      formeLisible = true;
      if (precedent === null) {
        exiger(manifeste.revision === 1 && manifeste.previous_sha256 === null, "RG-16", "revision_mal_chainee", `révision ${manifeste.revision} sans révision précédente : revision 1 et previous_sha256 nul attendus`);
      } else {
        let p;
        try {
          p = JSON.parse(Buffer.from(precedent).toString("utf8"));
        } catch {
          throw new EchecVerification("RG-16", "revision_mal_chainee", "révision précédente illisible");
        }
        exiger(manifeste.revision === p.revision + 1, "RG-16", "revision_mal_chainee", `revision ${manifeste.revision} après ${p.revision}`);
        exiger(manifeste.previous_sha256 === sha256Hex(precedent), "RG-16", "revision_mal_chainee", `previous_sha256 ${manifeste.previous_sha256} ≠ SHA-256 de la révision ${p.revision} (${sha256Hex(precedent)})`);
        exiger(manifeste.published_at >= p.published_at, "RG-16", "revision_mal_chainee", "published_at précède celui de la révision précédente");
      }
      return { revision: manifeste.revision, sha256: sha256Hex(octetsManifeste) };
    }),
  );
  if (!formeLisible) {
    for (const id of ["RG-17", "RG-18", "RG-19", "RG-20"]) checks.push({ check: id, status: "echoue", code: "schema", detail: "manifeste non conforme (RG-16)", valeurs: null });
    return { verdicts: Object.fromEntries(checks.map((c) => [c.check, c.status])), checks, registry: null, manifeste };
  }
  // RG-17 : genèse et identifiants.
  poser(
    verifier("RG-17", () => {
      exiger(sha256Hex(genese) === manifeste.genesis.sha256, "RG-17", "genese_differente", `SHA-256 du document de genèse ${sha256Hex(genese)} ≠ genesis.sha256 ${manifeste.genesis.sha256}`);
      let g;
      try {
        g = JSON.parse(Buffer.from(genese).toString("utf8"));
      } catch (err) {
        throw new EchecVerification("RG-17", "genese_invalide", `genèse illisible : ${err.message}`);
      }
      const G = (c, m) => exiger(c, "RG-17", "genese_invalide", m);
      G(g && typeof g === "object" && Number.isSafeInteger(g.chainId) && g.chainId > 0, "chainId de tête : entier EVM non nul attendu");
      G(Array.isArray(g.alloc) && g.alloc.length > 0, "alloc non vide attendu");
      const vues = new Set();
      let total = 0n;
      for (const a of g.alloc) {
        G(typeof a.address === "string" && /^0x[0-9a-fA-F]{40}$/.test(a.address), "alloc : adresse invalide");
        G(!vues.has(a.address.toLowerCase()), "alloc : adresses en double");
        vues.add(a.address.toLowerCase());
        G(typeof a.balanceWei === "string" && /^(0|[1-9][0-9]*)$/.test(a.balanceWei), "alloc : balanceWei décimal attendu");
        total += BigInt(a.balanceWei);
      }
      exiger(g.rules && typeof g.rules === "object", "RG-17", "regles_invalides", "section rules absente : le nœud ne vérifierait rien (EX-4.2)");
      for (const [k, v] of Object.entries(REGLES_SANS_EMISSION)) exiger(egalJSON(g.rules[k], v), "RG-17", "regles_invalides", `rules.${k} = ${JSON.stringify(g.rules[k])} au lieu de ${JSON.stringify(v)}`);
      exiger(Object.keys(g.rules).sort().join(",") === ["chainId", ...Object.keys(REGLES_SANS_EMISSION)].sort().join(","), "RG-17", "regles_invalides", "rules : exactement les champs d'EX-4.2 attendus");
      const ligne = ligneRegles(g);
      exiger(ligne === manifeste.genesis.rules_line, "RG-17", "ligne_regles_differente", "ligne de règles recalculée différente de genesis.rules_line");
      const I = (c, m) => exiger(c, "RG-17", "identifiants_incoherents", m);
      I(g.rules.chainId === manifeste.bft_chain_id, `rules.chainId ${g.rules.chainId} ≠ bft_chain_id ${manifeste.bft_chain_id}`);
      I(g.chainId === manifeste.evm_chain_id, `chainId de tête ${g.chainId} ≠ evm_chain_id ${manifeste.evm_chain_id}`);
      I(nombreBFT(manifeste.bft_chain_id) === manifeste.evm_chain_id, `le nombre de ${manifeste.bft_chain_id} n'est pas evm_chain_id ${manifeste.evm_chain_id}`);
      exiger(total.toString() === manifeste.genesis.alloc_total_wei, "RG-17", "offre_differente", `somme des balanceWei ${total} ≠ alloc_total_wei ${manifeste.genesis.alloc_total_wei}`);
      return { rules_line: ligne, alloc_total_wei: total.toString() };
    }),
  );
  // RG-18 : jeux de validateurs.
  poser(
    verifier("RG-18", () => {
      const intervalles = [];
      manifeste.validator_sets.forEach((j, i) => {
        exiger(j.validators.length >= 4, "RG-18", "jeu_invalide", `jeu ${i} : ${j.validators.length} validateurs, au moins 4 exigés (EX-4.11)`);
        let charge;
        try {
          charge = chargerJeuValidateurs({ validators: j.validators });
          // EX-6.21 : chaque clé est un point de secp256k1 (le chargement n'en vérifie que la forme).
          for (const v of j.validators) {
            try {
              SigningKey.computePublicKey(String(v.pubKeyHex), true);
            } catch (err) {
              throw new Error(`validateur ${v.id} : clé publique hors de secp256k1 (${err.shortMessage ?? err.message})`);
            }
          }
        } catch (err) {
          throw new EchecVerification("RG-18", "jeu_invalide", `jeu ${i} : ${err.message}`);
        }
        exiger(charge.hachage === j.valset_hash, "RG-18", "valset_hash_different", `jeu ${i} : valset_hash ${j.valset_hash} ≠ recalculé ${charge.hachage}`);
        const ids = j.validators.map((v) => v.id);
        const nommes = j.operators.map((o) => o.validator);
        exiger(nommes.length === ids.length && new Set(nommes).size === nommes.length && nommes.every((n) => ids.includes(n)), "RG-18", "operateurs_incoherents", `jeu ${i} : operators doit nommer chaque validateur une fois et rien d'autre`);
        if (j.to_height !== null) exiger(j.from_height <= j.to_height, "RG-18", "intervalles_incoherents", `jeu ${i} : from_height > to_height`);
        if (manifeste.nature === "production") {
          const f = Math.floor((ids.length - 1) / 3);
          const compte = (cle) => {
            const m = new Map();
            for (const o of j.operators) m.set(o[cle], (m.get(o[cle]) ?? 0) + 1);
            return m;
          };
          for (const [cle, libelle] of [["operator", "opérateur"], ["site", "site"]]) {
            for (const [nom, n] of compte(cle)) exiger(n <= f, "RG-18", "domaine_de_panne", `jeu ${i} : ${libelle} « ${nom} » porte ${n} validateurs, au plus f = ${f} (EX-4.12)`);
          }
        }
        intervalles.push({ i, de: BigInt(j.from_height), a: j.to_height === null ? null : BigInt(j.to_height) });
      });
      const tries = [...intervalles].sort((x, y) => (x.de < y.de ? -1 : x.de > y.de ? 1 : 0));
      exiger(tries[0].de === 1n, "RG-18", "intervalles_incoherents", "le premier jeu ne commence pas à la hauteur 1");
      for (let k = 1; k < tries.length; k++) {
        const p = tries[k - 1];
        exiger(p.a !== null && p.a < tries[k].de, "RG-18", "intervalles_incoherents", `jeux ${p.i} et ${tries[k].i} : intervalles qui se recouvrent`);
      }
      return { valset_hashes: manifeste.validator_sets.map((j) => j.valset_hash) };
    }),
  );
  // RG-19 : contrats.
  poser(
    verifier("RG-19", () => {
      const csr = contratEnService(manifeste, "CuratorSetRegistry");
      for (const nom of ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]) {
        exiger(manifeste.contracts.filter((c) => c.name === nom && c.to_height === null).length === 1, "RG-19", "contrats_en_service", `${nom} : exactement un contrat de to_height nul attendu`);
      }
      const details = [];
      const registres = manifeste.contracts.filter((x) => x.name === "CuratorSetRegistry").map((x) => x.address);
      for (const c of manifeste.contracts) {
        const cree = adresseCreation(c.deployer, c.nonce);
        exiger(cree === c.address, "RG-19", "adresse_creation", `${c.name} : address ${c.address} ≠ CREATE(${c.deployer}, ${c.nonce}) = ${cree}`);
        // EX-5.2 : initialAdmin = l'administrateur du registre à la hauteur du
        // déploiement ; PeriodRegistry et RecorderRegistry pointent sur le
        // CuratorSetRegistry en service (un contrat retiré, sur l'un d'eux).
        let attendus;
        if (c.name === "AttestationRegistry") attendus = [];
        else if (c.name === "CuratorSetRegistry") {
          const admin = manifeste.accounts.find((a) => a.role === "administrateur_registre" && a.from_height <= c.block_number && (a.to_height === null || c.block_number <= a.to_height));
          exiger(admin, "RG-19", "arguments_constructeur", `${c.name} : aucun compte administrateur_registre valable au bloc ${c.block_number}`);
          attendus = [admin.address];
        } else if (c.to_height === null) attendus = [csr.address];
        else attendus = registres.includes(c.constructor_args[0]) ? [c.constructor_args[0]] : [csr.address];
        exiger(egalJSON(c.constructor_args, attendus), "RG-19", "arguments_constructeur", `${c.name} : constructor_args ${JSON.stringify(c.constructor_args)} au lieu de ${JSON.stringify(attendus)} (EX-5.2)`);
        if (manifeste.nature === "production") exiger(c.block_hash !== null && c.evidence !== null, "RG-19", "preuve_absente", `${c.name} : block_hash et evidence non nuls exigés en production`);
        if (c.evidence !== null) {
          const nom = c.evidence.capture.file;
          const brut = lireCapture(nom);
          exiger(brut, "RG-19", "preuve_absente", `${c.name} : index de capture ${nom} absent`);
          exiger(sha256Hex(brut) === c.evidence.capture.sha256, "RG-19", "preuve_invalide", `${c.name} : SHA-256 de ${nom} différent de celui déclaré`);
          let index;
          try {
            index = JSON.parse(Buffer.from(brut).toString("utf8"));
          } catch {
            throw new EchecVerification("RG-19", "preuve_invalide", `${c.name} : index illisible`);
          }
          exiger(index.role === "deploiement", "RG-19", "preuve_invalide", `${c.name} : index de rôle ${index.role}, deploiement attendu`);
          exiger(index.contract === c.address && index.transaction_hash === c.transaction_hash && index.block_number === c.block_number && index.block_hash === c.block_hash, "RG-19", "preuve_invalide", `${c.name} : contract, transaction_hash, block_number ou block_hash de l'index différent du manifeste`);
          const jeu = jeuPourHauteur(manifeste, index.block_number);
          exiger(jeu, "RG-19", "preuve_invalide", `${c.name} : aucun jeu du manifeste ne couvre la hauteur ${index.block_number}`);
          // Les fichiers d'un index sont dans son propre répertoire (CP-6).
          const rep = nom.includes("/") ? nom.slice(0, nom.lastIndexOf("/") + 1) : "";
          const cap = verifierCapture({ index, lireFichier: (n) => lireCapture(rep + n), validators: { validators: jeu.validators }, bft_chain_id: manifeste.bft_chain_id, schemas, ids: ["CP-2", "CP-3", "CP-4", "CP-6"] });
          const enEchec = cap.checks.find((x) => x.status !== "reussi");
          exiger(!enEchec, "RG-19", "preuve_invalide", `${c.name} : ${enEchec?.check} ${enEchec?.detail}`);
          const ctx = cap.contexte;
          exiger(ctx.recu?.status === "0x1", "RG-19", "preuve_invalide", `${c.name} : reçu de déploiement de status ${ctx.recu?.status}`);
          const brutTx = ctx.txsRaw[index.transaction_index];
          let tx;
          try {
            tx = decoderTransaction(hex(brutTx));
          } catch (err) {
            throw new EchecVerification("RG-19", "preuve_invalide", `${c.name} : transaction brute illisible (${err.message})`);
          }
          exiger(tx.to === null, "RG-19", "preuve_invalide", `${c.name} : transaction de déploiement avec destinataire ${tx.to}`);
          const exp = computeAddress(SigningKey.recoverPublicKey(tx.signing_hash, { r: quantite32(tx.r), s: quantite32(tx.s), yParity: Number(tx.y_parity) })).toLowerCase();
          exiger(exp === c.deployer && tx.nonce === BigInt(c.nonce), "RG-19", "preuve_invalide", `${c.name} : transaction signée par ${exp} au nonce ${tx.nonce}, au lieu de ${c.deployer} au nonce ${c.nonce}`);
          details.push(`${c.name} : preuve ${nom}`);
        }
      }
      return { details };
    }),
  );
  // RG-20 : ancre registry dérivée.
  let registry = null;
  poser(
    verifier("RG-20", () => {
      registry = ancreRegistreDuManifeste(manifeste, ancre?.source ?? null);
      if (ancre) {
        const sansSource = (x) => ({ ...x, source: null, validator_sets: x.validator_sets.map((j) => ({ ...j, source: null })) });
        exiger(egalJSON(sansSource(registry), sansSource(ancre)), "RG-20", "ancre_differente", "ancre registry fournie différente de celle que le manifeste donne (hors source)");
      }
      return { registry };
    }),
  );
  return { verdicts: Object.fromEntries(checks.map((c) => [c.check, c.status])), checks, registry: checks[4].status === "reussi" ? registry : null, manifeste };
}

// ---------------------------------------------------------------------------
// Capture d'une transaction : CP-2 à CP-6 sur les fichiers (9.4)
// ---------------------------------------------------------------------------

/** Nom de l'index de capture (CP-6). */
export function nomIndex(h, transactionIndex, role) {
  return `capture-${h}-${transactionIndex}-${role}.json`;
}

/** Résultat JSON-RPC d'une réponse brute écrite telle que reçue. */
function resultatRPC(brut, nom) {
  let v;
  try {
    v = JSON.parse(Buffer.from(brut).toString("utf8"));
  } catch (err) {
    throw new Error(`${nom} : JSON illisible (${err.message})`);
  }
  if (!v || typeof v !== "object" || !("result" in v) || v.result === null) throw new Error(`${nom} : réponse sans result`);
  return v.result;
}

/** Transactions brutes (Buffers) du corps signé de la proposition d'un certificat. */
export function transactionsBrutesDuCertificat(certificat) {
  const env = analyserEnveloppe(certificat.proposal?.line ?? certificat.prop);
  const corps = JSON.parse(env.corpsBrut);
  const liste = Array.isArray(corps.txsRaw) ? corps.txsRaw : [];
  return liste.map((t) => Buffer.from(t, "base64"));
}

/** Racine des transactions d'un bloc depuis ses transactions brutes (calcul de RG-19, CT-6 EX-11.5 règle 4). */
export function racineTransactions(txsRaw) {
  return hex(racineTrie(txsRaw.map((t, i) => ({ cle: rlp(octetsEntier(i)), valeur: t }))));
}

/**
 * CP-2 à CP-6 d'un index de capture, sur les fichiers déjà écrits.
 * `lireFichier(nom)` rend les octets d'un fichier du répertoire (ou null) ;
 * `validators` : le jeu du manifeste dont l'intervalle contient la hauteur ;
 * `ids` : vérifications à exécuter (défaut CP-2 à CP-6). Rend { checks,
 * contexte: { bloc, recus, certificat, recu, txsRaw } }.
 */
export function verifierCapture({ index, lireFichier, validators, bft_chain_id, schemas, ids = ["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"] }) {
  const contexte = { bloc: null, recus: null, certificat: null, recu: null, txsRaw: [] };
  const checks = [];
  const lire = (nom) => {
    const b = lireFichier(nom);
    if (!b) throw new EchecVerification("CP-6", "capture_incomplete", `fichier ${nom} absent`);
    return b;
  };
  const fait = (id, f) => {
    if (!ids.includes(id)) return;
    checks.push(verifier(id, f));
  };
  const C = (id, cond, msg, code = "capture_incomplete") => exiger(cond, id, code, msg);
  // Lecture des fichiers (sans juger : CP-6 juge leurs empreintes et noms).
  const nomRecu = (t) => `recu-${t}.json`;
  const hachagesTransactions = (bloc) => (bloc && Array.isArray(bloc.transactions) ? bloc.transactions.map((t) => (typeof t === "string" ? t : t.hash).toLowerCase()) : null);
  try {
    contexte.bloc = resultatRPC(lire(index.files.block.name), index.files.block.name);
  } catch {
    contexte.bloc = null;
  }
  fait("CP-2", () => {
    const bloc = contexte.bloc;
    C("CP-2", bloc, `en-tête ${index.files.block.name} absent ou illisible`);
    C("CP-2", BigInt(bloc.number) === BigInt(index.block_number), `en-tête de la hauteur ${BigInt(bloc.number)} au lieu de ${index.block_number}`);
    const h = hachageBlocBFT(bloc);
    C("CP-2", h === String(bloc.hash).toLowerCase(), `BFTBlockHash recalculé ${h} ≠ hash de l'en-tête ${bloc.hash}`);
    C("CP-2", String(bloc.hash).toLowerCase() === index.block_hash, `hash de l'en-tête ${bloc.hash} ≠ block_hash de l'index ${index.block_hash}`);
    // 9.4 : le blockHash du reçu de la transaction capturée égale hash de l'en-tête (le reçu illisible relève de CP-3).
    let recu = null;
    try {
      recu = resultatRPC(lire(index.files.receipts[index.transaction_index].name), "reçu");
    } catch {
      recu = null;
    }
    if (recu) C("CP-2", String(recu.blockHash).toLowerCase() === String(bloc.hash).toLowerCase(), `blockHash du reçu ${recu.blockHash} ≠ hash de l'en-tête ${bloc.hash}`);
    return { block_hash: h };
  });
  fait("CP-3", () => {
    const bloc = contexte.bloc;
    const txs = hachagesTransactions(bloc);
    C("CP-3", txs, "en-tête illisible");
    C("CP-3", txs.length === index.files.receipts.length, `${index.files.receipts.length} reçu(s) pour ${txs.length} transaction(s) du bloc`);
    // La correspondance d'un reçu à sa transaction se lit dans le reçu (transactionHash du reçu de rang i égal au hachage de rang i de l'en-tête) ; le nom du fichier relève de CP-6.
    const recus = txs.map((t, i) => {
      const r = resultatRPC(lire(index.files.receipts[i].name), index.files.receipts[i].name);
      C("CP-3", String(r.transactionHash).toLowerCase() === t, `reçu de rang ${i} de transactionHash ${r.transactionHash} au lieu de ${t}`);
      return r;
    });
    const racine = racineRecus(recus.map((r) => ({ type: r.type ?? "0x0", status: r.status, cumulativeGasUsed: r.cumulativeGasUsed, logs: r.logs })));
    C("CP-3", racine === String(bloc.receiptsRoot).toLowerCase(), `receiptsRoot recalculée ${racine} ≠ ${bloc.receiptsRoot}`);
    C("CP-3", txs[index.transaction_index] === index.transaction_hash, `la transaction ${index.transaction_hash} n'est pas à l'indice ${index.transaction_index}`);
    contexte.recus = recus;
    contexte.recu = recus[index.transaction_index];
    return { receipts_root: racine };
  });
  fait("CP-4", () => {
    let brut;
    try {
      brut = lire(index.files.certificate.name);
    } catch (err) {
      throw new EchecVerification("CP-4", "certificat_indisponible", err.message);
    }
    let cert;
    try {
      cert = resultatRPC(brut, index.files.certificate.name);
    } catch (err) {
      throw new EchecVerification("CP-4", "certificat_indisponible", err.message);
    }
    contexte.certificat = cert;
    if (cert.retention?.pruned === true) throw new EchecVerification("CP-4", "certificat_elague", "certificat élagué chez ce nœud (retention.pruned)");
    const v = verifierCertificat(cert, validators, { chainIdAttendu: bft_chain_id, hauteurAttendue: index.block_number, blockHashAttendu: contexte.bloc?.hash ?? index.block_hash });
    C("CP-4", v.valide, `certificat invalide : ${v.controles.filter((x) => !x.ok).map((x) => `${x.nom} (${x.detail})`).join(" ; ")}`, "certificat_invalide");
    // 9.4 : validator_set_hash de l'index est le hachage du jeu employé (CT-6 EX-11.8).
    const hachageJeu = hachageJeuValidateurs(validators.validators ?? validators);
    C("CP-4", String(index.validator_set_hash).toLowerCase() === hachageJeu, `validator_set_hash de l'index ${index.validator_set_hash} ≠ hachage du jeu employé ${hachageJeu}`, "certificat_invalide");
    let txs;
    try {
      txs = transactionsBrutesDuCertificat(cert);
    } catch (err) {
      throw new EchecVerification("CP-4", "certificat_invalide", `corps de la proposition illisible : ${err.message}`);
    }
    contexte.txsRaw = txs;
    C("CP-4", txs.length > index.transaction_index, `txsRaw de ${txs.length} transaction(s), indice ${index.transaction_index} absent`, "certificat_invalide");
    C("CP-4", hex(keccak(txs[index.transaction_index])) === index.transaction_hash, `txsRaw[${index.transaction_index}] de hachage ${hex(keccak(txs[index.transaction_index]))} ≠ ${index.transaction_hash}`, "certificat_invalide");
    const racine = racineTransactions(txs);
    C("CP-4", contexte.bloc && racine === String(contexte.bloc.transactionsRoot).toLowerCase(), `racine des transactions recalculée ${racine} ≠ transactionsRoot ${contexte.bloc?.transactionsRoot}`, "certificat_invalide");
    return { signers: v.signataires, valset_hash: v.valsetHash, retention: cert.retention ?? null };
  });
  fait("CP-5", () => {
    const evenement = EVENEMENT_DU_ROLE[index.role];
    if (evenement === null || evenement === undefined) {
      C("CP-5", index.log_index === null, `rôle ${index.role} sans journal prouvé : log_index nul attendu`);
      return { event: null };
    }
    const recu = contexte.recu ?? (() => {
      const r = resultatRPC(lire(index.files.receipts[index.transaction_index].name), "reçu");
      return r;
    })();
    C("CP-5", Number.isInteger(index.log_index) && Array.isArray(recu.logs) && recu.logs.length > index.log_index, `journal ${index.log_index} absent du reçu`);
    const j = recu.logs[index.log_index];
    C("CP-5", String(j.address).toLowerCase() === index.contract, `journal émis par ${String(j.address).toLowerCase()} au lieu de ${index.contract}`);
    C("CP-5", String(j.topics?.[0]).toLowerCase() === EVENEMENTS[evenement].topic, `topics[0] ${j.topics?.[0]} n'est pas celui de ${evenement}`);
    if (["inscription", "ancre", "cloture"].includes(index.role)) {
      const d = decoderJournal(index.role, { address: j.address, topics: j.topics.map((t) => t.toLowerCase()), data: j.data.toLowerCase() });
      C("CP-5", d.erreurs.length === 0, `disposition de ${evenement} : ${d.erreurs.join(" ; ")}`);
      return { event: d.valeurs };
    }
    return { event: { name: evenement } };
  });
  fait("CP-6", () => {
    const nomValide = (n) => typeof n === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/.test(n) && !n.includes("/");
    const h = index.block_number;
    C("CP-6", index.files.block.name === `bloc-${h}.json` && index.files.certificate.name === `certificat-${h}.json`, "noms de fichiers hors de la convention bloc-<h>.json, certificat-<h>.json");
    // Chaque reçu est écrit sous recu-<hachage de transactions[i]>.json (9.4, CP-6).
    const txs = hachagesTransactions(contexte.bloc);
    index.files.receipts.forEach((f, i) => {
      if (txs && i < txs.length) C("CP-6", f.name === nomRecu(txs[i]), `fichier ${f.name} au lieu de ${nomRecu(txs[i])}`);
      else C("CP-6", /^recu-0x[0-9a-f]{64}\.json$/.test(f.name), `reçu ${f.name} hors de la forme recu-<hachage>.json`);
    });
    for (const f of [index.files.block, ...index.files.receipts, index.files.certificate]) {
      C("CP-6", nomValide(f.name), `nom de fichier ${f.name} hors du répertoire des captures`);
      const b = lire(f.name);
      C("CP-6", sha256Hex(b) === f.sha256, `SHA-256 de ${f.name} ${sha256Hex(b)} ≠ ${f.sha256} déclaré`);
    }
    if (schemas) {
      const erreurs = validerSchema(index, schemas[ID_SCHEMA_OPERATIONS], { registre: schemas });
      C("CP-6", erreurs.length === 0, `index non conforme : ${erreurs.slice(0, 3).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
    }
    return {};
  });
  return { checks, contexte };
}

/** Les CP- d'un index en forme de vérifications de l'index (id, status, detail). */
export function checksIndex(resultats) {
  return resultats.map((r) => ({ id: r.check, status: r.status, detail: r.status === "reussi" ? "" : `${r.code} : ${r.detail}`.slice(0, 1024) }));
}

// ---------------------------------------------------------------------------
// Export des parties (9.6)
// ---------------------------------------------------------------------------

/**
 * Parties registre.json, certificat-commit.json et validateurs.json d'une
 * période depuis des captures. `captures` : [{ index, lireFichier }] des
 * transactions à prouver (une clôture, une ancre, des inscriptions) ;
 * `jeux` : validator_sets du manifeste (ou d'un fichier publier-jeu) ;
 * `source` : texte de registre.json. Les entrées sont rangées par hauteur puis
 * par transaction_index (EX-9.8).
 */
export function exporterParties({ captures, jeux, source }) {
  const entrees = captures.map(({ index, lireFichier }) => {
    const bloc = resultatRPC(lireFichier(index.files.block.name), index.files.block.name);
    const recus = index.files.receipts.map((f) => resultatRPC(lireFichier(f.name), f.name));
    const cert = resultatRPC(lireFichier(index.files.certificate.name), index.files.certificate.name);
    return { index, entree: entreeRegistre({ role: index.role, bloc, recus, transactionHash: index.transaction_hash, logIndex: index.log_index }), cert };
  });
  entrees.sort((a, b) => a.index.block_number - b.index.block_number || a.index.transaction_index - b.index.transaction_index);
  const hauteurs = [];
  const certificats = [];
  for (const e of entrees) {
    if (!hauteurs.includes(e.index.block_number)) {
      hauteurs.push(e.index.block_number);
      certificats.push(e.cert);
    }
  }
  const sets = jeux
    .filter((j) => hauteurs.some((h) => BigInt(j.from_height) <= BigInt(h) && (j.to_height === null || BigInt(h) <= BigInt(j.to_height))))
    .map((j) => ({ from_height: j.from_height, to_height: j.to_height, validators: j.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source: j.source }));
  return {
    registre: { version: 0, source: source.slice(0, 512), entries: entrees.map((e) => e.entree) },
    certificat_commit: { version: 0, certificates: certificats },
    validateurs: { version: 0, sets },
  };
}

// ---------------------------------------------------------------------------
// Demande de signature : condensé (OP-6) et signatures (OP-7) hors ligne
// ---------------------------------------------------------------------------

/** Condensé interne d'une demande, recalculé depuis fields, evm_chain_id et contract (RG-6 à RG-11). */
export function condenseDeDemande(demande) {
  const f = demande.fields;
  const base = { chain_id: demande.evm_chain_id, contract: demande.contract };
  switch (demande.operation) {
    case "inscription":
      return condenseInscription({ ...base, org_id: f.org_id, journal_id: f.journal_id, chain_key: f.chain_key, ed25519_public_key: f.ed25519_public_key });
    case "revocation":
      return condenseRevocation({ ...base, org_id: f.org_id, chain_key: f.chain_key, registered_at: f.registered_at });
    case "cloture":
      return condenseCloture({ ...base, period_meta: f.period_meta });
    case "ancre":
      return condenseAncre({ ...base, fingerprint: f.fingerprint, doc_type: f.doc_type });
    case "administration_jeu":
      return condenseOperationJeu({ ...base, op: f.op, arg: f.arg, nonce: f.nonce });
    default:
      throw new Error(`opération inconnue : ${demande.operation}`);
  }
}

/**
 * Vérifications hors ligne d'une demande de signature : schéma (en tête
 * d'OP-6, code entree_illisible), OP-6 (condensé et hachage signé recalculés),
 * OP-7 (signatures canoniques, recouvrées, distinctes, rangées ; membres et
 * seuil quand `membres` est donné ; `complete` exige au moins le seuil, et
 * pour une ancre une signature de l'émetteur). Rend { checks: [OP-6, OP-7],
 * resultat: "valide" | refus { check, code } }.
 */
export function verifierDemande(demande, { schemas, membres = null, complete = true, signataireAttendu = null } = {}) {
  const checks = [];
  const fin = () => {
    const e = checks.find((c) => c.status !== "reussi");
    return { checks, refusal: e ? { check: e.check, code: e.code } : null, detail: e?.detail ?? "" };
  };
  const erreurs = schemas ? validerSchema(demande, schemas[ID_SCHEMA_OPERATIONS], { registre: schemas, fragment: "#/$defs/demande_signature" }) : [];
  if (erreurs.length) {
    checks.push(echec("OP-6", "entree_illisible", `demande non conforme à demande_signature : ${erreurs.slice(0, 3).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`));
    return fin();
  }
  let condense;
  const op6 = verifier("OP-6", () => {
    try {
      condense = condenseDeDemande(demande);
    } catch (err) {
      throw new EchecVerification("OP-6", "condense_different", err.message);
    }
    exiger(condense.digest === demande.digest, "OP-6", "condense_different", `condensé recalculé ${condense.digest} ≠ digest ${demande.digest}`);
    exiger(condense.eip191_digest === demande.eip191_digest, "OP-6", "condense_different", `hachage signé recalculé ${condense.eip191_digest} ≠ eip191_digest ${demande.eip191_digest}`);
    if (demande.operation === "cloture") {
      const r = verifier("RG-5", () => verifierChampsCloture(demande.fields.period_meta));
      exiger(r.status === "reussi", "OP-6", "condense_different", `champs de clôture refusés par RG-5 : ${r.detail}`);
    }
    return { digest: condense.digest };
  });
  checks.push(op6);
  if (op6.status !== "reussi") return fin();
  checks.push(
    verifier("OP-7", () => {
      const vus = new Set();
      let precedent = null;
      for (const [i, s] of demande.signatures.entries()) {
        const r = verifier("RG-12", () => verifierSignature({ digest: demande.digest, signature: s }));
        if (r.status !== "reussi") throw new EchecVerification("OP-7", r.code === "signature_non_canonique" ? "signature_non_canonique" : "signataire_hors_jeu", `signature ${i} : ${r.detail}`);
        const a = r.valeurs.recovered;
        exiger(!vus.has(a), "OP-7", "signature_non_canonique", `signataire ${a} présent deux fois`);
        vus.add(a);
        exiger(precedent === null || precedent < a, "OP-7", "signature_non_canonique", `signatures non rangées par adresse croissante (${precedent} puis ${a})`);
        precedent = a;
        if (membres && demande.signer_set) exiger(membres.map((m) => m.toLowerCase()).includes(a), "OP-7", "signataire_hors_jeu", `signataire ${a} hors du jeu`);
      }
      if (demande.operation === "ancre") {
        if (complete) exiger(demande.signatures.length === 1, "OP-7", "signatures_insuffisantes", "une ancre porte la signature de son émetteur");
        if (demande.signatures.length) exiger(demande.signatures[0].signer === demande.fields.issuer, "OP-7", "signataire_hors_jeu", `signataire ${demande.signatures[0].signer} autre que l'émetteur ${demande.fields.issuer}`);
      } else if (demande.signer_set) {
        if (complete) exiger(demande.signatures.length >= demande.signer_set.threshold, "OP-7", "signatures_insuffisantes", `${demande.signatures.length} signature(s) pour un seuil de ${demande.signer_set.threshold}`);
      } else {
        if (complete) exiger(demande.signatures.length === 1, "OP-7", "signatures_insuffisantes", "une opération du jeu porte la signature de son administrateur");
        if (signataireAttendu && demande.signatures.length) exiger(demande.signatures[0].signer === signataireAttendu.toLowerCase(), "OP-7", "signataire_hors_jeu", `signataire ${demande.signatures[0].signer} autre que l'administrateur attendu ${signataireAttendu}`);
      }
      return { signers: demande.signatures.map((s) => s.signer) };
    }),
  );
  return fin();
}

/** Insère une signature dans une demande, à sa place dans l'ordre des adresses ; refuse un signataire déjà présent. */
export function insererSignature(demande, signature) {
  if (demande.signatures.some((s) => s.signer === signature.signer)) throw new EchecVerification("OP-7", "signature_non_canonique", `signataire ${signature.signer} déjà présent`);
  return { ...demande, signatures: rangerSignatures([...demande.signatures, signature]) };
}

/** Les t premières signatures dans l'ordre des adresses, au format {v, r, s} des contrats. */
export function signaturesPourTransaction(demande, seuil) {
  return rangerSignatures(demande.signatures)
    .slice(0, seuil)
    .map((s) => ({ v: s.v, r: s.r, s: s.s, signer: s.signer }));
}

// ---------------------------------------------------------------------------
// Dossier d'inscription : OP-4 hors ligne
// ---------------------------------------------------------------------------

/**
 * OP-4 hors ligne d'un dossier d'inscription : schéma (code
 * entree_illisible), slug et journaux conformes à RG-1 et RG-2 et identifiants
 * recalculés, membres non nuls, distincts, minuscules et triés, seuil, clé de
 * gouvernance non nulle et, en production, distincte des comptes de
 * l'exploitant ; clés d'enregistreur rattachées à un journal du dossier.
 */
export function verifierDossierInscription(dossier, { schemas, nature = "developpement", comptes = [] } = {}) {
  if (schemas) {
    const erreurs = validerSchema(dossier, schemas[ID_SCHEMA_INSCRIPTION], { registre: schemas });
    if (erreurs.length) return echec("OP-4", "entree_illisible", `dossier non conforme à inscription-client-v0 : ${erreurs.slice(0, 3).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
  }
  return verifier("OP-4", () => {
    const J = (c, m) => exiger(c, "OP-4", "jeu_invalide", m);
    const r1 = verifier("RG-1", () => orgIdDuSlug(dossier.organisation.slug, { production: nature === "production" }));
    J(r1.status === "reussi", `RG-1 : ${r1.detail}`);
    J(r1.valeurs === dossier.organisation.org_id, `org_id ${dossier.organisation.org_id} ≠ keccak256(utf8(slug)) ${r1.valeurs}`);
    const noms = new Set();
    for (const j of dossier.journals) {
      const r2 = verifier("RG-2", () => journalIdDuNom(j.name));
      J(r2.status === "reussi", `RG-2 : ${r2.detail}`);
      J(r2.valeurs === j.journal_id, `journal_id de ${j.name} ≠ keccak256(utf8(nom))`);
      J(!noms.has(j.name), `journal ${j.name} en double`);
      noms.add(j.name);
    }
    const m = dossier.approvers.members;
    J(m.every((a) => /^0x[0-9a-f]{40}$/.test(a) && !estNul(a)), "membres : adresses non nulles, en minuscules");
    J(new Set(m).size === m.length, "membres en double");
    J(m.every((a, i) => i === 0 || m[i - 1] < a), "membres non triés par ordre croissant");
    J(dossier.approvers.threshold >= 1 && dossier.approvers.threshold <= m.length, `seuil ${dossier.approvers.threshold} hors de [1, ${m.length}]`);
    J(!estNul(dossier.approvers.set_admin), "administrateur du jeu nul");
    if (nature === "production") J(!comptes.map((c) => c.toLowerCase()).includes(dossier.approvers.set_admin), "administrateur du jeu : compte de l'exploitant (EX-5.6)");
    const ids = new Set(dossier.journals.map((j) => j.journal_id));
    const cles = new Set();
    for (const r of dossier.recorders) {
      J(ids.has(r.journal_id), `clé ${r.key_id} rattachée à un journal absent du dossier`);
      J(!cles.has(r.key_id), `clé ${r.key_id} en double`);
      cles.add(r.key_id);
      J(!estNul(r.chain_key), `clé de chaîne nulle pour ${r.key_id}`);
      // CT-2 §11.2 et EX-11.19 : la classe de garde D (fichier sur l'hôte) n'est pas admise en production.
      if (nature === "production") exiger(r.custody_class !== "D" && r.chain_key_class !== "D", "OP-4", "cle_invalide", `clé ${r.key_id} : classe de garde D (custody_class ${r.custody_class}, chain_key_class ${r.chain_key_class}) refusée en production (CT-2 §11.2, EX-11.19)`);
    }
    return { org_id: r1.valeurs };
  });
}

// ---------------------------------------------------------------------------
// Schémas
// ---------------------------------------------------------------------------

/** Les trois schémas de CT-4 et ceux de CT-6 dont l'export a besoin, en registre $id -> document. */
export function registreSchemasCt4(documents) {
  const r = {};
  for (const d of documents) r[d.$id] = d;
  return r;
}

/** hachageJeuValidateurs ré-exporté pour les outils (CT-6 EX-11.8). */
export { hachageJeuValidateurs, quorum };

/** Adresse EIP-55 (pour les appels ethers qui l'exigent). */
export function eip55(a) {
  return getAddress(a);
}
