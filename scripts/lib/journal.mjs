// Implémentation de référence de la spécification CT-1 de NOORTRACE
// (spec/CT-1-evenements-et-formats.md) : forme canonique JCS v0, hachage et
// signature des événements, chaînage, arbre de Merkle RFC 6962, manifeste de
// période, références de charge utile, dossier de preuve et ses contrôles.
//
// Fonctions pures : node:crypto et ethers seulement, aucun accès au système de
// fichiers. Les scripts (scripts/vecteurs/generer-ct1.mjs,
// scripts/verify/dossier.mjs) lisent et écrivent les fichiers ; cette
// bibliothèque ne manipule que des valeurs JSON, des chaînes et des octets.
//
// Conventions (CT-1 §3) : octets en hexadécimal minuscule préfixé 0x,
// horodatages RFC 3339 UTC à la milliseconde, entiers sûrs seulement.

import { createHash, createPrivateKey, createPublicKey, sign as signerCrypto, verify as verifierCrypto } from "node:crypto";
import { Signature, getBytes, hashMessage, keccak256, recoverAddress, solidityPacked, toUtf8Bytes } from "ethers";
// Révision 0.4 de CT-1 : vérifications AT-1 à AT-7 de la partie
// attestation-perimetre.json, définies avec l'attestation par CT-7 section 7.
// securite.mjs importe aussi ce module : ni l'un ni l'autre ne lit de valeur
// de l'autre au chargement.
import * as S from "./securite.mjs";
import * as O from "./ots.mjs";

// ---------------------------------------------------------------------------
// Constantes du format v0
// ---------------------------------------------------------------------------

/** Version du format d'événement, de manifeste et de dossier. */
export const VERSION_FORMAT = 0;

/** 32 octets nuls : prev_hash du premier événement, racine d'une période vide, prev_period_hash de la première période. */
export const HASH_NUL = "0x" + "00".repeat(32);

/** Durée d'une période, secondes (une heure UTC pleine). */
export const DUREE_PERIODE = 3600;

/** Préfixes de domaine (CT-1 §6, §8, §10), octets UTF-8 avec le saut de ligne final. */
export const PREFIXE_EVENEMENT = "noortrace/evenement/v0\n";
export const PREFIXE_SIGNATURE_EVENEMENT = "noortrace/signature-evenement/v0\n";
export const PREFIXE_MANIFESTE = "noortrace/manifeste/v0\n";
export const PREFIXE_SIGNATURE_MANIFESTE = "noortrace/signature-manifeste/v0\n";
export const PREFIXE_APPROBATION = "noortrace/approbation/v0\n";
export const PREFIXE_ROTATION = "noortrace/signature-rotation/v0\n";
/** Préfixes du point de contrôle (CT-1 révision 0.3, §10.6) : hachage P_K et signature P_SK. */
export const PREFIXE_POINT_DE_CONTROLE = "noortrace/point-de-controle/v0\n";
export const PREFIXE_SIGNATURE_POINT_DE_CONTROLE = "noortrace/signature-point-de-controle/v0\n";

/** Noms d'outils réservés (CT-1 §5.1). */
export const OUTIL_MODELE = "noortrace.modele.echange";
export const OUTIL_APPROBATION = "noortrace.approbation.decision";
export const OUTIL_ROTATION = "noortrace.journal.rotation-cle";
export const OUTIL_POLITIQUE = "noortrace.journal.politique";
export const OUTILS_RESERVES = [OUTIL_MODELE, OUTIL_APPROBATION, OUTIL_ROTATION, OUTIL_POLITIQUE];

/** Les dix-sept clés d'un événement, dans l'ordre de présentation de la spécification. */
export const CLES_EVENEMENT = [
  "version", "seq", "ts", "org_id", "journal_id", "recorder_key_id", "prev_hash",
  "delegation", "code", "intent", "policy", "approval", "execution", "effects", "context",
  "hash", "sig",
];

/** Les douze clés d'un point de contrôle, dans l'ordre de présentation (CT-1 §10.5). */
export const CLES_POINT_DE_CONTROLE = [
  "version", "org_id", "journal_id", "period_start", "tree_size", "root", "last_seq", "last_hash",
  "checkpoint_ts", "prev_checkpoint_hash", "key_id", "sig",
];

/** Les douze parties d'un dossier, dans l'ordre (CT-1 §11.1). */
export const PARTIES_DOSSIER = [
  { name: "evenement", file: "evenement.json" },
  { name: "voisins", file: "voisins.json" },
  { name: "chemin", file: "chemin.json" },
  { name: "manifeste", file: "manifeste.json" },
  { name: "manifeste_sig", file: "manifeste.sig" },
  { name: "cles", file: "cles.json" },
  { name: "approbations", file: "approbations.json" },
  { name: "jeton_rfc3161", file: "jeton-rfc3161.der" },
  { name: "preuve_ots", file: "preuve.ots" },
  { name: "registre", file: "registre.json" },
  { name: "certificat_commit", file: "certificat-commit.json" },
  { name: "validateurs", file: "validateurs.json" },
];

/** Parties réservées à CT-4 et CT-5, absentes des dossiers de CT-1. */
export const PARTIES_RESERVEES = ["jeton_rfc3161", "preuve_ots", "registre", "certificat_commit", "validateurs"];

/** Treizième partie facultative du dossier (CT-1 révision 0.3, §11.1), toujours en treizième position quand elle est déclarée. */
export const PARTIE_POINTS_DE_CONTROLE = { name: "points_de_controle", file: "points-de-controle.json" };
/** Quatorzième partie facultative du dossier (CT-1 révision 0.4, §11.1), déclarée seulement après la treizième. */
export const PARTIE_ATTESTATION_PERIMETRE = { name: "attestation_perimetre", file: "attestation-perimetre.json" };

export const RAISON_HORS_PERIMETRE = "hors périmètre CT-1";
export const RAISON_AUCUNE_APPROBATION = "aucune approbation liée";
/** Raison d'absence de la partie points_de_controle quand l'exportateur la déclare sans la fournir (CT-1 §11.1). */
export const RAISON_AUCUN_POINT = "aucun point de contrôle";
/** Raison d'absence de la partie attestation_perimetre quand l'exportateur la déclare sans la fournir (CT-1 §11.1, révision 0.4). */
export const RAISON_AUCUNE_ATTESTATION = "aucune attestation de périmètre";
/** docType de l'ancre d'un point de contrôle au registre : keccak256(UTF-8("noortrace/point-de-controle/v0")) (CT-1 §10.6, CT-4 §6.4). */
export const DOC_TYPE_POINT_DE_CONTROLE = keccak256(toUtf8Bytes("noortrace/point-de-controle/v0"));

/** Identifiants des schémas, pour le registre de validation (spec/schemas). */
export const ID_SCHEMA_EVENEMENT = "https://noortrace.example/schemas/v0/evenement.schema.json";
export const ID_SCHEMA_MANIFESTE = "https://noortrace.example/schemas/v0/manifeste.schema.json";
export const ID_SCHEMA_DOSSIER = "https://noortrace.example/schemas/v0/dossier.schema.json";
export const ID_SCHEMA_POINT_DE_CONTROLE = "https://noortrace.example/schemas/v0/point-de-controle.schema.json";
/** Schéma de l'attestation de périmètre (CT-7 §7.1), référencé par $defs/attestation_perimetre de dossier-v0 (CT-1 révision 0.4). */
export const ID_SCHEMA_ATTESTATION_PERIMETRE = "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json";

/** Les contrôles du vérificateur (CT-1 §11.4), dans l'ordre du rapport, avec le contrôle de l'architecture qu'ils servent. */
export const CONTROLES_DOSSIER = [
  { id: "D-1", libelle: "index dossier.json conforme au schéma, event.seq et event.hash égaux à ceux de evenement.json", architecture: null },
  { id: "D-2", libelle: "SHA-256 de chaque partie présente égal à l'index ; parties absentes réellement absentes, avec raison", architecture: null },
  { id: "E-1", libelle: "chaque événement conforme à evenement-v0.schema.json", architecture: 1 },
  { id: "E-2", libelle: "forme canonique calculable (entiers seulement, chaînes bien formées, aucune clé en double)", architecture: 1 },
  { id: "E-3", libelle: "outil réservé parmi les quatre noms ; champs cohérents avec la sorte d'événement", architecture: 1 },
  { id: "E-4", libelle: "toute référence rédigée accompagnée d'un policy.redaction non nul", architecture: 1 },
  { id: "E-5", libelle: "approvers et signatures de même longueur ; approval.ticket = policy.ticket", architecture: 7 },
  { id: "E-6", libelle: "toute référence en ligne vérifie sha256 = SHA-256(JCS(value)) et length", architecture: 1 },
  { id: "E-7", libelle: "hash recalculé depuis l'objet égal à hash", architecture: 1 },
  { id: "E-8", libelle: "cles.json exploitable (schéma, org_id et journal_id de l'événement, key_id et public_key uniques, valid_to >= valid_from) ; sig Ed25519 valide sous la clé publique recorder_key_id de cles.json", architecture: 6 },
  { id: "E-9", libelle: "adresse recouvrée de chaque signature EIP-191 égale à approvers[i] ; signature canonique", architecture: 7 },
  { id: "E-10", libelle: "événement de rotation cohérent avec l'enveloppe, new_key_id différent de old_key_id, contresignature valide, clé et validité annoncées dans cles.json égales (valid_from nouvelle = valid_to ancienne = ts)", architecture: 6 },
  { id: "E-11", libelle: "ts de chaque événement dans la période de validité annoncée de la clé qui le signe (bornes incluses ; clé absente : non exécuté, E-8 porte l'échec)", architecture: 6 },
  { id: "C-1", libelle: "voisins.json : enveloppe { version, previous, next } ; seq contigus, ts non décroissants, org_id et journal_id identiques", architecture: 2 },
  { id: "C-2", libelle: "prev_hash = hash recalculé du précédent ; next.prev_hash = hash recalculé de l'événement ; prev_hash nul ssi seq = 1", architecture: 2 },
  { id: "C-3", libelle: "recorder_key_id constant entre voisins, sauf après une rotation (new_key_id)", architecture: 6 },
  { id: "M-1", libelle: "chemin.leaf_hash = SHA-256(0x00 || hash recalculé)", architecture: 3 },
  { id: "M-2", libelle: "algorithme d'inclusion RFC 9162 sur (leaf_hash, leaf_index, tree_size, path) donne chemin.root", architecture: 3 },
  { id: "M-3", libelle: "chemin.root = manifeste.root ; tree_size = count ; leaf_index = seq - first_seq", architecture: 3 },
  { id: "P-1", libelle: "manifeste conforme au schéma ; period_end = period_start + 3600 ; count = last_seq - first_seq + 1 ; org_id et journal_id de l'événement", architecture: 3 },
  { id: "P-2", libelle: "first_seq <= seq <= last_seq et period_start <= ts < period_end pour l'événement prouvé", architecture: 3 },
  { id: "P-3", libelle: "voisins de la période dans ses bornes de temps ; voisin hors période à first_seq - 1 (ts < period_start) ou last_seq + 1 (ts >= period_end), sinon manifeste tronqué", architecture: 2 },
  { id: "P-4", libelle: "root nulle ssi count = 0 ; count >= 1 dans un dossier", architecture: 3 },
  { id: "P-5", libelle: "periodHash recalculé = manifeste.sig.period_hash ; signature valide sous la clé de cles.json ; clé cohérente ; generated_at dans sa validité (cles.json inexploitable : non exécuté)", architecture: 3 },
  { id: "A-1", libelle: "approbations.json présent ssi approval non nul ; ticket et request_hash égaux", architecture: 7 },
  { id: "A-2", libelle: "chaque événement d'approbation est une décision (E-1 à E-11) dont approval et arguments.value correspondent à l'événement prouvé ; décision antérieure à l'appel relayé (seq, approval.at <= ts) ; une décision prouvée figure dans events", architecture: 7 },
  { id: "A-3", libelle: "approbateurs distincts, membres du jeu déclaré, en nombre >= required ; seuil cohérent avec le jeu", architecture: 7 },
  { id: "A-4", libelle: "request_hash = hash recalculé de l'événement de demande (status retenue) quand il est dans le dossier", architecture: 7 },
  { id: "K-1", libelle: "points-de-controle.json conforme au schéma (le point contre point-de-controle-v0.schema.json) ; org_id et journal_id de l'événement ; period_start du manifeste ; 1 <= tree_size <= count ; last_seq = first_seq + tree_size - 1 ; racine non nulle ; checkpoint_ts >= period_start", architecture: 3 },
  { id: "K-2", libelle: "checkpointHash recalculé (SHA-256(P_K || JCS(point sans sig))) égal à checkpoint_hash", architecture: 3 },
  { id: "K-3", libelle: "sig du point valide sous la clé publique key_id de cles.json, sur P_SK || C_K ; checkpoint_ts dans la validité de la clé (cles.json inexploitable : non exécuté, E-8 porte l'échec ; clé absente : échec)", architecture: 6 },
  { id: "K-4", libelle: "couverture : chemin.leaf_index < tree_size et ts de l'événement prouvé <= checkpoint_ts", architecture: 3 },
  { id: "K-5", libelle: "consistency : first_size = tree_size, second_size = count, first_root = root du point, second_root = root du manifeste ; algorithme de cohérence RFC 9162 §2.1.4 accepté", architecture: 3 },
  { id: "K-6", libelle: "last_hash = hash recalculé de l'événement last_seq quand il est dans le dossier (prouvé ou voisin) ; sinon non vérifiable, signalé", architecture: 2 },
  { id: "K-7", libelle: "anchors.rfc3161 non nul : jeton décodé (base64 canonique) puis T-1 à T-11 de CT-6 sur checkpoint_hash ; nul : non exécuté, ancre absente", architecture: 4 },
  { id: "K-8", libelle: "anchors.registry non nul : fingerprint = keccak256(org_id || journal_id || checkpoint_hash), doc_type du point, contract du fichier d'ancres, inclusion par les R- de CT-6 ; nul : non exécuté, ancre absente", architecture: 8 },
  { id: "K-9", libelle: "anchors.ots non nul : preuve décodée (base64 canonique) puis O-1 à O-7 de CT-6 sur checkpoint_hash ; nul : non exécuté, ancre absente", architecture: 5 },
];

const L_ED25519 = (1n << 252n) + 27742317777372353535851937790883648493n;
const P_ED25519 = (1n << 255n) - 19n;
/** Encodages canoniques des huit points de petit ordre de la courbe (RFC 8032 ne les exclut pas, CT-1 §6.2 les refuse). */
const PETIT_ORDRE_ED25519 = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);
/** d = -121665/121666 mod p (RFC 8032 §5.1). */
const D_ED25519 = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
/** Racine carrée de -1 modulo p : 2^((p-1)/4) (RFC 8032 §5.1.3, pas 3). */
const RACINE_MOINS_UN_ED25519 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
/**
 * Coordonnées y des huit points de petit ordre, tirées de leurs encodages
 * canoniques (bit de signe effacé) : y = 1 (neutre), p - 1 (ordre 2), 0 (ordre 4)
 * et les deux valeurs des points d'ordre 8. Comparer y, et non les 32 octets,
 * couvre aussi les encodages au bit de signe inversé (x = 0 avec bit de signe 1
 * pour y = 1 et y = p - 1, refusés par ailleurs au décodage).
 */
const Y_PETIT_ORDRE_ED25519 = new Set([...PETIT_ORDRE_ED25519].map((h) => BigInt("0x" + Buffer.from(h, "hex").reverse().toString("hex")) & ((1n << 255n) - 1n)));
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

// ---------------------------------------------------------------------------
// Erreurs
// ---------------------------------------------------------------------------

/** Document qui n'a pas de forme canonique (CT-1 §4) ou qui ne respecte pas les conventions d'encodage. */
export class ErreurFormat extends Error {
  constructor(message, controle = "E-2") {
    super(message);
    this.name = "ErreurFormat";
    this.controle = controle;
  }
}

/**
 * Texte qui n'est pas un document JSON acceptable. `canonique` vaut true quand
 * l'erreur est une violation de la forme canonique v0 (nombre non entier ou
 * hors intervalle, clé en double, substitut isolé, échappé ou écrit en octets
 * ED A0 80 à ED BF BF : contrôle E-2), false quand le texte n'est pas du JSON
 * (UTF-8 mal formé, marque d'ordre d'octets, syntaxe, profondeur au-delà de
 * 128), que le vérificateur impute au contrôle qui porte la partie (CT-1 §3,
 * §4 règle 7, §11.4 cas (c) ; CT-6 EX-4.16).
 */
export class ErreurJSON extends ErreurFormat {
  constructor(message, canonique = false) {
    super(message, canonique ? "E-2" : "E-1");
    this.name = "ErreurJSON";
    this.canonique = canonique;
  }
}

/** Entrée qui n'est pas un dossier : pas d'index, index illisible. Le vérificateur en ligne de commande rend le code 2. */
export class DossierInutilisable extends Error {
  constructor(message) {
    super(message);
    this.name = "DossierInutilisable";
  }
}

// ---------------------------------------------------------------------------
// Octets, hexadécimal, hachage, horodatages
// ---------------------------------------------------------------------------

const RE_HEX = /^0x([0-9a-f]{2})*$/;
const RE_HEX32 = /^0x[0-9a-f]{64}$/;
const RE_ADRESSE = /^0x[0-9a-f]{40}$/;
const RE_HORODATAGE = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/;
const RE_IDENTIFIANT_CLE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Hexadécimal minuscule préfixé 0x d'un Buffer ou d'un tableau d'octets. */
export function hex(octetsBruts) {
  return "0x" + Buffer.from(octetsBruts).toString("hex");
}

/** Octets d'une chaîne hexadécimale 0x… (minuscules exigées, longueur paire). */
export function octets(chaineHex) {
  if (typeof chaineHex !== "string" || !RE_HEX.test(chaineHex)) throw new ErreurFormat(`hexadécimal 0x minuscule attendu, reçu ${JSON.stringify(chaineHex)}`, "E-1");
  return Buffer.from(chaineHex.slice(2), "hex");
}

/** Vrai si `v` est un hachage de 32 octets au format du journal. */
export const estHex32 = (v) => typeof v === "string" && RE_HEX32.test(v);
/** Vrai si `v` est une adresse de 20 octets en minuscules. */
export const estAdresse = (v) => typeof v === "string" && RE_ADRESSE.test(v);
/**
 * Vrai si `v` est un horodatage RFC 3339 UTC à la milliseconde dont la date
 * existe dans le calendrier grégorien proleptique (CT-1 §3). Date.parse
 * renormalise une date hors calendrier (le 30 février devient le 2 mars) au
 * lieu de la refuser : l'aller-retour par toISOString la rejette.
 */
export const estHorodatage = (v) => {
  if (typeof v !== "string" || !RE_HORODATAGE.test(v)) return false;
  const ms = Date.parse(v);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === v;
};
/** Vrai si `v` est un identifiant de clé. */
export const estIdentifiantCle = (v) => typeof v === "string" && RE_IDENTIFIANT_CLE.test(v);

/**
 * Les horodatages d'un objet qui respectent le motif des schémas sans se
 * décoder (date hors du calendrier grégorien, CT-1 §3) : le motif des schémas
 * ne porte pas la règle calendaire, le vérificateur la porte (E-1, E-8, D-1,
 * P-1). `chemins` : liste de [chemin, valeur]. Rend des erreurs { chemin, message }.
 */
export function horodatagesHorsCalendrier(chemins) {
  return chemins
    .filter(([, v]) => typeof v === "string" && RE_HORODATAGE.test(v) && !estHorodatage(v))
    .map(([chemin, v]) => ({ chemin, message: `horodatage ${v} hors du calendrier grégorien (date inexistante)` }));
}

/** SHA-256, rendu en hexadécimal 0x. `donnees` : Buffer, Uint8Array, chaîne (UTF-8) ou hexadécimal 0x. */
export function sha256(donnees) {
  return hex(sha256Octets(donnees));
}

/** SHA-256, rendu en Buffer. */
export function sha256Octets(donnees) {
  return createHash("sha256").update(enOctets(donnees)).digest();
}

/** Octets d'une donnée : Buffer tel quel, hexadécimal 0x décodé, chaîne encodée en UTF-8. */
export function enOctets(donnees) {
  if (Buffer.isBuffer(donnees)) return donnees;
  if (donnees instanceof Uint8Array) return Buffer.from(donnees);
  if (typeof donnees === "string") return donnees.startsWith("0x") ? octets(donnees) : Buffer.from(donnees, "utf8");
  throw new ErreurFormat(`octets attendus, reçu ${typeof donnees}`);
}

/** Millisecondes UNIX d'un horodatage du journal ; NaN si le format est incorrect. */
export function msHorodatage(ts) {
  return estHorodatage(ts) ? Date.parse(ts) : NaN;
}

/** Horodatage du journal (RFC 3339, UTC, millisecondes) d'un instant en millisecondes UNIX. */
export function horodatage(ms) {
  return new Date(ms).toISOString();
}

/** Début (secondes UNIX, heure pleine) de la période qui contient l'horodatage `ts`. */
export function debutPeriode(ts) {
  const ms = msHorodatage(ts);
  if (Number.isNaN(ms)) throw new ErreurFormat(`horodatage invalide : ${JSON.stringify(ts)}`, "E-1");
  const s = Math.floor(ms / 1000);
  return s - (s % DUREE_PERIODE);
}

/** Vrai si l'horodatage `ts` est dans [period_start, period_end) (secondes UNIX). */
export function dansPeriode(ts, period_start, period_end) {
  const ms = msHorodatage(ts);
  if (Number.isNaN(ms)) return false;
  const s = Math.floor(ms / 1000);
  return s >= period_start && s < period_end;
}

// ---------------------------------------------------------------------------
// Forme canonique : JCS v0 (RFC 8785 restreint aux entiers)
// ---------------------------------------------------------------------------

/** Vrai si la chaîne est une suite de points de code bien formée (aucun substitut isolé). */
export function chaineBienFormee(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Forme canonique JCS v0 d'une valeur JSON (CT-1 §4) : clés triées par unités
 * de code UTF-16, chaînes échappées comme JSON.stringify d'ECMAScript, entiers
 * de l'intervalle sûr seulement, aucun espace. Lève ErreurFormat sur un nombre
 * non entier, un substitut isolé, ou toute valeur qui n'est pas du JSON.
 */
export function canonicaliserJCS(valeur, chemin = "") {
  if (valeur === null) return "null";
  switch (typeof valeur) {
    case "boolean":
      return valeur ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(valeur)) throw new ErreurFormat(`nombre non entier ou hors de l'intervalle sûr à ${chemin || "/"} : ${String(valeur)}`);
      return valeur === 0 ? "0" : String(valeur);
    case "string":
      if (!chaineBienFormee(valeur)) throw new ErreurFormat(`substitut isolé dans la chaîne à ${chemin || "/"}`);
      return JSON.stringify(valeur);
    case "object": {
      if (Array.isArray(valeur)) return "[" + valeur.map((v, i) => canonicaliserJCS(v, `${chemin}/${i}`)).join(",") + "]";
      const cles = Object.keys(valeur).sort();
      const membres = [];
      for (const k of cles) {
        if (!chaineBienFormee(k)) throw new ErreurFormat(`substitut isolé dans un nom de membre à ${chemin || "/"}`);
        if (valeur[k] === undefined) continue;
        membres.push(JSON.stringify(k) + ":" + canonicaliserJCS(valeur[k], `${chemin}/${k}`));
      }
      return "{" + membres.join(",") + "}";
    }
    default:
      throw new ErreurFormat(`valeur non JSON (${typeof valeur}) à ${chemin || "/"}`);
  }
}

/** Octets UTF-8 de la forme canonique. */
export function octetsJCS(valeur) {
  return Buffer.from(canonicaliserJCS(valeur), "utf8");
}

/**
 * Forme canonique JCS intégral d'une valeur JSON (CT-2 §8.1, EX-8.1) : la
 * RFC 8785 appliquée telle quelle, pour les pièces (arguments, résultat,
 * requête, réponse, documents de politique), jamais pour les structures que
 * CT-1 hache (événement, manifeste, valeur en ligne), qui restent en JCS v0
 * (canonicaliserJCS). Clés triées par unités de code UTF-16, chaînes échappées
 * comme JSON.stringify d'ECMAScript (échappement minimal, contrôles en
 * minuscules), nombres sérialisés par la règle ES6 Number::toString sur la
 * valeur double précision (-0 donne 0), aucun espace. Lève ErreurFormat sur
 * NaN, Infinity, un substitut isolé ou une valeur qui n'est pas du JSON. La
 * forme canonique porte la valeur, pas le texte reçu : un nombre au-delà de
 * la double précision IEEE 754 n'y est pas conservé exactement (RFC 7493).
 */
export function canonicaliserJCSIntegral(valeur, chemin = "") {
  if (valeur === null) return "null";
  switch (typeof valeur) {
    case "boolean":
      return valeur ? "true" : "false";
    case "number":
      if (!Number.isFinite(valeur)) throw new ErreurFormat(`nombre non fini (NaN ou Infinity) à ${chemin || "/"} : interdit par la RFC 8785 §3.2.2.3`);
      return valeur === 0 ? "0" : String(valeur);
    case "string":
      if (!chaineBienFormee(valeur)) throw new ErreurFormat(`substitut isolé dans la chaîne à ${chemin || "/"}`);
      return JSON.stringify(valeur);
    case "object": {
      if (Array.isArray(valeur)) return "[" + valeur.map((v, i) => canonicaliserJCSIntegral(v, `${chemin}/${i}`)).join(",") + "]";
      const cles = Object.keys(valeur).sort();
      const membres = [];
      for (const k of cles) {
        if (!chaineBienFormee(k)) throw new ErreurFormat(`substitut isolé dans un nom de membre à ${chemin || "/"}`);
        if (valeur[k] === undefined) continue;
        membres.push(JSON.stringify(k) + ":" + canonicaliserJCSIntegral(valeur[k], `${chemin}/${k}`));
      }
      return "{" + membres.join(",") + "}";
    }
    default:
      throw new ErreurFormat(`valeur non JSON (${typeof valeur}) à ${chemin || "/"}`);
  }
}

/** Profondeur maximale d'un texte JSON du format v0 (CT-1 §4, règle 7 ; CT-6 EX-4.13, EX-4.16). */
export const PROFONDEUR_JSON_MAX = 128;

/**
 * Décodage UTF-8 d'octets (CT-1 §3, CT-6 EX-4.16, point 1). Rend { texte,
 * substitutEnOctets } ; lève ErreurJSON (pas du JSON) pour une marque d'ordre
 * d'octets en tête ou une suite qui n'est pas de l'UTF-8 bien formé (RFC 3629).
 * Seule exception : une suite ED A0 80 à ED BF BF (point de code U+D800 à
 * U+DFFF écrit en octets, seul ou en paire à la manière de CESU-8) est décodée
 * en unité de code UTF-16 et signalée : c'est un substitut isolé au sens de
 * CT-1 §4 (règle 3), un défaut de forme canonique (E-2), non de codage.
 */
export function decoderUTF8(octetsTexte) {
  const buf = Buffer.isBuffer(octetsTexte) ? octetsTexte : Buffer.from(octetsTexte);
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) throw new ErreurJSON("marque d'ordre d'octets en tête du document : pas un texte JSON (CT-1 §3)", false);
  try {
    return { texte: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf), substitutEnOctets: false };
  } catch {
    // Décodage octet par octet : seules les suites ED A0..BF 80..BF sont tolérées ici, et signalées.
  }
  const unites = [];
  let substitutEnOctets = false;
  const suite = (k) => k < buf.length && (buf[k] & 0xc0) === 0x80;
  for (let i = 0; i < buf.length; ) {
    const b0 = buf[i];
    if (b0 < 0x80) {
      unites.push(b0);
      i += 1;
      continue;
    }
    if (b0 === 0xed && i + 2 < buf.length && buf[i + 1] >= 0xa0 && buf[i + 1] <= 0xbf && suite(i + 2)) {
      unites.push(0xd000 | ((buf[i + 1] & 0x3f) << 6) | (buf[i + 2] & 0x3f));
      substitutEnOctets = true;
      i += 3;
      continue;
    }
    let n;
    let cp;
    let min;
    if (b0 >= 0xc2 && b0 <= 0xdf) [n, cp, min] = [2, b0 & 0x1f, 0x80];
    else if (b0 >= 0xe0 && b0 <= 0xef) [n, cp, min] = [3, b0 & 0x0f, 0x800];
    else if (b0 >= 0xf0 && b0 <= 0xf4) [n, cp, min] = [4, b0 & 0x07, 0x10000];
    else throw new ErreurJSON(`octets UTF-8 invalides (octet ${i}) : pas un texte JSON (CT-1 §3)`, false);
    for (let k = 1; k < n; k++) {
      if (!suite(i + k)) throw new ErreurJSON(`octets UTF-8 invalides (octet ${i}) : pas un texte JSON (CT-1 §3)`, false);
      cp = (cp << 6) | (buf[i + k] & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw new ErreurJSON(`octets UTF-8 invalides (octet ${i}) : pas un texte JSON (CT-1 §3)`, false);
    if (cp >= 0x10000) {
      const v = cp - 0x10000;
      unites.push(0xd800 | (v >> 10), 0xdc00 | (v & 0x3ff));
    } else unites.push(cp);
    i += n;
  }
  let texte = "";
  for (let k = 0; k < unites.length; k += 8192) texte += String.fromCharCode(...unites.slice(k, k + 8192));
  return { texte, substitutEnOctets };
}

/**
 * Analyse stricte d'un texte JSON (chaîne ou octets UTF-8), dans l'ordre de CT-6
 * EX-4.16 : codage (UTF-8 bien formé, sans marque d'ordre d'octets), syntaxe
 * (RFC 8259), profondeur (`profondeurMax`, comptage de CT-1 §4, règle 7 : les
 * objets et tableaux imbriqués, la racine comprise ; par défaut sans borne),
 * puis forme canonique : ce que la forme canonique v0 ne sait pas représenter
 * et que JSON.parse accepterait en silence — nombre à partie fractionnaire ou
 * exposant (412.0, 1e3), entier hors de l'intervalle sûr, clé en double,
 * substitut isolé (échappé ou écrit en octets). Un défaut des trois premiers
 * points lève ErreurJSON avec `canonique` faux (pas du JSON) ; un défaut de
 * forme canonique n'est levé qu'après la lecture complète du texte, avec
 * `canonique` vrai (E-2). C'est l'analyseur du vérificateur.
 */
export function analyserJSONStrict(entree, { profondeurMax = Infinity, parElement = false } = {}) {
  let texte;
  let substitutEnOctets = false;
  if (typeof entree === "string") {
    texte = entree;
  } else {
    ({ texte, substitutEnOctets } = decoderUTF8(entree));
  }
  let i = 0;
  const n = texte.length;
  let defautCanonique = null;
  const erreur = (m) => {
    throw new ErreurJSON(`${m} (caractère ${i})`, false);
  };
  // Défaut de forme canonique : relevé au premier, levé après la lecture complète (EX-4.16, point 4 après les points 1 à 3).
  // parElement : texte dont la racine est un tableau (journal) ; un défaut de forme canonique est imputé à
  // l'élément de premier niveau qui le porte, marqué sans forme canonique, au lieu de refuser tout le texte.
  let elementCourant = null;
  const defautsElements = new Map();
  const canonique = (m) => {
    if (parElement && elementCourant !== null) {
      if (!defautsElements.has(elementCourant)) defautsElements.set(elementCourant, `${m} (caractère ${i})`);
      return;
    }
    defautCanonique ??= `${m} (caractère ${i})`;
  };
  let profondeur = 0;
  const entrer = () => {
    profondeur++;
    if (profondeur > profondeurMax) erreur(`imbrication JSON de plus de ${profondeurMax} niveaux : pas un texte JSON exploitable (CT-1 §4, règle 7)`);
  };
  const blancs = () => {
    for (;;) {
      const c = texte.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const unite = () => {
    const h = texte.slice(i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) erreur("échappement \\u invalide");
    i += 4;
    return parseInt(h, 16);
  };
  const chaine = () => {
    i++;
    let out = "";
    for (;;) {
      if (i >= n) erreur("chaîne non terminée");
      const c = texte.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) erreur("caractère de contrôle non échappé dans une chaîne");
      if (c !== 0x5c) {
        out += texte[i++];
        continue;
      }
      const e = texte[i + 1];
      i += 2;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const cu = unite();
          if (cu >= 0xd800 && cu <= 0xdbff && texte[i] === "\\" && texte[i + 1] === "u" && /^[dD][c-fC-F][0-9a-fA-F]{2}$/.test(texte.slice(i + 2, i + 6))) {
            i += 2;
            out += String.fromCharCode(cu, unite());
          } else if (cu >= 0xd800 && cu <= 0xdfff) {
            canonique(cu <= 0xdbff ? "substitut haut isolé" : "substitut bas isolé");
            out += String.fromCharCode(cu);
          } else {
            out += String.fromCharCode(cu);
          }
          break;
        }
        default:
          erreur("échappement invalide");
      }
    }
  };
  const nombre = () => {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(texte.slice(i, i + 400));
    if (!m) erreur("nombre invalide");
    if (m[2] !== undefined || m[3] !== undefined) {
      canonique(`nombre non entier « ${m[0]} » : JCS v0 n'admet que les entiers`);
      i += m[0].length;
      return Number(m[0]);
    }
    const grand = BigInt(m[0]);
    if (grand > 9007199254740991n || grand < -9007199254740991n) canonique(`entier hors de l'intervalle sûr « ${m[0]} » : à porter en chaîne décimale`);
    i += m[0].length;
    return Number(grand);
  };
  const litteral = (mot, val) => {
    if (!texte.startsWith(mot, i)) erreur("littéral invalide");
    i += mot.length;
    return val;
  };
  const tableau = () => {
    const racine = profondeur === 0;
    i++;
    entrer();
    const out = [];
    blancs();
    if (texte[i] === "]") {
      i++;
      profondeur--;
      return out;
    }
    for (;;) {
      if (racine) elementCourant = out.length;
      out.push(valeur());
      if (racine) elementCourant = null;
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "]") {
        i++;
        profondeur--;
        return out;
      }
      erreur("« , » ou « ] » attendu");
    }
  };
  const objet = () => {
    i++;
    entrer();
    const out = {};
    blancs();
    if (texte[i] === "}") {
      i++;
      profondeur--;
      return out;
    }
    for (;;) {
      blancs();
      if (texte[i] !== '"') erreur("nom de membre attendu");
      const k = chaine();
      blancs();
      if (texte[i] !== ":") erreur("« : » attendu");
      i++;
      const v = valeur();
      if (Object.hasOwn(out, k)) canonique(`clé en double « ${k} »`);
      else Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "}") {
        i++;
        profondeur--;
        return out;
      }
      erreur("« , » ou « } » attendu");
    }
  };
  const valeur = () => {
    blancs();
    if (i >= n) erreur("fin de texte inattendue");
    const c = texte[i];
    if (c === "{") return objet();
    if (c === "[") return tableau();
    if (c === '"') return chaine();
    if (c === "t") return litteral("true", true);
    if (c === "f") return litteral("false", false);
    if (c === "n") return litteral("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return nombre();
    erreur(`caractère inattendu « ${c} »`);
    return undefined;
  };
  const v = valeur();
  blancs();
  if (i < n) erreur("texte après la valeur JSON");
  if (substitutEnOctets) defautCanonique ??= "substitut (U+D800 à U+DFFF) écrit en octets ED A0 80 à ED BF BF : substitut isolé (CT-1 §3, §4 règle 3)";
  if (defautCanonique) throw new ErreurJSON(defautCanonique, true);
  for (const [k, m] of defautsElements) {
    if (estObjet(v[k])) SANS_FORME_CANONIQUE.set(v[k], m);
    else throw new ErreurJSON(m, true);
  }
  return v;
}

/**
 * Objets lus sans forme canonique (élément d'un journal, lireJournalJSON) : la
 * valeur est celle que le texte porte, lue sans perte de ses autres membres,
 * mais son hachage ne se calcule pas (E-2, CT-1 §4) et ses autres contrôles ne
 * s'exécutent pas (CT-1 §11.4, cas (d), appliqué à un événement du journal).
 */
const SANS_FORME_CANONIQUE = new WeakMap();

/** Le défaut de forme canonique d'un objet lu par lireJournalJSON, ou null. */
export function defautFormeCanonique(valeur) {
  return estObjet(valeur) ? SANS_FORME_CANONIQUE.get(valeur) ?? null : null;
}

/**
 * Lit un fichier d'événements (tableau JSON : `evenements.json` d'un journal,
 * événements fournis à une série de points). Le texte doit être du JSON
 * (CT-1 §3) ; un événement sans forme canonique (nombre non entier, clé en
 * double, substitut isolé échappé) ne rend pas tout le fichier illisible : il
 * est rendu tel qu'il se lit et marqué, de sorte que la vérification de chaîne
 * rapporte E-2 pour lui et `rupture` sur le suivant (CT-1 §7.2), et qu'une
 * série le compte comme fourni sans forme canonique (`prerequis_en_echec`,
 * CT-1 §10.5).
 */
export function lireJournalJSON(entree) {
  return analyserJSONStrict(entree, { parElement: true });
}

/** Égalité structurelle de deux valeurs JSON. */
export function egalJSON(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((v, i) => egalJSON(v, b[i]));
  const ka = Object.keys(a).filter((k) => a[k] !== undefined).sort();
  const kb = Object.keys(b).filter((k) => b[k] !== undefined).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && egalJSON(a[k], b[k]));
}

/** Mise en forme de référence des fichiers JSON des vecteurs et des dossiers : deux espaces, saut de ligne final. */
export function texteJSON(valeur) {
  return JSON.stringify(valeur, null, 2) + "\n";
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032, « pur »)
// ---------------------------------------------------------------------------

/**
 * Paire Ed25519 depuis une graine de 32 octets (la clé privée de la RFC 8032),
 * donnée en hexadécimal 0x. Rend { graine, clePrivee (KeyObject), clePublique (hex 0x) }.
 */
export function cleEd25519DepuisGraine(graineHex) {
  const graine = octets(graineHex);
  if (graine.length !== 32) throw new ErreurFormat("graine Ed25519 de 32 octets attendue", "E-8");
  const clePrivee = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, graine]), format: "der", type: "pkcs8" });
  return { graine: graineHex, clePrivee, clePublique: clePubliqueEd25519(clePrivee) };
}

/** Clé publique (hex 0x, 32 octets) d'une clé privée Ed25519 (KeyObject) ou d'une graine hexadécimale. */
export function clePubliqueEd25519(cle) {
  const privee = typeof cle === "string" ? cleEd25519DepuisGraine(cle).clePrivee : cle;
  const jwk = createPublicKey(privee).export({ format: "jwk" });
  return hex(Buffer.from(jwk.x, "base64url"));
}

/** Signature Ed25519 (64 octets, hex 0x) de `message` (Buffer ou chaîne UTF-8) par une clé privée (KeyObject ou graine). */
export function signerEd25519(cle, message) {
  const privee = typeof cle === "string" ? cleEd25519DepuisGraine(cle).clePrivee : cle;
  return hex(signerCrypto(null, enOctets(message), privee));
}

/** a^e mod p (exponentiation rapide, entiers BigInt positifs). */
function puissanceModP(a, e) {
  let r = 1n;
  let b = a % P_ED25519;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P_ED25519;
    b = (b * b) % P_ED25519;
    e >>= 1n;
  }
  return r;
}

/**
 * Vrai si les 32 octets (hex 0x minuscule) sont une clé publique Ed25519
 * admise : encodage canonique décodable selon la RFC 8032 §5.1.3 (y < p, x
 * existe, et non « x = 0 avec bit de signe 1 », pas 4) et point qui n'est pas
 * l'un des huit points de petit ordre de CT-1 §6.2 et annexe B, quel que soit
 * le bit de signe de son encodage. Une clé d'ordre mixte reste admise (CT-1
 * §6.2 ne l'exclut pas). Ce contrôle précède toute vérification : une
 * bibliothèque qui décode sans le pas 4 accepte sinon, sous l'encodage
 * 01 00…00 80 du point neutre, la signature R = B, S = 1 pour tout message.
 */
export function clePubliqueEd25519Admise(clePubliqueHex) {
  if (!estHex32(clePubliqueHex)) return false;
  const pub = octets(clePubliqueHex);
  const signe = pub[31] >> 7;
  const y = BigInt("0x" + Buffer.from(pub).reverse().toString("hex")) & ((1n << 255n) - 1n);
  // RFC 8032 §5.1.3, pas 1 : y >= p fait échouer le décodage (pas de réduction).
  if (y >= P_ED25519) return false;
  // CT-1 §6.2 : A ne doit pas être de petit ordre (8·A = 0), encodage canonique ou non.
  if (Y_PETIT_ORDRE_ED25519.has(y)) return false;
  // RFC 8032 §5.1.3, pas 2 et 3 : x² = (y² - 1) / (d·y² + 1) doit avoir une racine.
  const y2 = (y * y) % P_ED25519;
  const u = (y2 - 1n + P_ED25519) % P_ED25519;
  const v = (D_ED25519 * y2 + 1n) % P_ED25519;
  const x2 = (u * puissanceModP(v, P_ED25519 - 2n)) % P_ED25519;
  let x = puissanceModP(x2, (P_ED25519 + 3n) / 8n);
  if ((x * x) % P_ED25519 !== x2) x = (x * RACINE_MOINS_UN_ED25519) % P_ED25519;
  if ((x * x) % P_ED25519 !== x2) return false;
  // RFC 8032 §5.1.3, pas 4 : x = 0 avec bit de signe 1 fait échouer le décodage.
  if (x === 0n && signe === 1) return false;
  return true;
}

/**
 * Vérification Ed25519 : clé publique admise (clePubliqueEd25519Admise :
 * encodage canonique décodable, point qui n'est pas de petit ordre), signature
 * de 64 octets dont S est réduit modulo l'ordre du groupe, puis vérification
 * RFC 8032 §5.1.7. Rend false sur toute entrée malformée.
 */
export function verifierEd25519(clePubliqueHex, message, signatureHex) {
  if (!estHex32(clePubliqueHex) || typeof signatureHex !== "string" || !/^0x[0-9a-f]{128}$/.test(signatureHex)) return false;
  if (!clePubliqueEd25519Admise(clePubliqueHex)) return false;
  const pub = octets(clePubliqueHex);
  const sig = octets(signatureHex);
  const s = BigInt("0x" + Buffer.from(sig.subarray(32)).reverse().toString("hex"));
  if (s >= L_ED25519) return false;
  try {
    const cle = createPublicKey({ key: Buffer.concat([SPKI_ED25519, pub]), format: "der", type: "spki" });
    return verifierCrypto(null, enOctets(message), cle, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Événement : corps, hachage, signature
// ---------------------------------------------------------------------------

/**
 * Pose `valeur` comme propriété propre `cle` de `objet`, y compris pour un
 * membre « __proto__ » : l'affectation `objet[cle] = valeur` appellerait
 * l'accesseur hérité d'Object.prototype, changerait le prototype et perdrait le
 * membre, qui échapperait alors au hachage et à la signature.
 */
function poserMembre(objet, cle, valeur) {
  Object.defineProperty(objet, cle, { value: valeur, enumerable: true, writable: true, configurable: true });
}

/** E' : l'événement privé de hash et sig (CT-1 §6.1), tous ses autres membres compris (« __proto__ » aussi). */
export function corpsEvenement(evenement) {
  if (!evenement || typeof evenement !== "object" || Array.isArray(evenement)) throw new ErreurFormat("événement : objet attendu", "E-1");
  const corps = {};
  for (const k of Object.keys(evenement)) if (k !== "hash" && k !== "sig") poserMembre(corps, k, evenement[k]);
  return corps;
}

/** hash = SHA-256(P_H || JCS(E')). */
export function hachageEvenement(evenement) {
  if (defautFormeCanonique(evenement)) throw new ErreurJSON(`événement sans forme canonique : ${defautFormeCanonique(evenement)}`, true);
  return sha256(Buffer.concat([Buffer.from(PREFIXE_EVENEMENT, "utf8"), octetsJCS(corpsEvenement(evenement))]));
}

/** Message signé par l'enregistreur : P_S || JCS(E'). */
export function messageSignatureEvenement(evenement) {
  if (defautFormeCanonique(evenement)) throw new ErreurJSON(`événement sans forme canonique : ${defautFormeCanonique(evenement)}`, true);
  return Buffer.concat([Buffer.from(PREFIXE_SIGNATURE_EVENEMENT, "utf8"), octetsJCS(corpsEvenement(evenement))]);
}

/** sig = Ed25519(sk, P_S || JCS(E')). `cle` : KeyObject privé ou graine hexadécimale. */
export function signerEvenement(evenement, cle) {
  return signerEd25519(cle, messageSignatureEvenement(evenement));
}

/** Vrai si hash recalculé = evenement.hash (E-7). */
export function verifierHachageEvenement(evenement) {
  return hachageEvenement(evenement) === evenement.hash;
}

/** Vrai si evenement.sig est valide sous la clé publique donnée (E-8). */
export function verifierSignatureEvenement(evenement, clePubliqueHex) {
  return verifierEd25519(clePubliqueHex, messageSignatureEvenement(evenement), evenement.sig);
}

/**
 * Scelle un corps d'événement : rend l'événement complet, clés dans l'ordre de
 * la spécification, avec hash et sig calculés par la clé donnée.
 */
export function scellerEvenement(corps, cle) {
  const ordonne = {};
  for (const k of CLES_EVENEMENT) if (k !== "hash" && k !== "sig") poserMembre(ordonne, k, corps[k]);
  for (const k of Object.keys(corps)) if (!Object.hasOwn(ordonne, k) && k !== "hash" && k !== "sig") poserMembre(ordonne, k, corps[k]);
  ordonne.hash = hachageEvenement(ordonne);
  ordonne.sig = signerEvenement(ordonne, cle);
  return ordonne;
}

/** Vrai si l'outil est l'un des noms réservés. */
export const estOutilReserve = (tool) => typeof tool === "string" && tool.startsWith("noortrace.");

/** Vrai si l'événement est une rotation de clé. */
export const estRotation = (evenement) => evenement?.execution?.tool === OUTIL_ROTATION;

/** Vrai si l'événement est une décision d'approbation. */
export const estDecisionApprobation = (evenement) => evenement?.execution?.tool === OUTIL_APPROBATION;

/** Clé attendue pour l'événement qui suit `evenement` (C-3) : new_key_id après une rotation, sinon la même. */
export function cleSuivanteAttendue(evenement) {
  if (estRotation(evenement)) {
    const nouvelle = evenement?.execution?.arguments?.value?.new_key_id;
    return typeof nouvelle === "string" ? nouvelle : evenement.recorder_key_id;
  }
  return evenement.recorder_key_id;
}

// ---------------------------------------------------------------------------
// Références de charge utile (CT-1 §5.4)
// ---------------------------------------------------------------------------

/** Référence à une pièce stockée : { sha256, length, redacted[, media_type] }. `piece` : Buffer ou chaîne UTF-8. */
export function reference(piece, { redacted = false, media_type } = {}) {
  const o = enOctets(Buffer.isBuffer(piece) ? piece : typeof piece === "string" && piece.startsWith("0x") ? octets(piece) : Buffer.from(String(piece), "utf8"));
  const ref = { sha256: sha256(o), length: o.length, redacted: Boolean(redacted) };
  if (media_type !== undefined) ref.media_type = media_type;
  return ref;
}

/** Référence en ligne : la pièce est JCS(value), jamais rédigée. */
export function referenceEnLigne(value, { media_type } = {}) {
  const o = octetsJCS(value);
  const ref = { sha256: sha256(o), length: o.length, redacted: false };
  if (media_type !== undefined) ref.media_type = media_type;
  ref.value = value;
  return ref;
}

/**
 * Vérifie une référence (E-6) : si `value` est présente, sha256 = SHA-256(JCS(value))
 * et length = longueur de JCS(value) ; si `piece` (octets) est fournie, sha256 et
 * length de la pièce. Rend { ok, raison }.
 */
export function verifierReference(ref, piece) {
  if (!ref || typeof ref !== "object") return { ok: false, raison: "référence : objet attendu" };
  if (ref.redacted === true && ref.value !== undefined) return { ok: false, raison: "value interdite sur une référence rédigée" };
  if (ref.value !== undefined) {
    let o;
    try {
      o = octetsJCS(ref.value);
    } catch (err) {
      return { ok: false, raison: `value sans forme canonique : ${err.message}` };
    }
    if (sha256(o) !== ref.sha256) return { ok: false, raison: `sha256 de JCS(value) (${sha256(o)}) différent de sha256 déclaré (${ref.sha256})` };
    if (o.length !== ref.length) return { ok: false, raison: `length de JCS(value) (${o.length}) différente de length déclarée (${ref.length})` };
  }
  if (piece !== undefined) {
    const o = enOctets(piece);
    if (sha256(o) !== ref.sha256) return { ok: false, raison: "sha256 de la pièce fournie différent du sha256 déclaré" };
    if (o.length !== ref.length) return { ok: false, raison: `length de la pièce (${o.length}) différente de length déclarée (${ref.length})` };
  }
  return { ok: true, raison: null };
}

/** Les références d'un événement, avec leur emplacement. */
export function referencesEvenement(evenement) {
  const refs = [];
  const ex = evenement?.execution ?? {};
  if (ex.arguments && typeof ex.arguments === "object") refs.push({ chemin: "execution.arguments", ref: ex.arguments });
  if (ex.result && typeof ex.result === "object") refs.push({ chemin: "execution.result", ref: ex.result });
  if (evenement?.intent && typeof evenement.intent === "object") refs.push({ chemin: "intent", ref: evenement.intent });
  if (Array.isArray(evenement?.context)) evenement.context.forEach((c, i) => c && typeof c === "object" && refs.push({ chemin: `context[${i}]`, ref: c }));
  return refs;
}

// ---------------------------------------------------------------------------
// Approbation (EIP-191 sur un condensé SHA-256, CT-1 §6.3)
// ---------------------------------------------------------------------------

/** A = { decision, journal_id, org_id, request_hash, ticket } d'un événement ou d'un objet qui porte ces champs. */
export function objetApprobation(source) {
  const a = source.approval ?? source;
  return {
    decision: a.decision,
    journal_id: source.journal_id ?? a.journal_id,
    org_id: source.org_id ?? a.org_id,
    request_hash: a.request_hash,
    ticket: a.ticket,
  };
}

/** D_A = SHA-256(P_A || JCS(A)). */
export function condenseApprobation(A) {
  return sha256(Buffer.concat([Buffer.from(PREFIXE_APPROBATION, "utf8"), octetsJCS(A)]));
}

/** Condensé EIP-191 (keccak256 du message préfixé) que les approbateurs signent : hashMessage(D_A). */
export function condenseEIP191Approbation(A) {
  return hashMessage(getBytes(condenseApprobation(A)));
}

/**
 * Signature EIP-191 d'un approbateur sur A, par un Wallet ethers (synchrone, via
 * sa SigningKey : RFC 6979, déterministe). Rend r || s || v en hexadécimal 0x.
 */
export function signerApprobation(wallet, A) {
  return Signature.from(wallet.signingKey.sign(condenseEIP191Approbation(A))).serialized;
}

const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Vérifie une signature d'approbateur (E-9) : forme 65 octets, s dans la moitié
 * basse, v dans {27, 28}, adresse recouvrée égale à `adresseAttendue` (minuscules).
 * Rend { ok, adresse, raison }.
 */
export function verifierSignatureApprobation(A, signatureHex, adresseAttendue) {
  if (typeof signatureHex !== "string" || !/^0x[0-9a-f]{130}$/.test(signatureHex)) return { ok: false, adresse: null, raison: "signature EIP-191 de 65 octets en hexadécimal minuscule attendue" };
  const s = BigInt("0x" + signatureHex.slice(66, 130));
  const v = parseInt(signatureHex.slice(130, 132), 16);
  if (s > N_SECP256K1 / 2n) return { ok: false, adresse: null, raison: "signature non canonique : s dans la moitié haute de l'ordre" };
  if (v !== 27 && v !== 28) return { ok: false, adresse: null, raison: `signature non canonique : v = ${v}, attendu 27 ou 28` };
  let adresse;
  try {
    adresse = recoverAddress(condenseEIP191Approbation(A), signatureHex).toLowerCase();
  } catch (err) {
    return { ok: false, adresse: null, raison: `signature non recouvrable : ${err.message}` };
  }
  if (adresse !== adresseAttendue) return { ok: false, adresse, raison: `adresse recouvrée ${adresse} différente de l'approbateur déclaré ${adresseAttendue}` };
  return { ok: true, adresse, raison: null };
}

// ---------------------------------------------------------------------------
// Rotation de clé (CT-1 §8)
// ---------------------------------------------------------------------------

/** R : l'annonce de rotation sans counter_sig. */
export function objetRotation(value) {
  const R = {};
  for (const k of Object.keys(value)) if (k !== "counter_sig") poserMembre(R, k, value[k]);
  return R;
}

/** counter_sig = Ed25519(sk(new_key_id), P_R || JCS(R)). */
export function contresignerRotation(R, cleNouvelle) {
  return signerEd25519(cleNouvelle, Buffer.concat([Buffer.from(PREFIXE_ROTATION, "utf8"), octetsJCS(objetRotation(R))]));
}

/** Vrai si value.counter_sig est valide sous value.new_public_key. */
export function verifierContresignatureRotation(value) {
  if (!value || typeof value !== "object") return false;
  return verifierEd25519(value.new_public_key, Buffer.concat([Buffer.from(PREFIXE_ROTATION, "utf8"), octetsJCS(objetRotation(value))]), value.counter_sig);
}

/** Construit la valeur en ligne d'une rotation, contresignée par la nouvelle clé. */
export function annonceRotation({ org_id, journal_id, old_key_id, new_key_id, new_public_key, valid_from, cleNouvelle }) {
  const R = { journal_id, new_key_id, new_public_key, old_key_id, org_id, valid_from };
  return { ...R, counter_sig: contresignerRotation(R, cleNouvelle) };
}

// ---------------------------------------------------------------------------
// Chaînage (CT-1 §7)
// ---------------------------------------------------------------------------

/**
 * Construit un journal : à chaque entrée (les huit champs, ts, recorder_key_id),
 * assigne version, seq, org_id, journal_id, prev_hash, puis hash et sig par la
 * clé privée de son recorder_key_id. `cles` : objet ou Map key_id -> KeyObject
 * privé ou graine hexadécimale. Rend les événements complets.
 */
export function chainer(entrees, { org_id, journal_id, cles, premierSeq = 1, prevHash = HASH_NUL }) {
  const cle = (id) => {
    const c = cles instanceof Map ? cles.get(id) : cles?.[id];
    if (!c) throw new ErreurFormat(`chainer : aucune clé privée pour ${id}`, "E-8");
    return c;
  };
  const sortie = [];
  let seq = premierSeq;
  let prev_hash = prevHash;
  for (const e of entrees) {
    const corps = { version: VERSION_FORMAT, seq, ts: e.ts, org_id, journal_id, recorder_key_id: e.recorder_key_id, prev_hash, ...e };
    corps.version = VERSION_FORMAT;
    corps.seq = seq;
    corps.org_id = org_id;
    corps.journal_id = journal_id;
    corps.prev_hash = prev_hash;
    delete corps.hash;
    delete corps.sig;
    const ev = scellerEvenement(corps, cle(e.recorder_key_id));
    sortie.push(ev);
    prev_hash = ev.hash;
    seq++;
  }
  return sortie;
}

/** Normalise une source de clés publiques (cles.json, tableau de clés, objet key_id -> hex, Map) en Map key_id -> { public_key, valid_from, valid_to }. */
export function normaliserCles(cles) {
  const m = new Map();
  if (!cles) return m;
  const liste = Array.isArray(cles) ? cles : Array.isArray(cles.keys) ? cles.keys : null;
  if (liste) {
    for (const k of liste) if (k && typeof k === "object" && typeof k.key_id === "string" && !m.has(k.key_id)) m.set(k.key_id, { public_key: k.public_key, valid_from: k.valid_from ?? null, valid_to: k.valid_to ?? null });
    return m;
  }
  const entrees = cles instanceof Map ? cles.entries() : Object.entries(cles);
  for (const [id, v] of entrees) {
    if (typeof v === "string") m.set(id, { public_key: v, valid_from: null, valid_to: null });
    else if (v && typeof v === "object") m.set(id, { public_key: v.public_key ?? v.clePublique, valid_from: v.valid_from ?? null, valid_to: v.valid_to ?? null });
  }
  return m;
}

/**
 * Règles de cles.json que le schéma n'exprime pas (CT-1 §11.2, contrôle E-8) :
 * org_id et journal_id égaux à ceux de l'événement prouvé, key_id et public_key
 * uniques dans keys, valid_to >= valid_from quand valid_to n'est pas nul. Rend
 * la liste des erreurs (vide si conforme). `evenement` peut être null.
 */
export function verifierCles(clesDoc, evenement = null) {
  if (!clesDoc || typeof clesDoc !== "object" || Array.isArray(clesDoc)) return ["objet attendu"];
  const erreurs = [];
  if (evenement && typeof evenement === "object") {
    if (clesDoc.org_id !== evenement.org_id) erreurs.push(`org_id ${clesDoc.org_id} différent de celui de l'événement (${evenement.org_id})`);
    if (clesDoc.journal_id !== evenement.journal_id) erreurs.push(`journal_id ${clesDoc.journal_id} différent de celui de l'événement (${evenement.journal_id})`);
  }
  const ids = new Map();
  const pubs = new Map();
  (Array.isArray(clesDoc.keys) ? clesDoc.keys : []).forEach((k, i) => {
    if (!k || typeof k !== "object") return;
    if (typeof k.key_id === "string") {
      if (ids.has(k.key_id)) erreurs.push(`keys[${i}].key_id ${k.key_id} en double (déjà keys[${ids.get(k.key_id)}])`);
      else ids.set(k.key_id, i);
    }
    if (typeof k.public_key === "string") {
      if (pubs.has(k.public_key)) erreurs.push(`keys[${i}].public_key déjà portée par keys[${pubs.get(k.public_key)}] : deux identifiants pour une même clé`);
      else pubs.set(k.public_key, i);
    }
    for (const e of horodatagesHorsCalendrier([[`keys[${i}].valid_from`, k.valid_from], [`keys[${i}].valid_to`, k.valid_to]])) erreurs.push(`${e.chemin} : ${e.message}`);
    if (typeof k.valid_from === "string" && typeof k.valid_to === "string") {
      const de = msHorodatage(k.valid_from);
      const a = msHorodatage(k.valid_to);
      if (!Number.isNaN(de) && !Number.isNaN(a) && a < de) erreurs.push(`keys[${i}] : valid_to ${k.valid_to} antérieur à valid_from ${k.valid_from}`);
    }
  });
  return erreurs;
}

/** Type des symptômes de E-1 à E-11 d'un journal (CT-1 §7.2, révision 0.5). */
export const TYPES_SYMPTOMES = { "E-1": "schema", "E-2": "format", "E-3": "sorte", "E-4": "redaction", "E-5": "approbation", "E-6": "reference", "E-7": "modification", "E-8": "signature", "E-9": "approbateur", "E-10": "rotation", "E-11": "validite_cle" };

/**
 * Première partie de E-8 sur le cles.json d'un journal, sans référence à un
 * événement (CT-1 §7.2, révision 0.5) : schéma (`schemas` fourni), dates
 * existantes, key_id et public_key uniques, valid_to >= valid_from. Rend la
 * liste des erreurs.
 */
export function verifierClesJournal(clesDoc, { schemas = null } = {}) {
  if (!estObjet(clesDoc)) return ["cles.json : objet JSON attendu"];
  const erreurs = [];
  if (schemas?.[ID_SCHEMA_DOSSIER]) erreurs.push(...validerSchema(clesDoc, schemas[ID_SCHEMA_DOSSIER], { registre: schemas, fragment: "#/$defs/cles" }).map((e) => `${e.chemin} : ${e.message}`));
  erreurs.push(...verifierCles(clesDoc, null));
  return erreurs;
}

/**
 * Vérifie un journal (CT-1 §7.2, règle exacte de la révision 0.5) : les
 * événements dans l'ordre du fichier et le cles.json du journal. Diagnostics :
 * { type, controle, seq, message }, rapportés en trois temps et dans cet ordre :
 *
 *   1. chaque événement pour lui-même, dans l'ordre du fichier : E-1 à E-11
 *      (types de TYPES_SYMPTOMES), puis l'origine (prev_hash nul si et
 *      seulement si seq = 1 : C-2, type origine). cles.json est lu d'abord :
 *      s'il ne passe pas la première partie de E-8, un symptôme E-8 de type
 *      cles et de seq nul est rapporté en tête et E-8 ne l'est pour aucun
 *      événement ; sinon son org_id et son journal_id sont comparés à ceux de
 *      chaque événement (écart : E-8, type signature) ;
 *   2. la suite des seq sur tout le fichier (C-1), parmi les seq entiers :
 *      insertion (seq présent plusieurs fois, ordre de première apparition),
 *      suppression (trou de l'ensemble trié des seq distincts, seq qui suit le
 *      trou, ordre croissant), reordonnancement (seq inférieur à celui de
 *      l'événement qui le précède dans le fichier) ;
 *   3. chaque couple consécutif (a, b) dans l'ordre du fichier : rupture
 *      (b.prev_hash différent du hash recalculé de a, ou hash de a
 *      incalculable, C-2), horodatage (ts de b antérieur à celui de a, ou
 *      incomparable, C-1), journal (org_id ou journal_id différents, C-1), cle
 *      (recorder_key_id de b différent de la clé attendue après a, C-3). Un
 *      couple dont un élément n'est pas un objet n'est pas examiné.
 *
 * `clesPubliques` : le cles.json du journal (objet { org_id, journal_id, keys }),
 * ou, hors de la règle exacte, une source de clés (voir normaliserCles) sans
 * comparaison d'org_id ni de journal_id ; sans clés, E-8, E-10 (clés) et E-11
 * ne sont pas exécutées. `schemas` : registre des schémas (E-1 et schéma de
 * cles.json) ; sans lui, E-1 n'est pas exécutée. La troncature de la fin du
 * journal n'est pas détectable par la chaîne seule (manifeste, P-3/P-4).
 */
export function verifierChaine(evenements, { clesPubliques, schemas = null } = {}) {
  const diagnostics = [];
  const dire = (type, controle, seq, message) => diagnostics.push({ type, controle, seq, message });
  if (!Array.isArray(evenements)) return { valide: false, diagnostics: [{ type: "format", controle: "E-1", seq: null, message: "tableau d'événements attendu" }] };
  const seqDe = (ev) => (estObjet(ev) && Number.isSafeInteger(ev.seq) ? ev.seq : null);

  // cles.json du journal, lu d'abord (première partie de E-8, sans événement).
  const estClesJson = estObjet(clesPubliques) && Array.isArray(clesPubliques.keys) && ("org_id" in clesPubliques || "journal_id" in clesPubliques);
  let clesExploitables = true;
  if (estClesJson) {
    const erreurs = verifierClesJournal(clesPubliques, { schemas });
    if (erreurs.length) {
      clesExploitables = false;
      dire("cles", "E-8", null, `cles.json du journal : ${erreurs.slice(0, 4).join(" ; ")}`);
    }
  }
  const cles = clesExploitables ? normaliserCles(clesPubliques) : new Map();
  const haches = new Map(); // position -> hash recalculé (null : incalculable)

  // 1. Chaque événement pour lui-même : E-1 à E-11, puis l'origine.
  evenements.forEach((ev, pos) => {
    const seq = seqDe(ev);
    const res = controlesEvenement(ev, { schemas, cles: clesExploitables ? clesPubliques : null, clesExploitables });
    let h = null;
    if (estObjet(ev)) {
      try {
        h = hachageEvenement(ev);
      } catch {
        h = null;
      }
    }
    haches.set(pos, h);
    for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"]) {
      const x = res[id];
      const ecart = id === "E-8" && estClesJson && clesExploitables && estObjet(ev) && !defautFormeCanonique(ev) && (ev.org_id !== clesPubliques.org_id || ev.journal_id !== clesPubliques.journal_id);
      const messages = [];
      if (x && x.ok === false) messages.push(id === "E-7" ? `seq ${seq} : ${x.detail} (contenu modifié après scellement)` : id === "E-8" && /^signature invalide/.test(x.detail ?? "") ? `seq ${seq} : signature invalide sous la clé ${ev.recorder_key_id}${res["E-7"]?.ok === false ? " (contenu modifié)" : ""}` : `seq ${seq} : ${x.detail}`);
      if (ecart) messages.unshift(`seq ${seq} : org_id ou journal_id de l'événement différents de ceux de cles.json du journal`);
      if (messages.length) dire(TYPES_SYMPTOMES[id], id, seq, messages.join(" ; "));
    }
    if (estObjet(ev)) {
      if (ev.seq === 1 && ev.prev_hash !== HASH_NUL) dire("origine", "C-2", seq, "seq 1 : prev_hash doit être nul");
      if (ev.seq !== 1 && ev.prev_hash === HASH_NUL) dire("origine", "C-2", seq, `seq ${seq} : prev_hash nul réservé au premier événement`);
    }
  });

  // 2. La suite des seq sur tout le fichier : doublons (insertion), trous (suppression), ordre (réordonnancement).
  const seqs = evenements.map(seqDe);
  const vus = new Map();
  seqs.forEach((s, pos) => {
    if (s !== null) vus.set(s, [...(vus.get(s) ?? []), pos]);
  });
  for (const [s, positions] of vus) if (positions.length > 1) dire("insertion", "C-1", s, `seq ${s} présent ${positions.length} fois (positions ${positions.join(", ")}) : événement inséré`);
  const uniques = [...vus.keys()].sort((x, y) => x - y);
  for (let i = 1; i < uniques.length; i++) {
    if (uniques[i] !== uniques[i - 1] + 1) {
      const manquants = uniques[i] - uniques[i - 1] - 1;
      dire("suppression", "C-1", uniques[i], `trou entre seq ${uniques[i - 1]} et seq ${uniques[i]} : ${manquants} événement(s) supprimé(s)`);
    }
  }
  // Révision 0.5 : « l'événement qui le précède » est le dernier événement à seq entier qui le précède dans le fichier.
  let dernierEntier = null;
  for (let pos = 0; pos < seqs.length; pos++) {
    if (seqs[pos] === null) continue;
    if (dernierEntier !== null && seqs[pos] < seqs[dernierEntier]) {
      dire("reordonnancement", "C-1", seqs[pos], `seq ${seqs[pos]} (position ${pos}) après seq ${seqs[dernierEntier]} (position ${dernierEntier}) : ordre du journal non respecté`);
    }
    dernierEntier = pos;
  }

  // 3. Les liens, couple par couple dans l'ordre du fichier. Révision 0.5 : un terme qui ne se calcule
  // pas (événement qui n'est pas un objet, hash sans forme canonique, ts qui n'est pas une date existante,
  // identifiant absent ou mal typé) ne tient pas la relation, qui est rapportée.
  const texteOuAbsent = (v) => (typeof v === "string" ? v : JSON.stringify(v) ?? "absent");
  for (let pos = 1; pos < evenements.length; pos++) {
    const prec = estObjet(evenements[pos - 1]) ? evenements[pos - 1] : {};
    const ev = estObjet(evenements[pos]) ? evenements[pos] : {};
    const seq = seqDe(evenements[pos]);
    const seqPrec = estObjet(evenements[pos - 1]) ? JSON.stringify(evenements[pos - 1].seq) : `(position ${pos - 1}, pas un objet)`;
    const hp = haches.get(pos - 1);
    if (hp === null) dire("rupture", "C-2", seq, `seq ${seq} (position ${pos}) : hash de l'événement précédent dans le fichier incalculable (${estObjet(evenements[pos - 1]) ? "sans forme canonique" : "pas un objet"}) : chaînage non établi`);
    else if (ev.prev_hash !== hp) dire("rupture", "C-2", seq, `seq ${seq} (position ${pos}) : prev_hash ${texteOuAbsent(ev.prev_hash)} différent du hash recalculé de l'événement précédent dans le fichier, seq ${seqPrec} (${hp})`);
    const t0 = msHorodatage(prec.ts);
    const t1 = msHorodatage(ev.ts);
    if (Number.isNaN(t0) || Number.isNaN(t1)) dire("horodatage", "C-1", seq, `seq ${seq} : ts ${texteOuAbsent(ev.ts)} incomparable à celui de seq ${seqPrec} (${texteOuAbsent(prec.ts)}) : horodatage qui n'est pas une date existante`);
    else if (t1 < t0) dire("horodatage", "C-1", seq, `seq ${seq} : ts ${ev.ts} antérieur à celui de seq ${seqPrec} (${prec.ts})`);
    const idsLisibles = ["org_id", "journal_id"].every((k) => typeof ev[k] === "string" && typeof prec[k] === "string");
    if (!idsLisibles || ev.org_id !== prec.org_id || ev.journal_id !== prec.journal_id) dire("journal", "C-1", seq, idsLisibles ? `seq ${seq} : org_id ou journal_id différents de seq ${seqPrec}` : `seq ${seq} : org_id ou journal_id absent ou mal typé (seq ${seq} ou seq ${seqPrec})`);
    const attendue = estObjet(evenements[pos - 1]) ? cleSuivanteAttendue(prec) : undefined;
    if (typeof attendue !== "string" || ev.recorder_key_id !== attendue) dire("cle", "C-3", seq, `seq ${seq} : recorder_key_id ${texteOuAbsent(ev.recorder_key_id)}, attendu ${texteOuAbsent(attendue)}${estObjet(evenements[pos - 1]) && estRotation(prec) ? " (rotation en seq " + prec.seq + ")" : ""}`);
  }
  return { valide: diagnostics.length === 0, diagnostics };
}

// ---------------------------------------------------------------------------
// Arbre de Merkle RFC 6962 (CT-1 §9)
// ---------------------------------------------------------------------------

/** L(i) = SHA-256(0x00 || D[i]). `donnee` : hexadécimal 0x (le hash d'un événement) ou octets. */
export function feuilleMerkle(donnee) {
  return sha256(Buffer.concat([Buffer.from([0x00]), enOctets(donnee)]));
}

/** N(g, d) = SHA-256(0x01 || g || d). */
export function noeudMerkle(gauche, droite) {
  return sha256(Buffer.concat([Buffer.from([0x01]), octets(gauche), octets(droite)]));
}

/** Plus grande puissance de deux strictement inférieure à n (n > 1). */
export function puissanceDeDeuxInferieure(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function mth(feuilles, debut, fin) {
  const n = fin - debut;
  if (n === 1) return feuilleMerkle(feuilles[debut]);
  const k = puissanceDeDeuxInferieure(n);
  return noeudMerkle(mth(feuilles, debut, debut + k), mth(feuilles, debut + k, fin));
}

/**
 * Racine RFC 6962 des données `feuilles` (hash des événements dans l'ordre des
 * seq). Période vide : 32 octets nuls, convention NOORTRACE imposée par
 * PeriodRegistry, et non SHA-256("") de l'arbre vide de la RFC.
 */
export function racineMerkle(feuilles) {
  if (!Array.isArray(feuilles)) throw new ErreurFormat("racineMerkle : tableau attendu", "M-2");
  if (feuilles.length === 0) return HASH_NUL;
  return mth(feuilles, 0, feuilles.length);
}

/** PATH(m, D[0..n-1]) de la RFC 6962 §2.1.1, du bas vers le haut. */
export function cheminAudit(feuilles, m) {
  const n = feuilles.length;
  if (!Number.isInteger(m) || m < 0 || m >= n) throw new ErreurFormat(`cheminAudit : indice ${m} hors de [0, ${n})`, "M-2");
  const path = (idx, debut, fin) => {
    if (fin - debut === 1) return [];
    const k = puissanceDeDeuxInferieure(fin - debut);
    if (idx < k) return [...path(idx, debut, debut + k), mth(feuilles, debut + k, fin)];
    return [...path(idx - k, debut + k, fin), mth(feuilles, debut, debut + k)];
  };
  return path(m, 0, n);
}

/** Preuve d'inclusion de la feuille m : le contenu de chemin.json (CT-1 §9.3). */
export function preuveInclusion(feuilles, m) {
  return {
    version: VERSION_FORMAT,
    tree_size: feuilles.length,
    leaf_index: m,
    leaf_hash: feuilleMerkle(feuilles[m]),
    path: cheminAudit(feuilles, m),
    root: racineMerkle(feuilles),
  };
}

/**
 * Vérification d'une preuve d'inclusion par l'algorithme de la RFC 9162 §2.1.3.2
 * (CT-1 §9.3) : rend true si et seulement si le chemin a exactement la longueur
 * attendue pour (leaf_index, tree_size) et mène de leaf_hash à root.
 */
export function verifierInclusion({ leaf_hash, leaf_index, tree_size, path, root }) {
  if (!estHex32(leaf_hash) || !estHex32(root) || !Array.isArray(path) || !path.every(estHex32)) return false;
  if (!Number.isSafeInteger(leaf_index) || !Number.isSafeInteger(tree_size) || leaf_index < 0 || tree_size < 1) return false;
  if (leaf_index >= tree_size) return false;
  let fn = leaf_index;
  let sn = tree_size - 1;
  let r = leaf_hash;
  for (const h of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = noeudMerkle(h, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = noeudMerkle(r, h);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r === root;
}

/**
 * SUBPROOF(m, D[debut..fin-1], b) de la RFC 9162 §2.1.4.1 (CT-1 §10.7) : b vrai
 * quand la racine du sous-arbre des m premières feuilles est déjà connue.
 */
function sousPreuveCoherence(feuilles, m, debut, fin, b) {
  const n = fin - debut;
  if (m === n) return b ? [] : [mth(feuilles, debut, fin)];
  const k = puissanceDeDeuxInferieure(n);
  if (m <= k) return [...sousPreuveCoherence(feuilles, m, debut, debut + k, b), mth(feuilles, debut + k, fin)];
  return [...sousPreuveCoherence(feuilles, m - k, debut + k, fin, false), mth(feuilles, debut, debut + k)];
}

/**
 * PROOF(m, D[0..n-1]) de la RFC 9162 §2.1.4.1 (CT-1 §10.7) : la preuve que
 * l'arbre des m premières feuilles est un préfixe de l'arbre des n feuilles.
 * Vide pour m = n ; m = 0 et m > n ne sont pas définis (ErreurFormat K-5).
 */
export function preuveCoherence(feuilles, m) {
  if (!Array.isArray(feuilles)) throw new ErreurFormat("preuveCoherence : tableau de feuilles attendu", "K-5");
  const n = feuilles.length;
  if (!Number.isInteger(m) || m < 1 || m > n) throw new ErreurFormat(`preuveCoherence : m = ${m} hors de [1, ${n}]`, "K-5");
  if (m === n) return [];
  return sousPreuveCoherence(feuilles, m, 0, n, true);
}

/** Vrai si n est une puissance de deux (entier sûr). */
function estPuissanceDeDeux(n) {
  let p = 1;
  while (p < n) p *= 2;
  return p === n;
}

/**
 * Vérification d'une preuve de cohérence par l'algorithme de la RFC 9162
 * §2.1.4.2, tel que CT-1 §10.7 le reproduit : rend true si et seulement si
 * `path` a exactement la longueur attendue pour (first_size, second_size) et
 * mène de first_root à second_root. Entrées mal formées : false.
 */
export function verifierCoherence({ first_size, second_size, first_root, second_root, path }) {
  if (!estHex32(first_root) || !estHex32(second_root) || !Array.isArray(path) || !path.every(estHex32)) return false;
  if (!Number.isSafeInteger(first_size) || !Number.isSafeInteger(second_size)) return false;
  const m = first_size;
  const n = second_size;
  if (m < 1 || n < m) return false;
  if (m === n) return path.length === 0 && first_root === second_root;
  if (path.length === 0) return false;
  const chemin = estPuissanceDeDeux(m) ? [first_root, ...path] : path;
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = chemin[0];
  let sr = chemin[0];
  for (const h of chemin.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = noeudMerkle(h, fr);
      sr = noeudMerkle(h, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = noeudMerkle(sr, h);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return fr === first_root && sr === second_root && sn === 0;
}

/**
 * Le contenu de `consistency` de la partie points-de-controle.json (CT-1
 * §11.2) : preuve de cohérence des `tree_size` premières feuilles de la période
 * vers la racine du manifeste (toutes les feuilles).
 */
export function preuveCoherenceDossier(feuillesPeriode, tree_size) {
  return {
    version: VERSION_FORMAT,
    first_size: tree_size,
    second_size: feuillesPeriode.length,
    first_root: racineMerkle(feuillesPeriode.slice(0, tree_size)),
    second_root: racineMerkle(feuillesPeriode),
    path: preuveCoherence(feuillesPeriode, tree_size),
  };
}

// ---------------------------------------------------------------------------
// Manifeste de période (CT-1 §10)
// ---------------------------------------------------------------------------

/**
 * Construit le manifeste v0 d'une période : `hashes` sont les hash des
 * événements de la période dans l'ordre des seq (vide pour une période vide).
 */
export function construireManifeste({ org_id, journal_id, period_start, first_seq, hashes, prev_period_hash = HASH_NUL, recorder_key_id, nonce, generated_at }) {
  if (!Number.isSafeInteger(period_start) || period_start % DUREE_PERIODE !== 0) throw new ErreurFormat("period_start : heure UTC pleine en secondes UNIX attendue", "P-1");
  if (!Number.isSafeInteger(first_seq) || first_seq < 1) throw new ErreurFormat("first_seq : entier >= 1 attendu", "P-1");
  if (!estHex32(nonce)) throw new ErreurFormat("nonce : 32 octets hexadécimaux attendus", "P-1");
  const count = hashes.length;
  return {
    version: VERSION_FORMAT,
    org_id,
    journal_id,
    period_start,
    period_end: period_start + DUREE_PERIODE,
    first_seq,
    last_seq: first_seq + count - 1,
    count,
    root: racineMerkle(hashes),
    prev_period_hash,
    recorder_key_id,
    nonce,
    generated_at,
  };
}

/** Les événements d'une période : ceux dont period_start <= ts < period_end. */
export function evenementsDePeriode(evenements, period_start) {
  return evenements.filter((e) => dansPeriode(e.ts, period_start, period_start + DUREE_PERIODE));
}

/** periodHash = SHA-256(P_M || JCS(manifeste)). C'est ce que PeriodRegistry enregistre. */
export function hachageManifeste(manifeste) {
  return sha256(Buffer.concat([Buffer.from(PREFIXE_MANIFESTE, "utf8"), octetsJCS(manifeste)]));
}

function messageSignatureManifeste(manifeste) {
  return Buffer.concat([Buffer.from(PREFIXE_SIGNATURE_MANIFESTE, "utf8"), octetsJCS(manifeste)]);
}

/** Signature du manifeste par l'enregistreur : le contenu de manifeste.sig, porté à côté du manifeste. */
export function signerManifeste(manifeste, cle) {
  return {
    version: VERSION_FORMAT,
    period_hash: hachageManifeste(manifeste),
    recorder_key_id: manifeste.recorder_key_id,
    sig: signerEd25519(cle, messageSignatureManifeste(manifeste)),
  };
}

/** Vrai si manifesteSig.sig est valide sous la clé publique donnée. */
export function verifierSignatureManifeste(manifeste, manifesteSig, clePubliqueHex) {
  return verifierEd25519(clePubliqueHex, messageSignatureManifeste(manifeste), manifesteSig?.sig);
}

/**
 * Règles internes d'un manifeste (P-1, P-4) : period_end = period_start + 3600,
 * heure pleine, count = last_seq - first_seq + 1, racine nulle ssi count = 0.
 * Rend la liste des erreurs (vide si conforme).
 */
export function verifierManifeste(m) {
  const erreurs = [];
  if (!m || typeof m !== "object") return ["manifeste : objet attendu"];
  if (m.version !== VERSION_FORMAT) erreurs.push(`version ${m.version}, attendu ${VERSION_FORMAT}`);
  if (!Number.isSafeInteger(m.period_start) || m.period_start % DUREE_PERIODE !== 0) erreurs.push("period_start n'est pas une heure UTC pleine");
  if (m.period_end !== m.period_start + DUREE_PERIODE) erreurs.push(`period_end ${m.period_end} différent de period_start + 3600 (${m.period_start + DUREE_PERIODE})`);
  if (!Number.isSafeInteger(m.first_seq) || m.first_seq < 1) erreurs.push("first_seq doit être un entier >= 1");
  if (!Number.isSafeInteger(m.last_seq) || m.last_seq < m.first_seq - 1) erreurs.push("last_seq doit être >= first_seq - 1");
  if (m.count !== m.last_seq - m.first_seq + 1) erreurs.push(`count ${m.count} différent de last_seq - first_seq + 1 (${m.last_seq - m.first_seq + 1})`);
  if ((m.count === 0) !== (m.root === HASH_NUL)) erreurs.push(m.count === 0 ? "période vide à racine non nulle" : "période non vide à racine nulle");
  if (!estHex32(m.org_id) || m.org_id === HASH_NUL) erreurs.push("org_id invalide ou nul");
  if (!estHex32(m.journal_id) || m.journal_id === HASH_NUL) erreurs.push("journal_id invalide ou nul");
  if (!estHex32(m.prev_period_hash)) erreurs.push("prev_period_hash invalide");
  if (!estIdentifiantCle(m.recorder_key_id)) erreurs.push("recorder_key_id invalide");
  if (!estHex32(m.nonce)) erreurs.push("nonce invalide");
  if (!estHorodatage(m.generated_at)) erreurs.push("generated_at invalide");
  return erreurs;
}

/**
 * Continuité de deux manifestes consécutifs p puis q du même journal (CT-1 §10.3,
 * P-5) : q.period_start = p.period_end, q.first_seq = p.last_seq + 1,
 * q.prev_period_hash = periodHash(p). Rend { valide, erreurs }.
 */
export function verifierContinuiteManifestes(p, q) {
  const erreurs = [];
  if (p.org_id !== q.org_id || p.journal_id !== q.journal_id) erreurs.push("org_id ou journal_id différents : les manifestes ne sont pas du même journal");
  if (q.period_start !== p.period_end) erreurs.push(`discontinuité temporelle : period_start ${q.period_start} différent de period_end précédent ${p.period_end}`);
  if (q.first_seq !== p.last_seq + 1) erreurs.push(`discontinuité de séquence : first_seq ${q.first_seq} différent de last_seq précédent + 1 (${p.last_seq + 1})`);
  const attendu = hachageManifeste(p);
  if (q.prev_period_hash !== attendu) erreurs.push(`prev_period_hash ${q.prev_period_hash} différent du periodHash précédent ${attendu}`);
  return { valide: erreurs.length === 0, erreurs };
}

// ---------------------------------------------------------------------------
// Point de contrôle de la période en cours (CT-1 révision 0.3, §10.5 à §10.9)
// ---------------------------------------------------------------------------

/**
 * Construit un point de contrôle (sans signature) : `hashes` sont les hash des
 * événements de la période dans l'ordre des seq, `tree_size` le nombre
 * d'événements engagés (0 admis : racine nulle, last_seq = first_seq - 1 et
 * last_hash = `last_hash_journal`, hash du dernier événement avant la période,
 * ou 32 octets nuls si le journal est vide). Règles de CT-1 §10.5.
 */
export function construirePointDeControle({ org_id, journal_id, period_start, first_seq, hashes, tree_size, checkpoint_ts, prev_checkpoint_hash = HASH_NUL, key_id, last_hash_journal = HASH_NUL }) {
  if (!Number.isSafeInteger(period_start) || period_start < 0 || period_start % DUREE_PERIODE !== 0) throw new ErreurFormat("period_start : heure UTC pleine en secondes UNIX attendue", "K-1");
  if (!Number.isSafeInteger(first_seq) || first_seq < 1) throw new ErreurFormat("first_seq : entier >= 1 attendu", "K-1");
  if (!Array.isArray(hashes) || !hashes.every(estHex32)) throw new ErreurFormat("hashes : tableau de hash d'événements attendu", "K-1");
  if (!Number.isSafeInteger(tree_size) || tree_size < 0 || tree_size > hashes.length) throw new ErreurFormat(`tree_size ${tree_size} hors de [0, ${hashes.length}]`, "K-1");
  if (!estHorodatage(checkpoint_ts) || horodatagesHorsCalendrier([["/checkpoint_ts", checkpoint_ts]]).length) throw new ErreurFormat("checkpoint_ts : horodatage RFC 3339 UTC à la milliseconde attendu", "K-1");
  if (!estHex32(prev_checkpoint_hash)) throw new ErreurFormat("prev_checkpoint_hash : hex de 32 octets attendu", "K-1");
  if (!estIdentifiantCle(key_id)) throw new ErreurFormat("key_id : identifiant de clé attendu", "K-1");
  if (!estHex32(last_hash_journal)) throw new ErreurFormat("last_hash_journal : hex de 32 octets attendu", "K-1");
  return {
    version: VERSION_FORMAT,
    org_id,
    journal_id,
    period_start,
    tree_size,
    root: racineMerkle(hashes.slice(0, tree_size)),
    last_seq: first_seq + tree_size - 1,
    last_hash: tree_size > 0 ? hashes[tree_size - 1] : last_hash_journal,
    checkpoint_ts,
    prev_checkpoint_hash,
    key_id,
  };
}

/** K' : le point privé de sa clé sig (onze clés), dans l'ordre de présentation. */
export function corpsPointDeControle(point) {
  const corps = {};
  for (const k of CLES_POINT_DE_CONTROLE) if (k !== "sig" && point[k] !== undefined) poserMembre(corps, k, point[k]);
  for (const k of Object.keys(point ?? {})) if (k !== "sig" && !Object.hasOwn(corps, k)) poserMembre(corps, k, point[k]);
  return corps;
}

/** checkpointHash = SHA-256(P_K || JCS(K')) : l'empreinte que les ancres portent (CT-1 §10.6). */
export function hachagePointDeControle(point) {
  return sha256(Buffer.concat([Buffer.from(PREFIXE_POINT_DE_CONTROLE, "utf8"), octetsJCS(corpsPointDeControle(point))]));
}

function messageSignaturePointDeControle(point) {
  return Buffer.concat([Buffer.from(PREFIXE_SIGNATURE_POINT_DE_CONTROLE, "utf8"), octetsJCS(corpsPointDeControle(point))]);
}

/** Signe un point : rend { ...point, sig }, la signature étant portée dans l'objet. */
export function signerPointDeControle(point, cle) {
  return { ...corpsPointDeControle(point), sig: signerEd25519(cle, messageSignaturePointDeControle(point)) };
}

/** Vrai si point.sig est valide sous la clé publique donnée, sur P_SK || C_K. */
export function verifierSignaturePointDeControle(point, clePubliqueHex) {
  try {
    return verifierEd25519(clePubliqueHex, messageSignaturePointDeControle(point), point?.sig);
  } catch {
    return false;
  }
}

/**
 * Règles internes d'un point (schéma de CT-1 §10.5 et règle « racine nulle si
 * et seulement si tree_size = 0 ») : rend la liste des erreurs (vide si conforme).
 */
export function verifierPointDeControle(p) {
  const erreurs = [];
  if (p === null || typeof p !== "object" || Array.isArray(p)) return ["point : objet JSON attendu"];
  const cles = Object.keys(p).sort();
  const attendues = [...CLES_POINT_DE_CONTROLE].sort();
  if (!egalJSON(cles, attendues)) erreurs.push(`clés ${JSON.stringify(cles)}, attendues ${JSON.stringify(attendues)}`);
  if (p.version !== VERSION_FORMAT) erreurs.push(`version ${JSON.stringify(p.version)}, attendu ${VERSION_FORMAT}`);
  for (const k of ["org_id", "journal_id", "root", "last_hash", "prev_checkpoint_hash"]) if (!estHex32(p[k])) erreurs.push(`${k} : hex de 32 octets attendu`);
  if (!Number.isSafeInteger(p.period_start) || p.period_start < 0 || p.period_start % DUREE_PERIODE !== 0) erreurs.push("period_start : heure UTC pleine en secondes UNIX attendue");
  if (!Number.isSafeInteger(p.tree_size) || p.tree_size < 0) erreurs.push("tree_size : entier >= 0 attendu");
  if (!Number.isSafeInteger(p.last_seq) || p.last_seq < 0) erreurs.push("last_seq : entier >= 0 attendu");
  if (Number.isSafeInteger(p.tree_size) && estHex32(p.root) && (p.tree_size === 0) !== (p.root === HASH_NUL)) erreurs.push(p.tree_size === 0 ? "racine non nulle pour tree_size = 0" : "racine nulle pour tree_size > 0");
  if (!estHorodatage(p.checkpoint_ts)) erreurs.push("checkpoint_ts : horodatage RFC 3339 UTC à la milliseconde attendu");
  else erreurs.push(...horodatagesHorsCalendrier([["/checkpoint_ts", p.checkpoint_ts]]));
  if (!estIdentifiantCle(p.key_id)) erreurs.push("key_id : identifiant de clé attendu");
  if (typeof p.sig !== "string" || !/^0x[0-9a-f]{128}$/.test(p.sig)) erreurs.push("sig : hex de 64 octets attendu");
  return erreurs;
}

/**
 * Clé de l'enregistreur en vigueur pour un point (CT-1 §10.5, règle 5, règle
 * exacte de la révision 0.5). Quand l'événement de seq = last_seq est parmi
 * `evenements` : son new_key_id s'il est une rotation, sinon son
 * recorder_key_id. Sinon (last_seq = 0, journal encore vide, ou événement non
 * fourni) : la règle de la section 10.1 appliquée à `cles` (cles.json, tableau
 * de clés ou Map de normaliserCles) — la clé de plus grand valid_from
 * inférieur ou égal à `checkpoint_ts` (instants décodés), la dernière dans
 * l'ordre de keys en cas d'égalité. Rend null si aucune clé ne remplit la
 * condition, ou si `cles` ou `checkpoint_ts` manquent. Un événement de seq
 * inférieur à last_seq ne remplace jamais l'événement last_seq manquant.
 */
export function cleEnVigueurPoint(evenements, last_seq, { cles = null, checkpoint_ts = null } = {}) {
  const ev = Number.isSafeInteger(last_seq) && last_seq >= 1 ? (evenements ?? []).find((e) => estObjet(e) && e.seq === last_seq) : undefined;
  if (ev) return cleSuivanteAttendue(ev);
  if (!cles || typeof checkpoint_ts !== "string") return null;
  const t = msHorodatage(checkpoint_ts);
  if (Number.isNaN(t)) return null;
  const liste = cles instanceof Map ? [...cles.entries()].map(([key_id, k]) => ({ key_id, ...k })) : Array.isArray(cles) ? cles : Array.isArray(cles.keys) ? cles.keys : [];
  let choisie = null;
  let meilleur = -Infinity;
  for (const k of liste) {
    if (!estObjet(k) || typeof k.key_id !== "string") continue;
    const de = msHorodatage(k.valid_from);
    if (Number.isNaN(de) || de > t) continue;
    if (de >= meilleur) {
      meilleur = de;
      choisie = k.key_id;
    }
  }
  return choisie;
}

/**
 * Règles de série d'une période (CT-1 §10.5, règles 2 à 5 ; révision 0.5 pour
 * root, last_hash et la clé en vigueur quand des événements manquent), hors
 * dossier. `manifeste` : le manifeste de la période ; `evenements` : les
 * événements fournis (tout ou partie du journal) ; `cles` : cles.json (ou
 * { keys }, ou Map de normaliserCles), pour les signatures, la validité de la
 * clé à checkpoint_ts et la clé en vigueur quand l'événement last_seq manque.
 * Chaque règle est évaluée point par point. root (n >= 1) et last_hash
 * (last_seq >= 1) exigent les événements qu'elles nomment : un événement non
 * fourni rend la règle non évaluée pour ce point (piece_hors_dossier), un
 * événement fourni sans forme canonique aussi (prerequis_en_echec) ; jamais
 * violée, et 32 octets nuls ne remplacent jamais un événement manquant. Rend
 * { valide, erreurs, rules_failed, rules_not_evaluated } : `erreurs` (messages)
 * et `rules_failed` (noms de règles, ordre de première apparition) pour les
 * règles violées ; `rules_not_evaluated`, liste de { rule, reason } distincts ;
 * `valide` exige les deux listes vides.
 */
export const REGLES_SERIE = Object.freeze(["chainage", "tree_size_decroissant", "checkpoint_ts_decroissant", "period_start", "root", "last_seq", "last_hash", "dernier_point", "cle_en_vigueur", "signature", "validite_cle"]);
const RAISONS_SERIE = ["prerequis_en_echec", "piece_hors_dossier"];

export function verifierSeriePointsDeControle(points, manifeste, { evenements = null, cles = null, schemas = null } = {}) {
  const ecarts = [];
  const nonEvaluees = [];
  const ecart = (regle, message) => ecarts.push({ regle, message });
  const nonEvaluee = (rule, reason) => {
    if (!nonEvaluees.some((x) => x.rule === rule && x.reason === reason)) nonEvaluees.push({ rule, reason });
  };
  // Révision 0.5 : une entrée par règle violée, une par couple (règle, raison), dans l'ordre des noms de
  // règle de CT-1 §10.5, puis prerequis_en_echec avant piece_hors_dossier ; une règle violée pour un point
  // n'est pas aussi non évaluée pour lui (elle peut l'être pour un autre point).
  const fin = () => {
    const rules_failed = REGLES_SERIE.filter((r) => ecarts.some((e) => e.regle === r));
    const rules_not_evaluated = [...nonEvaluees].sort((a, b) => REGLES_SERIE.indexOf(a.rule) - REGLES_SERIE.indexOf(b.rule) || RAISONS_SERIE.indexOf(a.reason) - RAISONS_SERIE.indexOf(b.reason));
    return { valide: ecarts.length === 0 && nonEvaluees.length === 0, erreurs: ecarts.map((e) => e.message), rules_failed, rules_not_evaluated };
  };
  if (!Array.isArray(points) || points.length === 0) {
    ecart("dernier_point", "série vide");
    return fin();
  }
  // cles.json (révision 0.5) : signature, validite_cle et, quand l'événement last_seq n'est pas fourni,
  // cle_en_vigueur le lisent ; absent : non évaluées (piece_hors_dossier) ; qui ne passe pas la première
  // partie de E-8 sans référence à un événement : non évaluées (prerequis_en_echec) ; jamais violées alors.
  let raisonCles = null;
  if (cles === null || cles === undefined) raisonCles = "piece_hors_dossier";
  else if (!(cles instanceof Map) && verifierClesJournal(Array.isArray(cles) ? { keys: cles } : cles, { schemas }).length) raisonCles = "prerequis_en_echec";
  const jeu = raisonCles ? null : cles instanceof Map ? cles : normaliserCles(cles);
  // Événements fournis, par seq (le premier en cas de doublon), avec leur hash recalculé (null : sans forme canonique).
  const fournis = new Map();
  for (const e of Array.isArray(evenements) ? evenements : []) {
    if (!estObjet(e) || !Number.isSafeInteger(e.seq) || fournis.has(e.seq)) continue;
    let h = null;
    try {
      h = hachageEvenement(e);
    } catch {
      h = null;
    }
    fournis.set(e.seq, { ev: e, h });
  }
  const listeEvenements = [...fournis.values()].map((x) => x.ev);
  let precedent = null;
  points.forEach((p, i) => {
    const ou = `point[${i}]`;
    const internes = verifierPointDeControle(p);
    if (internes.length) {
      for (const m of internes) ecart(/racine/.test(m) ? "root" : "period_start", `${ou} : ${m}`);
      precedent = p;
      return;
    }
    if (p.org_id !== manifeste.org_id || p.journal_id !== manifeste.journal_id) ecart("period_start", `${ou} : org_id ou journal_id différents du manifeste`);
    if (p.period_start !== manifeste.period_start) ecart("period_start", `${ou} : period_start ${p.period_start} différent de celui du manifeste ${manifeste.period_start}`);
    if (p.tree_size > manifeste.count) ecart("last_seq", `${ou} : tree_size ${p.tree_size} supérieur à count ${manifeste.count}`);
    if (p.last_seq !== manifeste.first_seq + p.tree_size - 1) ecart("last_seq", `${ou} : last_seq ${p.last_seq} différent de first_seq + tree_size - 1 (${manifeste.first_seq + p.tree_size - 1})`);
    if (Math.floor(msHorodatage(p.checkpoint_ts) / 1000) < manifeste.period_start) ecart("period_start", `${ou} : checkpoint_ts ${p.checkpoint_ts} antérieur à period_start`);
    const attenduPrev = precedent ? hachagePointDeControle(precedent) : HASH_NUL;
    if (p.prev_checkpoint_hash !== attenduPrev) ecart("chainage", `${ou} : prev_checkpoint_hash ${p.prev_checkpoint_hash} différent de ${precedent ? "checkpointHash du point précédent " + attenduPrev : "32 octets nuls (premier point de la période)"}`);
    if (precedent) {
      if (p.tree_size < precedent.tree_size) ecart("tree_size_decroissant", `${ou} : tree_size ${p.tree_size} décroît (précédent ${precedent.tree_size})`);
      if (msHorodatage(p.checkpoint_ts) < msHorodatage(precedent.checkpoint_ts)) ecart("checkpoint_ts_decroissant", `${ou} : checkpoint_ts ${p.checkpoint_ts} antérieur au précédent ${precedent.checkpoint_ts}`);
    }
    // root : n = 0, 32 octets nuls (règle interne du point) ; n >= 1, les événements first_seq .. first_seq + n - 1.
    if (p.tree_size >= 1) {
      // Les événements first_seq à first_seq + n − 1, même au-delà de count (la règle last_seq porte cet écart) ;
      // au plus jusqu'au plus grand seq fourni, les suivants manquant de toute façon.
      const derniere = manifeste.first_seq + p.tree_size - 1;
      const borne = Math.min(derniere, fournis.size ? Math.max(...fournis.keys()) : manifeste.first_seq - 1);
      const lus = [];
      for (let s = manifeste.first_seq; s <= borne; s++) lus.push(fournis.get(s));
      const manque = borne < derniere || lus.some((x) => x === undefined);
      if (lus.some((x) => x !== undefined && x.h === null)) nonEvaluee("root", "prerequis_en_echec");
      else if (manque) nonEvaluee("root", "piece_hors_dossier");
      else {
        const root = racineMerkle(lus.map((x) => x.h));
        if (p.root !== root) ecart("root", `${ou} : root ${p.root} différent de la racine recalculée ${root}`);
      }
    }
    // last_hash : last_seq = 0, 32 octets nuls ; sinon l'événement last_seq, même quand il appartient à la période précédente (n = 0).
    if (p.last_seq === 0) {
      if (p.last_hash !== HASH_NUL) ecart("last_hash", `${ou} : last_hash ${p.last_hash} différent de 32 octets nuls (last_seq = 0, journal vide)`);
    } else {
      const cible = fournis.get(p.last_seq);
      if (!cible) nonEvaluee("last_hash", "piece_hors_dossier");
      else if (cible.h === null) nonEvaluee("last_hash", "prerequis_en_echec");
      else if (p.last_hash !== cible.h) ecart("last_hash", `${ou} : last_hash ${p.last_hash} différent du hash de l'événement ${p.last_seq} (${cible.h})`);
    }
    if ((p.last_seq >= 1 && fournis.has(p.last_seq)) || jeu) {
      const attendue = cleEnVigueurPoint(listeEvenements, p.last_seq, { cles: jeu, checkpoint_ts: p.checkpoint_ts });
      if (attendue === null) ecart("cle_en_vigueur", `${ou} : key_id ${p.key_id}, aucune clé en vigueur à ${p.checkpoint_ts}`);
      else if (p.key_id !== attendue) ecart("cle_en_vigueur", `${ou} : key_id ${p.key_id}, clé en vigueur attendue ${attendue}`);
    } else nonEvaluee("cle_en_vigueur", raisonCles);
    if (!jeu) {
      nonEvaluee("signature", raisonCles);
      nonEvaluee("validite_cle", raisonCles);
    } else {
      const cle = jeu.get(p.key_id);
      if (!cle) ecart("signature", `${ou} : clé ${p.key_id} absente du jeu de clés`);
      else {
        if (!verifierSignaturePointDeControle(p, cle.public_key)) ecart("signature", `${ou} : signature invalide sous ${p.key_id}`);
        const t = msHorodatage(p.checkpoint_ts);
        const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
        const a = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
        if (!(t >= de && t <= a)) ecart("validite_cle", `${ou} : checkpoint_ts ${p.checkpoint_ts} hors de la validité de la clé ${p.key_id}`);
      }
    }
    precedent = p;
  });
  const dernier = points[points.length - 1];
  if (estObjet(dernier)) {
    if (dernier.tree_size !== manifeste.count) ecart("dernier_point", `dernier point : tree_size ${dernier.tree_size} différent de count ${manifeste.count}`);
    if (dernier.root !== manifeste.root) ecart("dernier_point", `dernier point : root ${dernier.root} différent de celui du manifeste`);
    if (dernier.last_seq !== manifeste.last_seq) ecart("dernier_point", `dernier point : last_seq ${dernier.last_seq} différent de celui du manifeste ${manifeste.last_seq}`);
  }
  return fin();
}

/**
 * Le point couvrant d'un événement d'indice leaf_index (CT-1 §11.2 ; CT-5
 * EX-10.2) parmi les points de tree_size strictement supérieur à leaf_index,
 * dans cet ordre de préférence : (1) un point qui porte un jeton RFC 3161
 * promu ; (2) à défaut, une preuve OpenTimestamps complète ; (3) à défaut, une
 * ancre au registre ; (4) à défaut, un point sans ancre. À rang égal, le plus
 * petit tree_size, puis le premier de la série (plus petit checkpoint_ts).
 * `ancres` (facultatif) : Map ou objet indexé par checkpointHash, valeurs
 * { rfc3161, ots, registry } ; `rfc3161` et `registry` sont des booléens ;
 * `ots` est soit `true` (preuve complète, jugée par l'appelant), soit les octets
 * du fichier .ots (ou { proof: base64 }), auquel cas la preuve ne compte que si
 * elle est complète : lisible et porteuse d'une attestation Bitcoin (CT-5
 * EX-10.2, EX-6.7 ; une preuve en attente ne donne pas le rang (2)). Sans
 * `ancres`, tous les points sont de rang (4) et le choix est le point de plus
 * petit tree_size, le premier de la série à tree_size égal. null si aucun point
 * ne couvre l'indice.
 */
export function choisirPointCouvrant(points, leaf_index, ancres = null) {
  const rang = (p) => {
    if (!ancres) return 3;
    const h = typeof p.checkpoint_hash === "string" ? p.checkpoint_hash : hachagePointDeControle(p);
    const a = (ancres instanceof Map ? ancres.get(h) : ancres[h]) ?? {};
    return a.rfc3161 ? 0 : preuveOtsComplete(a.ots) ? 1 : a.registry ? 2 : 3;
  };
  let choisi = null;
  let rangChoisi = Infinity;
  for (const p of points ?? []) {
    if (!estObjet(p) || !Number.isSafeInteger(p.tree_size) || p.tree_size <= leaf_index) continue;
    const r = rang(p);
    if (!choisi || r < rangChoisi || (r === rangChoisi && p.tree_size < choisi.tree_size)) {
      choisi = p;
      rangChoisi = r;
    }
  }
  return choisi;
}

/**
 * Une preuve .ots « complète » au sens de CT-5 EX-10.2 et EX-6.7 : `true`
 * (jugement de l'appelant), ou des octets (Buffer, Uint8Array ou { proof:
 * base64 }) qui se lisent (O-1) et portent au moins une attestation Bitcoin.
 * Une preuve en attente, illisible ou d'une autre forme ne compte pas.
 */
function preuveOtsComplete(v) {
  if (v === true) return true;
  if (!v) return false;
  let octets = null;
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) octets = Buffer.from(v);
  else if (estObjet(v) && typeof v.proof === "string") octets = Buffer.from(v.proof, "base64");
  else return false;
  try {
    return O.executer(O.lireOts(octets)).attestations.some((a) => a.genre === "bitcoin");
  } catch (err) {
    if (err instanceof O.ErreurOts) return false;
    throw err;
  }
}

/** Empreinte de l'ancre d'un point au registre : keccak256(org_id || journal_id || checkpointHash), 96 octets (CT-1 §10.6). */
export function empreinteAncrePoint(org_id, journal_id, checkpoint_hash) {
  return keccak256(solidityPacked(["bytes32", "bytes32", "bytes32"], [org_id, journal_id, checkpoint_hash]));
}

const enBase64 = (v, cle) => {
  if (v === null || v === undefined) return null;
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return { [cle]: Buffer.from(v).toString("base64") };
  if (estObjet(v) && typeof v[cle] === "string") return { [cle]: v[cle] };
  throw new ErreurFormat(`ancre ${cle} : octets ou { ${cle}: base64 } attendus`, "K-1");
};

/**
 * La partie points-de-controle.json (CT-1 §11.2) pour un point signé :
 * `feuillesPeriode` sont les hash des événements de la période dans l'ordre des
 * seq ; `anchors` : { rfc3161: octets DER | { token } | null, registry: objet |
 * null, ots: octets .ots | { proof } | null }.
 */
export function construirePartiePointsDeControle({ point, feuillesPeriode, anchors = {} }) {
  if (!estObjet(point) || typeof point.sig !== "string") throw new ErreurFormat("point signé attendu", "K-1");
  if (!Number.isSafeInteger(point.tree_size) || point.tree_size < 1 || point.tree_size > feuillesPeriode.length) throw new ErreurFormat(`tree_size ${point.tree_size} hors de [1, ${feuillesPeriode.length}]`, "K-1");
  return {
    version: VERSION_FORMAT,
    checkpoint: point,
    checkpoint_hash: hachagePointDeControle(point),
    consistency: preuveCoherenceDossier(feuillesPeriode, point.tree_size),
    anchors: {
      rfc3161: enBase64(anchors.rfc3161, "token"),
      registry: anchors.registry ?? null,
      ots: enBase64(anchors.ots, "proof"),
    },
  };
}

// ---------------------------------------------------------------------------
// Validation contre les schémas JSON (draft 2020-12, sous-ensemble employé par spec/schemas)
// ---------------------------------------------------------------------------

/** Registre de schémas : objet $id -> schéma, à partir d'une liste de documents de schéma. */
export function registreSchemas(documents) {
  const registre = {};
  for (const d of documents) {
    if (!d || typeof d.$id !== "string") throw new ErreurFormat("schéma sans $id", "D-1");
    registre[d.$id] = d;
  }
  return registre;
}

function typeJSON(v, t) {
  switch (t) {
    case "null": return v === null;
    case "boolean": return typeof v === "boolean";
    case "string": return typeof v === "string";
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "array": return Array.isArray(v);
    case "object": return v !== null && typeof v === "object" && !Array.isArray(v);
    default: return false;
  }
}

function resoudreRef(ref, racine, registre) {
  const idx = ref.indexOf("#");
  const base = idx === -1 ? ref : ref.slice(0, idx);
  const fragment = idx === -1 ? "" : ref.slice(idx + 1);
  let doc = racine;
  if (base) {
    doc = registre[base];
    if (!doc) throw new ErreurFormat(`schéma référencé inconnu : ${base}`, "D-1");
  }
  let cible = doc;
  if (fragment) {
    for (const seg of fragment.split("/").slice(1)) {
      cible = cible?.[seg.replace(/~1/g, "/").replace(/~0/g, "~")];
      if (cible === undefined) throw new ErreurFormat(`référence de schéma introuvable : ${ref}`, "D-1");
    }
  }
  return { schema: cible, racine: doc };
}

function validerContre(v, s, racine, chemin, erreurs, registre) {
  const ou = chemin || "/";
  if (s === true) return;
  if (s === false) {
    erreurs.push({ chemin: ou, message: "aucune valeur admise ici" });
    return;
  }
  const conforme = (val, sch, rac) => {
    const e = [];
    validerContre(val, sch, rac, chemin, e, registre);
    return e.length === 0;
  };
  if (typeof s.$ref === "string") {
    const r = resoudreRef(s.$ref, racine, registre);
    validerContre(v, r.schema, r.racine, chemin, erreurs, registre);
  }
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => typeJSON(v, t))) erreurs.push({ chemin: ou, message: `type ${types.join(" ou ")} attendu` });
  }
  if ("const" in s && !egalJSON(v, s.const)) erreurs.push({ chemin: ou, message: `valeur constante ${JSON.stringify(s.const)} attendue` });
  if (Array.isArray(s.enum) && !s.enum.some((e) => egalJSON(v, e))) erreurs.push({ chemin: ou, message: `valeur hors de l'énumération ${JSON.stringify(s.enum)}` });
  if (typeof v === "string") {
    if (typeof s.pattern === "string" && !new RegExp(s.pattern, "u").test(v)) erreurs.push({ chemin: ou, message: `ne respecte pas le motif ${s.pattern}` });
    const longueur = [...v].length;
    if (typeof s.minLength === "number" && longueur < s.minLength) erreurs.push({ chemin: ou, message: `chaîne de moins de ${s.minLength} caractère(s)` });
    if (typeof s.maxLength === "number" && longueur > s.maxLength) erreurs.push({ chemin: ou, message: `chaîne de plus de ${s.maxLength} caractères` });
  }
  if (typeof v === "number") {
    if (typeof s.minimum === "number" && v < s.minimum) erreurs.push({ chemin: ou, message: `inférieur au minimum ${s.minimum}` });
    if (typeof s.maximum === "number" && v > s.maximum) erreurs.push({ chemin: ou, message: `supérieur au maximum ${s.maximum}` });
    if (typeof s.multipleOf === "number" && v % s.multipleOf !== 0) erreurs.push({ chemin: ou, message: `n'est pas un multiple de ${s.multipleOf}` });
  }
  if (typeJSON(v, "object")) {
    if (Array.isArray(s.required)) for (const k of s.required) if (!Object.hasOwn(v, k)) erreurs.push({ chemin: ou, message: `membre obligatoire absent : ${k}` });
    // propertyNames et minProperties : employés par les schémas de CT-2 (configuration, politique de rédaction).
    if (typeof s.minProperties === "number" && Object.keys(v).length < s.minProperties) erreurs.push({ chemin: ou, message: `moins de ${s.minProperties} membre(s)` });
    if (s.propertyNames !== undefined) for (const k of Object.keys(v)) validerContre(k, s.propertyNames, racine, `${chemin}/${k}`, erreurs, registre);
    const proprietes = s.properties && typeof s.properties === "object" ? s.properties : {};
    for (const k of Object.keys(v)) {
      if (Object.hasOwn(proprietes, k)) validerContre(v[k], proprietes[k], racine, `${chemin}/${k}`, erreurs, registre);
      else if (s.additionalProperties === false) erreurs.push({ chemin: `${chemin}/${k}`, message: "membre non admis" });
      else if (s.additionalProperties && typeof s.additionalProperties === "object") validerContre(v[k], s.additionalProperties, racine, `${chemin}/${k}`, erreurs, registre);
    }
  }
  if (Array.isArray(v)) {
    const prefixe = Array.isArray(s.prefixItems) ? s.prefixItems : [];
    v.forEach((el, i) => {
      if (i < prefixe.length) validerContre(el, prefixe[i], racine, `${chemin}/${i}`, erreurs, registre);
      else if (s.items !== undefined) validerContre(el, s.items, racine, `${chemin}/${i}`, erreurs, registre);
    });
    if (typeof s.minItems === "number" && v.length < s.minItems) erreurs.push({ chemin: ou, message: `moins de ${s.minItems} élément(s)` });
    if (typeof s.maxItems === "number" && v.length > s.maxItems) erreurs.push({ chemin: ou, message: `plus de ${s.maxItems} élément(s)` });
    if (s.uniqueItems === true) {
      // En O(n) par la forme canonique de chaque élément (les tableaux admis vont jusqu'à 65535 éléments).
      const vus = new Map();
      v.forEach((el, i) => {
        let k;
        try {
          k = canonicaliserJCS(el);
        } catch {
          k = "\u0000" + JSON.stringify(el);
        }
        if (vus.has(k)) erreurs.push({ chemin: ou, message: `éléments ${vus.get(k)} et ${i} identiques` });
        else vus.set(k, i);
      });
    }
  }
  if (Array.isArray(s.allOf)) s.allOf.forEach((sub) => validerContre(v, sub, racine, chemin, erreurs, registre));
  if (Array.isArray(s.anyOf) && !s.anyOf.some((sub) => conforme(v, sub, racine))) erreurs.push({ chemin: ou, message: "aucune des variantes anyOf n'est satisfaite" });
  if (Array.isArray(s.oneOf)) {
    const nb = s.oneOf.filter((sub) => conforme(v, sub, racine)).length;
    if (nb !== 1) erreurs.push({ chemin: ou, message: `exactement une variante oneOf attendue, ${nb} satisfaite(s)` });
  }
  if (s.not !== undefined && conforme(v, s.not, racine)) erreurs.push({ chemin: ou, message: "valeur interdite (not)" });
  if (s.if !== undefined) {
    if (conforme(v, s.if, racine)) {
      if (s.then !== undefined) validerContre(v, s.then, racine, chemin, erreurs, registre);
    } else if (s.else !== undefined) {
      validerContre(v, s.else, racine, chemin, erreurs, registre);
    }
  }
}

/**
 * Valide `valeur` contre `schema` (un document de spec/schemas, ou l'un de ses
 * $defs par `fragment`, par exemple "#/$defs/chemin"). `registre` : voir
 * registreSchemas, requis pour les références croisées. Rend la liste des
 * erreurs { chemin, message }, vide si la valeur est conforme.
 */
export function validerSchema(valeur, schema, { registre = {}, fragment = "" } = {}) {
  const r = fragment ? resoudreRef(fragment, schema, registre) : { schema, racine: schema };
  const erreurs = [];
  validerContre(valeur, r.schema, r.racine, "", erreurs, registre);
  return erreurs;
}

/** Mots-clés de validation que validerContre applique (sous-ensemble fermé de JSON Schema 2020-12). */
export const MOTS_CLES_VALIDATION = Object.freeze(["$ref", "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum", "multipleOf", "required", "minProperties", "propertyNames", "properties", "additionalProperties", "prefixItems", "items", "minItems", "maxItems", "uniqueItems", "allOf", "anyOf", "oneOf", "not", "if", "then", "else"]);

/** Mots-clés d'annotation, sans effet sur la validation. */
const MOTS_CLES_ANNOTATION = new Set(["$id", "$schema", "$defs", "$comment", "title", "description", "examples", "default", "deprecated", "readOnly", "writeOnly"]);

/**
 * Inventaire d'un schéma : les mots-clés rencontrés hors du sous-ensemble que
 * validerContre applique et hors des annotations, avec leur chemin. Vide pour
 * un schéma que ce validateur applique en entier ; un mot-clé listé (contains,
 * maxProperties, format…) serait ignoré sans bruit par validerSchema et doit
 * être vérifié à part par l'appelant (CT-4 §7.2).
 */
export function motsClesHorsSousEnsemble(schema) {
  const hors = [];
  const connus = new Set(MOTS_CLES_VALIDATION);
  const parcourir = (s, chemin) => {
    if (Array.isArray(s)) {
      s.forEach((x, i) => parcourir(x, `${chemin}/${i}`));
      return;
    }
    if (!s || typeof s !== "object") return;
    for (const [k, v] of Object.entries(s)) {
      if (["properties", "$defs", "patternProperties"].includes(k) && v && typeof v === "object") {
        if (k === "patternProperties") hors.push({ chemin: `${chemin}/${k}`, motCle: k });
        for (const [nom, sous] of Object.entries(v)) parcourir(sous, `${chemin}/${k}/${nom}`);
        continue;
      }
      if (["const", "enum", "default", "examples", "required"].includes(k)) continue;
      if (!connus.has(k) && !MOTS_CLES_ANNOTATION.has(k)) hors.push({ chemin: `${chemin}/${k}`, motCle: k });
      if (v && typeof v === "object") parcourir(v, `${chemin}/${k}`);
    }
  };
  parcourir(schema, "#");
  return hors;
}

/** Résumé d'une liste d'erreurs de schéma, pour un détail de contrôle. */
function resumerErreurs(erreurs, max = 4) {
  const vues = erreurs.slice(0, max).map((e) => `${e.chemin} : ${e.message}`);
  return vues.join(" ; ") + (erreurs.length > max ? ` ; … (${erreurs.length} erreurs)` : "");
}

// ---------------------------------------------------------------------------
// Contrôles d'un événement pris seul (E-1 à E-11)
// ---------------------------------------------------------------------------

/**
 * Les blancs de la « chaîne non vide » de CT-1 §3 (révision 0.5) : propriété
 * Unicode White_Space et U+FEFF. U+0085 et U+FEFF y sont, à la différence de
 * String.prototype.trim (sans U+0085) et de strings.TrimSpace de Go (sans U+FEFF).
 */
const BLANCS_CT1 = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);
/** Chaîne non vide au sens de CT-1 §3 : une chaîne qui contient au moins un caractère qui n'est pas un blanc. */
export function estChaineNonVide(v) {
  if (typeof v !== "string") return false;
  for (const c of v) if (!BLANCS_CT1.has(c.codePointAt(0))) return true;
  return false;
}

/** Vrai si `v` est un entier JSON de l'intervalle sûr supérieur ou égal à 0. */
const entierNaturel = (v) => Number.isSafeInteger(v) && v >= 0;
/** Même forme canonique (CT-1 §4) ; faux si l'une des deux n'en a pas. */
function memeFormeCanonique(a, b) {
  try {
    return canonicaliserJCS(a) === canonicaliserJCS(b);
  } catch {
    return false;
  }
}

/**
 * Profondeur d'une valeur JSON déjà lue (CT-1 §4, règle 7) : objets et tableaux
 * imbriqués, la valeur comprise ; parcours itératif, sans récursion.
 */
export function profondeurValeur(valeur) {
  let max = 0;
  const pile = [[valeur, 1]];
  while (pile.length) {
    const [v, p] = pile.pop();
    if (v === null || typeof v !== "object") continue;
    if (p > max) max = p;
    for (const x of Array.isArray(v) ? v : Object.values(v)) if (x !== null && typeof x === "object") pile.push([x, p + 1]);
  }
  return max;
}

/** Effet unique d'une rotation (CT-1 §8, règle 4), pour un new_key_id lu dans l'annonce. */
const effetRotation = (new_key_id) => ({ system: "noortrace", action: "ecriture", object: `cle:${new_key_id}`, amount: null, currency: null });

/**
 * E-3 : la règle exacte de CT-1 §5.3 (révision 0.5, « Cohérence avec la
 * sorte »). Rend la liste des règles non tenues (vide si E-3 réussit). Une
 * valeur absente, ou d'un autre type que celui que la règle nomme, ne la tient
 * pas. `policy.rule` et `policy.ticket` relèvent du schéma (E-1) et
 * `approval.ticket = policy.ticket` de E-5 seule.
 */
export function regleE3(ev) {
  const erreurs = [];
  const ex = estObjet(ev?.execution) ? ev.execution : {};
  const outil = ex.tool;
  // Révision 0.5 (CT-1 §11.4, « Autres termes mal typés ») : execution.tool qui n'est pas une chaîne, la sorte ne se lit pas.
  if (typeof outil !== "string") return [`execution.tool ${JSON.stringify(outil) ?? "absent"} qui n'est pas une chaîne : sorte de l'événement illisible`];
  // Un nom en noortrace. hors des quatre noms réservés : échec, et aucune autre règle de E-3.
  if (estOutilReserve(outil) && !OUTILS_RESERVES.includes(outil)) return [`outil réservé inconnu : ${outil}`];
  const pol = estObjet(ev?.policy) ? ev.policy : {};
  const dec = pol.decision;
  const app = ev?.approval;
  const statut = ex.status;
  const effetsVides = Array.isArray(ev?.effects) && ev.effects.length === 0;
  const sortiesExecutee = () => {
    if (!estObjet(ex.result)) erreurs.push("execution.result doit être une référence");
    if (!entierNaturel(ex.duration_ms)) erreurs.push("execution.duration_ms doit être un entier >= 0");
    if (typeof ex.is_error !== "boolean") erreurs.push("execution.is_error doit être un booléen");
  };
  if (!estOutilReserve(outil)) {
    // Règle 1 : appel d'outil.
    if (!["autorise", "a_approuver", "refuse"].includes(dec)) erreurs.push(`policy.decision ${JSON.stringify(dec)} invalide pour un appel d'outil (autorise, a_approuver ou refuse)`);
    if (app !== null && dec !== "a_approuver") erreurs.push("approval non nul alors que policy.decision ne vaut pas a_approuver");
    if (statut === "retenue") {
      if (dec !== "a_approuver" || app !== null) erreurs.push("appel retenu : policy.decision a_approuver et approval nul attendus");
    } else if (statut === "executee") {
      if (!(dec === "autorise" || (dec === "a_approuver" && estObjet(app) && app.decision === "approuve"))) erreurs.push("appel exécuté : policy.decision autorise, ou a_approuver avec approval.decision approuve, attendus");
    } else if (statut === "refusee") {
      if (!(dec === "refuse" || (dec === "a_approuver" && estObjet(app) && (app.decision === "refuse" || app.decision === "expire")))) erreurs.push("appel refusé : policy.decision refuse, ou a_approuver avec approval.decision refuse ou expire, attendus");
    } else erreurs.push(`execution.status ${JSON.stringify(statut)} invalide pour un appel d'outil`);
    if (statut === "executee") sortiesExecutee();
    else if (statut === "retenue" || statut === "refusee") {
      if (ex.result !== null || ex.duration_ms !== null || ex.is_error !== null) erreurs.push(`appel ${statut} : execution.result, duration_ms et is_error doivent être null`);
      if (!effetsVides) erreurs.push(`appel ${statut} : effects doit être vide (un appel qui n'a pas été relayé n'a pas d'effet)`);
    }
    return erreurs;
  }
  if (dec !== "sans_objet") erreurs.push(`policy.decision doit valoir sans_objet pour ${outil}`);
  if (statut !== "executee") erreurs.push(`execution.status doit valoir executee pour ${outil}`);
  if (outil === OUTIL_MODELE) {
    // Règle 2 : échange avec le modèle.
    if (app !== null) erreurs.push("approval doit être null pour un échange avec le modèle");
    sortiesExecutee();
    return erreurs;
  }
  // Règle 3 : décision d'approbation, rotation de clé, changement de politique.
  if (ex.result !== null || ex.duration_ms !== null || ex.is_error !== null) erreurs.push(`execution.result, duration_ms et is_error doivent être null pour ${outil}`);
  if (ev?.intent !== null) erreurs.push(`intent doit être null pour ${outil}`);
  const aValeur = estObjet(ex.arguments) && Object.hasOwn(ex.arguments, "value");
  if (!aValeur) erreurs.push("execution.arguments doit porter un membre value (référence en ligne)");
  const val = aValeur ? ex.arguments.value : undefined;
  const lanceParEnregistreur = () => {
    if (!estObjet(ev?.delegation) || ev.delegation.launched_by !== "noortrace-enregistreur") erreurs.push(`delegation.launched_by doit valoir noortrace-enregistreur pour ${outil}`);
  };
  if (outil === OUTIL_APPROBATION) {
    if (!estObjet(app)) erreurs.push("approval doit être un objet pour une décision d'approbation");
    else if (aValeur && !memeFormeCanonique(val, objetApprobation(ev))) erreurs.push("execution.arguments.value différent de A = { decision, journal_id, org_id, request_hash, ticket } (forme canonique)");
    if (!effetsVides) erreurs.push("effects doit être vide pour une décision d'approbation");
  } else if (outil === OUTIL_ROTATION) {
    if (app !== null) erreurs.push("approval doit être null pour une rotation");
    lanceParEnregistreur();
    if (!estObjet(val) || typeof val.new_key_id !== "string") erreurs.push("effects d'une rotation : new_key_id introuvable dans execution.arguments.value");
    else if (!Array.isArray(ev?.effects) || ev.effects.length !== 1 || !memeFormeCanonique(ev.effects[0], effetRotation(val.new_key_id))) erreurs.push(`effects d'une rotation : exactement ${JSON.stringify([effetRotation(val.new_key_id)])}`);
  } else if (outil === OUTIL_POLITIQUE) {
    if (app !== null) erreurs.push("approval doit être null pour un changement de politique");
    lanceParEnregistreur();
    const longueur = typeof val?.policy_version === "string" ? [...val.policy_version].length : 0;
    if (!estObjet(val) || Object.keys(val).length !== 2 || longueur < 1 || longueur > 128 || !estHex32(val.policy_sha256)) erreurs.push("execution.arguments.value doit être { policy_version (chaîne de 1 à 128 caractères), policy_sha256 (32 octets) }, exactement");
  }
  return erreurs;
}

/**
 * Les contrôles E-1 à E-11 sur un événement pris seul. `schemas` : registre de
 * schémas (registreSchemas) ; sans registre, E-1 n'est pas exécuté. `cles` :
 * clés publiques (voir normaliserCles) ; sans clés, E-8, E-10 (clé annoncée) et
 * E-11 ne sont pas exécutés. `clesExploitables` (faux dans un dossier dont
 * cles.json est inexploitable, CT-1 §11.4) : E-8 et E-11 ne sont pas exécutées,
 * et E-10 ne l'est pas pour une rotation dont les autres règles tiennent.
 * Rend un objet id -> { ok, execute, detail }.
 */
export function controlesEvenement(ev, { schemas, cles, clesExploitables = true } = {}) {
  const r = {};
  const pose = (id, ok, detail = null) => (r[id] = { ok, execute: true, detail });
  const nonExecute = (id, detail) => (r[id] = { ok: null, execute: false, detail });
  const clesMap = clesExploitables ? normaliserCles(cles) : new Map();
  const SANS_CLES = "cles.json inexploitable (première partie de E-8)";

  // Événement d'un journal lu sans forme canonique (lireJournalJSON) : E-2 échoue, les autres ne s'exécutent pas (CT-1 §11.4, cas (d)).
  const defaut = defautFormeCanonique(ev);
  if (defaut) {
    for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"]) nonExecute(id, "événement sans forme canonique (E-2)");
    pose("E-2", false, defaut);
    return r;
  }

  if (schemas?.[ID_SCHEMA_EVENEMENT]) {
    const erreurs = validerSchema(ev, schemas[ID_SCHEMA_EVENEMENT], { registre: schemas });
    // CT-1 §3 et §11.4 (révision 0.5) : ts et approval.at dates existantes, org_id et journal_id non nuls, profondeur au plus 128.
    erreurs.push(...horodatagesHorsCalendrier([["/ts", ev?.ts], ["/approval/at", ev?.approval?.at]]));
    for (const k of ["org_id", "journal_id"]) if (ev?.[k] === HASH_NUL) erreurs.push({ chemin: `/${k}`, message: "32 octets nuls : identifiant refusé (CT-1 §3, révision 0.5)" });
    if (profondeurValeur(ev) > PROFONDEUR_JSON_MAX) erreurs.push({ chemin: "/", message: `profondeur au-delà de ${PROFONDEUR_JSON_MAX} (CT-1 §4, règle 7)` });
    pose("E-1", erreurs.length === 0, erreurs.length ? resumerErreurs(erreurs) : "conforme au schéma");
  } else {
    nonExecute("E-1", "aucun schéma fourni");
  }
  if (!ev || typeof ev !== "object" || Array.isArray(ev)) {
    for (const id of ["E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"]) nonExecute(id, "événement inexploitable (objet attendu)");
    return r;
  }

  let canon = null;
  try {
    canon = canonicaliserJCS(corpsEvenement(ev));
    pose("E-2", true, `forme canonique de ${Buffer.byteLength(canon, "utf8")} octets`);
  } catch (err) {
    pose("E-2", false, err.message);
  }

  const e3 = regleE3(ev);
  pose("E-3", e3.length === 0, e3.length ? e3.join(" ; ") : `sorte : ${estOutilReserve(ev.execution?.tool) ? ev.execution.tool : "appel d'outil"}`);

  const refs = referencesEvenement(ev);
  const redigees = refs.filter(({ ref }) => ref.redacted === true);
  const redaction = ev.policy?.redaction;
  const redactionNommee = estChaineNonVide(redaction);
  pose("E-4", redigees.length === 0 || redactionNommee, redigees.length === 0 ? "aucune référence rédigée" : redactionNommee ? `${redigees.length} référence(s) rédigée(s) par ${redaction}` : `référence(s) rédigée(s) (${redigees.map((x) => x.chemin).join(", ")}) sans policy.redaction qui soit une chaîne non vide`);

  const a = ev.approval;
  if (a === null || a === undefined) {
    pose("E-5", true, "aucune approbation liée");
  } else {
    const erreurs = [];
    const approvers = estObjet(a) ? a.approvers : undefined;
    const signatures = estObjet(a) ? a.signatures : undefined;
    if (!Array.isArray(approvers) || !Array.isArray(signatures) || approvers.length !== signatures.length) erreurs.push(`approvers (${Array.isArray(approvers) ? approvers.length : "pas un tableau"}) et signatures (${Array.isArray(signatures) ? signatures.length : "pas un tableau"}) de longueurs différentes`);
    const ticket = estObjet(a) ? a.ticket : undefined;
    if (typeof ticket !== "string" || ticket !== ev.policy?.ticket) erreurs.push(`approval.ticket ${JSON.stringify(ticket)} différent de policy.ticket ${JSON.stringify(ev.policy?.ticket)}`);
    pose("E-5", erreurs.length === 0, erreurs.length ? erreurs.join(" ; ") : `${approvers.length} signature(s), ticket ${ticket}`);
  }

  const e6 = refs.filter(({ ref }) => ref.value !== undefined).map(({ chemin, ref }) => ({ chemin, ...verifierReference(ref) })).filter((x) => !x.ok);
  pose("E-6", e6.length === 0, e6.length ? e6.map((x) => `${x.chemin} : ${x.raison}`).join(" ; ") : `${refs.filter(({ ref }) => ref.value !== undefined).length} référence(s) en ligne vérifiée(s)`);

  if (canon === null) {
    nonExecute("E-7", "forme canonique incalculable");
    nonExecute("E-8", "forme canonique incalculable");
  } else {
    const h = hachageEvenement(ev);
    pose("E-7", h === ev.hash, h === ev.hash ? `hash ${h}` : `hash recalculé ${h} différent de hash ${ev.hash}`);
    const cle = typeof ev.recorder_key_id === "string" ? clesMap.get(ev.recorder_key_id) : undefined;
    if (!clesExploitables) nonExecute("E-8", SANS_CLES);
    else if (clesMap.size === 0) nonExecute("E-8", "aucune clé publique fournie");
    else if (!cle) pose("E-8", false, `clé ${ev.recorder_key_id} absente de cles.json`);
    else {
      const ok = verifierSignatureEvenement(ev, cle.public_key);
      pose("E-8", ok, ok ? `signature valide sous ${ev.recorder_key_id}` : `signature invalide sous la clé ${ev.recorder_key_id} (${cle.public_key})`);
    }
  }

  // E-9 (révision 0.5) : chaque signature, une signature sans approbateur comprise ; approvers ou signatures qui n'est pas un tableau : échec.
  if (a === null || a === undefined) {
    pose("E-9", true, "aucune approbation liée");
  } else if (!estObjet(a) || !Array.isArray(a.approvers) || !Array.isArray(a.signatures)) {
    pose("E-9", false, "approvers ou signatures ne sont pas des tableaux");
  } else {
    const A = objetApprobation(ev);
    const erreurs = [];
    a.signatures.forEach((sig, i) => {
      if (i >= a.approvers.length) {
        erreurs.push(`signatures[${i}] sans approvers[${i}]`);
        return;
      }
      try {
        const res = verifierSignatureApprobation(A, sig, a.approvers[i]);
        if (!res.ok) erreurs.push(`signatures[${i}] : ${res.raison}`);
      } catch (err) {
        erreurs.push(`signatures[${i}] : ${err.message}`);
      }
    });
    pose("E-9", erreurs.length === 0, erreurs.length ? erreurs.join(" ; ") : `${a.signatures.length} signature(s) d'approbateur recouvrée(s) : ${a.approvers.join(", ")}`);
  }

  if (!estRotation(ev)) {
    pose("E-10", true, "pas une rotation");
  } else {
    const val = ev.execution?.arguments?.value;
    const erreurs = [];
    let comparerCles = false;
    if (!estObjet(val)) erreurs.push("annonce de rotation absente");
    else {
      if (val.old_key_id !== ev.recorder_key_id) erreurs.push(`old_key_id ${val.old_key_id} différent de recorder_key_id ${ev.recorder_key_id}`);
      if (typeof val.valid_from !== "string" || val.valid_from !== ev.ts) erreurs.push(`valid_from ${val.valid_from} différent de ts ${ev.ts}`);
      if (val.org_id !== ev.org_id || val.journal_id !== ev.journal_id) erreurs.push("org_id ou journal_id de l'annonce différents de l'enveloppe");
      if (typeof val.new_key_id !== "string" || val.new_key_id === val.old_key_id) erreurs.push(`new_key_id ${val.new_key_id} absent ou égal à old_key_id`);
      if (!verifierContresignatureRotation(val)) erreurs.push("counter_sig invalide sous new_public_key");
      comparerCles = true;
      if (clesMap.size > 0) {
        // CT-1 §8 règle 3 : cles.json annonce valid_from(nouvelle) = valid_to(ancienne) = ts de la rotation.
        const t = msHorodatage(ev.ts);
        const nouvelle = clesMap.get(val.new_key_id);
        if (!nouvelle) erreurs.push(`new_key_id ${val.new_key_id} absent de cles.json`);
        else {
          if (nouvelle.public_key !== val.new_public_key) erreurs.push(`new_public_key différent de la clé ${val.new_key_id} de cles.json`);
          if (nouvelle.valid_from !== null && (Number.isNaN(t) || msHorodatage(nouvelle.valid_from) !== t)) erreurs.push(`valid_from de ${val.new_key_id} dans cles.json (${nouvelle.valid_from}) différent du ts de la rotation (${ev.ts})`);
        }
        const ancienne = clesMap.get(val.old_key_id);
        if (ancienne && ancienne.valid_from !== null && (Number.isNaN(t) || ancienne.valid_to === null || msHorodatage(ancienne.valid_to) !== t)) erreurs.push(`valid_to de ${val.old_key_id} dans cles.json (${ancienne.valid_to}) différent du ts de la rotation (${ev.ts})`);
      }
    }
    if (erreurs.length) pose("E-10", false, erreurs.join(" ; "));
    else if (comparerCles && !clesExploitables) nonExecute("E-10", `${SANS_CLES} : comparaisons de la rotation à cles.json non faites`);
    else pose("E-10", true, `rotation ${val.old_key_id} -> ${val.new_key_id} contresignée`);
  }

  const cle = typeof ev.recorder_key_id === "string" ? clesMap.get(ev.recorder_key_id) : undefined;
  if (!clesExploitables) nonExecute("E-11", SANS_CLES);
  else if (clesMap.size === 0) nonExecute("E-11", "aucune clé publique fournie");
  else if (!cle) nonExecute("E-11", `clé ${ev.recorder_key_id} absente de cles.json (échec porté par E-8)`);
  else if (cle.valid_from === null && cle.valid_to === null) nonExecute("E-11", "aucune période de validité annoncée");
  else {
    const t = msHorodatage(ev.ts);
    const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
    const fin = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
    const ok = !Number.isNaN(t) && !Number.isNaN(de) && !Number.isNaN(fin) && t >= de && t <= fin;
    pose("E-11", ok, ok ? `ts ${ev.ts} dans la validité de ${ev.recorder_key_id}` : `ts ${ev.ts} hors de [${cle.valid_from ?? "-∞"}, ${cle.valid_to ?? "+∞"}] de la clé ${ev.recorder_key_id}`);
  }
  return r;
}

// ---------------------------------------------------------------------------
// Dossier de preuve (CT-1 §11)
// ---------------------------------------------------------------------------

/**
 * L'index dossier.json : les douze parties, sha256 des fichiers présents, raison
 * des absents. La treizième partie facultative points_de_controle (CT-1
 * révision 0.3) est ajoutée quand son fichier est fourni ou quand `raisons`
 * porte une raison d'absence pour elle ; sinon l'index garde douze parties.
 * La quatorzième, attestation_perimetre (révision 0.4), est ajoutée de même ;
 * elle n'est déclarée qu'après la treizième, qui est alors déclarée absente
 * avec la raison « aucun point de contrôle » si elle n'est pas fournie.
 */
export function indexDossier({ evenement, generated_at, fichiers, raisons = {} }) {
  const declaree = (p) => (fichiers[p.file] !== undefined && fichiers[p.file] !== null) || raisons[p.name] !== undefined;
  const avecAttestation = declaree(PARTIE_ATTESTATION_PERIMETRE);
  const declarees = avecAttestation
    ? [...PARTIES_DOSSIER, PARTIE_POINTS_DE_CONTROLE, PARTIE_ATTESTATION_PERIMETRE]
    : declaree(PARTIE_POINTS_DE_CONTROLE)
      ? [...PARTIES_DOSSIER, PARTIE_POINTS_DE_CONTROLE]
      : PARTIES_DOSSIER;
  const parts = declarees.map(({ name, file }) => {
    const contenu = fichiers[file];
    if (contenu !== undefined && contenu !== null) return { name, file, sha256: sha256(enOctets(contenu)), present: true, reason_if_absent: null };
    const raison = raisons[name] ?? (PARTIES_RESERVEES.includes(name) ? RAISON_HORS_PERIMETRE : name === "approbations" ? RAISON_AUCUNE_APPROBATION : name === PARTIE_POINTS_DE_CONTROLE.name ? RAISON_AUCUN_POINT : name === PARTIE_ATTESTATION_PERIMETRE.name ? RAISON_AUCUNE_ATTESTATION : "partie absente");
    return { name, file, sha256: null, present: false, reason_if_absent: raison };
  });
  return {
    version: VERSION_FORMAT,
    event: { seq: evenement.seq, hash: evenement.hash },
    org_id: evenement.org_id,
    journal_id: evenement.journal_id,
    generated_at,
    parts,
  };
}

/**
 * Assemble un dossier v0 pour `evenement` : rend { index, fichiers } où
 * `fichiers` associe chaque nom de fichier au texte à écrire (dossier.json
 * compris). `hashesPeriode` : les hash des événements de la période du
 * manifeste, dans l'ordre des seq. `cles` : { keys: [...] } ou tableau de clés.
 * `approbations` : { approver_set, events } quand l'événement porte une approbation.
 * `pointsDeControle` (CT-1 révision 0.3, facultatif) : la partie
 * points-de-controle.json (construirePartiePointsDeControle) ; sans elle et sans
 * raison `raisons.points_de_controle`, l'index garde douze parties.
 * `attestationPerimetre` (CT-1 révision 0.4, facultatif) : la partie
 * attestation-perimetre.json (objet, ou texte déjà écrit) ; avec elle, ou avec
 * une raison `raisons.attestation_perimetre`, l'index a quatorze parties.
 * Les parties réservées à CT-4 et CT-5 sont déclarées absentes.
 */
export function assemblerDossier({ evenement, previous = null, next = null, hashesPeriode, manifeste, manifesteSig, cles, approbations = null, pointsDeControle = null, attestationPerimetre = null, generated_at, raisons = {} }) {
  const chemin = preuveInclusion(hashesPeriode, evenement.seq - manifeste.first_seq);
  const fichiers = {
    "evenement.json": texteJSON(evenement),
    "voisins.json": texteJSON({ version: VERSION_FORMAT, previous, next }),
    "chemin.json": texteJSON(chemin),
    "manifeste.json": texteJSON(manifeste),
    "manifeste.sig": texteJSON(manifesteSig),
    "cles.json": texteJSON(Array.isArray(cles) ? { version: VERSION_FORMAT, org_id: evenement.org_id, journal_id: evenement.journal_id, keys: cles } : cles),
  };
  if (evenement.approval !== null) {
    if (!approbations) throw new ErreurFormat("assemblerDossier : approbations requises quand approval n'est pas null", "A-1");
    fichiers["approbations.json"] = texteJSON({
      version: VERSION_FORMAT,
      ticket: evenement.approval.ticket,
      request_hash: evenement.approval.request_hash,
      approver_set: approbations.approver_set,
      events: approbations.events,
    });
  }
  if (pointsDeControle) fichiers[PARTIE_POINTS_DE_CONTROLE.file] = texteJSON(pointsDeControle);
  if (attestationPerimetre !== null && attestationPerimetre !== undefined) fichiers[PARTIE_ATTESTATION_PERIMETRE.file] = typeof attestationPerimetre === "string" || Buffer.isBuffer(attestationPerimetre) ? attestationPerimetre : texteJSON(attestationPerimetre);
  const index = indexDossier({ evenement, generated_at, fichiers, raisons });
  return { index, fichiers: { "dossier.json": texteJSON(index), ...fichiers } };
}

/**
 * Recalcule l'index d'un dossier dont des fichiers ont changé (fichiers : nom
 * -> texte ou octets, dossier.json compris et ignoré). Les parties absentes et
 * leurs raisons sont reprises de l'index existant.
 */
export function reindexerDossier(fichiers) {
  const ancien = analyserJSONStrict(fichiers["dossier.json"]);
  const evenement = analyserJSONStrict(fichiers["evenement.json"]);
  const raisons = {};
  for (const p of ancien.parts ?? []) if (!p.present && p.reason_if_absent) raisons[p.name] = p.reason_if_absent;
  const sansIndex = { ...fichiers };
  delete sansIndex["dossier.json"];
  const index = indexDossier({ evenement, generated_at: ancien.generated_at, fichiers: sansIndex, raisons });
  return { index, fichiers: { "dossier.json": texteJSON(index), ...sansIndex } };
}

class Rapport {
  constructor() {
    this.controles = CONTROLES_DOSSIER.map((c) => ({ id: c.id, libelle: c.libelle, architecture: c.architecture, ok: null, execute: false, details: [] }));
    this.parId = new Map(this.controles.map((c) => [c.id, c]));
  }
  echec(id, detail) {
    const c = this.parId.get(id);
    c.execute = true;
    c.ok = false;
    c.details.push(detail);
  }
  succes(id, detail) {
    const c = this.parId.get(id);
    c.execute = true;
    if (c.ok === null) c.ok = true;
    if (detail) c.details.push(detail);
  }
  nonExecute(id, detail) {
    const c = this.parId.get(id);
    if (c.execute) return;
    c.ok = null;
    c.execute = false;
    c.details.push(detail);
  }
  resultat(id, ok, detail) {
    if (ok) this.succes(id, detail);
    else this.echec(id, detail);
  }
  /**
   * Statut d'une vérification depuis ses fautes et ses manques (CT-1 §11.4,
   * révision 0.5) : en échec dès qu'une faute est relevée sur ce qu'elle lit,
   * l'échec l'emportant sur un prérequis manquant ; sinon non exécutée si un
   * prérequis manque ; sinon réussie.
   */
  juger(id, fautes, manque, succes) {
    if (fautes.length) fautes.forEach((m) => this.echec(id, m));
    else if (manque) this.nonExecute(id, manque);
    else this.succes(id, succes);
  }
  statut(id) {
    const c = this.parId.get(id);
    return c.ok === false ? "echoue" : c.execute ? "reussi" : "non_execute";
  }
  /** Aucun contrôle en échec. La validité du dossier exige en plus qu'aucun contrôle ne soit non exécuté sans raison admise (voir terminer). */
  get sansEchec() {
    return this.controles.every((c) => c.ok !== false);
  }
}

/** Vrai si `v` est un objet JSON (ni null, ni tableau). */
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Décrit une valeur JSON pour un message d'erreur. */
const sorteJSON = (v) => (v === null ? "le littéral null" : Array.isArray(v) ? "un tableau" : typeof v);

/** Détails de non-exécution des vérifications K- (CT-1 §11.4) que CT-6 traduit en raisons. */
export const DETAIL_K_PARTIE_ABSENTE = "partie absente";
export const DETAIL_K6_HORS_DOSSIER = "événement last_seq hors du dossier";
export const DETAIL_K_ANCRE_NULLE = "ancre nulle : partie absente";
/**
 * Révision 0.5 (CT-1 §11.4, parties réservées ; CT-6 EX-4.2) : une vérification de CT-6 qu'un vérificateur
 * de CT-1 seul n'exécute pas est rapportée avec la raison prerequis_en_echec, seule raison non admise de la
 * liste fermée de CT-6 §6.2, et ce détail ; aucune autre valeur n'est employée.
 */
export const RAISON_VERIFICATION_CT6 = "prerequis_en_echec";
export const DETAIL_VERIFICATION_CT6 = "vérification de CT-6 non exécutée par ce vérificateur";
export const DETAIL_K_HORS_PERIMETRE = `${DETAIL_VERIFICATION_CT6} (${RAISON_VERIFICATION_CT6}, sans raison admise)`;
/** Détail de non-exécution de A-4 dont l'événement de demande n'est pas un voisin (raison admise, CT-1 §11.4). */
export const DETAIL_A4_HORS_DOSSIER = "événement de demande";
const IDS_K = ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"];
const IDS_E = ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"];
const MIO = 1024 * 1024;

/**
 * Limites de taille des fichiers d'un dossier (CT-1 §11.4, révision 0.5, qui
 * reprend CT-6 EX-4.13 à EX-4.15) : un fichier de taille égale à sa limite est
 * lu, un fichier plus grand ne l'est pas (cas (b)).
 */
export const LIMITES_DOSSIER = Object.freeze({
  "dossier.json": 1 * MIO,
  "evenement.json": 16 * MIO,
  "voisins.json": 16 * MIO,
  "chemin.json": 16 * MIO,
  "manifeste.json": 16 * MIO,
  "manifeste.sig": 16 * MIO,
  "cles.json": 16 * MIO,
  "approbations.json": 16 * MIO,
  "points-de-controle.json": 1 * MIO,
  "attestation-perimetre.json": 4 * MIO,
  "jeton-rfc3161.der": 64 * 1024,
  "preuve.ots": 256 * 1024,
  "registre.json": 64 * MIO,
  "certificat-commit.json": 64 * MIO,
  "validateurs.json": 1 * MIO,
});

/**
 * Les contrôles non exécutés qu'un dossier valide ne peut pas avoir (CT-1
 * §11.4) : tout contrôle non exécuté, sauf A-4 (événement de demande hors du
 * dossier), A-2 à A-4 quand `approval` est nul et approbations.json déclaré
 * absent avec la raison exacte « aucune approbation liée » (révision 0.5), K-
 * quand la partie points_de_controle est absente, K-6 pour l'événement
 * last_seq hors du dossier et K-7 à K-9 pour une ancre nulle.
 */
function nonExecutesBloquants(rapport, parts) {
  const points = parts.find((p) => p && p.name === PARTIE_POINTS_DE_CONTROLE.name);
  const pointsAbsents = !points || (points.present === false && estChaineNonVide(points.reason_if_absent));
  const admis = (c) => {
    const detail = c.details.join(" ; ");
    if (c.id.startsWith("K-")) {
      if (pointsAbsents) return true;
      if (c.id === "K-6") return detail.includes(DETAIL_K6_HORS_DOSSIER);
      if (["K-7", "K-8", "K-9"].includes(c.id)) return detail === DETAIL_K_ANCRE_NULLE;
      return false;
    }
    if (["A-2", "A-3", "A-4"].includes(c.id) && detail === RAISON_AUCUNE_APPROBATION) return true;
    if (c.id === "A-4") return detail.startsWith(DETAIL_A4_HORS_DOSSIER) && detail.includes("absent du dossier");
    return false;
  };
  return rapport.controles.filter((c) => !c.execute && !admis(c)).map((c) => c.id);
}

/**
 * Vérifie un dossier v0 (contrôles 1, 2, 3, 6, 7 de l'architecture, soit D-1 à
 * A-4 de CT-1 §11.4, et K-1 à K-9 de la partie facultative). `fichiers` : objet
 * nom de fichier -> octets ou texte, pour les fichiers ordinaires PRÉSENTS dans
 * le répertoire (un lien symbolique, un répertoire ou tout autre objet compte
 * comme absent : à l'appelant de ne pas le passer). `schemas` : registre des
 * schémas (evenement, manifeste, dossier ; point-de-controle et
 * attestation-perimetre quand ces parties sont déclarées présentes ;
 * registreSchemas). Lève DossierInutilisable si dossier.json manque ou n'est
 * pas du JSON (UTF-8 mal formé, marque d'ordre d'octets, syntaxe, profondeur
 * au-delà de 128 : CT-6 EX-4.12, EX-4.16).
 *
 * Règles de CT-1 §11.4, révision 0.5 :
 *
 * - `dossier.json` au-delà de 1 Mio, qui n'est pas un objet, contraire à son
 *   schéma ou dont generated_at n'est pas une date existante : D-1 échoue ;
 *   sans forme canonique (clé en double, nombre non entier) : E-2 échoue, D-1
 *   n'est pas exécutée ; dans ces cas rien d'autre n'est lu ni exécuté
 *   (`indexExploitable` faux dans le rapport) ;
 * - partie inexploitable (cas (a) à (e)) : (a) fichier manquant, D-2 échoue
 *   et le contrôle porteur n'est pas exécuté ; (b) au-delà de sa limite
 *   (LIMITES_DOSSIER, ou `inexploitables` de l'appelant pour un fichier non
 *   lu), D-2 ne compare pas son SHA-256 et le contrôle porteur échoue ; (c) pas
 *   du JSON ou plus profond que 128, et (e) pas un objet, le contrôle porteur
 *   échoue ; (d) sans forme canonique, E-2 échoue et le contrôle porteur n'est
 *   pas exécuté. Tout contrôle qui lit la partie n'est pas exécuté, sans raison
 *   admise, sauf s'il échoue sur ce qu'il lit des autres parties ;
 * - partie contraire à son schéma : le contrôle porteur échoue, la partie
 *   reste exploitable ; chaque relation dont un terme est absent, mal typé ou
 *   incalculable n'est pas tenue (échec) ; exceptions de cles.json (exploitable
 *   si et seulement si la première partie de E-8 réussit) et de
 *   points-de-controle.json (K-1 non réussie : K-2 à K-9 non exécutées) ;
 * - E-1 à E-11 sur chaque événement d'une partie exploitable (événement
 *   prouvé, voisins, décisions de approbations.json) : en échec si une échoue
 *   pour un événement ; sinon non exécutée si evenement.json est inexploitable
 *   ou si elle ne l'est pas pour un événement ; sinon réussie ;
 * - une partie réservée déclarée présente, ou une ancre non nulle du point,
 *   n'est pas vérifiée par cette bibliothèque (CT-6 le fait) : le dossier n'est
 *   jamais « valide » pour elle (`partiesNonVerifiees`, K-7 et K-9 non
 *   exécutées sans raison admise, K-8 en échec sur fingerprint ou doc_type,
 *   sinon non exécutée sans raison admise).
 *
 * `inexploitables` (facultatif, CT-6 EX-4.13) : Map nom de fichier -> motif,
 * pour les parties que l'appelant n'a pas lues (au-delà de leur limite) ;
 * `empreintes` : Map nom de fichier -> SHA-256 des octets complets calculé en
 * flux (attestation-perimetre.json, seule partie dont D-2 compare le SHA-256
 * au-delà de sa limite, CT-6 EX-4.15).
 *
 * Rend { valide, controles, nonExecutesBloquants, partiesNonVerifiees,
 * evenement, org_id, journal_id, partiesAbsentes, borne, attestation,
 * indexExploitable, parties } ; `parties` porte les valeurs exploitables lues
 * (null sinon) et l'état de chaque partie, pour le vérificateur de CT-6.
 *
 * Révision 0.4 : avec la quatorzième partie (attestation_perimetre) déclarée
 * présente, AT-1 à AT-7 sont exécutées par scripts/lib/securite.mjs et rendues
 * dans `attestation` ; elles ne figurent pas dans `controles` et ne rendent
 * jamais le dossier invalide (CT-6 EX-5.11) ; seule D-2 porte sur le fichier.
 */
export function verifierDossier(fichiers, { schemas, inexploitables = null, empreintes = null } = {}) {
  if (!schemas || !schemas[ID_SCHEMA_EVENEMENT] || !schemas[ID_SCHEMA_MANIFESTE] || !schemas[ID_SCHEMA_DOSSIER]) {
    throw new DossierInutilisable("les trois schémas (evenement, manifeste, dossier) sont requis pour vérifier un dossier");
  }
  const rapport = new Rapport();
  const brut = (nom) => (fichiers[nom] === undefined || fichiers[nom] === null ? null : enOctets(fichiers[nom]));
  const refus = (nom) => (inexploitables instanceof Map && inexploitables.has(nom) ? inexploitables.get(nom) : null);
  const nonLu = (nom) => refus(nom) !== null && !brut(nom);
  const limite = (nom) => LIMITES_DOSSIER[nom] ?? 16 * MIO;
  const tropGrand = (nom) => nonLu(nom) || (brut(nom) !== null && brut(nom).length > limite(nom));
  const toutNonExecute = (detail, sauf = []) => {
    for (const c of rapport.controles) if (!sauf.includes(c.id)) rapport.nonExecute(c.id, detail);
  };

  // dossier.json (CT-1 §11.4, révision 0.5 ; CT-6 EX-4.11 point 3, EX-4.12 point 2).
  const indexOctets = brut("dossier.json");
  if (!indexOctets && !nonLu("dossier.json")) throw new DossierInutilisable("dossier.json absent : le répertoire n'est pas un dossier de preuve");
  if (tropGrand("dossier.json")) {
    rapport.echec("D-1", `dossier.json : ${refus("dossier.json") ?? `fichier de ${indexOctets.length} octets`}, au-delà de la limite de ${limite("dossier.json")} octets ; rien n'est lu de l'index`);
    toutNonExecute("index inexploitable", ["D-1"]);
    return terminer(rapport, null, null, []);
  }
  let index;
  try {
    index = analyserJSONStrict(indexOctets, { profondeurMax: PROFONDEUR_JSON_MAX });
  } catch (err) {
    if (!(err instanceof ErreurJSON) || !err.canonique) throw new DossierInutilisable(`dossier.json illisible : ${err.message}`);
    rapport.echec("E-2", `dossier.json sans forme canonique : ${err.message} ; rien n'est lu de l'index`);
    toutNonExecute("index inexploitable", ["E-2"]);
    return terminer(rapport, null, null, []);
  }
  const erreursIndex = estObjet(index) ? validerSchema(index, schemas[ID_SCHEMA_DOSSIER], { registre: schemas }) : [{ chemin: "/", message: `objet JSON attendu, reçu ${sorteJSON(index)}` }];
  if (estObjet(index)) erreursIndex.push(...horodatagesHorsCalendrier([["/generated_at", index.generated_at]]));
  if (erreursIndex.length) {
    rapport.echec("D-1", `dossier.json : ${resumerErreurs(erreursIndex)} ; rien n'est lu de l'index`);
    toutNonExecute("index inexploitable", ["D-1"]);
    return terminer(rapport, null, null, []);
  }
  const parts = index.parts;
  const partie = (name) => parts.find((p) => p.name === name);
  // Le schéma fixe l'ordre : douze parties, puis la treizième (points_de_controle) et la quatorzième (attestation_perimetre).
  const partiesDeclarees = [...PARTIES_DOSSIER, PARTIE_POINTS_DE_CONTROLE, PARTIE_ATTESTATION_PERIMETRE].slice(0, parts.length);

  // D-2 : les fichiers ordinaires du répertoire contre l'index ; état de chaque partie.
  const etats = new Map(); // fichier -> "presente" | "manquante" | "trop_grande" | "absente"
  for (const { name, file } of partiesDeclarees) {
    const p = partie(name);
    const o = brut(file);
    if (p.present === true) {
      if (!o && !nonLu(file)) {
        rapport.echec("D-2", `${file} déclaré présent mais absent du répertoire`);
        etats.set(file, "manquante");
      } else if (tropGrand(file)) {
        etats.set(file, "trop_grande");
        // Au-delà de la limite, le SHA-256 n'est pas comparé (CT-6 EX-4.11, point 2), sauf pour attestation-perimetre.json (EX-4.15).
        if (file === PARTIE_ATTESTATION_PERIMETRE.file) {
          const h = o ? sha256(o) : empreintes instanceof Map ? empreintes.get(file) ?? null : null;
          if (h === null) rapport.echec("D-2", `${file} non lu (${refus(file)}) : SHA-256 non calculé`);
          else if (h !== p.sha256) rapport.echec("D-2", `${file} : SHA-256 ${h} différent de l'index ${p.sha256}`);
          else rapport.succes("D-2");
        }
      } else if (sha256(o) !== p.sha256) {
        rapport.echec("D-2", `${file} : SHA-256 ${sha256(o)} différent de l'index ${p.sha256}`);
        etats.set(file, "presente");
      } else {
        rapport.succes("D-2");
        etats.set(file, "presente");
      }
    } else {
      etats.set(file, "absente");
      if (o || nonLu(file)) rapport.echec("D-2", `${file} déclaré absent mais présent dans le répertoire`);
      else if (!estChaineNonVide(p.reason_if_absent)) rapport.echec("D-2", `${file} absent sans raison (raison qui n'est pas une chaîne non vide, CT-1 §3)`);
      else rapport.succes("D-2");
    }
  }

  // Lecture des parties JSON de CT-1 (cas (a) à (e)) : rend { valeur, etat } ;
  // etat « exploitable », « manquante » (cas (a), porteur non exécuté),
  // « inexploitable » (porteur en échec, ou E-2 en échec et porteur non exécuté), « absente ».
  const lire = (file, controle) => {
    const etat = etats.get(file);
    if (etat === undefined || etat === "absente") return { valeur: null, etat: "absente" };
    if (etat === "manquante") {
      rapport.nonExecute(controle, `${file} absent du répertoire`);
      return { valeur: null, etat: "manquante" };
    }
    if (etat === "trop_grande") {
      rapport.echec(controle, `${file} : ${refus(file) ?? `fichier de ${brut(file).length} octets`}, au-delà de la limite de ${limite(file)} octets ; la partie est inexploitable`);
      return { valeur: null, etat: "inexploitable" };
    }
    let valeur;
    try {
      valeur = analyserJSONStrict(brut(file), { profondeurMax: PROFONDEUR_JSON_MAX });
    } catch (err) {
      if (err instanceof ErreurJSON && err.canonique) {
        rapport.echec("E-2", `${file} sans forme canonique : ${err.message}`);
        rapport.nonExecute(controle, `${file} sans forme canonique (E-2) : la partie est inexploitable`);
      } else rapport.echec(controle, `${file} : ${err.message} ; la partie est inexploitable`);
      return { valeur: null, etat: "inexploitable" };
    }
    if (!estObjet(valeur)) {
      rapport.echec(controle, `${file} : objet JSON attendu, reçu ${sorteJSON(valeur)} ; la partie est inexploitable`);
      return { valeur: null, etat: "inexploitable" };
    }
    return { valeur, etat: "exploitable" };
  };
  const pEv = lire("evenement.json", "E-1");
  const pVoisins = lire("voisins.json", "C-1");
  const pChemin = lire("chemin.json", "M-2");
  const pManifeste = lire("manifeste.json", "P-1");
  const pSig = lire("manifeste.sig", "P-5");
  const pCles = lire("cles.json", "E-8");
  const pApprobations = lire("approbations.json", "A-1");
  const partiePoints = partie(PARTIE_POINTS_DE_CONTROLE.name);
  const pointsDeclaresPresents = Boolean(partiePoints && partiePoints.present === true);
  // Révision 0.3 : le schéma point-de-controle-v0 n'est exigé que pour vérifier la partie déclarée présente.
  if (pointsDeclaresPresents && !schemas[ID_SCHEMA_POINT_DE_CONTROLE]) throw new DossierInutilisable("le schéma point-de-controle est requis pour vérifier la partie points-de-controle.json (CT-1 révision 0.3)");
  const pPoints = pointsDeclaresPresents ? lire(PARTIE_POINTS_DE_CONTROLE.file, "K-1") : { valeur: null, etat: "absente" };

  const ev = pEv.valeur;
  const voisins = pVoisins.valeur;
  const chemin = pChemin.valeur;
  const manifeste = pManifeste.valeur;
  const manifesteSig = pSig.valeur;
  const clesDoc = pCles.valeur;
  const approbations = pApprobations.valeur;
  const SANS_EV = "evenement.json inexploitable";
  const hashRecalcule = (e) => {
    if (!estObjet(e)) return null;
    try {
      return hachageEvenement(e);
    } catch {
      return null;
    }
  };
  const hashEv = ev ? hashRecalcule(ev) : null;
  const entier = (v) => Number.isSafeInteger(v);

  // D-1 : relations de l'index à evenement.json (révision 0.5 : org_id et journal_id compris).
  {
    const f = [];
    if (ev) {
      if (index.event.seq !== ev.seq || index.event.hash !== ev.hash) f.push(`event de l'index (seq ${index.event.seq}, ${index.event.hash}) différent de evenement.json (seq ${JSON.stringify(ev.seq)}, ${JSON.stringify(ev.hash)})`);
      if (index.org_id !== ev.org_id || index.journal_id !== ev.journal_id) f.push("org_id ou journal_id de l'index différents de ceux de evenement.json");
    }
    rapport.juger("D-1", f, ev ? null : SANS_EV, "dossier.json conforme au schéma");
  }

  // E-8, première partie : cles.json (schéma, org_id et journal_id de l'événement prouvé, unicités, dates).
  let clesExploitables = false;
  if (clesDoc) {
    const f = validerSchema(clesDoc, schemas[ID_SCHEMA_DOSSIER], { registre: schemas, fragment: "#/$defs/cles" }).map((e) => `cles.json : ${e.chemin} : ${e.message}`);
    f.push(...verifierCles(clesDoc, ev).map((m) => `cles.json : ${m}`));
    if (f.length) f.forEach((m) => rapport.echec("E-8", m));
    clesExploitables = f.length === 0 && Boolean(ev);
  }
  const cles = clesExploitables ? normaliserCles(clesDoc) : new Map();

  // Enveloppe de voisins.json (C-1) et de approbations.json (A-1) ; schémas de chemin.json (M-2) et de manifeste.sig (P-5).
  if (voisins) {
    const clesV = Object.keys(voisins).sort();
    if (!egalJSON(clesV, ["next", "previous", "version"])) rapport.echec("C-1", `voisins.json : clés ${JSON.stringify(clesV)}, attendues ["next","previous","version"]`);
    if (voisins.version !== VERSION_FORMAT) rapport.echec("C-1", `voisins.json : version ${JSON.stringify(voisins.version)}, attendu ${VERSION_FORMAT}`);
  }
  const erreursSchema = (valeur, fragment, document = schemas[ID_SCHEMA_DOSSIER], filtre = () => true) => validerSchema(valeur, document, { registre: schemas, fragment }).filter(filtre);
  const schemaChemin = chemin ? erreursSchema(chemin, "#/$defs/chemin") : [];
  schemaChemin.forEach((e) => rapport.echec("M-2", `chemin.json : ${e.chemin} : ${e.message}`));
  if (manifesteSig) erreursSchema(manifesteSig, "#/$defs/manifeste_sig").forEach((e) => rapport.echec("P-5", `manifeste.sig : ${e.chemin} : ${e.message}`));
  if (approbations) erreursSchema(approbations, "#/$defs/approbations", schemas[ID_SCHEMA_DOSSIER], (e) => !/^\/events\/[0-9]+(\/|$)/.test(e.chemin)).forEach((e) => rapport.echec("A-1", `approbations.json : ${e.chemin} : ${e.message}`));

  // E-1 à E-11 sur chaque événement d'une partie exploitable.
  const roles = [];
  if (ev) roles.push({ role: "evenement", e: ev });
  if (voisins && voisins.previous !== null && voisins.previous !== undefined) roles.push({ role: "voisin précédent", e: voisins.previous });
  if (voisins && voisins.next !== null && voisins.next !== undefined) roles.push({ role: "voisin suivant", e: voisins.next });
  if (approbations && Array.isArray(approbations.events)) approbations.events.forEach((e, i) => roles.push({ role: `approbation[${i}]`, e }));
  const resultatsE = roles.map(({ role, e }) => ({ role, res: controlesEvenement(e, { schemas, cles: clesExploitables ? clesDoc : null, clesExploitables }) }));
  for (const id of IDS_E) {
    const echecs = resultatsE.filter(({ res }) => res[id]?.ok === false);
    if (echecs.length) {
      // Dans l'ordre des événements ; E-7 et E-8 gardent aussi le détail des événements où elles réussissent.
      for (const { role, res } of resultatsE) {
        if (res[id]?.ok === false) rapport.echec(id, `${role} : ${res[id].detail}`);
        else if (res[id]?.ok === true && (id === "E-7" || id === "E-8")) rapport.succes(id, `${role} : ${res[id].detail}`);
      }
      continue;
    }
    if (rapport.parId.get(id).ok === false) continue;
    const nonExec = resultatsE.find(({ res }) => !res[id]?.execute);
    if (!ev) rapport.nonExecute(id, nonExec ? `${SANS_EV} ; ${nonExec.role} : ${nonExec.res[id].detail}` : SANS_EV);
    else if (nonExec) rapport.nonExecute(id, `${nonExec.role} : ${nonExec.res[id].detail}`);
    else for (const { role, res } of resultatsE) rapport.succes(id, id === "E-7" || id === "E-8" ? `${role} : ${res[id].detail}` : null);
  }

  // C-1, C-2, C-3 : les voisins (les relations à terme absent, mal typé ou incalculable ne sont pas tenues).
  // Révision 0.5 (règle unique du voisin qui n'est pas un objet) : un membre previous ou next absent, ou ni
  // objet ni null, est un voisin qui n'est pas un objet ; les relations qui l'ont pour terme ne sont pas tenues.
  const avecVoisin = (nom) => Boolean(voisins) && voisins[nom] !== null;
  const SANS_VOISINS = pVoisins.etat === "manquante" ? "voisins.json absent du répertoire" : "voisins.json inexploitable";
  if (!voisins) {
    for (const id of ["C-1", "C-2", "C-3"]) rapport.nonExecute(id, SANS_VOISINS);
  } else {
    const prev = voisins.previous;
    const next = voisins.next;
    const c1 = [];
    const c2 = [];
    const c3 = [];
    for (const [nom, v] of [["previous", prev], ["next", next]]) {
      if (v === undefined) c1.push(`voisins.json : membre ${nom} absent : voisin qui n'est pas un objet`);
      else if (v !== null && !estObjet(v)) c1.push(`voisins.json : ${nom} doit être un événement ou null (${sorteJSON(v)})`);
    }
    // prev_hash nul si et seulement si seq = 1, pour chaque voisin (lu dans voisins.json seul).
    for (const [nom, v] of [["previous", prev], ["next", next]]) {
      if (!estObjet(v)) continue;
      if (!entier(v.seq)) c2.push(`${nom} : seq ${JSON.stringify(v.seq)} qui n'est pas un entier : origine non établie`);
      else if ((v.seq === 1) !== (v.prev_hash === HASH_NUL)) c2.push(`${nom} : prev_hash ${v.prev_hash === HASH_NUL ? "nul" : "non nul"} avec seq ${v.seq}`);
    }
    if (ev) {
      const seqOk = entier(ev.seq);
      const tEv = msHorodatage(ev.ts);
      if (!avecVoisin("previous")) {
        if (ev.seq !== 1) c1.push(`previous null alors que seq = ${JSON.stringify(ev.seq)}`);
      } else if (!estObjet(prev)) {
        c1.push("previous qui n'est pas un objet : relation de seq non tenue");
      } else {
        if (!seqOk || !entier(prev.seq) || prev.seq !== ev.seq - 1) c1.push(`previous.seq ${JSON.stringify(prev.seq)} différent de seq - 1 (seq ${JSON.stringify(ev.seq)})`);
        const t = msHorodatage(prev.ts);
        if (Number.isNaN(t) || Number.isNaN(tEv)) c1.push(`ts ${ev.ts} et previous.ts ${prev.ts} incomparables (date inexistante ou mal formée)`);
        else if (t > tEv) c1.push(`ts ${ev.ts} antérieur à previous.ts ${prev.ts}`);
      }
      if (avecVoisin("next") && !estObjet(next)) c1.push("next qui n'est pas un objet : relation de seq non tenue");
      if (avecVoisin("next") && estObjet(next)) {
        if (!seqOk || !entier(next.seq) || next.seq !== ev.seq + 1) c1.push(`next.seq ${JSON.stringify(next.seq)} différent de seq + 1 (seq ${JSON.stringify(ev.seq)})`);
        const t = msHorodatage(next.ts);
        if (Number.isNaN(t) || Number.isNaN(tEv)) c1.push(`next.ts ${next.ts} et ts ${ev.ts} incomparables (date inexistante ou mal formée)`);
        else if (t < tEv) c1.push(`next.ts ${next.ts} antérieur à ts ${ev.ts}`);
      }
      for (const [nom, v] of [["previous", prev], ["next", next]]) {
        if (avecVoisin(nom) && (!estObjet(v) || v.org_id !== ev.org_id || v.journal_id !== ev.journal_id)) c1.push(`${nom} : org_id ou journal_id différents`);
      }
      if (!seqOk) c2.push(`evenement : seq ${JSON.stringify(ev.seq)} qui n'est pas un entier : origine non établie`);
      else if ((ev.seq === 1) !== (ev.prev_hash === HASH_NUL)) c2.push(`evenement : prev_hash ${ev.prev_hash === HASH_NUL ? "nul" : "non nul"} avec seq ${ev.seq}`);
      if (avecVoisin("previous")) {
        const hp = hashRecalcule(prev);
        if (hp === null) c2.push("hash de previous incalculable : chaînage non établi");
        else if (ev.prev_hash !== hp) c2.push(`prev_hash ${ev.prev_hash} différent du hash recalculé de previous ${hp}`);
        if (!estObjet(prev) || ev.recorder_key_id !== cleSuivanteAttendue(prev)) c3.push(`recorder_key_id ${ev.recorder_key_id}, attendu ${estObjet(prev) ? cleSuivanteAttendue(prev) : "?"} d'après previous`);
      }
      if (avecVoisin("next")) {
        if (!estObjet(next) || next.prev_hash !== hashEv) c2.push(`next.prev_hash ${estObjet(next) ? next.prev_hash : "?"} différent du hash recalculé de l'événement ${hashEv}`);
        if (!estObjet(next) || next.recorder_key_id !== cleSuivanteAttendue(ev)) c3.push(`next.recorder_key_id ${estObjet(next) ? next.recorder_key_id : "?"}, attendu ${cleSuivanteAttendue(ev)}`);
      }
    }
    const p = estObjet(prev) ? prev : null;
    const n = estObjet(next) ? next : null;
    rapport.juger("C-1", c1, ev ? null : SANS_EV, `previous ${p ? "seq " + p.seq : "null"}, next ${n ? "seq " + n.seq : "null"}`);
    rapport.juger("C-2", c2, ev ? null : SANS_EV, "chaînage avec les voisins fournis");
    rapport.juger("C-3", c3, ev ? null : SANS_EV, ev ? `clé ${ev.recorder_key_id}${estRotation(ev) ? " puis " + cleSuivanteAttendue(ev) : ""}` : null);
  }

  // M-1, M-2, M-3 : le chemin.
  const SANS_CHEMIN = pChemin.etat === "manquante" ? "chemin.json absent du répertoire" : "chemin.json inexploitable";
  if (!chemin) {
    for (const id of ["M-1", "M-2", "M-3"]) rapport.nonExecute(id, SANS_CHEMIN);
  } else {
    const feuille = hashEv ? feuilleMerkle(hashEv) : null;
    rapport.juger("M-1", feuille && chemin.leaf_hash !== feuille ? [`leaf_hash ${chemin.leaf_hash} différent de SHA-256(0x00 || hash recalculé) ${feuille}`] : [], feuille ? null : SANS_EV, `leaf_hash ${feuille}`);
    let inclus = false;
    try {
      inclus = verifierInclusion(chemin);
    } catch {
      inclus = false;
    }
    if (schemaChemin.length === 0) rapport.resultat("M-2", inclus, inclus ? `chemin de ${chemin.path?.length} nœud(s) mène à la racine (indice ${chemin.leaf_index}, taille ${chemin.tree_size})` : "le chemin ne mène pas à chemin.root pour (leaf_index, tree_size), ou sa longueur est incorrecte");
    else if (!inclus) rapport.echec("M-2", "le chemin ne mène pas à chemin.root pour (leaf_index, tree_size), ou sa longueur est incorrecte");
    if (!manifeste) rapport.nonExecute("M-3", pManifeste.etat === "manquante" ? "manifeste.json absent du répertoire" : "manifeste.json inexploitable");
    else {
      const m3 = [];
      if (chemin.root !== manifeste.root) m3.push(`chemin.root ${chemin.root} différent de manifeste.root ${manifeste.root}`);
      if (!entier(chemin.tree_size) || chemin.tree_size !== manifeste.count) m3.push(`tree_size ${JSON.stringify(chemin.tree_size)} différent de count ${JSON.stringify(manifeste.count)}`);
      if (ev && (!entier(chemin.leaf_index) || !entier(ev.seq) || !entier(manifeste.first_seq) || chemin.leaf_index !== ev.seq - manifeste.first_seq)) m3.push(`leaf_index ${JSON.stringify(chemin.leaf_index)} différent de seq - first_seq (seq ${JSON.stringify(ev.seq)}, first_seq ${JSON.stringify(manifeste.first_seq)})`);
      rapport.juger("M-3", m3, ev ? null : SANS_EV, "chemin cohérent avec le manifeste");
    }
  }

  // P-1 à P-5 : le manifeste.
  const SANS_MANIFESTE = pManifeste.etat === "manquante" ? "manifeste.json absent du répertoire" : "manifeste.json inexploitable";
  if (!manifeste) {
    for (const id of ["P-1", "P-2", "P-3", "P-4"]) rapport.nonExecute(id, SANS_MANIFESTE);
    rapport.nonExecute("P-5", SANS_MANIFESTE);
  } else {
    const p1 = validerSchema(manifeste, schemas[ID_SCHEMA_MANIFESTE], { registre: schemas }).map((e) => `manifeste.json : ${e.chemin} : ${e.message}`);
    p1.push(...horodatagesHorsCalendrier([["/generated_at", manifeste.generated_at]]).map((e) => `manifeste.json : ${e.chemin} : ${e.message}`));
    p1.push(...verifierManifeste(manifeste).filter((m) => !m.includes("racine")));
    for (const k of ["org_id", "journal_id"]) if (manifeste[k] === HASH_NUL) p1.push(`${k} du manifeste : 32 octets nuls (CT-1 §3, révision 0.5)`);
    if (ev && (manifeste.org_id !== ev.org_id || manifeste.journal_id !== ev.journal_id)) p1.push("org_id ou journal_id différents de ceux de l'événement");
    rapport.juger("P-1", [...new Set(p1)], ev ? null : SANS_EV, `période [${manifeste.period_start}, ${manifeste.period_end}), seq ${manifeste.first_seq}..${manifeste.last_seq}`);
    if (ev) {
      const p2 = [];
      if (!entier(ev.seq) || !entier(manifeste.first_seq) || !entier(manifeste.last_seq) || !(manifeste.first_seq <= ev.seq && ev.seq <= manifeste.last_seq)) p2.push(`seq ${JSON.stringify(ev.seq)} hors de [${manifeste.first_seq}, ${manifeste.last_seq}]`);
      if (!entier(manifeste.period_start) || !entier(manifeste.period_end) || !dansPeriode(ev.ts, manifeste.period_start, manifeste.period_end)) p2.push(`ts ${ev.ts} hors de la période`);
      rapport.juger("P-2", p2, null, "événement dans la période");
    } else rapport.nonExecute("P-2", SANS_EV);
    if (voisins) {
      // P-3 : un voisin dans la période par seq y est aussi par ts ; un voisin hors
      // période est adjacent (first_seq - 1, ts < period_start ; last_seq + 1,
      // ts >= period_end), sinon le manifeste a tronqué sa période (CT-1 §7.2).
      const p3 = [];
      const bornesOk = entier(manifeste.first_seq) && entier(manifeste.last_seq) && entier(manifeste.period_start) && entier(manifeste.period_end);
      for (const [nom, v] of [["previous", voisins.previous], ["next", voisins.next]]) {
        if (v === null) continue;
        if (!estObjet(v) || !entier(v.seq) || !bornesOk) {
          p3.push(`${nom} : seq ou bornes du manifeste mal typés : appartenance à la période non établie`);
          continue;
        }
        if (manifeste.first_seq <= v.seq && v.seq <= manifeste.last_seq) {
          if (!dansPeriode(v.ts, manifeste.period_start, manifeste.period_end)) p3.push(`${nom} (seq ${v.seq}) dans la période par seq mais ts ${v.ts} hors des bornes`);
        } else if (v.seq !== manifeste.first_seq - 1 && v.seq !== manifeste.last_seq + 1) {
          p3.push(`${nom} (seq ${v.seq}) hors période sans être adjacent (${manifeste.first_seq - 1} ou ${manifeste.last_seq + 1})`);
        } else {
          const sec = Math.floor(msHorodatage(v.ts) / 1000);
          const horsPeriode = v.seq === manifeste.first_seq - 1 ? sec < manifeste.period_start : sec >= manifeste.period_end;
          if (Number.isNaN(sec)) p3.push(`${nom} (seq ${v.seq}) : ts ${v.ts} qui n'est pas une date existante`);
          else if (!horsPeriode) p3.push(`${nom} (seq ${v.seq}) hors de l'intervalle de seq du manifeste mais horodaté ${v.ts}, dans la période : manifeste tronqué`);
        }
      }
      rapport.juger("P-3", p3, null, "voisins cohérents avec la période");
    } else rapport.nonExecute("P-3", SANS_VOISINS);
    const p4 = [];
    if (!entier(manifeste.count) || (manifeste.count === 0) !== (manifeste.root === HASH_NUL)) p4.push(manifeste.count === 0 ? "racine non nulle pour une période vide" : "racine nulle pour une période non vide, ou count mal typé");
    if (!(entier(manifeste.count) && manifeste.count >= 1)) p4.push(`count ${JSON.stringify(manifeste.count)} : un dossier prouve un événement, la période n'est pas vide`);
    rapport.juger("P-4", p4, null, `count ${manifeste.count}, racine ${manifeste.root}`);
    if (!manifesteSig) rapport.nonExecute("P-5", pSig.etat === "manquante" ? "manifeste.sig absent du répertoire" : "manifeste.sig inexploitable");
    else {
      const p5 = [];
      let ph = null;
      try {
        ph = hachageManifeste(manifeste);
      } catch (err) {
        p5.push(`manifeste sans forme canonique : ${err.message}`);
      }
      if (ph && ph !== manifesteSig.period_hash) p5.push(`periodHash recalculé ${ph} différent de manifeste.sig.period_hash ${manifesteSig.period_hash}`);
      if (manifeste.recorder_key_id !== manifesteSig.recorder_key_id) p5.push(`manifeste.recorder_key_id ${manifeste.recorder_key_id} différent de manifeste.sig.recorder_key_id ${manifesteSig.recorder_key_id}`);
      if (clesExploitables) {
        const cle = typeof manifesteSig.recorder_key_id === "string" ? cles.get(manifesteSig.recorder_key_id) : undefined;
        if (!cle) p5.push(`clé ${manifesteSig.recorder_key_id} absente de cles.json`);
        else {
          if (ph && !verifierSignatureManifeste(manifeste, manifesteSig, cle.public_key)) p5.push(`signature du manifeste invalide sous ${manifesteSig.recorder_key_id}`);
          const t = msHorodatage(manifeste.generated_at);
          const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
          const a = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
          if (!(t >= de && t <= a)) p5.push(`generated_at ${manifeste.generated_at} hors de la validité de la clé ${manifesteSig.recorder_key_id}`);
        }
      }
      rapport.juger("P-5", p5, clesExploitables ? null : "cles.json inexploitable (E-8) : signature du manifeste non vérifiable", `periodHash ${ph} signé par ${manifesteSig.recorder_key_id}`);
    }
  }

  // A-1 à A-4 : les approbations (révision 0.5 : raison exacte, A-4 avec approbations.json absent ou inexploitable).
  const partieApprobations = partie("approbations");
  const app = ev ? ev.approval : undefined;
  const sansApprobation = ev && (app === null || app === undefined);
  const declareeAbsente = partieApprobations?.present === false;
  const raisonExacte = declareeAbsente && partieApprobations.reason_if_absent === RAISON_AUCUNE_APPROBATION;
  // A-4 : la demande est le voisin dont le hash recalculé égale request_hash ; voisins.json inexploitable : sans raison admise.
  const jugerA4 = () => {
    // Révision 0.5 : approval ni nul ni objet, request_hash (terme de la règle d'A-4) ne se lit pas : A-4 échoue.
    if (!estObjet(app)) return rapport.echec("A-4", `approval ${sorteJSON(app)} qui n'est pas un objet : request_hash illisible, demande non désignée`);
    if (!voisins) return rapport.nonExecute("A-4", `${SANS_VOISINS} : événement de demande non recherché`);
    const candidats = [voisins.previous, voisins.next].filter((v) => estObjet(v));
    const demande = estObjet(app) ? candidats.find((v) => hashRecalcule(v) === app.request_hash) : undefined;
    if (!demande) rapport.nonExecute("A-4", `${DETAIL_A4_HORS_DOSSIER} (request_hash ${estObjet(app) ? app.request_hash : "?"}) absent du dossier : non vérifiable`);
    else if (demande.execution?.status !== "retenue") rapport.echec("A-4", `événement de demande seq ${demande.seq} avec status ${demande.execution?.status}, attendu retenue`);
    else rapport.succes("A-4", `événement de demande seq ${demande.seq} retenu, hash égal à request_hash`);
  };
  if (!ev) {
    for (const id of ["A-1", "A-2", "A-3", "A-4"]) rapport.nonExecute(id, SANS_EV);
  } else if (sansApprobation) {
    const a1 = [];
    if (!declareeAbsente) a1.push("approbations.json déclaré présent alors que approval est null");
    else if (!raisonExacte) a1.push(`raison d'absence « ${partieApprobations.reason_if_absent} », attendue exactement « ${RAISON_AUCUNE_APPROBATION} »`);
    rapport.juger("A-1", a1, null, "aucune approbation liée, partie absente avec sa raison");
    for (const id of ["A-2", "A-3", "A-4"]) rapport.nonExecute(id, rapport.statut("A-1") === "reussi" ? RAISON_AUCUNE_APPROBATION : "A-1 en échec : partie approbations.json mal déclarée");
  } else {
    if (declareeAbsente) {
      rapport.echec("A-1", "approval non nul mais approbations.json déclaré absent");
      for (const id of ["A-2", "A-3"]) rapport.nonExecute(id, "approbations.json déclaré absent");
    } else if (!approbations) {
      // Cas (a) : A-1 non exécutée (D-2 en échec) ; cas (b) à (e) : A-1 déjà en échec, ou E-2.
      rapport.nonExecute("A-1", pApprobations.etat === "manquante" ? "approbations.json absent du répertoire" : "approbations.json inexploitable");
      for (const id of ["A-2", "A-3"]) rapport.nonExecute(id, pApprobations.etat === "manquante" ? "approbations.json absent du répertoire" : "approbations.json inexploitable");
    } else {
      const a1 = [];
      if (!estObjet(app) || approbations.ticket !== app.ticket) a1.push(`ticket ${approbations.ticket} différent de approval.ticket ${estObjet(app) ? app.ticket : "?"}`);
      if (!estObjet(app) || approbations.request_hash !== app.request_hash) a1.push(`request_hash ${approbations.request_hash} différent de approval.request_hash ${estObjet(app) ? app.request_hash : "?"}`);
      rapport.juger("A-1", a1, null, `ticket ${estObjet(app) ? app.ticket : "?"}`);

      const events = Array.isArray(approbations.events) ? approbations.events : [];
      const a2 = [];
      if (events.length === 0) a2.push("aucun événement de décision");
      const evEstDecision = estDecisionApprobation(ev);
      const A = objetApprobation(ev);
      events.forEach((d, i) => {
        if (!estObjet(d)) {
          a2.push(`events[${i}] : ${sorteJSON(d)}, pas un événement`);
          return;
        }
        if (d.execution?.tool !== OUTIL_APPROBATION) a2.push(`events[${i}] : execution.tool ${d.execution?.tool} au lieu de ${OUTIL_APPROBATION}`);
        if (!egalJSON(d.approval, app)) a2.push(`events[${i}] : approval différent de celui de l'événement prouvé`);
        if (!memeFormeCanonique(d.execution?.arguments?.value, A)) a2.push(`events[${i}] : execution.arguments.value différent de A`);
        if (!evEstDecision && !(entier(d.seq) && entier(ev.seq) && d.seq < ev.seq)) a2.push(`events[${i}] : seq ${JSON.stringify(d.seq)} n'est pas antérieur à celui de l'appel relayé (${JSON.stringify(ev.seq)})`);
      });
      if (!evEstDecision) {
        const tAt = msHorodatage(estObjet(app) ? app.at : undefined);
        const tEv = msHorodatage(ev.ts);
        if (Number.isNaN(tAt) || Number.isNaN(tEv)) a2.push(`approval.at ${estObjet(app) ? app.at : "?"} et ts ${ev.ts} de l'appel relayé incomparables (date inexistante ou mal formée)`);
        else if (tAt > tEv) a2.push(`approval.at ${app.at} postérieur au ts de l'appel relayé ${ev.ts}`);
      } else if (!events.some((d) => hashRecalcule(d) === hashEv)) a2.push("l'événement prouvé est une décision mais ne figure pas dans events");
      rapport.juger("A-2", a2, null, `${events.length} événement(s) de décision cohérent(s)`);

      const a3 = [];
      const jeu = estObjet(approbations.approver_set) ? approbations.approver_set : {};
      const membres = Array.isArray(jeu.members) ? jeu.members : [];
      const jeuMembres = new Set(membres);
      const approvers = estObjet(app) && Array.isArray(app.approvers) ? app.approvers : [];
      const seuil = estObjet(app) ? app.threshold : undefined;
      if (new Set(approvers).size !== approvers.length) a3.push("approbateur en double");
      for (const x of approvers) if (!jeuMembres.has(x)) a3.push(`approbateur ${x} hors du jeu déclaré`);
      if (!egalJSON(seuil, jeu.threshold)) a3.push(`threshold de l'événement ${JSON.stringify(seuil)} différent de celui du jeu ${JSON.stringify(jeu.threshold)}`);
      const req = jeu.threshold?.required;
      const size = jeu.threshold?.size;
      if (!(entier(req) && entier(size) && req <= size && size === membres.length)) a3.push(`seuil ${req}/${size} incohérent avec ${membres.length} membre(s)`);
      if (estObjet(app) && app.decision === "expire") {
        if (approvers.length !== 0) a3.push("décision expirée avec des approbateurs");
      } else if (!(estObjet(seuil) && entier(seuil.required) && approvers.length >= seuil.required)) a3.push(`${approvers.length} approbateur(s) pour un seuil de ${estObjet(seuil) ? seuil.required : "?"}`);
      rapport.juger("A-3", a3, null, `${approvers.length} approbateur(s) distinct(s) sur un seuil de ${seuil?.required}/${seuil?.size}`);
    }
    jugerA4();
  }

  // K-1 à K-9 : la partie points-de-controle.json (CT-1 révision 0.3, §11.4).
  if (!pointsDeclaresPresents) {
    for (const id of IDS_K) rapport.nonExecute(id, DETAIL_K_PARTIE_ABSENTE);
  } else if (!pPoints.valeur) {
    // lire() a imputé K-1 (cas (b), (c), (e)) ou E-2 (cas (d)), ou laissé K-1 non exécutée (cas (a), D-2 en échec).
    for (const id of IDS_K.slice(1)) rapport.nonExecute(id, `${PARTIE_POINTS_DE_CONTROLE.file} inexploitable`);
  } else {
    verifierPartiePointsDeControle(rapport, pPoints.valeur, { ev, voisins, chemin, manifeste, cles, clesExploitables, schemas, hashRecalcule });
  }

  // AT-1 à AT-7 : la partie attestation-perimetre.json (CT-1 révision 0.4, §11.4), sans effet sur la validité.
  let attestation = null;
  const partieAttestation = partie(PARTIE_ATTESTATION_PERIMETRE.name);
  if (partieAttestation && partieAttestation.present === true) {
    if (!schemas[ID_SCHEMA_ATTESTATION_PERIMETRE]) throw new DossierInutilisable("le schéma attestation-perimetre est requis pour vérifier la partie attestation-perimetre.json (CT-1 révision 0.4)");
    const file = PARTIE_ATTESTATION_PERIMETRE.file;
    const motifTaille = etats.get(file) === "trop_grande" ? refus(file) ?? `${file} : ${brut(file).length} octets, au-delà de la limite de ${limite(file)} octets` : null;
    attestation = S.verifierPartieAttestation({ octets: motifTaille ? null : brut(file), inexploitable: motifTaille, evenement: ev, cles: clesDoc, approbations, schemas });
  }

  // Parties réservées déclarées présentes : CT-6 les vérifie ; cette bibliothèque ne dit pas valide ce qu'elle n'a pas vérifié.
  const partiesNonVerifiees = PARTIES_RESERVEES.filter((name) => partie(name)?.present === true);
  const parties = {
    evenement: ev, voisins, chemin, manifeste, manifesteSig, cles: clesDoc, approbations, points: pPoints.valeur,
    clesExploitables,
    etats: Object.fromEntries(etats),
    exploitabilite: { evenement: pEv.etat, voisins: pVoisins.etat, chemin: pChemin.etat, manifeste: pManifeste.etat, manifesteSig: pSig.etat, cles: pCles.etat, approbations: pApprobations.etat, points: pPoints.etat },
  };
  return terminer(rapport, index, ev, parts, attestation, { partiesNonVerifiees, parties });
}

/**
 * K-1 à K-9 sur une partie points-de-controle.json exploitable (objet JSON).
 * K-1 contrôle toujours le schéma ; ses relations au manifeste exigent P-1
 * réussie et celles à l'événement evenement.json exploitable (sinon K-1 n'est
 * pas exécutée, sauf échec). K-2 à K-9 exigent K-1 réussie. K-7 à K-9 : ancre
 * nulle, non exécutées (partie absente, raison admise) ; ancre non nulle,
 * vérifiée par CT-6 : ici K-7 et K-9 ne sont pas exécutées, sans raison admise,
 * et K-8 compare fingerprint et doc_type (écart : échec ; sinon non exécutée,
 * sans raison admise).
 */
function verifierPartiePointsDeControle(rapport, doc, { ev, voisins, chemin, manifeste: manifesteLu, cles, clesExploitables, schemas, hashRecalcule }) {
  const file = PARTIE_POINTS_DE_CONTROLE.file;
  const erreursSchema = validerSchema(doc, schemas[ID_SCHEMA_DOSSIER], { registre: schemas, fragment: "#/$defs/points_de_controle" });
  const point = estObjet(doc.checkpoint) ? doc.checkpoint : null;
  // Prérequis (CT-6 EX-5.9, table 5.3) : les relations au manifeste exigent P-1 réussie ; K-4 exige M-3 réussie.
  const reussie = (id) => rapport.statut(id) === "reussi";
  const manifeste = reussie("P-1") ? manifesteLu : null;
  const k1 = erreursSchema.length ? [`${file} : ${resumerErreurs(erreursSchema)}`] : [];
  if (point) k1.push(...horodatagesHorsCalendrier([["/checkpoint/checkpoint_ts", point.checkpoint_ts]]).map((e) => `${file} : ${e.chemin} : ${e.message}`));
  if (point && ev && (point.org_id !== ev.org_id || point.journal_id !== ev.journal_id)) k1.push("org_id ou journal_id du point différents de ceux de l'événement");
  if (point && manifeste) {
    if (point.period_start !== manifeste.period_start) k1.push(`period_start du point ${point.period_start} différent de celui du manifeste ${manifeste.period_start}`);
    if (!(Number.isSafeInteger(point.tree_size) && point.tree_size >= 1 && point.tree_size <= manifeste.count)) k1.push(`tree_size ${point.tree_size} hors de [1, count = ${manifeste.count}]`);
    if (!Number.isSafeInteger(point.last_seq) || point.last_seq !== manifeste.first_seq + point.tree_size - 1) k1.push(`last_seq ${point.last_seq} différent de first_seq + tree_size - 1 (${manifeste.first_seq + point.tree_size - 1})`);
    if (point.root === HASH_NUL) k1.push("racine du point nulle");
    const sec = Math.floor(msHorodatage(point.checkpoint_ts) / 1000);
    if (Number.isNaN(sec) || sec < manifeste.period_start) k1.push(`checkpoint_ts ${point.checkpoint_ts} antérieur à period_start ${manifeste.period_start}`);
  }
  const manqueK1 = !point ? "checkpoint inexploitable" : !ev ? "événement ou manifeste inexploitable : relations du point non vérifiables" : !manifeste ? (manifesteLu ? "P-1 n'a pas réussi : relations du point au manifeste non vérifiables" : "événement ou manifeste inexploitable : relations du point non vérifiables") : null;
  rapport.juger("K-1", k1, manqueK1, point ? `point de tree_size ${point.tree_size} (seq ${manifeste?.first_seq}..${point.last_seq}), checkpoint_ts ${point.checkpoint_ts}` : null);
  // CT-1 §11.4, CT-6 EX-5.9 : K-1 en échec ou non exécutée, K-2 à K-9 ne sont pas exécutées, sans raison
  // admise (prerequis_en_echec), ancres nulles comprises ; aucun calcul n'est fait sur la partie.
  if (!reussie("K-1")) {
    const detail = rapport.parId.get("K-1").ok === false ? "K-1 en échec" : "K-1 non exécutée";
    for (const id of IDS_K.slice(1)) rapport.nonExecute(id, detail);
    return;
  }

  // K-2 : checkpointHash.
  let ch = null;
  try {
    ch = hachagePointDeControle(point);
  } catch (err) {
    rapport.echec("K-2", `point sans forme canonique : ${err.message}`);
  }
  if (ch) rapport.resultat("K-2", ch === doc.checkpoint_hash, ch === doc.checkpoint_hash ? `checkpointHash ${ch}` : `checkpointHash recalculé ${ch} différent de checkpoint_hash ${doc.checkpoint_hash}`);

  // K-3 : signature et validité de la clé.
  if (!clesExploitables) rapport.nonExecute("K-3", "cles.json inexploitable (E-8) : signature du point non vérifiable");
  else {
    const cle = cles.get(point.key_id);
    const k3 = [];
    if (!cle) k3.push(`clé ${point.key_id} absente de cles.json`);
    else {
      if (!verifierSignaturePointDeControle(point, cle.public_key)) k3.push(`signature du point invalide sous ${point.key_id}`);
      const t = msHorodatage(point.checkpoint_ts);
      const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
      const a = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
      if (!(t >= de && t <= a)) k3.push(`checkpoint_ts ${point.checkpoint_ts} hors de la validité de la clé ${point.key_id}`);
    }
    rapport.juger("K-3", k3, null, `point signé par ${point.key_id}`);
  }

  // K-4 : couverture de l'événement prouvé (prérequis : M-3 réussie).
  if (!reussie("M-3")) rapport.nonExecute("K-4", "M-3 n'a pas réussi : indice de feuille de l'événement non établi");
  else if (!chemin || !ev) rapport.nonExecute("K-4", "chemin ou événement inexploitable");
  else {
    const k4 = [];
    if (!(Number.isSafeInteger(chemin.leaf_index) && chemin.leaf_index < point.tree_size)) k4.push(`leaf_index ${chemin.leaf_index} non couvert par tree_size ${point.tree_size}`);
    const tEv = msHorodatage(ev.ts);
    const tK = msHorodatage(point.checkpoint_ts);
    if (Number.isNaN(tEv) || Number.isNaN(tK) || tEv > tK) k4.push(`ts de l'événement ${ev.ts} postérieur à checkpoint_ts ${point.checkpoint_ts}`);
    rapport.juger("K-4", k4, null, `feuille ${chemin.leaf_index} couverte (tree_size ${point.tree_size}), ts ${ev.ts} <= ${point.checkpoint_ts}`);
  }

  // K-5 : preuve de cohérence vers le manifeste.
  const cs = estObjet(doc.consistency) ? doc.consistency : null;
  if (!cs) rapport.echec("K-5", "consistency inexploitable");
  else if (!manifeste) rapport.nonExecute("K-5", "manifeste inexploitable");
  else {
    const k5 = [];
    if (cs.first_size !== point.tree_size) k5.push(`first_size ${cs.first_size} différent de tree_size ${point.tree_size}`);
    if (cs.second_size !== manifeste.count) k5.push(`second_size ${cs.second_size} différent de count ${manifeste.count}`);
    if (cs.first_root !== point.root) k5.push(`first_root ${cs.first_root} différent de root du point ${point.root}`);
    if (cs.second_root !== manifeste.root) k5.push(`second_root ${cs.second_root} différent de root du manifeste ${manifeste.root}`);
    let accepte = false;
    try {
      accepte = verifierCoherence(cs);
    } catch {
      accepte = false;
    }
    if (!accepte) k5.push(`la preuve de cohérence (${Array.isArray(cs.path) ? cs.path.length : "?"} nœud(s)) n'est pas acceptée pour (${cs.first_size}, ${cs.second_size})`);
    rapport.juger("K-5", k5, null, `arbre de ${cs.first_size} feuilles préfixe de l'arbre de ${cs.second_size} (${Array.isArray(cs.path) ? cs.path.length : 0} nœud(s))`);
  }

  // K-6 : last_hash contre l'événement last_seq quand il est dans le dossier ; voisins.json inexploitable : sans raison admise.
  let cible = ev && ev.seq === point.last_seq ? ev : undefined;
  if (!cible && !voisins) rapport.nonExecute("K-6", "voisins.json inexploitable : événement last_seq non recherché");
  else {
    cible ??= [voisins?.previous, voisins?.next].filter((v) => estObjet(v)).find((v) => v.seq === point.last_seq);
    if (!cible) rapport.nonExecute("K-6", `${DETAIL_K6_HORS_DOSSIER} (seq ${point.last_seq}) : last_hash non vérifiable`);
    else {
      const h = hashRecalcule(cible);
      if (!h) rapport.nonExecute("K-6", `hash de l'événement ${point.last_seq} incalculable`);
      else rapport.resultat("K-6", h === point.last_hash, h === point.last_hash ? `last_hash égal au hash recalculé de l'événement ${point.last_seq}` : `last_hash ${point.last_hash} différent du hash recalculé de l'événement ${point.last_seq} (${h})`);
    }
  }

  // K-7 à K-9 : ancres du point. Nulles : partie absente (admise). Non nulles : vérifiées par CT-6 (verificateur.mjs).
  const anchors = estObjet(doc.anchors) ? doc.anchors : {};
  const nulle = (cle) => anchors[cle] === null || anchors[cle] === undefined;
  for (const [id, cle] of [["K-7", "rfc3161"], ["K-9", "ots"]]) rapport.nonExecute(id, nulle(cle) ? DETAIL_K_ANCRE_NULLE : DETAIL_K_HORS_PERIMETRE);
  if (nulle("registry")) rapport.nonExecute("K-8", DETAIL_K_ANCRE_NULLE);
  else if (rapport.statut("K-2") !== "reussi") rapport.nonExecute("K-8", "K-2 n'a pas réussi : checkpointHash non recalculé");
  else {
    const ref = estObjet(anchors.registry) ? anchors.registry : {};
    const k8 = [];
    const attendue = empreinteAncrePoint(ev.org_id, ev.journal_id, ch);
    if (ref.fingerprint !== attendue) k8.push(`fingerprint ${ref.fingerprint} au lieu de keccak256(org_id ‖ journal_id ‖ checkpoint_hash) = ${attendue}`);
    if (ref.doc_type !== DOC_TYPE_POINT_DE_CONTROLE) k8.push(`doc_type ${ref.doc_type} au lieu de ${DOC_TYPE_POINT_DE_CONTROLE} (noortrace/point-de-controle/v0)`);
    rapport.juger("K-8", k8, `${DETAIL_K_HORS_PERIMETRE} (fichier d'ancres et vérifications R- de CT-6)`, null);
  }
}

function terminer(rapport, index, ev, parts, attestation = null, { partiesNonVerifiees = [], parties = null } = {}) {
  const partiesAbsentes = parts.filter((p) => p && p.present === false).map((p) => ({ name: p.name, file: p.file, reason: p.reason_if_absent ?? null }));
  const reserveesAbsentes = partiesAbsentes.filter((p) => PARTIES_RESERVEES.includes(p.name));
  const borne = reserveesAbsentes.length
    ? `verdict borné : sans ${reserveesAbsentes.map((p) => p.file).join(", ")}, rien n'est prouvé sur la date de l'événement (contrôles 4 et 5, CT-5) ni sur son ancrage dans le registre (contrôle 8, CT-4) ; ce dossier établit au plus que l'événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste signé par cette clé, et approuvé par ces adresses`
    : null;
  const bloquants = nonExecutesBloquants(rapport, parts);
  return {
    valide: rapport.sansEchec && bloquants.length === 0 && partiesNonVerifiees.length === 0,
    controles: rapport.controles.map((c) => ({ id: c.id, libelle: c.libelle, architecture: c.architecture, ok: c.ok, execute: c.execute, detail: c.details.join(" ; ") || null })),
    nonExecutesBloquants: bloquants,
    // Révision 0.5 : parties réservées déclarées présentes, non vérifiées par CT-1 seule (sans raison admise).
    partiesNonVerifiees,
    // Leurs vérifications de CT-6, rapportées non exécutées : raison prerequis_en_echec, détail fixé par CT-1 §11.4.
    verificationsCT6NonExecutees: partiesNonVerifiees.map((name) => ({ part: name, reason: RAISON_VERIFICATION_CT6, detail: DETAIL_VERIFICATION_CT6 })),
    // Rien n'est repris de l'index à la place d'un evenement.json inexploitable (CT-6 EX-6.22).
    evenement: ev ? { seq: ev.seq, hash: ev.hash, ts: ev.ts, tool: ev.execution?.tool ?? null } : null,
    org_id: ev && estHex32(ev.org_id) ? ev.org_id : null,
    journal_id: ev && estHex32(ev.journal_id) ? ev.journal_id : null,
    partiesAbsentes,
    borne,
    attestation,
    indexExploitable: index !== null,
    index,
    parties,
  };
}

/** Les identifiants des contrôles en échec d'un rapport, dans l'ordre du rapport. */
export function controlesEnEchec(rapport) {
  return rapport.controles.filter((c) => c.ok === false).map((c) => c.id);
}
