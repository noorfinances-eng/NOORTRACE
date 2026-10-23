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
import { Signature, getBytes, hashMessage, recoverAddress } from "ethers";

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

export const RAISON_HORS_PERIMETRE = "hors périmètre CT-1";
export const RAISON_AUCUNE_APPROBATION = "aucune approbation liée";

/** Identifiants des schémas, pour le registre de validation (spec/schemas). */
export const ID_SCHEMA_EVENEMENT = "https://noortrace.example/schemas/v0/evenement.schema.json";
export const ID_SCHEMA_MANIFESTE = "https://noortrace.example/schemas/v0/manifeste.schema.json";
export const ID_SCHEMA_DOSSIER = "https://noortrace.example/schemas/v0/dossier.schema.json";

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
 * hors intervalle, clé en double, substitut isolé, octets UTF-8 invalides,
 * marque d'ordre d'octets : contrôle E-2), false pour une erreur de syntaxe
 * JSON, que le vérificateur impute au contrôle qui porte la partie (CT-1 §11.4).
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

/**
 * Analyse stricte d'un texte JSON (chaîne ou octets UTF-8) : refuse ce que la
 * forme canonique v0 ne sait pas représenter et que JSON.parse accepterait en
 * silence — nombre à partie fractionnaire ou exposant (412.0, 1e3), entier hors
 * de l'intervalle sûr, clé en double, substitut isolé, marque d'ordre d'octets.
 * C'est l'analyseur du vérificateur (contrôle E-2).
 */
export function analyserJSONStrict(entree) {
  let texte;
  if (typeof entree === "string") {
    texte = entree;
  } else {
    const buf = Buffer.isBuffer(entree) ? entree : Buffer.from(entree);
    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) throw new ErreurJSON("marque d'ordre d'octets en tête du document", true);
    try {
      texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf);
    } catch {
      throw new ErreurJSON("octets UTF-8 invalides", true);
    }
  }
  let i = 0;
  const n = texte.length;
  const erreur = (m, canonique = false) => {
    throw new ErreurJSON(`${m} (caractère ${i})`, canonique);
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
          if (cu >= 0xd800 && cu <= 0xdbff) {
            if (texte[i] !== "\\" || texte[i + 1] !== "u") erreur("substitut haut isolé", true);
            i += 2;
            const bas = unite();
            if (bas < 0xdc00 || bas > 0xdfff) erreur("substitut haut sans substitut bas", true);
            out += String.fromCharCode(cu, bas);
          } else if (cu >= 0xdc00 && cu <= 0xdfff) {
            erreur("substitut bas isolé", true);
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
    if (m[2] !== undefined || m[3] !== undefined) erreur(`nombre non entier « ${m[0]} » : JCS v0 n'admet que les entiers`, true);
    const grand = BigInt(m[0]);
    if (grand > 9007199254740991n || grand < -9007199254740991n) erreur(`entier hors de l'intervalle sûr « ${m[0]} » : à porter en chaîne décimale`, true);
    i += m[0].length;
    return Number(grand);
  };
  const litteral = (mot, val) => {
    if (!texte.startsWith(mot, i)) erreur("littéral invalide");
    i += mot.length;
    return val;
  };
  const tableau = () => {
    i++;
    const out = [];
    blancs();
    if (texte[i] === "]") {
      i++;
      return out;
    }
    for (;;) {
      out.push(valeur());
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "]") {
        i++;
        return out;
      }
      erreur("« , » ou « ] » attendu");
    }
  };
  const objet = () => {
    i++;
    const out = {};
    blancs();
    if (texte[i] === "}") {
      i++;
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
      if (Object.hasOwn(out, k)) erreur(`clé en double « ${k} »`, true);
      Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "}") {
        i++;
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
  return v;
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

/**
 * Vérification Ed25519 : signature de 64 octets dont S est réduit modulo l'ordre
 * du groupe, clé publique canonique (y < p) qui n'est pas de petit ordre, puis
 * vérification RFC 8032 §5.1.7. Rend false sur toute entrée malformée.
 */
export function verifierEd25519(clePubliqueHex, message, signatureHex) {
  if (!estHex32(clePubliqueHex) || typeof signatureHex !== "string" || !/^0x[0-9a-f]{128}$/.test(signatureHex)) return false;
  const pub = octets(clePubliqueHex);
  const sig = octets(signatureHex);
  const y = BigInt("0x" + Buffer.from(pub).reverse().toString("hex")) & ((1n << 255n) - 1n);
  if (y >= P_ED25519) return false;
  if (PETIT_ORDRE_ED25519.has(pub.toString("hex"))) return false;
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

/** E' : l'événement privé de hash et sig (CT-1 §6.1). */
export function corpsEvenement(evenement) {
  if (!evenement || typeof evenement !== "object" || Array.isArray(evenement)) throw new ErreurFormat("événement : objet attendu", "E-1");
  const corps = {};
  for (const k of Object.keys(evenement)) if (k !== "hash" && k !== "sig") corps[k] = evenement[k];
  return corps;
}

/** hash = SHA-256(P_H || JCS(E')). */
export function hachageEvenement(evenement) {
  return sha256(Buffer.concat([Buffer.from(PREFIXE_EVENEMENT, "utf8"), octetsJCS(corpsEvenement(evenement))]));
}

/** Message signé par l'enregistreur : P_S || JCS(E'). */
export function messageSignatureEvenement(evenement) {
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
  for (const k of CLES_EVENEMENT) if (k !== "hash" && k !== "sig") ordonne[k] = corps[k];
  for (const k of Object.keys(corps)) if (!(k in ordonne) && k !== "hash" && k !== "sig") ordonne[k] = corps[k];
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
  for (const k of Object.keys(value)) if (k !== "counter_sig") R[k] = value[k];
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

/**
 * Vérifie une suite d'événements d'un même journal (CT-1 §7.2) et nomme ce
 * qu'elle détecte. Diagnostics : { type, controle, seq, message } avec type dans
 * modification (hash recalculé différent, E-7), signature (E-8), origine
 * (prev_hash nul ssi seq = 1, C-2), suppression (trou de seq, C-1), insertion
 * (seq en double, C-1), reordonnancement (seq décroissant, C-1), rupture
 * (prev_hash différent du hash recalculé de l'événement qui précède dans le
 * fichier, C-2), horodatage (ts décroissant, C-1), journal (org_id ou
 * journal_id différents, C-1), cle (recorder_key_id inattendu, C-3). Tous les
 * symptômes de la table 7.2 sont rapportés, pas seulement le premier : chaque
 * événement est contrôlé pour lui-même, puis chaque couple consécutif dans
 * l'ordre du fichier. La troncature de la fin du journal n'est pas détectable
 * par la chaîne seule (manifeste, P-3/P-4).
 * `clesPubliques` : voir normaliserCles ; sans clés, les signatures ne sont pas contrôlées.
 */
export function verifierChaine(evenements, { clesPubliques } = {}) {
  const diagnostics = [];
  const dire = (type, controle, seq, message) => diagnostics.push({ type, controle, seq, message });
  if (!Array.isArray(evenements)) return { valide: false, diagnostics: [{ type: "format", controle: "E-1", seq: null, message: "tableau d'événements attendu" }] };
  const cles = normaliserCles(clesPubliques);
  const haches = new Map(); // position -> hash recalculé
  const intacts = new Map();

  // 1. Chaque événement pour lui-même : hachage, signature, prev_hash nul ssi seq = 1.
  evenements.forEach((ev, pos) => {
    const seq = typeof ev?.seq === "number" ? ev.seq : null;
    let h = null;
    try {
      h = hachageEvenement(ev);
    } catch (err) {
      dire("format", "E-2", seq, `événement en position ${pos} sans forme canonique : ${err.message}`);
      intacts.set(pos, false);
      return;
    }
    haches.set(pos, h);
    const intact = h === ev.hash;
    intacts.set(pos, intact);
    if (!intact) dire("modification", "E-7", seq, `seq ${seq} : hash recalculé ${h} différent de hash ${ev.hash} (contenu modifié après scellement)`);
    if (cles.size > 0) {
      const cle = cles.get(ev.recorder_key_id);
      if (!cle) dire("signature", "E-8", seq, `seq ${seq} : clé ${ev.recorder_key_id} inconnue`);
      else if (!verifierSignatureEvenement(ev, cle.public_key)) dire("signature", "E-8", seq, `seq ${seq} : signature invalide sous la clé ${ev.recorder_key_id}${intact ? "" : " (contenu modifié)"}`);
    }
    if (seq === 1 && ev.prev_hash !== HASH_NUL) dire("origine", "C-2", seq, "seq 1 : prev_hash doit être nul");
    if (seq !== 1 && ev.prev_hash === HASH_NUL) dire("origine", "C-2", seq, `seq ${seq} : prev_hash nul réservé au premier événement`);
  });

  // 2. La suite des seq : doublons (insertion), trous (suppression), ordre (réordonnancement).
  const seqs = evenements.map((ev) => ev?.seq);
  const vus = new Map();
  seqs.forEach((s, pos) => vus.set(s, [...(vus.get(s) ?? []), pos]));
  for (const [s, positions] of vus) if (positions.length > 1) dire("insertion", "C-1", s, `seq ${s} présent ${positions.length} fois (positions ${positions.join(", ")}) : événement inséré`);
  const uniques = [...vus.keys()].filter((s) => Number.isInteger(s)).sort((a, b) => a - b);
  for (let i = 1; i < uniques.length; i++) {
    if (uniques[i] !== uniques[i - 1] + 1) {
      const manquants = uniques[i] - uniques[i - 1] - 1;
      dire("suppression", "C-1", uniques[i], `trou entre seq ${uniques[i - 1]} et seq ${uniques[i]} : ${manquants} événement(s) supprimé(s)`);
    }
  }
  for (let pos = 1; pos < seqs.length; pos++) {
    if (Number.isInteger(seqs[pos]) && Number.isInteger(seqs[pos - 1]) && seqs[pos] < seqs[pos - 1]) {
      dire("reordonnancement", "C-1", seqs[pos], `seq ${seqs[pos]} (position ${pos}) après seq ${seqs[pos - 1]} (position ${pos - 1}) : ordre du journal non respecté`);
    }
  }

  // 3. Les liens, couple par couple dans l'ordre du fichier : prev_hash contre
  // le hash recalculé du précédent (C-2), ts et journal (C-1), clé (C-3).
  for (let pos = 1; pos < evenements.length; pos++) {
    const prec = evenements[pos - 1];
    const ev = evenements[pos];
    if (!prec || typeof prec !== "object" || !ev || typeof ev !== "object") continue;
    const hp = haches.get(pos - 1);
    if (hp && ev.prev_hash !== hp) dire("rupture", "C-2", ev.seq, `seq ${ev.seq} (position ${pos}) : prev_hash ${ev.prev_hash} différent du hash recalculé de l'événement précédent dans le fichier, seq ${prec.seq} (${hp})`);
    const t0 = msHorodatage(prec.ts);
    const t1 = msHorodatage(ev.ts);
    if (!Number.isNaN(t0) && !Number.isNaN(t1) && t1 < t0) dire("horodatage", "C-1", ev.seq, `seq ${ev.seq} : ts ${ev.ts} antérieur à celui de seq ${prec.seq} (${prec.ts})`);
    if (ev.org_id !== prec.org_id || ev.journal_id !== prec.journal_id) dire("journal", "C-1", ev.seq, `seq ${ev.seq} : org_id ou journal_id différents de seq ${prec.seq}`);
    const attendue = cleSuivanteAttendue(prec);
    if (ev.recorder_key_id !== attendue) dire("cle", "C-3", ev.seq, `seq ${ev.seq} : recorder_key_id ${ev.recorder_key_id}, attendu ${attendue}${estRotation(prec) ? " (rotation en seq " + prec.seq + ")" : ""}`);
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

/** Résumé d'une liste d'erreurs de schéma, pour un détail de contrôle. */
function resumerErreurs(erreurs, max = 4) {
  const vues = erreurs.slice(0, max).map((e) => `${e.chemin} : ${e.message}`);
  return vues.join(" ; ") + (erreurs.length > max ? ` ; … (${erreurs.length} erreurs)` : "");
}

// ---------------------------------------------------------------------------
// Contrôles d'un événement pris seul (E-1 à E-11)
// ---------------------------------------------------------------------------

function outilsCoherents(ev) {
  const erreurs = [];
  const ex = ev.execution ?? {};
  const outil = ex.tool;
  const refs = (o) => o && typeof o === "object";
  if (estOutilReserve(outil) && !OUTILS_RESERVES.includes(outil)) erreurs.push(`outil réservé inconnu : ${outil}`);
  const sansObjet = ev.policy?.decision === "sans_objet";
  if (estOutilReserve(outil)) {
    if (!sansObjet) erreurs.push(`policy.decision doit valoir sans_objet pour ${outil}`);
    if (ex.status !== "executee") erreurs.push(`execution.status doit valoir executee pour ${outil}`);
    if (outil !== OUTIL_MODELE && ex.result !== null) erreurs.push(`execution.result doit être null pour ${outil}`);
    if (outil !== OUTIL_MODELE && ev.intent !== null) erreurs.push(`intent doit être null pour ${outil}`);
    if (outil !== OUTIL_MODELE && (ex.duration_ms !== null || ex.is_error !== null)) erreurs.push(`duration_ms et is_error doivent être null pour ${outil}`);
  } else if (!sansObjet || ev.policy?.decision === undefined) {
    // Appel d'outil réel : les trois sorties de la politique, cohérentes avec le statut et l'approbation.
    const dec = ev.policy?.decision;
    const app = ev.approval;
    if (!["autorise", "a_approuver", "refuse"].includes(dec)) erreurs.push(`policy.decision ${JSON.stringify(dec)} invalide pour un appel d'outil`);
    if (ex.status === "retenue" && (dec !== "a_approuver" || app !== null)) erreurs.push("appel retenu : policy.decision doit valoir a_approuver sans approbation liée");
    if (ex.status === "executee" && app === null && dec !== "autorise") erreurs.push("appel exécuté sans approbation : policy.decision doit valoir autorise");
    if (ex.status === "executee" && app !== null && (app?.decision !== "approuve" || dec !== "a_approuver")) erreurs.push("appel exécuté après approbation : approval.decision approuve et policy.decision a_approuver attendus");
    if (ex.status === "refusee" && !(dec === "refuse" || (app && ["refuse", "expire"].includes(app.decision)))) erreurs.push("appel refusé : policy.decision refuse, ou approbation refusée ou expirée, attendus");
  } else {
    erreurs.push("policy.decision sans_objet réservé aux événements qui ne sont pas des appels d'outil");
  }
  switch (outil) {
    case OUTIL_MODELE:
      // Table 5.3 : l'échange avec le modèle porte la référence à la réponse, la durée et le drapeau d'erreur.
      if (ev.approval !== null) erreurs.push("approval doit être null pour un échange avec le modèle");
      if (!refs(ex.result)) erreurs.push("execution.result doit référencer la réponse du modèle");
      if (!Number.isSafeInteger(ex.duration_ms) || ex.duration_ms < 0) erreurs.push("execution.duration_ms doit être un entier >= 0 pour un échange avec le modèle");
      if (typeof ex.is_error !== "boolean") erreurs.push("execution.is_error doit être un booléen pour un échange avec le modèle");
      break;
    case OUTIL_APPROBATION: {
      if (!refs(ev.approval)) erreurs.push("approval obligatoire pour une décision d'approbation");
      if (!refs(ex.arguments) || ex.arguments.value === undefined) erreurs.push("execution.arguments.value (objet signé A) obligatoire");
      else if (refs(ev.approval) && !egalJSON(ex.arguments.value, objetApprobation(ev))) erreurs.push("execution.arguments.value différent de A = { decision, journal_id, org_id, request_hash, ticket }");
      if (refs(ev.approval) && ev.policy?.ticket !== ev.approval.ticket) erreurs.push("policy.ticket différent de approval.ticket");
      if (Array.isArray(ev.effects) && ev.effects.length) erreurs.push("effects doit être vide pour une décision d'approbation");
      break;
    }
    case OUTIL_ROTATION: {
      if (ev.approval !== null) erreurs.push("approval doit être null pour une rotation");
      const val = refs(ex.arguments) ? ex.arguments.value : undefined;
      const attendues = ["journal_id", "new_key_id", "new_public_key", "old_key_id", "org_id", "valid_from", "counter_sig"];
      if (!refs(val)) erreurs.push("execution.arguments.value (annonce de rotation) obligatoire");
      else {
        const cles = Object.keys(val).sort();
        if (!egalJSON(cles, [...attendues].sort())) erreurs.push(`annonce de rotation : clés ${JSON.stringify(cles)}, attendues ${JSON.stringify([...attendues].sort())}`);
      }
      const effet = { system: "noortrace", action: "ecriture", object: `cle:${val?.new_key_id}`, amount: null, currency: null };
      if (!Array.isArray(ev.effects) || ev.effects.length !== 1 || !egalJSON(ev.effects[0], effet)) erreurs.push(`effects d'une rotation : exactement ${JSON.stringify(effet)}`);
      break;
    }
    case OUTIL_POLITIQUE: {
      if (ev.approval !== null) erreurs.push("approval doit être null pour un changement de politique");
      const val = refs(ex.arguments) ? ex.arguments.value : undefined;
      if (!refs(val) || typeof val.policy_version !== "string" || !estHex32(val.policy_sha256) || Object.keys(val).length !== 2) erreurs.push("execution.arguments.value doit être { policy_version, policy_sha256 }");
      break;
    }
    default:
      break;
  }
  return erreurs;
}

/**
 * Les contrôles E-1 à E-11 sur un événement pris seul. `schemas` : registre de
 * schémas (registreSchemas) ; sans registre, E-1 n'est pas exécuté. `cles` :
 * clés publiques (voir normaliserCles) ; sans clés, E-8, E-10 (clé annoncée) et
 * E-11 ne sont pas exécutés. Rend un objet id -> { ok, execute, detail }.
 */
export function controlesEvenement(ev, { schemas, cles } = {}) {
  const r = {};
  const pose = (id, ok, detail = null) => (r[id] = { ok, execute: true, detail });
  const nonExecute = (id, detail) => (r[id] = { ok: null, execute: false, detail });
  const clesMap = normaliserCles(cles);

  if (schemas?.[ID_SCHEMA_EVENEMENT]) {
    const erreurs = validerSchema(ev, schemas[ID_SCHEMA_EVENEMENT], { registre: schemas });
    erreurs.push(...horodatagesHorsCalendrier([["/ts", ev?.ts], ["/approval/at", ev?.approval?.at], ["/execution/arguments/value/valid_from", ev?.execution?.arguments?.value?.valid_from]]));
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

  const e3 = outilsCoherents(ev);
  pose("E-3", e3.length === 0, e3.length ? e3.join(" ; ") : `sorte : ${estOutilReserve(ev.execution?.tool) ? ev.execution.tool : "appel d'outil"}`);

  const refs = referencesEvenement(ev);
  const redigees = refs.filter(({ ref }) => ref.redacted === true);
  const redaction = ev.policy?.redaction;
  pose("E-4", redigees.length === 0 || (typeof redaction === "string" && redaction.length > 0), redigees.length === 0 ? "aucune référence rédigée" : typeof redaction === "string" && redaction ? `${redigees.length} référence(s) rédigée(s) par ${redaction}` : `référence(s) rédigée(s) (${redigees.map((x) => x.chemin).join(", ")}) sans policy.redaction`);

  if (ev.approval === null || ev.approval === undefined) {
    pose("E-5", true, "aucune approbation liée");
  } else {
    const a = ev.approval;
    const erreurs = [];
    if (!Array.isArray(a.approvers) || !Array.isArray(a.signatures) || a.approvers.length !== a.signatures.length) erreurs.push(`approvers (${a.approvers?.length}) et signatures (${a.signatures?.length}) de longueurs différentes`);
    if (a.ticket !== ev.policy?.ticket) erreurs.push(`approval.ticket ${JSON.stringify(a.ticket)} différent de policy.ticket ${JSON.stringify(ev.policy?.ticket)}`);
    pose("E-5", erreurs.length === 0, erreurs.length ? erreurs.join(" ; ") : `${a.approvers.length} signature(s), ticket ${a.ticket}`);
  }

  const e6 = refs.filter(({ ref }) => ref.value !== undefined).map(({ chemin, ref }) => ({ chemin, ...verifierReference(ref) })).filter((x) => !x.ok);
  pose("E-6", e6.length === 0, e6.length ? e6.map((x) => `${x.chemin} : ${x.raison}`).join(" ; ") : `${refs.filter(({ ref }) => ref.value !== undefined).length} référence(s) en ligne vérifiée(s)`);

  if (canon === null) {
    nonExecute("E-7", "forme canonique incalculable");
    nonExecute("E-8", "forme canonique incalculable");
  } else {
    const h = hachageEvenement(ev);
    pose("E-7", h === ev.hash, h === ev.hash ? `hash ${h}` : `hash recalculé ${h} différent de hash ${ev.hash}`);
    const cle = clesMap.get(ev.recorder_key_id);
    if (clesMap.size === 0) nonExecute("E-8", "aucune clé publique fournie");
    else if (!cle) pose("E-8", false, `clé ${ev.recorder_key_id} absente de cles.json`);
    else {
      const ok = verifierSignatureEvenement(ev, cle.public_key);
      pose("E-8", ok, ok ? `signature valide sous ${ev.recorder_key_id}` : `signature invalide sous la clé ${ev.recorder_key_id} (${cle.public_key})`);
    }
  }

  if (!ev.approval || typeof ev.approval !== "object") {
    pose("E-9", true, "aucune approbation liée");
  } else if (!Array.isArray(ev.approval.approvers) || !Array.isArray(ev.approval.signatures)) {
    pose("E-9", false, "approvers ou signatures ne sont pas des tableaux");
  } else {
    const A = objetApprobation(ev);
    const erreurs = [];
    try {
      ev.approval.signatures.forEach((sig, i) => {
        const res = verifierSignatureApprobation(A, sig, ev.approval.approvers[i]);
        if (!res.ok) erreurs.push(`signatures[${i}] : ${res.raison}`);
      });
    } catch (err) {
      erreurs.push(err.message);
    }
    pose("E-9", erreurs.length === 0, erreurs.length ? erreurs.join(" ; ") : `${ev.approval.signatures.length} signature(s) d'approbateur recouvrée(s) : ${ev.approval.approvers.join(", ")}`);
  }

  if (!estRotation(ev)) {
    pose("E-10", true, "pas une rotation");
  } else {
    const val = ev.execution?.arguments?.value;
    const erreurs = [];
    if (!val || typeof val !== "object") erreurs.push("annonce de rotation absente");
    else {
      if (val.old_key_id !== ev.recorder_key_id) erreurs.push(`old_key_id ${val.old_key_id} différent de recorder_key_id ${ev.recorder_key_id}`);
      if (val.valid_from !== ev.ts) erreurs.push(`valid_from ${val.valid_from} différent de ts ${ev.ts}`);
      if (val.org_id !== ev.org_id || val.journal_id !== ev.journal_id) erreurs.push("org_id ou journal_id de l'annonce différents de l'enveloppe");
      if (typeof val.new_key_id === "string" && val.new_key_id === val.old_key_id) erreurs.push(`new_key_id ${val.new_key_id} égal à old_key_id`);
      if (!verifierContresignatureRotation(val)) erreurs.push("counter_sig invalide sous new_public_key");
      if (clesMap.size > 0) {
        // CT-1 §8 règle 3 : cles.json annonce valid_from(nouvelle) = valid_to(ancienne) = ts de la rotation.
        const t = msHorodatage(ev.ts);
        const nouvelle = clesMap.get(val.new_key_id);
        if (!nouvelle) erreurs.push(`new_key_id ${val.new_key_id} absent de cles.json`);
        else {
          if (nouvelle.public_key !== val.new_public_key) erreurs.push(`new_public_key différent de la clé ${val.new_key_id} de cles.json`);
          if (nouvelle.valid_from !== null && msHorodatage(nouvelle.valid_from) !== t) erreurs.push(`valid_from de ${val.new_key_id} dans cles.json (${nouvelle.valid_from}) différent du ts de la rotation (${ev.ts})`);
        }
        const ancienne = clesMap.get(val.old_key_id);
        if (ancienne && ancienne.valid_from !== null && (ancienne.valid_to === null || msHorodatage(ancienne.valid_to) !== t)) erreurs.push(`valid_to de ${val.old_key_id} dans cles.json (${ancienne.valid_to}) différent du ts de la rotation (${ev.ts})`);
      }
    }
    pose("E-10", erreurs.length === 0, erreurs.length ? erreurs.join(" ; ") : `rotation ${val.old_key_id} -> ${val.new_key_id} contresignée`);
  }

  const cle = clesMap.get(ev.recorder_key_id);
  if (clesMap.size === 0) nonExecute("E-11", "aucune clé publique fournie");
  else if (!cle) nonExecute("E-11", `clé ${ev.recorder_key_id} absente de cles.json (échec porté par E-8)`);
  else if (cle.valid_from === null && cle.valid_to === null) nonExecute("E-11", "aucune période de validité annoncée");
  else {
    const t = msHorodatage(ev.ts);
    const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
    const a = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
    const ok = !Number.isNaN(t) && !Number.isNaN(de) && !Number.isNaN(a) && t >= de && t <= a;
    pose("E-11", ok, ok ? `ts ${ev.ts} dans la validité de ${ev.recorder_key_id}` : `ts ${ev.ts} hors de [${cle.valid_from ?? "-∞"}, ${cle.valid_to ?? "+∞"}] de la clé ${ev.recorder_key_id}`);
  }
  return r;
}

// ---------------------------------------------------------------------------
// Dossier de preuve (CT-1 §11)
// ---------------------------------------------------------------------------

/** L'index dossier.json : les douze parties, sha256 des fichiers présents, raison des absents. */
export function indexDossier({ evenement, generated_at, fichiers, raisons = {} }) {
  const parts = PARTIES_DOSSIER.map(({ name, file }) => {
    const contenu = fichiers[file];
    if (contenu !== undefined && contenu !== null) return { name, file, sha256: sha256(enOctets(contenu)), present: true, reason_if_absent: null };
    const raison = raisons[name] ?? (PARTIES_RESERVEES.includes(name) ? RAISON_HORS_PERIMETRE : name === "approbations" ? RAISON_AUCUNE_APPROBATION : "partie absente");
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
 * Les parties réservées à CT-4 et CT-5 sont déclarées absentes.
 */
export function assemblerDossier({ evenement, previous = null, next = null, hashesPeriode, manifeste, manifesteSig, cles, approbations = null, generated_at, raisons = {} }) {
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
  /** Aucun contrôle en échec. La validité du dossier exige en plus qu'aucun contrôle ne soit non exécuté sans raison admise (voir terminer). */
  get sansEchec() {
    return this.controles.every((c) => c.ok !== false);
  }
}

/** Vrai si `v` est un objet JSON (ni null, ni tableau). */
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Décrit une valeur JSON pour un message d'erreur. */
const sorteJSON = (v) => (v === null ? "le littéral null" : Array.isArray(v) ? "un tableau" : typeof v);

/**
 * Les contrôles non exécutés qu'un dossier valide ne peut pas avoir (CT-1
 * §11.4) : tout contrôle non exécuté, sauf A-4 (événement de demande hors du
 * dossier) et, quand approbations.json est déclaré absent avec raison, A-2,
 * A-3 et A-4. Les parties réservées à CT-4 et CT-5 n'ont pas de contrôle ici.
 */
function nonExecutesBloquants(rapport, parts) {
  const approbations = parts.find((p) => p && p.name === "approbations");
  const absenteAvecRaison = Boolean(approbations && approbations.present === false && typeof approbations.reason_if_absent === "string" && approbations.reason_if_absent.trim() !== "");
  const admis = (id) => id === "A-4" || (absenteAvecRaison && ["A-2", "A-3", "A-4"].includes(id));
  return rapport.controles.filter((c) => !c.execute && !admis(c.id)).map((c) => c.id);
}

/**
 * Vérifie un dossier v0 (contrôles 1, 2, 3, 6, 7 de l'architecture, soit D-1 à
 * A-4 de CT-1 §11.4). `fichiers` : objet nom de fichier -> octets ou texte, pour
 * les fichiers PRÉSENTS dans le répertoire. `schemas` : registre des trois
 * schémas (registreSchemas). Lève DossierInutilisable si dossier.json manque ou
 * n'est pas du JSON ; sinon rend un rapport { valide, controles,
 * nonExecutesBloquants, evenement, org_id, journal_id, partiesAbsentes, borne }.
 *
 * Une partie présente dont le fichier n'est pas un objet JSON, ou n'est pas
 * conforme à son schéma, met en échec le contrôle qui la porte (dossier.json
 * D-1, evenement.json E-1, enveloppe de voisins.json C-1, chemin.json M-2,
 * manifeste.json P-1, manifeste.sig P-5, cles.json E-8, approbations.json A-1 ;
 * forme canonique impossible E-2) ; les contrôles qui en dépendent sont non
 * exécutés, sans raison admise, et le dossier est invalide.
 *
 * `inexploitables` (facultatif, CT-6 EX-4.11, EX-4.13) : Map nom de fichier ->
 * motif, pour les parties que l'appelant a refusé de lire ou d'analyser (taille
 * au-delà de la limite de la partie, imbrication JSON trop profonde). Une telle
 * partie met en échec le contrôle qui la porte, avec ce motif ; si ses octets ne
 * sont pas dans `fichiers` (fichier non lu), D-2 échoue aussi, son SHA-256
 * n'étant pas vérifiable. Sans cette option, le comportement est celui de CT-1.
 */
export function verifierDossier(fichiers, { schemas, inexploitables = null } = {}) {
  if (!schemas || !schemas[ID_SCHEMA_EVENEMENT] || !schemas[ID_SCHEMA_MANIFESTE] || !schemas[ID_SCHEMA_DOSSIER]) {
    throw new DossierInutilisable("les trois schémas (evenement, manifeste, dossier) sont requis pour vérifier un dossier");
  }
  const rapport = new Rapport();
  const brut = (nom) => (fichiers[nom] === undefined || fichiers[nom] === null ? null : enOctets(fichiers[nom]));
  const refus = (nom) => (inexploitables instanceof Map && inexploitables.has(nom) ? inexploitables.get(nom) : null);
  const nonLu = (nom) => refus(nom) !== null && !brut(nom);
  const indexOctets = brut("dossier.json");
  if (!indexOctets) throw new DossierInutilisable("dossier.json absent : le répertoire n'est pas un dossier de preuve");
  let index;
  try {
    index = analyserJSONStrict(indexOctets);
  } catch (err) {
    throw new DossierInutilisable(`dossier.json illisible : ${err.message}`);
  }
  if (!estObjet(index)) {
    rapport.echec("D-1", `dossier.json : objet JSON attendu, reçu ${sorteJSON(index)}`);
    index = {};
  }

  // D-1 : schéma de l'index (et règle calendaire de generated_at, CT-1 §3).
  const erreursIndex = validerSchema(index, schemas[ID_SCHEMA_DOSSIER], { registre: schemas });
  erreursIndex.push(...horodatagesHorsCalendrier([["/generated_at", index.generated_at]]));
  rapport.resultat("D-1", erreursIndex.length === 0, erreursIndex.length ? `dossier.json : ${resumerErreurs(erreursIndex)}` : "dossier.json conforme au schéma");
  const parts = Array.isArray(index.parts) ? index.parts : [];
  const partie = (name) => parts.find((p) => p && p.name === name);
  if (parts.length !== PARTIES_DOSSIER.length) {
    for (const c of rapport.controles) if (c.id !== "D-1") rapport.nonExecute(c.id, "index inexploitable");
    return terminer(rapport, index, null, parts);
  }

  // D-2 : les fichiers tels qu'ils sont dans le répertoire.
  for (const { name, file } of PARTIES_DOSSIER) {
    const p = partie(name);
    const o = brut(file);
    if (!p) {
      rapport.echec("D-2", `partie ${name} absente de l'index`);
      continue;
    }
    if (p.present === true) {
      if (nonLu(file)) rapport.echec("D-2", `${file} non lu (${refus(file)}) : SHA-256 non vérifiable`);
      else if (!o) rapport.echec("D-2", `${file} déclaré présent mais absent du répertoire`);
      else if (sha256(o) !== p.sha256) rapport.echec("D-2", `${file} : SHA-256 ${sha256(o)} différent de l'index ${p.sha256}`);
      else rapport.succes("D-2");
    } else {
      if (o || nonLu(file)) rapport.echec("D-2", `${file} déclaré absent mais présent dans le répertoire`);
      else if (typeof p.reason_if_absent !== "string" || !p.reason_if_absent.trim()) rapport.echec("D-2", `${file} absent sans raison`);
      else rapport.succes("D-2");
    }
  }

  // Lecture stricte des parties JSON : chaque partie présente doit être un objet
  // JSON. L'échec est imputé au contrôle qui porte la partie (E-2 quand c'est
  // la forme canonique qui est en cause).
  const lire = (file, controle) => {
    if (refus(file) !== null) {
      rapport.echec(controle, `${file} : ${refus(file)} ; la partie est inexploitable`);
      return null;
    }
    const o = brut(file);
    if (!o) return null;
    let valeur;
    try {
      valeur = analyserJSONStrict(o);
    } catch (err) {
      rapport.echec(err instanceof ErreurJSON && err.canonique ? "E-2" : controle, `${file} : ${err.message}`);
      return null;
    }
    if (!estObjet(valeur)) {
      rapport.echec(controle, `${file} : objet JSON attendu, reçu ${sorteJSON(valeur)} ; la partie est inexploitable`);
      return null;
    }
    return valeur;
  };
  const evenement = lire("evenement.json", "E-1");
  const voisins = lire("voisins.json", "C-1");
  const chemin = lire("chemin.json", "M-2");
  const manifeste = lire("manifeste.json", "P-1");
  const manifesteSig = lire("manifeste.sig", "P-5");
  const clesDoc = lire("cles.json", "E-8");
  const approbations = brut("approbations.json") || refus("approbations.json") !== null ? lire("approbations.json", "A-1") : null;

  if (evenement) {
    if (index.event?.seq !== evenement.seq || index.event?.hash !== evenement.hash) rapport.echec("D-1", `event de l'index (seq ${index.event?.seq}, ${index.event?.hash}) différent de evenement.json (seq ${evenement.seq}, ${evenement.hash})`);
    if (index.org_id !== evenement.org_id || index.journal_id !== evenement.journal_id) rapport.echec("D-1", "org_id ou journal_id de l'index différents de evenement.json");
  }

  // Schémas des fichiers compagnons ; l'échec de lecture a déjà été imputé par lire().
  const schemaDossier = schemas[ID_SCHEMA_DOSSIER];
  const valider = (valeur, controle, file, fragment, document = schemaDossier, filtre = () => true, poserSucces = true) => {
    if (valeur === null) return false;
    const erreurs = validerSchema(valeur, document, { registre: schemas, fragment }).filter(filtre);
    if (erreurs.length) rapport.echec(controle, `${file} : ${resumerErreurs(erreurs)}`);
    else if (poserSucces) rapport.succes(controle);
    return erreurs.length === 0;
  };
  if (voisins) {
    // L'enveloppe de voisins.json relève de C-1 ; ses événements, de E-1 à E-11 (plus bas).
    const c1 = [];
    const clesV = Object.keys(voisins).sort();
    if (!egalJSON(clesV, ["next", "previous", "version"])) c1.push(`voisins.json : clés ${JSON.stringify(clesV)}, attendues ["next","previous","version"]`);
    if (voisins.version !== VERSION_FORMAT) c1.push(`voisins.json : version ${JSON.stringify(voisins.version)}, attendu ${VERSION_FORMAT}`);
    for (const nom of ["previous", "next"]) if (voisins[nom] !== null && !estObjet(voisins[nom])) c1.push(`voisins.json : ${nom} doit être un événement ou null`);
    c1.forEach((m) => rapport.echec("C-1", m));
  }
  valider(chemin, "M-2", "chemin.json", "#/$defs/chemin");
  valider(manifeste, "P-1", "manifeste.json", "", schemas[ID_SCHEMA_MANIFESTE]);
  // Le succès de P-5 n'est posé qu'au terme du bloc P-5 : sans clés exploitables, le contrôle reste non exécuté.
  valider(manifesteSig, "P-5", "manifeste.sig", "#/$defs/manifeste_sig", schemaDossier, () => true, false);
  valider(clesDoc, "E-8", "cles.json", "#/$defs/cles");
  if (clesDoc) for (const m of verifierCles(clesDoc, evenement)) rapport.echec("E-8", `cles.json : ${m}`);
  // L'enveloppe de approbations.json relève de A-1 ; le contenu de ses événements, de E-1 à E-11 (plus bas).
  if (approbations) valider(approbations, "A-1", "approbations.json", "#/$defs/approbations", schemaDossier, (e) => !/^\/events\/[0-9]+(\/|$)/.test(e.chemin));
  // Les clés sont employées au mieux même si cles.json est en échec (première occurrence d'un key_id) : le verdict est déjà invalide, le rapport reste informatif.
  const cles = clesDoc && Array.isArray(clesDoc.keys) ? normaliserCles(clesDoc) : new Map();

  // E-1 à E-11 sur chaque événement du dossier.
  const roles = [];
  if (evenement) roles.push({ role: "evenement", ev: evenement });
  if (voisins && estObjet(voisins.previous)) roles.push({ role: "voisin précédent", ev: voisins.previous });
  if (voisins && estObjet(voisins.next)) roles.push({ role: "voisin suivant", ev: voisins.next });
  if (Array.isArray(approbations?.events)) approbations.events.forEach((ev, i) => roles.push({ role: `approbation[${i}]`, ev }));
  for (const { role, ev } of roles) {
    const res = controlesEvenement(ev, { schemas, cles });
    for (const [id, x] of Object.entries(res)) {
      if (!x.execute) rapport.nonExecute(id, `${role} : ${x.detail}`);
      else rapport.resultat(id, x.ok, x.ok ? (id === "E-7" || id === "E-8" ? `${role} : ${x.detail}` : null) : `${role} : ${x.detail}`);
    }
  }
  if (roles.length === 0) for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"]) rapport.nonExecute(id, "aucun événement lisible");

  const hashRecalcule = (ev) => {
    try {
      return hachageEvenement(ev);
    } catch {
      return null;
    }
  };
  const ev = evenement;
  const hashEv = ev ? hashRecalcule(ev) : null;

  // C-1, C-2, C-3 : les voisins.
  if (!ev || !voisins) {
    for (const id of ["C-1", "C-2", "C-3"]) rapport.nonExecute(id, "événement ou voisins inexploitables");
  } else {
    const previous = estObjet(voisins.previous) ? voisins.previous : null;
    const next = estObjet(voisins.next) ? voisins.next : null;
    const c1 = [];
    if (previous === null && ev.seq !== 1) c1.push(`previous null alors que seq = ${ev.seq}`);
    if (previous && ev.seq === 1) c1.push("previous présent alors que seq = 1");
    if (previous && previous.seq !== ev.seq - 1) c1.push(`previous.seq ${previous.seq} différent de seq - 1 (${ev.seq - 1})`);
    if (next && next.seq !== ev.seq + 1) c1.push(`next.seq ${next.seq} différent de seq + 1 (${ev.seq + 1})`);
    if (previous && msHorodatage(previous.ts) > msHorodatage(ev.ts)) c1.push(`ts ${ev.ts} antérieur à previous.ts ${previous.ts}`);
    if (next && msHorodatage(next.ts) < msHorodatage(ev.ts)) c1.push(`next.ts ${next.ts} antérieur à ts ${ev.ts}`);
    for (const [nom, v] of [["previous", previous], ["next", next]]) {
      if (v && (v.org_id !== ev.org_id || v.journal_id !== ev.journal_id)) c1.push(`${nom} : org_id ou journal_id différents`);
    }
    c1.length ? c1.forEach((m) => rapport.echec("C-1", m)) : rapport.succes("C-1", `previous ${previous ? "seq " + previous.seq : "null"}, next ${next ? "seq " + next.seq : "null"}`);

    const c2 = [];
    for (const [nom, v] of [["evenement", ev], ["previous", previous], ["next", next]]) {
      if (v && (v.seq === 1) !== (v.prev_hash === HASH_NUL)) c2.push(`${nom} : prev_hash ${v.prev_hash === HASH_NUL ? "nul" : "non nul"} avec seq ${v.seq}`);
    }
    if (previous) {
      const hp = hashRecalcule(previous);
      if (hp && ev.prev_hash !== hp) c2.push(`prev_hash ${ev.prev_hash} différent du hash recalculé de previous ${hp}`);
    }
    if (next && hashEv && next.prev_hash !== hashEv) c2.push(`next.prev_hash ${next.prev_hash} différent du hash recalculé de l'événement ${hashEv}`);
    c2.length ? c2.forEach((m) => rapport.echec("C-2", m)) : rapport.succes("C-2", "chaînage avec les voisins fournis");

    const c3 = [];
    if (previous && ev.recorder_key_id !== cleSuivanteAttendue(previous)) c3.push(`recorder_key_id ${ev.recorder_key_id}, attendu ${cleSuivanteAttendue(previous)} d'après previous`);
    if (next && next.recorder_key_id !== cleSuivanteAttendue(ev)) c3.push(`next.recorder_key_id ${next.recorder_key_id}, attendu ${cleSuivanteAttendue(ev)}`);
    c3.length ? c3.forEach((m) => rapport.echec("C-3", m)) : rapport.succes("C-3", `clé ${ev.recorder_key_id}${estRotation(ev) ? " puis " + cleSuivanteAttendue(ev) : ""}`);
  }

  // M-1, M-2, M-3 : le chemin.
  if (!chemin) {
    for (const id of ["M-1", "M-2", "M-3"]) rapport.nonExecute(id, "chemin.json inexploitable");
  } else {
    if (hashEv) {
      const feuille = feuilleMerkle(hashEv);
      rapport.resultat("M-1", chemin.leaf_hash === feuille, chemin.leaf_hash === feuille ? `leaf_hash ${feuille}` : `leaf_hash ${chemin.leaf_hash} différent de SHA-256(0x00 || hash recalculé) ${feuille}`);
    } else rapport.nonExecute("M-1", "hash de l'événement incalculable");
    const ok = verifierInclusion(chemin);
    rapport.resultat("M-2", ok, ok ? `chemin de ${chemin.path?.length} nœud(s) mène à la racine (indice ${chemin.leaf_index}, taille ${chemin.tree_size})` : "le chemin ne mène pas à chemin.root pour (leaf_index, tree_size), ou sa longueur est incorrecte");
    if (manifeste && ev) {
      const m3 = [];
      if (chemin.root !== manifeste.root) m3.push(`chemin.root ${chemin.root} différent de manifeste.root ${manifeste.root}`);
      if (chemin.tree_size !== manifeste.count) m3.push(`tree_size ${chemin.tree_size} différent de count ${manifeste.count}`);
      if (chemin.leaf_index !== ev.seq - manifeste.first_seq) m3.push(`leaf_index ${chemin.leaf_index} différent de seq - first_seq (${ev.seq - manifeste.first_seq})`);
      m3.length ? m3.forEach((m) => rapport.echec("M-3", m)) : rapport.succes("M-3", "chemin cohérent avec le manifeste");
    } else rapport.nonExecute("M-3", "manifeste ou événement inexploitable");
  }

  // P-1 à P-5 : le manifeste.
  if (!manifeste) {
    for (const id of ["P-1", "P-2", "P-3", "P-4", "P-5"]) rapport.nonExecute(id, "manifeste.json inexploitable");
  } else {
    const p1 = verifierManifeste(manifeste).filter((m) => !m.includes("racine"));
    if (ev && (manifeste.org_id !== ev.org_id || manifeste.journal_id !== ev.journal_id)) p1.push("org_id ou journal_id différents de ceux de l'événement");
    p1.length ? p1.forEach((m) => rapport.echec("P-1", m)) : rapport.succes("P-1", `période [${manifeste.period_start}, ${manifeste.period_end}), seq ${manifeste.first_seq}..${manifeste.last_seq}`);
    if (ev) {
      const p2 = [];
      if (!(manifeste.first_seq <= ev.seq && ev.seq <= manifeste.last_seq)) p2.push(`seq ${ev.seq} hors de [${manifeste.first_seq}, ${manifeste.last_seq}]`);
      if (!dansPeriode(ev.ts, manifeste.period_start, manifeste.period_end)) p2.push(`ts ${ev.ts} hors de la période`);
      p2.length ? p2.forEach((m) => rapport.echec("P-2", m)) : rapport.succes("P-2", "événement dans la période");
    } else rapport.nonExecute("P-2", "événement inexploitable");
    if (voisins) {
      // P-3 : un voisin dans la période par seq y est aussi par ts ; un voisin hors
      // période est adjacent (first_seq - 1, ts < period_start ; last_seq + 1,
      // ts >= period_end), sinon le manifeste a tronqué sa période (CT-1 §7.2).
      const p3 = [];
      for (const [nom, v] of [["previous", voisins.previous], ["next", voisins.next]]) {
        if (!estObjet(v)) continue;
        if (manifeste.first_seq <= v.seq && v.seq <= manifeste.last_seq) {
          if (!dansPeriode(v.ts, manifeste.period_start, manifeste.period_end)) p3.push(`${nom} (seq ${v.seq}) dans la période par seq mais ts ${v.ts} hors des bornes`);
        } else if (v.seq !== manifeste.first_seq - 1 && v.seq !== manifeste.last_seq + 1) {
          p3.push(`${nom} (seq ${v.seq}) hors période sans être adjacent (${manifeste.first_seq - 1} ou ${manifeste.last_seq + 1})`);
        } else {
          const sec = Math.floor(msHorodatage(v.ts) / 1000);
          const horsPeriode = nom === "previous" ? sec < manifeste.period_start : sec >= manifeste.period_end;
          if (!Number.isNaN(sec) && !horsPeriode) p3.push(`${nom} (seq ${v.seq}) hors de l'intervalle de seq du manifeste mais horodaté ${v.ts}, dans la période : manifeste tronqué`);
        }
      }
      p3.length ? p3.forEach((m) => rapport.echec("P-3", m)) : rapport.succes("P-3", "voisins cohérents avec la période");
    } else rapport.nonExecute("P-3", "voisins inexploitables");
    const p4 = [];
    if ((manifeste.count === 0) !== (manifeste.root === HASH_NUL)) p4.push(manifeste.count === 0 ? "racine non nulle pour une période vide" : "racine nulle pour une période non vide");
    if (!(manifeste.count >= 1)) p4.push(`count ${manifeste.count} : un dossier prouve un événement, la période n'est pas vide`);
    p4.length ? p4.forEach((m) => rapport.echec("P-4", m)) : rapport.succes("P-4", `count ${manifeste.count}, racine ${manifeste.root}`);
    if (!manifesteSig) rapport.nonExecute("P-5", "manifeste.sig inexploitable");
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
      const cle = cles.get(manifesteSig.recorder_key_id);
      let clesInexploitables = false;
      if (cles.size === 0) clesInexploitables = true;
      else if (!cle) p5.push(`clé ${manifesteSig.recorder_key_id} absente de cles.json`);
      else {
        if (ph && !verifierSignatureManifeste(manifeste, manifesteSig, cle.public_key)) p5.push(`signature du manifeste invalide sous ${manifesteSig.recorder_key_id}`);
        const t = msHorodatage(manifeste.generated_at);
        const de = cle.valid_from === null ? -Infinity : msHorodatage(cle.valid_from);
        const a = cle.valid_to === null ? Infinity : msHorodatage(cle.valid_to);
        if (!(t >= de && t <= a)) p5.push(`generated_at ${manifeste.generated_at} hors de la validité de la clé ${manifesteSig.recorder_key_id}`);
      }
      if (p5.length) p5.forEach((m) => rapport.echec("P-5", m));
      else if (clesInexploitables) rapport.nonExecute("P-5", "cles.json inexploitable (E-8) : signature du manifeste non vérifiable");
      else rapport.succes("P-5", `periodHash ${ph} signé par ${manifesteSig.recorder_key_id}`);
    }
  }

  // A-1 à A-4 : les approbations.
  const partieApprobations = partie("approbations");
  if (!ev) {
    for (const id of ["A-1", "A-2", "A-3", "A-4"]) rapport.nonExecute(id, "événement inexploitable");
  } else if (ev.approval === null || ev.approval === undefined) {
    const a1 = [];
    if (approbations || brut("approbations.json") || nonLu("approbations.json")) a1.push("approbations.json présent alors que approval est null");
    if (partieApprobations?.present === false && partieApprobations.reason_if_absent !== RAISON_AUCUNE_APPROBATION) a1.push(`raison d'absence « ${partieApprobations.reason_if_absent} », attendue « ${RAISON_AUCUNE_APPROBATION} »`);
    a1.length ? a1.forEach((m) => rapport.echec("A-1", m)) : rapport.succes("A-1", "aucune approbation liée, partie absente avec sa raison");
    for (const id of ["A-2", "A-3", "A-4"]) rapport.nonExecute(id, "aucune approbation liée");
  } else if (!approbations) {
    rapport.echec("A-1", "approval non nul mais approbations.json absent ou inexploitable");
    for (const id of ["A-2", "A-3", "A-4"]) rapport.nonExecute(id, "approbations.json absent ou inexploitable");
  } else {
    const app = ev.approval;
    const a1 = [];
    if (approbations.ticket !== app.ticket) a1.push(`ticket ${approbations.ticket} différent de approval.ticket ${app.ticket}`);
    if (approbations.request_hash !== app.request_hash) a1.push(`request_hash ${approbations.request_hash} différent de approval.request_hash ${app.request_hash}`);
    a1.length ? a1.forEach((m) => rapport.echec("A-1", m)) : rapport.succes("A-1", `ticket ${app.ticket}`);

    const events = Array.isArray(approbations.events) ? approbations.events : [];
    const a2 = [];
    if (events.length === 0) a2.push("aucun événement de décision");
    const evEstDecision = estDecisionApprobation(ev);
    events.forEach((d, i) => {
      if (d?.execution?.tool !== OUTIL_APPROBATION) a2.push(`events[${i}] : execution.tool ${d?.execution?.tool} au lieu de ${OUTIL_APPROBATION}`);
      if (!egalJSON(d?.approval, app)) a2.push(`events[${i}] : approval différent de celui de l'événement prouvé`);
      if (!egalJSON(d?.execution?.arguments?.value, objetApprobation(ev))) a2.push(`events[${i}] : execution.arguments.value différent de A`);
      if (!evEstDecision && !(Number.isInteger(d?.seq) && d.seq < ev.seq)) a2.push(`events[${i}] : seq ${d?.seq} n'est pas antérieur à celui de l'appel relayé (${ev.seq})`);
    });
    if (!evEstDecision) {
      const tAt = msHorodatage(app.at);
      const tEv = msHorodatage(ev.ts);
      if (!Number.isNaN(tAt) && !Number.isNaN(tEv) && tAt > tEv) a2.push(`approval.at ${app.at} postérieur au ts de l'appel relayé ${ev.ts}`);
    } else if (hashEv && !events.some((d) => hashRecalcule(d) === hashEv)) a2.push("l'événement prouvé est une décision mais ne figure pas dans events");
    a2.length ? a2.forEach((m) => rapport.echec("A-2", m)) : rapport.succes("A-2", `${events.length} événement(s) de décision cohérent(s)`);

    const a3 = [];
    const jeu = approbations.approver_set ?? {};
    const membres = Array.isArray(jeu.members) ? jeu.members : [];
    const jeuMembres = new Set(membres);
    const approvers = Array.isArray(app.approvers) ? app.approvers : [];
    if (new Set(approvers).size !== approvers.length) a3.push("approbateur en double");
    for (const a of approvers) if (!jeuMembres.has(a)) a3.push(`approbateur ${a} hors du jeu déclaré`);
    if (!egalJSON(app.threshold, jeu.threshold)) a3.push(`threshold de l'événement ${JSON.stringify(app.threshold)} différent de celui du jeu ${JSON.stringify(jeu.threshold)}`);
    if (!(jeu.threshold?.required <= jeu.threshold?.size && jeu.threshold?.size === membres.length)) a3.push(`seuil ${jeu.threshold?.required}/${jeu.threshold?.size} incohérent avec ${membres.length} membre(s)`);
    if (app.decision === "expire") {
      if (approvers.length !== 0) a3.push("décision expirée avec des approbateurs");
    } else if (approvers.length < (app.threshold?.required ?? Infinity)) a3.push(`${approvers.length} approbateur(s) pour un seuil de ${app.threshold?.required}`);
    a3.length ? a3.forEach((m) => rapport.echec("A-3", m)) : rapport.succes("A-3", `${approvers.length} approbateur(s) distinct(s) sur un seuil de ${app.threshold?.required}/${app.threshold?.size}`);

    const candidats = [voisins?.previous, voisins?.next].filter((v) => estObjet(v));
    const demande = candidats.find((v) => hashRecalcule(v) === app.request_hash);
    if (!demande) rapport.nonExecute("A-4", `événement de demande (request_hash ${app.request_hash}) absent du dossier : non vérifiable`);
    else if (demande.execution?.status !== "retenue") rapport.echec("A-4", `événement de demande seq ${demande.seq} avec status ${demande.execution?.status}, attendu retenue`);
    else rapport.succes("A-4", `événement de demande seq ${demande.seq} retenu, hash égal à request_hash`);
  }

  return terminer(rapport, index, ev, parts);
}

function terminer(rapport, index, ev, parts) {
  const partiesAbsentes = parts.filter((p) => p && p.present === false).map((p) => ({ name: p.name, file: p.file, reason: p.reason_if_absent ?? null }));
  const reserveesAbsentes = partiesAbsentes.filter((p) => PARTIES_RESERVEES.includes(p.name));
  const borne = reserveesAbsentes.length
    ? `verdict borné : sans ${reserveesAbsentes.map((p) => p.file).join(", ")}, rien n'est prouvé sur la date de l'événement (contrôles 4 et 5, CT-5) ni sur son ancrage dans le registre (contrôle 8, CT-4) ; ce dossier établit au plus que l'événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste signé par cette clé, et approuvé par ces adresses`
    : null;
  const bloquants = nonExecutesBloquants(rapport, parts);
  return {
    valide: rapport.sansEchec && bloquants.length === 0,
    controles: rapport.controles.map((c) => ({ id: c.id, libelle: c.libelle, architecture: c.architecture, ok: c.ok, execute: c.execute, detail: c.details.join(" ; ") || null })),
    nonExecutesBloquants: bloquants,
    // Rien n'est repris de l'index à la place d'un evenement.json inexploitable.
    evenement: ev ? { seq: ev.seq, hash: ev.hash, ts: ev.ts, tool: ev.execution?.tool ?? null } : null,
    org_id: index.org_id ?? null,
    journal_id: index.journal_id ?? null,
    partiesAbsentes,
    borne,
  };
}

/** Les identifiants des contrôles en échec d'un rapport, dans l'ordre du rapport. */
export function controlesEnEchec(rapport) {
  return rapport.controles.filter((c) => c.ok === false).map((c) => c.id);
}
