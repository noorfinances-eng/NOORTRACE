// Événement v0 (CT-1 §5), hachage et signature d'un événement (§6.1, §6.2),
// objet d'approbation et sa signature EIP-191 (§6.3), références de charge
// utile et rédaction (§5.4).

import { concatener, estHex, hexVersOctets, octetsVersHex } from "./conventions.mjs";
import { jcs, jcsOctets } from "./json-strict.mjs";
import { PREFIXES, sha256, sha256Hex, signerEd25519, signerEip191, verifierEd25519 } from "./hachage.mjs";

// Le hachage et la signature portent sur l'objet en mémoire : la borne de
// profondeur de CT-1 §4 (règle 7) s'applique à la lecture et à E-1, non ici.
const SANS_BORNE = Object.freeze({ profondeurMax: Infinity });

/** Les quatre noms réservés de l'espace `noortrace.` (CT-1 §5.1). */
export const NOMS_RESERVES = Object.freeze({
  ECHANGE: "noortrace.modele.echange",
  DECISION: "noortrace.approbation.decision",
  ROTATION: "noortrace.journal.rotation-cle",
  POLITIQUE: "noortrace.journal.politique",
});

const RESERVES = new Set(Object.values(NOMS_RESERVES));

/** Les dix-sept clés d'un événement, dans l'ordre de CT-1 §5.1. */
export const CLES_EVENEMENT = Object.freeze([
  "version", "seq", "ts", "org_id", "journal_id", "recorder_key_id", "prev_hash",
  "delegation", "code", "intent", "policy", "approval", "execution", "effects", "context",
  "hash", "sig",
]);

/**
 * Sorte d'un événement d'après `execution.tool` : `appel_outil`, `echange`,
 * `decision`, `rotation`, `politique`, ou `reserve_inconnu` (nom en
 * `noortrace.` hors des quatre réservés, E-3) ; null si l'outil n'est pas lisible.
 * @param {object} evenement
 * @returns {string|null}
 */
export function sorteEvenement(evenement) {
  const outil = evenement?.execution?.tool;
  if (typeof outil !== "string") return null;
  switch (outil) {
    case NOMS_RESERVES.ECHANGE: return "echange";
    case NOMS_RESERVES.DECISION: return "decision";
    case NOMS_RESERVES.ROTATION: return "rotation";
    case NOMS_RESERVES.POLITIQUE: return "politique";
    default: return outil.startsWith("noortrace.") ? "reserve_inconnu" : "appel_outil";
  }
}

/**
 * Dit si un nom d'outil est l'un des quatre noms réservés.
 * @param {string} outil
 * @returns {boolean}
 */
export function estNomReserve(outil) {
  return RESERVES.has(outil);
}

/**
 * Corps E' d'un événement : l'objet privé de `hash` et `sig` (CT-1 §6.1).
 * @param {object} evenement
 * @returns {object}
 */
export function corpsEvenement(evenement) {
  if (evenement === null || typeof evenement !== "object" || Array.isArray(evenement)) {
    throw new TypeError("événement : objet attendu");
  }
  const { hash, sig, ...corps } = evenement;
  return corps;
}

/**
 * Forme canonique C = JCS(E') d'un événement.
 * @param {object} evenement
 * @returns {string}
 */
export function formeCanoniqueEvenement(evenement) {
  return jcs(corpsEvenement(evenement), SANS_BORNE);
}

/**
 * Hachage d'un événement : SHA-256(P_H || JCS(E')), hexadécimal préfixé.
 * @param {object} evenement
 * @returns {string}
 */
export function hacherEvenement(evenement) {
  return sha256Hex(concatener(PREFIXES.P_H, jcsOctets(corpsEvenement(evenement), SANS_BORNE)));
}

/**
 * Message signé d'un événement : P_S || JCS(E').
 * @param {object} evenement
 * @returns {Uint8Array}
 */
export function messageSignatureEvenement(evenement) {
  return concatener(PREFIXES.P_S, jcsOctets(corpsEvenement(evenement), SANS_BORNE));
}

/**
 * Scelle un événement : calcule `hash` et `sig` (Ed25519 de la graine de
 * `recorder_key_id`) et rend une copie aux dix-sept clés.
 * @param {object} evenement événement, avec ou sans `hash` et `sig`
 * @param {Uint8Array} graine clé privée Ed25519 de 32 octets
 * @returns {object}
 */
export function scellerEvenement(evenement, graine) {
  const corps = corpsEvenement(evenement);
  return {
    ...corps,
    hash: hacherEvenement(corps),
    sig: octetsVersHex(signerEd25519(graine, messageSignatureEvenement(corps))),
  };
}

/**
 * Vérifie `sig` d'un événement sous une clé publique Ed25519 (CT-1 §6.2).
 * @param {object} evenement
 * @param {Uint8Array} clePublique 32 octets
 * @returns {boolean}
 */
export function verifierSignatureEvenement(evenement, clePublique) {
  if (!estHex(evenement?.sig, 64)) return false;
  let message;
  try {
    message = messageSignatureEvenement(evenement);
  } catch {
    return false;
  }
  return verifierEd25519(clePublique, message, hexVersOctets(evenement.sig));
}

// ------------------------------------------------------------ approbation

/**
 * Objet signé par les approbateurs, A = { decision, journal_id, org_id,
 * request_hash, ticket } (CT-1 §5.3, §6.3), tiré du champ `approval` et de
 * l'enveloppe d'un événement.
 * @param {object} evenement événement dont `approval` n'est pas null
 * @returns {{decision: string, journal_id: string, org_id: string, request_hash: string, ticket: string}}
 */
export function objetApprobation(evenement) {
  const a = evenement?.approval;
  if (a === null || typeof a !== "object") throw new TypeError("événement sans approbation");
  return {
    decision: a.decision,
    journal_id: evenement.journal_id,
    org_id: evenement.org_id,
    request_hash: a.request_hash,
    ticket: a.ticket,
  };
}

/**
 * Condensé d'approbation D_A = SHA-256(P_A || JCS(A)).
 * @param {object} A
 * @returns {Uint8Array} 32 octets
 */
export function condenseApprobation(A) {
  return sha256(concatener(PREFIXES.P_A, jcsOctets(A, SANS_BORNE)));
}

/**
 * Signature EIP-191 d'un approbateur sur D_A (CT-1 §6.3).
 * @param {Uint8Array} clePrivee clé secp256k1 de 32 octets
 * @param {object} A
 * @returns {string} 65 octets en hexadécimal préfixé
 */
export function signerApprobation(clePrivee, A) {
  return octetsVersHex(signerEip191(clePrivee, condenseApprobation(A)));
}

// ------------------------------------------------------------- références

/**
 * Référence à une pièce stockée (CT-1 §5.4) : SHA-256 et longueur de ses
 * octets, drapeau de rédaction, type de média facultatif (absent, jamais null).
 * @param {Uint8Array} octets la pièce telle qu'elle est stockée
 * @param {{redacted?: boolean, media_type?: string}} [options]
 * @returns {{sha256: string, length: number, redacted: boolean, media_type?: string}}
 */
export function creerReference(octets, options = {}) {
  const ref = { sha256: sha256Hex(octets), length: octets.length, redacted: options.redacted === true };
  if (options.media_type !== undefined) ref.media_type = options.media_type;
  return ref;
}

/**
 * Référence en ligne : la pièce est JCS(value) en UTF-8 (CT-1 §5.4).
 * @param {unknown} value valeur JSON conforme à JCS v0
 * @param {{media_type?: string}} [options]
 * @returns {{sha256: string, length: number, redacted: false, value: unknown}}
 */
export function creerReferenceEnLigne(value, options = {}) {
  const octets = jcsOctets(value, SANS_BORNE);
  const ref = { sha256: sha256Hex(octets), length: octets.length, redacted: false };
  if (options.media_type !== undefined) ref.media_type = options.media_type;
  ref.value = value;
  return ref;
}

/**
 * Dit si une référence en ligne est juste : sha256 et length de JCS(value)
 * (contrôle E-6). Une référence sans `value` rend true.
 * @param {object} ref
 * @returns {boolean}
 */
export function verifierReferenceEnLigne(ref) {
  if (ref === null || typeof ref !== "object" || !("value" in ref)) return true;
  try {
    const octets = jcsOctets(ref.value, SANS_BORNE);
    return ref.sha256 === sha256Hex(octets) && ref.length === octets.length;
  } catch {
    return false;
  }
}

/**
 * Dit si des octets fournis à part sont la pièce d'une référence (E-6).
 * @param {object} ref
 * @param {Uint8Array} octets
 * @returns {boolean}
 */
export function verifierPiece(ref, octets) {
  return ref?.sha256 === sha256Hex(octets) && ref?.length === octets.length;
}

function estReference(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && "sha256" in v && "length" in v && "redacted" in v;
}

/**
 * Toutes les références d'un événement, avec leur emplacement : `intent`
 * (s'il est une référence), `execution.arguments`, `execution.result`,
 * `context[i]`.
 * @param {object} evenement
 * @returns {{chemin: string, reference: object}[]}
 */
export function referencesEvenement(evenement) {
  const sortie = [];
  if (estReference(evenement?.intent)) sortie.push({ chemin: "intent", reference: evenement.intent });
  const x = evenement?.execution;
  if (estReference(x?.arguments)) sortie.push({ chemin: "execution.arguments", reference: x.arguments });
  if (estReference(x?.result)) sortie.push({ chemin: "execution.result", reference: x.result });
  if (Array.isArray(evenement?.context)) {
    evenement.context.forEach((c, k) => {
      if (estReference(c)) sortie.push({ chemin: `context[${k}]`, reference: c });
    });
  }
  return sortie;
}
