// Manifeste de période (CT-1 §10.1 à §10.4) : periodHash, signature portée à
// côté (manifeste.sig), continuité entre deux manifestes, correspondance avec
// PeriodRegistry et empreinte d'ancre.

import { ZERO32, concatener, decoderHorodatage, estHex, hexVersOctets, octetsVersHex } from "./conventions.mjs";
import { jcs, jcsOctets } from "./json-strict.mjs";
import { PREFIXES, keccak256, sha256Hex, signerEd25519, verifierEd25519 } from "./hachage.mjs";
import { racineMerkle } from "./merkle.mjs";
import { validerSchema } from "./schemas.mjs";

/** Durée d'une période : une heure UTC pleine, en secondes. */
export const DUREE_PERIODE = 3600;

/**
 * Forme canonique C_M = JCS(manifeste).
 * @param {object} manifeste
 * @returns {string}
 */
export function formeCanoniqueManifeste(manifeste) {
  return jcs(manifeste);
}

/**
 * periodHash = SHA-256(P_M || JCS(manifeste)) (CT-1 §10.2).
 * @param {object} manifeste
 * @returns {string}
 */
export function hacherManifeste(manifeste) {
  return sha256Hex(concatener(PREFIXES.P_M, jcsOctets(manifeste)));
}

/**
 * Message signé d'un manifeste : P_SM || JCS(manifeste).
 * @param {object} manifeste
 * @returns {Uint8Array}
 */
export function messageSignatureManifeste(manifeste) {
  return concatener(PREFIXES.P_SM, jcsOctets(manifeste));
}

/**
 * Signe un manifeste et rend le contenu de manifeste.sig.
 * @param {object} manifeste
 * @param {Uint8Array} graine graine Ed25519 de la clé `recorder_key_id` du manifeste
 * @returns {{version: 0, period_hash: string, recorder_key_id: string, sig: string}}
 */
export function signerManifeste(manifeste, graine) {
  return {
    version: 0,
    period_hash: hacherManifeste(manifeste),
    recorder_key_id: manifeste.recorder_key_id,
    sig: octetsVersHex(signerEd25519(graine, messageSignatureManifeste(manifeste))),
  };
}

/**
 * Vérifie la signature d'un manifeste sous une clé publique.
 * @param {object} manifeste
 * @param {string} sigHex signature de manifeste.sig
 * @param {Uint8Array} clePublique
 * @returns {boolean}
 */
export function verifierSignatureManifeste(manifeste, sigHex, clePublique) {
  if (!estHex(sigHex, 64)) return false;
  try {
    return verifierEd25519(clePublique, messageSignatureManifeste(manifeste), hexVersOctets(sigHex));
  } catch {
    return false;
  }
}

/**
 * Construit le manifeste d'une période à partir des hash de ses événements.
 * @param {{org_id: string, journal_id: string, period_start: number, first_seq: number, hashes: string[],
 *   prev_period_hash: string, recorder_key_id: string, nonce: string, generated_at: string}} p
 * @returns {object} les treize clés de CT-1 §10.1
 */
export function construireManifeste(p) {
  const count = p.hashes.length;
  return {
    version: 0,
    org_id: p.org_id,
    journal_id: p.journal_id,
    period_start: p.period_start,
    period_end: p.period_start + DUREE_PERIODE,
    first_seq: p.first_seq,
    last_seq: p.first_seq + count - 1,
    count,
    root: racineMerkle(p.hashes),
    prev_period_hash: p.prev_period_hash,
    recorder_key_id: p.recorder_key_id,
    nonce: p.nonce,
    generated_at: p.generated_at,
  };
}

/**
 * Écarts d'un manifeste à ses relations propres (P-1 sans les identifiants de
 * l'événement, P-4) : schéma, période d'une heure, count, racine nulle si et
 * seulement si count = 0, generated_at existant.
 * @param {unknown} manifeste
 * @returns {string[]}
 */
export function ecartsManifeste(manifeste) {
  const ecarts = [];
  const s = validerSchema("manifeste", manifeste);
  if (!s.valide) ecarts.push(...s.erreurs.map((e) => `schéma : ${e}`));
  if (manifeste === null || typeof manifeste !== "object") return ecarts;
  const m = manifeste;
  // org_id et journal_id : n'importe quels 32 octets non nuls (CT-1 §3, §5.2,
  // §10.1 « ceux des événements ») ; le schéma ne l'exprime pas.
  if (m.org_id === ZERO32) ecarts.push("org_id nul");
  if (m.journal_id === ZERO32) ecarts.push("journal_id nul");
  if (Number.isSafeInteger(m.period_start) && m.period_end !== m.period_start + DUREE_PERIODE) {
    ecarts.push(`period_end ${m.period_end} différent de period_start + 3600 (${m.period_start + DUREE_PERIODE})`);
  }
  if (Number.isSafeInteger(m.first_seq) && Number.isSafeInteger(m.last_seq) && m.count !== m.last_seq - m.first_seq + 1) {
    ecarts.push(`count ${m.count} différent de last_seq − first_seq + 1 (${m.last_seq - m.first_seq + 1})`);
  }
  if (decoderHorodatage(m.generated_at) === null) ecarts.push("generated_at : horodatage qui ne se décode pas");
  return ecarts;
}

/**
 * Continuité de deux manifestes consécutifs p puis q du même journal (CT-1
 * §10.3, contrôle P-5 avec un second manifeste).
 * @param {object} p manifeste précédent
 * @param {object} q manifeste suivant
 * @returns {{valide: boolean, erreurs: string[]}}
 */
export function verifierContinuite(p, q) {
  const erreurs = [];
  if (p.org_id !== q.org_id || p.journal_id !== q.journal_id) erreurs.push("manifestes de deux journaux différents");
  if (q.period_start !== p.period_end) {
    erreurs.push(`discontinuité temporelle : period_start ${q.period_start} différent de period_end précédent (${p.period_end})`);
  }
  if (q.first_seq !== p.last_seq + 1) {
    erreurs.push(`discontinuité de séquence : first_seq ${q.first_seq} différent de last_seq précédent + 1 (${p.last_seq + 1})`);
  }
  const hp = hacherManifeste(p);
  if (q.prev_period_hash !== hp) erreurs.push(`prev_period_hash ${q.prev_period_hash} différent du periodHash précédent ${hp}`);
  return { valide: erreurs.length === 0, erreurs };
}

/**
 * Empreinte d'ancre keccak256(org_id || journal_id || empreinte) sur 96
 * octets (CT-1 §10.4 pour periodHash, §10.6 pour checkpointHash).
 * @param {string} orgId
 * @param {string} journalId
 * @param {string} empreinte periodHash ou checkpointHash
 * @returns {string}
 */
export function empreinteAncre(orgId, journalId, empreinte) {
  return octetsVersHex(keccak256(concatener(hexVersOctets(orgId, 32), hexVersOctets(journalId, 32), hexVersOctets(empreinte, 32))));
}

/**
 * Champs de PeriodRegistry.PeriodMeta d'un manifeste (CT-1 §10.4), sans `uri`.
 * @param {object} manifeste
 * @returns {{orgId: string, journalId: string, periodHash: string, root: string, periodStart: number,
 *   periodEnd: number, firstSeq: number, lastSeq: number, version: number}}
 */
export function periodMeta(manifeste) {
  return {
    orgId: manifeste.org_id,
    journalId: manifeste.journal_id,
    periodHash: hacherManifeste(manifeste),
    root: manifeste.root,
    periodStart: manifeste.period_start,
    periodEnd: manifeste.period_end,
    firstSeq: manifeste.first_seq,
    lastSeq: manifeste.last_seq,
    version: manifeste.version,
  };
}

/** Racine d'une période vide (CT-1 §9.2). */
export const RACINE_VIDE = ZERO32;
