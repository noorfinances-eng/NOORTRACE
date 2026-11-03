// Rotation de clé de l'enregistreur (CT-1 §8) : annonce en ligne, signée par
// l'ancienne clé dans l'événement et contresignée par la nouvelle dans le
// corps ; contrôle E-10.

import { concatener, decoderHorodatage, estHex, hexVersOctets, octetsVersHex } from "./conventions.mjs";
import { jcsOctets } from "./json-strict.mjs";
import { PREFIXES, clePubliqueEd25519, signerEd25519, verifierEd25519 } from "./hachage.mjs";
import { NOMS_RESERVES, creerReferenceEnLigne } from "./evenement.mjs";

// Le hachage et la signature portent sur l'objet en mémoire : la borne de
// profondeur de CT-1 §4 (règle 7) s'applique à la lecture et à E-1, non ici.
const SANS_BORNE = Object.freeze({ profondeurMax: Infinity });

const CLES_ANNONCE = ["journal_id", "new_key_id", "new_public_key", "old_key_id", "org_id", "valid_from", "counter_sig"];
const MOTIF_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Corps R d'une annonce de rotation : la valeur privée de `counter_sig`
 * (six clés).
 * @param {object} annonce
 * @returns {object}
 */
export function corpsRotation(annonce) {
  const { counter_sig, ...R } = annonce;
  return R;
}

/**
 * Message contresigné : P_R || JCS(R).
 * @param {object} annonce
 * @returns {Uint8Array}
 */
export function messageRotation(annonce) {
  return concatener(PREFIXES.P_R, jcsOctets(corpsRotation(annonce), SANS_BORNE));
}

/**
 * Construit l'annonce de rotation contresignée par la nouvelle clé.
 * @param {{journal_id: string, org_id: string, old_key_id: string, new_key_id: string, valid_from: string}} champs
 * @param {Uint8Array} graineNouvelle graine Ed25519 de la nouvelle clé
 * @returns {object} les sept clés de CT-1 §8
 */
export function annoncerRotation(champs, graineNouvelle) {
  const R = {
    journal_id: champs.journal_id,
    new_key_id: champs.new_key_id,
    new_public_key: octetsVersHex(clePubliqueEd25519(graineNouvelle)),
    old_key_id: champs.old_key_id,
    org_id: champs.org_id,
    valid_from: champs.valid_from,
  };
  return { ...R, counter_sig: octetsVersHex(signerEd25519(graineNouvelle, messageRotation(R))) };
}

/**
 * Champs `execution` et `effects` d'un événement de rotation (CT-1 §8,
 * règle 4) pour une annonce donnée.
 * @param {object} annonce
 * @returns {{execution: object, effects: object[]}}
 */
export function champsEvenementRotation(annonce) {
  return {
    execution: {
      tool: NOMS_RESERVES.ROTATION,
      arguments: creerReferenceEnLigne(annonce),
      status: "executee",
      result: null,
      duration_ms: null,
      is_error: null,
    },
    effects: [{ system: "noortrace", action: "ecriture", object: `cle:${annonce.new_key_id}`, amount: null, currency: null }],
  };
}

/**
 * Vérifie la contresignature d'une annonce sous `new_public_key`.
 * @param {object} annonce
 * @returns {boolean}
 */
export function verifierContresignature(annonce) {
  if (!estHex(annonce?.new_public_key, 32) || !estHex(annonce?.counter_sig, 64)) return false;
  try {
    return verifierEd25519(hexVersOctets(annonce.new_public_key), messageRotation(annonce), hexVersOctets(annonce.counter_sig));
  } catch {
    return false;
  }
}

/**
 * Lit l'annonce d'un événement de rotation si elle a la forme de CT-1 §8
 * (sept clés, types attendus), sinon null.
 * @param {object} evenement
 * @returns {object|null}
 */
export function annonceRotation(evenement) {
  const v = evenement?.execution?.arguments?.value;
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const cles = Object.keys(v);
  if (cles.length !== CLES_ANNONCE.length || !CLES_ANNONCE.every((c) => cles.includes(c))) return null;
  if (!MOTIF_ID.test(String(v.new_key_id)) || !MOTIF_ID.test(String(v.old_key_id))) return null;
  if (typeof v.new_key_id !== "string" || typeof v.old_key_id !== "string" || typeof v.valid_from !== "string") return null;
  return v;
}

/**
 * Contrôle E-10 d'un événement de rotation : annonce cohérente avec
 * l'enveloppe, identifiants distincts, contresignature valide et, si cles.json
 * est exploitable, clé publique et validités annoncées (CT-1 §8, règle 3).
 * @param {object} evenement
 * @param {{exploitable: boolean, cles: Map<string, object>}|null} indexCles
 * @returns {string[]} les écarts ; vide si le contrôle réussit
 */
export function ecartsRotation(evenement, indexCles) {
  const ecarts = [];
  const a = annonceRotation(evenement);
  if (!a) return ["annonce de rotation absente ou mal formée (sept clés de CT-1 §8 attendues)"];
  if (a.old_key_id !== evenement.recorder_key_id) ecarts.push(`old_key_id ${a.old_key_id} différent de recorder_key_id ${evenement.recorder_key_id}`);
  const tsEvt = decoderHorodatage(evenement.ts);
  const tsAnnonce = decoderHorodatage(a.valid_from);
  if (tsAnnonce === null || tsAnnonce !== tsEvt) ecarts.push(`valid_from ${a.valid_from} différent du ts de l'événement ${evenement.ts}`);
  if (a.org_id !== evenement.org_id) ecarts.push("org_id de l'annonce différent de celui de l'événement");
  if (a.journal_id !== evenement.journal_id) ecarts.push("journal_id de l'annonce différent de celui de l'événement");
  if (a.new_key_id === a.old_key_id) ecarts.push("new_key_id identique à old_key_id");
  if (!verifierContresignature(a)) ecarts.push(`contresignature invalide sous new_public_key de ${a.new_key_id}`);
  if (indexCles?.exploitable) {
    const nouvelle = indexCles.cles.get(a.new_key_id);
    const ancienne = indexCles.cles.get(a.old_key_id);
    if (!nouvelle) {
      ecarts.push(`cles.json ne porte pas la clé ${a.new_key_id}`);
    } else {
      if (nouvelle.public_key !== a.new_public_key) ecarts.push(`cles.json : clé publique de ${a.new_key_id} différente de new_public_key`);
      if (nouvelle.debut !== tsEvt) ecarts.push(`cles.json : valid_from de ${a.new_key_id} différent du ts de la rotation`);
    }
    if (ancienne && ancienne.fin !== tsEvt) ecarts.push(`cles.json : valid_to de ${a.old_key_id} différent du ts de la rotation`);
  }
  return ecarts;
}
