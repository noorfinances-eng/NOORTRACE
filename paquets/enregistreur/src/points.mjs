// Points de contrôle (CT-1 §10.5, CT-2 §12.10, révision 0.4). L'écrivain
// produit un point à chaque instant `period_start + j × checkpoint_interval_s`
// (à 1 s près), qu'un événement ait été écrit ou non, et un point de clôture
// qui engage exactement les feuilles du manifeste (EX-12.24). Chaque point est
// signé par la clé en vigueur, chaîné au précédent de la période
// (`prev_checkpoint_hash`), construit après la dernière écriture durable
// qu'il engage (EX-12.25), écrit en ajout seul et synchronisé dans
// `points/periode-<period_start>.ndjson`, une ligne JCS intégral par point
// (EX-12.26), puis remis au composant d'ancrage sans attendre (EX-12.27).

import fs from "node:fs/promises";
import path from "node:path";
import { ZERO32, ecrireHorodatage, hacherPoint, messageSignaturePoint, octetsVersHex, racineMerkle, decoderHorodatage } from "@noortrace/noyau";
import { jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { decouperLignes, tronquer } from "./fichiers.mjs";

/** Cadence par défaut (15.1). */
export const INTERVALLE_DEFAUT = 60;

/** Tolérance d'alignement : 1 s (CT-1 §10.5 règle 1). */
export const TOLERANCE_MS = 1000;

/**
 * Nom du fichier de la série d'une période.
 * @param {number} periodStart secondes UNIX
 * @returns {string}
 */
export function nomSerie(periodStart) {
  return `periode-${String(periodStart).padStart(10, "0")}.ndjson`;
}

/**
 * Dit si une cadence est admise (EX-12.24, EX-15.4 pas 3) : diviseur de 3600
 * entre 10 et 3600.
 * @param {number} s
 */
export function cadenceAdmise(s) {
  return Number.isSafeInteger(s) && s >= 10 && s <= 3600 && 3600 % s === 0;
}

/**
 * Corps d'un point (onze clés, sans `sig`), dans l'ordre de CT-1 §10.5.
 * @param {{org_id: string, journal_id: string, period_start: number, hashes: string[], tree_size: number,
 *   first_seq: number, hash_avant: string, checkpoint_ts: number, prev_checkpoint_hash: string, key_id: string}} p
 *   `hashes` : hash des événements de la période connus ; `hash_avant` : hash de l'événement first_seq − 1 (ou nul)
 * @returns {object}
 */
export function corpsPointDeControle(p) {
  const n = p.tree_size;
  return {
    version: 0,
    org_id: p.org_id,
    journal_id: p.journal_id,
    period_start: p.period_start,
    tree_size: n,
    root: racineMerkle(p.hashes.slice(0, n)),
    last_seq: p.first_seq + n - 1,
    last_hash: n === 0 ? p.hash_avant : p.hashes[n - 1],
    checkpoint_ts: ecrireHorodatage(p.checkpoint_ts),
    prev_checkpoint_hash: p.prev_checkpoint_hash,
    key_id: p.key_id,
  };
}

/**
 * Signe un point par le signataire (interface d'EX-11.18).
 * @param {object} corps
 * @param {{signer: (keyId: string, message: Uint8Array) => Promise<Uint8Array>}} signataire
 * @returns {Promise<object>} le point aux douze clés
 */
export async function signerPointDeControle(corps, signataire) {
  const sig = await signataire.signer(corps.key_id, messageSignaturePoint(corps));
  return { ...corps, sig: octetsVersHex(sig) };
}

/**
 * Prochain indice d'instant aligné à produire après un instant donné.
 * @param {number} periodStartMs
 * @param {number} intervalleS
 * @param {number} instantMs
 * @returns {number} j tel que period_start + j × intervalle > instant
 */
export function indiceSuivant(periodStartMs, intervalleS, instantMs) {
  return Math.floor((instantMs - periodStartMs) / (intervalleS * 1000)) + 1;
}

/**
 * Instant aligné à produire maintenant, s'il y en a un (EX-12.24) : l'indice
 * `j ≥ prochainJ` tel que `instant_j ≤ maintenant ≤ instant_j + 1 s`. Un
 * instant manqué n'est pas rattrapé.
 * @param {number} periodStartMs
 * @param {number} intervalleS
 * @param {number} prochainJ
 * @param {number} maintenant
 * @returns {{j: number|null, prochainJ: number}}
 */
export function instantAligne(periodStartMs, intervalleS, prochainJ, maintenant) {
  const pas = intervalleS * 1000;
  const nb = 3600 / intervalleS;
  const j = Math.floor((maintenant - periodStartMs) / pas);
  if (j < prochainJ || j >= nb) return { j: null, prochainJ };
  if (maintenant - (periodStartMs + j * pas) <= TOLERANCE_MS) return { j, prochainJ: j + 1 };
  // Instant j manqué : le suivant est j + 1.
  return { j: null, prochainJ: j + 1 };
}

/**
 * Relit la série d'une période (EX-12.28 : un écrivain qui reprend chaîne son
 * premier point au dernier écrit) ; une dernière ligne incomplète est coupée.
 * @param {string} chemin
 * @returns {Promise<object[]>}
 */
export async function relireSerie(chemin) {
  let octets;
  try {
    octets = new Uint8Array(await fs.readFile(chemin));
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  const points = [];
  const lignes = decouperLignes(octets);
  for (let k = 0; k < lignes.length; k++) {
    const l = lignes[k];
    let p = null;
    try {
      if (l.complete) p = analyserJsonIntegral(l.octets);
    } catch {
      p = null;
    }
    if (p === null) {
      if (k === lignes.length - 1) {
        await tronquer(chemin, l.debut);
        break;
      }
      throw new Error(`série de points corrompue : ${path.basename(chemin)}, ligne ${k + 1}`);
    }
    points.push(p);
  }
  return points;
}

/**
 * État de la série d'une période relue : hash du dernier point, son
 * instant, le prochain indice aligné.
 * @param {object[]} points
 * @param {number} periodStartMs
 * @param {number} intervalleS
 * @returns {{prev: string, dernierTs: number|null, dernierTreeSize: number, prochainJ: number}}
 */
export function etatSerie(points, periodStartMs, intervalleS) {
  const dernier = points[points.length - 1];
  if (!dernier) return { prev: ZERO32, dernierTs: null, dernierTreeSize: 0, prochainJ: 0 };
  const ts = decoderHorodatage(dernier.checkpoint_ts);
  return { prev: hacherPoint(dernier), dernierTs: ts, dernierTreeSize: dernier.tree_size, prochainJ: indiceSuivant(periodStartMs, intervalleS, ts) };
}

/**
 * Octets d'une ligne de la série : JCS intégral du point signé, suivi de \n.
 * @param {object} point
 * @returns {Uint8Array}
 */
export function ligneSerie(point) {
  const o = jcsIntegralOctets(point);
  const s = new Uint8Array(o.length + 1);
  s.set(o);
  s[o.length] = 0x0a;
  return s;
}

/**
 * Choix du point d'un dossier (CT-1 §11.2) parmi une série sans ancres : le
 * plus petit `tree_size` strictement supérieur à `leafIndex`, puis le premier
 * de la série.
 * @param {object[]} serie
 * @param {number} leafIndex
 * @returns {object|null}
 */
export function choisirPoint(serie, leafIndex) {
  let retenu = null;
  for (const p of serie) if (p.tree_size > leafIndex && (retenu === null || p.tree_size < retenu.tree_size)) retenu = p;
  return retenu;
}
