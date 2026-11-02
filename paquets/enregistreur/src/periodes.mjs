// Périodes et clôture (CT-1 §9, §10 ; CT-2 §3.1 « Clôture de période »,
// EX-7.11, EX-9.3). Toutes les heures UTC, l'écrivain clôt la période :
// point de clôture (12.10), arbre de Merkle des événements de la période,
// manifeste, signature par la clé en vigueur à la clôture, fichiers
// `manifestes/periode-<period_start>.json` et `.sig` (12.1). Une période sans
// événement a son manifeste (racine nulle, CT-1 §9.2) : la continuité de
// CT-1 §10.3 l'exige. La clôture n'est pas un événement de la chaîne (9.1).
//
// Le nonce est un aléa frais par manifeste (CT-1 §10.1) ; la fabrique est
// injectable pour les vecteurs.

import fs from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import {
  DUREE_PERIODE, ZERO32, construireManifeste, ecrireHorodatage, hacherManifeste, messageSignatureManifeste,
  octetsVersHex, analyserJson,
} from "@noortrace/noyau";

/**
 * Début de la période (heure UTC pleine) qui contient un instant.
 * @param {number} instantMs
 * @returns {number} secondes UNIX
 */
export function debutPeriode(instantMs) {
  return Math.floor(instantMs / 1000 / DUREE_PERIODE) * DUREE_PERIODE;
}

/**
 * Nom des fichiers d'une période : `periode-<period_start sur 10 chiffres>`.
 * @param {number} periodStart
 * @returns {{manifeste: string, signature: string}}
 */
export function nomsManifeste(periodStart) {
  const base = `periode-${String(periodStart).padStart(10, "0")}`;
  return { manifeste: `${base}.json`, signature: `${base}.sig` };
}

/** Nonce frais par manifeste (CT-1 §10.1). */
export function nonceAleatoire() {
  return octetsVersHex(new Uint8Array(randomBytes(32)));
}

/**
 * Construit et signe le manifeste d'une période (CT-1 §10.1, §10.2).
 * @param {{org_id: string, journal_id: string, period_start: number, first_seq: number, hashes: string[],
 *   prev_period_hash: string, recorder_key_id: string, nonce: string, generated_at: number}} p
 * @param {{signer: (keyId: string, message: Uint8Array) => Promise<Uint8Array>}} signataire
 * @returns {Promise<{manifeste: object, signature: object, periodHash: string}>}
 */
export async function construireEtSignerManifeste(p, signataire) {
  const manifeste = construireManifeste({ ...p, generated_at: ecrireHorodatage(p.generated_at) });
  const sig = await signataire.signer(manifeste.recorder_key_id, messageSignatureManifeste(manifeste));
  const periodHash = hacherManifeste(manifeste);
  const signature = { version: 0, period_hash: periodHash, recorder_key_id: manifeste.recorder_key_id, sig: octetsVersHex(sig) };
  return { manifeste, signature, periodHash };
}

/**
 * Octets d'un fichier JSON de période ou de dossier : `JSON.stringify(objet,
 * null, 2)` suivi d'un saut de ligne, la mise en forme des vecteurs de CT-1
 * (§11.1) ; l'exportateur copie ces octets tels quels.
 * @param {object} objet
 * @returns {Uint8Array}
 */
export function octetsJsonLisible(objet) {
  return new TextEncoder().encode(JSON.stringify(objet, null, 2) + "\n");
}

/**
 * Relit le dernier manifeste d'un journal (plus grand `period_start`).
 * @param {string} repertoire `manifestes/`
 * @returns {Promise<{manifeste: object, periodHash: string, chemin: string}|null>}
 */
export async function dernierManifeste(repertoire) {
  let noms;
  try {
    noms = (await fs.readdir(repertoire)).filter((n) => /^periode-[0-9]{10}\.json$/.test(n)).sort();
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
  if (!noms.length) return null;
  const chemin = path.join(repertoire, noms[noms.length - 1]);
  const manifeste = analyserJson(new Uint8Array(await fs.readFile(chemin)));
  return { manifeste, periodHash: hacherManifeste(manifeste), chemin };
}

/**
 * Lit le manifeste et la signature d'une période, ou null.
 * @param {string} repertoire
 * @param {number} periodStart
 * @returns {Promise<{manifeste: object, signature: object, octetsManifeste: Uint8Array, octetsSignature: Uint8Array}|null>}
 */
export async function lireManifeste(repertoire, periodStart) {
  const noms = nomsManifeste(periodStart);
  try {
    const octetsManifeste = new Uint8Array(await fs.readFile(path.join(repertoire, noms.manifeste)));
    const octetsSignature = new Uint8Array(await fs.readFile(path.join(repertoire, noms.signature)));
    return { manifeste: analyserJson(octetsManifeste), signature: analyserJson(octetsSignature), octetsManifeste, octetsSignature };
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

export { DUREE_PERIODE, ZERO32 };
