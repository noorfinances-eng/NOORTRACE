// Opérations de fichiers durables (CT-2 §12.3) : ajout en O_APPEND par une
// boucle qui réitère tant que write rend moins que demandé (EX-12.5),
// durabilité par fdatasync, fsync du répertoire parent à la création d'un
// fichier, écriture atomique par fichier temporaire renommé (EX-12.6),
// lecture ligne à ligne avec repérage d'une dernière ligne incomplète
// (EX-12.10, EX-12.22).

import { constants as C } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";

/** Fichier ouvert en ajout seul par un seul écrivain. */
export class FichierAjout {
  /** @param {import("node:fs/promises").FileHandle} poignee @param {string} chemin @param {number} taille */
  constructor(poignee, chemin, taille) {
    this.poignee = poignee;
    this.chemin = chemin;
    this.taille = taille;
  }

  /**
   * Ouvre un fichier en O_WRONLY | O_APPEND (O_CLOEXEC est posé par Node.js).
   * Avec `creer`, le fichier est créé exclusivement (O_CREAT | O_EXCL) et le
   * répertoire parent synchronisé.
   * @param {string} chemin
   * @param {{creer?: boolean, existantAdmis?: boolean}} [options]
   * @returns {Promise<FichierAjout>}
   */
  static async ouvrir(chemin, options = {}) {
    let drapeaux = C.O_WRONLY | C.O_APPEND;
    if (options.creer) drapeaux |= C.O_CREAT | (options.existantAdmis ? 0 : C.O_EXCL);
    const poignee = await fs.open(chemin, drapeaux, 0o600);
    const { size } = await poignee.stat();
    if (options.creer) await synchroniserRepertoire(path.dirname(chemin));
    return new FichierAjout(poignee, chemin, size);
  }

  /**
   * Ajoute des octets, en réitérant jusqu'à ce que tout soit écrit.
   * @param {Uint8Array} octets
   */
  async ajouter(octets) {
    let fait = 0;
    while (fait < octets.length) {
      const { bytesWritten } = await this.poignee.write(octets, fait, octets.length - fait);
      if (bytesWritten <= 0) throw new Error("écriture sans progrès");
      fait += bytesWritten;
    }
    this.taille += octets.length;
  }

  /** fdatasync du fichier : la taille change à chaque ajout, les métadonnées nécessaires sont incluses. */
  async synchroniser() {
    await this.poignee.datasync();
  }

  async fermer() {
    try {
      await this.poignee.close();
    } catch {
      // déjà fermé
    }
  }
}

/**
 * fsync d'un répertoire (« an explicit fsync() on a file descriptor for the
 * directory is also needed », fsync(2), EX-12.5).
 * @param {string} repertoire
 */
export async function synchroniserRepertoire(repertoire) {
  const h = await fs.open(repertoire, C.O_RDONLY);
  try {
    await h.sync();
  } finally {
    await h.close();
  }
}

/**
 * Crée un répertoire (et ses parents) avec des droits restreints, puis
 * synchronise son parent.
 * @param {string} repertoire
 */
export async function creerRepertoire(repertoire) {
  await fs.mkdir(repertoire, { recursive: true, mode: 0o700 });
}

/**
 * Écrit un fichier de façon atomique : fichier temporaire du même
 * répertoire, fdatasync, renommage, fsync du répertoire. Avec
 * `jamaisReecrire`, un fichier déjà présent n'est pas touché (adressage par
 * contenu, EX-8.9) et la fonction rend false.
 * @param {string} chemin
 * @param {Uint8Array} octets
 * @param {{jamaisReecrire?: boolean}} [options]
 * @returns {Promise<boolean>} vrai si le fichier a été écrit
 */
export async function ecrireAtomique(chemin, octets, options = {}) {
  const dir = path.dirname(chemin);
  if (options.jamaisReecrire && (await existe(chemin))) return false;
  const tmp = path.join(dir, `.tmp-${path.basename(chemin)}-${randomBytes(6).toString("hex")}`);
  const h = await fs.open(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL, 0o600);
  try {
    let fait = 0;
    while (fait < octets.length) {
      const { bytesWritten } = await h.write(octets, fait, octets.length - fait);
      fait += bytesWritten;
    }
    await h.datasync();
  } finally {
    await h.close();
  }
  if (options.jamaisReecrire && (await existe(chemin))) {
    await fs.rm(tmp, { force: true });
    return false;
  }
  await fs.rename(tmp, chemin);
  await synchroniserRepertoire(dir);
  return true;
}

/**
 * @param {string} chemin
 * @returns {Promise<boolean>}
 */
export async function existe(chemin) {
  try {
    await fs.lstat(chemin);
    return true;
  } catch (e) {
    if (e.code === "ENOENT") return false;
    throw e;
  }
}

/**
 * Découpe des octets en lignes terminées par \n. La dernière, si elle n'a pas
 * de \n, est rendue avec `complete: false` (écriture tronquée possible).
 * @param {Uint8Array} octets
 * @returns {{debut: number, fin: number, octets: Uint8Array, complete: boolean}[]}
 *   `fin` est l'indice qui suit le \n (ou la fin des octets)
 */
export function decouperLignes(octets) {
  const lignes = [];
  let debut = 0;
  for (let k = 0; k < octets.length; k++) {
    if (octets[k] === 0x0a) {
      lignes.push({ debut, fin: k + 1, octets: octets.subarray(debut, k), complete: true });
      debut = k + 1;
    }
  }
  if (debut < octets.length) lignes.push({ debut, fin: octets.length, octets: octets.subarray(debut), complete: false });
  return lignes;
}

/**
 * Tronque un fichier à une longueur, puis le synchronise (EX-12.10 pas 3).
 * @param {string} chemin
 * @param {number} longueur
 */
export async function tronquer(chemin, longueur) {
  const h = await fs.open(chemin, C.O_WRONLY);
  try {
    await h.truncate(longueur);
    await h.datasync();
  } finally {
    await h.close();
  }
}

/**
 * Octets libres du volume qui porte un chemin (fs.statfs), ou null si
 * l'appel n'est pas disponible.
 * @param {string} chemin
 * @returns {Promise<number|null>}
 */
export async function octetsLibres(chemin) {
  try {
    const s = await fs.statfs(chemin);
    return Number(s.bavail) * Number(s.bsize);
  } catch {
    return null;
  }
}
