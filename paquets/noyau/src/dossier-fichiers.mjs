// Lecture d'un répertoire de dossier de preuve : le seul module de la
// bibliothèque qui lit des fichiers. Il ne lit que dossier.json et les
// fichiers qu'un index v0 peut déclarer (CT-1 §11.1) ; tout autre fichier du
// répertoire (attendu.json des vecteurs, par exemple) est ignoré, comme le
// vérificateur doit le faire.

import fs from "node:fs";
import path from "node:path";
import { FICHIERS_DOSSIER, verifierDossier } from "./dossier.mjs";

/**
 * Lit les fichiers d'un répertoire de dossier qu'un index peut déclarer.
 * Seuls les fichiers ordinaires sont lus ; un fichier absent n'apparaît pas
 * dans le résultat.
 * @param {string} repertoire chemin du répertoire
 * @returns {Map<string, Uint8Array>} nom de fichier → octets
 */
export function lireRepertoireDossier(repertoire) {
  const fichiers = new Map();
  for (const nom of FICHIERS_DOSSIER) {
    const chemin = path.join(repertoire, nom);
    let stat;
    try {
      stat = fs.lstatSync(chemin);
    } catch (e) {
      if (e.code === "ENOENT") continue;
      throw e;
    }
    if (!stat.isFile()) continue;
    fichiers.set(nom, Uint8Array.from(fs.readFileSync(chemin)));
  }
  return fichiers;
}

/**
 * Lit un répertoire de dossier et le vérifie (verifierDossier).
 * @param {string} repertoire
 * @param {object} [options] options de verifierDossier
 * @returns {import("./dossier.mjs").RapportDossier}
 */
export function verifierRepertoireDossier(repertoire, options = {}) {
  return verifierDossier(lireRepertoireDossier(repertoire), options);
}
