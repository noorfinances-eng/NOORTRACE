// Lecture d'un répertoire de dossier de preuve : le seul module de la
// bibliothèque qui lit des fichiers. Il ne lit que dossier.json et les
// fichiers qu'un index v0 peut déclarer (CT-1 §11.1) ; tout autre fichier du
// répertoire (attendu.json des vecteurs, par exemple) est ignoré, comme le
// vérificateur doit le faire.
//
// Aucune lecture n'est sans borne (CT-6 EX-4.13) : un fichier n'est ouvert
// qu'après lstat, s'il est ordinaire, et n'est lu que s'il ne dépasse pas sa
// limite (TAILLES_MAX de dossier.mjs : dossier.json 1 Mio, parties JSON v0
// 16 Mio, jeton-rfc3161.der 64 Kio, preuve.ots 256 Kio, registre.json et
// certificat-commit.json 64 Mio, validateurs.json 1 Mio,
// points-de-controle.json 1 Mio, attestation-perimetre.json 4 Mio). Au-delà,
// le fichier est rendu comme FichierNonLu (sa taille) : verifierDossier en
// fait un échec du contrôle qui le porte, ou de D-2 s'il est déclaré absent,
// jamais une exception. Seule attestation-perimetre.json au-delà de 4 Mio est
// encore lue, en flux et sans rien conserver, pour son SHA-256 (D-2), jusqu'au
// plafond de 64 Mio (CT-6 EX-4.15).

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { FICHIERS_DOSSIER, PARTIE_ATTESTATION_PERIMETRE, PLAFOND_LECTURE, TAILLES_MAX, verifierDossier } from "./dossier.mjs";

const BLOC = 1024 * 1024;
const O_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

/**
 * Ouvre un fichier ordinaire sans suivre de lien et vérifie, sur le
 * descripteur, qu'il l'est toujours ; rend le descripteur et la taille, ou
 * null si l'entrée n'est plus un fichier ordinaire.
 */
function ouvrirOrdinaire(chemin) {
  let fd;
  try {
    fd = fs.openSync(chemin, fs.constants.O_RDONLY | O_NOFOLLOW);
  } catch (e) {
    if (e.code === "ENOENT" || e.code === "ELOOP") return null;
    throw e;
  }
  const stat = fs.fstatSync(fd);
  if (!stat.isFile()) {
    fs.closeSync(fd);
    return null;
  }
  return { fd, taille: stat.size };
}

// Lit au plus `limite` + 1 octets : un fichier qui a grandi depuis fstat est
// vu trop grand, jamais lu au-delà.
function lireBorne(fd, limite) {
  const tampon = Buffer.allocUnsafe(Math.min(limite + 1, BLOC));
  const morceaux = [];
  let total = 0;
  while (total <= limite) {
    const n = fs.readSync(fd, tampon, 0, Math.min(tampon.length, limite + 1 - total), null);
    if (n === 0) break;
    morceaux.push(Uint8Array.from(tampon.subarray(0, n)));
    total += n;
  }
  if (total > limite) return null;
  const octets = new Uint8Array(total);
  let k = 0;
  for (const m of morceaux) {
    octets.set(m, k);
    k += m.length;
  }
  return octets;
}

// SHA-256 en flux, jusqu'au plafond ; null au-delà.
function empreinteEnFlux(fd, plafond) {
  const h = createHash("sha256");
  const tampon = Buffer.allocUnsafe(BLOC);
  let total = 0;
  while (true) {
    const n = fs.readSync(fd, tampon, 0, tampon.length, null);
    if (n === 0) break;
    total += n;
    if (total > plafond) return { taille: total, sha256: null };
    h.update(tampon.subarray(0, n));
  }
  return { taille: total, sha256: "0x" + h.digest("hex") };
}

/**
 * Lit les fichiers d'un répertoire de dossier qu'un index peut déclarer.
 * Seuls les fichiers ordinaires sont ouverts (lstat, puis ouverture sans
 * suivre de lien) ; un fichier absent, un répertoire ou un lien n'apparaît pas
 * dans le résultat. Un fichier dans sa limite (TAILLES_MAX) est rendu par ses
 * octets ; au-delà, par un FichierNonLu `{ taille, sha256 }` (sha256 calculé
 * en flux pour attestation-perimetre.json jusqu'à PLAFOND_LECTURE, null
 * sinon), sans être lu.
 * @param {string} repertoire chemin du répertoire
 * @returns {Map<string, Uint8Array|import("./dossier.mjs").FichierNonLu>} nom de fichier → octets, ou fichier non lu
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
    const limite = TAILLES_MAX[nom];
    if (stat.size > limite && nom !== PARTIE_ATTESTATION_PERIMETRE.file) {
      fichiers.set(nom, { taille: stat.size, sha256: null });
      continue;
    }
    const ouvert = ouvrirOrdinaire(chemin);
    if (!ouvert) continue;
    try {
      if (ouvert.taille > limite) {
        // attestation-perimetre.json au-delà de 4 Mio : SHA-256 en flux (D-2).
        fichiers.set(nom, ouvert.taille > PLAFOND_LECTURE ? { taille: ouvert.taille, sha256: null } : empreinteEnFlux(ouvert.fd, PLAFOND_LECTURE));
        continue;
      }
      const octets = lireBorne(ouvert.fd, limite);
      fichiers.set(nom, octets ?? { taille: limite + 1, sha256: null });
    } finally {
      fs.closeSync(ouvert.fd);
    }
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
