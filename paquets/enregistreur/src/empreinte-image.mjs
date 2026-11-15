// Empreinte du code en cours et comparaison à l'image attendue (CT-7 EX-3.14,
// proposition PA-4 ; menace MN-25, test TA-25 de CT-9).
//
// Un processus ne connaît pas le condensé de l'image dont son conteneur est
// issu : ce condensé est celui du manifeste de l'image, que seul
// l'orchestrateur lit. Le démon calcule donc ce qu'il peut calculer, une
// empreinte de son répertoire d'installation et du binaire Node.js qui
// l'exécute, et la compare à la valeur attendue pour l'image publiée, lue
// dans un fichier que l'orchestrateur monte en lecture seule :
//
//   noortrace --config <fichier> --image-attendue <fichier>
//   noortrace empreinte            imprime l'empreinte du code installé
//
// Fichier de l'image attendue (JSON strict, trois membres, aucun autre) :
//
//   { "version": 0,
//     "image": "noortrace/enregistreur:0.1.0@sha256:<64 hex>",
//     "code_sha256": "0x<64 hex>" }
//
// `image` est la référence de l'image publiée, condensé compris, recopiée de
// la note de version : le démon la consigne telle quelle et ne peut pas la
// vérifier. `code_sha256` est l'empreinte du code que cette image contient,
// rendue par `noortrace empreinte` dans l'image désignée par ce condensé : le
// démon la compare à celle qu'il calcule.
//
// Empreinte du code (`code_sha256`) : SHA-256 d'un manifeste UTF-8, une ligne
// JSON par entrée, terminée par LF :
//   ["node", "<sha256 du binaire process.execPath>"]
//   ["f", "<chemin relatif>", "<sha256 du fichier>"]      fichier ordinaire
//   ["l", "<chemin relatif>", "<cible du lien>"]          lien symbolique, non suivi
//   ["x", "<chemin relatif>"]                             toute autre entrée
// Chaque SHA-256 s'écrit `0x` suivi de 64 chiffres hexadécimaux minuscules,
// comme `config_sha256` à la ligne `startup` (CT-2 EX-18.6).
// La première ligne est celle du binaire ; les suivantes couvrent tout le
// répertoire d'installation, triées par les octets UTF-8 du chemin (séparateur
// « / »). Les répertoires n'ont pas de ligne ; les droits et les dates n'y
// entrent pas. Le répertoire d'installation est le plus proche ancêtre du
// paquet dont `node_modules/@noortrace/enregistreur` désigne ce paquet
// (`/opt/noortrace` dans l'image de référence) ; à défaut, le paquet lui-même.
//
// Ce que la comparaison voit : un fichier ajouté, retiré ou modifié sous le
// répertoire d'installation, un lien redirigé, un autre binaire Node.js. Ce
// qu'elle ne voit pas : un fichier de l'image hors de ce répertoire
// (bibliothèques du système, `/etc`), que seule la comparaison du condensé de
// l'image par l'orchestrateur voit (CT-7 EX-3.14, CT-8 EX-3.15) ; et un code
// modifié pour mentir sur sa propre empreinte (risque RA-22 de CT-7).

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { analyserJsonIntegral } from "./jcs-integral.mjs";

/** Répertoire du paquet en cours (celui qui contient `src/`). */
export const PAQUET_EN_COURS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const MOTIF_SHA256 = /^0x[0-9a-f]{64}$/;
const MOTIF_IMAGE = /^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$/;
const MEMBRES = ["code_sha256", "image", "version"];
const TAILLE_MAX_FICHIER_ATTENDU = 4096;

/** Erreur de lecture du fichier de l'image attendue ou de calcul de l'empreinte. */
export class ErreurImageAttendue extends Error {
  /**
   * @param {string} regle `fichier_illisible`, `forme_invalide` ou `empreinte_impossible`
   * @param {string} message
   */
  constructor(regle, message) {
    super(message);
    this.name = "ErreurImageAttendue";
    this.regle = regle;
  }
}

/**
 * Répertoire d'installation d'un paquet : le plus proche ancêtre dont
 * `node_modules/@noortrace/enregistreur` désigne ce paquet ; à défaut, le
 * paquet lui-même.
 * @param {string} [paquet]
 * @returns {string} chemin réel
 */
export function racineInstallation(paquet = PAQUET_EN_COURS) {
  const reel = fs.realpathSync(paquet);
  for (let d = path.dirname(reel); ; d = path.dirname(d)) {
    let cible = null;
    try {
      cible = fs.realpathSync(path.join(d, "node_modules", "@noortrace", "enregistreur"));
    } catch {
      cible = null;
    }
    if (cible === reel) return d;
    if (path.dirname(d) === d) return reel;
  }
}

/** SHA-256 d'un fichier, lu par blocs (le binaire Node.js dépasse cent mégaoctets). */
function sha256Fichier(chemin) {
  const h = createHash("sha256");
  const fd = fs.openSync(chemin, "r");
  try {
    const bloc = Buffer.allocUnsafe(1 << 20);
    for (;;) {
      const n = fs.readSync(fd, bloc, 0, bloc.length, null);
      if (n === 0) break;
      h.update(n === bloc.length ? bloc : bloc.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return `0x${h.digest("hex")}`;
}

/**
 * Empreinte du code en cours : manifeste du répertoire d'installation et du
 * binaire, puis son SHA-256 (forme en tête de ce fichier).
 * @param {{racine?: string, executable?: string}} [o]
 * @returns {{code_sha256: string, racine: string, entrees: number, manifeste: string}}
 */
export function empreinteCode(o = {}) {
  let racine;
  const entrees = [];
  let binaire;
  try {
    racine = fs.realpathSync(o.racine ?? racineInstallation());
    binaire = sha256Fichier(o.executable ?? process.execPath);
    const pile = [""];
    while (pile.length) {
      const rel = pile.pop();
      for (const e of fs.readdirSync(path.join(racine, rel), { withFileTypes: true })) {
        const chemin = rel === "" ? e.name : `${rel}/${e.name}`;
        const absolu = path.join(racine, chemin);
        if (e.isSymbolicLink()) entrees.push([chemin, ["l", chemin, fs.readlinkSync(absolu)]]);
        else if (e.isDirectory()) pile.push(chemin);
        else if (e.isFile()) entrees.push([chemin, ["f", chemin, sha256Fichier(absolu)]]);
        else entrees.push([chemin, ["x", chemin]]);
      }
    }
  } catch (e) {
    throw new ErreurImageAttendue("empreinte_impossible", `empreinte du code impossible : ${e?.code ?? e?.message ?? e}`);
  }
  entrees.sort((a, b) => Buffer.compare(Buffer.from(a[0], "utf8"), Buffer.from(b[0], "utf8")));
  const manifeste = [["node", binaire], ...entrees.map((x) => x[1])].map((l) => `${JSON.stringify(l)}\n`).join("");
  return { code_sha256: `0x${createHash("sha256").update(manifeste, "utf8").digest("hex")}`, racine, entrees: entrees.length, manifeste };
}

/**
 * Lit le fichier de l'image attendue (forme en tête de ce fichier).
 * @param {string} chemin
 * @returns {{image: string, code_sha256: string}}
 */
export function lireImageAttendue(chemin) {
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    throw new ErreurImageAttendue("fichier_illisible", "fichier de l'image attendue illisible");
  }
  if (octets.length > TAILLE_MAX_FICHIER_ATTENDU) throw new ErreurImageAttendue("forme_invalide", `fichier de l'image attendue de plus de ${TAILLE_MAX_FICHIER_ATTENDU} octets`);
  let d;
  try {
    d = analyserJsonIntegral(new Uint8Array(octets));
  } catch {
    throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : JSON strict attendu");
  }
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : objet attendu");
  const cles = Object.keys(d).sort();
  if (cles.length !== MEMBRES.length || cles.some((k, i) => k !== MEMBRES[i])) throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : membres version, image et code_sha256 attendus, aucun autre");
  if (d.version !== 0) throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : version 0 attendue");
  if (typeof d.image !== "string" || !MOTIF_IMAGE.test(d.image)) throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : image de la forme <nom>[:<étiquette>]@sha256:<64 hex> attendue");
  if (typeof d.code_sha256 !== "string" || !MOTIF_SHA256.test(d.code_sha256)) throw new ErreurImageAttendue("forme_invalide", "fichier de l'image attendue : code_sha256 de la forme 0x<64 chiffres hexadécimaux minuscules> attendu");
  return { image: d.image, code_sha256: d.code_sha256 };
}

/**
 * Lit l'image attendue, calcule l'empreinte du code en cours et les compare.
 * Rend ce que la ligne `startup` consigne (CT-7 EX-3.14, PA-4) ;
 * `image_match` faux fait écrire la ligne `image_mismatch` par le cœur.
 * @param {{fichier: string, racine?: string, executable?: string}} o
 * @returns {{image_expected: string, expected_code_sha256: string, code_sha256: string, image_match: boolean}}
 */
export function controlerImage(o) {
  const attendu = lireImageAttendue(o.fichier);
  const calcule = empreinteCode({ racine: o.racine, executable: o.executable });
  const concorde = calcule.code_sha256 === attendu.code_sha256;
  return { image_expected: attendu.image, expected_code_sha256: attendu.code_sha256, code_sha256: calcule.code_sha256, image_match: concorde };
}
