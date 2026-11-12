// Fichiers servis par le serveur de console (contrat 2.12 et 3.3) : le
// serveur ne sert que ce que nomme le manifeste des pages (les cinq écrans et
// les fichiers sous `/statique/`). Au démarrage, il lit chaque fichier, en
// recalcule le SHA-384 et le SHA-256, refuse de démarrer sur un écart, puis
// sert les octets lus, jamais relus. La source d'un fichier de `@noble/*` est
// résolue depuis ce répertoire : racine du paquet = répertoire de
// `import.meta.resolve("<paquet>/utils.js")`.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { lireJsonStrict } from "@noortrace/approbation";
import { ErreurDemarrage } from "./outils.mjs";

/** Répertoire des pages par défaut (`src/pages/`). */
export const PAGES_DEFAUT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "pages");

export const ECRANS = Object.freeze(["tickets", "ticket", "inscription", "annuaire", "connexion"]);

/** Types de média admis pour un fichier sous `/statique/` (contrat 2.6). */
const TYPES = new Set(["text/css; charset=utf-8", "text/javascript; charset=utf-8", "application/json; charset=utf-8"]);

const sha384 = (o) => "sha384-" + crypto.createHash("sha384").update(o).digest("base64");
const sha256Hex = (o) => "0x" + crypto.createHash("sha256").update(o).digest("hex");
const sha256B64 = (o) => "sha256-" + crypto.createHash("sha256").update(o).digest("base64");

const refus = (quoi) => new ErreurDemarrage(`manifeste des pages : ${quoi}`);

/** Chemin relatif sans remontée ni racine. */
function relatifSur(f) {
  return typeof f === "string" && f !== "" && !path.isAbsolute(f) && !f.split(/[\\/]/).some((s) => s === ".." || s === "");
}

/** Racine d'un paquet de `@noble/*`, résolue depuis le serveur. */
function racineNoble(paquet) {
  return path.dirname(fileURLToPath(import.meta.resolve(`${paquet}/utils.js`)));
}

/**
 * Charge et vérifie le manifeste et les fichiers qu'il nomme.
 * @param {string} repertoire répertoire qui porte `manifeste.json` et `ecrans/`
 * @returns {{carteSha256: string, ecrans: Map<string, Buffer>, statiques: Map<string, {octets: Buffer, type: string}>, feuille: {chemin: string, sha384: string}|null}}
 */
export function chargerPages(repertoire) {
  let m;
  try {
    m = lireJsonStrict(fs.readFileSync(path.join(repertoire, "manifeste.json")));
  } catch {
    throw refus("illisible");
  }
  if (m === null || typeof m !== "object" || m.version !== 0 || typeof m.carte !== "string" || typeof m.carte_sha256 !== "string") throw refus("forme");
  if (sha256B64(Buffer.from(m.carte, "utf8")) !== m.carte_sha256) throw refus("carte_sha256 different de la carte");
  if (!/^sha256-[A-Za-z0-9+/]{43}=$/.test(m.carte_sha256)) throw refus("carte_sha256");
  const verifier = (octets, e, nom) => {
    if (sha384(octets) !== e.sha384 || sha256Hex(octets) !== e.sha256) throw refus(`empreinte differente : ${nom}`);
  };
  const ecrans = new Map();
  if (m.ecrans === null || typeof m.ecrans !== "object") throw refus("ecrans");
  for (const nom of ECRANS) {
    const e = m.ecrans[nom];
    if (!e || !relatifSur(e.fichier)) throw refus(`ecran ${nom}`);
    let octets;
    try {
      octets = fs.readFileSync(path.join(repertoire, e.fichier));
    } catch {
      throw refus(`ecran illisible : ${nom}`);
    }
    verifier(octets, e, nom);
    ecrans.set(nom, octets);
  }
  const racineConsole = path.resolve(repertoire, "..", "..");
  const statiques = new Map();
  if (!Array.isArray(m.statiques)) throw refus("statiques");
  for (const s of m.statiques) {
    if (!s || typeof s.chemin !== "string" || !s.chemin.startsWith("/statique/") || statiques.has(s.chemin)) throw refus("chemin");
    if (!TYPES.has(s.type)) throw refus(`type : ${s.chemin}`);
    if (!s.source || !relatifSur(s.source.fichier)) throw refus(`source : ${s.chemin}`);
    let racine;
    if (s.source.paquet === "@noortrace/console") racine = racineConsole;
    else if (s.source.paquet === "@noble/hashes" || s.source.paquet === "@noble/curves") racine = racineNoble(s.source.paquet);
    else throw refus(`paquet : ${s.chemin}`);
    let octets;
    try {
      octets = fs.readFileSync(path.join(racine, s.source.fichier));
    } catch {
      throw refus(`fichier illisible : ${s.chemin}`);
    }
    verifier(octets, s, s.chemin);
    if (s.octets !== octets.length) throw refus(`longueur differente : ${s.chemin}`);
    statiques.set(s.chemin, { octets, type: s.type });
  }
  const css = m.statiques.find((s) => s.chemin === "/statique/console.css");
  return { carteSha256: m.carte_sha256, ecrans, statiques, feuille: css ? { chemin: css.chemin, sha384: css.sha384 } : null };
}
