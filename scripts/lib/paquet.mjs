// Paquet réviseur (CT-8 §13) : écriture déterministe d'une archive tar ustar,
// lecture stricte, manifeste paquet-reviseur-v0 et vérifications PR-1 à PR-9,
// celles qui ne lisent que les octets de l'archive, sans rien écrire. PR-10 à
// PR-12 (extraction, vérificateur joint, attestation) sont dans
// scripts/paquet-reviseur/verifier.mjs.
//
// Forme canonique (EX-13.13, EX-13.14) : ustar de POSIX, sans en-tête pax ni
// GNU ; fichiers ordinaires seulement (typeflag 0), triés par ordre
// strictement croissant des octets de leur nom complet ; mode 0644,
// propriétaires 0 sans nom, une seule date (created_at du manifeste).
//
// Découpage nom/préfixe (EX-13.14) : un nom complet de 100 octets au plus va
// dans `name` et `prefix` reste vide ; sinon `prefix` est le plus long début
// du nom qui s'arrête avant un « / » et tient en 155 octets, et le reste, non
// vide et de 100 octets au plus, va dans `name` ; sans un tel début, le nom
// n'est pas représentable. C'est la règle de GNU tar (split_long_name de
// src/create.c : dernier « / » parmi les 156 premiers octets).
//
// Longueur canonique (EX-13.14) : chaque fichier occupe un en-tête de 512
// octets et ses données arrondies au multiple de 512 suivant ; viennent deux
// blocs nuls, puis des zéros jusqu'au plus petit multiple de 10 240 octets
// (facteur de blocage 20 de GNU tar) :
//   L = 10240 × ⌈(Σᵢ (512 + 512 × ⌈tᵢ ÷ 512⌉) + 1024) ÷ 10240⌉.
//
// Aucune dépendance hors de la bibliothèque standard de Node.js et de
// journal.mjs (JSON strict, validation de schéma). Aucun accès au réseau.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "./journal.mjs";

/** Racine de l'outil : le dépôt, ou le répertoire verificateur/ d'un paquet extrait. */
export const RACINE_OUTIL = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const RACINE = "paquet-reviseur";
export const MANIFESTE = `${RACINE}/MANIFESTE.json`;
export const FORMAT = "noortrace/paquet-reviseur";
export const BLOC = 512;
export const ENREGISTREMENT = 10240; // 20 blocs, facteur de blocage par défaut de GNU tar
export const LIMITE_ARCHIVE = 512 * 1024 * 1024;
export const LIMITE_FICHIER = 64 * 1024 * 1024;
export const LIMITE_MANIFESTE = 16 * 1024 * 1024;
export const LIMITE_ENTREES = 10001; // 10 000 fichiers + le manifeste
export const MODE = 0o644;
const COMPOSANT = /^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,99}$/;

export const sha256 = (o) => "0x" + crypto.createHash("sha256").update(o).digest("hex");

// ---------------------------------------------------------------- écriture

function octal(n, largeur) {
  const s = n.toString(8);
  if (s.length > largeur - 1) throw new Error(`valeur ${n} trop grande pour un champ de ${largeur} octets`);
  return s.padStart(largeur - 1, "0") + "\0";
}

/** Découpage canonique nom/préfixe : nom entier s'il tient en 100 octets, sinon le plus long préfixe (≤ 155 octets, avant un « / ») ; le reste doit être non vide et tenir en 100 (règle de GNU tar). */
export function decouper(nom) {
  const o = Buffer.from(nom, "ascii");
  if (o.length <= 100) return { prefix: "", name: nom };
  for (let i = Math.min(155, nom.length - 1); i > 0; i--) {
    if (nom[i] !== "/") continue;
    const prefix = nom.slice(0, i);
    const name = nom.slice(i + 1);
    if (name.length > 0 && name.length <= 100) return { prefix, name };
    break;
  }
  throw new Error(`nom non représentable en ustar : ${nom}`);
}

export function enTete({ nom, taille, mtime, type = "0", mode = MODE, lien = "", uid = 0, gid = 0 }) {
  const h = Buffer.alloc(BLOC, 0);
  const { prefix, name } = decouper(nom);
  h.write(name, 0, "ascii");
  h.write(octal(mode, 8), 100, "ascii");
  h.write(octal(uid, 8), 108, "ascii");
  h.write(octal(gid, 8), 116, "ascii");
  h.write(octal(taille, 12), 124, "ascii");
  h.write(octal(mtime, 12), 136, "ascii");
  h.fill(0x20, 148, 156);
  h.write(type, 156, "ascii");
  h.write(lien, 157, "ascii");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  h.write(prefix, 345, "ascii");
  let somme = 0;
  for (const b of h) somme += b;
  h.write(somme.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  return h;
}

/** Archive canonique : entrées triées par nom (octets), fichiers ordinaires, mode 0644, propriétaires 0, une seule date. */
export function ecrireArchive(fichiers, mtime) {
  const tries = [...fichiers].sort((a, b) => Buffer.compare(Buffer.from(a.nom), Buffer.from(b.nom)));
  const morceaux = [];
  for (const f of tries) {
    morceaux.push(enTete({ nom: f.nom, taille: f.octets.length, mtime }));
    morceaux.push(f.octets);
    const reste = f.octets.length % BLOC;
    if (reste) morceaux.push(Buffer.alloc(BLOC - reste, 0));
  }
  morceaux.push(Buffer.alloc(2 * BLOC, 0));
  let total = morceaux.reduce((s, m) => s + m.length, 0);
  const pad = (ENREGISTREMENT - (total % ENREGISTREMENT)) % ENREGISTREMENT;
  if (pad) morceaux.push(Buffer.alloc(pad, 0));
  return Buffer.concat(morceaux);
}

export const longueurCanonique = (tailles) => {
  const brut = tailles.reduce((s, t) => s + BLOC + Math.ceil(t / BLOC) * BLOC, 0) + 2 * BLOC;
  return Math.ceil(brut / ENREGISTREMENT) * ENREGISTREMENT;
};

// ------------------------------------------------------------------ lecture

const chaine = (h, debut, longueur) => {
  const champ = h.subarray(debut, debut + longueur);
  const fin = champ.indexOf(0);
  const texte = fin < 0 ? champ : champ.subarray(0, fin);
  const bourrageNul = fin < 0 || champ.subarray(fin).every((b) => b === 0);
  return { texte: texte.toString("latin1"), octets: texte, bourrageNul };
};

/** Champ numérique strict : (largeur − 1) chiffres octaux puis NUL. */
function nombre(h, debut, largeur) {
  const champ = h.subarray(debut, debut + largeur);
  const t = champ.subarray(0, largeur - 1).toString("latin1");
  if (!/^[0-7]+$/.test(t) || t.length !== largeur - 1 || champ[largeur - 1] !== 0) return null;
  return parseInt(t, 8);
}

/** Les deux langues d'un détail. */
const T = (fr, en) => ({ fr, en });

/** Les deux premiers octets 1f 8b sont la signature de gzip (EX-13.16). */
export const estGzip = (octets) => octets.length >= 2 && octets[0] === 0x1f && octets[1] === 0x8b;
const GZIP = T("archive compressée (gzip) : décompressez-la d'abord ; l'empreinte attendue est celle du .tar (EX-13.16)", "compressed archive (gzip): decompress it first; the expected digest is that of the .tar (EX-13.16)");

/**
 * Lit l'archive bloc par bloc sans rien écrire. Rend les entrées et, pour
 * chacune des vérifications PR-3 à PR-6, la première anomalie trouvée.
 */
export function lireArchive(octets) {
  const entrees = [];
  const anomalies = { "PR-3": null, "PR-4": null, "PR-5": null, "PR-6": null };
  const noter = (id, detail) => {
    if (!anomalies[id]) anomalies[id] = detail;
  };
  let o = 0;
  let fin = false;
  if (estGzip(octets)) {
    noter("PR-3", GZIP);
    return { entrees, anomalies, fin };
  }
  while (o + BLOC <= octets.length) {
    const h = octets.subarray(o, o + BLOC);
    if (h.every((b) => b === 0)) {
      const suivant = octets.subarray(o + BLOC, o + 2 * BLOC);
      if (suivant.length < BLOC || !suivant.every((b) => b === 0)) noter("PR-3", T(`bloc nul isolé à l'octet ${o} : la fin d'archive exige deux blocs nuls`, `lone zero block at byte ${o}: end of archive needs two zero blocks`));
      else if (!octets.subarray(o + 2 * BLOC).every((b) => b === 0)) noter("PR-3", T(`octets non nuls après la fin d'archive (octet ${o + 2 * BLOC} et suivants)`, `non-zero bytes after the end of archive (byte ${o + 2 * BLOC} onwards)`));
      fin = true;
      break;
    }
    if (entrees.length >= LIMITE_ENTREES) {
      noter("PR-3", T(`plus de ${LIMITE_ENTREES} entrées`, `more than ${LIMITE_ENTREES} entries`));
      return { entrees, anomalies, fin };
    }
    const n = entrees.length + 1;
    if (h.subarray(257, 263).toString("latin1") !== "ustar\0" || h.subarray(263, 265).toString("latin1") !== "00") {
      noter("PR-3", T(`entrée ${n} (octet ${o}) : magie ou version autre que « ustar\\0 » « 00 »`, `entry ${n} (byte ${o}): magic or version other than "ustar\\0" "00"`));
      return { entrees, anomalies, fin };
    }
    const sommeLue = h.subarray(148, 156);
    let somme = 0;
    for (let i = 0; i < BLOC; i++) somme += i >= 148 && i < 156 ? 0x20 : h[i];
    const attendue = Buffer.from(somme.toString(8).padStart(6, "0") + "\0 ", "latin1");
    if (!sommeLue.equals(attendue)) {
      noter("PR-3", T(`entrée ${n} (octet ${o}) : somme de contrôle « ${sommeLue.toString("latin1").replace(/\0/g, "\\0")} » au lieu de « ${attendue.toString("latin1").replace(/\0/g, "\\0")} »`, `entry ${n} (byte ${o}): checksum "${sommeLue.toString("latin1").replace(/\0/g, "\\0")}" instead of "${attendue.toString("latin1").replace(/\0/g, "\\0")}"`));
      return { entrees, anomalies, fin };
    }
    const mode = nombre(h, 100, 8);
    const uid = nombre(h, 108, 8);
    const gid = nombre(h, 116, 8);
    const taille = nombre(h, 124, 12);
    const mtime = nombre(h, 136, 12);
    if ([mode, uid, gid, taille, mtime].some((v) => v === null)) {
      noter("PR-3", T(`entrée ${n} (octet ${o}) : champ numérique hors de la forme stricte (chiffres octaux et NUL final)`, `entry ${n} (byte ${o}): numeric field not in strict form (octal digits and final NUL)`));
      return { entrees, anomalies, fin };
    }
    const champs = { name: chaine(h, 0, 100), linkname: chaine(h, 157, 100), uname: chaine(h, 265, 32), gname: chaine(h, 297, 32), devmajor: chaine(h, 329, 8), devminor: chaine(h, 337, 8), prefix: chaine(h, 345, 155) };
    const champMalForme = Object.entries(champs).find(([, c]) => !c.bourrageNul);
    if (champMalForme || !h.subarray(500, 512).every((b) => b === 0)) {
      noter("PR-3", T(`entrée ${n} (octet ${o}) : champ ${champMalForme ? champMalForme[0] : "pad"} mal bourré (octets non nuls après le premier NUL)`, `entry ${n} (byte ${o}): field ${champMalForme ? champMalForme[0] : "pad"} badly padded (non-zero bytes after the first NUL)`));
      return { entrees, anomalies, fin };
    }
    const type = String.fromCharCode(h[156]);
    const nom = champs.prefix.texte ? `${champs.prefix.texte}/${champs.name.texte}` : champs.name.texte;
    const debutDonnees = o + BLOC;
    const blocsDonnees = Math.ceil(taille / BLOC);
    if (debutDonnees + blocsDonnees * BLOC > octets.length) {
      noter("PR-3", T(`entrée ${n} « ${nom} » : données tronquées (${taille} octets annoncés)`, `entry ${n} "${nom}": truncated data (${taille} bytes announced)`));
      return { entrees, anomalies, fin };
    }
    const donnees = octets.subarray(debutDonnees, debutDonnees + taille);
    const bourrage = octets.subarray(debutDonnees + taille, debutDonnees + blocsDonnees * BLOC);
    if (!bourrage.every((b) => b === 0)) noter("PR-3", T(`entrée ${n} « ${nom} » : bourrage des données non nul`, `entry ${n} "${nom}": non-zero data padding`));
    entrees.push({ n, offset: o, nom, champs, type, mode, uid, gid, taille, mtime, donnees });
    o = debutDonnees + blocsDonnees * BLOC;
  }
  if (!fin) noter("PR-3", T("archive sans fin d'archive (deux blocs nuls)", "archive without end-of-archive marker (two zero blocks)"));
  if (entrees.length === 0) noter("PR-3", T("archive sans entrée", "archive without entries"));
  return { entrees, anomalies, fin };
}

// ------------------------------------------------------------ vérifications

export function verifierNoms(entrees) {
  const vus = new Map();
  const minuscules = new Map();
  for (const e of entrees) {
    const brut = e.champs.prefix.octets.length ? Buffer.concat([e.champs.prefix.octets, Buffer.from("/"), e.champs.name.octets]) : e.champs.name.octets;
    if (![...brut].every((b) => b >= 0x20 && b < 0x7f)) return T(`entrée ${e.n} : nom hors de l'ASCII imprimable`, `entry ${e.n}: name outside printable ASCII`);
    const nom = e.nom;
    if (nom.startsWith("/")) return T(`entrée ${e.n} « ${nom} » : chemin absolu`, `entry ${e.n} "${nom}": absolute path`);
    const comps = nom.split("/");
    if (comps.includes("..")) return T(`entrée ${e.n} « ${nom} » : composant « .. » (chemin hors de l'archive)`, `entry ${e.n} "${nom}": ".." component (path outside the archive)`);
    if (comps[0] !== RACINE) return T(`entrée ${e.n} « ${nom} » : hors de la racine ${RACINE}/`, `entry ${e.n} "${nom}": outside the root ${RACINE}/`);
    if (comps.length < 2 || comps.length > 17) return T(`entrée ${e.n} « ${nom} » : profondeur hors de 1 à 16 sous la racine`, `entry ${e.n} "${nom}": depth outside 1 to 16 under the root`);
    const mauvais = comps.slice(1).find((c) => !COMPOSANT.test(c));
    if (mauvais !== undefined) return T(`entrée ${e.n} « ${nom} » : composant « ${mauvais} » hors de la forme admise`, `entry ${e.n} "${nom}": component "${mauvais}" not in the admitted form`);
    if (Buffer.byteLength(nom) > 255) return T(`entrée ${e.n} « ${nom} » : plus de 255 octets`, `entry ${e.n} "${nom}": more than 255 bytes`);
    if (vus.has(nom)) return T(`entrées ${vus.get(nom)} et ${e.n} : même nom « ${nom} »`, `entries ${vus.get(nom)} and ${e.n}: same name "${nom}"`);
    const bas = nom.toLowerCase();
    if (minuscules.has(bas)) return T(`entrées ${minuscules.get(bas)} et ${e.n} : noms égaux à la casse près (« ${nom} »)`, `entries ${minuscules.get(bas)} and ${e.n}: names equal up to case ("${nom}")`);
    vus.set(nom, e.n);
    minuscules.set(bas, e.n);
  }
  for (const nom of vus.keys()) {
    const comps = nom.split("/");
    for (let i = 1; i < comps.length; i++) {
      const parent = comps.slice(0, i).join("/");
      if (vus.has(parent)) return T(`« ${parent} » est à la fois un fichier et le répertoire de « ${nom} »`, `"${parent}" is both a file and the directory of "${nom}"`);
    }
  }
  return null;
}

export function verifierForme(entrees, longueur) {
  for (let i = 1; i < entrees.length; i++) {
    if (Buffer.compare(Buffer.from(entrees[i - 1].nom), Buffer.from(entrees[i].nom)) >= 0) return T(`entrées ${i} et ${i + 1} : ordre non croissant (« ${entrees[i - 1].nom} », « ${entrees[i].nom} »)`, `entries ${i} and ${i + 1}: order not increasing ("${entrees[i - 1].nom}", "${entrees[i].nom}")`);
  }
  const mtime = entrees[0]?.mtime;
  for (const e of entrees) {
    if (e.mode !== MODE) return T(`entrée ${e.n} « ${e.nom} » : mode ${e.mode.toString(8).padStart(4, "0")} au lieu de 0644`, `entry ${e.n} "${e.nom}": mode ${e.mode.toString(8).padStart(4, "0")} instead of 0644`);
    if (e.uid !== 0 || e.gid !== 0 || e.champs.uname.texte !== "" || e.champs.gname.texte !== "") return T(`entrée ${e.n} « ${e.nom} » : propriétaire autre que 0/0 sans nom`, `entry ${e.n} "${e.nom}": owner other than 0/0 without name`);
    if (e.champs.devmajor.texte !== "" || e.champs.devminor.texte !== "") return T(`entrée ${e.n} « ${e.nom} » : champs de périphérique non vides`, `entry ${e.n} "${e.nom}": non-empty device fields`);
    if (e.mtime !== mtime) return T(`entrée ${e.n} « ${e.nom} » : date ${e.mtime} différente de celle de la première entrée (${mtime})`, `entry ${e.n} "${e.nom}": date ${e.mtime} differs from the first entry (${mtime})`);
    const d = decouper(e.nom);
    if (d.prefix !== e.champs.prefix.texte || d.name !== e.champs.name.texte) return T(`entrée ${e.n} « ${e.nom} » : découpage nom/préfixe non canonique`, `entry ${e.n} "${e.nom}": non-canonical name/prefix split`);
  }
  const attendue = longueurCanonique(entrees.map((e) => e.taille));
  if (longueur !== attendue) return T(`longueur ${longueur} au lieu de ${attendue} octets (fin d'archive puis bourrage au multiple de ${ENREGISTREMENT})`, `length ${longueur} instead of ${attendue} bytes (end of archive then padding to a multiple of ${ENREGISTREMENT})`);
  return null;
}

/** Texte d'une erreur de validation de schéma ({ chemin, message }). */
export const texteErreur = (e) => `${e.chemin || "/"} : ${e.message}`;

const instantVersEpoch = (s) => Date.parse(s) / 1000;
export const epochVersInstant = (t) => new Date(t * 1000).toISOString();

/** Rôle imposé par l'emplacement d'un fichier (table de 13.2, PR-9). */
export function roleAttendu(chemin) {
  if (chemin === "LISEZMOI.md" || chemin === "README.md") return "instructions";
  const tete = chemin.split("/")[0];
  return { dossiers: "dossier", ancres: "ancres", entetes: "entetes", attestation: "attestation", pieces: "pieces", verificateur: "verificateur" }[tete] ?? null;
}

export function chargerSchema(repertoire = path.join(RACINE_OUTIL, "spec", "schemas")) {
  return JSON.parse(fs.readFileSync(path.join(repertoire, "paquet-reviseur-v0.schema.json"), "utf8"));
}

/**
 * PR-1 à PR-9, dans l'ordre ; la première vérification en échec arrête les
 * suivantes (prerequis_en_echec). Rend { checks, entrees, manifeste, octetsManifeste }.
 */
export function verifierArchive(octets, { empreinte = null, schema = chargerSchema() } = {}) {
  const checks = [];
  let arret = false;
  const poser = (id, statut, detail, raison = null) => checks.push({ id, status: statut, reason: raison, detail });
  const etape = (id, f) => {
    if (arret) return poser(id, "non_execute", T("une vérification précédente a échoué", "a previous check failed"), "prerequis_en_echec");
    const r = f();
    if (r === undefined) return;
    if (r.statut === "echoue") arret = true;
    poser(id, r.statut, r.detail, r.raison ?? null);
  };
  let lu = null;
  let manifeste = null;
  let octetsManifeste = null;

  etape("PR-1", () => {
    const L = octets.length;
    if (L > LIMITE_ARCHIVE) return { statut: "echoue", detail: T(`${L} octets, au-delà de ${LIMITE_ARCHIVE}`, `${L} bytes, beyond ${LIMITE_ARCHIVE}`) };
    if (L < 2 * BLOC || L % BLOC) {
      const g = estGzip(octets) ? T(` ; ${GZIP.fr}`, `; ${GZIP.en}`) : T("", "");
      return { statut: "echoue", detail: T(`${L} octets : pas un multiple de ${BLOC} d'au moins ${2 * BLOC}${g.fr}`, `${L} bytes: not a multiple of ${BLOC} of at least ${2 * BLOC}${g.en}`) };
    }
    return { statut: "reussi", detail: T(`${L} octets, ${L / BLOC} blocs`, `${L} bytes, ${L / BLOC} blocks`) };
  });
  etape("PR-2", () => {
    if (empreinte === null) return { statut: "non_execute", raison: "empreinte_non_fournie", detail: T("aucune empreinte attendue (--empreinte)", "no expected digest (--empreinte)") };
    const vu = sha256(octets);
    if (vu !== empreinte) return { statut: "echoue", detail: T(`SHA-256 ${vu} au lieu de ${empreinte}`, `SHA-256 ${vu} instead of ${empreinte}`) };
    return { statut: "reussi", detail: T(`SHA-256 égal à l'empreinte attendue ${vu}`, `SHA-256 equal to the expected digest ${vu}`) };
  });
  etape("PR-3", () => {
    lu = lireArchive(octets);
    if (lu.anomalies["PR-3"]) return { statut: "echoue", detail: lu.anomalies["PR-3"] };
    return { statut: "reussi", detail: T(`${lu.entrees.length} entrées ustar bien formées`, `${lu.entrees.length} well-formed ustar entries`) };
  });
  etape("PR-4", () => {
    const e = lu.entrees.find((x) => x.type !== "0" || x.champs.linkname.texte !== "");
    if (e) {
      const nature = { "1": "lien physique", "2": "lien symbolique", "3": "périphérique caractère", "4": "périphérique bloc", "5": "répertoire", "6": "tube nommé", "x": "en-tête étendu pax", "g": "en-tête global pax", "L": "nom long GNU", "K": "lien long GNU", "\0": "fichier ancien format" }[e.type] ?? `type « ${e.type} »`;
      const nature_en = { "1": "hard link", "2": "symbolic link", "3": "character device", "4": "block device", "5": "directory", "6": "FIFO", "x": "pax extended header", "g": "pax global header", "L": "GNU long name", "K": "GNU long link", "\0": "old-format file" }[e.type] ?? `type "${e.type}"`;
      const cible = e.champs.linkname.texte ? ` vers « ${e.champs.linkname.texte} »` : "";
      const cible_en = e.champs.linkname.texte ? ` to "${e.champs.linkname.texte}"` : "";
      return { statut: "echoue", detail: T(`entrée ${e.n} « ${e.nom} » : ${nature}${cible} refusé ; seuls les fichiers ordinaires (type 0) sont admis`, `entry ${e.n} "${e.nom}": ${nature_en}${cible_en} refused; only regular files (type 0) are admitted`) };
    }
    return { statut: "reussi", detail: T("fichiers ordinaires seulement", "regular files only") };
  });
  etape("PR-5", () => {
    const d = verifierNoms(lu.entrees);
    if (d) return { statut: "echoue", detail: d };
    return { statut: "reussi", detail: T(`${lu.entrees.length} noms relatifs sous ${RACINE}/, uniques`, `${lu.entrees.length} relative names under ${RACINE}/, unique`) };
  });
  etape("PR-6", () => {
    const d = verifierForme(lu.entrees, octets.length);
    if (d) return { statut: "echoue", detail: d };
    return { statut: "reussi", detail: T(`ordre des noms, mode 0644, propriétaire 0/0, date ${epochVersInstant(lu.entrees[0].mtime)} pour toutes les entrées`, `name order, mode 0644, owner 0/0, date ${epochVersInstant(lu.entrees[0].mtime)} for every entry`) };
  });
  etape("PR-7", () => {
    const e = lu.entrees.find((x) => x.nom === MANIFESTE);
    if (!e) return { statut: "echoue", detail: T(`${MANIFESTE} absent`, `${MANIFESTE} missing`) };
    if (e.taille > LIMITE_MANIFESTE) return { statut: "echoue", detail: T(`manifeste de ${e.taille} octets, au-delà de ${LIMITE_MANIFESTE}`, `manifest of ${e.taille} bytes, beyond ${LIMITE_MANIFESTE}`) };
    octetsManifeste = e.donnees;
    try {
      manifeste = J.analyserJSONStrict(e.donnees);
    } catch (err) {
      return { statut: "echoue", detail: T(`manifeste illisible : ${err.message}`, `unreadable manifest: ${err.message}`) };
    }
    const erreurs = J.validerSchema(manifeste, schema);
    if (erreurs.length) return { statut: "echoue", detail: T(`manifeste non conforme à paquet-reviseur-v0 : ${erreurs.slice(0, 3).map(texteErreur).join(" ; ")}`, `manifest not conforming to paquet-reviseur-v0: ${erreurs.slice(0, 3).map(texteErreur).join("; ")}`) };
    for (let i = 1; i < manifeste.files.length; i++) {
      if (Buffer.compare(Buffer.from(manifeste.files[i - 1].path), Buffer.from(manifeste.files[i].path)) >= 0) return { statut: "echoue", detail: T(`files : chemins non strictement croissants (« ${manifeste.files[i - 1].path} », « ${manifeste.files[i].path} »)`, `files: paths not strictly increasing ("${manifeste.files[i - 1].path}", "${manifeste.files[i].path}")`) };
    }
    if (manifeste.files.some((f) => f.path === "MANIFESTE.json")) return { statut: "echoue", detail: T("files ne doit pas lister MANIFESTE.json", "files must not list MANIFESTE.json") };
    const chemins = manifeste.dossiers.map((d) => d.path);
    if (new Set(chemins).size !== chemins.length) return { statut: "echoue", detail: T("dossiers : chemin en double", "dossiers: duplicate path") };
    if (instantVersEpoch(manifeste.created_at) !== e.mtime) return { statut: "echoue", detail: T(`created_at ${manifeste.created_at} différent de la date des entrées ${epochVersInstant(e.mtime)}`, `created_at ${manifeste.created_at} differs from the entries' date ${epochVersInstant(e.mtime)}`) };
    return { statut: "reussi", detail: T(`manifeste conforme : ${manifeste.files.length} fichiers, ${manifeste.dossiers.length} dossier(s)`, `conforming manifest: ${manifeste.files.length} files, ${manifeste.dossiers.length} dossier(s)`) };
  });
  etape("PR-8", () => {
    const archive = new Map(lu.entrees.filter((x) => x.nom !== MANIFESTE).map((x) => [x.nom.slice(RACINE.length + 1), x]));
    const declares = new Map(manifeste.files.map((f) => [f.path, f]));
    const manquants = [...declares.keys()].filter((p) => !archive.has(p));
    const enTrop = [...archive.keys()].filter((p) => !declares.has(p));
    const fautes = [];
    if (manquants.length) fautes.push(T(`fichier(s) déclaré(s) absent(s) de l'archive : ${manquants.join(", ")}`, `declared file(s) missing from the archive: ${manquants.join(", ")}`));
    if (enTrop.length) fautes.push(T(`fichier(s) de l'archive absent(s) du manifeste : ${enTrop.join(", ")}`, `archive file(s) missing from the manifest: ${enTrop.join(", ")}`));
    for (const [p, f] of declares) {
      const x = archive.get(p);
      if (!x) continue;
      if (x.taille !== f.size) fautes.push(T(`${p} : ${x.taille} octets au lieu de ${f.size}`, `${p}: ${x.taille} bytes instead of ${f.size}`));
      else if (sha256(x.donnees) !== f.sha256) fautes.push(T(`${p} : SHA-256 ${sha256(x.donnees)} au lieu de ${f.sha256}`, `${p}: SHA-256 ${sha256(x.donnees)} instead of ${f.sha256}`));
    }
    if (fautes.length) return { statut: "echoue", detail: T(fautes.map((f) => f.fr).join(" ; "), fautes.map((f) => f.en).join("; ")) };
    const total = manifeste.files.reduce((s, f) => s + f.size, 0);
    return { statut: "reussi", detail: T(`${declares.size} fichiers, ${total} octets : tailles et SHA-256 égaux au manifeste`, `${declares.size} files, ${total} bytes: sizes and SHA-256 equal to the manifest`) };
  });
  etape("PR-9", () => {
    const parChemin = new Map(manifeste.files.map((f) => [f.path, f]));
    const fautes = [];
    for (const f of manifeste.files) {
      const r = roleAttendu(f.path);
      if (r === null) fautes.push(T(`${f.path} : emplacement hors de la disposition du paquet`, `${f.path}: location outside the package layout`));
      else if (r !== f.role) fautes.push(T(`${f.path} : rôle ${f.role} au lieu de ${r}`, `${f.path}: role ${f.role} instead of ${r}`));
    }
    for (const n of ["LISEZMOI.md", "README.md"]) if (!parChemin.has(n)) fautes.push(T(`${n} absent`, `${n} missing`));
    const dossiers = manifeste.dossiers.map((d) => d.path);
    for (const d of manifeste.dossiers) {
      if (!parChemin.has(`${d.path}/dossier.json`)) fautes.push(T(`${d.path}/dossier.json absent`, `${d.path}/dossier.json missing`));
      if (d.anchors !== null && parChemin.get(d.anchors)?.role !== "ancres") fautes.push(T(`${d.path} : fichier d'ancres ${d.anchors} absent`, `${d.path}: anchors file ${d.anchors} missing`));
      if (d.bitcoin_headers !== null && parChemin.get(d.bitcoin_headers)?.role !== "entetes") fautes.push(T(`${d.path} : fichier d'en-têtes ${d.bitcoin_headers} absent`, `${d.path}: headers file ${d.bitcoin_headers} missing`));
    }
    for (const f of manifeste.files) {
      if (f.role === "dossier" && !dossiers.some((d) => f.path.startsWith(d + "/"))) fautes.push(T(`${f.path} : dans aucun dossier déclaré`, `${f.path}: in no declared dossier`));
      if (f.role === "ancres" && !manifeste.dossiers.some((d) => d.anchors === f.path)) fautes.push(T(`${f.path} : fichier d'ancres qu'aucun dossier ne désigne`, `${f.path}: anchors file that no dossier designates`));
      if (f.role === "entetes" && !manifeste.dossiers.some((d) => d.bitcoin_headers === f.path)) fautes.push(T(`${f.path} : fichier d'en-têtes qu'aucun dossier ne désigne`, `${f.path}: headers file that no dossier designates`));
    }
    const att = manifeste.files.filter((f) => f.role === "attestation").map((f) => f.path).sort();
    const attAttendu = manifeste.attestation ? [manifeste.attestation.approver_set, manifeste.attestation.signed].sort() : [];
    if (JSON.stringify(att) !== JSON.stringify(attAttendu)) fautes.push(T(`attestation/ : ${att.join(", ") || "aucun fichier"} au lieu de ${attAttendu.join(", ") || "aucun fichier"}`, `attestation/: ${att.join(", ") || "no file"} instead of ${attAttendu.join(", ") || "no file"}`));
    const verif = manifeste.files.filter((f) => f.role === "verificateur").map((f) => f.path);
    if (manifeste.verifier === null && verif.length) fautes.push(T(`verifier nul mais ${verif.length} fichier(s) sous verificateur/`, `verifier null but ${verif.length} file(s) under verificateur/`));
    if (manifeste.verifier !== null) for (const p of [manifeste.verifier.tool, manifeste.verifier.dossier_verifier]) if (!verif.includes(p)) fautes.push(T(`${p} absent`, `${p} missing`));
    if (fautes.length) return { statut: "echoue", detail: T(fautes.map((f) => f.fr).join(" ; "), fautes.map((f) => f.en).join("; ")) };
    return { statut: "reussi", detail: T("rôles, dossiers, ancres, en-têtes, attestation, vérificateur et instructions cohérents", "roles, dossiers, anchors, headers, attestation, verifier and instructions consistent") };
  });
  return { checks, entrees: lu?.entrees ?? [], manifeste, octetsManifeste };
}

/**
 * Lecture et vérification PR-1 à PR-9 d'une archive en mémoire, pour l'outil
 * et les tests. `options` : `empreinte` (SHA-256 attendu, `0x` et 64 chiffres
 * hexadécimaux minuscules, ou null), `langue` (`fr`, `en`, ou null pour garder
 * les deux langues de chaque détail), `schema` (schéma paquet-reviseur-v0).
 * Rend { checks, intact, entrees, manifeste, octetsManifeste } ; `intact` est
 * vrai quand aucune de PR-1 à PR-9 n'a échoué. Rien n'est écrit.
 */
export function lireEtVerifier(octets, { empreinte = null, langue = null, schema = chargerSchema() } = {}) {
  const r = verifierArchive(octets, { empreinte, schema });
  const checks = r.checks.map((c) => ({ ...c, detail: langue ? c.detail[langue] : c.detail }));
  return { ...r, checks, intact: !checks.some((c) => c.status === "echoue") };
}

// ------------------------------------------------------ vérificateur joint

/** Fichiers du vérificateur joint, relatifs à la racine du dépôt (EX-13.20). */
export const FICHIERS_VERIFICATEUR = [
  "LICENSE",
  "NOTICE",
  "scripts/lib/certificat-commit.mjs",
  "scripts/lib/console.mjs",
  "scripts/lib/horodatage.mjs",
  "scripts/lib/journal.mjs",
  "scripts/lib/ots.mjs",
  "scripts/lib/paquet.mjs",
  "scripts/lib/registre.mjs",
  "scripts/lib/securite.mjs",
  "scripts/lib/verificateur.mjs",
  "scripts/paquet-reviseur/verifier.mjs",
  "scripts/verify/dossier.mjs",
  "spec/schemas/ancres-confiance-v0.schema.json",
  "spec/schemas/attestation-perimetre-v0.schema.json",
  "spec/schemas/dossier-v0.schema.json",
  "spec/schemas/entetes-bitcoin-v0.schema.json",
  "spec/schemas/evenement-v0.schema.json",
  "spec/schemas/manifeste-v0.schema.json",
  "spec/schemas/paquet-reviseur-v0.schema.json",
  "spec/schemas/point-de-controle-v0.schema.json",
  "spec/schemas/rapport-verification-v0.schema.json",
  "spec/schemas/registre-v0.schema.json",
  "spec/schemas/validateurs-v0.schema.json",
];

/** package.json engendré pour la copie de la distribution ESM d'ethers (EX-13.21). */
export function paquetEthers(version) {
  return Buffer.from(JSON.stringify({ name: "ethers", version, type: "module", main: "./dist/ethers.js", exports: { ".": "./dist/ethers.js" }, license: "MIT", description: "Copie de dist/ethers.js de la distribution npm d'ethers, jointe au vérificateur de référence (CT-8 §13)" }, null, 2) + "\n");
}

/**
 * Ce que l'outil exécuté joindrait comme vérificateur : chemin dans le paquet
 * -> octets. Sert à la construction et à PR-11.
 */
export function fichiersVerificateur(racine = RACINE_OUTIL) {
  const r = new Map();
  for (const rel of FICHIERS_VERIFICATEUR) r.set(`verificateur/${rel}`, fs.readFileSync(path.join(racine, rel)));
  const ethers = path.join(racine, "node_modules", "ethers");
  const version = JSON.parse(fs.readFileSync(path.join(ethers, "package.json"), "utf8")).version;
  r.set("verificateur/node_modules/ethers/package.json", paquetEthers(version));
  r.set("verificateur/node_modules/ethers/dist/ethers.js", fs.readFileSync(path.join(ethers, "dist", "ethers.js")));
  r.set("verificateur/node_modules/ethers/LICENSE.md", fs.readFileSync(path.join(ethers, "LICENSE.md")));
  return r;
}
