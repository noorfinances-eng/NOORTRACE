// Sauvegarde du journal (CT-8 §11.2, EX-11.2 à EX-11.4) et archivage des
// fichiers tournés du journal d'exploitation (EX-11.22, EX-11.23, tâche TP-6).
//
// - Archive déterministe au format de CT-8 13.4 (EX-13.13, EX-13.14) :
//   sous-ensemble ustar, fichiers ordinaires seuls, triés par octets du nom,
//   propriétaires 0, droits 0644, une seule date, deux blocs nuls puis des
//   zéros jusqu'au multiple de 10 240 octets. `ecrireArchive` l'écrit,
//   `lireArchive` la relit en contrôlant chaque champ de la table d'EX-13.14
//   (le contrôle de forme que CT-8 0.1 n'outillait pas, section 15).
// - Inventaire d'un répertoire de journal : fichiers ordinaires seulement
//   (un lien, un répertoire spécial ou un fichier spécial est refusé), chemins
//   de la forme du schéma proces-verbal-exploitation-v0, aucun composant
//   `secrets`, aucune clé privée (règle de PV-10 ; EX-11.1, point 2).
// - Extraction sûre (EX-11.4) : répertoire neuf, refus de tout membre absolu,
//   de tout composant vide, `.` ou `..`, de toute entrée qui n'est pas un
//   fichier ordinaire.
//
// Aucune dépendance hors de Node.js : ni réseau, ni npm.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** Taille d'un bloc ustar et facteur de blocage de GNU tar (CT-8 EX-13.14). */
export const BLOC = 512;
export const ENREGISTREMENT = 10240;

/** Préfixe DER PKCS#8 d'une clé privée Ed25519 (CT-1 §13 ; PV-10). */
export const PREFIXE_CLE_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

/** Chemin admis par proces-verbal-exploitation-v0 ($defs/fichier/path). */
export const RE_CHEMIN = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

/** Taille maximale d'un fichier ustar (11 chiffres octaux : moins de 8 Gio). */
export const TAILLE_MAX = 8 ** 11 - 1;

export const sha256 = (octets) => "0x" + crypto.createHash("sha256").update(octets).digest("hex");

/** Comparaison des chemins par octets UTF-8 (ordre de la locale C ; PV-2, EX-13.14). */
export function comparerOctets(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/** Composants d'un chemin relatif à refuser (vide, `.`, `..`) ; null si le chemin est admis. */
export function defautChemin(rel) {
  if (typeof rel !== "string" || rel === "") return "chemin vide";
  if (rel.startsWith("/")) return "chemin absolu";
  const parts = rel.split("/");
  if (parts.some((p) => p === "")) return "composant vide";
  if (parts.some((p) => p === "." || p === "..")) return "composant . ou ..";
  if (Buffer.byteLength(rel) > 255) return "chemin de plus de 255 octets";
  if (!RE_CHEMIN.test(rel)) return "caractère hors de [A-Za-z0-9._-]";
  return null;
}

/** Vrai si les octets portent une clé privée (préfixe DER Ed25519, ou ligne PEM dans les 4 096 premiers octets ; PV-10). */
export function porteCle(octets) {
  if (octets.length >= PREFIXE_CLE_ED25519.length && octets.subarray(0, PREFIXE_CLE_ED25519.length).equals(PREFIXE_CLE_ED25519)) return true;
  return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(octets.subarray(0, 4096).toString("latin1"));
}

// ---------------------------------------------------------------------------
// Format ustar de CT-8 13.4
// ---------------------------------------------------------------------------

function octal(n, chiffres) {
  const s = n.toString(8);
  if (s.length > chiffres) throw new Error(`valeur ${n} non représentable sur ${chiffres} chiffres octaux`);
  return s.padStart(chiffres, "0");
}

/** Découpage nom/préfixe de CT-8 EX-13.14 (règle de GNU tar). Lève si le nom n'est pas représentable. */
export function decouper(nom) {
  const o = Buffer.from(nom, "utf8");
  if (o.length <= 100) return { name: o, prefix: Buffer.alloc(0) };
  const max = Math.min(o.length - 1, 155);
  for (let i = max; i > 0; i--) {
    if (o[i] !== 0x2f) continue;
    const prefix = o.subarray(0, i);
    const name = o.subarray(i + 1);
    if (name.length > 0 && name.length <= 100) return { name, prefix };
    break;
  }
  throw new Error(`nom non représentable en ustar : ${nom}`);
}

function entete(nom, taille, mtime) {
  const h = Buffer.alloc(BLOC, 0);
  const { name, prefix } = decouper(nom);
  name.copy(h, 0);
  h.write("0000644\0", 100, "latin1");
  h.write("0000000\0", 108, "latin1");
  h.write("0000000\0", 116, "latin1");
  h.write(octal(taille, 11) + "\0", 124, "latin1");
  h.write(octal(mtime, 11) + "\0", 136, "latin1");
  h.write("        ", 148, "latin1");
  h.write("0", 156, "latin1");
  h.write("ustar\0", 257, "latin1");
  h.write("00", 263, "latin1");
  prefix.copy(h, 345);
  let somme = 0;
  for (const b of h) somme += b;
  h.write(octal(somme, 6) + "\0 ", 148, "latin1");
  return h;
}

/** Longueur d'une archive (formule L d'EX-13.14) pour des tailles de fichiers données. */
export function longueurArchive(tailles) {
  const brut = tailles.reduce((s, t) => s + BLOC + BLOC * Math.ceil(t / BLOC), 0) + 2 * BLOC;
  return ENREGISTREMENT * Math.ceil(brut / ENREGISTREMENT);
}

/**
 * Octets de l'archive de `fichiers` ([{ path, octets }]), triés par octets du
 * nom, tous datés de `mtime` (secondes depuis 1970).
 */
export function ecrireArchive(fichiers, mtime) {
  if (!Number.isInteger(mtime) || mtime < 0) throw new Error("mtime : entier positif attendu");
  const tries = [...fichiers].sort((a, b) => comparerOctets(a.path, b.path));
  for (let i = 1; i < tries.length; i++) if (comparerOctets(tries[i - 1].path, tries[i].path) === 0) throw new Error(`nom en double : ${tries[i].path}`);
  const parts = [];
  for (const f of tries) {
    const d = defautChemin(f.path);
    if (d) throw new Error(`${f.path} : ${d}`);
    if (f.octets.length > TAILLE_MAX) throw new Error(`${f.path} : fichier de 8 Gio ou plus`);
    parts.push(entete(f.path, f.octets.length, mtime), f.octets);
    const reste = f.octets.length % BLOC;
    if (reste) parts.push(Buffer.alloc(BLOC - reste, 0));
  }
  const corps = Buffer.concat(parts);
  const total = longueurArchive(tries.map((f) => f.octets.length));
  return Buffer.concat([corps, Buffer.alloc(total - corps.length, 0)]);
}

function champ(h, debut, fin) {
  return h.subarray(debut, fin);
}

function texteNul(octets) {
  const k = octets.indexOf(0);
  return (k === -1 ? octets : octets.subarray(0, k)).toString("utf8");
}

const estNul = (octets) => octets.every((b) => b === 0);

/**
 * Relit une archive en contrôlant la forme d'EX-13.13 et EX-13.14. Rend
 * { fichiers: [{ path, length, octets, sha256 }], mtime, erreurs: [texte] } :
 * `erreurs` vide si la forme est exacte (fichiers non vides alors).
 */
export function lireArchive(octets) {
  const erreurs = [];
  const fichiers = [];
  let mtime = null;
  if (octets.length === 0 || octets.length % BLOC !== 0) {
    erreurs.push(`longueur ${octets.length} : multiple de 512 attendu${octets[0] === 0x1f && octets[1] === 0x8b ? " (archive compressée par gzip : la décompresser d'abord)" : ""}`);
    return { fichiers, mtime, erreurs };
  }
  let p = 0;
  let precedent = null;
  for (;;) {
    if (p + BLOC > octets.length) {
      erreurs.push("fin d'archive absente (deux blocs nuls)");
      break;
    }
    const h = octets.subarray(p, p + BLOC);
    if (estNul(h)) {
      if (p + 2 * BLOC > octets.length || !estNul(octets.subarray(p + BLOC, p + 2 * BLOC))) erreurs.push(`bloc nul isolé à l'octet ${p}`);
      if (!estNul(octets.subarray(p))) erreurs.push("octets non nuls après la fin d'archive");
      break;
    }
    const prefix = texteNul(champ(h, 345, 500));
    const name = texteNul(champ(h, 0, 100));
    const nom = prefix ? `${prefix}/${name}` : name;
    const ici = `entrée ${nom || "(sans nom)"}`;
    const attendu = (debut, fin, valeur, libelle) => {
      if (!champ(h, debut, fin).equals(Buffer.from(valeur, "latin1"))) erreurs.push(`${ici} : ${libelle} ${JSON.stringify(champ(h, debut, fin).toString("latin1"))} au lieu de ${JSON.stringify(valeur)}`);
    };
    attendu(100, 108, "0000644\0", "mode");
    attendu(108, 116, "0000000\0", "uid");
    attendu(116, 124, "0000000\0", "gid");
    attendu(156, 157, "0", "typeflag");
    attendu(257, 263, "ustar\0", "magic");
    attendu(263, 265, "00", "version");
    for (const [debut, fin, libelle] of [[157, 257, "linkname"], [265, 297, "uname"], [297, 329, "gname"], [329, 337, "devmajor"], [337, 345, "devminor"], [500, 512, "bourrage"]]) {
      if (!estNul(champ(h, debut, fin))) erreurs.push(`${ici} : ${libelle} non nul`);
    }
    const tailleTxt = champ(h, 124, 136).toString("latin1");
    const mtimeTxt = champ(h, 136, 148).toString("latin1");
    if (!/^[0-7]{11}\0$/.test(tailleTxt)) erreurs.push(`${ici} : size mal formé`);
    if (!/^[0-7]{11}\0$/.test(mtimeTxt)) erreurs.push(`${ici} : mtime mal formé`);
    const taille = parseInt(tailleTxt.slice(0, 11), 8);
    const m = parseInt(mtimeTxt.slice(0, 11), 8);
    if (mtime === null) mtime = m;
    else if (m !== mtime) erreurs.push(`${ici} : mtime ${m} différent de celui de la première entrée (${mtime})`);
    const somme = [...h].reduce((s, b, i) => s + (i >= 148 && i < 156 ? 0x20 : b), 0);
    if (champ(h, 148, 156).toString("latin1") !== octal(somme, 6) + "\0 ") erreurs.push(`${ici} : chksum faux`);
    const d = defautChemin(nom);
    if (d) erreurs.push(`${ici} : ${d}`);
    else {
      try {
        const dec = decouper(nom);
        if (dec.prefix.toString("utf8") !== prefix || dec.name.toString("utf8") !== name) erreurs.push(`${ici} : découpage nom/préfixe différent de celui d'EX-13.14`);
      } catch (err) {
        erreurs.push(`${ici} : ${err.message}`);
      }
    }
    if (precedent !== null && comparerOctets(precedent, nom) >= 0) erreurs.push(`${ici} : ordre des noms non strictement croissant (après ${precedent})`);
    precedent = nom;
    if (!Number.isFinite(taille) || p + BLOC + taille > octets.length) {
      erreurs.push(`${ici} : contenu tronqué`);
      break;
    }
    const contenu = octets.subarray(p + BLOC, p + BLOC + taille);
    const fin = p + BLOC + BLOC * Math.ceil(taille / BLOC);
    if (!estNul(octets.subarray(p + BLOC + taille, fin))) erreurs.push(`${ici} : bourrage du contenu non nul`);
    fichiers.push({ path: nom, length: taille, octets: Buffer.from(contenu), sha256: sha256(contenu) });
    p = fin;
  }
  if (erreurs.length === 0 && octets.length !== longueurArchive(fichiers.map((f) => f.length))) erreurs.push(`longueur ${octets.length} au lieu de ${longueurArchive(fichiers.map((f) => f.length))} (formule L d'EX-13.14)`);
  if (erreurs.length === 0 && fichiers.length === 0) erreurs.push("archive sans fichier");
  return { fichiers, mtime, erreurs };
}

// ---------------------------------------------------------------------------
// Inventaire d'un répertoire et extraction
// ---------------------------------------------------------------------------

/** Erreur d'inventaire ou d'extraction : `code` 1 (contenu refusé). */
export class ErreurSauvegarde extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurSauvegarde";
  }
}

const RE_LIGNES = /\.ndjson$/;

/**
 * Inventaire d'un répertoire de journal (CT-2 EX-12.1) : chaque fichier
 * ordinaire, lu une fois. Un fichier en ajout seul (`.ndjson`) qui ne finit
 * pas par une fin de ligne est en cours d'écriture : on en garde le préfixe
 * jusqu'à la dernière fin de ligne (une version partielle, comme celle que le
 * chemin A, pas 4, complète par la copie WORM) et on le signale. Lève
 * ErreurSauvegarde sur un lien, un fichier spécial, un chemin hors du schéma,
 * un composant `secrets` ou une clé privée.
 * @returns {{fichiers: {path: string, octets: Buffer}[], tronques: {path: string, length: number, retenu: number}[]}}
 */
export function inventaire(racine) {
  const fichiers = [];
  const tronques = [];
  const parcourir = (rel) => {
    const abs = rel ? path.join(racine, ...rel.split("/")) : racine;
    for (const e of fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => comparerOctets(a.name, b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) throw new ErreurSauvegarde(`${r} : lien refusé (jamais suivi)`);
      if (e.isDirectory()) {
        if (e.name === "secrets") throw new ErreurSauvegarde(`${r} : répertoire de secrets refusé (EX-11.1, point 2)`);
        parcourir(r);
        continue;
      }
      if (!e.isFile()) throw new ErreurSauvegarde(`${r} : fichier spécial refusé`);
      const d = defautChemin(r);
      if (d) throw new ErreurSauvegarde(`${r} : ${d}`);
      let octets = fs.readFileSync(path.join(abs, e.name));
      if (porteCle(octets)) throw new ErreurSauvegarde(`${r} : clé privée refusée (EX-11.1, point 2 ; PV-10)`);
      if (RE_LIGNES.test(e.name) && octets.length > 0 && octets[octets.length - 1] !== 0x0a) {
        const k = octets.lastIndexOf(0x0a);
        tronques.push({ path: r, length: octets.length, retenu: k + 1 });
        octets = octets.subarray(0, k + 1);
      }
      if (octets.length > TAILLE_MAX) throw new ErreurSauvegarde(`${r} : fichier de 8 Gio ou plus`);
      fichiers.push({ path: r, octets });
    }
  };
  parcourir("");
  fichiers.sort((a, b) => comparerOctets(a.path, b.path));
  return { fichiers, tronques };
}

/**
 * Écrit `fichiers` ([{ path, octets }]) sous `vers`, répertoire neuf (son
 * parent existe, lui non) : répertoires en 0700, fichiers en 0600, créés en
 * exclusivité. Lève ErreurSauvegarde sur un chemin refusé (EX-11.4).
 */
export function extraire(fichiers, vers) {
  for (const f of fichiers) {
    const d = defautChemin(f.path);
    if (d) throw new ErreurSauvegarde(`${f.path} : ${d} (EX-11.4)`);
  }
  if (fs.existsSync(vers)) throw new ErreurSauvegarde(`${vers} existe déjà : l'extraction se fait dans un répertoire neuf (EX-11.4)`);
  fs.mkdirSync(vers, { mode: 0o700 });
  fs.chmodSync(vers, 0o700);
  for (const f of fichiers) {
    const parties = f.path.split("/");
    let rep = vers;
    for (const p of parties.slice(0, -1)) {
      rep = path.join(rep, p);
      if (!fs.existsSync(rep)) fs.mkdirSync(rep, { mode: 0o700 });
      else if (!fs.lstatSync(rep).isDirectory()) throw new ErreurSauvegarde(`${f.path} : ${path.relative(vers, rep)} n'est pas un répertoire`);
    }
    fs.writeFileSync(path.join(rep, parties[parties.length - 1]), f.octets, { flag: "wx", mode: 0o600 });
  }
}

/** Plus haute époque dans les noms des segments (`segments/seg-<first_seq:16>-<epoch:20>.ndjson`, CT-2 EX-12.1), ou null. */
export function epoqueMaxSegments(chemins) {
  let max = null;
  for (const c of chemins) {
    const m = /^segments\/seg-[0-9]{16}-([0-9]{20})\.ndjson$/.exec(c);
    if (m && (max === null || BigInt(m[1]) > BigInt(max))) max = m[1];
  }
  return max === null ? null : BigInt(max).toString();
}
