#!/usr/bin/env node
// Sauvegarde d'un journal (CT-8 §11.2, EX-11.2 à EX-11.4 ; chemin A de 11.4,
// pas 2 et 3) : archive au format déterministe de 13.4 et procès-verbal
// `sauvegarde` (schéma proces-verbal-exploitation-v0, 11.9).
//
//   node scripts/deploiement/sauvegarde.mjs creer --journal <répertoire du journal> --cles <cles.json> \
//     --archive <archive.tar à créer> --pv <procès-verbal.json à créer> --id pv-AAAA-MM-JJ-NNN \
//     --executant <identité> [--temoin <identité>] --motif <texte> --source <désignation> \
//     --destination <désignation> [--support-source volume_local|volume_bloc|autre] [--date <horodatage>] [--json]
//   node scripts/deploiement/sauvegarde.mjs verifier --archive <archive.tar> --pv <procès-verbal.json> [--json]
//   node scripts/deploiement/sauvegarde.mjs extraire --archive <archive.tar> --pv <procès-verbal.json> --vers <répertoire neuf> [--json]
//
// `creer` parcourt les fichiers ordinaires du répertoire du journal (refus
// d'un lien, d'un fichier spécial, d'un composant `secrets` ou d'une clé
// privée : EX-11.1, point 2 ; PV-10), garde d'un fichier `.ndjson` en cours
// d'écriture le préfixe qui finit à sa dernière fin de ligne (noté dans
// `observations`), écrit l'archive (date commune : `started_at`), la relit et
// en contrôle la forme, l'extrait dans un répertoire temporaire neuf, y
// exécute verifier-journal.mjs (EX-11.7) puis proces-verbal.mjs verifier
// --racine (PV-1 à PV-10), et n'écrit le procès-verbal, avec le rapport du
// vérificateur à côté (`<pv>.verification-journal.json`, dont le SHA-256 est
// `verification.report_sha256`), que si tout réussit.
// Écriture en flux (décision du porteur du 2026-11-16 ; CT-8 EX-11.1) :
// l'inventaire lit chaque fichier par morceaux (longueur retenue, SHA-256 de
// la source), l'archive est écrite par ecrireArchiveFlux, un fichier à la
// fois, relu sur le même inode et contrôlé contre son SHA-256 d'inventaire
// (un fichier changé entre les deux lectures est refusé), puis relue entrée
// par entrée, chaque entrée contrôlée par lireArchive et extraite aussitôt :
// la mémoire tient le plus grand fichier du journal, jamais le journal
// entier. Les octets de l'archive et le procès-verbal sont ceux d'avant.
// `verifier` contrôle la forme de l'archive (EX-13.13, EX-13.14) et chaque
// fichier contre le procès-verbal (longueur, SHA-256 : EX-11.4, PV-4, PV-7).
// `extraire` fait ce contrôle puis écrit les fichiers dans un répertoire neuf
// (0700, fichiers 0600 : EX-11.4 ; le chemin A, pas 6, en fixe ensuite le
// propriétaire) et imprime la plus haute époque des noms de segments, à
// consigner au procès-verbal `restauration` (pas 6).
// Codes : 0 fait (ou conforme) ; 1 contenu refusé, archive non conforme ou
// vérification en échec (rien n'est écrit par creer) ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions, texteJSON } from "../lib/deploiement.mjs";
import crypto from "node:crypto";
import {
  lireArchive, extraire, epoqueMaxSegments, sha256, ErreurSauvegarde, ecrireArchiveFlux, longueurArchive, ouvrirSansSuivre, porteCle,
  defautChemin, comparerOctets, TAILLE_MAX, BLOC,
} from "../lib/sauvegarde.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const VERSION = "0.1.0";

const USAGE = [
  "Usage : node scripts/deploiement/sauvegarde.mjs creer --journal <répertoire> --cles <cles.json> --archive <archive.tar> --pv <pv.json> --id pv-AAAA-MM-JJ-NNN --executant <identité> [--temoin <identité>] --motif <texte> --source <désignation> --destination <désignation> [--support-source volume_local|volume_bloc|autre] [--date <horodatage>] [--json]",
  "        node scripts/deploiement/sauvegarde.mjs verifier --archive <archive.tar> --pv <pv.json> [--json]",
  "        node scripts/deploiement/sauvegarde.mjs extraire --archive <archive.tar> --pv <pv.json> --vers <répertoire neuf> [--json]",
].join("\n");

const OPTIONS = {
  journal: { type: "string" }, cles: { type: "string" }, archive: { type: "string" }, pv: { type: "string" }, id: { type: "string" },
  executant: { type: "string" }, temoin: { type: "string" }, motif: { type: "string" }, source: { type: "string" }, destination: { type: "string" },
  "support-source": { type: "string" }, date: { type: "string" }, vers: { type: "string" }, json: { type: "boolean" },
};
const REQUISES = {
  creer: ["journal", "cles", "archive", "pv", "id", "executant", "motif", "source", "destination"],
  verifier: ["archive", "pv"],
  extraire: ["archive", "pv", "vers"],
};
const PERMISES = {
  creer: [...REQUISES.creer, "temoin", "support-source", "date", "json"],
  verifier: [...REQUISES.verifier, "json"],
  extraire: [...REQUISES.extraire, "json"],
};
const RE_HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const RE_ID = /^pv-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{3}$/;

class ErreurUsage extends Error {}

function analyser(argv) {
  const [sous, ...reste] = argv;
  const o = parseArgs({ args: reste, strict: true, allowPositionals: false, options: OPTIONS }).values;
  if (!Object.hasOwn(REQUISES, sous ?? "")) throw new ErreurUsage(sous === undefined ? "sous-commande requise (creer, verifier, extraire)" : sous.startsWith("-") ? `option inconnue : ${sous}` : `sous-commande inconnue : ${sous}`);
  for (const k of REQUISES[sous]) if (o[k] === undefined) throw new ErreurUsage(`option --${k} requise`);
  for (const k of Object.keys(o)) if (!PERMISES[sous].includes(k)) throw new ErreurUsage(`option --${k} sans objet pour ${sous}`);
  if (o.date !== undefined && !RE_HORODATAGE.test(o.date)) throw new ErreurUsage("--date : horodatage AAAA-MM-JJTHH:MM:SS.mmmZ attendu");
  if (o.id !== undefined && !RE_ID.test(o.id)) throw new ErreurUsage("--id : pv-AAAA-MM-JJ-NNN attendu");
  if (o["support-source"] !== undefined && !["volume_local", "volume_bloc", "autre"].includes(o["support-source"])) throw new ErreurUsage("--support-source : volume_local, volume_bloc ou autre");
  if (o.temoin !== undefined && o.temoin === o.executant) throw new ErreurUsage("--temoin : identité distincte de l'exécutant attendue (PV-5)");
  return { sous, o };
}

const horodatage = (ms) => new Date(ms).toISOString();

function lancerOutil(nom, args) {
  return spawnSync(process.execPath, [path.join(ICI, nom), ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
}

/** Contrôle d'une archive contre un procès-verbal `sauvegarde` : liste d'écarts (vide si conforme). */
export function controlerArchive(octetsArchive, pv) {
  const lu = lireArchive(octetsArchive);
  const ecarts = [...lu.erreurs];
  if (pv?.kind !== "sauvegarde") ecarts.push(`procès-verbal de sorte ${JSON.stringify(pv?.kind)} : sauvegarde attendue`);
  const attendus = new Map((pv?.files ?? []).map((f) => [f.path, f]));
  const presents = new Set();
  for (const f of lu.fichiers) {
    presents.add(f.path);
    const a = attendus.get(f.path);
    if (!a) {
      ecarts.push(`${f.path} : présent dans l'archive, absent du procès-verbal`);
      continue;
    }
    if (a.length !== f.length) ecarts.push(`${f.path} : longueur ${f.length} au lieu de ${a.length}`);
    const s = a.sha256_destination ?? a.sha256_source;
    if (s !== f.sha256) ecarts.push(`${f.path} : SHA-256 ${f.sha256} au lieu de ${s}`);
  }
  for (const p of attendus.keys()) if (!presents.has(p)) ecarts.push(`${p} : listé au procès-verbal, absent de l'archive`);
  if (lu.mtime !== null && typeof pv?.started_at === "string" && lu.mtime !== Math.floor(Date.parse(pv.started_at) / 1000)) ecarts.push(`date des entrées ${lu.mtime} différente de started_at (${pv.started_at})`);
  return { ecarts, fichiers: lu.fichiers };
}

/** Taille des morceaux lus et écrits par la sauvegarde en flux. */
const MORCEAU = 1 << 20;
const RE_LIGNES = /\.ndjson$/;

/** Tampon de lecture commun (les lectures sont synchrones et ne se chevauchent pas). */
let tamponMorceaux = null;

/** Lit au plus `longueur` octets de `fd` depuis le début, par morceaux de MORCEAU ; `surMorceau(morceau, position)` ; rend le nombre d'octets lus. */
function lireParMorceaux(fd, longueur, surMorceau) {
  tamponMorceaux ??= Buffer.alloc(MORCEAU);
  const tampon = tamponMorceaux;
  let lus = 0;
  while (lus < longueur) {
    const n = fs.readSync(fd, tampon, 0, Math.min(tampon.length, longueur - lus), lus);
    if (n === 0) break;
    surMorceau(tampon.subarray(0, n), lus);
    lus += n;
  }
  return lus;
}

/**
 * Inventaire en flux du répertoire d'un journal : mêmes règles et même ordre
 * qu'`inventaire` de scripts/lib/sauvegarde.mjs (fichiers ordinaires ouverts
 * sans suivre de lien et contrôlés sur leur descripteur, chemins du schéma,
 * aucun composant `secrets`, aucune clé privée, préfixe d'un `.ndjson` en
 * cours d'écriture jusqu'à sa dernière fin de ligne), sans garder les octets :
 * rend pour chaque fichier son chemin, son inode, la longueur retenue et le
 * SHA-256 de ces octets.
 * @returns {{fichiers: {path: string, abs: string, ino: number, dev: number, length: number, sha256: string}[], tronques: {path: string, length: number, retenu: number}[]}}
 */
function inventaireFlux(racine) {
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
      const chemin = path.join(abs, e.name);
      const liste = fs.lstatSync(chemin);
      const { fd, st } = ouvrirSansSuivre(chemin, r, liste);
      const lignes = RE_LIGNES.test(e.name);
      const h = crypto.createHash("sha256");
      let tete = Buffer.alloc(0);
      let prefixe = null; // SHA-256 des octets jusqu'à la dernière fin de ligne vue (fichier en ajout seul)
      let finLigne = 0;
      let dernier = null;
      let lus;
      try {
        if (st.size > TAILLE_MAX) throw new ErreurSauvegarde(`${r} : fichier de 8 Gio ou plus`);
        lus = lireParMorceaux(fd, st.size, (m, position) => {
          if (tete.length < 4096) tete = Buffer.concat([tete, m.subarray(0, 4096 - tete.length)]);
          if (lignes) {
            const k = m.lastIndexOf(0x0a);
            if (k !== -1) {
              prefixe = h.copy().update(m.subarray(0, k + 1));
              finLigne = position + k + 1;
            }
          }
          h.update(m);
          dernier = m[m.length - 1];
        });
      } finally {
        fs.closeSync(fd);
      }
      if (porteCle(tete)) throw new ErreurSauvegarde(`${r} : clé privée refusée (EX-11.1, point 2 ; PV-10)`);
      let length = lus;
      let empreinte = "0x" + h.digest("hex");
      if (lignes && lus > 0 && dernier !== 0x0a) {
        tronques.push({ path: r, length: lus, retenu: finLigne });
        length = finLigne;
        empreinte = prefixe ? "0x" + prefixe.digest("hex") : sha256(Buffer.alloc(0));
      }
      fichiers.push({ path: r, abs: chemin, ino: st.ino, dev: st.dev, length, sha256: empreinte });
    }
  };
  parcourir("");
  fichiers.sort((a, b) => comparerOctets(a.path, b.path));
  return { fichiers, tronques };
}

/**
 * Relit un fichier de l'inventaire pour l'archive : même inode, longueur
 * retenue, même SHA-256 qu'à l'inventaire. Les octets sont rendus dans
 * `tampon` (un seul tampon, de la taille du plus grand fichier, sert à tous :
 * ecrireArchiveFlux remet les octets d'un fichier à `ecrire` avant de lire le
 * suivant).
 */
function relireFichier(f, tampon) {
  const { fd } = ouvrirSansSuivre(f.abs, f.path, { ino: f.ino, dev: f.dev });
  const octets = tampon.subarray(0, f.length);
  let lus;
  try {
    lus = lireParMorceaux(fd, f.length, (m, position) => m.copy(octets, position));
  } finally {
    fs.closeSync(fd);
  }
  if (lus !== f.length || sha256(octets) !== f.sha256) throw new ErreurSauvegarde(`${f.path} : contenu changé pendant la sauvegarde`);
  return octets;
}

/** Écrit tous les octets de `b` sur `fd`. */
function ecrireTout(fd, b) {
  let n = 0;
  while (n < b.length) n += fs.writeSync(fd, b, n, b.length - n);
}

/** Somme de contrôle d'un en-tête ustar (champ chksum compté comme huit espaces), en texte de CT-8 EX-13.14. */
function sommeEntete(h) {
  let somme = 0;
  for (let i = 0; i < BLOC; i++) somme += i >= 148 && i < 156 ? 0x20 : h[i];
  return somme.toString(8).padStart(6, "0") + "\0 ";
}

/**
 * Relit l'archive écrite entrée par entrée (EX-11.4, EX-13.13, EX-13.14),
 * sans tenir une entrée entière en mémoire : l'en-tête de chaque entrée est
 * contrôlé par lireArchive (copie de l'en-tête au champ size nul, somme
 * recalculée : mode, propriétaires, typeflag, magic, version, champs nuls,
 * mtime, chemin, découpage nom/préfixe), le champ size et la somme de
 * l'en-tête lu le sont ici, comme l'ordre des noms, la date commune, le
 * bourrage, la fin d'archive et la longueur L ; le contenu est lu par
 * morceaux, haché et écrit aussitôt sous `vers` (répertoire neuf ;
 * répertoires 0700, fichiers 0600 créés en exclusivité, comme extraire).
 * Rend { fichiers: [{ path, length, sha256 }], erreurs }.
 */
function relireEtExtraire(chemin, vers) {
  const erreurs = [];
  const fichiers = [];
  const fd = fs.openSync(chemin, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const taille = fs.fstatSync(fd).size;
    /** Parcourt `longueur` octets de l'archive depuis `position`, par morceaux. */
    const parcourir = (position, longueur, surMorceau) => {
      tamponMorceaux ??= Buffer.alloc(MORCEAU);
      let lus = 0;
      while (lus < longueur) {
        const n = fs.readSync(fd, tamponMorceaux, 0, Math.min(MORCEAU, longueur - lus), position + lus);
        if (n === 0) break;
        surMorceau(tamponMorceaux.subarray(0, n));
        lus += n;
      }
      return lus;
    };
    if (taille === 0 || taille % BLOC !== 0) return { fichiers, erreurs: [`longueur ${taille} : multiple de 512 attendu`] };
    fs.mkdirSync(vers, { mode: 0o700 });
    fs.chmodSync(vers, 0o700);
    let p = 0;
    let precedent = null;
    let mtime = null;
    for (;;) {
      if (p + BLOC > taille) {
        erreurs.push("fin d'archive absente (deux blocs nuls)");
        break;
      }
      const h = Buffer.alloc(BLOC);
      fs.readSync(fd, h, 0, BLOC, p);
      if (h.every((b) => b === 0)) {
        let nul = true;
        parcourir(p, taille - p, (m) => {
          if (nul && !m.every((b) => b === 0)) nul = false;
        });
        if (p + 2 * BLOC > taille) erreurs.push(`bloc nul isolé à l'octet ${p}`);
        if (!nul) erreurs.push("octets non nuls après la fin d'archive");
        break;
      }
      const tailleTxt = h.subarray(124, 136).toString("latin1");
      if (!/^[0-7]{11}\0$/.test(tailleTxt)) {
        erreurs.push(`entrée à l'octet ${p} : size mal formé`);
        break;
      }
      if (h.subarray(148, 156).toString("latin1") !== sommeEntete(h)) erreurs.push(`entrée à l'octet ${p} : chksum faux`);
      const longueur = parseInt(tailleTxt.slice(0, 11), 8);
      const fin = p + BLOC + BLOC * Math.ceil(longueur / BLOC);
      if (fin > taille) {
        erreurs.push(`entrée à l'octet ${p} : contenu tronqué`);
        break;
      }
      // L'en-tête seul, au champ size nul, suivi de la fin d'archive : lireArchive en contrôle les autres champs (table d'EX-13.14).
      const vide = Buffer.from(h);
      vide.write("00000000000\0", 124, "latin1");
      vide.write(sommeEntete(vide), 148, "latin1");
      const lu = lireArchive(Buffer.concat([vide, Buffer.alloc(longueurArchive([0]) - BLOC, 0)]));
      if (lu.erreurs.length || lu.fichiers.length !== 1) {
        erreurs.push(...lu.erreurs);
        break;
      }
      const nom = lu.fichiers[0].path;
      if (mtime === null) mtime = lu.mtime;
      else if (lu.mtime !== mtime) erreurs.push(`entrée ${nom} : mtime ${lu.mtime} différent de celui de la première entrée (${mtime})`);
      if (precedent !== null && comparerOctets(precedent, nom) >= 0) erreurs.push(`entrée ${nom} : ordre des noms non strictement croissant (après ${precedent})`);
      precedent = nom;
      if (erreurs.length) break;
      const parties = nom.split("/");
      let rep = vers;
      for (const partie of parties.slice(0, -1)) {
        rep = path.join(rep, partie);
        if (!fs.existsSync(rep)) fs.mkdirSync(rep, { mode: 0o700 });
        else if (!fs.lstatSync(rep).isDirectory()) throw new ErreurSauvegarde(`${nom} : ${path.relative(vers, rep)} n'est pas un répertoire`);
      }
      const hache = crypto.createHash("sha256");
      const sortie = fs.openSync(path.join(rep, parties[parties.length - 1]), "wx", 0o600);
      try {
        parcourir(p + BLOC, longueur, (m) => {
          hache.update(m);
          ecrireTout(sortie, m);
        });
      } finally {
        fs.closeSync(sortie);
      }
      let bourrageNul = true;
      parcourir(p + BLOC + longueur, fin - p - BLOC - longueur, (m) => {
        if (!m.every((b) => b === 0)) bourrageNul = false;
      });
      if (!bourrageNul) {
        erreurs.push(`entrée ${nom} : bourrage du contenu non nul`);
        break;
      }
      fichiers.push({ path: nom, length: longueur, sha256: "0x" + hache.digest("hex") });
      p = fin;
    }
    if (erreurs.length === 0 && taille !== longueurArchive(fichiers.map((f) => f.length))) erreurs.push(`longueur ${taille} au lieu de ${longueurArchive(fichiers.map((f) => f.length))} (formule L d'EX-13.14)`);
    if (erreurs.length === 0 && fichiers.length === 0) erreurs.push("archive sans fichier");
    return { fichiers, erreurs };
  } finally {
    fs.closeSync(fd);
  }
}

function creer(o, sortie) {
  const debut = o.date !== undefined ? Date.parse(o.date) : Math.floor(Date.now() / 1000) * 1000;
  const started_at = horodatage(debut);
  for (const [k, v] of [["archive", o.archive], ["pv", o.pv]]) if (fs.existsSync(v)) throw new ErreurUsage(`--${k} : ${v} existe déjà`);
  const rapportChemin = `${o.pv}.verification-journal.json`;
  if (fs.existsSync(rapportChemin)) throw new ErreurUsage(`${rapportChemin} existe déjà`);
  if (!fs.statSync(o.journal, { throwIfNoEntry: false })?.isDirectory()) throw new ErreurUsage(`--journal : ${o.journal} n'est pas un répertoire`);
  const identite = JSON.parse(fs.readFileSync(path.join(o.journal, "journal.json"), "utf8"));
  const { fichiers, tronques } = inventaireFlux(o.journal);
  // Copie extraite pour la vérification : à côté de l'archive (répertoire des sauvegardes, 0700), jamais sous le
  // répertoire temporaire du système, souvent en mémoire et partagé (CT-8 EX-11.1).
  const travail = fs.mkdtempSync(path.join(path.dirname(path.resolve(o.archive)), ".noortrace-sauvegarde-"));
  try {
    // Archive écrite en flux, un fichier à la fois (décision du porteur du 2026-11-16 ; EX-11.1).
    let archive;
    const tampon = Buffer.alloc(fichiers.reduce((m, f) => Math.max(m, f.length), 0));
    const fd = fs.openSync(o.archive, "wx", 0o600);
    try {
      archive = ecrireArchiveFlux(fichiers.map((f) => ({ path: f.path, length: f.length, lire: () => relireFichier(f, tampon) })), Math.floor(debut / 1000), (b) => ecrireTout(fd, b));
    } finally {
      fs.closeSync(fd);
    }
    // Relecture de l'archive écrite, entrée par entrée : forme, puis chaque fichier contre la source (EX-11.4), extrait aussitôt.
    const racine = path.join(travail, "journal");
    const relue = relireEtExtraire(o.archive, racine);
    if (relue.erreurs.length) throw new ErreurSauvegarde(`archive relue non conforme : ${relue.erreurs.join(" ; ")}`);
    const source = new Map(fichiers.map((f) => [f.path, f]));
    const lignes = relue.fichiers.map((f) => {
      const s = source.get(f.path);
      return { path: f.path, length: s.length, sha256_source: s.sha256, sha256_destination: f.sha256 };
    });
    for (const l of lignes) if (l.sha256_source !== l.sha256_destination) throw new ErreurSauvegarde(`${l.path} : SHA-256 relu différent de la source`);
    const vj = lancerOutil("verifier-journal.mjs", [racine, "--cles", o.cles, "--json"]);
    if (vj.status !== 0 && vj.status !== 1) throw new ErreurSauvegarde(`verifier-journal.mjs : code ${vj.status} ${vj.stderr.trim()}`);
    const rapport = JSON.parse(vj.stdout);
    if (rapport.verdict !== "valide") throw new ErreurSauvegarde(`verifier-journal.mjs rend ${rapport.verdict} sur l'archive : ${JSON.stringify(rapport.errors).slice(0, 2000)}`);
    const periodes = (rapport.manifests ?? []).filter((m) => m.verdict === "valide").map((m) => m.period_start);
    const observations = tronques.length
      ? `fichiers en cours d'écriture, gardés jusqu'à leur dernière fin de ligne : ${tronques.map((t) => `${t.path} (${t.retenu} octets sur ${t.length})`).join(", ")}`
      : null;
    const pv = {
      version: 0,
      kind: "sauvegarde",
      id: o.id,
      org_id: identite.org_id,
      journal_id: identite.journal_id,
      started_at,
      finished_at: horodatage(Math.max(debut, Math.floor(Date.now() / 1000) * 1000)),
      operators: [{ identity: o.executant, role: "executant" }, ...(o.temoin !== undefined ? [{ identity: o.temoin, role: "temoin" }] : [])],
      reason: o.motif,
      source: { medium: o["support-source"] ?? "volume_local", locator: o.source },
      destination: { medium: "archive_sauvegarde", locator: o.destination },
      files: lignes,
      totals: { files: lignes.length, bytes: lignes.reduce((s, l) => s + l.length, 0) },
      verification: {
        tool: `verifier-journal ${VERSION} (CT-8 EX-11.7), par sauvegarde.mjs ${VERSION}`,
        command: "node scripts/deploiement/verifier-journal.mjs . --cles cles.json --json (sur l'archive extraite)",
        result: "valide",
        report_sha256: sha256(Buffer.from(vj.stdout, "utf8")),
      },
      continuity: { last_seq: rapport.last_seq, last_hash: rapport.last_hash, last_period_start: periodes.length ? Math.max(...periodes) : null },
      retention: null,
      mode_change: null,
      observations,
    };
    const cheminPv = path.join(travail, "pv.json");
    fs.writeFileSync(cheminPv, texteJSON(pv));
    const verif = lancerOutil("proces-verbal.mjs", ["verifier", cheminPv, "--racine", racine, "--cles", o.cles, "--json"]);
    if (verif.status !== 0) throw new ErreurSauvegarde(`proces-verbal.mjs verifier rend le code ${verif.status} : ${verif.stdout.trim().slice(0, 2000)} ${verif.stderr.trim()}`);
    fs.writeFileSync(rapportChemin, vj.stdout, { flag: "wx" });
    fs.writeFileSync(o.pv, texteJSON(pv), { flag: "wx" });
    if (o.json) sortie.write(texteJSON(pv));
    else sortie.write(`sauvegarde ${pv.id} : ${pv.totals.files} fichiers, ${pv.totals.bytes} octets ; archive ${archive.sha256} (${archive.length} octets) ; dernier seq ${pv.continuity.last_seq} ; PV-1 à PV-10 réussies\n`);
    return 0;
  } catch (err) {
    fs.rmSync(o.archive, { force: true });
    throw err;
  } finally {
    fs.rmSync(travail, { recursive: true, force: true });
  }
}

function lirePv(chemin) {
  try {
    return JSON.parse(fs.readFileSync(chemin, "utf8"));
  } catch (err) {
    throw new ErreurUsage(`--pv : ${chemin} illisible (${err.message})`);
  }
}

function lireOctets(chemin) {
  try {
    return fs.readFileSync(chemin);
  } catch (err) {
    throw new ErreurUsage(`--archive : ${chemin} illisible (${err.message})`);
  }
}

function verifierOuExtraire(sous, o, sortie) {
  const pv = lirePv(o.pv);
  const { ecarts, fichiers } = controlerArchive(lireOctets(o.archive), pv);
  if (sous === "verifier" || ecarts.length) {
    const r = { verdict: ecarts.length ? "non_conforme" : "conforme", files: fichiers.length, errors: ecarts };
    sortie.write(o.json ? texteJSON(r) : `${r.verdict} : ${fichiers.length} fichiers${ecarts.length ? `\n${ecarts.map((e) => `  ${e}`).join("\n")}` : ""}\n`);
    return ecarts.length ? 1 : 0;
  }
  if (!fs.existsSync(path.dirname(path.resolve(o.vers)))) throw new ErreurUsage(`--vers : le parent de ${o.vers} n'existe pas`);
  extraire(fichiers, o.vers);
  const r = { verdict: "extrait", files: fichiers.length, bytes: fichiers.reduce((s, f) => s + f.length, 0), highest_segment_epoch: epoqueMaxSegments(fichiers.map((f) => f.path)), errors: [] };
  sortie.write(o.json ? texteJSON(r) : `extrait : ${r.files} fichiers, ${r.bytes} octets sous ${o.vers} ; époque la plus haute des segments : ${r.highest_segment_epoch}\n`);
  return 0;
}

export function principal(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
  let a;
  try {
    a = analyser(argv);
  } catch (err) {
    stderr.write(`Erreur : ${err instanceof ErreurUsage ? err.message : messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  try {
    return a.sous === "creer" ? creer(a.o, stdout) : verifierOuExtraire(a.sous, a.o, stdout);
  } catch (err) {
    if (err instanceof ErreurUsage) {
      stderr.write(`Erreur : ${err.message}\n`);
      return 2;
    }
    if (err instanceof ErreurSauvegarde) {
      stderr.write(`Refus : ${err.message}\n`);
      return 1;
    }
    stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
