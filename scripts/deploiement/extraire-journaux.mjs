#!/usr/bin/env node
// Extracteur des journaux de référence (CT-8 §10.3, EX-10.5).
//
//   node scripts/deploiement/extraire-journaux.mjs --repertoire <répertoire>
//       [--sortie <fichier .prom>] [--intervalle <secondes>]
//   node scripts/deploiement/extraire-journaux.mjs [--exploitation <chemin>]…
//       [--gel <chemin>]… [--acquisitions <chemin>]… [--registre <chemin>]…
//       [--consultations <chemin>]… [--approbation <chemin>]…
//       [--proces-verbaux <chemin>]… [--sortie <fichier>] [--intervalle <s>]
//
// Lit, sans jamais y écrire, le journal d'exploitation (CT-2 EX-9.5, fichiers
// tournés compris), le fichier de l'outil de gel (CT-2 EX-12.40), les
// fichiers acquisitions.ndjson (CT-5 EX-5.14), les sorties JSON de l'outil du
// registre (un document par fichier .json, operations-registre-v0#/$defs/sortie),
// le journal des consultations (11.10), le journal du service d'approbation
// (journal-service.ndjson de state_dir) et les procès-verbaux d'exploitation
// (.json, retenus quand PV-1 réussit). Un chemin est un fichier ou un
// répertoire, parcouru récursivement par ordre d'octets des noms ; avec
// --repertoire, chaque source est le sous-répertoire de son nom
// (proces-verbaux/ pour les procès-verbaux).
//
// Expose au format texte de Prometheus noortrace_journal_lignes_total,
// noortrace_journal_derniere_ligne_s, noortrace_journal_illisibles_total et
// noortrace_proces_verbal_dernier_s (table de 10.3, noms du code : voir
// scripts/lib/supervision.mjs). Seules les lignes terminées par LF sont lues.
// Sans --intervalle : une passe, exposition sur la sortie standard ou dans
// --sortie (écrit par renommage, pour le collecteur textfile de
// l'exportateur de nœud). Avec --intervalle : une passe par intervalle, en
// ajout (seuls les octets nouveaux de chaque fichier sont lus ; un fichier
// raccourci ou remplacé est relu depuis le début), jusqu'à SIGTERM ou SIGINT.
// Codes : 0 exposition écrite ; 1 chemin illisible ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions } from "../lib/deploiement.mjs";
import { verifierProcesVerbal } from "../lib/exploitation.mjs";
import { Extracteur, SOURCES, analyserJSONStrict, lignesCompletes } from "../lib/supervision.mjs";

const USAGE = [
  "Usage : node scripts/deploiement/extraire-journaux.mjs --repertoire <répertoire> [--sortie <fichier>] [--intervalle <s>]",
  "        node scripts/deploiement/extraire-journaux.mjs [--exploitation|--gel|--acquisitions|--registre|--consultations|--approbation|--proces-verbaux <chemin>]… [--sortie <fichier>] [--intervalle <s>]",
].join("\n");

const OPTIONS_SOURCES = [...SOURCES, "proces-verbaux"];

/** Fichiers ordinaires d'un chemin (fichier, ou répertoire parcouru récursivement par ordre d'octets des noms). */
export function fichiersDe(chemin, suffixe = null) {
  const st = fs.statSync(chemin);
  if (st.isFile()) return [chemin];
  if (!st.isDirectory()) return [];
  const out = [];
  const noms = fs.readdirSync(chemin).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  for (const n of noms) {
    const p = path.join(chemin, n);
    const s = fs.lstatSync(p);
    if (s.isDirectory()) out.push(...fichiersDe(p, suffixe));
    else if (s.isFile() && (suffixe === null || n.endsWith(suffixe))) out.push(p);
  }
  return out;
}

/** Validité PV-1 d'un procès-verbal (bibliothèque de l'exploitation). */
function pv1(texte) {
  const r = verifierProcesVerbal(texte, {});
  return r.checks.find((c) => c.id === "PV-1")?.status === "reussi";
}

/**
 * Extracteur sur des fichiers, avec la position lue de chaque fichier (mode
 * en ajout).
 */
export class ExtracteurFichiers {
  /** @param {Record<string, string[]>} chemins par source (et "proces-verbaux") */
  constructor(chemins) {
    this.chemins = chemins;
    this.x = new Extracteur();
    /** @type {Map<string, {position: number}>} position lue, par « périphérique:inode » */
    this.positions = new Map();
    /** @type {Map<string, string>} empreinte (mtime, taille) des documents entiers déjà lus */
    this.documents = new Map();
  }

  /** Une passe : lit ce qui est nouveau. */
  passe() {
    for (const source of SOURCES) {
      if (this.chemins[source]?.length && !this.x.illisibles.has(source)) this.x.illisibles.set(source, 0);
      for (const racine of this.chemins[source] ?? []) {
        if (source === "registre") {
          for (const f of fichiersDe(racine, ".json")) {
            const st = fs.statSync(f);
            const marque = `${st.ino}:${st.size}:${st.mtimeMs}`;
            if (this.documents.get(f) === marque) continue;
            this.documents.set(f, marque);
            this.x.ajouterDocument(source, fs.readFileSync(f));
          }
          continue;
        }
        for (const f of fichiersDe(racine)) this.lireEnAjout(source, f);
      }
    }
    for (const racine of this.chemins["proces-verbaux"] ?? []) {
      for (const f of fichiersDe(racine, ".json")) {
        const st = fs.statSync(f);
        const marque = `${st.ino}:${st.size}:${st.mtimeMs}`;
        if (this.documents.get(f) === marque) continue;
        this.documents.set(f, marque);
        const texte = fs.readFileSync(f, "utf8");
        let doc = null;
        try {
          doc = analyserJSONStrict(texte);
        } catch {
          continue;
        }
        this.x.ajouterProcesVerbal(doc, pv1(texte));
      }
    }
    return this.x.exposer();
  }

  /**
   * Lit les lignes nouvelles d'un fichier. La position est tenue par fichier
   * physique (périphérique et inode) : un fichier tourné sous un autre nom
   * garde sa position, un fichier neuf sous l'ancien nom est lu depuis le
   * début, un fichier raccourci est relu depuis le début.
   */
  lireEnAjout(source, f) {
    const st = fs.statSync(f);
    const cle = `${st.dev}:${st.ino}`;
    let p = this.positions.get(cle);
    if (!p || st.size < p.position) p = { position: 0 };
    if (st.size > p.position) {
      const fd = fs.openSync(f, "r");
      try {
        const tampon = Buffer.alloc(st.size - p.position);
        const lus = fs.readSync(fd, tampon, 0, tampon.length, p.position);
        const octets = tampon.subarray(0, lus);
        const dernierLF = octets.lastIndexOf(0x0a);
        if (dernierLF >= 0) {
          this.x.ajouterLignes(source, lignesCompletes(octets.subarray(0, dernierLF + 1)));
          p.position += dernierLF + 1;
        }
      } finally {
        fs.closeSync(fd);
      }
    }
    this.positions.set(cle, p);
  }
}

/** Écrit l'exposition par renommage d'un fichier voisin. */
function ecrireAtomique(fichier, texte) {
  const tmp = `${fichier}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, texte, { mode: 0o644 });
  fs.renameSync(tmp, fichier);
}

export function principal(argv, sortie = process.stdout, erreur = process.stderr) {
  let o;
  try {
    const options = { repertoire: { type: "string" }, sortie: { type: "string" }, intervalle: { type: "string" } };
    for (const s of OPTIONS_SOURCES) options[s] = { type: "string", multiple: true };
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options }).values;
    const parSource = OPTIONS_SOURCES.some((s) => o[s] !== undefined);
    if (o.repertoire !== undefined && parSource) throw new Error("--repertoire exclut les options par source");
    if (o.repertoire === undefined && !parSource) throw new Error("--repertoire ou au moins une source requis");
    if (o.intervalle !== undefined && (!/^[0-9]{1,6}$/.test(o.intervalle) || Number(o.intervalle) < 1)) throw new Error("--intervalle : entier de secondes, au moins 1");
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  const chemins = {};
  if (o.repertoire !== undefined) {
    if (!fs.existsSync(o.repertoire) || !fs.statSync(o.repertoire).isDirectory()) {
      erreur.write(`Erreur : répertoire illisible : ${o.repertoire}\n`);
      return 1;
    }
    for (const s of OPTIONS_SOURCES) {
      const p = path.join(o.repertoire, s);
      if (fs.existsSync(p)) chemins[s] = [p];
    }
  } else {
    for (const s of OPTIONS_SOURCES) if (o[s] !== undefined) chemins[s] = o[s];
  }
  const ex = new ExtracteurFichiers(chemins);
  const unePasse = () => {
    const texte = ex.passe();
    if (o.sortie !== undefined) ecrireAtomique(o.sortie, texte);
    else sortie.write(texte);
  };
  try {
    unePasse();
  } catch (err) {
    erreur.write(`Erreur : ${err.code === "ENOENT" || err.code === "EACCES" ? `chemin illisible : ${err.path ?? ""} (${err.code})` : err.message}\n`);
    return 1;
  }
  if (o.intervalle === undefined) return 0;
  const minuterie = setInterval(() => {
    try {
      unePasse();
    } catch (err) {
      erreur.write(`Erreur : ${err.message}\n`);
    }
  }, Number(o.intervalle) * 1000);
  const arreter = () => clearInterval(minuterie);
  process.once("SIGTERM", arreter);
  process.once("SIGINT", arreter);
  return null;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const code = principal(process.argv.slice(2));
  if (code !== null) process.exitCode = code;
}
