#!/usr/bin/env node
// Copies dérivées des runbooks d'incident (CT-8 §10.12 à §10.19, RB-1 à
// RB-8 ; décision D-6 de l'étape 7) : `deploiement/runbooks/RB-<n>.md`, que
// l'archive de déploiement emporte pour l'exploitant hors ligne.
//
//   node scripts/deploiement/extraire-runbooks.mjs [--spec <CT-8.md>] [--sortie <répertoire>]
//   node scripts/deploiement/extraire-runbooks.mjs --verifier [--spec <CT-8.md>] [--sortie <répertoire>]
//
// Le bloc d'un runbook va de sa ligne de titre (`### 10.<k> RB-<n> <titre>`)
// à la ligne qui précède le titre suivant de niveau 2 ou 3, sans les lignes
// vides finales. La copie est une ligne de provenance (commentaire HTML), une
// ligne vide, puis le bloc octet pour octet, suivi d'un saut de ligne : le
// texte normatif reste celui de CT-8, et la copie ne se modifie jamais à la
// main. Sans --verifier, les huit fichiers sont écrits (remplacés) ; avec
// --verifier, rien n'est écrit et chaque fichier est comparé à sa copie
// attendue, et aucun autre fichier `RB-*.md` n'est admis dans le répertoire.
// Outil du dépôt (comme renvois.mjs), hors de l'archive.
// Codes : 0 écrit, ou copies égales aux blocs ; 1 écart ; 2 usage ou CT-8
// sans les huit runbooks.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { RACINE, messageOptions } from "../lib/deploiement.mjs";

export const SPEC_CT8 = path.join(RACINE, "spec", "CT-8-deploiement-et-exploitation.md");
export const REPERTOIRE_RUNBOOKS = path.join(RACINE, "deploiement", "runbooks");

const USAGE = "Usage : node scripts/deploiement/extraire-runbooks.mjs [--verifier] [--spec <CT-8.md>] [--sortie <répertoire>]";
const RE_TITRE_RB = /^### (10\.[0-9]+) (RB-([0-9]+)) (.+)$/;
const RE_TITRE = /^#{2,3} /;

/**
 * Blocs RB-1 à RB-8 de CT-8, dans l'ordre : [{ id, n, section, titre, bloc }].
 * Lève si un runbook manque, est en double ou hors d'ordre.
 */
export function blocsRunbooks(texte) {
  const lignes = texte.split("\n");
  const r = [];
  let enCode = false;
  for (let i = 0; i < lignes.length; i++) {
    if (/^```/.test(lignes[i])) enCode = !enCode;
    if (enCode) continue;
    const m = RE_TITRE_RB.exec(lignes[i]);
    if (!m) continue;
    let j = i + 1;
    let code = false;
    for (; j < lignes.length; j++) {
      if (/^```/.test(lignes[j])) code = !code;
      if (!code && RE_TITRE.test(lignes[j])) break;
    }
    let fin = j;
    while (fin > i + 1 && lignes[fin - 1].trim() === "") fin--;
    r.push({ id: m[2], n: Number(m[3]), section: m[1], titre: m[4], bloc: lignes.slice(i, fin).join("\n") + "\n" });
  }
  const ids = r.map((x) => x.id);
  const attendus = Array.from({ length: 8 }, (_, k) => `RB-${k + 1}`);
  if (JSON.stringify(ids) !== JSON.stringify(attendus)) throw new Error(`runbooks de CT-8 : ${JSON.stringify(ids)} au lieu de RB-1 à RB-8 dans l'ordre`);
  return r;
}

/** Ligne de provenance d'une copie. */
export function provenance(rb) {
  return `<!-- Copie dérivée de CT-8 §${rb.section} (${rb.id}), spec/CT-8-deploiement-et-exploitation.md, tirée par scripts/deploiement/extraire-runbooks.mjs. Le texte normatif est celui de CT-8 : ne pas modifier ce fichier à la main. -->`;
}

/** Copies attendues : Map nom de fichier -> texte. */
export function copiesRunbooks(texte) {
  return new Map(blocsRunbooks(texte).map((rb) => [`${rb.id}.md`, `${provenance(rb)}\n\n${rb.bloc}`]));
}

/** Écarts entre le répertoire et les copies attendues (liste vide si égales). */
export function ecartsRunbooks(texte, repertoire) {
  const attendues = copiesRunbooks(texte);
  const ecarts = [];
  const presents = fs.existsSync(repertoire) ? fs.readdirSync(repertoire).filter((f) => /^RB-.*\.md$/.test(f)) : [];
  for (const f of presents) if (!attendues.has(f)) ecarts.push(`${f} : fichier sans runbook dans CT-8`);
  for (const [f, t] of attendues) {
    const p = path.join(repertoire, f);
    if (!fs.existsSync(p)) ecarts.push(`${f} : absent`);
    else if (!fs.readFileSync(p).equals(Buffer.from(t, "utf8"))) ecarts.push(`${f} : différent du bloc de CT-8`);
  }
  return ecarts;
}

export function principal(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { verifier: { type: "boolean" }, spec: { type: "string" }, sortie: { type: "string" } } }).values;
  } catch (err) {
    stderr.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  const rep = o.sortie ?? REPERTOIRE_RUNBOOKS;
  let texte;
  let copies;
  try {
    texte = fs.readFileSync(o.spec ?? SPEC_CT8, "utf8");
    copies = copiesRunbooks(texte);
  } catch (err) {
    stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  if (o.verifier) {
    const e = ecartsRunbooks(texte, rep);
    stdout.write(e.length ? `${e.map((x) => `écart : ${x}`).join("\n")}\n` : `${copies.size} copies égales aux blocs de CT-8\n`);
    return e.length ? 1 : 0;
  }
  fs.mkdirSync(rep, { recursive: true });
  for (const [f, t] of copies) fs.writeFileSync(path.join(rep, f), t);
  stdout.write(`${copies.size} copies écrites sous ${path.relative(process.cwd(), rep) || "."}\n`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
