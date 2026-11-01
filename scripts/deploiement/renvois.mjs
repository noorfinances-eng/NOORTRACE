#!/usr/bin/env node
// Vérificateur des renvois vers CT-8 (CT-8 §0.2, EX-0.1, annexe A.2).
//
//   node scripts/deploiement/renvois.mjs [--json]
//   npm run deploiement:renvois
//
// Relit spec/*.md hors CT-8 (CT-1 à CT-7, puis spec/README.md), compte les
// occurrences de « CT-8 » par fichier et par section (dernier titre de niveau
// 2 à 4 hors bloc de code : « CT-n §s » si le titre commence par un numéro,
// son texte entre guillemets sinon, « en-tête » avant le premier titre), lit
// la table TC de CT-8 §0.2 et échoue (code 1) si : une occurrence n'a pas de
// ligne ; une ligne n'a pas d'occurrence ; deux lignes portent le même TC- ou
// les TC- ne se suivent pas ; une réponse cite un EX-, CO-, IP-, FL-, IR-,
// IC-, TP- ou DM- qui n'existe pas dans CT-8 (un identifiant précédé de
// « CT-n » est celui d'une autre spécification et n'est pas vérifié ici).
// Imprime, pour chaque fichier, le nombre d'occurrences et de lignes de la
// table. Réutilise definitions() de scripts/conformite/verifier-renvois.mjs,
// sans le modifier. Codes : 0 réussi ; 1 écart ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { definitions } from "../conformite/verifier-renvois.mjs";
import { RACINE, messageOptions } from "../lib/deploiement.mjs";

/** Fichiers relus, dans l'ordre de la table, et leur préfixe dans la colonne « Spécification, section ». */
export const FICHIERS = [
  ["CT-1-evenements-et-formats.md", "CT-1"],
  ["CT-2-enregistreur.md", "CT-2"],
  ["CT-3-approbations.md", "CT-3"],
  ["CT-4-registre.md", "CT-4"],
  ["CT-5-ancrage.md", "CT-5"],
  ["CT-6-verificateur.md", "CT-6"],
  ["CT-7-securite-et-conformite.md", "CT-7"],
  ["README.md", "`spec/README.md`"],
];
export const FICHIER_CT8 = "CT-8-deploiement-et-exploitation.md";

/** Occurrences de « CT-8 » d'un texte : [{ cle: "<préfixe> <section>", ligne }]. */
export function occurrences(prefixe, texte) {
  const out = [];
  let section = "« en-tête »";
  let code = false;
  texte.split("\n").forEach((l, i) => {
    if (l.startsWith("```")) code = !code;
    const t = !code && /^#{2,4}\s+(.*)$/.exec(l);
    if (t) {
      const n = /^([0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\.?\s/.exec(t[1]);
      section = n ? `§${n[1]}` : `« ${t[1]} »`;
    }
    for (const _ of l.matchAll(/CT-8/g)) out.push({ cle: `${prefixe} ${section}`, ligne: i + 1 });
  });
  return out;
}

/** Lignes de la table TC de CT-8 §0.2 : [{ id, n, cle, ligne, delegue, reponse }]. */
export function tableTC(texteCT8) {
  const debut = texteCT8.indexOf("### 0.2 ");
  const fin = texteCT8.indexOf("\n### 0.3 ", debut);
  if (debut === -1 || fin === -1) throw new Error("CT-8 : section 0.2 introuvable");
  const out = [];
  for (const l of texteCT8.slice(debut, fin).split("\n")) {
    const m = /^\| (TC-([0-9]+)) \| (.*) \(l\. ([0-9]+)\) \| (.*) \| (.*) \|$/.exec(l);
    if (m) out.push({ id: m[1], n: Number(m[2]), cle: m[3], ligne: Number(m[4]), delegue: m[5], reponse: m[6] });
  }
  return out;
}

/** Identifiants de CT-8 cités par une réponse, hors ceux précédés de « CT-n ». */
export function identifiantsCites(reponse) {
  const out = [];
  for (const m of reponse.matchAll(/(CT-[0-9] )?\b(EX-[0-9A-Z]+\.[0-9]+|(?:CO|IP|FL|IR|IC|TP|DM)-[0-9]+)\b/g)) if (!m[1]) out.push(m[2]);
  return out;
}

/** Identifiants définis par CT-8 : EX- en gras, familles des tables (CO-, IP-, FL-, IR-, IC-, TP-…), lignes DM- du bloc de formules. */
export function definisCT8(texte) {
  const d = definitions(texte);
  const ids = new Set([...d.ex, ...d.familles]);
  for (const m of texte.matchAll(/^(DM-[0-9]+)\s/gm)) ids.add(m[1]);
  for (const m of texte.matchAll(/^\*\*((?:IR|IC|RB)-[0-9]+)\b/gm)) ids.add(m[1]);
  return ids;
}

/** Vérification complète du dépôt : rend { erreurs, comptes }. */
export function verifierRenvois(racine = RACINE) {
  const dir = path.join(racine, "spec");
  const texteCT8 = fs.readFileSync(path.join(dir, FICHIER_CT8), "utf8");
  const table = tableTC(texteCT8);
  const definis = definisCT8(texteCT8);
  const erreurs = [];
  const comptes = [];
  const occ = [];
  for (const [f, prefixe] of FICHIERS) {
    const o = occurrences(prefixe, fs.readFileSync(path.join(dir, f), "utf8"));
    occ.push(...o);
    comptes.push({ fichier: f, occurrences: o.length, lignes: table.filter((t) => t.cle.startsWith(`${prefixe} `)).length });
  }
  // Une ligne par occurrence, section par section.
  const parCle = (liste) => liste.reduce((m, x) => m.set(x.cle, (m.get(x.cle) ?? 0) + 1), new Map());
  const a = parCle(occ);
  const b = parCle(table);
  for (const [cle, n] of a) if ((b.get(cle) ?? 0) < n) erreurs.push(`${cle} : ${n} occurrence(s) de CT-8, ${b.get(cle) ?? 0} ligne(s) dans la table`);
  for (const [cle, n] of b) if ((a.get(cle) ?? 0) < n) erreurs.push(`${cle} : ${n} ligne(s) dans la table, ${a.get(cle) ?? 0} occurrence(s) de CT-8`);
  // TC- uniques et consécutifs.
  table.forEach((t, i) => { if (t.n !== i + 1) erreurs.push(`${t.id} : TC-${i + 1} attendu à cette place (numéros uniques et consécutifs)`); });
  // Identifiants cités par les réponses.
  for (const t of table) for (const id of identifiantsCites(t.reponse)) if (!definis.has(id)) erreurs.push(`${t.id} : la réponse cite ${id}, qui n'existe pas dans CT-8`);
  return { erreurs, comptes, occurrences: occ.length, lignes: table.length };
}

function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { json: { type: "boolean" } } }).values;
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\nUsage : node scripts/deploiement/renvois.mjs [--json]\n`);
    return 2;
  }
  const r = verifierRenvois();
  if (o.json) process.stdout.write(JSON.stringify(r, null, 2) + "\n");
  else {
    for (const c of r.comptes) process.stdout.write(`${c.fichier} : ${c.occurrences} occurrence(s), ${c.lignes} ligne(s)\n`);
    process.stdout.write(`total : ${r.occurrences} occurrence(s), ${r.lignes} ligne(s) dans la table de CT-8 §0.2\n`);
    for (const e of r.erreurs) process.stdout.write(`ÉCART : ${e}\n`);
    process.stdout.write(r.erreurs.length ? `${r.erreurs.length} écart(s)\n` : "aucun écart\n");
  }
  return r.erreurs.length ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
