#!/usr/bin/env node
// Générateur des règles d'alerte de référence (CT-8 §10.4 à §10.7, EX-10.6).
//
//   node scripts/deploiement/regles.mjs
//       écrit sur la sortie standard le fichier de référence, identique octet
//       pour octet à deploiement/observabilite/regles-noortrace.yml (SV-6) ;
//   node scripts/deploiement/regles.mjs --configuration <configuration de
//       l'enregistreur> [--ancrage <document ancrage-v0>] [--instance
//       <manifeste d'instance>] [--dimensionnement <entrées du calculateur>]
//       [--txpool-max-pending <n>] [--rpo <secondes>] [--sortie <fichier>]
//       écrit les mêmes règles avec les valeurs du client ;
//   node scripts/deploiement/regles.mjs --tests [mêmes options]
//       écrit le fichier des tests des règles (promtool test rules) pour ces
//       valeurs ;
//   node scripts/deploiement/regles.mjs --reference <répertoire>
//       écrit les quatre fichiers de référence de deploiement/observabilite/
//       (regles-noortrace.yml, tests-regles.yml, prometheus.yml,
//       tableau-noortrace.json).
//
// Les documents ne sont pas validés contre leur schéma : seuls les membres
// lus sont contrôlés (type et bornes du schéma). --dimensionnement lance le
// calculateur de la section 9 sur les entrées et en tire <A_h>.
// Codes : 0 écrit ; 1 document illisible ou refusé ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { dimensionner, messageOptions, texteJSON } from "../lib/deploiement.mjs";
import { ErreurParametres, genererCollecte, genererRegles, genererTableau, genererTestsRegles, parametresRegles } from "../lib/supervision.mjs";

const USAGE = [
  "Usage : node scripts/deploiement/regles.mjs [--configuration <fichier>] [--ancrage <fichier>] [--instance <fichier>]",
  "          [--dimensionnement <entrées>] [--txpool-max-pending <n>] [--rpo <s>] [--tests] [--sortie <fichier>]",
  "        node scripts/deploiement/regles.mjs --reference <répertoire>",
].join("\n");

/** Fichiers de référence de deploiement/observabilite/, par nom. */
export function fichiersReference() {
  return new Map([
    ["regles-noortrace.yml", genererRegles()],
    ["tests-regles.yml", genererTestsRegles()],
    ["prometheus.yml", genererCollecte()],
    ["tableau-noortrace.json", texteJSON(genererTableau())],
  ]);
}

function lireDocument(f, quoi) {
  let texte;
  try {
    texte = fs.readFileSync(f, "utf8");
  } catch (e) {
    throw new ErreurParametres(`${quoi} illisible : ${f} (${e.code ?? e.message})`);
  }
  try {
    return JSON.parse(texte);
  } catch (e) {
    throw new ErreurParametres(`${quoi} : JSON invalide (${e.message})`);
  }
}

export function principal(argv, sortie = process.stdout, erreur = process.stderr) {
  let o;
  try {
    o = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        configuration: { type: "string" },
        ancrage: { type: "string" },
        instance: { type: "string" },
        dimensionnement: { type: "string" },
        "txpool-max-pending": { type: "string" },
        rpo: { type: "string" },
        tests: { type: "boolean" },
        sortie: { type: "string" },
        reference: { type: "string" },
      },
    }).values;
    if (o.reference !== undefined && Object.keys(o).length > 1) throw new Error("--reference ne se combine avec aucune autre option");
    for (const k of ["txpool-max-pending", "rpo"]) if (o[k] !== undefined && !/^[0-9]{1,10}$/.test(o[k])) throw new Error(`--${k} : entier attendu`);
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  if (o.reference !== undefined) {
    fs.mkdirSync(o.reference, { recursive: true });
    for (const [nom, texte] of fichiersReference()) fs.writeFileSync(path.join(o.reference, nom), texte);
    sortie.write(`4 fichiers écrits sous ${o.reference}\n`);
    return 0;
  }
  let texte;
  try {
    const docs = {
      configuration: o.configuration !== undefined ? lireDocument(o.configuration, "configuration") : null,
      ancrage: o.ancrage !== undefined ? lireDocument(o.ancrage, "document d'ancrage") : null,
      instance: o.instance !== undefined ? lireDocument(o.instance, "manifeste d'instance") : null,
      dimensionnement: null,
      txpool_max_pending: o["txpool-max-pending"] !== undefined ? Number(o["txpool-max-pending"]) : null,
      rpo_s: o.rpo !== undefined ? Number(o.rpo) : null,
    };
    if (o.dimensionnement !== undefined) {
      const entrees = lireDocument(o.dimensionnement, "entrées du dimensionnement");
      const e = entrees;
      let s;
      try {
        s = dimensionner(e);
      } catch (err) {
        throw new ErreurParametres(`dimensionnement : ${err.message}`);
      }
      if (!s.valid) throw new ErreurParametres(`dimensionnement refusé : ${JSON.stringify(s.errors)}`);
      docs.dimensionnement = { entrees: e, sortie: s };
    }
    texte = o.tests ? genererTestsRegles(parametresRegles(docs)) : genererRegles(docs);
  } catch (err) {
    if (!(err instanceof ErreurParametres)) throw err;
    erreur.write(`Erreur : ${err.message}\n`);
    return 1;
  }
  if (o.sortie !== undefined) fs.writeFileSync(o.sortie, texte);
  else sortie.write(texte);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
