#!/usr/bin/env node
// Configuration de l'installation rapide (CT-8 §7.2, pas IR-3, et §7.3).
//
//   node scripts/deploiement/configurer-rapide.mjs --org <nom court> --journal <nom> \
//     --serveur-outils https://<serveur>/mcp --sortie <configuration.json>
//
// Part de deploiement/config/rapide/configuration.json (configuration de
// référence, mode observation), recalcule recorder.org_id = orgIdOf(<org>) et
// recorder.journal_id = journalIdOf(<journal>) (CT-4 §6.2, §6.3), remplace
// policy.servers.outils.transport.url, valide le résultat contre
// configuration-enregistreur-v0 (avec politique-redaction-v0 et
// politique-approbation-v0), l'écrit en JSON indenté de deux espaces suivi
// d'un saut de ligne, et imprime org_id, journal_id, le SHA-256 du fichier et
// « configuration valide ». Avec --org organisation-exemple --journal
// journal-rapide --serveur-outils https://outils.interne.example/mcp, le
// fichier écrit est octet pour octet la configuration de référence.
// Codes : 0 écrite ; 2 usage ou configuration invalide (rien n'est écrit).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import * as J from "../lib/journal.mjs";
import { orgIdOf, journalIdOf } from "../lib/noortrace.mjs";
import { RACINE, messageOptions, texteJSON } from "../lib/deploiement.mjs";

export const REFERENCE = path.join(RACINE, "deploiement", "config", "rapide", "configuration.json");

const RE_NOM = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** Configuration de l'installation rapide pour une organisation, un journal et un serveur d'outils. Lève une Error décrite. */
export function configurationRapide({ org, journal, serveurOutils }) {
  if (!RE_NOM.test(org)) throw new Error(`--org : nom court attendu (minuscules, chiffres, tirets), reçu ${JSON.stringify(org)}`);
  if (!RE_NOM.test(journal)) throw new Error(`--journal : nom attendu (minuscules, chiffres, tirets), reçu ${JSON.stringify(journal)}`);
  let url;
  try {
    url = new URL(serveurOutils);
  } catch {
    throw new Error(`--serveur-outils : URL invalide ${JSON.stringify(serveurOutils)}`);
  }
  if (url.protocol !== "https:") throw new Error("--serveur-outils : une URL https est exigée");
  const c = JSON.parse(fs.readFileSync(REFERENCE, "utf8"));
  c.recorder.org_id = orgIdOf(org);
  c.recorder.journal_id = journalIdOf(journal);
  c.policy.servers.outils.transport.url = serveurOutils;
  const schemas = ["configuration-enregistreur", "politique-redaction", "politique-approbation"].map((n) => JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", `${n}-v0.schema.json`), "utf8")));
  const erreurs = J.validerSchema(c, schemas[0], { registre: J.registreSchemas(schemas) });
  if (erreurs.length) throw new Error(`configuration invalide : ${erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
  return texteJSON(c);
}

function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { org: { type: "string" }, journal: { type: "string" }, "serveur-outils": { type: "string" }, sortie: { type: "string" } } }).values;
    for (const k of ["org", "journal", "serveur-outils", "sortie"]) if (o[k] === undefined) throw new Error(`option --${k} requise`);
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\nUsage : node scripts/deploiement/configurer-rapide.mjs --org <nom court> --journal <nom> --serveur-outils https://<serveur>/mcp --sortie <fichier>\n`);
    return 2;
  }
  let texte;
  try {
    texte = configurationRapide({ org: o.org, journal: o.journal, serveurOutils: o["serveur-outils"] });
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  fs.writeFileSync(o.sortie, texte);
  const c = JSON.parse(texte);
  process.stdout.write(`org_id ${c.recorder.org_id}\njournal_id ${c.recorder.journal_id}\nsha256 ${crypto.createHash("sha256").update(texte).digest("hex")}\nconfiguration valide\n`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
