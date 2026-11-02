// Ligne de commande du service : `noortrace-approbation --config <fichier>`
// démarre le service (une ligne JSON sur la sortie standard quand il écoute,
// arrêt propre sur SIGTERM ou SIGINT) ; `noortrace-approbation
// valider-politique <fichier> [--environment production|developpement]
// [--expire-after-ms N]` valide un document `politique-approbation-v0` hors
// protocole (CT-3 EX-4.2, point 4 compris) ; `--version`.

import fs from "node:fs";
import path from "node:path";
import { chargerConfiguration } from "./configuration.mjs";
import { demarrerService } from "./demarrage.mjs";
import { validerPolitique, avertissementsPolitique } from "./politique.mjs";
import { lireJsonStrict } from "./json.mjs";

const USAGE = `usage :
  noortrace-approbation --config <fichier>
  noortrace-approbation valider-politique <fichier> [--environment production|developpement] [--expire-after-ms N]
  noortrace-approbation --version`;

function option(args, nom) {
  const k = args.indexOf(nom);
  return k >= 0 ? args[k + 1] : undefined;
}

/**
 * @param {string[]} args
 * @returns {Promise<number>} code de sortie (0, 1 refus, 2 usage)
 */
export async function principal(args) {
  if (args.includes("--version")) {
    const p = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    process.stdout.write(`${p.name} ${p.version}\n`);
    return 0;
  }
  if (args[0] === "valider-politique") {
    const fichier = args[1];
    if (!fichier) {
      process.stderr.write(USAGE + "\n");
      return 2;
    }
    const environment = option(args, "--environment") ?? "developpement";
    const expire = Number(option(args, "--expire-after-ms") ?? 3600000);
    let doc;
    try {
      doc = lireJsonStrict(fs.readFileSync(fichier), { substituts: "admis" });
    } catch (e) {
      process.stdout.write(JSON.stringify({ valide: false, errors: [{ code: "schema", pointer: null }], message: e.message }) + "\n");
      return 1;
    }
    const errors = validerPolitique(doc, { environment, expire_after_ms: expire });
    const warnings = errors.length ? [] : avertissementsPolitique(doc, {});
    process.stdout.write(JSON.stringify({ valide: errors.length === 0, errors, warnings }) + "\n");
    return errors.length === 0 ? 0 : 1;
  }
  const chemin = option(args, "--config");
  if (!chemin) {
    process.stderr.write(USAGE + "\n");
    return 2;
  }
  let charge;
  try {
    charge = chargerConfiguration(chemin);
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 1;
  }
  let instance;
  try {
    instance = await demarrerService({ config: charge.config, secrets: charge.secrets, base: path.dirname(path.resolve(chemin)) });
  } catch (e) {
    process.stderr.write(`démarrage refusé : ${e.message}\n`);
    return 1;
  }
  process.stdout.write(JSON.stringify({ pret: true, pid: process.pid, noyau: instance.noyau, console: instance.console }) + "\n");
  return new Promise((resoudre) => {
    let fin = false;
    const arreter = async () => {
      if (fin) return;
      fin = true;
      await instance.arreter().catch(() => {});
      resoudre(0);
    };
    process.on("SIGTERM", arreter);
    process.on("SIGINT", arreter);
  });
}
