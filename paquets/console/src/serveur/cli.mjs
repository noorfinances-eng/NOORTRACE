// Ligne de commande du serveur de console (contrat 2.1) :
//   noortrace-console --config <fichier>                  sert la console (EX-10.13)
//   noortrace-console valider-configuration <fichier>     rapport d'EX-10.13, codes 0, 1, 2
//   noortrace-console sonde [--config <fichier>]          sonde d'EX-13.44, codes 0 et 1
//   noortrace-console --version                           nom et version du paquet
// Usage incorrect : code 2, sauf pour `sonde`, qui ne rend que 0 ou 1
// (EX-13.44 : « aucune autre valeur » ; révision 0.6 de CT-3, 15.2).
// Refus au démarrage : la ligne `$defs/rapport_validation` d'EX-10.14 sur la
// sortie d'erreur, code 1 ; une cause qu'aucun code ne nomme (manifeste des
// pages en écart) est écrite comme texte.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { validerConfiguration } from "./configuration.mjs";
import { ErreurDemarrage } from "./outils.mjs";
import { sonder, CONFIGURATION_DEFAUT } from "./sonde.mjs";

const USAGE = `usage :
  noortrace-console --config <fichier>
  noortrace-console valider-configuration <fichier>
  noortrace-console sonde [--config <fichier>]
  noortrace-console --version
`;

const usage = () => {
  process.stderr.write(USAGE);
  return 2;
};

/**
 * @param {string[]} args arguments après le nom de la commande
 * @returns {Promise<number>} code de sortie
 */
export async function principal(args) {
  if (args.length === 1 && args[0] === "--version") {
    const p = JSON.parse(fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    process.stdout.write(`${p.name} ${p.version}\n`);
    return 0;
  }
  if (args[0] === "valider-configuration") {
    if (args.length !== 2) return usage();
    let octets;
    try {
      octets = fs.readFileSync(args[1]);
    } catch {
      octets = null;
    }
    const rapport = octets === null ? { valide: false, errors: [{ code: "json", pointer: "" }] } : validerConfiguration(octets);
    process.stdout.write(JSON.stringify(rapport) + "\n");
    return rapport.valide ? 0 : 1;
  }
  if (args[0] === "sonde") {
    let chemin = CONFIGURATION_DEFAUT;
    if (args.length === 3 && args[1] === "--config") chemin = args[2];
    else if (args.length !== 1) {
      process.stderr.write(USAGE);
      return 1;
    }
    const r = await sonder({ chemin });
    process.stdout.write(r.sortie);
    process.stderr.write(r.erreur);
    return r.code;
  }
  if (args.length === 2 && args[0] === "--config") return servir(args[1]);
  return usage();
}

/** Sert la console jusqu'à SIGTERM ou SIGINT. */
async function servir(fichier) {
  let config;
  let octets;
  try {
    octets = fs.readFileSync(fichier);
  } catch {
    octets = null;
  }
  const rapport = octets === null ? { valide: false, errors: [{ code: "json", pointer: "" }] } : validerConfiguration(octets);
  if (!rapport.valide) {
    process.stderr.write(JSON.stringify(rapport) + "\n");
    return 1;
  }
  config = lireJsonStrict(octets);
  const { demarrerServeur } = await import("./index.mjs");
  let srv;
  try {
    srv = await demarrerServeur({ config, base: path.dirname(path.resolve(fichier)) });
  } catch (e) {
    if (!(e instanceof ErreurDemarrage)) throw e;
    process.stderr.write(e.rapport !== null ? JSON.stringify(e.rapport) + "\n" : `noortrace-console : ${e.message}\n`);
    return 1;
  }
  process.stdout.write(JSON.stringify({ pret: true, pid: process.pid, ecoute: srv.adresse }) + "\n");
  await new Promise((resoudre) => {
    const arret = () => {
      process.off("SIGTERM", arret);
      process.off("SIGINT", arret);
      srv.arreter().then(resoudre, resoudre);
    };
    process.on("SIGTERM", arret);
    process.on("SIGINT", arret);
  });
  return 0;
}
