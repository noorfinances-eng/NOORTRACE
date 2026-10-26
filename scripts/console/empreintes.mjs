#!/usr/bin/env node
// Empreintes de la page de la console de référence (spec/CT-3-approbations.md,
// révision 0.3, EX-13.33 à EX-13.35) : intégrité sha384 du script d'entrée
// console/console.js et de la bibliothèque scripts/lib/console.mjs, carte
// d'importation qui porte cette dernière, condensé sha256 de la carte pour
// script-src, en-têtes exacts. console/index.html est entièrement produit
// ici ; un test exige qu'il soit à jour.
//
//   node scripts/console/empreintes.mjs            vérifie (code 1 si périmé)
//   node scripts/console/empreintes.mjs --ecrire   réécrit console/index.html

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RACINE = fileURLToPath(new URL("../../", import.meta.url));
/** Chemins servis depuis l'origine de la console (la racine du dépôt est servie telle quelle). */
export const CHEMIN_BIBLIOTHEQUE = "/scripts/lib/console.mjs";
export const CHEMIN_PAGE = "/console/";
export const SPECIFICATEUR = "noortrace-console";

const sri = (octets) => "sha384-" + crypto.createHash("sha384").update(octets).digest("base64");

/** Empreintes, carte d'importation, texte de index.html et en-têtes d'EX-13.35, depuis les fichiers du dépôt. */
export function empreintesConsole(racine = RACINE) {
  const bibliotheque = fs.readFileSync(path.join(racine, "scripts", "lib", "console.mjs"));
  const entree = fs.readFileSync(path.join(racine, "console", "console.js"));
  const carte = JSON.stringify({ imports: { [SPECIFICATEUR]: CHEMIN_BIBLIOTHEQUE }, integrity: { [CHEMIN_BIBLIOTHEQUE]: sri(bibliotheque) } });
  const carteSha256 = "sha256-" + crypto.createHash("sha256").update(carte, "utf8").digest("base64");
  const csp = `default-src 'none'; script-src 'self' '${carteSha256}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'`;
  const html = [
    "<!doctype html>",
    '<html lang="fr">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Console d'approbation NOORTRACE</title>",
    '<link rel="stylesheet" href="console.css">',
    `<script type="importmap">${carte}</script>`,
    `<script type="module" src="console.js" integrity="${sri(entree)}"></script>`,
    "</head>",
    "<body>",
    '<main id="console"></main>',
    "</body>",
    "</html>",
    "",
  ].join("\n");
  return {
    bibliotheque: sri(bibliotheque),
    entree: sri(entree),
    carte,
    carteSha256,
    html,
    entetes: { "content-security-policy": csp, "integrity-policy": "blocked-destinations=(script)" },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const e = empreintesConsole();
  const fichier = path.join(RACINE, "console", "index.html");
  const actuel = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : null;
  if (process.argv.includes("--ecrire")) {
    fs.writeFileSync(fichier, e.html);
    process.stdout.write(`console/index.html réécrit ; Content-Security-Policy : ${e.entetes["content-security-policy"]}\n`);
  } else if (actuel !== e.html) {
    process.stderr.write("console/index.html est périmé : node scripts/console/empreintes.mjs --ecrire\n");
    process.exit(1);
  } else {
    process.stdout.write(`console/index.html à jour ; Content-Security-Policy : ${e.entetes["content-security-policy"]}\n`);
  }
}
