#!/usr/bin/env node
// Construction des fichiers de la page de vérification (CT-6 §18, EX-18.6).
//
// node paquets/verification-web/src/construire.mjs --wasm <répertoire> --version <version> --sortie <répertoire>
//
// --wasm : le répertoire qu'a rempli verificateur/scripts/construire-wasm.sh
// (noortrace-verifier.wasm et wasm_exec.js) ; --version : la version des
// binaires, la même que celle passée à construire-wasm.sh ; --sortie : un
// répertoire absent ou vide. Le script y écrit index.html, page.css, page.js,
// verificateur-wasm.js, travailleur.js, noortrace-verifier.wasm, SHA256SUMS et
// en-tetes.json, de façon déterministe : aucune date, aucun aléa, aucun chemin
// de la machine ; deux exécutions sur les mêmes entrées donnent les mêmes
// octets.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const SOURCES_PAGE = path.join(ICI, "page");
const SOURCES_TRAVAILLEUR = path.join(ICI, "travailleur");

/** Modules de page.js, dans l'ordre d'assemblage. */
export const MODULES_PAGE = ["libelles-fr.js", "libelles-en.js", "archives.js", "interface.js"];

/** Les six fichiers de la page couverts par SHA256SUMS (EX-18.4, table de 18.3). */
export const FICHIERS_PAGE = [
  "index.html",
  "noortrace-verifier.wasm",
  "page.css",
  "page.js",
  "travailleur.js",
  "verificateur-wasm.js",
];

const POLITIQUE_PAGE = "default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types noortrace-travailleur";
const POLITIQUE_TRAVAILLEUR = "default-src 'none'; script-src 'wasm-unsafe-eval'";

const TYPES = {
  "index.html": "text/html; charset=utf-8",
  "page.css": "text/css; charset=utf-8",
  "page.js": "text/javascript; charset=utf-8",
  "verificateur-wasm.js": "text/javascript; charset=utf-8",
  "travailleur.js": "text/javascript; charset=utf-8",
  "noortrace-verifier.wasm": "application/wasm",
};

/** En-têtes d'EX-18.12, par fichier, dans l'ordre de la table. */
export function enTetes() {
  const r = {};
  for (const f of FICHIERS_PAGE) {
    const h = {};
    if (f === "index.html") {
      h["Content-Security-Policy"] = POLITIQUE_PAGE;
      h["Integrity-Policy"] = "blocked-destinations=(script style)";
      h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
    }
    if (f === "travailleur.js") h["Content-Security-Policy"] = POLITIQUE_TRAVAILLEUR;
    h["Content-Type"] = TYPES[f];
    h["X-Content-Type-Options"] = "nosniff";
    h["Referrer-Policy"] = "no-referrer";
    h["Cross-Origin-Opener-Policy"] = "same-origin";
    h["Cross-Origin-Resource-Policy"] = "same-origin";
    h["Strict-Transport-Security"] = "max-age=31536000";
    if (f === "noortrace-verifier.wasm") h["Content-Disposition"] = "attachment";
    r[f] = h;
  }
  return r;
}

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const integrite = (b) => `sha384-${crypto.createHash("sha384").update(b).digest("base64")}`;

function remplacerUneFois(texte, marque, valeur, fichier) {
  const i = texte.indexOf(marque);
  if (i < 0 || texte.indexOf(marque, i + marque.length) >= 0) {
    throw new Error(`${fichier} : la marque ${marque} doit figurer exactement une fois`);
  }
  return texte.slice(0, i) + valeur + texte.slice(i + marque.length);
}

function echapperHtml(t) {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function lireTexte(fichier) {
  const b = fs.readFileSync(fichier);
  const t = new TextDecoder("utf-8", { fatal: true }).decode(b);
  if (t.includes("\r")) throw new Error(`${path.basename(fichier)} : retour chariot interdit`);
  return t;
}

/** Libellés français, lus dans libelles-fr.js sans l'importer. */
function libellesFrancais() {
  const source = lireTexte(path.join(SOURCES_PAGE, "libelles-fr.js"));
  return vm.runInNewContext(`${source}\nLIBELLES_FR;`, {}, { filename: "libelles-fr.js" });
}

/** Texte de travailleur.js : prélude ‖ wasm_exec.js sans changement ‖ pilote. */
export function texteTravailleur(wasmExec, empreinte, version) {
  const prelude = lireTexte(path.join(SOURCES_TRAVAILLEUR, "prelude.js"));
  let pilote = lireTexte(path.join(SOURCES_TRAVAILLEUR, "pilote.js"));
  pilote = remplacerUneFois(pilote, "@@EMPREINTE_WASM@@", empreinte, "pilote.js");
  pilote = remplacerUneFois(pilote, "@@VERSION@@", version, "pilote.js");
  return prelude + wasmExec + pilote;
}

/** Texte de page.js : un seul script classique, sans importation. */
export function textePage(version) {
  let t = '"use strict";\n';
  t += "// page.js de la page de vérification NOORTRACE (CT-6 §18), assemblé par\n";
  t += "// paquets/verification-web/src/construire.mjs depuis src/page/ : libellés,\n";
  t += "// lecture des archives, interface. Script classique, sans importation.\n";
  t += "(() => {\n";
  t += `const VERSION_VERIFICATEUR = ${JSON.stringify(version)};\n`;
  for (const m of MODULES_PAGE) {
    t += `\n// --- ${m} ---\n`;
    t += lireTexte(path.join(SOURCES_PAGE, m));
  }
  t += "})();\n";
  return t;
}

/** index.html : modèle rempli des libellés français, de la version et des intégrités. */
export function texteIndex(version, integrites) {
  let t = lireTexte(path.join(SOURCES_PAGE, "index.modele.html"));
  t = remplacerUneFois(t, "{{INTEGRITE_PAGE_CSS}}", integrites["page.css"], "index.modele.html");
  t = remplacerUneFois(t, "{{INTEGRITE_VERIFICATEUR_WASM_JS}}", integrites["verificateur-wasm.js"], "index.modele.html");
  t = remplacerUneFois(t, "{{INTEGRITE_PAGE_JS}}", integrites["page.js"], "index.modele.html");
  const libelles = libellesFrancais();
  t = t.replace(/\{\{([a-z0-9_]+)\}\}/g, (tout, cle) => {
    if (!Object.hasOwn(libelles, cle)) throw new Error(`index.modele.html : libellé inconnu ${cle}`);
    return echapperHtml(libelles[cle].replaceAll("{version}", version));
  });
  if (t.includes("{{")) throw new Error("index.modele.html : marque non remplacée");
  return t;
}

const MOTIF_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/;

/**
 * Construit la page dans `sortie` (absent ou vide) depuis le répertoire
 * `wasm` ; rend le texte de SHA256SUMS.
 */
export function construire({ wasm, version, sortie }) {
  if (!MOTIF_VERSION.test(version)) throw new Error(`version mal formée : ${version}`);
  const artefact = fs.readFileSync(path.join(wasm, "noortrace-verifier.wasm"));
  const wasmExec = lireTexte(path.join(wasm, "wasm_exec.js"));
  if (fs.existsSync(sortie)) {
    if (!fs.statSync(sortie).isDirectory() || fs.readdirSync(sortie).length !== 0) {
      throw new Error("le répertoire de sortie doit être absent ou vide");
    }
  } else {
    fs.mkdirSync(sortie, { recursive: true });
  }
  const empreinte = `0x${sha256(artefact)}`;
  const fichiers = new Map();
  fichiers.set("noortrace-verifier.wasm", artefact);
  fichiers.set("verificateur-wasm.js", Buffer.from(`globalThis.NOORTRACE_VERIFICATEUR_WASM = "${artefact.toString("base64")}";\n`, "utf8"));
  fichiers.set("travailleur.js", Buffer.from(texteTravailleur(wasmExec, empreinte, version), "utf8"));
  fichiers.set("page.js", Buffer.from(textePage(version), "utf8"));
  fichiers.set("page.css", Buffer.from(lireTexte(path.join(SOURCES_PAGE, "page.css")), "utf8"));
  const integrites = {};
  for (const f of ["page.css", "verificateur-wasm.js", "page.js"]) integrites[f] = integrite(fichiers.get(f));
  fichiers.set("index.html", Buffer.from(texteIndex(version, integrites), "utf8"));
  const sommes = FICHIERS_PAGE.map((f) => `${sha256(fichiers.get(f))}  ${f}\n`).join("");
  fichiers.set("SHA256SUMS", Buffer.from(sommes, "utf8"));
  fichiers.set("en-tetes.json", Buffer.from(`${JSON.stringify(enTetes(), null, 2)}\n`, "utf8"));
  for (const nom of [...fichiers.keys()].sort()) fs.writeFileSync(path.join(sortie, nom), fichiers.get(nom));
  return sommes;
}

function usage(message) {
  process.stderr.write(`construire.mjs : ${message}\nusage : node construire.mjs --wasm <répertoire> --version <version> --sortie <répertoire>\n`);
  process.exit(2);
}

function principal(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const m = /^--(wasm|version|sortie)$/.exec(a);
    if (!m) usage(`argument inconnu : ${a}`);
    if (Object.hasOwn(options, m[1])) usage(`option répétée : ${a}`);
    if (i + 1 >= argv.length) usage(`option sans valeur : ${a}`);
    options[m[1]] = argv[++i];
  }
  for (const o of ["wasm", "version", "sortie"]) if (!Object.hasOwn(options, o)) usage(`option --${o} absente`);
  try {
    process.stdout.write(construire(options));
  } catch (e) {
    process.stderr.write(`construire.mjs : ${e.message}\n`);
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal(process.argv.slice(2));
}
