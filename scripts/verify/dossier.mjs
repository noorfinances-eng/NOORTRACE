#!/usr/bin/env node
// Vérificateur en ligne de commande d'un dossier de preuve NOORTRACE v0
// (spec/CT-1-evenements-et-formats.md §11). Il exécute les contrôles 1, 2, 3, 6
// et 7 de l'architecture, soit les contrôles D-1 à A-4 de CT-1 §11.4, hors
// ligne : l'événement est bien formé, haché et signé comme annoncé, chaîné à
// ses voisins, inclus dans la racine du manifeste de sa période, lequel est
// signé par la clé annoncée, et approuvé par les adresses déclarées au seuil
// déclaré. La logique est dans scripts/lib/journal.mjs ; ce fichier porte la
// ligne de commande et le rapport.
//
//   node scripts/verify/dossier.mjs <répertoire> [--schemas <répertoire>] [--json]
//   npm run verify:dossier -- spec/vecteurs/ct-1/dossiers/valide-seq-7
//
// Options :
//   <répertoire>          le dossier : contient dossier.json et les parties présentes
//   --schemas <dir>       répertoire des schémas JSON (défaut : spec/schemas du projet)
//   --json                rapport en JSON au lieu du rapport lisible
//
// Codes de retour : 0 dossier valide (tous les contrôles exécutés passent et
// aucun contrôle n'est non exécuté sans raison admise, CT-1 §11.4) ; 1 dossier
// invalide (au moins un contrôle en échec, ou non exécuté sans raison admise :
// partie inexploitable) ; 2 entrée inutilisable
// (répertoire ou schémas illisibles, dossier.json absent ou qui n'est pas du
// JSON). Le code 1 est une affirmation sur le dossier ; le code 2 n'en est pas une.
//
// Les parties réservées à CT-4 et CT-5 (jeton RFC 3161, preuve OpenTimestamps,
// reçu du registre, certificat de commit, validateurs) ne sont pas vérifiées
// ici : quand elles sont absentes, le rapport énonce la borne du verdict (rien
// sur la date, rien sur l'ancre). Ne dépend pas de Hardhat : node et ethers suffisent.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DossierInutilisable, controlesEnEchec, registreSchemas, verifierDossier } from "../lib/journal.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const CODE_VALIDE = 0;
const CODE_INVALIDE = 1;
const CODE_INUTILISABLE = 2;
const FICHIERS_SCHEMAS = ["evenement-v0.schema.json", "manifeste-v0.schema.json", "dossier-v0.schema.json"];

class EntreeInutilisable extends Error {}

/** Analyse argv : un argument positionnel (le répertoire), --schemas <dir>, --json, --aide. */
function analyserArguments(argv) {
  const avecValeur = new Set(["schemas"]);
  const drapeaux = new Set(["json", "aide", "help"]);
  const options = { positionnels: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      options.positionnels.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const nom = eq === -1 ? a.slice(2) : a.slice(2, eq);
    if (drapeaux.has(nom)) {
      options[nom] = true;
    } else if (avecValeur.has(nom)) {
      const valeur = eq === -1 ? argv[++i] : a.slice(eq + 1);
      if (valeur === undefined || valeur.startsWith("--")) throw new EntreeInutilisable(`l'option --${nom} attend une valeur`);
      options[nom] = valeur;
    } else {
      throw new EntreeInutilisable(`option inconnue : ${a}`);
    }
  }
  return options;
}

function aide() {
  return [
    "Usage :",
    "  node scripts/verify/dossier.mjs <répertoire> [--schemas <répertoire>] [--json]",
    "Vérifie un dossier de preuve NOORTRACE v0 (contrôles D-1 à A-4 de CT-1 §11.4).",
    "Codes de retour : 0 valide, 1 invalide, 2 entrée inutilisable.",
  ].join("\n");
}

/** Les trois schémas, chargés depuis un répertoire. */
function chargerSchemas(repertoire) {
  const documents = FICHIERS_SCHEMAS.map((nom) => {
    const fichier = path.join(repertoire, nom);
    let texte;
    try {
      texte = fs.readFileSync(fichier, "utf8");
    } catch (err) {
      throw new EntreeInutilisable(`schéma illisible (${fichier}) : ${err.message}`);
    }
    try {
      return JSON.parse(texte);
    } catch (err) {
      throw new EntreeInutilisable(`schéma (${fichier}) qui n'est pas du JSON : ${err.message}`);
    }
  });
  return registreSchemas(documents);
}

/** Les fichiers réguliers du répertoire, nom -> octets. */
function lireRepertoire(repertoire) {
  let entrees;
  try {
    entrees = fs.readdirSync(repertoire, { withFileTypes: true });
  } catch (err) {
    throw new EntreeInutilisable(`répertoire illisible (${repertoire}) : ${err.message}`);
  }
  const fichiers = {};
  for (const e of entrees) if (e.isFile()) fichiers[e.name] = fs.readFileSync(path.join(repertoire, e.name));
  return fichiers;
}

function principal() {
  const options = analyserArguments(process.argv.slice(2));
  if (options.aide || options.help) {
    process.stdout.write(aide() + "\n");
    return CODE_VALIDE;
  }
  if (options.positionnels.length !== 1) throw new EntreeInutilisable(`un répertoire de dossier attendu, ${options.positionnels.length} argument(s) reçu(s)`);
  const repertoire = path.resolve(options.positionnels[0]);
  const repertoireSchemas = path.resolve(options.schemas ?? path.join(PROJECT_ROOT, "spec", "schemas"));
  const schemas = chargerSchemas(repertoireSchemas);
  const fichiers = lireRepertoire(repertoire);

  let resultat;
  try {
    resultat = verifierDossier(fichiers, { schemas });
  } catch (err) {
    if (err instanceof DossierInutilisable) throw new EntreeInutilisable(err.message);
    throw err;
  }
  const rapport = { ...resultat, controlesEnEchec: controlesEnEchec(resultat), repertoire, schemas: repertoireSchemas };
  if (options.json) process.stdout.write(JSON.stringify(rapport, null, 2) + "\n");
  else process.stdout.write(rapportLisible(rapport) + "\n");
  return resultat.valide ? CODE_VALIDE : CODE_INVALIDE;
}

/** Rapport lisible en français. */
function rapportLisible(r) {
  const lignes = [];
  lignes.push("Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1)");
  lignes.push(`Répertoire    : ${r.repertoire}`);
  lignes.push(`Schémas       : ${r.schemas}`);
  if (r.evenement) lignes.push(`Événement     : seq ${r.evenement.seq}, hash ${r.evenement.hash}${r.evenement.ts ? `, ts ${r.evenement.ts}` : ""}${r.evenement.tool ? `, outil ${r.evenement.tool}` : ""}`);
  if (r.org_id) lignes.push(`Journal       : org_id ${r.org_id}, journal_id ${r.journal_id}`);
  lignes.push("Contrôles (architecture entre crochets) :");
  for (const c of r.controles) {
    const etat = !c.execute ? "[non exécuté]" : c.ok ? "[ok]         " : "[ÉCHEC]      ";
    const archi = c.architecture === null ? "   " : `[${c.architecture}]`;
    lignes.push(`  ${etat} ${c.id.padEnd(4)} ${archi} ${c.libelle}`);
    if (c.detail && (!c.ok || !c.execute)) lignes.push(`                      ${c.detail}`);
  }
  if (r.partiesAbsentes.length) lignes.push(`Parties absentes : ${r.partiesAbsentes.map((p) => `${p.file} (${p.reason})`).join(", ")}`);
  if (r.borne) lignes.push(`Borne         : ${r.borne}`);
  const motifs = [];
  if (r.controlesEnEchec.length) motifs.push(`contrôle(s) en échec : ${r.controlesEnEchec.join(", ")}`);
  if (r.nonExecutesBloquants.length) motifs.push(`contrôle(s) non exécuté(s) sans raison admise : ${r.nonExecutesBloquants.join(", ")}`);
  lignes.push(`Résultat      : ${r.valide ? "VALIDE" : "INVALIDE"} — ${r.valide ? "tous les contrôles exécutés passent, aucun contrôle non exécuté sans raison admise" : motifs.join(" ; ")}`);
  return lignes.join("\n");
}

try {
  process.exit(principal());
} catch (err) {
  const message = err instanceof EntreeInutilisable ? err.message : `erreur inattendue : ${err?.stack ?? err}`;
  process.stderr.write(`Erreur : ${message}\n`);
  if (process.argv.includes("--json")) process.stdout.write(JSON.stringify({ valide: null, erreur: message }) + "\n");
  process.exit(CODE_INUTILISABLE);
}
