#!/usr/bin/env node
// Générateur des vecteurs de CT-8 (spec/CT-8-deploiement-et-exploitation.md,
// annexe A) : spec/vecteurs/ct-8/.
//
//   node scripts/vecteurs/generer-ct8.mjs [--sortie <répertoire ct-8>]
//   npm run vecteurs:ct8
//
// Familles écrites (EX-A.1), chacune par son module de scripts/vecteurs/ct8/ :
//
//   conteneurs/  fichiers Compose de référence et 23 variantes à un seul
//                remplacement, rapports CO-1 à CO-14 attendus (A.3) ;
//   controle-prealable/
//                observations d'un hôte et évaluation IP-1 à IP-13 attendue
//                (A.4) ;
//   dimensionnement/
//                entrées et sorties exactes du calculateur, seize cas de 9.6
//                (A.5) ;
//   observation/ marques, correspondance avec CT-3, réponses du service,
//                journal d'exemple de 12.4, rapport attendu et suites
//                invalides d'OB-1 à OB-4 (A.8) ;
//   journaux/    répertoires de journal et rapports verification-journal-v0
//                attendus de l'outil d'EX-11.7 (A.6) ;
//   proces-verbaux/
//                procès-verbaux valides et invalides, résultats PV-1 à PV-10
//                attendus (A.7) ;
//   consultations/
//                fichiers du journal des consultations, résultats CA-1 à CA-6
//                attendus (A.7) ;
//   acceptation-exploitation/, acceptation-observation/ et leurs grilles
//                acceptation-*-attendu.json (A.9, section 14) ;
//   paquets/     paquets réviseurs de §13 (A.10) : description.json,
//                valide.tar et ses variantes, cas.json dont les résultats
//                attendus viennent de l'outil de vérification de référence
//                (EX-A.10 à EX-A.14) ;
//   INDEX.md     une section par famille écrite, une ligne par cas, la
//                commande qui le rejoue et le résultat attendu (EX-A.3).
//
// Chaque famille efface son propre répertoire avant de l'écrire ; rien d'autre
// n'est effacé. Les sous-répertoires confrontation/ et
// verificateur-independant/ ne sont jamais écrits ni effacés. Deux exécutions
// donnent des fichiers identiques octet pour octet (EX-A.1). Le générateur
// lit les vecteurs de CT-1, CT-3, CT-4, CT-6 et CT-7 sans jamais les réécrire
// (EX-A.2).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as Deploiement from "./ct8/deploiement.mjs";
import * as Exploitation from "./ct8/exploitation.mjs";
import * as Paquets from "./ct8/paquets.mjs";

const RACINE_PROJET = fileURLToPath(new URL("../../", import.meta.url));
export const REPERTOIRE_CT8 = path.join(RACINE_PROJET, "spec", "vecteurs", "ct-8");

/**
 * Familles, dans l'ordre d'INDEX.md : nom du répertoire (ou des répertoires
 * et fichiers écrits à la racine de ct-8 quand `racine` est vrai), fonction
 * qui l'écrit et rend ce que la section d'INDEX.md reprend, fonction qui
 * écrit la section. Les familles de l'exploitation reçoivent le journal
 * d'exemple de 12.4, calculé une fois.
 */
export const FAMILLES = [
  { nom: "conteneurs", generer: Deploiement.genererConteneurs, section: Deploiement.sectionConteneurs },
  { nom: "controle-prealable", generer: Deploiement.genererControle, section: Deploiement.sectionControle },
  { nom: "dimensionnement", generer: Deploiement.genererDimensionnement, section: Deploiement.sectionDimensionnement },
  { nom: "observation", generer: Exploitation.genererObservation, section: Exploitation.sectionObservation },
  { nom: "journaux", generer: Exploitation.genererJournaux, section: Exploitation.sectionJournaux },
  { nom: "proces-verbaux", generer: Exploitation.genererProcesVerbaux, section: Exploitation.sectionProcesVerbaux },
  { nom: "consultations", generer: Exploitation.genererConsultations, section: Exploitation.sectionConsultations },
  { nom: "acceptation-exploitation/`, `acceptation-observation", racine: true, generer: Exploitation.genererAcceptation, section: Exploitation.sectionAcceptation },
  { nom: "paquets", generer: Paquets.genererPaquets, section: Paquets.sectionIndex },
];

function entete(familles) {
  return [
    "# Vecteurs CT-8 — déploiement et exploitation",
    "",
    "Produit par `scripts/vecteurs/generer-ct8.mjs` (`npm run vecteurs:ct8`) ; ne pas",
    "l'éditer à la main. Spécification :",
    "[`spec/CT-8-deploiement-et-exploitation.md`](../../CT-8-deploiement-et-exploitation.md),",
    "annexe A.",
    "",
    "Le générateur lit les vecteurs de CT-1, CT-3, CT-4, CT-6 et CT-7 et les",
    "fichiers de référence de `deploiement/` sans jamais les réécrire (EX-A.2). Il",
    "n'écrit ni n'efface `confrontation/` ni `verificateur-independant/`. Deux",
    "exécutions donnent des fichiers identiques (EX-A.1).",
    "",
    "Familles de cette génération :",
    ...familles.map((f, i) => `\`${f}/\`${i === familles.length - 1 ? "." : ","}`),
    "",
    "```bash",
    "npm run vecteurs:ct8",
    "npm run deploiement:conteneurs   # code 0",
    "node scripts/paquet-reviseur/verifier.mjs spec/vecteurs/ct-8/paquets/valide.tar   # code 0",
    "node scripts/deploiement/verifier-journal.mjs spec/vecteurs/ct-8/journaux/valide --cles spec/vecteurs/ct-8/journaux/valide/cles.json   # code 0",
    "```",
  ].join("\n");
}

export function generer(sortie = REPERTOIRE_CT8) {
  fs.mkdirSync(sortie, { recursive: true });
  const sections = [];
  const exemple = Exploitation.journalExemple();
  for (const f of FAMILLES) {
    const r = f.generer(f.racine ? sortie : path.join(sortie, f.nom), exemple);
    sections.push(f.section(r));
  }
  const index = [entete(FAMILLES.map((f) => f.nom)), ...sections].join("\n\n") + "\n";
  fs.writeFileSync(path.join(sortie, "INDEX.md"), index);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const args = process.argv.slice(2);
  let sortie = REPERTOIRE_CT8;
  if (args.length === 2 && args[0] === "--sortie") sortie = path.resolve(args[1]);
  else if (args.length) {
    console.error("usage : node scripts/vecteurs/generer-ct8.mjs [--sortie <répertoire ct-8>]");
    process.exit(2);
  }
  try {
    generer(sortie);
  } catch (err) {
    console.error(`Erreur : ${err.message}`);
    process.exit(1);
  }
  console.log(`Vecteurs CT-8 écrits dans ${path.relative(process.cwd(), sortie) || "."}`);
}
