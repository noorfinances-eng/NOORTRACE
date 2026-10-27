#!/usr/bin/env node
// Vérification hors ligne d'un procès-verbal de cérémonie des clés
// (CT-7 §5.8, EX-A.16) : CR-1 à CR-12, condensé D_C, signataires.
//
//   node scripts/verify/ceremonie.mjs <fichier> [--json] [--condense]
//
// Codes de retour : 0 valide (ou, avec --condense, D_C calculé) ; 1 invalide
// (ou, avec --condense, CR-1 en échec) ; 2 fichier absent, illisible ou de
// plus de 1 Mio, ou arguments invalides. Aucune connexion réseau.
//
// --condense imprime D_C seul, sans exiger de signatures : c'est ce que le
// participant recalcule sur son poste avant de signer (EX-5.8).
// --json imprime le rapport : la forme de `attendu.json`
// (ceremonie-cles-v0#/$defs/attendu) plus `statuses`.

import fs from "node:fs";
import * as S from "../lib/securite.mjs";

function usage(message) {
  if (message) console.error(message);
  console.error("usage : node scripts/verify/ceremonie.mjs <fichier> [--json] [--condense]");
  process.exit(2);
}

const args = process.argv.slice(2);
const options = new Set(args.filter((a) => a.startsWith("--")));
const fichiers = args.filter((a) => !a.startsWith("--"));
for (const o of options) if (o !== "--json" && o !== "--condense") usage(`option inconnue : ${o}`);
if (fichiers.length !== 1) usage();

let octets;
try {
  const st = fs.statSync(fichiers[0]);
  if (!st.isFile()) usage(`${fichiers[0]} n'est pas un fichier`);
  if (st.size > S.LIMITE_PROCES_VERBAL) {
    console.error(`${fichiers[0]} : ${st.size} octets, plus de 1 Mio (CT-7 EX-5.9)`);
    process.exit(2);
  }
  octets = fs.readFileSync(fichiers[0]);
} catch (err) {
  console.error(`${fichiers[0]} : illisible (${err.code ?? err.message})`);
  process.exit(2);
}

const r = S.verifierCeremonie(octets);

if (options.has("--condense")) {
  if (r.digest === null) {
    console.error(`CR-1 en échec : ${r.statuses[0].detail}`);
    process.exit(1);
  }
  console.log(r.digest);
  // Par groupes de huit chiffres, pour la comparaison à l'écran du portefeuille et au second outil (CT-7 EX-5.8).
  console.error(`Groupes de huit : ${r.digest.slice(2).match(/.{8}/g).join(" ")}`);
  process.exit(0);
}

if (options.has("--json")) {
  console.log(JSON.stringify({ ...S.attenduCeremonie(r), statuses: r.statuses }, null, 2));
  process.exit(r.verdict === "valide" ? 0 : 1);
}

console.log(`Verdict : ${r.verdict}`);
console.log(`D_C : ${r.digest ?? "non calculé (CR-1 en échec)"}`);
for (const s of r.statuses) {
  if (s.status === "echoue") console.log(`[ÉCHEC] ${s.id} : ${s.detail}`);
}
if (r.not_executed.length) console.log(`Non exécutées (prérequis en échec) : ${r.not_executed.join(", ")}`);
if (r.signers.length) console.log(`Signataires vérifiés : ${r.signers.join(", ")}`);
if (r.verdict === "valide") console.log(S.phraseCeremonie(JSON.parse(octets.toString("utf8")), r));
process.exit(r.verdict === "valide" ? 0 : 1);
