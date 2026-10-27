#!/usr/bin/env node
// Outil de référence de l'attestation de périmètre (CT-7 §7.4, EX-A.17).
// Il n'ouvre aucune connexion réseau : il lit et écrit des fichiers locaux.
//
//   node scripts/conformite/attestation.mjs gabarit
//   node scripts/conformite/attestation.mjs condenser <attestation.json>
//   node scripts/conformite/attestation.mjs signer <attestation.json>
//        --cle fichier:<fichier de la clé en hexadécimal 0x>
//            | keystore:<fichier de clé chiffré de CT-3 §13.13>   [--oui]
//   node scripts/conformite/attestation.mjs assembler <attestation.json> <signature.json>…
//   node scripts/conformite/attestation.mjs verifier <fichier> [--forme] [--jeu <jeu.json>]
//
// `verifier --forme` applique à une attestation (ou à celle d'une attestation
// signée) AT-1 et les contrôles d'EX-7.3 et EX-7.4 ; `verifier --jeu`
// applique AT-1 à AT-4 à une attestation signée. Codes de retour : 0 si tout
// réussit (attestation retenue, ou forme sans erreur), 1 sinon, 2 si une
// entrée est absente ou illisible ou si les arguments sont invalides. Le mot
// de passe d'un fichier de clé chiffré est lu dans la variable
// d'environnement NOORTRACE_MOT_DE_PASSE.

import fs from "node:fs";
import readline from "node:readline";
import * as J from "../lib/journal.mjs";
import * as C from "../lib/console.mjs";
import * as S from "../lib/securite.mjs";

function sortir(code, message) {
  if (message) (code === 0 ? console.log : console.error)(message);
  process.exit(code);
}

function usage(message) {
  sortir(2, `${message ? message + "\n" : ""}usage : node scripts/conformite/attestation.mjs gabarit | condenser <fichier> | signer <fichier> --cle fichier:<chemin>|keystore:<chemin> [--oui] | assembler <fichier> <signature>… | verifier <fichier> [--forme] [--jeu <jeu.json>]`);
}

function lire(fichier) {
  let octets;
  try {
    octets = fs.readFileSync(fichier);
  } catch (err) {
    sortir(2, `${fichier} : illisible (${err.code ?? err.message})`);
  }
  try {
    return J.analyserJSONStrict(octets);
  } catch (err) {
    sortir(2, `${fichier} : JSON invalide (${err.message})`);
  }
}

/** Gabarit conforme au schéma : les valeurs sont à remplacer (7.4, pas 2). */
function gabarit() {
  const zero = "0x" + "00".repeat(32);
  return {
    version: 0,
    org: { org_id: zero, slug: "organisation", name: "Nom de l'organisation" },
    journals: [{ journal_id: zero, name: "nom-du-journal" }],
    validity: { from: "2026-01-01T00:00:00.000Z", until: "2026-12-31T23:59:59.999Z" },
    issued_at: "2026-01-01T00:00:00.000Z",
    prepared_by: { identity: "identité de l'administrateur au système d'identité", function: "fonction de l'administrateur" },
    agents: [{ agent_id: "agent-1", journal_id: zero, host: "nom-de-l-hote", framework: "cadre ou SDK de l'agent", capture_channels: ["mandataire_mcp"], notes: null }],
    tools_via_proxy_only: [{ server_alias: "alias-du-serveur", tools: ["*"], enforcement: "règle qui empêche de joindre le serveur autrement que par l'enregistreur" }],
    egress: {
      default_policy: "refus_par_defaut",
      rules_sha256: zero,
      rules_format: "format de l'export des règles de sortie",
      summary: "Résumé des règles de sortie, sans leur contenu.",
      allowed_destinations: [{ name: "fournisseurs de modèle", via: "enregistreur", description: "route de la passerelle" }],
    },
    gateway_credentials: [{ route: "/v1/messages", provider_label: "fournisseur", secret_ref: { file: "/run/secrets/cle-fournisseur" } }],
    not_captured: [],
    signatories: [{ name: "Signataire 1", function: "fonction", address: "0x" + "00".repeat(20) }],
    declaration: "Nous déclarons qu'à notre connaissance, pendant la période de validité, les agents de l'inventaire n'atteignent leurs outils et leurs modèles que par les canaux de capture indiqués, sous les règles de sortie dont l'empreinte est donnée, sauf les cas déclarés non capturés.",
  };
}

/** Membres de l'attestation en clair, pour qui la contrôle ou la signe (EX-7.8). */
function afficherMembres(P) {
  console.log(`Organisation : ${P.org?.name} (${P.org?.slug}, ${P.org?.org_id})`);
  console.log(`Journaux : ${(P.journals ?? []).map((j) => `${j.name} (${j.journal_id})`).join(", ")}`);
  console.log(`Validité : du ${P.validity?.from} au ${P.validity?.until} ; émise le ${P.issued_at}`);
  for (const a of P.agents ?? []) console.log(`Agent ${a.agent_id} : hôte ${a.host}, ${a.framework}, canaux ${(a.capture_channels ?? []).join(", ")}`);
  for (const t of P.tools_via_proxy_only ?? []) console.log(`Outils de ${t.server_alias} (${(t.tools ?? []).join(", ")}) seulement par le mandataire : ${t.enforcement}`);
  console.log(`Sortie : ${P.egress?.default_policy}, règles ${P.egress?.rules_sha256} ; ${P.egress?.summary}`);
  for (const d of P.egress?.allowed_destinations ?? []) console.log(`  destination ${d.name} par ${d.via} : ${d.description}`);
  for (const n of P.not_captured ?? []) console.log(`Non capturé : ${n.channel} : ${n.description}`);
  for (const s of P.signatories ?? []) console.log(`Signataire : ${s.name}, ${s.function}, ${s.address}`);
  console.log(`Déclaration : ${P.declaration}`);
}

/**
 * AT-1 et contrôles d'EX-7.3 et EX-7.4 avant de condenser ou de signer : une
 * attestation que l'outil refuse n'est ni condensée ni signée (code 1).
 * Avertissements et rappels sur la sortie d'erreur.
 */
function controlerAvantSignature(P) {
  const erreurs = S.formeAttestation(P);
  if (erreurs.length) sortir(1, `AT-1 en échec : ${erreurs.join(" ; ")}`);
  const c = S.controlerDeclaration(P);
  for (const a of c.avertissements) console.error(`[AVERTISSEMENT] ${a}`);
  for (const r of c.rappels) console.error(`[RAPPEL] ${r}`);
  if (c.erreurs.length) sortir(1, c.erreurs.map((e) => `[ERREUR] ${e}`).join("\n"));
}

async function confirmer(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const r = await new Promise((resolve) => rl.question(question, resolve));
  rl.close();
  return /^(o|oui|y|yes)$/i.test(r.trim());
}

const [commande, ...reste] = process.argv.slice(2);
const options = {};
const positionnels = [];
for (let i = 0; i < reste.length; i++) {
  const a = reste[i];
  if (a === "--forme" || a === "--oui") options[a.slice(2)] = true;
  else if (a === "--jeu" || a === "--cle") {
    if (i + 1 >= reste.length) usage(`${a} sans valeur`);
    options[a.slice(2)] = reste[++i];
  } else if (a.startsWith("--")) usage(`option inconnue : ${a}`);
  else positionnels.push(a);
}

switch (commande) {
  case "gabarit": {
    if (positionnels.length) usage();
    console.log(JSON.stringify(gabarit(), null, 2));
    break;
  }
  case "condenser": {
    if (positionnels.length !== 1) usage();
    const P = lire(positionnels[0]);
    controlerAvantSignature(P);
    const D_P = S.condenseAttestation(P);
    // D_P par groupes de huit chiffres, pour la comparaison à l'écran du portefeuille et au second outil (CT-7 EX-7.8).
    console.log(D_P);
    console.error(`Groupes de huit : ${D_P.slice(2).match(/.{8}/g).join(" ")}`);
    break;
  }
  case "signer": {
    if (positionnels.length !== 1 || !options.cle) usage("signer exige un fichier et --cle");
    const P = lire(positionnels[0]);
    controlerAvantSignature(P);
    const D_P = S.condenseAttestation(P);
    let cle;
    const [sorte, ...chemin] = options.cle.split(":");
    const fichierCle = chemin.join(":");
    if (sorte === "fichier") {
      let texte;
      try {
        texte = fs.readFileSync(fichierCle, "utf8").trim();
      } catch (err) {
        sortir(2, `${fichierCle} : illisible (${err.code ?? err.message})`);
      }
      if (!/^0x[0-9a-fA-F]{64}$/.test(texte)) sortir(2, `${fichierCle} : clé hexadécimale 0x de 32 octets attendue`);
      cle = C.depuisHex(texte.toLowerCase());
    } else if (sorte === "keystore") {
      const doc = lire(fichierCle);
      const mdp = process.env.NOORTRACE_MOT_DE_PASSE;
      if (!mdp) sortir(2, "NOORTRACE_MOT_DE_PASSE n'est pas défini");
      const r = C.lireFichierCle(doc, mdp, doc.address ? "0x" + String(doc.address).toLowerCase().replace(/^0x/, "") : null);
      if (r.outcome !== "accepte" && !r.cle) sortir(2, `${fichierCle} : fichier de clé refusé (${r.reason})`);
      cle = r.cle;
    } else usage("--cle fichier:<chemin> ou keystore:<chemin>");
    const adresse = C.adresseDeCle(cle);
    if (!adresse) sortir(2, "clé secp256k1 hors de [1, n − 1]");
    afficherMembres(P);
    console.log(`D_P : ${D_P}`);
    console.log(`D_P par groupes de huit : ${D_P.slice(2).match(/.{8}/g).join(" ")} (à comparer au second outil, CT-7 EX-7.8)`);
    console.log(`Adresse du signataire : ${adresse}`);
    if (!(P.signatories ?? []).some((s) => s.address === adresse)) console.error(`Attention : ${adresse} n'est pas nommée dans signatories ; sa signature fera échouer AT-4.`);
    if (!options.oui && !(await confirmer("Signer ce D_P, recalculé depuis le fichier ? (oui/non) "))) sortir(1, "signature abandonnée");
    const signature = C.signerHachage(cle, C.depuisHex(S.messageAttestation(D_P)));
    cle.fill(0);
    console.log(JSON.stringify({ address: adresse, signature }, null, 2));
    break;
  }
  case "assembler": {
    if (positionnels.length < 2) usage("assembler exige l'attestation et au moins une signature");
    const P = lire(positionnels[0]);
    const signatures = positionnels.slice(1).map((f) => {
      const s = lire(f);
      return { address: s.address, signature: s.signature };
    });
    console.log(JSON.stringify(S.assemblerAttestation(P, signatures), null, 2));
    break;
  }
  case "verifier": {
    if (positionnels.length !== 1) usage();
    const doc = lire(positionnels[0]);
    const signee = doc !== null && typeof doc === "object" && !Array.isArray(doc) && "attestation" in doc && "signatures" in doc;
    const P = signee ? doc.attestation : doc;
    let code = 0;
    if (options.forme || !signee) {
      afficherMembres(P);
      const erreurs = S.formeAttestation(P);
      const c = S.controlerDeclaration(P);
      for (const e of erreurs) console.log(`[ÉCHEC] AT-1 : ${e}`);
      for (const e of c.erreurs) console.log(`[ERREUR] ${e}`);
      for (const a of c.avertissements) console.log(`[AVERTISSEMENT] ${a}`);
      for (const r of c.rappels) console.log(`[RAPPEL] ${r}`);
      if (erreurs.length || c.erreurs.length) code = 1;
      else console.log("Forme : AT-1 réussie, aucune erreur d'EX-7.3 ni d'EX-7.4.");
    }
    if (signee && !options.forme) {
      // Les contrôles d'EX-7.3 et EX-7.4 s'appliquent aussi à l'attestation d'une attestation signée.
      const c = S.controlerDeclaration(P);
      for (const e of c.erreurs) console.log(`[ERREUR] ${e}`);
      for (const a of c.avertissements) console.log(`[AVERTISSEMENT] ${a}`);
      if (c.erreurs.length) code = 1;
    }
    if (signee) {
      if (!options.jeu) sortir(2, "verifier une attestation signée exige --jeu <jeu.json> (AT-4)");
      const jeu = lire(options.jeu);
      const r = S.verifierAttestation(fs.readFileSync(positionnels[0]), jeu);
      for (const c of r.checks) console.log(`${c.status === "reussi" ? "[OK]" : c.status === "echoue" ? "[ÉCHEC]" : "[NON EXÉCUTÉE]"} ${c.id} : ${r.details[c.id].fr}`);
      console.log(r.retained ? "Attestation retenue : le périmètre est déclaré par ses signataires, non prouvé." : "Attestation non retenue.");
      if (!r.retained) code = 1;
    }
    process.exit(code);
  }
  default:
    usage(commande ? `commande inconnue : ${commande}` : undefined);
}
