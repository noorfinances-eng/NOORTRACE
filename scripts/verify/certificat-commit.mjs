#!/usr/bin/env node
// Vérificateur en ligne de commande d'un certificat de commit de noorcore.
//
// Entrée : un fichier JSON contenant le certificat (sortie de
// noor_getCommitCertificate, telle quelle ou réduite à son résultat), ou bien
// --rpc <url> --bloc <hauteur|hash> pour l'obtenir du nœud. Le jeu de
// validateurs (--validateurs validators.json) est OBLIGATOIRE : c'est contre
// lui, et lui seul, que les signatures sont vérifiées ; le vérificateur ne va
// pas le chercher sur le réseau. Le réviseur le fournit, obtenu par une voie
// indépendante du dossier : un jeu porté par le dossier reste déclaratif
// (CT-6 EX-3.4).
//
//   node scripts/verify/certificat-commit.mjs certificat.json --validateurs chain/runtime/validators.json
//   node scripts/verify/certificat-commit.mjs --rpc http://127.0.0.1:8645 --bloc 8328 \
//        --validateurs chain/runtime/validators.json --en-ligne --enregistrer dossier/certificat-8328.json
//   npm run verify:certificat -- certificat.json --validateurs chain/runtime/validators.json --json
//
// Options :
//   --validateurs <fichier>   jeu de validateurs {validators:[{id, pubKeyHex}]} (obligatoire)
//   --rpc <url>               point JSON-RPC du nœud (obligatoire avec --bloc ou --en-ligne)
//   --bloc <hauteur|0xhash>   bloc dont obtenir le certificat (hauteur décimale, 0x…, hachage de 32 octets ou latest)
//   --en-ligne                compare le bloc du certificat au bloc canonique rendu par eth_getBlockByNumber
//   --chaine <id>             identifiant de chaîne BFT attendu (ex. noortrace-2124-dev) ; recommandé, avertissement sinon
//   --enregistrer <fichier>   écrit le certificat obtenu par --rpc dans ce fichier (pour le dossier)
//   --json                    rapport en JSON au lieu du rapport lisible
//
// Codes de retour : 0 certificat valide ; 1 certificat invalide (au moins un
// contrôle cryptographique, de quorum ou de liaison en échec sur un certificat
// bien formé) ; 2 entrée inutilisable (option manquante, fichier illisible,
// JSON qui n'est pas un certificat ou certificat mal formé — contrôle
// « structure » en échec —, nœud injoignable, bloc inconnu). Le code 1 est une
// affirmation sur la chaîne ; le code 2 n'en est pas une.
//
// Sans --chaine, le rapport porte un avertissement : un certificat d'une autre
// chaîne signée par le même jeu de validateurs passerait tous les contrôles.
//
// Ne dépend pas de Hardhat : node et ethers suffisent.

import fs from "node:fs";
import path from "node:path";
import { chargerJeuValidateurs, entierCertificat, normaliserCertificat, verifierCertificat } from "../lib/certificat-commit.mjs";

const CODE_VALIDE = 0;
const CODE_INVALIDE = 1;
const CODE_INUTILISABLE = 2;
const DELAI_RPC_MS = 15_000;

class EntreeInutilisable extends Error {}

/** Analyse argv : un argument positionnel (le fichier), des options --cle valeur, --cle=valeur ou --drapeau. */
function analyserArguments(argv) {
  const avecValeur = new Set(["validateurs", "rpc", "bloc", "chaine", "enregistrer"]);
  const drapeaux = new Set(["en-ligne", "json", "aide", "help"]);
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
    "  node scripts/verify/certificat-commit.mjs <certificat.json> --validateurs <validators.json> [--en-ligne --rpc <url>] [--chaine <id>] [--json]",
    "  node scripts/verify/certificat-commit.mjs --rpc <url> --bloc <hauteur|0xhash> --validateurs <validators.json> [--en-ligne] [--enregistrer <fichier>] [--json]",
    "Codes de retour : 0 valide, 1 invalide, 2 entrée inutilisable.",
  ].join("\n");
}

/** Lit et analyse un fichier JSON ; toute défaillance rend l'entrée inutilisable. */
function lireJSON(fichier, quoi) {
  let texte;
  try {
    texte = fs.readFileSync(fichier, "utf8");
  } catch (err) {
    throw new EntreeInutilisable(`${quoi} illisible (${fichier}) : ${err.message}`);
  }
  try {
    return JSON.parse(texte);
  } catch (err) {
    throw new EntreeInutilisable(`${quoi} (${fichier}) n'est pas du JSON : ${err.message}`);
  }
}

/** Appel JSON-RPC direct ; rend le champ result, ou lève EntreeInutilisable. */
let idRpc = 0;
async function rpc(url, methode, params) {
  let reponse;
  try {
    reponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++idRpc, method: methode, params }),
      signal: AbortSignal.timeout(DELAI_RPC_MS),
    });
  } catch (err) {
    throw new EntreeInutilisable(`nœud injoignable (${url}) : ${err.cause?.message ?? err.message}`);
  }
  if (!reponse.ok) throw new EntreeInutilisable(`${methode} : HTTP ${reponse.status} depuis ${url}`);
  let corps;
  try {
    corps = await reponse.json();
  } catch (err) {
    throw new EntreeInutilisable(`${methode} : réponse non JSON depuis ${url} : ${err.message}`);
  }
  if (corps.error) {
    const complement = corps.error.code === -32601 ? " (ce nœud ne connaît pas la méthode : binaire antérieur à noor_getCommitCertificate ?)" : "";
    throw new EntreeInutilisable(`${methode} : ${corps.error.message ?? JSON.stringify(corps.error)}${complement}`);
  }
  return corps.result;
}

/** Interprète --bloc : {latest}, {hash} pour un hachage de 32 octets, {hauteur} (bigint) sinon. */
function interpreterBloc(texte) {
  const t = String(texte).trim();
  if (t.toLowerCase() === "latest") return { latest: true };
  if (/^0x[0-9a-fA-F]{64}$/.test(t)) return { hash: t.toLowerCase() };
  if (/^(0|[1-9][0-9]*)$/.test(t)) return { hauteur: BigInt(t) };
  if (/^0x[0-9a-fA-F]+$/.test(t)) return { hauteur: BigInt(t) };
  throw new EntreeInutilisable(`--bloc : hauteur (décimale ou 0x…), hachage de 32 octets ou latest attendu, reçu « ${t} »`);
}

const quantite = (n) => "0x" + BigInt(n).toString(16);

async function principal() {
  const options = analyserArguments(process.argv.slice(2));
  if (options.aide || options.help) {
    process.stdout.write(aide() + "\n");
    return CODE_VALIDE;
  }
  if (options.positionnels.length > 1) throw new EntreeInutilisable(`un seul fichier de certificat attendu, ${options.positionnels.length} reçus`);
  const fichierCertificat = options.positionnels[0];
  if (!options.validateurs) throw new EntreeInutilisable("--validateurs <validators.json> est obligatoire : le réviseur fournit le jeu de validateurs, obtenu par une voie indépendante du dossier (CT-6 EX-3.4)");
  if (!fichierCertificat && !options.bloc) throw new EntreeInutilisable("donner un fichier de certificat, ou --rpc <url> --bloc <hauteur|hash>");
  if (fichierCertificat && options.bloc) throw new EntreeInutilisable("donner soit un fichier de certificat, soit --bloc, pas les deux");
  if ((options.bloc || options["en-ligne"]) && !options.rpc) throw new EntreeInutilisable("--rpc <url> est requis avec --bloc et avec --en-ligne");

  // Jeu de validateurs : fourni, chargé comme le nœud le charge.
  let jeu;
  try {
    jeu = chargerJeuValidateurs(lireJSON(options.validateurs, "fichier de validateurs"));
  } catch (err) {
    if (err instanceof EntreeInutilisable) throw err;
    throw new EntreeInutilisable(`fichier de validateurs (${options.validateurs}) inexploitable : ${err.message}`);
  }

  // Certificat : fichier ou RPC.
  const source = {};
  let brut;
  let bloc = null;
  if (fichierCertificat) {
    brut = lireJSON(fichierCertificat, "fichier de certificat");
    source.fichier = path.resolve(fichierCertificat);
  } else {
    bloc = interpreterBloc(options.bloc);
    const ref = bloc.latest ? "latest" : bloc.hash ?? quantite(bloc.hauteur);
    brut = await rpc(options.rpc, "noor_getCommitCertificate", [ref]);
    source.rpc = options.rpc;
    source.bloc = options.bloc;
    if (brut === null || brut === undefined) {
      throw new EntreeInutilisable(`aucun certificat pour le bloc ${options.bloc} sur ${options.rpc} (hauteur inconnue, bloc hors rétention ou nœud sans certificat)`);
    }
    if (options.enregistrer) {
      fs.mkdirSync(path.dirname(path.resolve(options.enregistrer)), { recursive: true });
      fs.writeFileSync(options.enregistrer, JSON.stringify(brut, null, 2) + "\n");
      source.enregistre = path.resolve(options.enregistrer);
    }
  }
  let certificat;
  try {
    certificat = normaliserCertificat(brut);
  } catch (err) {
    throw new EntreeInutilisable(`l'entrée n'est pas un certificat de commit : ${err.message}`);
  }

  // Attentes de l'appelant et comparaison en ligne.
  const attentes = {};
  if (options.chaine) attentes.chainIdAttendu = options.chaine;
  if (bloc?.hauteur !== undefined) attentes.hauteurAttendue = bloc.hauteur;
  if (bloc?.hash) attentes.blockHashAttendu = bloc.hash;
  let enLigne = null;
  if (options["en-ligne"]) {
    let hauteur;
    try {
      hauteur = entierCertificat(certificat.h, "hauteur");
    } catch {
      throw new EntreeInutilisable("--en-ligne : la hauteur du certificat (h) est illisible, impossible d'interroger le bloc canonique");
    }
    const blocCanonique = await rpc(options.rpc, "eth_getBlockByNumber", [quantite(hauteur), false]);
    if (!blocCanonique || typeof blocCanonique.hash !== "string") {
      throw new EntreeInutilisable(`--en-ligne : le nœud ${options.rpc} n'a pas de bloc à la hauteur ${hauteur}`);
    }
    attentes.blockHashCanonique = blocCanonique.hash;
    enLigne = { rpc: options.rpc, hauteur: hauteur.toString(), blockHashCanonique: blocCanonique.hash, numero: blocCanonique.number ?? null };
  }

  const resultat = verifierCertificat(certificat, jeu, attentes);
  // Un échec du seul contrôle « structure » n'est pas un verdict sur la chaîne :
  // l'entrée n'est pas un certificat bien formé, elle est inutilisable.
  if (!resultat.valide && resultat.controles.length === 1 && resultat.controles[0].nom === "structure") {
    throw new EntreeInutilisable(`l'entrée n'est pas un certificat de commit bien formé : ${resultat.controles[0].detail}`);
  }
  const avertissements = [];
  if (!options.chaine) {
    avertissements.push(`aucun identifiant de chaîne attendu (--chaine) : la preuve vaut pour la chaîne « ${resultat.chainId} » déclarée par le certificat ; un jeu de validateurs réutilisé sur une autre chaîne y produirait un certificat tout aussi valide`);
  }
  const rapport = { ...resultat, avertissements, source, enLigne, fichierValidateurs: path.resolve(options.validateurs) };
  if (options.json) {
    process.stdout.write(JSON.stringify(rapport, null, 2) + "\n");
  } else {
    process.stdout.write(rapportLisible(rapport) + "\n");
  }
  return resultat.valide ? CODE_VALIDE : CODE_INVALIDE;
}

/** Rapport lisible en français. */
function rapportLisible(r) {
  const lignes = [];
  lignes.push("Vérification hors ligne d'un certificat de commit noorcore");
  if (r.source.fichier) lignes.push(`Source        : fichier ${r.source.fichier}`);
  if (r.source.rpc) lignes.push(`Source        : ${r.source.rpc}, bloc ${r.source.bloc}${r.source.enregistre ? ` (enregistré dans ${r.source.enregistre})` : ""}`);
  lignes.push(`Validateurs   : ${r.fichierValidateurs}`);
  if (r.chainId !== null) lignes.push(`Certificat    : chaîne « ${r.chainId} », hauteur ${r.hauteur}, tour ${r.ronde}`);
  if (r.blockHash) lignes.push(`Bloc          : ${r.blockHash}`);
  if (r.valsetHash) lignes.push(`Jeu (hachage) : ${r.valsetHash}`);
  if (r.tailleJeu !== null) lignes.push(`Quorum        : ${r.quorum} sur ${r.tailleJeu}`);
  if (r.enLigne) lignes.push(`En ligne      : bloc canonique ${r.enLigne.blockHashCanonique} à la hauteur ${r.enLigne.hauteur} (${r.enLigne.rpc})`);
  lignes.push("Contrôles :");
  for (const c of r.controles) {
    const nom = c.nom === "precommit" ? `precommit ${c.indice}` : c.nom;
    lignes.push(`  ${c.ok ? "[ok]   " : "[ÉCHEC]"} ${nom.padEnd(22)} ${c.detail}`);
  }
  if (r.signataires.length) lignes.push(`Signataires   : ${r.signataires.join(", ")}${r.proposant ? ` ; proposant ${r.proposant}` : ""}`);
  for (const a of r.avertissements) lignes.push(`Avertissement : ${a}`);
  lignes.push(`Résultat      : ${r.valide ? "VALIDE" : "INVALIDE"} — ${r.valide ? "un quorum du jeu fourni a signé ce bloc" : "au moins un contrôle a échoué"}`);
  lignes.push("Rappel        : la preuve vaut pour le jeu de validateurs FOURNI ; son origine relève du dossier, pas de ce vérificateur.");
  return lignes.join("\n");
}

principal().then(
  (code) => process.exit(code),
  (err) => {
    const message = err instanceof EntreeInutilisable ? err.message : `erreur inattendue : ${err?.stack ?? err}`;
    process.stderr.write(`Erreur : ${message}\n`);
    if (process.argv.includes("--json")) process.stdout.write(JSON.stringify({ valide: null, erreur: message }) + "\n");
    process.exit(CODE_INUTILISABLE);
  },
);
