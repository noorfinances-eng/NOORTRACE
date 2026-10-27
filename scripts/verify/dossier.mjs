#!/usr/bin/env node
// Vérificateur hors ligne d'un dossier de preuve NOORTRACE v0 : implémentation
// de référence JavaScript de spec/CT-6-verificateur.md (section 8), qui
// exécute les huit contrôles de l'architecture.
//
//   contrôles 1, 2, 3, 6, 7 : vérifications D-1 à A-4 de CT-1 §11.4
//                             (scripts/lib/journal.mjs) ;
//   contrôle 4              : jeton RFC 3161 sur periodHash, T-1 à T-11
//                             (scripts/lib/horodatage.mjs) ;
//   contrôle 5              : preuve OpenTimestamps et en-têtes Bitcoin, O-1 à
//                             O-7 (scripts/lib/ots.mjs) ;
//   contrôle 8              : registre et certificats de commit, R-1 à R-11
//                             (scripts/lib/registre.mjs) ;
//   K-1 à K-9               : partie facultative points-de-controle.json (CT-1
//                             révision 0.3, CT-6 révision 0.2) ;
//   AT-1 à AT-7             : partie facultative attestation-perimetre.json (CT-1
//                             révision 0.4, CT-6 révision 0.3, CT-7 section 7),
//                             sans effet sur les statuts ni sur le verdict ;
//   N-1 à N-4               : fichier d'ancres du réviseur, fichier d'en-têtes,
//                             clés d'enregistreur et clé de chaîne.
//
// La logique est dans scripts/lib/verificateur.mjs ; ce fichier porte la ligne
// de commande : lecture bornée des entrées (EX-4.13), options, sorties lisible
// et JSON, codes de retour. Aucun accès réseau, aucune lecture de l'horloge du
// système pour décider d'un statut, aucun magasin de certificats.
//
//   node scripts/verify/dossier.mjs <répertoire> [--ancres <fichier>] [--entetes-bitcoin <fichier>]
//        [--pieces <répertoire>] [--second-manifeste <fichier>] [--exiger <contrôles>]
//        [--langue fr|en] [--json] [--detail] [--schemas <répertoire>]
//   node scripts/verify/dossier.mjs --version | --aide
//
// Codes de retour (section 8.3) : 0 valide ; 1 invalide ; 2 entrée inutilisable
// (usage, dossier, schémas, fichier d'ancres ou entrée à part illisibles, limite
// dépassée, erreur interne) ; 3 incomplet (un contrôle exigé par --exiger n'a
// pas réussi). Les codes 0, 1 et 2 gardent le sens de la version CT-1.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "../lib/journal.mjs";
import * as S from "../lib/securite.mjs";
import * as V from "../lib/verificateur.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const OPTIONS_A_VALEUR = new Set(["ancres", "entetes-bitcoin", "pieces", "second-manifeste", "exiger", "langue", "schemas"]);
const DRAPEAUX = new Set(["json", "detail", "version", "aide", "help"]);
const T = (fr, en = fr) => ({ fr, en });
const sha256Hex = (octets) => "0x" + crypto.createHash("sha256").update(octets).digest("hex");

const usage = (fr, en) => new V.EntreeInutilisable("usage", T(fr, en));

/** Langue annoncée sur la ligne de commande, pour les messages d'usage eux-mêmes. */
function langueAnnoncee(argv) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--langue=en" || (argv[i] === "--langue" && argv[i + 1] === "en")) return "en";
  }
  return "fr";
}

/** --exiger : numéros de 1 à 8 séparés par des virgules, ou « tous ». */
function analyserExiger(valeur) {
  if (valeur === "tous") return [1, 2, 3, 4, 5, 6, 7, 8];
  const morceaux = valeur.split(",");
  if (!morceaux.every((m) => /^[1-8]$/.test(m))) throw usage(`--exiger : numéros de contrôles de 1 à 8 séparés par des virgules, ou « tous », attendus (reçu « ${valeur} »)`, `--exiger: control numbers from 1 to 8 separated by commas, or "tous", expected (got "${valeur}")`);
  const nums = morceaux.map(Number);
  if (new Set(nums).size !== nums.length) throw usage(`--exiger : contrôle répété (« ${valeur} »)`, `--exiger: repeated control ("${valeur}")`);
  return nums.sort((a, b) => a - b);
}

/** Analyse argv (EX-8.2) : un répertoire, options à valeur (--option valeur ou --option=valeur), drapeaux. */
function analyserArguments(argv) {
  const options = { positionnels: [] };
  const vues = new Set();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      options.positionnels.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const nom = eq === -1 ? a.slice(2) : a.slice(2, eq);
    if (!DRAPEAUX.has(nom) && !OPTIONS_A_VALEUR.has(nom)) throw usage(`option inconnue : ${a}`, `unknown option: ${a}`);
    if (vues.has(nom)) throw usage(`option répétée : --${nom}`, `repeated option: --${nom}`);
    vues.add(nom);
    if (DRAPEAUX.has(nom)) {
      if (eq !== -1) throw usage(`l'option --${nom} ne prend pas de valeur`, `option --${nom} takes no value`);
      options[nom] = true;
    } else {
      const valeur = eq === -1 ? argv[++i] : a.slice(eq + 1);
      if (valeur === undefined || valeur === "" || (eq === -1 && valeur.startsWith("--"))) throw usage(`l'option --${nom} attend une valeur`, `option --${nom} expects a value`);
      options[nom] = valeur;
    }
  }
  if (options.langue !== undefined && !["fr", "en"].includes(options.langue)) throw usage(`--langue : fr ou en attendu (reçu « ${options.langue} »)`, `--langue: fr or en expected (got "${options.langue}")`);
  // --version et --aide sont exclusives (EX-8.2) : seules --langue et --schemas les accompagnent.
  const exclusives = ["version", "aide", "help"].filter((n) => options[n]);
  if (exclusives.length) {
    const autres = Object.keys(options).filter((n) => !["positionnels", "version", "aide", "help", "langue", "schemas"].includes(n));
    if (exclusives.length > 1 || autres.length || options.positionnels.length) {
      const nom = `--${exclusives[0]}`;
      throw usage(`${nom} ne se combine qu'avec --langue et --schemas (reçu aussi : ${[...exclusives.slice(1).map((n) => `--${n}`), ...autres.map((n) => `--${n}`), ...options.positionnels].join(", ")})`, `${nom} combines only with --langue and --schemas (also given: ${[...exclusives.slice(1).map((n) => `--${n}`), ...autres.map((n) => `--${n}`), ...options.positionnels].join(", ")})`);
    }
  }
  options.exiger = options.exiger === undefined ? [] : analyserExiger(options.exiger);
  return options;
}

function aide(langue) {
  if (langue === "en") {
    return [
      "Usage:",
      "  node scripts/verify/dossier.mjs <directory> [--ancres <file>] [--entetes-bitcoin <file>]",
      "       [--pieces <directory>] [--second-manifeste <file>] [--exiger <controls>]",
      "       [--langue fr|en] [--json] [--detail] [--schemas <directory>]",
      "  node scripts/verify/dossier.mjs --version | --aide",
      "Verifies a NOORTRACE v0 evidence dossier offline: the eight controls of the architecture (CT-1 §11.4, CT-6).",
      "  --ancres            the reviewer's trust anchors file (schema ancres-confiance-v0); without it, the checks that need an anchor are not run",
      "  --entetes-bitcoin   Bitcoin header chain (schema entetes-bitcoin-v0) for control 5",
      "  --pieces            directory of pieces named by their sha256 (E-6)",
      "  --second-manifeste  previous or next manifest of the same journal (P-5)",
      "  --exiger            controls (1 to 8, comma-separated, or tous) that must pass, otherwise code 3",
      "  --langue            language of the readable report and of the JSON texts (fr by default)",
      "  --json              JSON report (schema rapport-verification-v0) instead of the readable report",
      "  --detail            readable report: every check, not only those that did not pass",
      "The optional thirteenth part points-de-controle.json (journal checkpoint, CT-1 revision 0.3) is verified by K-1 to K-9 when the index declares it present.",
      "The optional fourteenth part attestation-perimetre.json (perimeter attestation, CT-1 revision 0.4, CT-7) is verified by AT-1 to AT-7 when the index declares it present; the perimeter is declared, not proven, and these checks do not change the verdict.",
      "Exit codes: 0 valid, 1 invalid, 2 unusable input, 3 incomplete (--exiger).",
    ].join("\n");
  }
  return [
    "Usage :",
    "  node scripts/verify/dossier.mjs <répertoire> [--ancres <fichier>] [--entetes-bitcoin <fichier>]",
    "       [--pieces <répertoire>] [--second-manifeste <fichier>] [--exiger <contrôles>]",
    "       [--langue fr|en] [--json] [--detail] [--schemas <répertoire>]",
    "  node scripts/verify/dossier.mjs --version | --aide",
    "Vérifie hors ligne un dossier de preuve NOORTRACE v0 : les huit contrôles de l'architecture (CT-1 §11.4, CT-6).",
    "  --ancres            fichier d'ancres de confiance du réviseur (schéma ancres-confiance-v0) ; sans lui, les vérifications qui exigent une ancre ne s'exécutent pas",
    "  --entetes-bitcoin   chaîne d'en-têtes Bitcoin (schéma entetes-bitcoin-v0) pour le contrôle 5",
    "  --pieces            répertoire de pièces nommées par leur sha256 (E-6)",
    "  --second-manifeste  manifeste précédent ou suivant du même journal (P-5)",
    "  --exiger            contrôles (1 à 8, séparés par des virgules, ou tous) qui doivent réussir, sinon code 3",
    "  --langue            langue du rapport lisible et des textes du rapport JSON (fr par défaut)",
    "  --json              rapport JSON (schéma rapport-verification-v0) au lieu du rapport lisible",
    "  --detail            rapport lisible : toutes les vérifications, pas seulement celles qui n'ont pas réussi",
    "La treizième partie facultative points-de-controle.json (point de contrôle du journal, CT-1 révision 0.3) est vérifiée par K-1 à K-9 quand l'index la déclare présente.",
    "La quatorzième partie facultative attestation-perimetre.json (attestation de périmètre, CT-1 révision 0.4, CT-7) est vérifiée par AT-1 à AT-7 quand l'index la déclare présente ; le périmètre est déclaré, non prouvé, et ces vérifications ne changent pas le verdict.",
    "Codes de retour : 0 valide, 1 invalide, 2 entrée inutilisable, 3 incomplet (--exiger).",
  ].join("\n");
}

/**
 * Lit au plus `limite + 1` octets d'un fichier régulier (EX-4.13) : rend
 * { octets } ou, au-delà de la limite, { trop: true, taille, debut } sans lire
 * plus loin. Lève l'erreur du système de fichiers.
 */
function lireBorne(fichier, limite) {
  const fd = fs.openSync(fichier, "r");
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error("pas un fichier régulier");
    const morceaux = [];
    let total = 0;
    const tampon = Buffer.alloc(Math.min(limite + 1, 1 << 20));
    for (;;) {
      const n = fs.readSync(fd, tampon, 0, Math.min(tampon.length, limite + 1 - total), null);
      if (n === 0) break;
      morceaux.push(Buffer.from(tampon.subarray(0, n)));
      total += n;
      if (total > limite) break;
    }
    const octets = Buffer.concat(morceaux);
    if (total > limite) return { trop: true, taille: Math.max(st.size, total), debut: octets };
    return { octets };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * SHA-256 des octets complets d'un fichier, lu par morceaux de 1 Mio (aucun
 * octet n'est conservé), au plus `plafond` octets : au-delà, l'entrée est
 * inutilisable (le fichier a grandi depuis sa mesure).
 */
function sha256Flux(fichier, plafond) {
  const fd = fs.openSync(fichier, "r");
  try {
    const h = crypto.createHash("sha256");
    const tampon = Buffer.alloc(1 << 20);
    let lus = 0;
    for (;;) {
      const n = fs.readSync(fd, tampon, 0, tampon.length, null);
      if (n === 0) break;
      lus += n;
      if (lus > plafond) throw new V.EntreeInutilisable("taille_depassee", T(`${path.basename(fichier)} : au-delà du plafond de lecture de ${plafond} octets (CT-6 EX-4.15)`, `${path.basename(fichier)}: beyond the read ceiling of ${plafond} bytes (CT-6 EX-4.15)`));
      h.update(tampon.subarray(0, n));
    }
    return "0x" + h.digest("hex");
  } finally {
    fs.closeSync(fd);
  }
}

/** Les schémas de spec/schemas : registre $id -> document et SHA-256 de chaque fichier. */
function chargerSchemas(repertoire) {
  const documents = [];
  const empreintes = new Map();
  for (const { fichier, id } of V.FICHIERS_SCHEMAS) {
    const chemin = path.join(repertoire, fichier);
    let octets;
    try {
      octets = fs.readFileSync(chemin);
    } catch (err) {
      throw new V.EntreeInutilisable("schemas_illisibles", T(`schéma illisible (${chemin}) : ${err.message}`, `unreadable schema (${chemin}): ${err.message}`));
    }
    let doc;
    try {
      doc = JSON.parse(octets.toString("utf8"));
    } catch (err) {
      throw new V.EntreeInutilisable("schemas_illisibles", T(`schéma (${chemin}) qui n'est pas du JSON : ${err.message}`, `schema (${chemin}) is not JSON: ${err.message}`));
    }
    if (doc?.$id !== id) throw new V.EntreeInutilisable("schemas_illisibles", T(`schéma ${chemin} : $id ${doc?.$id} au lieu de ${id}`, `schema ${chemin}: $id ${doc?.$id} instead of ${id}`));
    documents.push(doc);
    empreintes.set(id, sha256Hex(octets));
  }
  return { registre: J.registreSchemas(documents), empreintes };
}

/** Lit une entrée désignée par une option ; une erreur du système de fichiers devient une entrée inutilisable. */
function lireEntree(fichier, limite, { kind, check, nom }) {
  try {
    return lireBorne(fichier, limite);
  } catch (err) {
    throw new V.EntreeInutilisable(kind, T(`${nom} illisible (${fichier}) : ${err.message}`, `${nom} unreadable (${fichier}): ${err.message}`), check);
  }
}

function principal(argv, etat) {
  etat.langue = langueAnnoncee(argv);
  const options = analyserArguments(argv);
  const langue = options.langue ?? "fr";
  etat.langue = langue;
  etat.json = Boolean(options.json);
  if (options.aide || options.help) {
    process.stdout.write(aide(langue) + "\n");
    return 0;
  }
  const repertoireSchemas = path.resolve(options.schemas ?? path.join(PROJECT_ROOT, "spec", "schemas"));
  if (options.version) {
    const { empreintes } = chargerSchemas(repertoireSchemas);
    const lignes = [`${V.NOM_VERIFICATEUR} ${V.VERSION_VERIFICATEUR} (node ${process.version})`, langue === "en" ? `schemas (${repertoireSchemas}):` : `schémas (${repertoireSchemas}) :`];
    for (const [id, h] of empreintes) lignes.push(`  ${id} SHA-256 ${h}`);
    process.stdout.write(lignes.join("\n") + "\n");
    return 0;
  }
  if (options.positionnels.length !== 1) throw usage(`un répertoire de dossier attendu, ${options.positionnels.length} argument(s) reçu(s)`, `one dossier directory expected, ${options.positionnels.length} argument(s) given`);

  const repertoire = path.resolve(options.positionnels[0]);
  const inputs = { dossier: { path: repertoire, index_sha256: null }, anchors: null, bitcoin_headers: null, second_manifest: null, pieces: null, required_controls: options.exiger };
  etat.inputs = inputs;

  // 1. Schémas, fichier d'ancres (N-1), fichier d'en-têtes (N-2), entrées à part (EX-5.2).
  // verifier.schemas : les dix schémas embarqués, dans l'ordre fixé (section 8.6, EX-8.9, EX-8.11), quelles que soient les options.
  const { registre: schemas, empreintes } = chargerSchemas(repertoireSchemas);
  etat.schemas = V.FICHIERS_SCHEMAS.map(({ id }) => ({ id, sha256: empreintes.get(id) }));

  let ancres = null;
  if (options.ancres) {
    const fichier = path.resolve(options.ancres);
    const lu = lireEntree(fichier, V.LIMITES.ancres, { kind: "ancres_inutilisables", check: "N-1", nom: langue === "en" ? "anchors file" : "fichier d'ancres" });
    if (lu.trop) throw new V.EntreeInutilisable("ancres_inutilisables", T(`fichier d'ancres inutilisable : ${lu.taille} octets, au-delà de la limite de ${V.LIMITES.ancres}`, `unusable anchors file: ${lu.taille} bytes, beyond the limit of ${V.LIMITES.ancres}`), "N-1");
    inputs.anchors = { path: fichier, sha256: sha256Hex(lu.octets) };
    ancres = V.controlerAncres(lu.octets, schemas);
  }
  let entetes = null;
  if (options["entetes-bitcoin"]) {
    const fichier = path.resolve(options["entetes-bitcoin"]);
    const lu = lireEntree(fichier, V.LIMITES.entetes, { kind: "entree_illisible", check: "N-2", nom: langue === "en" ? "Bitcoin headers file" : "fichier d'en-têtes Bitcoin" });
    if (lu.trop) throw new V.EntreeInutilisable("taille_depassee", T(`fichier d'en-têtes Bitcoin : ${lu.taille} octets, au-delà de la limite de ${V.LIMITES.entetes}`, `Bitcoin headers file: ${lu.taille} bytes, beyond the limit of ${V.LIMITES.entetes}`), "N-2");
    inputs.bitcoin_headers = { path: fichier, sha256: sha256Hex(lu.octets) };
    entetes = V.controlerEntetes(lu.octets, schemas);
  }
  let secondManifeste = null;
  if (options["second-manifeste"]) {
    const fichier = path.resolve(options["second-manifeste"]);
    const lu = lireEntree(fichier, V.LIMITES.secondManifeste, { kind: "entree_illisible", check: null, nom: langue === "en" ? "second manifest" : "second manifeste" });
    if (lu.trop) throw new V.EntreeInutilisable("taille_depassee", T(`second manifeste : ${lu.taille} octets, au-delà de la limite de ${V.LIMITES.secondManifeste}`, `second manifest: ${lu.taille} bytes, beyond the limit of ${V.LIMITES.secondManifeste}`));
    inputs.second_manifest = { path: fichier, sha256: sha256Hex(lu.octets) };
    secondManifeste = V.controlerSecondManifeste(lu.octets, schemas);
  }
  let pieces = null;
  if (options.pieces) {
    const rep = path.resolve(options.pieces);
    let st;
    try {
      st = fs.statSync(rep);
    } catch (err) {
      throw new V.EntreeInutilisable("entree_illisible", T(`répertoire de pièces illisible (${rep}) : ${err.message}`, `unreadable pieces directory (${rep}): ${err.message}`));
    }
    if (!st.isDirectory()) throw new V.EntreeInutilisable("entree_illisible", T(`--pieces : ${rep} n'est pas un répertoire`, `--pieces: ${rep} is not a directory`));
    inputs.pieces = { path: rep, files: 0 };
    pieces = {
      lire(nom) {
        const fichier = path.join(rep, nom);
        let stp;
        try {
          stp = fs.statSync(fichier);
        } catch {
          return null; // pièce non fournie : la référence reste une empreinte (EX-4.6)
        }
        if (!stp.isFile()) return null;
        const lu = lireEntree(fichier, V.LIMITES.piece, { kind: "entree_illisible", check: null, nom: langue === "en" ? "piece" : "pièce" });
        if (lu.trop) throw new V.EntreeInutilisable("taille_depassee", T(`pièce ${fichier} : ${lu.taille} octets, au-delà de la limite de ${V.LIMITES.piece}`, `piece ${fichier}: ${lu.taille} bytes, beyond the limit of ${V.LIMITES.piece}`));
        return lu.octets;
      },
    };
  }

  // 2. Le dossier : dossier.json, les douze parties et la treizième facultative, chacune dans sa limite (EX-4.1, EX-4.13, EX-4.14).
  let entrees;
  try {
    entrees = fs.readdirSync(repertoire, { withFileTypes: true });
  } catch (err) {
    throw new V.EntreeInutilisable("dossier_illisible", T(`répertoire illisible (${repertoire}) : ${err.message}`, `unreadable directory (${repertoire}): ${err.message}`));
  }
  const fichiers = {};
  const nonLus = new Map();
  for (const e of entrees) {
    if (!e.isFile() || !V.FICHIERS_DOSSIER.includes(e.name)) continue;
    const limite = V.limiteFichier(e.name);
    let lu;
    try {
      lu = lireBorne(path.join(repertoire, e.name), limite);
    } catch (err) {
      throw new V.EntreeInutilisable("dossier_illisible", T(`${e.name} illisible : ${err.message}`, `${e.name} unreadable: ${err.message}`));
    }
    if (lu.trop) {
      if (e.name === "dossier.json") throw new V.EntreeInutilisable("taille_depassee", T(`dossier.json : ${lu.taille} octets, au-delà de la limite de ${limite}`, `dossier.json: ${lu.taille} bytes, beyond the limit of ${limite}`));
      // attestation-perimetre.json au-delà de 4 Mio fait échouer AT-1 et rien d'autre (CT-6 EX-4.15) : son SHA-256 est calculé en flux pour D-2,
      // jusqu'au plafond absolu de 64 Mio ; au-delà, l'entrée est inutilisable (code 2), comme une pièce trop grande.
      const info = { taille: lu.taille, limite, debut: lu.debut };
      if (e.name === J.PARTIE_ATTESTATION_PERIMETRE.file) {
        if (lu.taille > S.PLAFOND_LECTURE_ATTESTATION) throw new V.EntreeInutilisable("taille_depassee", T(`${e.name} : ${lu.taille} octets, au-delà du plafond de lecture de ${S.PLAFOND_LECTURE_ATTESTATION} octets (CT-6 EX-4.15)`, `${e.name}: ${lu.taille} bytes, beyond the read ceiling of ${S.PLAFOND_LECTURE_ATTESTATION} bytes (CT-6 EX-4.15)`));
        info.sha256 = sha256Flux(path.join(repertoire, e.name), S.PLAFOND_LECTURE_ATTESTATION);
      }
      nonLus.set(e.name, info);
    } else fichiers[e.name] = lu.octets;
  }
  if (fichiers["dossier.json"]) inputs.dossier.index_sha256 = sha256Hex(fichiers["dossier.json"]);

  // 3. Les huit contrôles, le verdict, l'énoncé.
  let corps;
  try {
    corps = V.verifierDossierComplet({ fichiers, nonLus, schemas, ancres, entetes, pieces, secondManifeste, exiger: options.exiger, langue });
  } catch (err) {
    if (err instanceof J.DossierInutilisable) throw new V.EntreeInutilisable("dossier_illisible", T(err.message, traduireDossierInutilisable(err.message)));
    throw err;
  }
  if (inputs.pieces) inputs.pieces.files = corps.pieces_lues;
  const rapport = V.rapportJSON({ verifier: V.blocVerificateur(etat.schemas), langue, inputs, corps });
  if (options.json) process.stdout.write(JSON.stringify(rapport, null, 2) + "\n");
  else process.stdout.write(V.rapportLisible(rapport, { detail: Boolean(options.detail) }) + "\n");
  return rapport.exit_code;
}

function traduireDossierInutilisable(message) {
  return message
    .replace(/^dossier\.json absent : le répertoire n'est pas un dossier de preuve$/, "dossier.json missing: the directory is not an evidence dossier")
    .replace(/^dossier\.json illisible : /, "dossier.json unreadable: ");
}

const etat = { langue: "fr", json: process.argv.includes("--json"), inputs: null, schemas: [] };
let code;
try {
  code = principal(process.argv.slice(2), etat);
} catch (err) {
  const erreur = err instanceof V.EntreeInutilisable ? err : new V.EntreeInutilisable("erreur_interne", T(`erreur interne du vérificateur : ${err?.message ?? err}`, `internal verifier error: ${err?.message ?? err}`));
  const message = erreur.texte[etat.langue] ?? erreur.message;
  process.stderr.write(`${etat.langue === "en" ? "Error: " : "Erreur : "}${message}\n`);
  if (!(err instanceof V.EntreeInutilisable) && err?.stack) process.stderr.write(err.stack + "\n");
  if (etat.json) process.stdout.write(JSON.stringify(V.rapportErreur({ verifier: V.blocVerificateur(etat.schemas), langue: etat.langue, inputs: etat.inputs, erreur }), null, 2) + "\n");
  code = 2;
}
process.exitCode = code;
