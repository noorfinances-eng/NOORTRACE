#!/usr/bin/env node
// Outil de référence du registre (spec/CT-4-registre.md, sections 7 à 9) :
// inscription d'un client, inscription et révocation d'une clé
// d'enregistreur, ancre et clôture d'une période, administration du jeu,
// réassignation, approvisionnement, capture des transactions, export et
// vérification des parties du dossier, publication du jeu de validateurs.
//
//   node scripts/registre/noortrace-registre.mjs <commande> [options]
//
// Node.js et ethers, sans Hardhat à l'exécution : les ABI sont lues dans
// hh-artifacts/ (npm run compile). L'outil réutilise scripts/lib/ et ne
// modifie ni scripts/deploy/ ni scripts/e2e/. Tout ce qui se calcule hors
// chaîne vient de scripts/lib/conventions-registre.mjs (section 6) ; les
// lectures d'état (eth_call) ne sont pas des preuves (CT-6 §11.1).
//
// Sortie standard : un seul objet JSON conforme à
// operations-registre-v0.schema.json#/$defs/sortie (EX-7.4) ; les messages
// d'avancement vont sur la sortie d'erreur. Codes : 0 reussi ou deja_fait ;
// 1 refuse ou echoue ; 2 inutilisable ; 3 incertain.
//
// Options communes (EX-7.1) : --instance <manifeste d'instance>, --rpc
// <url>[,<url>…] (points de validateurs), --jeton <env:VAR | fichier:chemin>
// (jeton Bearer du nœud, EX-10.3), --captures <répertoire>, --delai
// <secondes>, --dossier <dossier d'inscription>. --sans-capture n'est admis
// que pour l'identifiant EVM 31337 (réseau Hardhat des tests, EX-A.6).
//
// Les états d'une étape du dossier (EX-7.16) suivent l'envoi pas à pas :
// envoyee dès l'envoi écrit, incluse dès le reçu, capturee après CP-6, echec
// sur un status 0x0 ou une relecture contredite ; une étape envoyee ou
// incluse se reprend par la capture de sa transaction, jamais par un renvoi.
// approvisionner n'admet que les destinataires d'EX-8.20 (--dossier,
// --demande, --org-id, comptes du manifeste) ; reassigner exige la demande
// écrite du client (--demande, EX-8.10) ; condense cloture exige l'ancre
// capturée dans --captures et écrit expires_at (EX-8.4, EX-8.19).

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDNodeWallet, Interface, SigningKey, computeAddress, getAddress } from "ethers";
import * as C from "../lib/conventions-registre.mjs";
import { chargerJeuValidateurs, hachageJeuValidateurs } from "../lib/certificat-commit.mjs";
import { cleEd25519DepuisGraine, construireManifeste, egalJSON, hachageManifeste, sha256, signerManifeste, validerSchema } from "../lib/journal.mjs";
import { verifierControle8 } from "../lib/registre.mjs";
import { lireJeu } from "../lib/approbation.mjs";

const RACINE = fileURLToPath(new URL("../../", import.meta.url));
const MNEMONIQUE_TEST = "test test test test test test test test test test test junk";
const RPC_DEFAUT = "http://127.0.0.1:8645";
/** Ports JSON-RPC des quatre validateurs du réseau de développement (chain/scripts/dev-net.sh:40). */
const PORTS_DEV = { 8645: "v1", 8646: "v2", 8647: "v3", 8648: "v4" };
const COMMANDES = ["etat", "cles-essai", "inscrire-client", "approvisionner", "condense", "signer", "inscrire-cle", "revoquer-cle", "manifeste-essai", "ancrer", "clore", "administrer-jeu", "reassigner", "capturer", "exporter", "verifier", "publier-jeu"];

/** Codes d'erreur qui rendent `inutilisable` (code 2) : rien n'est affirmé (EX-7.4). */
const INUTILISABLE = new Set(["usage", "entree_illisible", "instance_illisible", "noeud_injoignable"]);

// ---------------------------------------------------------------------------
// Erreurs et sortie
// ---------------------------------------------------------------------------

/** Arrêt d'une commande : code d'erreur de 7.11, vérification en cause, résultat. */
class Arret extends Error {
  constructor(code, check, message, { result = null, outputs = null } = {}) {
    super(message);
    this.code = code;
    this.check = check;
    this.result = result ?? (INUTILISABLE.has(code) ? "inutilisable" : "refuse");
    this.outputs = outputs;
  }
}

const CODE_DE_SORTIE = { reussi: 0, deja_fait: 0, refuse: 1, echoue: 1, inutilisable: 2, incertain: 3 };

/** Contexte d'une commande : vérifications OP- et CP- accumulées, journal d'avancement. */
class Contexte {
  constructor(commande, options, flux) {
    this.commande = commande;
    this.options = options;
    this.flux = flux;
    this.checks = [];
  }
  log(message) {
    this.flux.stderr.write(`noortrace-registre ${this.commande} : ${message}\n`);
  }
  /** Note une vérification (le même identifiant n'est noté qu'une fois, la dernière issue gagne). */
  noter(id, status, detail = "") {
    const i = this.checks.findIndex((c) => c.id === id);
    const c = { id, status, detail: String(detail).slice(0, 1024) };
    if (i === -1) this.checks.push(c);
    else this.checks[i] = c;
  }
  /** Exécute une vérification : réussie si `f` rend sans lever ; un Arret la marque en échec. */
  async op(id, f) {
    try {
      const r = await f();
      this.noter(id, "reussi", "");
      return r;
    } catch (err) {
      if (err instanceof Arret) {
        this.noter(id, "echoue", err.message);
        if (!err.check) err.check = id;
      }
      throw err;
    }
  }
}

function sortie(commande, result, checks, error, outputs) {
  return { version: 0, command: COMMANDES.includes(commande) ? commande : "etat", result, exit_code: CODE_DE_SORTIE[result], checks: checks.slice(0, 32), error, outputs: outputs ?? {} };
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options booléennes (sans valeur). */
const DRAPEAUX = new Set(["preparer", "sans-capture", "renvoyer", "remplacer", "force", "changement-administrateur"]);
/** Options répétables. */
const REPETABLES = new Set(["cle-enregistreur"]);

function analyserOptions(argv) {
  const positionnels = [];
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      positionnels.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const nom = eq === -1 ? a.slice(2) : a.slice(2, eq);
    let valeur;
    if (DRAPEAUX.has(nom)) valeur = true;
    else if (eq !== -1) valeur = a.slice(eq + 1);
    else {
      valeur = argv[++i];
      if (valeur === undefined) throw new Arret("usage", null, `--${nom} attend une valeur`);
    }
    if (REPETABLES.has(nom)) (options[nom] ??= []).push(valeur);
    else options[nom] = valeur;
  }
  return { positionnels, options };
}

function exigerOption(options, nom) {
  if (options[nom] === undefined || options[nom] === true || options[nom] === "") throw new Arret("usage", null, `--${nom} est obligatoire pour cette commande`);
  return options[nom];
}

// ---------------------------------------------------------------------------
// Fichiers
// ---------------------------------------------------------------------------

function lireOctets(fichier, code = "entree_illisible") {
  try {
    return fs.readFileSync(fichier);
  } catch (err) {
    throw new Arret(code, null, `${fichier} illisible : ${err.code ?? err.message}`);
  }
}

function lireJSONFichier(fichier, code = "entree_illisible") {
  const b = lireOctets(fichier, code);
  try {
    return JSON.parse(b.toString("utf8"));
  } catch (err) {
    throw new Arret(code, null, `${fichier} : JSON illisible (${err.message})`);
  }
}

function texteJSON(v) {
  return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2) + "\n";
}

/** Écrit un fichier et le synchronise sur le disque (CP-6). */
function ecrireSynchronise(fichier, contenu, { mode = 0o644 } = {}) {
  fs.mkdirSync(path.dirname(fichier), { recursive: true });
  const fd = fs.openSync(fichier, "wx", mode);
  try {
    fs.writeSync(fd, typeof contenu === "string" ? Buffer.from(contenu, "utf8") : contenu);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    const d = fs.openSync(path.dirname(fichier), "r");
    fs.fsyncSync(d);
    fs.closeSync(d);
  } catch {
    // un système de fichiers qui ne synchronise pas les répertoires
  }
}

/** Remplace un fichier par écriture d'un temporaire puis renommage (l'état de reprise, 7.6). */
function remplacerFichier(fichier, contenu) {
  const tmp = `${fichier}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, contenu);
  const fd = fs.openSync(tmp, "r");
  fs.fsyncSync(fd);
  fs.closeSync(fd);
  fs.renameSync(tmp, fichier);
}

function maintenant() {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Schémas et ABI
// ---------------------------------------------------------------------------

let SCHEMAS = null;
function schemas() {
  if (SCHEMAS) return SCHEMAS;
  const rep = path.join(RACINE, "spec", "schemas");
  const docs = ["instance-registre-v0", "inscription-client-v0", "operations-registre-v0", "registre-v0", "validateurs-v0", "ancres-confiance-v0"].map((n) => JSON.parse(fs.readFileSync(path.join(rep, `${n}.schema.json`), "utf8")));
  SCHEMAS = C.registreSchemasCt4(docs);
  return SCHEMAS;
}

function conforme(valeur, id, fragment = "") {
  return validerSchema(valeur, schemas()[id], { registre: schemas(), fragment });
}

const ARTEFACTS = {};
function artefact(nom) {
  if (ARTEFACTS[nom]) return ARTEFACTS[nom];
  const f = path.join(RACINE, "hh-artifacts", "contracts", `${nom}.sol`, `${nom}.json`);
  if (!fs.existsSync(f)) throw new Arret("entree_illisible", null, `artefact absent : ${f} (lancer d'abord npm run compile)`);
  const a = JSON.parse(fs.readFileSync(f, "utf8"));
  ARTEFACTS[nom] = { abi: a.abi, bytecode: a.bytecode, iface: new Interface(a.abi) };
  return ARTEFACTS[nom];
}

// ---------------------------------------------------------------------------
// Instance (EX-7.1, EX-7.2)
// ---------------------------------------------------------------------------

/**
 * Instance en vigueur : le manifeste de --instance (schéma, adresses
 * CREATE(deployer, nonce), valset_hash recalculé), ou, sans manifeste, le
 * réseau de développement décrit par deployments/noorcore.json,
 * chain/config/alloc-dev.json et chain/runtime/validators.json (EX-7.2).
 */
function chargerInstance(options) {
  if (options.instance) {
    const octetsManifeste = lireOctets(options.instance, "instance_illisible");
    let m;
    try {
      m = JSON.parse(octetsManifeste.toString("utf8"));
    } catch (err) {
      throw new Arret("instance_illisible", null, `manifeste illisible : ${err.message}`);
    }
    const e = conforme(m, C.ID_SCHEMA_INSTANCE);
    if (e.length) throw new Arret("instance_illisible", null, `manifeste non conforme à instance-registre-v0 : ${e.slice(0, 3).map((x) => `${x.chemin} : ${x.message}`).join(" ; ")}`);
    for (const c of m.contracts) {
      if (C.adresseCreation(c.deployer, c.nonce) !== c.address) throw new Arret("instance_illisible", null, `${c.name} : adresse différente de CREATE(deployer, nonce) (RG-19)`);
    }
    for (const j of m.validator_sets) {
      let h;
      try {
        h = chargerJeuValidateurs({ validators: j.validators }).hachage;
      } catch (err) {
        throw new Arret("instance_illisible", null, `jeu de validateurs inexploitable : ${err.message}`);
      }
      if (h !== j.valset_hash) throw new Arret("instance_illisible", null, `valset_hash ${j.valset_hash} différent du hachage recalculé ${h} (RG-18)`);
    }
    for (const nom of ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]) if (!C.contratEnService(m, nom)) throw new Arret("instance_illisible", null, `aucun ${nom} en service`);
    if (m.nature === "production") {
      // EX-4.7 et EX-4.28 : identifiant inscrit, hors de 2121 à 2124 ; preuves de déploiement ; un opérateur par validateur.
      if (m.evm_chain_id_registration.status !== "inscrit") throw new Arret("instance_illisible", null, "instance de production : evm_chain_id_registration.status doit valoir inscrit (EX-4.28)");
      if (m.evm_chain_id >= 2121 && m.evm_chain_id <= 2124) throw new Arret("instance_illisible", null, `instance de production : l'identifiant EVM ${m.evm_chain_id} est réservé à NOORCHAIN ou au développement (EX-4.7)`);
      for (const c of m.contracts) if (c.block_hash === null || c.evidence === null) throw new Arret("instance_illisible", null, `instance de production : ${c.name} sans block_hash ou sans evidence (EX-4.28)`);
      for (const j of m.validator_sets) if (j.operators.length !== j.validators.length) throw new Arret("instance_illisible", null, "instance de production : un opérateur par validateur (EX-4.28)");
    }
    return { manifeste: m, manifest_sha256: sha256(octetsManifeste), defaut: false };
  }
  // Réseau de développement sans manifeste (EX-7.2, EX-4.26).
  const repDeploiements = process.env.NOORTRACE_DEPLOYMENTS_DIR || path.join(RACINE, "deployments");
  const fDep = path.join(repDeploiements, "noorcore.json");
  const dep = lireJSONFichier(fDep, "instance_illisible");
  if (String(dep.chainId) !== String(C.RESEAU_DEVELOPPEMENT.evm_chain_id)) throw new Arret("reseau_non_developpement", null, `${fDep} ne décrit pas la chaîne 2124`);
  const fGenese = path.join(RACINE, "chain", "config", "alloc-dev.json");
  const genese = lireOctets(fGenese, "instance_illisible");
  const fVal = process.env.NOORTRACE_VALIDATORS_FILE || path.join(RACINE, "chain", "runtime", "validators.json");
  const val = lireJSONFichier(fVal, "instance_illisible");
  const deployeur = C.adresseMinuscule(dep.deployeur);
  const contrat = (nom) => {
    const e = dep.contrats?.[nom];
    if (!e?.adresse) throw new Arret("instance_illisible", null, `${fDep} : ${nom} absent`);
    return { name: nom, address: C.adresseMinuscule(e.adresse), deployer: deployeur, nonce: null, constructor_args: [], transaction_hash: String(e.tx).toLowerCase(), block_number: e.bloc, block_hash: null, evidence: null, to_height: null };
  };
  const jeu = { from_height: 1, to_height: null, validators: val.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source: "chain/runtime/validators.json du réseau de développement", valset_hash: hachageJeuValidateurs(val), operators: [] };
  const g = JSON.parse(genese.toString("utf8"));
  const m = {
    version: 0,
    revision: 0,
    nature: "developpement",
    bft_chain_id: C.RESEAU_DEVELOPPEMENT.bft_chain_id,
    evm_chain_id: C.RESEAU_DEVELOPPEMENT.evm_chain_id,
    genesis: { file: "chain/config/alloc-dev.json", sha256: sha256(genese), rules_line: C.ligneRegles(g), alloc_total_wei: g.alloc.reduce((s, a) => s + BigInt(a.balanceWei), 0n).toString() },
    validator_sets: [jeu],
    fees: { ...C.FRAIS_DEFAUT },
    contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map(contrat),
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
  };
  return { manifeste: m, manifest_sha256: null, defaut: true };
}

/** Réseau de développement au sens d'EX-7.2 et EX-7.3 : nature developpement, identifiant 2124 (ou 31337, réseau Hardhat des tests). */
function estDeveloppement(instance) {
  const m = instance.manifeste;
  return m.nature === "developpement" && [C.RESEAU_DEVELOPPEMENT.evm_chain_id, C.RESEAU_ESSAI.evm_chain_id].includes(m.evm_chain_id);
}

function adressesContrats(m) {
  const a = (n) => C.contratEnService(m, n).address;
  return { curator_set_registry: a("CuratorSetRegistry"), recorder_registry: a("RecorderRegistry"), period_registry: a("PeriodRegistry"), attestation_registry: a("AttestationRegistry") };
}

// ---------------------------------------------------------------------------
// Clés (EX-7.3)
// ---------------------------------------------------------------------------

/**
 * Résout une référence de clé secp256k1 : fichier:<chemin> (32 octets en
 * hexadécimal, fichier lisible de son seul propriétaire), env:<VARIABLE>,
 * hardhat:<i> (réseau de développement seulement). Rend une SigningKey.
 */
function cleSecp(reference, instance, { nom = "clé" } = {}) {
  if (typeof reference !== "string") throw new Arret("usage", null, `${nom} : référence attendue (fichier:, env:, hardhat:)`);
  const [type, ...reste] = reference.split(":");
  const valeur = reste.join(":");
  let hexa;
  if (type === "fichier") {
    let st;
    try {
      st = fs.statSync(valeur);
    } catch (err) {
      throw new Arret("entree_illisible", null, `${nom} : ${valeur} illisible (${err.code})`);
    }
    if (process.platform !== "win32" && (st.mode & 0o077) !== 0) throw new Arret("entree_illisible", null, `${nom} : ${valeur} lisible par d'autres que son propriétaire (mode ${(st.mode & 0o777).toString(8)}) ; chmod 600`);
    hexa = fs.readFileSync(valeur, "utf8").trim();
  } else if (type === "env") {
    hexa = process.env[valeur];
    if (!hexa) throw new Arret("entree_illisible", null, `${nom} : variable ${valeur} absente`);
    hexa = hexa.trim();
  } else if (type === "hardhat") {
    if (instance && !estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, `${nom} : hardhat: n'est admis que sur le réseau de développement (EX-7.3)`);
    if (!/^(0|[1-9][0-9]?)$/.test(valeur)) throw new Arret("usage", null, `${nom} : hardhat:<i> attend un indice`);
    hexa = HDNodeWallet.fromPhrase(MNEMONIQUE_TEST, undefined, `m/44'/60'/0'/0/${valeur}`).privateKey;
  } else throw new Arret("usage", null, `${nom} : référence ${type}: inconnue (fichier:, env:, hardhat:)`);
  if (!hexa.startsWith("0x")) hexa = "0x" + hexa;
  if (!/^0x[0-9a-fA-F]{64}$/.test(hexa)) throw new Arret("entree_illisible", null, `${nom} : clé secp256k1 de 32 octets en hexadécimal attendue`);
  return new SigningKey(hexa.toLowerCase());
}

/** Graine Ed25519 graine:<chemin> (réseau de développement seulement). */
function graineEd25519(reference, instance) {
  if (typeof reference !== "string" || !reference.startsWith("graine:")) throw new Arret("usage", null, "--graine attend graine:<chemin>");
  if (!estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, "graine: n'est admis que sur le réseau de développement (EX-7.3)");
  const f = reference.slice("graine:".length);
  const st = fs.statSync(f, { throwIfNoEntry: false });
  if (!st) throw new Arret("entree_illisible", null, `${f} absent`);
  if (process.platform !== "win32" && (st.mode & 0o077) !== 0) throw new Arret("entree_illisible", null, `${f} lisible par d'autres que son propriétaire ; chmod 600`);
  let g = fs.readFileSync(f, "utf8").trim();
  if (!g.startsWith("0x")) g = "0x" + g;
  if (!/^0x[0-9a-fA-F]{64}$/.test(g)) throw new Arret("entree_illisible", null, `${f} : graine de 32 octets attendue`);
  return cleEd25519DepuisGraine(g.toLowerCase());
}

const adresseCle = (k) => computeAddress(k.publicKey).toLowerCase();

/** Comptes de l'exploitant (EX-7.3) : --exploitant (développement) ou un drapeau par rôle. */
function comptesExploitant(options, instance, roles) {
  const out = {};
  const drapeau = { deployeur: "deployeur", administrateur_registre: "administrateur", tresorerie: "tresorerie", relayeur: "relayeur" };
  for (const role of roles) {
    const ref = options[drapeau[role]] ?? options.exploitant;
    if (!ref) throw new Arret("usage", null, `--${drapeau[role]} (ou --exploitant sur le réseau de développement) est obligatoire`);
    if (options.exploitant && !options[drapeau[role]] && !estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, "--exploitant n'est admis que sur le réseau de développement (EX-7.3)");
    out[role] = cleSecp(ref, instance, { nom: `--${drapeau[role]}` });
  }
  return out;
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

class ErreurRPC extends Error {
  constructor(code, message, url) {
    super(message);
    this.codeRPC = code;
    this.url = url;
  }
}

/** Jeton Bearer du nœud (EX-10.3), posé par --jeton pour la commande en cours ; jamais journalisé ni écrit. */
let JETON_BEARER = null;

/** --jeton env:<VARIABLE> ou fichier:<chemin> (EX-7.1) ; toute autre forme est refusée (jamais en clair). */
function jetonDe(options) {
  const ref = options.jeton;
  if (ref === undefined) return null;
  if (typeof ref !== "string" || !/^(env|fichier):./.test(ref)) throw new Arret("usage", null, "--jeton attend env:<VARIABLE> ou fichier:<chemin>, jamais le jeton en clair");
  const [type, ...reste] = ref.split(":");
  const valeur = reste.join(":");
  let jeton;
  if (type === "env") jeton = process.env[valeur];
  else {
    let st;
    try {
      st = fs.statSync(valeur);
    } catch (err) {
      throw new Arret("entree_illisible", null, `--jeton : ${valeur} illisible (${err.code})`);
    }
    if (process.platform !== "win32" && (st.mode & 0o077) !== 0) throw new Arret("entree_illisible", null, `--jeton : ${valeur} lisible par d'autres que son propriétaire ; chmod 600`);
    jeton = fs.readFileSync(valeur, "utf8");
  }
  jeton = String(jeton ?? "").trim();
  if (!jeton) throw new Arret("entree_illisible", null, `--jeton : ${type === "env" ? `variable ${valeur} absente` : "fichier vide"}`);
  return jeton;
}

/** Appel JSON-RPC brut : octets exacts de la réponse et valeur analysée. */
async function rpcBrut(url, method, params) {
  const corps = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  let reponse;
  try {
    const headers = { "Content-Type": "application/json" };
    if (JETON_BEARER) headers.Authorization = `Bearer ${JETON_BEARER}`;
    reponse = await fetch(url, { method: "POST", headers, body: corps, signal: AbortSignal.timeout(15000) });
  } catch (err) {
    throw new ErreurRPC(null, `${url} injoignable (${err.cause?.code ?? err.name})`, url);
  }
  const octets = Buffer.from(await reponse.arrayBuffer());
  let valeur;
  try {
    valeur = JSON.parse(octets.toString("utf8"));
  } catch {
    throw new ErreurRPC(null, `${url} : réponse non JSON (HTTP ${reponse.status})`, url);
  }
  return { octets, valeur };
}

/** Client des points --rpc : lectures au premier qui répond, soumission à chacun (EX-8.15). */
class Client {
  constructor(urls) {
    this.urls = urls;
  }
  async appel(method, params, { url = null } = {}) {
    const liste = url ? [url] : this.urls;
    let derniere = null;
    for (const u of liste) {
      let r;
      try {
        r = await rpcBrut(u, method, params);
      } catch (err) {
        derniere = err;
        continue;
      }
      if (r.valeur.error) throw new ErreurRPC(r.valeur.error.code, r.valeur.error.message ?? JSON.stringify(r.valeur.error), u);
      return r.valeur.result;
    }
    throw new Arret("noeud_injoignable", "OP-2", derniere?.message ?? "aucun point --rpc ne répond");
  }
  async vue(adresse, nomContrat, fonction, args = [], bloc = "latest") {
    const iface = artefact(nomContrat).iface;
    const data = iface.encodeFunctionData(fonction, args);
    let brut;
    try {
      brut = await this.appel("eth_call", [{ to: adresse, data }, bloc]);
    } catch (err) {
      if (err instanceof ErreurRPC) throw new Arret("transaction_annulee", null, `eth_call ${fonction} : ${err.message}`);
      throw err;
    }
    // Une adresse sans code rend 0x : jamais une erreur interne (7.11, code_absent).
    if (!brut || brut === "0x") throw new Arret("code_absent", null, `eth_call ${nomContrat}.${fonction} sur ${adresse} : aucune donnée rendue (aucun code à cette adresse ?)`);
    let r;
    try {
      r = iface.decodeFunctionResult(fonction, brut);
    } catch (err) {
      throw new Arret("code_absent", null, `eth_call ${nomContrat}.${fonction} sur ${adresse} : réponse indécodable (${err.shortMessage ?? err.message})`);
    }
    return r.length === 1 ? r[0] : r;
  }
}

// ---------------------------------------------------------------------------
// OP-1, OP-2 : instance et nœuds validateurs (EX-4.9)
// ---------------------------------------------------------------------------

async function verifierInstanceEnLigne(ctx, instance, client, { sansCapture }) {
  const m = instance.manifeste;
  const tete = { hauteur: null, hachage: null };
  await ctx.op("OP-2", async () => {
    for (const url of client.urls) {
      // EX-7.1 : en production, http:// seulement vers la boucle locale (tunnel ou mandataire local, EX-10.8).
      if (m.nature === "production") {
        let u;
        try {
          u = new URL(url);
        } catch {
          throw new Arret("noeud_injoignable", "OP-2", `${url} : URL invalide`);
        }
        if (u.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]", "::1"].includes(u.hostname)) throw new Arret("noeud_injoignable", "OP-2", `${urlSansSecret(url)} : http:// vers un hôte non local n'est pas admis sur une instance de production (EX-7.1, EX-10.3)`);
      }
      try {
        await rpcBrut(url, "eth_chainId", []);
      } catch (err) {
        throw new Arret("noeud_injoignable", "OP-2", err.message);
      }
    }
  });
  await ctx.op("OP-1", async () => {
    for (const url of client.urls) {
      const id = BigInt(await client.appel("eth_chainId", [], { url }));
      if (id !== BigInt(m.evm_chain_id)) {
        if (instance.defaut) throw new Arret("reseau_non_developpement", "OP-1", `${url} sert l'identifiant EVM ${id}, pas 2124 : sans --instance, l'outil n'admet que le réseau de développement (EX-7.2)`);
        throw new Arret("chaine_differente", "OP-1", `${url} sert l'identifiant EVM ${id}, pas ${m.evm_chain_id}`);
      }
    }
    if (sansCapture && m.evm_chain_id !== C.RESEAU_ESSAI.evm_chain_id) throw new Arret("usage", "OP-1", "--sans-capture n'est admis que pour l'identifiant EVM 31337 (EX-A.6)");
    tete.hauteur = BigInt(await client.appel("eth_blockNumber", []));
    if (!sansCapture) {
      let cert;
      try {
        cert = await certificatAvecReessais(client, "latest", client.urls[0], ctx);
      } catch (err) {
        if (err instanceof Arret) err.check = "OP-1";
        throw err;
      }
      const jeu = C.jeuEnVigueur(m);
      if (cert.valeur.chainId !== m.bft_chain_id) throw new Arret("chaine_differente", "OP-1", `certificat de la tête : chainId ${cert.valeur.chainId} au lieu de ${m.bft_chain_id}`);
      if (String(cert.valeur.valsetHash).toLowerCase() !== jeu.valset_hash) throw new Arret("jeu_validateurs_different", "OP-1", `certificat de la tête : valsetHash ${cert.valeur.valsetHash} au lieu de ${jeu.valset_hash} (réseau recréé ?)`);
    }
    for (const c of m.contracts.filter((x) => x.to_height === null)) {
      const code = await client.appel("eth_getCode", [c.address, "latest"]);
      if (!code || code === "0x") throw new Arret("code_absent", "OP-1", `aucun code à l'adresse de ${c.name} (${c.address})`);
    }
    const att = C.contratEnService(m, "AttestationRegistry");
    if (att.block_hash) {
      const b = await client.appel("eth_getBlockByNumber", [C.quantiteRPC(att.block_number), false]);
      if (!b || String(b.hash).toLowerCase() !== att.block_hash) throw new Arret("chaine_differente", "OP-1", `bloc de déploiement d'AttestationRegistry ${att.block_number} de hachage ${b?.hash} au lieu de ${att.block_hash}`);
    }
    const b = await client.appel("eth_getBlockByNumber", [C.quantiteRPC(tete.hauteur), false]);
    tete.hachage = String(b.hash).toLowerCase();
  });
  if (!sansCapture) {
    await ctx.op("OP-2", async () => {
      for (const url of client.urls) {
        let st;
        try {
          st = await client.appel("noor_txindexStatus", [], { url });
        } catch (err) {
          throw new Arret("noeud_suiveur", "OP-2", `${url} : noor_txindexStatus en erreur (${err.message})`);
        }
        const h = BigInt(st?.last_indexed_height ?? 0);
        if (h === 0n || h < tete.hauteur) throw new Arret("noeud_suiveur", "OP-2", `${url} : last_indexed_height ${h} (tête ${tete.hauteur}) : point d'un suiveur, interroger un validateur (10.3)`);
      }
    });
  }
  return tete;
}

/**
 * noor_getCommitCertificate avec la conduite de 9.3 ; rend { octets, valeur,
 * essais }. Un certificat indisponible, élagué ou un nœud injoignable rendent
 * `incertain` (code 3) : une transaction peut être partie et sa capture n'est
 * pas faite ; seuls un appel mal formé et un binaire sans correctif rendent
 * `inutilisable` (7.11).
 */
async function certificatAvecReessais(client, parametre, url, ctx, { hauteur = null } = {}) {
  let essais = 0;
  const incertain = { result: "incertain" };
  const tete = async () => BigInt(await client.appel("eth_blockNumber", [], { url }));
  for (;;) {
    essais++;
    let r;
    try {
      r = await rpcBrut(url, "noor_getCommitCertificate", [parametre]);
    } catch (err) {
      throw new Arret("noeud_injoignable", "CP-1", err.message, incertain);
    }
    if (r.valeur.result) return { octets: r.octets, valeur: r.valeur.result, essais };
    const e = r.valeur.error ?? {};
    const msg = String(e.message ?? "");
    if (e.code === -32601) throw new Arret("entree_illisible", "CP-4", `${url} ne sert pas noor_getCommitCertificate (binaire sans correctif, 4.7)`, { result: "inutilisable" });
    if (e.code === -32602) throw new Arret("usage", "CP-4", `appel mal formé : ${msg}`);
    if (/leader unreachable/.test(msg)) throw new Arret("noeud_suiveur", "CP-1", `${url} : point d'un suiveur sans meneur`, incertain);
    if (/not yet persisted/.test(msg)) {
      // 9.3 : réessai toutes les 50 ms, au plus 100 fois et jusqu'à ce que la tête dépasse le bloc.
      const depassee = hauteur !== null && (await tete()) > BigInt(hauteur);
      if (essais < 100 && !depassee) {
        await new Promise((res) => setTimeout(res, 50));
        continue;
      }
      throw new Arret("certificat_indisponible", "CP-4", `${url} : ${msg} (${essais} essai(s)${depassee ? ", tête au-delà du bloc" : ""})`, incertain);
    }
    if (/prun|retention/i.test(msg) && !/inside the retention window/.test(msg)) throw new Arret("certificat_elague", "CP-4", `${url} : ${msg}`, incertain);
    if (/unknown block/.test(msg) && hauteur !== null) {
      // 9.3 : relire la tête ; si elle dépasse la hauteur, certificat_indisponible sans réessai ; sinon le bloc n'est pas encore là.
      const h = await tete();
      if (h < BigInt(hauteur) && essais < 100) {
        await new Promise((res) => setTimeout(res, 50));
        continue;
      }
      throw new Arret("certificat_indisponible", "CP-4", `${url} : ${msg} (tête ${h}, hauteur ${hauteur})`, incertain);
    }
    throw new Arret("certificat_indisponible", "CP-4", `${url} : ${msg || "certificat absent"}`, incertain);
  }
}

// ---------------------------------------------------------------------------
// Capture (9.4)
// ---------------------------------------------------------------------------

function nomValidateur(url, instance) {
  if (!instance.defaut) return null;
  try {
    const u = new URL(url);
    return (["127.0.0.1", "localhost"].includes(u.hostname) && PORTS_DEV[u.port]) || null;
  } catch {
    return null;
  }
}

function urlSansSecret(url) {
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    u.search = "";
    return u.toString().replace(/\/$/, "");
  } catch {
    return String(url).slice(0, 256);
  }
}

/**
 * Capture une transaction incluse : CP-1 (point de validateur), en-tête,
 * reçus de toutes les transactions du bloc, certificat ; CP-2 à CP-6 ; index
 * écrit et synchronisé. Les fichiers déjà présents ne sont jamais réécrits
 * (EX-9.3). Rend { nom, index, marge }.
 */
async function capturerTransaction(ctx, { instance, client, repertoire, role, transactionHash, contrat, logIndex, sending, hauteur }) {
  const m = instance.manifeste;
  const h = Number(hauteur);
  const incertain = { result: "incertain" };
  fs.mkdirSync(repertoire, { recursive: true });
  // CP-1 : premier point --rpc qui est un validateur de l'instance.
  let url = null;
  await ctx.op("CP-1", async () => {
    let raison = null;
    for (const u of client.urls) {
      try {
        const id = BigInt(await client.appel("eth_chainId", [], { url: u }));
        if (id !== BigInt(m.evm_chain_id)) {
          raison = new Arret("chaine_differente", "CP-1", `${u} : identifiant EVM ${id}`, incertain);
          continue;
        }
        const st = await client.appel("noor_txindexStatus", [], { url: u });
        if (!(BigInt(st?.last_indexed_height ?? 0) >= BigInt(h) && BigInt(st?.last_indexed_height ?? 0) > 0n)) {
          raison = new Arret("noeud_suiveur", "CP-1", `${u} : last_indexed_height ${st?.last_indexed_height} < ${h}`, incertain);
          continue;
        }
        url = u;
        return;
      } catch (err) {
        raison = err instanceof Arret ? err : new Arret("noeud_suiveur", "CP-1", `${u} : ${err.message}`, incertain);
        if (raison.result === "refuse") raison.result = "incertain";
      }
    }
    throw raison ?? new Arret("noeud_injoignable", "CP-1", "aucun point --rpc", incertain);
  });
  const fichier = (nom) => path.join(repertoire, nom);
  const lireFichier = (nom) => (fs.existsSync(fichier(nom)) ? fs.readFileSync(fichier(nom)) : null);
  const garder = async (nom, obtenir) => {
    if (fs.existsSync(fichier(nom))) return fs.readFileSync(fichier(nom));
    const o = await obtenir();
    ecrireSynchronise(fichier(nom), o);
    return o;
  };
  const q = C.quantiteRPC(h);
  const blocBrut = await garder(`bloc-${h}.json`, async () => {
    const r = await rpcBrut(url, "eth_getBlockByNumber", [q, false]);
    if (!r.valeur.result) throw new Arret("capture_incomplete", "CP-2", `bloc ${h} introuvable chez ${url}`, incertain);
    return r.octets;
  });
  const bloc = JSON.parse(blocBrut.toString("utf8")).result;
  const recus = [];
  for (const t of bloc.transactions.map((x) => (typeof x === "string" ? x : x.hash).toLowerCase())) {
    const nom = `recu-${t}.json`;
    const b = await garder(nom, async () => {
      const r = await rpcBrut(url, "eth_getTransactionReceipt", [t]);
      if (!r.valeur.result) throw new Arret("capture_incomplete", "CP-3", `reçu de ${t} introuvable chez ${url}`, incertain);
      return r.octets;
    });
    recus.push({ name: nom, sha256: sha256(b) });
  }
  let essais = 1;
  const nomCert = `certificat-${h}.json`;
  let certBrut = lireFichier(nomCert);
  if (!certBrut) {
    let dernier = null;
    for (const u of [url, ...client.urls.filter((x) => x !== url)]) {
      try {
        const c = await certificatAvecReessais(client, q, u, ctx, { hauteur: h });
        essais = c.essais;
        certBrut = c.octets;
        break;
      } catch (err) {
        dernier = err;
        if (err instanceof Arret && ["certificat_elague", "entree_illisible", "usage"].includes(err.code)) break;
      }
    }
    if (!certBrut) throw dernier;
    ecrireSynchronise(fichier(nomCert), certBrut);
  }
  const transactionIndex = bloc.transactions.map((x) => (typeof x === "string" ? x : x.hash).toLowerCase()).indexOf(transactionHash.toLowerCase());
  if (transactionIndex === -1) throw new Arret("capture_incomplete", "CP-3", `transaction ${transactionHash} absente du bloc ${h}`, incertain);
  const jeu = C.jeuPourHauteur(m, h);
  if (!jeu) throw new Arret("certificat_invalide", "CP-4", `aucun jeu du manifeste ne couvre la hauteur ${h}`, incertain);
  const index = {
    version: 0,
    role,
    evm_chain_id: m.evm_chain_id,
    bft_chain_id: m.bft_chain_id,
    contract: contrat ? contrat.toLowerCase() : null,
    transaction_hash: transactionHash.toLowerCase(),
    block_number: h,
    block_hash: String(bloc.hash).toLowerCase(),
    transaction_index: transactionIndex,
    log_index: logIndex,
    files: { block: { name: `bloc-${h}.json`, sha256: sha256(blocBrut) }, receipts: recus, certificate: { name: nomCert, sha256: sha256(certBrut) } },
    node: { rpc: urlSansSecret(url), validator_id: nomValidateur(url, instance) },
    validator_set_hash: jeu.valset_hash,
    captured_at: maintenant(),
    attempts: Math.min(essais, 1000),
    checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })),
    sending,
  };
  const nomIdx = C.nomIndex(h, transactionIndex, role);
  if (fs.existsSync(fichier(nomIdx))) {
    const existant = JSON.parse(fs.readFileSync(fichier(nomIdx), "utf8"));
    index.captured_at = existant.captured_at;
    index.attempts = existant.attempts;
    index.sending = existant.sending ?? sending;
  }
  const v = C.verifierCapture({ index, lireFichier, validators: { validators: jeu.validators }, bft_chain_id: m.bft_chain_id, schemas: schemas() });
  for (const r of v.checks) ctx.noter(r.check, r.status, r.status === "reussi" ? "" : r.detail);
  const enEchec = v.checks.find((r) => r.status !== "reussi");
  if (enEchec) throw new Arret(enEchec.code, enEchec.check, enEchec.detail, incertain);
  // EX-9.6 : marge de rétention.
  const retention = v.contexte.certificat?.retention?.heights ?? null;
  let marge = null;
  if (retention) {
    const tete = BigInt(await client.appel("eth_blockNumber", [], { url }));
    marge = { retention_heights: retention, margin_heights: Number(BigInt(h) + BigInt(retention) - tete), alert: BigInt(h) + BigInt(retention) - tete < BigInt(retention) / 10n };
    if (marge.alert) ctx.log(`alerte : marge de rétention de ${marge.margin_heights} hauteurs, sous 10 % de la fenêtre (EX-9.6)`);
  }
  if (!fs.existsSync(fichier(nomIdx))) ecrireSynchronise(fichier(nomIdx), texteJSON(index));
  return { nom: nomIdx, index, marge };
}

// ---------------------------------------------------------------------------
// Envoi d'une transaction (EX-7.5, 8.6)
// ---------------------------------------------------------------------------

/** Issue connue d'un envoi (fichier issue-<hachage>.json, #/$defs/issue), ou null. */
function lireIssue(repertoire, transactionHash) {
  const f = path.join(repertoire, `issue-${transactionHash}.json`);
  if (!fs.existsSync(f)) return null;
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Un envoi est sans issue connue quand il n'a pas de fichier d'issue, ou quand
 * son issue est `remplacee` et que son remplaçant n'a pas lui-même d'issue
 * d'inclusion ou de mise à l'écart (EX-8.16, chaîne replaced_by suivie).
 */
function envoiSansIssue(repertoire, transactionHash, profondeur = 0) {
  const issue = lireIssue(repertoire, transactionHash);
  if (!issue) return true;
  if (issue.state === "remplacee" && issue.replaced_by && profondeur < 32) return envoiSansIssue(repertoire, issue.replaced_by, profondeur + 1);
  return false;
}

/** Envois d'un expéditeur sans issue connue dans le répertoire des captures (OP-3, EX-8.14) ; `sauf` : hachage non compté (l'envoi qu'un remplacement remplace). */
function envoisEnAttente(repertoire, from, { sauf = null } = {}) {
  if (!repertoire || !fs.existsSync(repertoire)) return [];
  return fs
    .readdirSync(repertoire)
    .filter((f) => /^envoi-0x[0-9a-f]{64}\.json$/.test(f))
    .map((f) => ({ f, e: JSON.parse(fs.readFileSync(path.join(repertoire, f), "utf8")) }))
    .filter(({ e }) => e.from === from && e.transaction_hash !== sauf && envoiSansIssue(repertoire, e.transaction_hash))
    .map(({ f }) => f);
}

/** Écrit issue-<hachage>.json (#/$defs/issue) ; un fichier présent n'est réécrit qu'avec `remplacer`. */
function ecrireIssue(repertoire, transactionHash, issue, { remplacer = false } = {}) {
  const f = path.join(repertoire, `issue-${transactionHash}.json`);
  const doc = { version: 0, transaction_hash: transactionHash, ...issue, recorded_at: maintenant() };
  const e = conforme(doc, C.ID_SCHEMA_OPERATIONS, "#/$defs/issue");
  if (e.length) throw new Error(`issue produite non conforme : ${e[0].chemin} : ${e[0].message}`);
  if (!fs.existsSync(f)) ecrireSynchronise(f, texteJSON(doc));
  else if (remplacer) remplacerFichier(f, texteJSON(doc));
}

/** OP-3 : provision de l'expéditeur (au prix de la transaction à envoyer), provision du destinataire, envois en attente. */
async function verifierExpediteur(ctx, { client, instance, from, value = 0n, repertoire, destinataire = null, provisionDestinataire = null, prix = null, sauf = null }) {
  await ctx.op("OP-3", async () => {
    const fees = instance.manifeste.fees;
    const solde = BigInt(await client.appel("eth_getBalance", [from, "latest"]));
    const besoin = C.coutMaximal(fees, value, prix);
    if (solde < besoin) throw new Arret("solde_insuffisant", "OP-3", `solde de ${from} : ${solde} wei, il faut ${besoin} wei (gas_limit × maxFeePerGas + value, EX-4.18)`);
    if (destinataire && provisionDestinataire !== null) {
      const s = BigInt(await client.appel("eth_getBalance", [destinataire, "latest"]));
      if (s + value > provisionDestinataire) throw new Arret("provision_excessive", "OP-3", `${destinataire} : ${s} + ${value} wei au-delà de sa provision ${provisionDestinataire} wei (EX-4.20)`);
    }
    const attente = envoisEnAttente(repertoire, from, { sauf });
    if (attente.length) throw new Arret("transaction_en_attente", "OP-3", `envoi sans issue de ${from} : ${attente[0]} ; reprendre par capturer --envoi (8.6)`);
  });
}

/**
 * Signe, vérifie (RG-15), écrit l'envoi, soumet à chaque point --rpc, attend
 * le reçu, puis OP-11, la capture (sauf --sans-capture) et OP-12. `appel` :
 * { objet, to, data, value, contrat (pour l'index), role, logIndex,
 * evenement(recu) (OP-11, lève), relecture(bloc) (OP-12, lève), surEnvoi(envoi)
 * (étape envoyee, EX-7.16), surRecu(recu, h) (étape incluse), surEchec(err)
 * (étape echec) }. `remplace` : { prix, hash } de l'envoi remplacé (8.6).
 */
async function envoyer(ctx, { instance, client, cle, appel, repertoire, sansCapture, delai, remplace = null, nonceImpose = null }) {
  const m = instance.manifeste;
  const from = adresseCle(cle);
  const nonce = nonceImpose ?? BigInt(await client.appel("eth_getTransactionCount", [from, "latest"]));
  const prix = remplace !== null ? C.fraisRemplacement(remplace.prix) : BigInt(m.fees.max_fee_per_gas_wei);
  const champs = { chain_id: m.evm_chain_id, nonce, max_priority_fee_per_gas: prix, max_fee_per_gas: prix, gas_limit: m.fees.gas_limit, to: appel.objet === "deploiement" ? null : appel.to, value: appel.value ?? 0n, data: appel.data };
  const signee = C.signerTransaction(champs, cle.privateKey);
  const rg15 = C.verifier("RG-15", () => C.verifierTransaction(signee.raw_transaction, { evm_chain_id: m.evm_chain_id, fees: m.fees, objet: appel.objet, to: appel.to, data: appel.data, provision: appel.provision ?? null, remplace: remplace?.prix ?? null, from }));
  if (rg15.status !== "reussi") throw new Arret("transaction_refusee", null, `RG-15 sur les octets signés : ${rg15.detail}`);
  const envoi = {
    from,
    to: champs.to,
    nonce: Number(nonce),
    type: 2,
    max_fee_per_gas: prix.toString(),
    max_priority_fee_per_gas: prix.toString(),
    gas_limit: String(m.fees.gas_limit),
    value: BigInt(champs.value).toString(),
    raw_transaction: signee.raw_transaction,
    transaction_hash: signee.transaction_hash,
    submitted_to: client.urls.map(urlSansSecret),
    submitted_at: maintenant(),
  };
  const fEnvoi = path.join(repertoire, `envoi-${signee.transaction_hash}.json`);
  const e = conforme(envoi, C.ID_SCHEMA_OPERATIONS, "#/$defs/envoi");
  if (e.length) throw new Error(`envoi produit non conforme : ${e[0].chemin} : ${e[0].message}`);
  ecrireSynchronise(fEnvoi, texteJSON(envoi));
  ctx.log(`envoi ${signee.transaction_hash} (nonce ${nonce}) écrit, soumission à ${client.urls.length} point(s)`);
  if (appel.surEnvoi) await appel.surEnvoi(envoi);
  return attendreEtCapturer(ctx, { instance, client, envoi, fEnvoi, appel, repertoire, sansCapture, delai, soumettre: true, remplace });
}

/**
 * Soumission (si demandée), attente du reçu, OP-11, capture et OP-12 d'un
 * envoi écrit. Pour un remplacement (`remplace.hash` : l'original au même
 * nonce), l'issue `remplacee` de l'original n'est écrite qu'après acceptation
 * par au moins un point, et les deux hachages sont sondés jusqu'au reçu de
 * l'un d'eux (EX-8.16).
 */
async function attendreEtCapturer(ctx, { instance, client, envoi, fEnvoi, appel, repertoire, sansCapture, delai, soumettre, remplace = null }) {
  if (soumettre) {
    const erreurs = [];
    let acceptee = 0;
    for (const url of client.urls) {
      try {
        await client.appel("eth_sendRawTransaction", [envoi.raw_transaction], { url });
        acceptee++;
      } catch (err) {
        // « already known » : la copie y est déjà ; « nonce too low » : le nonce est consommé, l'issue se lit dans les reçus (EX-8.16).
        if (err instanceof ErreurRPC && /already known|known transaction|nonce too low/i.test(err.message)) acceptee++;
        else erreurs.push(err.message);
      }
    }
    if (acceptee === 0) {
      fs.renameSync(fEnvoi, path.join(repertoire, `refus-${path.basename(fEnvoi)}`));
      const complement = remplace ? ` ; l'envoi remplacé ${remplace.hash} reste sans issue (OP-3)` : "";
      throw new Arret("transaction_refusee", null, `transaction refusée par tous les points : ${erreurs.join(" ; ")}${complement}`, { result: "refuse" });
    }
    if (remplace) ecrireIssue(repertoire, remplace.hash, { state: "remplacee", replaced_by: envoi.transaction_hash }, { remplacer: true });
  }
  let courant = envoi;
  let fCourant = fEnvoi;
  const limite = Date.now() + delai * 1000;
  let recu = null;
  while (Date.now() < limite) {
    try {
      recu = await client.appel("eth_getTransactionReceipt", [courant.transaction_hash]);
      if (!recu && remplace) {
        // L'original, revenu du journal durable, a pu être inclus : il est capturé et le remplaçant écarté (EX-8.16).
        const r0 = await client.appel("eth_getTransactionReceipt", [remplace.hash]);
        if (r0) {
          const fOriginal = path.join(repertoire, `envoi-${remplace.hash}.json`);
          const original = fs.existsSync(fOriginal) ? JSON.parse(fs.readFileSync(fOriginal, "utf8")) : null;
          ctx.log(`l'envoi remplacé ${remplace.hash} est inclus au bloc ${BigInt(r0.blockNumber)} : le remplaçant ${envoi.transaction_hash} est écarté`);
          ecrireIssue(repertoire, envoi.transaction_hash, { state: "ecartee", replaces: remplace.hash });
          if (original) {
            courant = original;
            fCourant = fOriginal;
            recu = r0;
            ecrireIssue(repertoire, remplace.hash, { block_number: Number(BigInt(r0.blockNumber)), status: r0.status }, { remplacer: true });
          }
        }
      }
    } catch (err) {
      if (!(err instanceof ErreurRPC)) throw err;
    }
    if (recu) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!recu) throw new Arret("recu_absent", null, `aucun reçu pour ${courant.transaction_hash} en ${delai} s ; reprendre par capturer --envoi ${fCourant} (--renvoyer, puis --remplacer, 8.6)`, { result: "incertain", outputs: { envoi: path.basename(fCourant), transaction_hash: courant.transaction_hash } });
  const h = Number(BigInt(recu.blockNumber));
  ecrireIssue(repertoire, courant.transaction_hash, { block_number: h, status: recu.status });
  if (appel.surRecu) await appel.surRecu(recu, h, courant);
  if (!appel.role || (appel.contrat === null && appel.role !== "approvisionnement")) {
    // Reprise d'un envoi (capturer --envoi) : rôle et contrat déduits de la transaction et de son reçu ; --role et --contrat priment (8.6).
    const d = roleDeTransaction(C.decoderTransaction(courant.raw_transaction), recu);
    appel.role ??= d.role;
    appel.contrat ??= d.contrat;
    appel.logIndex = C.EVENEMENT_DU_ROLE[appel.role] ? 0 : null;
  }
  const base = { transaction_hash: courant.transaction_hash, block_number: h, gas_used: Number(BigInt(recu.gasUsed)), cost_wei: (BigInt(recu.gasUsed) * BigInt(courant.max_fee_per_gas)).toString() };
  try {
    await ctx.op("OP-11", async () => {
      if (recu.status !== "0x1") throw new Arret("transaction_annulee", "OP-11", `transaction incluse au bloc ${h} avec status ${recu.status}`, { result: "echoue", outputs: base });
      if (appel.evenement) await appel.evenement(recu);
    });
  } catch (err) {
    if (err instanceof Arret && err.result === "echoue" && appel.surEchec) await appel.surEchec(err, recu, h);
    throw err;
  }
  let capture = null;
  if (!sansCapture) {
    try {
      capture = await capturerTransaction(ctx, { instance, client, repertoire, role: appel.role, transactionHash: courant.transaction_hash, contrat: appel.contrat ?? (recu.contractAddress ? recu.contractAddress.toLowerCase() : null), logIndex: appel.logIndex, sending: courant, hauteur: h });
    } catch (err) {
      if (err instanceof Arret) {
        err.result = err.result === "inutilisable" ? "inutilisable" : "incertain";
        err.outputs = { ...base, envoi: path.basename(fCourant) };
      }
      throw err;
    }
  }
  try {
    await ctx.op("OP-12", async () => {
      if (appel.relecture) await appel.relecture(C.quantiteRPC(h), recu);
    });
  } catch (err) {
    if (err instanceof Arret && err.result === "echoue" && appel.surEchec) await appel.surEchec(err, recu, h);
    throw err;
  }
  return { ...base, recu, capture: capture?.nom ?? null, block_hash: capture?.index.block_hash ?? String(recu.blockHash).toLowerCase(), marge: capture?.marge ?? null };
}

/** Journal d'un reçu émis par `adresse` et décodé par l'ABI de `nomContrat`. */
function journaux(recu, adresse, nomContrat) {
  const iface = artefact(nomContrat).iface;
  return recu.logs
    .filter((j) => j.address.toLowerCase() === adresse.toLowerCase())
    .map((j) => {
      try {
        return iface.parseLog({ topics: j.topics, data: j.data });
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function exigerOP11(condition, message) {
  if (!condition) throw new Arret("transaction_annulee", "OP-11", message, { result: "echoue" });
}

function exigerOP12(condition, message) {
  if (!condition) throw new Arret("transaction_annulee", "OP-12", message, { result: "echoue" });
}

// ---------------------------------------------------------------------------
// Dossier d'inscription
// ---------------------------------------------------------------------------

function lireDossier(fichier) {
  const d = lireJSONFichier(fichier);
  const e = conforme(d, C.ID_SCHEMA_INSCRIPTION);
  if (e.length) throw new Arret("entree_illisible", null, `dossier non conforme à inscription-client-v0 : ${e.slice(0, 3).map((x) => `${x.chemin} : ${x.message}`).join(" ; ")}`);
  return d;
}

function ecrireDossier(fichier, d) {
  const e = conforme(d, C.ID_SCHEMA_INSCRIPTION);
  if (e.length) throw new Error(`dossier produit non conforme : ${e.slice(0, 3).map((x) => `${x.chemin} : ${x.message}`).join(" ; ")}`);
  remplacerFichier(fichier, texteJSON(d));
}

function etape(d, step, subject) {
  return d.steps.find((s) => s.step === step && s.subject === subject) ?? null;
}

function majEtape(e, { state, transaction_hash = null, block_number = null, block_hash = null, capture = null, error = null, contract = undefined }) {
  Object.assign(e, { state, transaction_hash, block_number, block_hash, capture, error, updated_at: maintenant() });
  if (contract !== undefined) e.contract = contract;
}

/** Le dossier désigne-t-il la même instance (EX-4.1) ? */
function verifierDossierInstance(d, instance) {
  const m = instance.manifeste;
  const c = adressesContrats(m);
  if (d.instance.evm_chain_id !== m.evm_chain_id || d.instance.bft_chain_id !== m.bft_chain_id || d.instance.genesis_sha256 !== m.genesis.sha256 || !egalJSON(d.instance.contracts, c)) {
    throw new Arret("chaine_differente", "OP-1", "le dossier désigne une autre instance (bft_chain_id, evm_chain_id, genesis_sha256 ou contrats, EX-4.1)");
  }
}

/** Remplit `result` quand toutes les étapes sont faites et capturées (7.10). */
function completerResultat(d, repertoireCaptures) {
  if (d.result) return;
  if (!d.steps.length || !d.steps.every((s) => s.state === "capturee" || s.state === "faite")) return;
  const ref = (s) => (s && s.transaction_hash && s.capture ? { transaction_hash: s.transaction_hash, block_number: s.block_number, block_hash: s.block_hash, capture: s.capture } : null);
  const jeu = d.steps.find((s) => s.step === "jeu_approbateurs");
  const ass = d.steps.find((s) => s.step === "assignation");
  const lec = d.steps.find((s) => s.step === "lecture_jeu");
  const set = curatorSetDuDossier(d, repertoireCaptures);
  const recorders = d.recorders.map((r) => ({ key_id: r.key_id, chain_key: r.chain_key, funding: ref(etape(d, "approvisionnement", r.chain_key)), registration: ref(etape(d, "inscription", r.key_id)) }));
  if (!set || !ref(jeu) || !ref(ass) || recorders.some((r) => !r.funding || !r.registration)) return;
  const fin = [...d.steps].map((s) => s.updated_at).filter(Boolean).sort().pop();
  d.result = {
    curator_set: set,
    set_deployment: ref(jeu),
    assignment: ref(ass),
    approver_set: { source: "registre", chain_id: d.instance.evm_chain_id, registry: d.instance.contracts.curator_set_registry, set, members: null, threshold: null },
    set_read: { height: lec.block_number, block_hash: lec.block_hash, threshold: d.approvers.threshold, size: d.approvers.members.length, members: [...d.approvers.members] },
    recorders,
    completed_at: fin,
  };
}

/** Adresse du CuratorSet de l'organisation : `contract` de l'étape jeu_approbateurs (EX-7.16), sinon l'index de capture de son déploiement. */
function curatorSetDuDossier(d, repertoireCaptures) {
  const s = d.steps.find((x) => x.step === "jeu_approbateurs");
  if (s?.contract) return s.contract;
  if (!s?.capture || !repertoireCaptures) return null;
  const f = path.join(repertoireCaptures, s.capture);
  if (!fs.existsSync(f)) return null;
  return JSON.parse(fs.readFileSync(f, "utf8")).contract;
}

/** Crochets d'une étape du dossier (EX-7.16) : envoyee, incluse (et contract pour le jeu), echec ; le dossier est réécrit à chaque passage. */
function suiviEtape(e, ecrire, { contrat = null, sujet = null } = {}) {
  return {
    surEnvoi: async (envoi) => {
      if (sujet) e.subject = sujet;
      majEtape(e, { state: "envoyee", transaction_hash: envoi.transaction_hash, ...(contrat ? { contract: contrat } : {}) });
      ecrire();
    },
    surRecu: async (recu, h) => {
      majEtape(e, { state: "incluse", transaction_hash: String(recu.transactionHash).toLowerCase(), block_number: h, block_hash: String(recu.blockHash).toLowerCase(), ...(contrat ? { contract: contrat } : {}) });
      ecrire();
    },
    surEchec: async (err, recu, h) => {
      majEtape(e, { state: "echec", transaction_hash: String(recu.transactionHash).toLowerCase(), block_number: h, block_hash: String(recu.blockHash).toLowerCase(), error: { code: err.code, message: String(err.message).slice(0, 1024) }, ...(contrat ? { contract: contrat } : {}) });
      ecrire();
    },
  };
}

/**
 * Reprise d'une étape `envoyee` ou `incluse` (EX-7.16) : le reçu de la
 * transaction connue est relu ; absent, `transaction_en_attente` (capturer
 * --envoi) ; `status` 0x0, `echec` ; sinon l'étape passe par `incluse`, puis,
 * sauf --sans-capture, est capturée et passe à `capturee`. Rend le reçu.
 */
async function reprendreEtape(ctx, e, { instance, client, repertoire, sansCapture, role, contrat, logIndex, ecrire }) {
  const recu = await client.appel("eth_getTransactionReceipt", [e.transaction_hash]).catch(() => null);
  if (!recu) throw new Arret("transaction_en_attente", "OP-3", `étape ${e.step} (${e.subject}) ${e.state} : ${e.transaction_hash} sans reçu ; reprendre par capturer --envoi ${path.join(repertoire, `envoi-${e.transaction_hash}.json`)} --dossier (8.6)`);
  const h = Number(BigInt(recu.blockNumber));
  ecrireIssue(repertoire, e.transaction_hash, { block_number: h, status: recu.status });
  if (recu.status !== "0x1") {
    majEtape(e, { state: "echec", transaction_hash: e.transaction_hash, block_number: h, block_hash: String(recu.blockHash).toLowerCase(), error: { code: "transaction_annulee", message: `transaction incluse au bloc ${h} avec status ${recu.status}` }, contract: e.contract ?? null });
    ecrire();
    throw new Arret("transaction_annulee", "OP-11", `étape ${e.step} : transaction ${e.transaction_hash} incluse au bloc ${h} avec status ${recu.status}`, { result: "echoue" });
  }
  ctx.log(`étape ${e.step} (${e.subject}) ${e.state} : reçu de ${e.transaction_hash} au bloc ${h}, reprise sans renvoi (EX-7.16)`);
  const contratEffectif = contrat ?? (recu.contractAddress ? String(recu.contractAddress).toLowerCase() : null);
  majEtape(e, { state: "incluse", transaction_hash: e.transaction_hash, block_number: h, block_hash: String(recu.blockHash).toLowerCase(), contract: role === "jeu_approbateurs" ? contratEffectif : e.contract ?? null });
  ecrire();
  if (!sansCapture) {
    const cap = await capturerTransaction(ctx, { instance, client, repertoire, role, transactionHash: e.transaction_hash, contrat: contratEffectif, logIndex, sending: lireEnvoi(repertoire, e.transaction_hash), hauteur: h });
    majEtape(e, { state: "capturee", transaction_hash: e.transaction_hash, block_number: h, block_hash: cap.index.block_hash, capture: cap.nom, contract: e.contract ?? null });
    ecrire();
  }
  return recu;
}

/** L'envoi écrit pour un hachage, ou null. */
function lireEnvoi(repertoire, transactionHash) {
  const f = path.join(repertoire, `envoi-${transactionHash}.json`);
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null;
}

/** Les envois du répertoire des captures qui portent exactement (from, to, data), les plus récents d'abord. */
function envoisCorrespondants(repertoire, { from, to, data }) {
  if (!repertoire || !fs.existsSync(repertoire)) return [];
  return fs
    .readdirSync(repertoire)
    .filter((f) => /^envoi-0x[0-9a-f]{64}\.json$/.test(f))
    .map((f) => JSON.parse(fs.readFileSync(path.join(repertoire, f), "utf8")))
    .filter((e) => e.from === from && (e.to ?? null) === (to ?? null))
    .filter((e) => {
      try {
        return C.decoderTransaction(e.raw_transaction).data === data.toLowerCase();
      } catch {
        return false;
      }
    })
    .sort((a, b) => b.nonce - a.nonce);
}

// ---------------------------------------------------------------------------
// Commandes
// ---------------------------------------------------------------------------

function urlsRPC(options) {
  return String(options.rpc ?? RPC_DEFAUT)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function delaiDe(options) {
  const d = options.delai === undefined ? 120 : Number(options.delai);
  if (!Number.isFinite(d) || d <= 0) throw new Arret("usage", null, "--delai : nombre de secondes positif attendu");
  return d;
}

function capturesDe(options) {
  const r = exigerOption(options, "captures");
  fs.mkdirSync(r, { recursive: true });
  return path.resolve(r);
}

async function preparer(ctx, { avecReseau = true } = {}) {
  const o = ctx.options;
  const instance = chargerInstance(o);
  const client = new Client(urlsRPC(o));
  const sansCapture = o["sans-capture"] === true;
  if (sansCapture && instance.manifeste.evm_chain_id !== C.RESEAU_ESSAI.evm_chain_id) throw new Arret("usage", null, "--sans-capture n'est admis que pour l'identifiant EVM 31337 (EX-A.6)");
  const tete = avecReseau ? await verifierInstanceEnLigne(ctx, instance, client, { sansCapture }) : null;
  return { instance, client, sansCapture, tete, m: instance.manifeste };
}

// --- etat -------------------------------------------------------------------

async function cmdEtat(ctx) {
  const { instance, client, tete, m } = await preparer(ctx);
  const out = {
    evm_chain_id: m.evm_chain_id,
    bft_chain_id: m.bft_chain_id,
    genesis_sha256: m.genesis.sha256,
    manifest_sha256: instance.manifest_sha256,
    height: Number(tete.hauteur),
    block_hash: tete.hachage,
    validator_set_hash: C.jeuEnVigueur(m).valset_hash,
    contracts: adressesContrats(m),
  };
  if (ctx.options.organisation) {
    await ctx.op("OP-4", async () => {
      const v = String(ctx.options.organisation);
      let orgId = v;
      if (!/^0x[0-9a-f]{64}$/.test(v)) {
        const r = C.verifier("RG-1", () => C.orgIdDuSlug(v));
        if (r.status !== "reussi") throw new Arret("jeu_invalide", "OP-4", r.detail);
        orgId = r.valeurs;
      }
      const csr = out.contracts.curator_set_registry;
      const set = String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId])).toLowerCase();
      const org = { org_id: orgId, registered: set !== C.ADRESSE_NULLE, curator_set: set === C.ADRESSE_NULLE ? null : set, threshold: null, size: null, admin: null };
      if (org.registered) {
        org.threshold = Number(await client.vue(set, "CuratorSet", "getThreshold"));
        org.size = Number(await client.vue(set, "CuratorSet", "getCuratorCount"));
        org.admin = String(await client.vue(set, "CuratorSet", "admin")).toLowerCase();
      }
      out.organisation = org;
    });
  }
  return { result: "reussi", outputs: out };
}

// --- cles-essai -------------------------------------------------------------

async function cmdClesEssai(ctx) {
  const o = ctx.options;
  const instance = chargerInstance(o);
  if (!estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, "cles-essai n'est admis que sur le réseau de développement (EX-7.3)");
  const rep = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(rep) && fs.readdirSync(rep).length) throw new Arret("usage", null, `${rep} n'est pas vide`);
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const keyId = o["key-id"] ?? "rec-essai-01";
  const journal = o.journal ?? "journal-principal";
  const journalId = C.journalIdDuNom(journal);
  const nouvelle = () => "0x" + randomBytes(32).toString("hex");
  const cles = { "admin-jeu": nouvelle(), "approbateur-1": nouvelle(), "approbateur-2": nouvelle(), "approbateur-3": nouvelle(), [`cle-chaine-${keyId}`]: nouvelle() };
  const ecrire = (nom, contenu) => ecrireSynchronise(path.join(rep, nom), contenu, { mode: 0o600 });
  for (const [nom, k] of Object.entries(cles)) ecrire(`${nom}.cle`, k + "\n");
  const graine = nouvelle();
  ecrire(`${keyId}.graine`, graine + "\n");
  const pub = cleEd25519DepuisGraine(graine).clePublique;
  const chainKey = adresseCle(new SigningKey(cles[`cle-chaine-${keyId}`]));
  const cle = { key_id: keyId, journal_id: journalId, algorithm: "ed25519", public_key: pub, custody_class: "D", backend_type: "fichier", created_at: maintenant(), chain_key: chainKey, chain_key_class: "D", origin_proof: null };
  ecrire(`${keyId}.json`, texteJSON(cle));
  const publiques = {
    version: 0,
    description: "Clés d'essai du réseau de développement (CT-4 §7.5) : adresses et clé publique seulement, aucune valeur secrète.",
    journal: { name: journal, journal_id: journalId },
    set_admin: adresseCle(new SigningKey(cles["admin-jeu"])),
    approvers: [1, 2, 3].map((i) => adresseCle(new SigningKey(cles[`approbateur-${i}`]))),
    recorders: [{ key_id: keyId, file: `${keyId}.json`, public_key: pub, chain_key: chainKey }],
  };
  ecrire("cles-essai.json", texteJSON(publiques));
  return { result: "reussi", outputs: { directory: rep, files: fs.readdirSync(rep).sort(), set_admin: publiques.set_admin, approvers: publiques.approvers, chain_key: chainKey, public_key: pub } };
}

// --- inscrire-client --------------------------------------------------------

async function cmdInscrireClient(ctx) {
  return ctx.options.preparer ? inscrireClientPreparer(ctx) : inscrireClientDossier(ctx);
}

async function inscrireClientPreparer(ctx) {
  const o = ctx.options;
  const { instance, client, m } = await preparer(ctx);
  const sortieF = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(sortieF)) throw new Arret("usage", null, `${sortieF} existe déjà`);
  const slug = String(exigerOption(o, "org"));
  const journaux = String(exigerOption(o, "journal")).split(",").map((s) => s.trim()).filter(Boolean);
  const seuil = Number(exigerOption(o, "seuil"));
  let approbateurs;
  let setAdmin;
  let fichiersCles = o["cle-enregistreur"] ?? [];
  if (o["cles-essai"]) {
    if (!estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, "--cles-essai n'est admis que sur le réseau de développement");
    const ce = lireJSONFichier(o["cles-essai"]);
    approbateurs = o.approbateurs ? String(o.approbateurs).split(",") : ce.approvers;
    setAdmin = o["admin-jeu"] ?? ce.set_admin;
    if (!fichiersCles.length) fichiersCles = ce.recorders.map((r) => path.join(path.dirname(o["cles-essai"]), r.file));
  } else {
    approbateurs = String(exigerOption(o, "approbateurs")).split(",");
    setAdmin = exigerOption(o, "admin-jeu");
  }
  const recorders = fichiersCles.map((f) => {
    const c = lireJSONFichier(f);
    const e = conforme(c, C.ID_SCHEMA_INSCRIPTION, "#/$defs/cle_enregistreur");
    if (e.length) throw new Arret("entree_illisible", null, `${f} non conforme à cle_enregistreur : ${e[0].chemin} : ${e[0].message}`);
    return c;
  });
  const budget = o["budget-jour"] === undefined ? C.BUDGET_JOUR_DEFAUT : Number(o["budget-jour"]);
  if (!Number.isSafeInteger(budget) || budget <= 0) throw new Arret("usage", null, "--budget-jour : entier positif attendu");
  const comptes = comptesExploitant(o, instance, ["tresorerie"]);
  const tresorerie = adresseCle(comptes.tresorerie);
  let membres;
  try {
    membres = approbateurs.map((a) => C.adresseMinuscule(a.trim())).sort();
  } catch (err) {
    throw new Arret("jeu_invalide", "OP-4", err.message);
  }
  const orgId = (() => {
    const r = C.verifier("RG-1", () => C.orgIdDuSlug(slug, { production: m.nature === "production" }));
    if (r.status !== "reussi") throw new Arret("jeu_invalide", "OP-4", r.detail);
    return r.valeurs;
  })();
  const { provision_wei } = C.provision(m.fees, budget);
  const d = {
    version: 0,
    instance: { evm_chain_id: m.evm_chain_id, bft_chain_id: m.bft_chain_id, genesis_sha256: m.genesis.sha256, contracts: adressesContrats(m), manifest_sha256: instance.manifest_sha256, validator_set_hash: C.jeuEnVigueur(m).valset_hash },
    organisation: { slug, org_id: orgId },
    approvers: { members: membres, threshold: seuil, set_admin: String(setAdmin).toLowerCase() },
    journals: journaux.map((n) => {
      const r = C.verifier("RG-2", () => C.journalIdDuNom(n));
      if (r.status !== "reussi") throw new Arret("jeu_invalide", "OP-4", r.detail);
      return { name: n, journal_id: r.valeurs };
    }),
    recorders,
    funding: { funder: tresorerie, daily_budget_gas: budget, amount_wei: provision_wei.toString() },
    steps: [],
    result: null,
    prepared_by: String(o["prepare-par"] ?? "exploitant (noortrace-registre.mjs inscrire-client --preparer)").slice(0, 256),
    prepared_at: maintenant(),
    source: "dossier préparé par scripts/registre/noortrace-registre.mjs (CT-4 §7.5)",
  };
  const vide = (step, subject) => ({ step, subject, state: "a_faire", transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null, updated_at: null });
  d.steps.push(vide("jeu_approbateurs", slug), vide("assignation", slug), vide("lecture_jeu", slug));
  for (const r of recorders) d.steps.push(vide("approvisionnement", r.chain_key));
  for (const r of recorders) d.steps.push(vide("inscription", r.key_id));
  for (const j of d.journals) d.steps.push(vide("premiere_ancre", j.name), vide("premiere_cloture", j.name));
  await ctx.op("OP-4", async () => {
    if (!Number.isInteger(seuil) || seuil < 1 || seuil > membres.length) throw new Arret("jeu_invalide", "OP-4", `seuil ${seuil} hors de [1, ${membres.length}]`);
    const r = C.verifierDossierInscription(d, { schemas: schemas(), nature: m.nature, comptes: m.accounts.map((a) => a.address) });
    if (r.status !== "reussi") throw new Arret(r.code === "entree_illisible" ? "jeu_invalide" : r.code, "OP-4", r.detail);
    const deja = await client.vue(adressesContrats(m).curator_set_registry, "CuratorSetRegistry", "isRegistered", [orgId]);
    if (deja) throw new Arret("organisation_existante", "OP-4", `l'organisation ${slug} (${orgId}) a déjà un jeu : un slug n'est attribué qu'une fois (EX-6.3)`);
  });
  await ctx.op("OP-5", async () => {
    const t = C.compteDuRole(m, "tresorerie");
    if (!t || t.address !== tresorerie) throw new Arret("compte_inattendu", "OP-5", `trésorerie ${tresorerie} ≠ compte de rôle tresorerie ${t?.address}`);
    verifierRolesDistincts(m);
  });
  ecrireDossier(sortieF, d);
  return { result: "reussi", outputs: { org_id: orgId, journal_ids: d.journals.map((j) => j.journal_id), amount_wei: provision_wei.toString(), dossier: sortieF } };
}

function verifierRolesDistincts(m) {
  if (m.nature === "developpement") return;
  const actifs = m.accounts.filter((a) => a.to_height === null);
  const vus = new Map();
  for (const a of actifs) {
    if (vus.has(a.address) && vus.get(a.address) !== a.role) throw new Arret("compte_inattendu", "OP-5", `rôles ${vus.get(a.address)} et ${a.role} sous une même adresse hors du réseau de développement (EX-3.1)`);
    vus.set(a.address, a.role);
  }
}

async function inscrireClientDossier(ctx) {
  const o = ctx.options;
  const fDossier = path.resolve(exigerOption(o, "dossier"));
  const d = lireDossier(fDossier);
  const { instance, client, sansCapture, m } = await preparer(ctx);
  verifierDossierInstance(d, instance);
  const rep = capturesDe(o);
  const delai = delaiDe(o);
  const comptes = comptesExploitant(o, instance, ["deployeur", "administrateur_registre", "tresorerie"]);
  const csr = adressesContrats(m).curator_set_registry;
  const orgId = d.organisation.org_id;
  const etat = { deja: 0, faits: 0 };
  const ecrire = () => {
    completerResultat(d, sansCapture ? null : rep);
    ecrireDossier(fDossier, d);
  };
  const fait = (e) => e.state === "capturee" || e.state === "faite" || (sansCapture && e.state === "incluse");
  // EX-7.16 : une étape envoyee ou incluse se reprend par la capture de sa transaction, jamais par un renvoi.
  const reprise = async (e, { role, contrat, logIndex }) => {
    if (e.state === "envoyee" || e.state === "incluse") {
      await reprendreEtape(ctx, e, { instance, client, repertoire: rep, sansCapture, role, contrat, logIndex, ecrire });
      etat.deja++;
      return true;
    }
    return false;
  };
  await ctx.op("OP-5", async () => {
    for (const [role, k] of Object.entries(comptes)) {
      const a = C.compteDuRole(m, role);
      if (!a || a.address !== adresseCle(k)) throw new Arret("compte_inattendu", "OP-5", `${role} ${adresseCle(k)} ≠ compte de rôle ${a?.address}`);
    }
    verifierRolesDistincts(m);
    const admin = String(await client.vue(csr, "CuratorSetRegistry", "admin")).toLowerCase();
    if (admin !== adresseCle(comptes.administrateur_registre)) throw new Arret("pas_administrateur", "OP-5", `CuratorSetRegistry.admin() = ${admin}, pas l'administrateur du registre ${adresseCle(comptes.administrateur_registre)}`);
  });
  // 1. jeu_approbateurs
  const eJeu = etape(d, "jeu_approbateurs", d.organisation.slug);
  const art = artefact("CuratorSet");
  const args = C.argumentsConstructeur("CuratorSet", { initial_admin: d.approvers.set_admin, members: d.approvers.members, threshold: d.approvers.threshold });
  const data = art.bytecode + args.slice(2);
  const dep = comptes.deployeur;
  let setAdresse = null;
  if (await reprise(eJeu, { role: "jeu_approbateurs", contrat: eJeu.contract ?? null, logIndex: null })) setAdresse = eJeu.contract;
  if (fait(eJeu)) {
    if (setAdresse === null) etat.deja++;
    setAdresse = eJeu.contract ?? curatorSetDuDossier(d, rep) ?? (sansCapture ? String((await client.appel("eth_getTransactionReceipt", [eJeu.transaction_hash])).contractAddress).toLowerCase() : null);
    if (!setAdresse) throw new Arret("entree_illisible", null, `étape jeu_approbateurs faite mais adresse du jeu introuvable : ni contract dans le dossier ni index ${eJeu.capture} dans ${rep} (EX-7.16)`);
  } else {
    await ctx.op("OP-4", async () => {
      const r = C.verifierDossierInscription(d, { schemas: schemas(), nature: m.nature, comptes: m.accounts.map((a) => a.address) });
      if (r.status !== "reussi") throw new Arret(r.code === "entree_illisible" ? "jeu_invalide" : r.code, "OP-4", r.detail);
      if (await client.vue(csr, "CuratorSetRegistry", "isRegistered", [orgId])) {
        // EX-7.16 : un jeu déjà assigné n'est adopté que s'il est celui du dossier et qu'il sort d'un envoi de ce déployeur.
        const set = String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId])).toLowerCase();
        const conforme = async () => {
          try {
            if (String(await client.vue(set, "CuratorSet", "admin")).toLowerCase() !== d.approvers.set_admin) return false;
            if (Number(await client.vue(set, "CuratorSet", "getThreshold")) !== d.approvers.threshold) return false;
            if (Number(await client.vue(set, "CuratorSet", "getCuratorCount")) !== d.approvers.members.length) return false;
            for (const a of d.approvers.members) if (!(await client.vue(set, "CuratorSet", "isCurator", [a]))) return false;
            return true;
          } catch {
            return false;
          }
        };
        const envoi = envoisCorrespondants(rep, { from: adresseCle(dep), to: null, data }).find((e) => C.adresseCreation(e.from, e.nonce) === set);
        if (!envoi || !(await conforme())) throw new Arret("organisation_existante", "OP-4", `l'organisation ${d.organisation.slug} a déjà un jeu (${set}) qui n'est pas celui que ce dossier a déployé (EX-6.3)`);
        majEtape(eJeu, { state: "envoyee", transaction_hash: envoi.transaction_hash, contract: set });
        ecrire();
      }
    });
    if (eJeu.state === "envoyee") {
      await reprendreEtape(ctx, eJeu, { instance, client, repertoire: rep, sansCapture, role: "jeu_approbateurs", contrat: eJeu.contract, logIndex: null, ecrire });
      setAdresse = eJeu.contract;
      etat.deja++;
    }
  }
  if (setAdresse === null) {
    await verifierExpediteur(ctx, { client, instance, from: adresseCle(dep), repertoire: rep });
    const nonce = BigInt(await client.appel("eth_getTransactionCount", [adresseCle(dep), "latest"]));
    const attendue = C.adresseCreation(adresseCle(dep), nonce);
    const r = await envoyer(ctx, {
      instance,
      client,
      cle: dep,
      repertoire: rep,
      sansCapture,
      delai,
      nonceImpose: nonce,
      appel: {
        objet: "deploiement",
        to: null,
        data,
        role: "jeu_approbateurs",
        contrat: attendue,
        logIndex: null,
        ...suiviEtape(eJeu, ecrire, { contrat: attendue }),
        evenement: async (recu) => {
          exigerOP11(String(recu.contractAddress).toLowerCase() === attendue, `contrat créé ${recu.contractAddress} au lieu de CREATE(déployeur, ${nonce}) = ${attendue}`);
          const ev = journaux(recu, attendue, "CuratorSet");
          exigerOP11(ev.some((e) => e.name === "AdminAccepted" && BigInt(e.args[0]) === 0n && e.args[1].toLowerCase() === d.approvers.set_admin), "AdminAccepted(0, administrateur du jeu) absent");
          const ajoutes = ev.filter((e) => e.name === "CuratorAdded").map((e) => e.args[0].toLowerCase()).sort();
          exigerOP11(egalJSON(ajoutes, d.approvers.members), `CuratorAdded ${JSON.stringify(ajoutes)} au lieu des membres du dossier`);
          exigerOP11(ev.some((e) => e.name === "ThresholdUpdated" && Number(e.args[0]) === d.approvers.threshold), "ThresholdUpdated(seuil) absent");
        },
        relecture: async (bloc) => {
          exigerOP12(Number(await client.vue(attendue, "CuratorSet", "getThreshold", [], bloc)) === d.approvers.threshold, "getThreshold relu différent");
          exigerOP12(Number(await client.vue(attendue, "CuratorSet", "getCuratorCount", [], bloc)) === d.approvers.members.length, "getCuratorCount relu différent");
          for (const a of d.approvers.members) exigerOP12(await client.vue(attendue, "CuratorSet", "isCurator", [a], bloc), `isCurator(${a}) relu faux`);
          exigerOP12(String(await client.vue(attendue, "CuratorSet", "admin", [], bloc)).toLowerCase() === d.approvers.set_admin, "admin relu différent de la clé de gouvernance");
        },
      },
    });
    majEtape(eJeu, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture, contract: attendue });
    setAdresse = attendue;
    etat.faits++;
    ecrire();
  }
  // 2. assignation
  const eAss = etape(d, "assignation", d.organisation.slug);
  const dataAss = C.donneesAppel("setCuratorSet", { org_id: orgId, curator_set: setAdresse });
  const adm = comptes.administrateur_registre;
  const repriseAss = await reprise(eAss, { role: "assignation", contrat: csr, logIndex: 0 });
  if (fait(eAss)) {
    if (!repriseAss) etat.deja++;
  } else {
    // 7.6, pas 2 : lecture de curatorSetOf avant tout envoi (setCuratorSet n'a pas de garde contre le même jeu).
    const courant = String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId])).toLowerCase();
    if (courant === setAdresse) {
      let envoi = envoisCorrespondants(rep, { from: adresseCle(adm), to: csr, data: dataAss })[0] ?? null;
      if (!envoi) {
        // Envoi absent du répertoire : la transaction est retrouvée par eth_getLogs de CuratorSetAssigned (EX-5.11, tranches de 16 384 blocs).
        const tete = BigInt(await client.appel("eth_blockNumber", []));
        const depuis = eJeu.block_number ? BigInt(eJeu.block_number) : tete > 16383n ? tete - 16383n : 0n;
        const journauxAss = await client.appel("eth_getLogs", [{ fromBlock: C.quantiteRPC(depuis), toBlock: "latest", address: csr, topics: [C.EVENEMENTS.CuratorSetAssigned.topic, orgId] }]);
        const j = (journauxAss ?? []).find((x) => "0x" + x.topics[2].slice(26).toLowerCase() === setAdresse);
        if (j) envoi = { transaction_hash: String(j.transactionHash).toLowerCase() };
      }
      if (!envoi) throw new Arret("organisation_existante", "OP-4", `curatorSetOf(${orgId}) vaut déjà ${setAdresse} sans envoi ni journal retrouvé : reprise impossible`);
      majEtape(eAss, { state: "envoyee", transaction_hash: envoi.transaction_hash });
      ecrire();
      await reprendreEtape(ctx, eAss, { instance, client, repertoire: rep, sansCapture, role: "assignation", contrat: csr, logIndex: 0, ecrire });
      etat.deja++;
    } else if (courant !== C.ADRESSE_NULLE) {
      throw new Arret("organisation_existante", "OP-4", `l'organisation ${d.organisation.slug} a déjà le jeu ${courant}, qui n'est pas celui du dossier (${setAdresse}) : un changement de jeu suit 8.5`);
    } else {
      await verifierExpediteur(ctx, { client, instance, from: adresseCle(adm), repertoire: rep });
      const r = await envoyer(ctx, {
        instance,
        client,
        cle: adm,
        repertoire: rep,
        sansCapture,
        delai,
        appel: {
          objet: "appel",
          to: csr,
          data: dataAss,
          role: "assignation",
          contrat: csr,
          logIndex: 0,
          ...suiviEtape(eAss, ecrire),
          evenement: async (recu) => {
            const ev = journaux(recu, csr, "CuratorSetRegistry").filter((e) => e.name === "CuratorSetAssigned");
            exigerOP11(ev.length === 1 && ev[0].args[0] === orgId && ev[0].args[1].toLowerCase() === setAdresse && ev[0].args[2].toLowerCase() === C.ADRESSE_NULLE, "CuratorSetAssigned(orgId, jeu, 0x0…0) absent ou différent");
          },
          relecture: async (bloc) => exigerOP12(String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId], bloc)).toLowerCase() === setAdresse, "curatorSetOf relu différent"),
        },
      });
      majEtape(eAss, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
      etat.faits++;
      ecrire();
    }
  }
  // 3. lecture_jeu (CT-3 EX-8.1)
  const eLec = etape(d, "lecture_jeu", d.organisation.slug);
  let setRead = null;
  if (fait(eLec)) {
    etat.deja++;
    setRead = { height: eLec.block_number, block_hash: eLec.block_hash, threshold: d.approvers.threshold, size: d.approvers.members.length, members: d.approvers.members };
  } else {
    const source = { requete: (methode, params) => client.appel(methode, params) };
    const lu = await lireJeu(source, { approver_set: { source: "registre", chain_id: m.evm_chain_id, registry: csr, set: setAdresse }, org_id: orgId, adresses: d.approvers.members, depuis: Math.max(0, (eJeu.block_number ?? 1) - 1) });
    if (lu.status !== "lu") throw new Arret("jeu_invalide", "OP-12", `lecture du jeu (CT-3 EX-8.1) illisible : ${lu.cause}`);
    if (lu.jeu.threshold.required !== d.approvers.threshold || !egalJSON(lu.jeu.members, d.approvers.members)) throw new Arret("jeu_invalide", "OP-12", "jeu lu différent du dossier");
    if (eAss.block_number !== null && lu.jeu.height < eAss.block_number) throw new Arret("jeu_invalide", "OP-12", "lecture à une hauteur antérieure à l'assignation");
    majEtape(eLec, { state: "faite", block_number: lu.jeu.height, block_hash: lu.jeu.block_hash });
    setRead = { height: lu.jeu.height, block_hash: lu.jeu.block_hash, threshold: lu.jeu.threshold.required, size: lu.jeu.threshold.size, members: lu.jeu.members };
    etat.faits++;
    ecrire();
  }
  // 4. approvisionnement de chaque clé de chaîne
  const funded = [];
  const P = BigInt(d.funding.amount_wei);
  for (const rec of d.recorders) {
    const e = etape(d, "approvisionnement", rec.chain_key);
    const repriseE = await reprise(e, { role: "approvisionnement", contrat: null, logIndex: null });
    if (fait(e)) {
      if (!repriseE) etat.deja++;
      funded.push({ chain_key: rec.chain_key, transaction_hash: e.transaction_hash, deja_fait: true });
      continue;
    }
    const solde = BigInt(await client.appel("eth_getBalance", [rec.chain_key, "latest"]));
    if (solde >= P) {
      majEtape(e, { state: "faite" });
      etat.deja++;
      funded.push({ chain_key: rec.chain_key, transaction_hash: null, deja_fait: true });
      ecrire();
      continue;
    }
    const valeur = P - solde;
    const tre = comptes.tresorerie;
    await verifierExpediteur(ctx, { client, instance, from: adresseCle(tre), value: valeur, repertoire: rep, destinataire: rec.chain_key, provisionDestinataire: P });
    const r = await envoyer(ctx, {
      instance,
      client,
      cle: tre,
      repertoire: rep,
      sansCapture,
      delai,
      appel: {
        objet: "approvisionnement",
        to: rec.chain_key,
        data: "0x",
        value: valeur,
        provision: P,
        role: "approvisionnement",
        contrat: null,
        logIndex: null,
        ...suiviEtape(e, ecrire),
        evenement: async (recu) => exigerOP11(recu.logs.length === 0, "un virement n'émet aucun journal"),
        relecture: async (bloc) => exigerOP12(BigInt(await client.appel("eth_getBalance", [rec.chain_key, bloc])) >= P, "solde relu sous la provision"),
      },
    });
    majEtape(e, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
    funded.push({ chain_key: rec.chain_key, transaction_hash: r.transaction_hash, amount_wei: valeur.toString() });
    etat.faits++;
    ecrire();
  }
  const ref = (s) => ({ transaction_hash: s.transaction_hash, block_number: s.block_number, block_hash: s.block_hash, capture: s.capture });
  if (etat.faits === 0 && etat.deja === 0) throw new Arret("transaction_en_attente", "OP-3", "aucune étape faite ni reprise");
  return {
    result: etat.faits === 0 ? "deja_fait" : "reussi",
    outputs: { curator_set: setAdresse, set_deployment: ref(eJeu), assignment: ref(eAss), set_read: setRead, funded },
  };
}

// --- approvisionner ---------------------------------------------------------

async function cmdApprovisionner(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const vers = C.adresseMinuscule(exigerOption(o, "vers"));
  const c = adressesContrats(m);
  const fDossier = o.dossier ? path.resolve(o.dossier) : null;
  const d = fDossier ? lireDossier(fDossier) : null;
  if (d) verifierDossierInstance(d, instance);
  let demande = null;
  if (o.demande) {
    demande = lireJSONFichier(o.demande);
    const e = conforme(demande, C.ID_SCHEMA_OPERATIONS, "#/$defs/demande_signature");
    if (e.length) throw new Arret("entree_illisible", null, `--demande non conforme : ${e[0].chemin} : ${e[0].message}`);
  }
  // 8.7 : --budget-jour est un entier positif, par défaut celui du dossier ou d'un journal horaire.
  let budget;
  if (o["budget-jour"] !== undefined) {
    if (!/^[1-9][0-9]{0,15}$/.test(String(o["budget-jour"]))) throw new Arret("usage", null, "--budget-jour : entier positif, en gaz (8.7)");
    budget = Number(o["budget-jour"]);
  } else budget = d?.funding.daily_budget_gas ?? C.BUDGET_JOUR_DEFAUT;
  const tre = comptesExploitant(o, instance, ["tresorerie"]).tresorerie;
  // OP-5 : trésorerie de son rôle ; destinataire admis par EX-8.20.
  let admission = null;
  await ctx.op("OP-5", async () => {
    const t = C.compteDuRole(m, "tresorerie");
    if (!t || t.address !== adresseCle(tre)) throw new Arret("compte_inattendu", "OP-5", `trésorerie ${adresseCle(tre)} ≠ compte de rôle ${t?.address}`);
    if (d && d.recorders.some((r) => r.chain_key === vers)) admission = "dossier";
    else if (demande && demande.operation === "inscription" && demande.evm_chain_id === m.evm_chain_id && demande.contract === c.recorder_registry && demande.fields?.chain_key === vers) admission = "demande";
    else if (o["org-id"] !== undefined && (await client.vue(c.recorder_registry, "RecorderRegistry", "isActiveRecorder", [String(o["org-id"]).toLowerCase(), vers]))) admission = "cle_active";
    else {
      const compte = m.accounts.find((a) => a.address === vers && a.to_height === null);
      if (compte) admission = `compte:${compte.role}`;
    }
    if (!admission) throw new Arret("compte_inattendu", "OP-5", `destinataire ${vers} hors d'EX-8.20 : ni clé de chaîne d'un dossier (--dossier), ni d'une demande d'inscription (--demande), ni clé active (--org-id), ni compte du manifeste`);
  });
  // OP-3 : le budget retenu ne dépasse pas fees.max_daily_budget_gas quand le manifeste le fixe (EX-8.20).
  const plafond = m.fees.max_daily_budget_gas ?? null;
  await ctx.op("OP-3", async () => {
    if (plafond !== null && budget > plafond) throw new Arret("provision_excessive", "OP-3", `budget journalier ${budget} gaz au-delà du plafond fees.max_daily_budget_gas ${plafond} du manifeste (EX-8.20)`);
  });
  const { provision_wei: P, refill_below_wei: seuil } = C.provision(m.fees, budget);
  const avant = BigInt(await client.appel("eth_getBalance", [vers, "latest"]));
  const out = { to: vers, admitted_as: admission, balance_before_wei: avant.toString(), provision_wei: P.toString(), refill_below_wei: seuil.toString(), daily_budget_gas: budget, consumption_since_last_funding_wei: null, elapsed_seconds: null, review: o["apres-examen"] ?? null };
  // Étape approvisionnement du dossier (EX-7.16) : une étape envoyee ou incluse se reprend par la capture de sa transaction.
  const e = d ? etape(d, "approvisionnement", vers) : null;
  const ecrire = () => {
    completerResultat(d, sansCapture ? null : rep);
    ecrireDossier(fDossier, d);
  };
  if (e && (e.state === "envoyee" || e.state === "incluse")) {
    await reprendreEtape(ctx, e, { instance, client, repertoire: rep, sansCapture, role: "approvisionnement", contrat: null, logIndex: null, ecrire });
    const apres = BigInt(await client.appel("eth_getBalance", [vers, "latest"]));
    return { result: "deja_fait", outputs: { ...out, balance_after_wei: apres.toString(), transaction_hash: e.transaction_hash, block_number: e.block_number, capture: e.capture } };
  }
  const suivi = e && e.state === "a_faire";
  // EX-8.18 : consommation depuis le dernier approvisionnement capturé.
  const derniers = fs
    .readdirSync(rep)
    .filter((f) => /^capture-\d+-\d+-approvisionnement\.json$/.test(f))
    .map((f) => JSON.parse(fs.readFileSync(path.join(rep, f), "utf8")))
    .filter((i) => i.sending?.to === vers)
    .sort((a, b) => b.block_number - a.block_number);
  if (derniers.length) {
    const dernier = derniers[0];
    const bloc = JSON.parse(fs.readFileSync(path.join(rep, dernier.files.block.name), "utf8")).result;
    const tete = await client.appel("eth_getBlockByNumber", ["latest", false]);
    const ecoule = Number(BigInt(tete.timestamp) - BigInt(bloc.timestamp));
    const conso = P - avant;
    out.consumption_since_last_funding_wei = conso > 0n ? conso.toString() : "0";
    out.elapsed_seconds = ecoule;
    out.twice_budget_wei = ((2n * BigInt(budget) * BigInt(Math.max(ecoule, 1))) / 86400n).toString();
  }
  // Au-dessus du seuil de recomplément, rien à verser (8.7) ; en dessous, le
  // recomplément d'un expéditeur qui a consommé plus de deux fois son budget
  // depuis le dernier approvisionnement attend l'examen (EX-4.20, EX-8.18).
  if (avant >= seuil) {
    if (suivi) {
      majEtape(e, { state: "faite" });
      ecrire();
    }
    return { result: "deja_fait", outputs: { ...out, balance_after_wei: avant.toString() } };
  }
  if (out.twice_budget_wei !== undefined && BigInt(out.consumption_since_last_funding_wei) > BigInt(out.twice_budget_wei) && !o["apres-examen"]) {
    throw new Arret("examen_requis", null, `consommation ${out.consumption_since_last_funding_wei} wei depuis le dernier approvisionnement (${out.elapsed_seconds} s) au-delà de deux fois le budget de la même durée (${out.twice_budget_wei} wei) : examen par l'exploitant, puis --apres-examen <motif> (EX-8.18)`, { outputs: out });
  }
  const valeur = P - avant;
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(tre), value: valeur, repertoire: rep, destinataire: vers, provisionDestinataire: P });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: tre,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "approvisionnement",
      to: vers,
      data: "0x",
      value: valeur,
      provision: P,
      role: "approvisionnement",
      contrat: null,
      logIndex: null,
      ...(suivi ? suiviEtape(e, ecrire) : {}),
      evenement: async (recu) => exigerOP11(recu.logs.length === 0, "un virement n'émet aucun journal"),
      relecture: async (bloc) => exigerOP12(BigInt(await client.appel("eth_getBalance", [vers, bloc])) >= P, "solde relu sous la provision"),
    },
  });
  if (suivi) {
    majEtape(e, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
    ecrire();
  }
  const apres = BigInt(await client.appel("eth_getBalance", [vers, "latest"]));
  return { result: "reussi", outputs: { ...out, balance_after_wei: apres.toString(), amount_wei: valeur.toString(), transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture } };
}

// --- condense ---------------------------------------------------------------

async function cmdCondense(ctx, positionnels) {
  const o = ctx.options;
  const operation = positionnels[0];
  if (!["inscription", "revocation", "cloture", "ancre", "administration_jeu"].includes(operation)) throw new Arret("usage", null, "condense <inscription | revocation | cloture | ancre | administration_jeu>");
  const sortieF = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(sortieF) && !o.force) throw new Arret("usage", null, `${sortieF} existe déjà`);
  const { client, m, tete, sansCapture } = await preparer(ctx);
  const c = adressesContrats(m);
  let fields;
  let contract;
  let vue;
  let orgId = null;
  let expiresAt = null;
  switch (operation) {
    case "inscription": {
      if (o.dossier) {
        const d = lireDossier(o.dossier);
        const keyId = exigerOption(o, "key-id");
        const r = d.recorders.find((x) => x.key_id === keyId);
        if (!r) throw new Arret("usage", null, `clé ${keyId} absente du dossier`);
        fields = { org_id: d.organisation.org_id, journal_id: r.journal_id, chain_key: r.chain_key, ed25519_public_key: r.public_key };
      } else fields = { org_id: String(exigerOption(o, "org-id")).toLowerCase(), journal_id: String(exigerOption(o, "journal-id")).toLowerCase(), chain_key: C.adresseMinuscule(exigerOption(o, "cle-chaine-adresse")), ed25519_public_key: String(exigerOption(o, "cle-ed25519")).toLowerCase() };
      contract = c.recorder_registry;
      orgId = fields.org_id;
      vue = () => client.vue(contract, "RecorderRegistry", "registerDigest", [fields.org_id, fields.journal_id, fields.chain_key, fields.ed25519_public_key]);
      break;
    }
    case "revocation": {
      orgId = String(exigerOption(o, "org-id")).toLowerCase();
      const ck = C.adresseMinuscule(exigerOption(o, "cle-chaine-adresse"));
      contract = c.recorder_registry;
      const rec = await client.vue(contract, "RecorderRegistry", "recorderOf", [orgId, ck]);
      await ctx.op("OP-8", async () => {
        if (rec.registeredAt === 0n) throw new Arret("cle_inconnue", "OP-8", `clé de chaîne ${ck} jamais inscrite chez ${orgId}`);
        if (rec.revokedAt !== 0n) throw new Arret("cle_revoquee", "OP-8", `clé de chaîne ${ck} déjà révoquée`);
      });
      fields = { org_id: orgId, chain_key: ck, registered_at: rec.registeredAt.toString() };
      vue = () => client.vue(contract, "RecorderRegistry", "revokeDigest", [orgId, ck]);
      break;
    }
    case "cloture": {
      const man = lireJSONFichier(exigerOption(o, "manifeste"));
      const meta = C.metaDuManifeste(man, o.uri === undefined || o.uri === true ? "" : String(o.uri));
      const rep = capturesDe(o);
      if (o.expiration !== undefined && !/^[1-9][0-9]{0,8}$/.test(String(o.expiration))) throw new Arret("usage", null, "--expiration : entier positif, en secondes (EX-8.19)");
      const duree = o.expiration === undefined ? 86400 : Number(o.expiration);
      expiresAt = new Date(Math.floor(Date.now() / 1000) * 1000 + duree * 1000).toISOString();
      contract = c.period_registry;
      orgId = meta.org_id;
      await ctx.op("OP-10", async () => {
        const precedente = await periodePrecedente(client, contract, meta.org_id, meta.journal_id);
        const r = C.verifier("RG-5", () => C.verifierChampsCloture(meta, { precedente }));
        if (r.status !== "reussi") throw new Arret(r.code, "OP-10", r.detail);
        // EX-8.4 : l'ancre de la période est incluse (émise par une clé de chaîne active) et capturée dans --captures.
        const empreinte = C.empreinteAncre({ org_id: meta.org_id, journal_id: meta.journal_id, period_hash: meta.period_hash }).fingerprint;
        const l = await client.vue(c.attestation_registry, "AttestationRegistry", "lookup", [empreinte]);
        const emetteur = String(l.issuer).toLowerCase();
        if (emetteur === C.ADRESSE_NULLE) throw new Arret("ancre_manquante", "OP-10", `ancre de la période ${empreinte} absente : ancrer d'abord, puis capturer (EX-8.4)`);
        if (!(await client.vue(c.recorder_registry, "RecorderRegistry", "isActiveRecorder", [meta.org_id, emetteur]))) throw new Arret("ancre_manquante", "OP-10", `ancre ${empreinte} émise par ${emetteur}, qui n'est pas une clé de chaîne active de ${meta.org_id} (EX-8.4)`);
        const capturee = lireIndexCaptures(rep).some(({ index }) => index.role === "ancre" && index.contract === c.attestation_registry && recuDeIndex(rep, index).logs.some((j) => String(j.address).toLowerCase() === c.attestation_registry && j.topics[0] === C.EVENEMENTS.Anchored.topic && String(j.topics[1]).toLowerCase() === empreinte));
        // Sur le réseau Hardhat (--sans-capture, EX-A.6), l'ancre incluse suffit : aucune capture n'y est faite.
        if (!capturee && !sansCapture) throw new Arret("ancre_manquante", "OP-10", `ancre ${empreinte} incluse mais sans index de capture dans ${rep} : capturer --transaction --role ancre d'abord (EX-8.4)`);
        // EX-8.19 : une seule demande de clôture par position (org_id, journal_id, first_seq).
        for (const f of fs.readdirSync(rep).filter((x) => /^demande-cloture-0x[0-9a-f]{64}\.json$/.test(x)).sort()) {
          let relayee;
          try {
            relayee = JSON.parse(fs.readFileSync(path.join(rep, f), "utf8"));
          } catch {
            continue;
          }
          const pm = relayee?.fields?.period_meta;
          if (pm && pm.org_id === meta.org_id && pm.journal_id === meta.journal_id && String(pm.first_seq) === String(meta.first_seq) && pm.period_hash !== meta.period_hash) {
            throw new Arret("demande_existante", "OP-10", `une demande de clôture du periodHash ${pm.period_hash} a déjà été relayée pour la position (${meta.org_id}, ${meta.journal_id}, ${meta.first_seq}) : ${f} ; le manifeste relayé est celui du dossier (EX-8.19)`);
          }
        }
      });
      fields = { period_meta: meta };
      vue = () => client.vue(contract, "PeriodRegistry", "periodDigest", [tupleEthers(meta)]);
      break;
    }
    case "ancre": {
      const man = lireJSONFichier(exigerOption(o, "manifeste"));
      const e = C.empreinteAncre({ org_id: man.org_id, journal_id: man.journal_id, period_hash: hachageManifeste(man) });
      fields = { fingerprint: e.fingerprint, doc_type: C.DOC_TYPE_PERIODE, issuer: C.adresseMinuscule(exigerOption(o, "emetteur")) };
      contract = c.attestation_registry;
      vue = () => client.vue(contract, "AttestationRegistry", "anchorDigest", [fields.fingerprint, fields.doc_type]);
      break;
    }
    case "administration_jeu": {
      contract = C.adresseMinuscule(exigerOption(o, "jeu"));
      const op = String(exigerOption(o, "op"));
      if (!C.OPERATIONS_JEU[op]) throw new Arret("usage", null, `--op : ${Object.keys(C.OPERATIONS_JEU).join(", ")}`);
      const arg = C.argumentOperationJeu(op, o.arg);
      const nonce = (await client.vue(contract, "CuratorSet", "opNonce")).toString();
      fields = { op, arg, nonce };
      vue = () => client.vue(contract, "CuratorSet", "adminOpDigest", [C.keccakTexte(op), arg, nonce]);
      break;
    }
  }
  const demande = { version: 0, operation, evm_chain_id: m.evm_chain_id, contract, fields, digest: null, eip191_digest: null, signer_set: null, signatures: [], prepared_at: maintenant(), ...(expiresAt ? { expires_at: expiresAt } : {}) };
  await ctx.op("OP-6", async () => {
    let calc;
    try {
      calc = C.condenseDeDemande(demande);
    } catch (err) {
      throw new Arret("condense_different", "OP-6", err.message);
    }
    const duContrat = String(await vue()).toLowerCase();
    if (duContrat !== calc.digest) throw new Arret("condense_different", "OP-6", `condensé du contrat ${duContrat} ≠ condensé recalculé ${calc.digest} (EX-6.1)`);
    demande.digest = calc.digest;
    demande.eip191_digest = calc.eip191_digest;
  });
  if (["inscription", "revocation", "cloture"].includes(operation)) {
    const set = String(await client.vue(c.curator_set_registry, "CuratorSetRegistry", "curatorSetOf", [orgId], C.quantiteRPC(tete.hauteur))).toLowerCase();
    if (set === C.ADRESSE_NULLE) throw new Arret("organisation_inconnue", "OP-8", `organisation ${orgId} sans jeu`);
    const t = Number(await client.vue(set, "CuratorSet", "getThreshold", [], C.quantiteRPC(tete.hauteur)));
    demande.signer_set = { curator_set: set, threshold: t, height: Number(tete.hauteur), block_hash: tete.hachage };
  }
  const e = conforme(demande, C.ID_SCHEMA_OPERATIONS, "#/$defs/demande_signature");
  if (e.length) throw new Error(`demande produite non conforme : ${e[0].chemin} : ${e[0].message}`);
  remplacerFichier(sortieF, texteJSON(demande));
  return { result: "reussi", outputs: { operation, digest: demande.digest, eip191_digest: demande.eip191_digest, signer_set: demande.signer_set, expires_at: expiresAt, demande: sortieF } };
}

function tupleEthers(meta) {
  return [meta.org_id, meta.journal_id, meta.period_hash, meta.root, BigInt(meta.period_start), BigInt(meta.period_end), BigInt(meta.first_seq), BigInt(meta.last_seq), meta.version, meta.uri];
}

async function periodePrecedente(client, periodRegistry, orgId, journalId, bloc = "latest") {
  const id = await client.vue(periodRegistry, "PeriodRegistry", "latestPeriodOf", [orgId, journalId], bloc);
  if (id === 0n) return null;
  const p = await client.vue(periodRegistry, "PeriodRegistry", "getPeriod", [id], bloc);
  return { id: id.toString(), period_hash: p.periodHash.toLowerCase(), period_end: p.periodEnd.toString(), last_seq: p.lastSeq.toString() };
}

// --- signer -----------------------------------------------------------------

async function cmdSigner(ctx) {
  const o = ctx.options;
  const fDemande = path.resolve(exigerOption(o, "demande"));
  const demande = lireJSONFichier(fDemande);
  const e = conforme(demande, C.ID_SCHEMA_OPERATIONS, "#/$defs/demande_signature");
  if (e.length) throw new Arret("entree_illisible", "OP-6", `demande non conforme : ${e[0].chemin} : ${e[0].message}`);
  const ref = exigerOption(o, "cle");
  if (/^hardhat:/.test(ref) && ![C.RESEAU_DEVELOPPEMENT.evm_chain_id, C.RESEAU_ESSAI.evm_chain_id].includes(demande.evm_chain_id)) throw new Arret("reseau_non_developpement", null, "hardhat: n'est admis que pour une demande du réseau de développement (EX-7.3)");
  const cle = cleSecp(ref, null, { nom: "--cle" });
  // EX-8.19 : une demande dont expires_at est passé n'est pas signée.
  if (demande.expires_at && Date.parse(demande.expires_at) <= Date.now()) throw new Arret("demande_expiree", null, `demande expirée depuis ${demande.expires_at} : refaire la demande par condense (EX-8.19)`);
  await ctx.op("OP-6", async () => {
    let calc;
    try {
      calc = C.condenseDeDemande(demande);
    } catch (err) {
      throw new Arret("condense_different", "OP-6", err.message);
    }
    if (calc.digest !== demande.digest || calc.eip191_digest !== demande.eip191_digest) throw new Arret("condense_different", "OP-6", `condensé recalculé ${calc.digest} ≠ digest de la demande ${demande.digest} : ne pas signer (EX-7.10)`);
  });
  // EX-7.10 : les champs en clair sont écrits sur la sortie d'erreur avant de signer (l'outil ne remplace pas un portefeuille, EX-7.3).
  ctx.log(`demande ${demande.operation} pour ${demande.contract} (identifiant EVM ${demande.evm_chain_id}) : fields ${JSON.stringify(demande.fields)} ; signer_set ${JSON.stringify(demande.signer_set)} ; expires_at ${demande.expires_at ?? "absent"} ; condensé ${demande.digest}`);
  const sig = C.signerCondense(cle.privateKey, demande.digest);
  let nouvelle;
  await ctx.op("OP-7", async () => {
    if (demande.operation === "ancre" && sig.signer !== demande.fields.issuer) throw new Arret("signataire_hors_jeu", "OP-7", `la clé ${sig.signer} n'est pas l'émetteur ${demande.fields.issuer}`);
    if (["ancre", "administration_jeu"].includes(demande.operation) && demande.signatures.length) throw new Arret("signature_non_canonique", "OP-7", "la demande porte déjà sa signature");
    const r = C.verifier("RG-12", () => C.verifierSignature({ digest: demande.digest, signature: sig }));
    if (r.status !== "reussi") throw new Arret("signature_non_canonique", "OP-7", r.detail);
    try {
      nouvelle = C.insererSignature(demande, sig);
    } catch (err) {
      throw new Arret("signature_non_canonique", "OP-7", err.message);
    }
  });
  remplacerFichier(fDemande, texteJSON(nouvelle));
  const seuil = demande.signer_set?.threshold ?? 1;
  return { result: "reussi", outputs: { signer: sig.signer, signatures: nouvelle.signatures.length, threshold: seuil, complete: nouvelle.signatures.length >= seuil, demande: fDemande } };
}

// --- vérifications de demande en ligne (OP-6, OP-7) ---------------------------

async function verifierDemandeEnLigne(ctx, { client, demande, m, attendus }) {
  await ctx.op("OP-6", async () => {
    const e = conforme(demande, C.ID_SCHEMA_OPERATIONS, "#/$defs/demande_signature");
    if (e.length) throw new Arret("entree_illisible", "OP-6", `demande non conforme : ${e[0].chemin} : ${e[0].message}`);
    if (demande.evm_chain_id !== m.evm_chain_id) throw new Arret("condense_different", "OP-6", `demande de l'identifiant EVM ${demande.evm_chain_id}`);
    if (demande.operation !== attendus.operation) throw new Arret("condense_different", "OP-6", `demande ${demande.operation} au lieu de ${attendus.operation}`);
    if (demande.contract !== attendus.contract) throw new Arret("condense_different", "OP-6", `demande pour le contrat ${demande.contract} au lieu de ${attendus.contract}`);
    let calc;
    try {
      calc = C.condenseDeDemande(demande);
    } catch (err) {
      throw new Arret("condense_different", "OP-6", `condensé non recalculable : ${err.message}`);
    }
    if (calc.digest !== demande.digest || calc.eip191_digest !== demande.eip191_digest) throw new Arret("condense_different", "OP-6", `condensé recalculé ${calc.digest} ≠ ${demande.digest}`);
    const duContrat = String(await attendus.vue()).toLowerCase();
    if (duContrat !== calc.digest) throw new Arret("condense_different", "OP-6", `condensé du contrat ${duContrat} ≠ ${calc.digest} (EX-6.1)`);
  });
}

/** OP-7 pour une opération au seuil : rend les t premières signatures dans l'ordre des adresses. */
async function signaturesAuSeuil(ctx, { client, demande, set }) {
  // OP-8, partie « organisation enregistrée », avant OP-7 (7.7).
  await ctx.op("OP-8", async () => {
    if (set === C.ADRESSE_NULLE) throw new Arret("organisation_inconnue", "OP-8", `organisation ${demande.fields?.org_id ?? demande.fields?.period_meta?.org_id ?? "?"} sans jeu`);
  });
  return ctx.op("OP-7", async () => {
    const t = Number(await client.vue(set, "CuratorSet", "getThreshold"));
    let precedent = null;
    for (const s of demande.signatures) {
      const r = C.verifier("RG-12", () => C.verifierSignature({ digest: demande.digest, signature: s }));
      if (r.status !== "reussi") throw new Arret("signature_non_canonique", "OP-7", r.detail);
      if (precedent !== null && !(precedent < s.signer)) throw new Arret("signature_non_canonique", "OP-7", "signataires non distincts ou non rangés par adresse croissante (RG-13)");
      precedent = s.signer;
      if (!(await client.vue(set, "CuratorSet", "isCurator", [s.signer]))) throw new Arret("signataire_hors_jeu", "OP-7", `${s.signer} n'est pas membre du jeu ${set}`);
    }
    if (demande.signatures.length < t) throw new Arret("signatures_insuffisantes", "OP-7", `${demande.signatures.length} signature(s) pour un seuil de ${t} lu à la tête (le seuil a pu changer, EX-8.11)`);
    return C.signaturesPourTransaction(demande, t).map(({ v, r, s }) => ({ v, r, s }));
  });
}

// --- inscrire-cle et revoquer-cle -------------------------------------------

function expediteur(ctx, instance, { defautRef }) {
  const o = ctx.options;
  if (o.relayeur) return { cle: cleSecp(o.relayeur, instance, { nom: "--relayeur" }), relayeur: true };
  if (o.expediteur) return { cle: cleSecp(o.expediteur, instance, { nom: "--expediteur" }), relayeur: false };
  return { cle: cleSecp(defautRef, instance, { nom: "--cle-chaine" }), relayeur: false };
}

async function verifierRelayeur(ctx, m, exp) {
  if (!exp.relayeur) return;
  await ctx.op("OP-5", async () => {
    const r = C.compteDuRole(m, "relayeur");
    if (!r || r.address !== adresseCle(exp.cle)) throw new Arret("compte_inattendu", "OP-5", `relayeur ${adresseCle(exp.cle)} ≠ compte de rôle relayeur ${r?.address}`);
  });
}

async function cmdInscrireCle(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const demande = lireJSONFichier(exigerOption(o, "demande"));
  const c = adressesContrats(m);
  const f = demande.fields ?? {};
  if (!o.relayeur && !o.expediteur) exigerOption(o, "cle-chaine");
  const exp = expediteur(ctx, instance, { defautRef: o["cle-chaine"] });
  if (!exp.relayeur && !o.expediteur && adresseCle(exp.cle) !== f.chain_key) throw new Arret("compte_inattendu", null, `--cle-chaine ${adresseCle(exp.cle)} n'est pas la clé de chaîne de la demande ${f.chain_key}`);
  await verifierRelayeur(ctx, m, exp);
  await verifierDemandeEnLigne(ctx, { client, demande, m, attendus: { operation: "inscription", contract: c.recorder_registry, vue: () => client.vue(c.recorder_registry, "RecorderRegistry", "registerDigest", [f.org_id, f.journal_id, f.chain_key, f.ed25519_public_key]) } });
  const fDossier = o.dossier ? path.resolve(o.dossier) : null;
  const d = fDossier ? lireDossier(fDossier) : null;
  if (d) verifierDossierInstance(d, instance);
  const rec = d?.recorders.find((x) => x.chain_key === f.chain_key && x.public_key === f.ed25519_public_key) ?? null;
  const e = d && rec ? etape(d, "inscription", rec.key_id) : null;
  const ecrire = () => {
    completerResultat(d, sansCapture ? null : rep);
    ecrireDossier(fDossier, d);
  };
  // EX-7.16 : une étape envoyee ou incluse se reprend par la capture de sa transaction, jamais par un renvoi.
  if (e && (e.state === "envoyee" || e.state === "incluse")) {
    await reprendreEtape(ctx, e, { instance, client, repertoire: rep, sansCapture, role: "inscription", contrat: c.recorder_registry, logIndex: 0, ecrire });
    return { result: "deja_fait", outputs: { transaction_hash: e.transaction_hash, block_number: e.block_number, capture: e.capture, is_active_recorder: true } };
  }
  // 7.11 : deja_fait dès que recorderOf est actif sous le même journalId et la même clé Ed25519 que la demande, dossier ou non.
  const actuel = await client.vue(c.recorder_registry, "RecorderRegistry", "recorderOf", [f.org_id, f.chain_key]);
  if (actuel.registeredAt !== 0n && actuel.revokedAt === 0n && actuel.ed25519PubKey.toLowerCase() === f.ed25519_public_key && actuel.journalId.toLowerCase() === f.journal_id) {
    if (e && e.state === "a_faire") {
      majEtape(e, { state: "faite" });
      ecrire();
    }
    return { result: "deja_fait", outputs: { transaction_hash: e?.transaction_hash ?? null, block_number: e?.block_number ?? null, capture: e?.capture ?? null, is_active_recorder: true, registered_at: actuel.registeredAt.toString() } };
  }
  const set = String(await client.vue(c.curator_set_registry, "CuratorSetRegistry", "curatorSetOf", [f.org_id])).toLowerCase();
  const sigs = await signaturesAuSeuil(ctx, { client, demande, set });
  await ctx.op("OP-8", async () => {
    if (actuel.revokedAt !== 0n) throw new Arret("cle_revoquee", "OP-8", `clé de chaîne ${f.chain_key} révoquée : jamais réinscrite (EX-8.8)`);
    if (actuel.registeredAt !== 0n) throw new Arret("cle_deja_active", "OP-8", `clé de chaîne ${f.chain_key} déjà inscrite`);
    const parCle = await client.vue(c.recorder_registry, "RecorderRegistry", "recorderByPubKey", [f.org_id, f.ed25519_public_key]);
    if (parCle.chainKey !== "0x0000000000000000000000000000000000000000" && parCle.revokedAt === 0n) throw new Arret("cle_ed25519_active", "OP-8", `clé Ed25519 active sous ${parCle.chainKey.toLowerCase()}`);
  });
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(exp.cle), repertoire: rep });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: exp.cle,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: c.recorder_registry,
      data: C.donneesAppel("registerRecorder", { org_id: f.org_id, journal_id: f.journal_id, chain_key: f.chain_key, ed25519_public_key: f.ed25519_public_key, signatures: sigs }),
      role: "inscription",
      contrat: c.recorder_registry,
      logIndex: 0,
      ...(e && e.state === "a_faire" ? suiviEtape(e, ecrire) : {}),
      evenement: async (recu) => {
        const ev = journaux(recu, c.recorder_registry, "RecorderRegistry").filter((x) => x.name === "RecorderRegistered");
        exigerOP11(ev.length === 1 && ev[0].args[0] === f.org_id && ev[0].args[1].toLowerCase() === f.chain_key && ev[0].args[2] === f.journal_id && ev[0].args[3] === f.ed25519_public_key && ev[0].args[4].toLowerCase() === adresseCle(exp.cle), "RecorderRegistered absent ou différent des valeurs envoyées");
      },
      relecture: async (bloc) => {
        exigerOP12(await client.vue(c.recorder_registry, "RecorderRegistry", "isActiveRecorder", [f.org_id, f.chain_key], bloc), "isActiveRecorder relu faux");
        exigerOP12((await client.vue(c.recorder_registry, "RecorderRegistry", "recorderByPubKey", [f.org_id, f.ed25519_public_key], bloc)).chainKey.toLowerCase() === f.chain_key, "recorderByPubKey relu différent");
      },
    },
  });
  if (e) {
    majEtape(e, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
    ecrire();
  }
  return { result: "reussi", outputs: { transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture, is_active_recorder: true, retention: r.marge } };
}

async function cmdRevoquerCle(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const demande = lireJSONFichier(exigerOption(o, "demande"));
  const c = adressesContrats(m);
  const f = demande.fields ?? {};
  if (!o.relayeur && !o.expediteur && !o["cle-chaine"]) throw new Arret("usage", null, "--relayeur, --expediteur ou --cle-chaine est obligatoire");
  const exp = expediteur(ctx, instance, { defautRef: o["cle-chaine"] });
  await verifierRelayeur(ctx, m, exp);
  await verifierDemandeEnLigne(ctx, { client, demande, m, attendus: { operation: "revocation", contract: c.recorder_registry, vue: () => client.vue(c.recorder_registry, "RecorderRegistry", "revokeDigest", [f.org_id, f.chain_key]) } });
  const actuel = await client.vue(c.recorder_registry, "RecorderRegistry", "recorderOf", [f.org_id, f.chain_key]);
  if (actuel.revokedAt !== 0n && actuel.registeredAt.toString() === f.registered_at) return { result: "deja_fait", outputs: { is_active_recorder: false, revoked_at: actuel.revokedAt.toString() } };
  const set = String(await client.vue(c.curator_set_registry, "CuratorSetRegistry", "curatorSetOf", [f.org_id])).toLowerCase();
  const sigs = await signaturesAuSeuil(ctx, { client, demande, set });
  await ctx.op("OP-8", async () => {
    if (actuel.registeredAt === 0n) throw new Arret("cle_inconnue", "OP-8", `clé de chaîne ${f.chain_key} inconnue`);
    if (actuel.registeredAt.toString() !== f.registered_at) throw new Arret("cle_inconnue", "OP-8", `registeredAt ${actuel.registeredAt} ≠ registered_at de la demande ${f.registered_at} (EX-8.7)`);
    if (actuel.revokedAt !== 0n) throw new Arret("cle_revoquee", "OP-8", "clé déjà révoquée");
  });
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(exp.cle), repertoire: rep });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: exp.cle,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: c.recorder_registry,
      data: C.donneesAppel("revokeRecorder", { org_id: f.org_id, chain_key: f.chain_key, signatures: sigs }),
      role: "revocation",
      contrat: c.recorder_registry,
      logIndex: 0,
      evenement: async (recu) => {
        const ev = journaux(recu, c.recorder_registry, "RecorderRegistry").filter((x) => x.name === "RecorderRevoked");
        exigerOP11(ev.length === 1 && ev[0].args[0] === f.org_id && ev[0].args[1].toLowerCase() === f.chain_key, "RecorderRevoked absent ou différent");
      },
      relecture: async (bloc) => exigerOP12(!(await client.vue(c.recorder_registry, "RecorderRegistry", "isActiveRecorder", [f.org_id, f.chain_key], bloc)), "isActiveRecorder relu vrai"),
    },
  });
  return { result: "reussi", outputs: { transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture, is_active_recorder: false } };
}

// --- manifeste-essai --------------------------------------------------------

async function cmdManifesteEssai(ctx) {
  const o = ctx.options;
  const { instance, client, m } = await preparer(ctx);
  if (!estDeveloppement(instance)) throw new Arret("reseau_non_developpement", null, "manifeste-essai n'est admis que sur le réseau de développement (EX-7.3)");
  const d = lireDossier(exigerOption(o, "dossier"));
  const keyId = exigerOption(o, "key-id");
  const rec = d.recorders.find((r) => r.key_id === keyId);
  if (!rec) throw new Arret("usage", null, `clé ${keyId} absente du dossier`);
  const ed = graineEd25519(exigerOption(o, "graine"), instance);
  if (ed.clePublique !== rec.public_key) throw new Arret("compte_inattendu", null, `la graine donne la clé publique ${ed.clePublique}, pas celle de ${keyId} (${rec.public_key})`);
  const rep = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(rep) && fs.readdirSync(rep).length) throw new Arret("usage", null, `${rep} n'est pas vide`);
  const n = o.evenements === undefined ? 3 : Number(o.evenements);
  if (!Number.isInteger(n) || n < 0 || n > 1000) throw new Arret("usage", null, "--evenements : entier de 0 à 1000");
  const precedente = await periodePrecedente(client, adressesContrats(m).period_registry, d.organisation.org_id, rec.journal_id);
  let periodStart;
  let firstSeq;
  let prev = C.HACHAGE_NUL;
  if (!precedente) {
    const t = Math.floor(Date.now() / 1000);
    periodStart = t - (t % 3600) - 3600;
    firstSeq = 1;
  } else {
    periodStart = Number(precedente.period_end);
    firstSeq = Number(BigInt(precedente.last_seq) + 1n);
    prev = precedente.period_hash;
  }
  const nonce = "0x" + randomBytes(32).toString("hex");
  const hashes = Array.from({ length: n }, (_, i) => sha256(Buffer.from(`noortrace/essai/ct4/evenement/${d.organisation.org_id}/${firstSeq + i}/${nonce}`, "utf8")));
  const manifeste = construireManifeste({ org_id: d.organisation.org_id, journal_id: rec.journal_id, period_start: periodStart, first_seq: firstSeq, hashes, prev_period_hash: prev, recorder_key_id: keyId, nonce, generated_at: maintenant() });
  const sig = signerManifeste(manifeste, ed.clePrivee);
  fs.mkdirSync(rep, { recursive: true });
  ecrireSynchronise(path.join(rep, "manifeste.json"), texteJSON(manifeste));
  ecrireSynchronise(path.join(rep, "manifeste.sig"), texteJSON(sig));
  const periodHash = hachageManifeste(manifeste);
  const e = C.empreinteAncre({ org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHash });
  return { result: "reussi", outputs: { period_hash: periodHash, fingerprint: e.fingerprint, period_start: manifeste.period_start, period_end: manifeste.period_end, first_seq: manifeste.first_seq, last_seq: manifeste.last_seq, root: manifeste.root, files: [path.join(rep, "manifeste.json"), path.join(rep, "manifeste.sig")] } };
}

// --- ancrer -----------------------------------------------------------------

function cleDuManifeste(o, d, manifeste) {
  if (o["cle-ed25519"]) return String(o["cle-ed25519"]).toLowerCase();
  if (!d) throw new Arret("usage", null, "--dossier (ou --cle-ed25519) est obligatoire : il donne la clé publique du manifeste (OP-9)");
  const r = d.recorders.find((x) => x.key_id === manifeste.recorder_key_id);
  if (!r) throw new Arret("cle_chaine_non_inscrite", "OP-9", `clé du manifeste ${manifeste.recorder_key_id} absente du dossier`);
  return r.public_key;
}

/** Étape premiere_ancre ou premiere_cloture d'un journal, encore à faire ou déjà faite pour ce periodHash. */
function etapePremiere(d, step, manifeste, periodHash) {
  if (!d) return null;
  const j = d.journals.find((x) => x.journal_id === manifeste.journal_id);
  return d.steps.find((s) => s.step === step && (s.subject === periodHash || (j && s.subject === j.name && s.state === "a_faire"))) ?? null;
}

async function cmdAncrer(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const manifeste = lireJSONFichier(exigerOption(o, "manifeste"));
  const d = o.dossier ? lireDossier(o.dossier) : null;
  const c = adressesContrats(m);
  const cle = cleSecp(exigerOption(o, "cle-chaine"), instance, { nom: "--cle-chaine" });
  const emetteur = adresseCle(cle);
  const periodHash = hachageManifeste(manifeste);
  const ed = cleDuManifeste(o, d, manifeste);
  let empreinte;
  let digest;
  await ctx.op("OP-6", async () => {
    empreinte = C.empreinteAncre({ org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHash }).fingerprint;
    const calc = C.condenseAncre({ chain_id: m.evm_chain_id, contract: c.attestation_registry, fingerprint: empreinte, doc_type: C.DOC_TYPE_PERIODE });
    const duContrat = String(await client.vue(c.attestation_registry, "AttestationRegistry", "anchorDigest", [empreinte, C.DOC_TYPE_PERIODE])).toLowerCase();
    if (duContrat !== calc.digest) throw new Arret("condense_different", "OP-6", `anchorDigest du contrat ${duContrat} ≠ ${calc.digest}`);
    digest = calc.digest;
  });
  const e = etapePremiere(d, "premiere_ancre", manifeste, periodHash);
  const ecrire = () => {
    completerResultat(d, sansCapture ? null : rep);
    ecrireDossier(path.resolve(o.dossier), d);
  };
  // EX-7.16 : une étape envoyee ou incluse se reprend par la capture de sa transaction, jamais par un renvoi.
  if (e && d && (e.state === "envoyee" || e.state === "incluse")) {
    await reprendreEtape(ctx, e, { instance, client, repertoire: rep, sansCapture, role: "ancre", contrat: c.attestation_registry, logIndex: 0, ecrire });
    return { result: "deja_fait", outputs: { fingerprint: empreinte, issuer: emetteur, transaction_hash: e.transaction_hash, block_number: e.block_number, capture: e.capture } };
  }
  let deja = null;
  await ctx.op("OP-9", async () => {
    if (!(await client.vue(c.recorder_registry, "RecorderRegistry", "isActiveRecorder", [manifeste.org_id, emetteur]))) throw new Arret("cle_chaine_non_inscrite", "OP-9", `clé de chaîne ${emetteur} non inscrite ou révoquée chez ${manifeste.org_id} (EX-7.11)`);
    const parCle = await client.vue(c.recorder_registry, "RecorderRegistry", "recorderByPubKey", [manifeste.org_id, ed]);
    if (parCle.chainKey.toLowerCase() !== emetteur) throw new Arret("cle_chaine_non_inscrite", "OP-9", `la clé du manifeste ${manifeste.recorder_key_id} est inscrite sous ${parCle.chainKey.toLowerCase()}, pas sous ${emetteur}`);
    if (await client.vue(c.attestation_registry, "AttestationRegistry", "isAnchored", [empreinte])) {
      const l = await client.vue(c.attestation_registry, "AttestationRegistry", "lookup", [empreinte]);
      if (l.issuer.toLowerCase() === emetteur && l.docType.toLowerCase() === C.DOC_TYPE_PERIODE) deja = l;
      else throw new Arret("empreinte_squattee", "OP-9", `empreinte ${empreinte} déjà ancrée par ${l.issuer.toLowerCase()} : ne pas réessayer, signaler (8.3, EX-8.6)`);
    }
  });
  if (deja) return { result: "deja_fait", outputs: { fingerprint: empreinte, issuer: emetteur, transaction_hash: e?.transaction_hash ?? null, block_number: e?.block_number ?? null, capture: e?.capture ?? null } };
  const sig = C.signerCondense(cle.privateKey, digest);
  await verifierExpediteur(ctx, { client, instance, from: emetteur, repertoire: rep });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: c.attestation_registry,
      data: C.donneesAppel("anchor", { fingerprint: empreinte, doc_type: C.DOC_TYPE_PERIODE, issuer: emetteur, signature: sig }),
      role: "ancre",
      contrat: c.attestation_registry,
      logIndex: 0,
      ...(e && d && e.state === "a_faire" ? suiviEtape(e, ecrire, { sujet: periodHash }) : {}),
      evenement: async (recu) => {
        const ev = journaux(recu, c.attestation_registry, "AttestationRegistry").filter((x) => x.name === "Anchored");
        exigerOP11(ev.length === 1 && ev[0].args[0] === empreinte && ev[0].args[1].toLowerCase() === emetteur && ev[0].args[2] === C.DOC_TYPE_PERIODE, "Anchored absent ou différent");
      },
      relecture: async (bloc) => {
        const l = await client.vue(c.attestation_registry, "AttestationRegistry", "lookup", [empreinte], bloc);
        exigerOP12(l.issuer.toLowerCase() === emetteur && l.docType.toLowerCase() === C.DOC_TYPE_PERIODE, "lookup relu différent");
      },
    },
  });
  if (e && d) {
    e.subject = periodHash;
    majEtape(e, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
    ecrire();
  }
  return { result: "reussi", outputs: { transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, fingerprint: empreinte, capture: r.capture, retention: r.marge } };
}

// --- clore ------------------------------------------------------------------

async function cmdClore(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const demande = lireJSONFichier(exigerOption(o, "demande"));
  const manifeste = lireJSONFichier(exigerOption(o, "manifeste"));
  const d = o.dossier ? lireDossier(o.dossier) : null;
  const c = adressesContrats(m);
  if (!o.relayeur && !o.expediteur && !o["cle-chaine"]) throw new Arret("usage", null, "--cle-chaine (ou --relayeur) est obligatoire");
  const exp = expediteur(ctx, instance, { defautRef: o["cle-chaine"] });
  await verifierRelayeur(ctx, m, exp);
  const meta = demande.fields?.period_meta;
  await verifierDemandeEnLigne(ctx, { client, demande, m, attendus: { operation: "cloture", contract: c.period_registry, vue: () => client.vue(c.period_registry, "PeriodRegistry", "periodDigest", [tupleEthers(meta)]) } });
  if (!egalJSON(meta, C.metaDuManifeste(manifeste, meta.uri))) throw new Arret("condense_different", "OP-6", "le PeriodMeta de la demande n'est pas celui du manifeste (CT-1 §10.4)");
  const periodHash = meta.period_hash;
  const ed = cleDuManifeste(o, d, manifeste);
  const e = etapePremiere(d, "premiere_cloture", manifeste, periodHash);
  const ecrire = () => {
    completerResultat(d, sansCapture ? null : rep);
    ecrireDossier(path.resolve(o.dossier), d);
  };
  // EX-7.16 : une étape envoyee ou incluse se reprend par la capture de sa transaction, jamais par un renvoi.
  if (e && d && (e.state === "envoyee" || e.state === "incluse")) {
    await reprendreEtape(ctx, e, { instance, client, repertoire: rep, sansCapture, role: "cloture", contrat: c.period_registry, logIndex: 0, ecrire });
    return { result: "deja_fait", outputs: { period_hash: periodHash, transaction_hash: e.transaction_hash, block_number: e.block_number, capture: e.capture } };
  }
  let deja = false;
  await ctx.op("OP-10", async () => {
    const precedente = await periodePrecedente(client, c.period_registry, meta.org_id, meta.journal_id);
    if (await client.vue(c.period_registry, "PeriodRegistry", "isKnown", [meta.org_id, periodHash])) {
      if (precedente && precedente.period_hash === periodHash) {
        deja = true;
        return;
      }
      throw new Arret("doublon", "OP-10", `periodHash ${periodHash} déjà enregistré et qui n'est pas la dernière période du journal`);
    }
    const r = C.verifier("RG-5", () => C.verifierChampsCloture(meta, { precedente }));
    if (r.status !== "reussi") throw new Arret(r.code, "OP-10", r.detail);
    const empreinte = C.empreinteAncre({ org_id: meta.org_id, journal_id: meta.journal_id, period_hash: periodHash }).fingerprint;
    const l = await client.vue(c.attestation_registry, "AttestationRegistry", "lookup", [empreinte]);
    const cleChaine = (await client.vue(c.recorder_registry, "RecorderRegistry", "recorderByPubKey", [meta.org_id, ed])).chainKey.toLowerCase();
    if (l.issuer === "0x0000000000000000000000000000000000000000") throw new Arret("ancre_manquante", "OP-10", `ancre de la période ${empreinte} absente : ancrer d'abord (EX-8.4)`);
    if (l.issuer.toLowerCase() !== cleChaine || (!exp.relayeur && !o.expediteur && l.issuer.toLowerCase() !== adresseCle(exp.cle))) throw new Arret("ancre_manquante", "OP-10", `ancre émise par ${l.issuer.toLowerCase()}, pas par la clé de chaîne qui relaie (EX-8.4)`);
  });
  if (deja) return { result: "deja_fait", outputs: { period_hash: periodHash, transaction_hash: e?.transaction_hash ?? null, block_number: e?.block_number ?? null, capture: e?.capture ?? null } };
  const set = String(await client.vue(c.curator_set_registry, "CuratorSetRegistry", "curatorSetOf", [meta.org_id])).toLowerCase();
  const sigs = await signaturesAuSeuil(ctx, { client, demande, set });
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(exp.cle), repertoire: rep });
  // EX-8.19 : la demande relayée est copiée dans --captures avant l'envoi (demande-cloture-<periodHash>.json).
  const fCopie = path.join(rep, `demande-cloture-${periodHash}.json`);
  if (!fs.existsSync(fCopie)) ecrireSynchronise(fCopie, texteJSON(demande));
  let periodId = null;
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: exp.cle,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: c.period_registry,
      data: C.donneesAppel("submitPeriod", { period_meta: meta, signatures: sigs }),
      role: "cloture",
      contrat: c.period_registry,
      logIndex: 0,
      ...(e && d && e.state === "a_faire" ? suiviEtape(e, ecrire, { sujet: periodHash }) : {}),
      evenement: async (recu) => {
        const ev = journaux(recu, c.period_registry, "PeriodRegistry").filter((x) => x.name === "PeriodSubmitted");
        exigerOP11(ev.length === 1 && ev[0].args[1] === periodHash && ev[0].args[2] === meta.org_id && ev[0].args[3] === meta.journal_id && ev[0].args[4] === meta.root && ev[0].args[10].toLowerCase() === adresseCle(exp.cle), "PeriodSubmitted absent ou différent des valeurs envoyées");
        periodId = ev[0].args[0].toString();
      },
      relecture: async (bloc) => {
        const p = await periodePrecedente(client, c.period_registry, meta.org_id, meta.journal_id, bloc);
        exigerOP12(p && p.period_hash === periodHash && p.id === periodId, "getPeriod(latestPeriodOf) relu différent");
      },
    },
  });
  if (e && d) {
    e.subject = periodHash;
    majEtape(e, { state: r.capture ? "capturee" : "incluse", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture });
    ecrire();
  }
  return { result: "reussi", outputs: { transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, period_id: periodId, capture: r.capture, retention: r.marge, relayed_request: fCopie } };
}

// --- administrer-jeu --------------------------------------------------------

async function cmdAdministrerJeu(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const demande = lireJSONFichier(exigerOption(o, "demande"));
  if (!o.relayeur && !o.expediteur) throw new Arret("usage", null, "--relayeur ou --expediteur est obligatoire");
  const exp = expediteur(ctx, instance, {});
  await verifierRelayeur(ctx, m, exp);
  const set = demande.contract;
  const f = demande.fields ?? {};
  await verifierDemandeEnLigne(ctx, { client, demande, m, attendus: { operation: "administration_jeu", contract: set, vue: () => client.vue(set, "CuratorSet", "adminOpDigest", [C.keccakTexte(f.op), f.arg, f.nonce]) } });
  await ctx.op("OP-5", async () => {
    const nonce = (await client.vue(set, "CuratorSet", "opNonce")).toString();
    if (nonce !== f.nonce) throw new Arret("pas_administrateur", "OP-5", `nonce de la demande ${f.nonce} ≠ opNonce() ${nonce} : refaire la demande`);
    const attendu = f.op === "CuratorSet.acceptAdmin" ? String(await client.vue(set, "CuratorSet", "pendingAdmin")).toLowerCase() : String(await client.vue(set, "CuratorSet", "admin")).toLowerCase();
    if (demande.signatures.length !== 1 || demande.signatures[0].signer !== attendu) throw new Arret("pas_administrateur", "OP-5", `signataire ${demande.signatures[0]?.signer} ≠ ${f.op === "CuratorSet.acceptAdmin" ? "pendingAdmin()" : "admin()"} ${attendu}`);
  });
  await ctx.op("OP-7", async () => {
    const r = C.verifier("RG-12", () => C.verifierSignature({ digest: demande.digest, signature: demande.signatures[0] }));
    if (r.status !== "reussi") throw new Arret("signature_non_canonique", "OP-7", r.detail);
  });
  const valeur = OPERATION_VALEUR(f);
  const { fonction, args } = C.appelOperationJeu(f.op, valeur, f.nonce, demande.signatures[0]);
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(exp.cle), repertoire: rep });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: exp.cle,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: set,
      data: C.donneesAppel(fonction, args),
      role: "administration_jeu",
      contrat: set,
      logIndex: 0,
      evenement: async (recu) => {
        const ev = journaux(recu, set, "CuratorSet").filter((x) => x.name === "AdminOpRelayed");
        exigerOP11(ev.length === 1 && ev[0].args[0] === C.keccakTexte(f.op) && ev[0].args[2].toString() === f.nonce && ev[0].args[1].toLowerCase() === adresseCle(exp.cle), "AdminOpRelayed absent ou différent");
      },
      relecture: async (bloc) => {
        exigerOP12((await client.vue(set, "CuratorSet", "opNonce", [], bloc)).toString() === String(BigInt(f.nonce) + 1n), "opNonce relu différent");
        if (f.op === "CuratorSet.addCurator") exigerOP12(await client.vue(set, "CuratorSet", "isCurator", [valeur], bloc), "isCurator relu faux");
        if (f.op === "CuratorSet.removeCurator") exigerOP12(!(await client.vue(set, "CuratorSet", "isCurator", [valeur], bloc)), "isCurator relu vrai");
        if (f.op === "CuratorSet.setThreshold") exigerOP12((await client.vue(set, "CuratorSet", "getThreshold", [], bloc)).toString() === String(valeur), "getThreshold relu différent");
        if (f.op === "CuratorSet.proposeAdmin") exigerOP12(String(await client.vue(set, "CuratorSet", "pendingAdmin", [], bloc)).toLowerCase() === valeur, "pendingAdmin relu différent");
      },
    },
  });
  return { result: "reussi", outputs: { operation: f.op, transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture } };
}

function OPERATION_VALEUR(f) {
  const d = C.OPERATIONS_JEU[f.op];
  if (d.argument === "adresse") return "0x" + f.arg.slice(26);
  if (d.argument === "entier") return BigInt(f.arg).toString();
  return null;
}

// --- reassigner -------------------------------------------------------------

async function cmdReassigner(ctx) {
  const o = ctx.options;
  const { instance, client, sansCapture, m } = await preparer(ctx);
  const rep = capturesDe(o);
  const orgId = String(exigerOption(o, "org-id")).toLowerCase();
  if (String(exigerOption(o, "confirmer")).toLowerCase() !== orgId) throw new Arret("usage", null, "--confirmer doit répéter l'org_id réassigné (EX-8.10)");
  // EX-8.10 : la demande écrite du client, consignée ; son SHA-256 va dans outputs.request_sha256.
  const demandeEcrite = lireOctets(exigerOption(o, "demande"));
  if (!demandeEcrite.length) throw new Arret("entree_illisible", null, "--demande : la demande écrite du client est vide (EX-8.10)");
  const requestSha256 = sha256(demandeEcrite);
  const nouveau = C.adresseMinuscule(exigerOption(o, "jeu"));
  const adm = comptesExploitant(o, instance, ["administrateur_registre"]).administrateur_registre;
  const csr = adressesContrats(m).curator_set_registry;
  let precedent;
  let lectures = null;
  await ctx.op("OP-5", async () => {
    const a = C.compteDuRole(m, "administrateur_registre");
    if (!a || a.address !== adresseCle(adm)) throw new Arret("compte_inattendu", "OP-5", `administrateur ${adresseCle(adm)} ≠ compte de rôle ${a?.address}`);
    const admin = String(await client.vue(csr, "CuratorSetRegistry", "admin")).toLowerCase();
    if (admin !== adresseCle(adm)) throw new Arret("pas_administrateur", "OP-5", `CuratorSetRegistry.admin() = ${admin}`);
    precedent = String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId])).toLowerCase();
    if (precedent === C.ADRESSE_NULLE) throw new Arret("organisation_inconnue", "OP-5", `organisation ${orgId} sans jeu : l'inscription suit la section 7`);
    const code = await client.appel("eth_getCode", [nouveau, "latest"]);
    if (!code || code === "0x") throw new Arret("code_absent", "OP-5", `aucun code à ${nouveau}`);
    if (precedent === nouveau) return;
    // Le nouveau jeu répond comme un CuratorSet (setCuratorSet accepterait toute adresse non nulle, EX-8.10).
    let adminNouveau;
    let seuil;
    let membres;
    try {
      adminNouveau = String(await client.vue(nouveau, "CuratorSet", "admin")).toLowerCase();
      seuil = Number(await client.vue(nouveau, "CuratorSet", "getThreshold"));
      membres = Number(await client.vue(nouveau, "CuratorSet", "getCuratorCount"));
    } catch (err) {
      throw new Arret("jeu_invalide", "OP-5", `${nouveau} ne répond pas comme un CuratorSet (admin, getThreshold, getCuratorCount) : ${err.message} (EX-8.10)`);
    }
    if (!(seuil >= 1 && membres >= seuil)) throw new Arret("jeu_invalide", "OP-5", `${nouveau} : seuil ${seuil}, membres ${membres} (EX-8.10)`);
    let adminPrecedent = null;
    try {
      adminPrecedent = String(await client.vue(precedent, "CuratorSet", "admin")).toLowerCase();
    } catch {
      adminPrecedent = null;
    }
    if (!o["changement-administrateur"] && adminNouveau !== adminPrecedent) throw new Arret("jeu_invalide", "OP-5", `admin() du nouveau jeu ${adminNouveau} ≠ admin() du jeu précédent ${adminPrecedent ?? "illisible"} : --changement-administrateur avec la demande consignée selon CT-7 (EX-8.10)`);
    lectures = { admin: adminNouveau, threshold: seuil, curators: membres, previous_admin: adminPrecedent, admin_change: Boolean(o["changement-administrateur"]) };
  });
  if (precedent === nouveau) return { result: "deja_fait", outputs: { org_id: orgId, curator_set: nouveau, request_sha256: requestSha256 } };
  await verifierExpediteur(ctx, { client, instance, from: adresseCle(adm), repertoire: rep });
  const r = await envoyer(ctx, {
    instance,
    client,
    cle: adm,
    repertoire: rep,
    sansCapture,
    delai: delaiDe(o),
    appel: {
      objet: "appel",
      to: csr,
      data: C.donneesAppel("setCuratorSet", { org_id: orgId, curator_set: nouveau }),
      role: "reassignation",
      contrat: csr,
      logIndex: 0,
      evenement: async (recu) => {
        const ev = journaux(recu, csr, "CuratorSetRegistry").filter((x) => x.name === "CuratorSetAssigned");
        exigerOP11(ev.length === 1 && ev[0].args[0] === orgId && ev[0].args[1].toLowerCase() === nouveau && ev[0].args[2].toLowerCase() === precedent, "CuratorSetAssigned(orgId, nouveau, précédent) absent ou différent");
      },
      relecture: async (bloc) => exigerOP12(String(await client.vue(csr, "CuratorSetRegistry", "curatorSetOf", [orgId], bloc)).toLowerCase() === nouveau, "curatorSetOf relu différent"),
    },
  });
  return { result: "reussi", outputs: { org_id: orgId, previous: precedent, curator_set: nouveau, new_set: lectures, request_sha256: requestSha256, transaction_hash: r.transaction_hash, block_number: r.block_number, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture } };
}

// --- capturer ---------------------------------------------------------------

/** Rôle et contrat d'une transaction déduits de ses données (sélecteur) et de son reçu. */
function roleDeTransaction(tx, recu) {
  if (tx.to === null) {
    let estJeu = false;
    try {
      estJeu = tx.data.startsWith(artefact("CuratorSet").bytecode.toLowerCase());
    } catch {
      estJeu = false;
    }
    return { role: estJeu ? "jeu_approbateurs" : "deploiement", contrat: String(recu.contractAddress).toLowerCase(), logIndex: null };
  }
  if (tx.data === "0x") return { role: "approvisionnement", contrat: null, logIndex: null };
  const sel = tx.data.slice(0, 10);
  const par = Object.entries(C.SELECTEURS).find(([, s]) => s === sel)?.[0];
  const role = { anchor: "ancre", submitPeriod: "cloture", registerRecorder: "inscription", revokeRecorder: "revocation", addCuratorSigned: "administration_jeu", removeCuratorSigned: "administration_jeu", setThresholdSigned: "administration_jeu", proposeAdminSigned: "administration_jeu", acceptAdminSigned: "administration_jeu" }[par];
  if (role) return { role, contrat: tx.to, logIndex: 0 };
  if (par === "setCuratorSet") {
    const j = recu.logs.find((x) => x.topics[0] === C.EVENEMENTS.CuratorSetAssigned.topic);
    return { role: j && BigInt(j.topics[3]) !== 0n ? "reassignation" : "assignation", contrat: tx.to, logIndex: 0 };
  }
  throw new Arret("usage", null, `rôle de la transaction non déductible (sélecteur ${sel}) : donner --role`);
}

/** Avec --dossier : l'étape dont transaction_hash est l'un de `hachages` passe à capturee (EX-7.16, 8.6). */
function majDossierCapture(o, hachages, r, contrat) {
  if (!o.dossier) return null;
  const f = path.resolve(o.dossier);
  const d = lireDossier(f);
  const e = d.steps.find((s) => s.transaction_hash && hachages.includes(s.transaction_hash));
  if (!e) return null;
  majEtape(e, { state: "capturee", transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, capture: r.capture, contract: e.step === "jeu_approbateurs" ? e.contract ?? contrat ?? null : undefined });
  completerResultat(d, path.resolve(exigerOption(o, "captures")));
  ecrireDossier(f, d);
  return { step: e.step, subject: e.subject, state: e.state };
}

async function cmdCapturer(ctx) {
  const o = ctx.options;
  const { instance, client, m } = await preparer(ctx);
  if (o["sans-capture"]) throw new Arret("usage", null, "capturer n'admet pas --sans-capture");
  const rep = capturesDe(o);
  if (o.role !== undefined && !C.ROLES_CAPTURE.includes(o.role)) throw new Arret("usage", null, `--role : ${C.ROLES_CAPTURE.join(", ")}`);
  const contratOption = o.contrat ? C.adresseMinuscule(o.contrat) : null;
  if (o.envoi) {
    const fEnvoi = path.resolve(o.envoi);
    const envoi = lireJSONFichier(fEnvoi);
    const e = conforme(envoi, C.ID_SCHEMA_OPERATIONS, "#/$defs/envoi");
    if (e.length) throw new Arret("entree_illisible", null, `envoi non conforme : ${e[0].chemin} : ${e[0].message}`);
    let tx;
    try {
      tx = C.decoderTransaction(envoi.raw_transaction);
    } catch (err) {
      throw new Arret("entree_illisible", null, `raw_transaction de l'envoi indécodable : ${err.message}`);
    }
    if (tx.transaction_hash !== envoi.transaction_hash) throw new Arret("entree_illisible", null, `transaction_hash de l'envoi ${envoi.transaction_hash} ≠ hachage des octets signés ${tx.transaction_hash}`);
    // --role et --contrat priment ; sans eux, rôle et contrat sont déduits de la transaction et du reçu (8.6).
    const appel = { role: o.role ?? null, contrat: contratOption, logIndex: null };
    if (appel.role) appel.logIndex = C.EVENEMENT_DU_ROLE[appel.role] ? 0 : null;
    appel.evenement = async (recu) => {
      const deduit = appel.role && (appel.contrat || appel.role === "approvisionnement") ? null : roleDeTransaction(tx, recu);
      const role = appel.role ?? deduit.role;
      const contrat = appel.contrat ?? deduit?.contrat ?? null;
      const ev = C.EVENEMENT_DU_ROLE[role];
      if (ev) exigerOP11(recu.logs.some((j) => j.address.toLowerCase() === contrat && j.topics[0] === C.EVENEMENTS[ev].topic), `${ev} absent du reçu`);
    };
    if (o.remplacer) {
      if (o.renvoyer) throw new Arret("usage", null, "--renvoyer et --remplacer s'excluent (8.6)");
      // EX-8.16 : remplacement seulement si la transaction est inconnue de chaque point ; un point injoignable compte comme un refus.
      for (const url of client.urls) {
        let t;
        try {
          t = await client.appel("eth_getTransactionByHash", [envoi.transaction_hash], { url });
        } catch (err) {
          if (err instanceof ErreurRPC || (err instanceof Arret && err.code === "noeud_injoignable")) throw new Arret("noeud_injoignable", "OP-2", `${url} : ${err.message} ; impossible de savoir si ${envoi.transaction_hash} y est connue, ce qui compte comme un refus : --remplacer refusé (EX-8.16)`);
          throw err;
        }
        if (t) throw new Arret("usage", null, `${envoi.transaction_hash} est connue de ${url} : --renvoyer d'abord, jamais --remplacer (8.6)`);
      }
      const cle = cleSecp(exigerOption(o, "cle"), instance, { nom: "--cle" });
      if (adresseCle(cle) !== envoi.from) throw new Arret("compte_inattendu", null, `--cle ${adresseCle(cle)} n'est pas l'expéditeur ${envoi.from}`);
      const prix = BigInt(envoi.max_fee_per_gas);
      const valeur = BigInt(tx.value ?? 0);
      const objet = tx.to === null ? "deploiement" : tx.data === "0x" ? "approvisionnement" : "appel";
      // OP-3 au prix relevé, l'envoi remplacé n'étant pas compté parmi les envois sans issue.
      await verifierExpediteur(ctx, { client, instance, from: envoi.from, value: valeur, repertoire: rep, prix: C.fraisRemplacement(prix), sauf: envoi.transaction_hash });
      const r = await envoyer(ctx, { instance, client, cle, appel: { ...appel, objet, to: tx.to, data: tx.data, value: valeur, provision: null }, repertoire: rep, sansCapture: false, delai: delaiDe(o), remplace: { prix, hash: envoi.transaction_hash }, nonceImpose: BigInt(envoi.nonce) });
      return conclureCapture(ctx, r, { replaced: envoi.transaction_hash, dossier: majDossierCapture(o, [envoi.transaction_hash, r.transaction_hash], r, appel.contrat) });
    }
    const r = await attendreEtCapturer(ctx, { instance, client, envoi, fEnvoi, appel, repertoire: rep, sansCapture: false, delai: delaiDe(o), soumettre: Boolean(o.renvoyer) });
    return conclureCapture(ctx, r, { dossier: majDossierCapture(o, [envoi.transaction_hash], r, appel.contrat) });
  }
  const hash = String(exigerOption(o, "transaction")).toLowerCase();
  const role = exigerOption(o, "role");
  if (!C.ROLES_CAPTURE.includes(role)) throw new Arret("usage", null, `--role : ${C.ROLES_CAPTURE.join(", ")}`);
  const recu = await client.appel("eth_getTransactionReceipt", [hash]);
  if (!recu) throw new Arret("recu_absent", null, `aucun reçu pour ${hash}`, { result: "incertain" });
  const t = await client.appel("eth_getTransactionByHash", [hash]);
  if (!t) throw new Arret("recu_absent", null, `transaction ${hash} inconnue du point --rpc alors qu'un reçu existe`, { result: "incertain" });
  const contrat = contratOption ?? (role === "approvisionnement" ? null : t.to === null ? String(recu.contractAddress).toLowerCase() : String(t.to).toLowerCase());
  await ctx.op("OP-11", async () => {
    if (recu.status !== "0x1") throw new Arret("transaction_annulee", "OP-11", `status ${recu.status}`, { result: "echoue" });
    const ev = C.EVENEMENT_DU_ROLE[role];
    if (ev) exigerOP11(recu.logs.some((j) => j.address.toLowerCase() === contrat && j.topics[0] === C.EVENEMENTS[ev].topic), `${ev} émis par ${contrat} absent du reçu`);
    if (role === "deploiement" || role === "jeu_approbateurs") {
      exigerOP11(t.to === null, "transaction de déploiement avec destinataire (RG-19)");
      exigerOP11(C.adresseCreation(t.from, BigInt(t.nonce)) === contrat && String(recu.contractAddress).toLowerCase() === contrat, `adresse créée ${recu.contractAddress} ≠ CREATE(${t.from}, ${BigInt(t.nonce)}) ou ≠ --contrat (RG-19)`);
      const dep = m.contracts.find((c) => c.address === contrat);
      if (dep && dep.nonce !== null) exigerOP11(t.from.toLowerCase() === dep.deployer && BigInt(t.nonce) === BigInt(dep.nonce), "transaction signée par un autre déployeur ou à un autre nonce que ceux du manifeste (RG-19)");
    }
  });
  const h = Number(BigInt(recu.blockNumber));
  ecrireIssue(rep, hash, { block_number: h, status: recu.status });
  const cap = await capturerTransaction(ctx, { instance, client, repertoire: rep, role, transactionHash: hash, contrat, logIndex: C.EVENEMENT_DU_ROLE[role] ? 0 : null, sending: lireEnvoi(rep, hash), hauteur: h });
  const r = { transaction_hash: hash, block_number: cap.index.block_number, block_hash: cap.index.block_hash, capture: cap.nom };
  const dossier = majDossierCapture(o, [hash], r, contrat);
  return { result: "reussi", outputs: { capture: cap.nom, transaction_hash: hash, block_number: cap.index.block_number, block_hash: cap.index.block_hash, sha256: sha256(fs.readFileSync(path.join(rep, cap.nom))), retention: cap.marge, dossier } };
}

function conclureCapture(_ctx, r, complement = {}) {
  return { result: "reussi", outputs: { transaction_hash: r.transaction_hash, block_number: r.block_number, block_hash: r.block_hash, gas_used: r.gas_used, cost_wei: r.cost_wei, capture: r.capture, retention: r.marge, ...complement } };
}

// --- exporter ---------------------------------------------------------------

function lireIndexCaptures(rep) {
  if (!fs.existsSync(rep)) throw new Arret("entree_illisible", null, `${rep} absent`);
  return fs
    .readdirSync(rep)
    .filter((f) => /^capture-\d+-\d+-[a-z_]+\.json$/.test(f))
    .sort()
    .map((f) => ({ nom: f, index: JSON.parse(fs.readFileSync(path.join(rep, f), "utf8")) }));
}

function recuDeIndex(rep, index) {
  return JSON.parse(fs.readFileSync(path.join(rep, index.files.receipts[index.transaction_index].name), "utf8")).result;
}

async function cmdExporter(ctx) {
  const o = ctx.options;
  const instance = chargerInstance(o);
  const m = instance.manifeste;
  const rep = path.resolve(exigerOption(o, "captures"));
  const manifeste = lireJSONFichier(exigerOption(o, "manifeste"));
  const d = o.dossier ? lireDossier(o.dossier) : null;
  const sortieRep = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(sortieRep) && fs.readdirSync(sortieRep).length) throw new Arret("usage", null, `${sortieRep} n'est pas vide`);
  let cles;
  if (o.cles) cles = lireJSONFichier(o.cles).keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key }));
  else if (d) cles = d.recorders.map((r) => ({ key_id: r.key_id, public_key: r.public_key }));
  else throw new Arret("usage", null, "--cles ou --dossier est obligatoire (clés qui signent dans le dossier, EX-9.8)");
  const periodHash = hachageManifeste(manifeste);
  const empreinte = C.empreinteAncre({ org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHash }).fingerprint;
  const tous = lireIndexCaptures(rep);
  const c = adressesContrats(m);
  const avecJournal = (role, pred) => tous.filter(({ index }) => index.role === role && pred(recuDeIndex(rep, index).logs[index.log_index]));
  const cloture = avecJournal("cloture", (j) => j && j.address.toLowerCase() === c.period_registry && j.topics[2]?.toLowerCase() === periodHash);
  const ancre = avecJournal("ancre", (j) => j && j.address.toLowerCase() === c.attestation_registry && j.topics[1]?.toLowerCase() === empreinte);
  if (cloture.length !== 1) throw new Arret("capture_incomplete", "CP-5", `${cloture.length} capture(s) de la clôture de ${periodHash} au lieu d'une`);
  if (ancre.length !== 1) throw new Arret("capture_incomplete", "CP-5", `${ancre.length} capture(s) de l'ancre de ${empreinte} au lieu d'une`);
  const emetteur = "0x" + recuDeIndex(rep, ancre[0].index).logs[ancre[0].index.log_index].topics[2].slice(26).toLowerCase();
  const inscriptions = tous
    .filter(({ index }) => index.role === "inscription")
    .map(({ nom, index }) => {
      const j = recuDeIndex(rep, index).logs[index.log_index];
      return { nom, index, org: j.topics[1].toLowerCase(), chainKey: "0x" + j.topics[2].slice(26).toLowerCase(), ed: "0x" + j.data.slice(2, 66).toLowerCase() };
    })
    .filter((x) => x.org === manifeste.org_id && x.index.contract === c.recorder_registry);
  const cleManifeste = cles.find((k) => k.key_id === manifeste.recorder_key_id);
  const retenues = [];
  if (cleManifeste) {
    const i = inscriptions.filter((x) => x.ed === cleManifeste.public_key && x.chainKey === emetteur).sort((a, b) => b.index.block_number - a.index.block_number)[0];
    if (i) retenues.push(i);
  }
  for (const k of cles) {
    if (k === cleManifeste) continue;
    const i = inscriptions.filter((x) => x.ed === k.public_key).sort((a, b) => b.index.block_number - a.index.block_number)[0];
    if (i && !retenues.includes(i)) retenues.push(i);
  }
  if (retenues.length > 8) throw new Arret("capture_incomplete", null, `${retenues.length} inscriptions : au plus 8 (CT-6 EX-13.9)`);
  const choisies = [cloture[0], ancre[0], ...retenues];
  const lireFichier = (n) => (fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null);
  for (const x of choisies) {
    const jeu = C.jeuPourHauteur(m, x.index.block_number);
    if (!jeu) throw new Arret("capture_incomplete", "CP-4", `aucun jeu pour la hauteur ${x.index.block_number}`);
    const v = C.verifierCapture({ index: x.index, lireFichier, validators: { validators: jeu.validators }, bft_chain_id: m.bft_chain_id, schemas: schemas() });
    const e = v.checks.find((r) => r.status !== "reussi");
    if (e) throw new Arret("capture_incomplete", e.check, `${x.nom} : ${e.detail} (EX-9.11)`);
  }
  const dates = [...new Set(choisies.map((x) => x.index.captured_at.slice(0, 10)))].sort();
  const noeuds = [...new Set(choisies.map((x) => x.index.node.validator_id ?? x.index.node.rpc))];
  const parties = C.exporterParties({ captures: choisies.map((x) => ({ index: x.index, lireFichier })), jeux: m.validator_sets, source: `instance ${m.bft_chain_id}, validateur ${noeuds.join(", ")}, captures du ${dates.join(", ")} (CT-4 §9.6)` });
  const fichiers = { "registre.json": [parties.registre, "https://noortrace.example/schemas/v0/registre.schema.json", ""], "certificat-commit.json": [parties.certificat_commit, "https://noortrace.example/schemas/v0/registre.schema.json", "#/$defs/certificat_commit"], "validateurs.json": [parties.validateurs, "https://noortrace.example/schemas/v0/validateurs.schema.json", ""] };
  for (const [nom, [v, id, frag]] of Object.entries(fichiers)) {
    const e = conforme(v, id, frag);
    if (e.length) throw new Arret("capture_incomplete", null, `${nom} non conforme : ${e[0].chemin} : ${e[0].message}`);
  }
  fs.mkdirSync(sortieRep, { recursive: true });
  for (const [nom, [v]] of Object.entries(fichiers)) ecrireSynchronise(path.join(sortieRep, nom), texteJSON(v));
  return { result: "reussi", outputs: { entries: parties.registre.entries.map((x) => ({ role: x.role, block_number: Number(BigInt(x.block.number)) })), certificates: parties.certificat_commit.certificates.map((x) => Number(BigInt(x.height))), files: Object.keys(fichiers).map((n) => path.join(sortieRep, n)) } };
}

// --- verifier ---------------------------------------------------------------

async function cmdVerifier(ctx) {
  const o = ctx.options;
  const instance = chargerInstance(o);
  const m = instance.manifeste;
  const rep = path.resolve(exigerOption(o, "parties"));
  const manifeste = lireJSONFichier(exigerOption(o, "manifeste"));
  const d = o.dossier ? lireDossier(o.dossier) : null;
  const partie = (nom) => (fs.existsSync(path.join(rep, nom)) ? { present: true, octets: fs.readFileSync(path.join(rep, nom)) } : { present: false, raison: "absent du répertoire" });
  const parties = { registre: partie("registre.json"), certificat_commit: partie("certificat-commit.json"), validateurs: partie("validateurs.json") };
  let ancres;
  let source;
  if (o.ancres) {
    ancres = lireJSONFichier(o.ancres);
    const e = conforme(ancres, "https://noortrace.example/schemas/v0/ancres-confiance.schema.json");
    if (e.length) throw new Arret("entree_illisible", null, `fichier d'ancres non conforme : ${e[0].chemin} : ${e[0].message}`);
    source = "fichier_ancres";
  } else {
    const registry = C.ancreRegistreDuManifeste(m, instance.defaut ? "valeurs du réseau de développement (EX-7.2), publication de l'exploitant : ce n'est pas une ancre indépendante (CT-6 §12.5)" : null);
    ancres = { registry, recorders: d ? d.recorders.map((r) => ({ org_id: d.organisation.org_id, journal_id: r.journal_id, key_id: r.key_id, public_key: r.public_key, chain_key: r.chain_key, source: "dossier d'inscription (CT-4 §7.10)" })) : [] };
    source = "publication_exploitant";
  }
  const cles = o.cles ? lireJSONFichier(o.cles).keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key })) : d ? d.recorders.map((r) => ({ key_id: r.key_id, public_key: r.public_key })) : null;
  const r = verifierControle8({ parties, manifeste, periodHash: hachageManifeste(manifeste), cles, ancres, schemas: schemas() });
  const verifications = r.verifications.map((v) => ({ id: v.id, status: v.status, reason: v.reason, detail: v.detail }));
  const out = { anchor_source: source, status: r.statut, summary: r.resume, verifications, n4: r.n4 ? { status: r.n4.status, detail: r.n4.detail } : null, warnings: r.avertissements, statement: r.enonce };
  if (r.statut !== "reussi") return { result: "echoue", outputs: out };
  return { result: "reussi", outputs: out };
}

// --- publier-jeu ------------------------------------------------------------

async function cmdPublierJeu(ctx) {
  const o = ctx.options;
  const fVal = exigerOption(o, "validateurs");
  const val = lireJSONFichier(fVal);
  const depuis = Number(o.depuis ?? 1);
  if (!Number.isSafeInteger(depuis) || depuis < 1) throw new Arret("usage", null, "--depuis : hauteur ≥ 1 (la hauteur 0 est la genèse, jamais décidée)");
  const sortieF = path.resolve(exigerOption(o, "sortie"));
  if (fs.existsSync(sortieF)) throw new Arret("usage", null, `${sortieF} existe déjà`);
  let hachage;
  const validators = Array.isArray(val?.validators) ? val.validators : null;
  if (!validators || validators.length < 4) throw new Arret("entree_illisible", null, "validators.json : au moins quatre validateurs (RG-18, EX-4.11)");
  try {
    hachage = chargerJeuValidateurs({ validators }).hachage;
  } catch (err) {
    throw new Arret("entree_illisible", null, `jeu inexploitable (RG-18) : ${err.message}`);
  }
  const source = `${String(exigerOption(o, "source"))} ; hachage ${hachage}`.slice(0, 512);
  const doc = { version: 0, sets: [{ from_height: depuis, to_height: null, validators: validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source }] };
  const e = conforme(doc, "https://noortrace.example/schemas/v0/validateurs.schema.json");
  if (e.length) throw new Arret("entree_illisible", null, `validateurs-v0 : ${e[0].chemin} : ${e[0].message}`);
  ecrireSynchronise(sortieF, texteJSON(doc));
  return { result: "reussi", outputs: { validator_set_hash: hachage, validators: validators.length, from_height: depuis, file: sortieF } };
}

// ---------------------------------------------------------------------------
// Entrée
// ---------------------------------------------------------------------------

const TABLE = {
  etat: cmdEtat,
  "cles-essai": cmdClesEssai,
  "inscrire-client": cmdInscrireClient,
  approvisionner: cmdApprovisionner,
  condense: cmdCondense,
  signer: cmdSigner,
  "inscrire-cle": cmdInscrireCle,
  "revoquer-cle": cmdRevoquerCle,
  "manifeste-essai": cmdManifesteEssai,
  ancrer: cmdAncrer,
  clore: cmdClore,
  "administrer-jeu": cmdAdministrerJeu,
  reassigner: cmdReassigner,
  capturer: cmdCapturer,
  exporter: cmdExporter,
  verifier: cmdVerifier,
  "publier-jeu": cmdPublierJeu,
};

/**
 * Exécute une commande. `argv` : arguments après le nom du programme ;
 * `flux` : { stdout, stderr } (process par défaut). Rend { code, sortie }.
 */
export async function executer(argv, flux = { stdout: process.stdout, stderr: process.stderr }) {
  const commande = argv[0];
  let ctx = new Contexte(commande ?? "etat", {}, flux);
  let resultat;
  try {
    if (!commande || !TABLE[commande]) throw new Arret("usage", null, `commande inconnue ${JSON.stringify(commande ?? "")} : ${COMMANDES.join(", ")}`);
    const { positionnels, options } = analyserOptions(argv.slice(1));
    ctx = new Contexte(commande, options, flux);
    JETON_BEARER = jetonDe(options);
    const r = await TABLE[commande](ctx, positionnels);
    resultat = sortie(commande, r.result, ctx.checks, null, r.outputs);
  } catch (err) {
    if (err instanceof Arret) {
      resultat = sortie(commande, err.result, ctx.checks, { code: err.code, check: err.check ?? null, message: String(err.message || err.code).slice(0, 2048) }, err.outputs ?? {});
    } else {
      flux.stderr.write(`noortrace-registre : erreur interne : ${err?.stack ?? err}\n`);
      resultat = sortie(commande, "inutilisable", ctx.checks, { code: "entree_illisible", check: null, message: `erreur interne : ${String(err?.message ?? err).slice(0, 1900)}` }, {});
    }
  }
  flux.stdout.write(JSON.stringify(resultat, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
  return { code: resultat.exit_code, sortie: resultat };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  executer(process.argv.slice(2)).then(({ code }) => {
    process.exitCode = code;
  });
}

export { getAddress };
