import { expect } from "chai";
import { network } from "hardhat";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { Wallet } from "ethers";
import { PROJECT_ROOT, deployNoortrace } from "../scripts/lib/noortrace.mjs";
import * as C from "../scripts/lib/conventions-registre.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { executer } from "../scripts/registre/noortrace-registre.mjs";

// Revue de sécurité interne de l'étape 8 : outil de référence du registre
// (scripts/registre/noortrace-registre.mjs). Constats : CT-4 CP-6 (nom de
// fichier venu du point RPC, écriture hors du répertoire des captures), 
// (réponse fausse gardée, captures suivantes bloquées), (réponse RPC
// sans borne, redirections, id non comparé), EX-7.1 (URL à secret dans les
// messages), (administrer-jeu et approvisionner sans confirmation hors
// bande, EX-8.21, TA-73), (reassigner reconnaît le jeu à ses réponses),
// CT-4 OP-4 (provision lue dans le dossier non authentifié), (slug et
// nom de journal dans l'URI d'une clôture, EX-6.8), EX-8.4 (index et envois
// relus sans contrôle), (garde de lancement par un lien symbolique).
//
// Deux bancs : un faux nœud JSON-RPC qui sert la capture réelle des vecteurs de
// CT-6 (spec/vecteurs/ct-6/registre/capture, réseau 2124, menteur sur demande)
// pour la capture ; le réseau Hardhat en mémoire (31337, --sans-capture) derrière
// un pont pour les commandes qui envoient. Chaque règle nouvelle a son mutant :
// copie de scripts/registre/ sous NOORTRACE_TMP, règle retirée par un
// remplacement textuel unique, essai qui échoue par son oracle ; la copie est
// détruite à la fin. Aucun réseau réel, aucune transaction sur 2124.

const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const OUTIL = path.join(PROJECT_ROOT, "scripts", "registre", "noortrace-registre.mjs");
const CAPTURE = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "registre", "capture");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const HEX32 = /^0x[0-9a-f]{64}$/;

let TRAVAIL;
const MUTANTS = [];
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-registre-revue-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
  for (const m of MUTANTS.splice(0)) fs.rmSync(m, { recursive: true, force: true });
});

/** Exécute une commande dans ce processus avec l'`executer` donné ; rend la sortie JSON, plus `stderr`. */
async function lancer(executerFn, args, env = {}) {
  let out = "";
  let err = "";
  const avant = {};
  for (const [k, v] of Object.entries(env)) {
    avant[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    const { code } = await executerFn(args, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) } });
    const s = JSON.parse(out);
    expect(s.exit_code).to.equal(code);
    s.stderr = err;
    s.stdout = out;
    return s;
  } finally {
    for (const [k, v] of Object.entries(avant)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}
const outil = (args, env) => lancer(executer, args, env);

/**
 * Copie mutante de scripts/ sous NOORTRACE_TMP : spec/, hh-artifacts/,
 * node_modules/, package.json et chain/ liés symboliquement, scripts/<dossier>
 * recopié par liens fichier à fichier, le fichier muté recopié avec chaque
 * remplacement { fichier, ancien, nouveau } appliqué une fois exactement.
 */
function racineMutante(nom, remplacements) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-mutant-${nom}-`));
  MUTANTS.push(racine);
  for (const n of ["spec", "hh-artifacts", "node_modules", "package.json", "chain"]) if (fs.existsSync(path.join(PROJECT_ROOT, n))) fs.symlinkSync(path.join(PROJECT_ROOT, n), path.join(racine, n));
  fs.mkdirSync(path.join(racine, "scripts"));
  const mutes = new Set(remplacements.map((r) => r.fichier));
  for (const d of fs.readdirSync(path.join(PROJECT_ROOT, "scripts"))) {
    const de = path.join(PROJECT_ROOT, "scripts", d);
    const vers = path.join(racine, "scripts", d);
    if (![...mutes].some((f) => f.startsWith(`scripts/${d}/`))) {
      fs.symlinkSync(de, vers);
      continue;
    }
    fs.mkdirSync(vers);
    for (const f of fs.readdirSync(de)) {
      const rel = `scripts/${d}/${f}`;
      if (mutes.has(rel)) fs.copyFileSync(path.join(de, f), path.join(vers, f));
      else fs.symlinkSync(path.join(de, f), path.join(vers, f));
    }
  }
  for (const r of remplacements) {
    const f = path.join(racine, r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    expect(texte.split(r.ancien).length, `motif unique dans ${r.fichier} : ${r.ancien.slice(0, 60)}`).to.equal(2);
    fs.writeFileSync(f, texte.replace(r.ancien, r.nouveau));
  }
  return { racine, importer: (rel) => import(pathToFileURL(path.join(racine, rel)).href) };
}

async function executerMutant(nom, ancien, nouveau) {
  const m = racineMutante(nom, [{ fichier: "scripts/registre/noortrace-registre.mjs", ancien, nouveau }]);
  return (await m.importer("scripts/registre/noortrace-registre.mjs")).executer;
}

const fichiersCapture = (rep) => (fs.existsSync(rep) ? fs.readdirSync(rep).filter((f) => /^(bloc|recu|certificat|capture)-/.test(f)).sort() : []);
const tousLesFichiers = (rep) => {
  const out = [];
  const marcher = (r) => {
    for (const e of fs.readdirSync(r, { withFileTypes: true })) {
      const p = path.join(r, e.name);
      if (e.isDirectory()) marcher(p);
      else out.push(path.relative(rep, p));
    }
  };
  marcher(rep);
  return out.sort();
};

// ---------------------------------------------------------------------------
// Faux nœud JSON-RPC : la capture réelle des vecteurs de CT-6 (réseau 2124)
// ---------------------------------------------------------------------------

/** Serveur JSON-RPC qui sert bloc-<h>.json, recu-<t>.json et certificat-<h>.json de la capture ; `crochets` : alterer(method, params, result), envelopper(method, reponse), brut(req, res, requete). */
function fauxNoeud(crochets) {
  const hauteurs = fs.readdirSync(CAPTURE).filter((f) => /^bloc-\d+\.json$/.test(f)).map((f) => Number(f.match(/\d+/)[0])).sort((a, b) => a - b);
  const tete = hauteurs[hauteurs.length - 1];
  const bloc = (h) => (fs.existsSync(path.join(CAPTURE, `bloc-${h}.json`)) ? lireJSON(path.join(CAPTURE, `bloc-${h}.json`)).result : null);
  const recu = (t) => (HEX32.test(t) && fs.existsSync(path.join(CAPTURE, `recu-${t}.json`)) ? lireJSON(path.join(CAPTURE, `recu-${t}.json`)).result : null);
  const cert = (h) => (fs.existsSync(path.join(CAPTURE, `certificat-${h}.json`)) ? lireJSON(path.join(CAPTURE, `certificat-${h}.json`)).result : null);
  const hauteur = (q) => (q === "latest" ? tete : Number(BigInt(q)));
  const repondre = (q) => {
    switch (q.method) {
      case "eth_chainId":
        return "0x84c";
      case "eth_blockNumber":
        return "0x" + tete.toString(16);
      case "noor_txindexStatus":
        return { last_indexed_height: tete };
      case "eth_getCode":
        return "0x6080";
      case "eth_getBlockByNumber":
        return bloc(hauteur(q.params[0]));
      case "eth_getTransactionReceipt":
        return recu(String(q.params[0]).toLowerCase());
      case "eth_getTransactionByHash": {
        const r = recu(String(q.params[0]).toLowerCase());
        return r ? { hash: r.transactionHash, to: r.to, from: r.from, nonce: "0x0", blockNumber: r.blockNumber, blockHash: r.blockHash, input: "0x", type: "0x2" } : null;
      }
      case "noor_getCommitCertificate": {
        const c = cert(hauteur(q.params[0]));
        if (!c) throw Object.assign(new Error("unknown block"), { code: -32000 });
        return c;
      }
      default:
        throw Object.assign(new Error(`${q.method} : méthode non servie par le faux nœud`), { code: -32601 });
    }
  };
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const q = JSON.parse(corps);
    if (crochets.brut && crochets.brut(req, res, q)) return;
    let reponse;
    try {
      let result = repondre(q);
      if (crochets.alterer) result = crochets.alterer(q.method, q.params, result);
      reponse = { jsonrpc: "2.0", id: q.id, result };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: q.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    if (crochets.envelopper) reponse = crochets.envelopper(q.method, reponse);
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve({ serveur, url: `http://127.0.0.1:${serveur.address().port}`, tete })));
}

/** Instance de développement de l'outil sans --instance (EX-7.2) : deployments/noorcore.json synthétisé depuis capture.json, jeu de la capture. */
function environnementCapture(rep) {
  const c = lireJSON(path.join(CAPTURE, "capture.json"));
  const dep = {
    reseau: "noorcore",
    chainId: "2124",
    deployeur: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    contrats: Object.fromEntries(Object.entries(c.code_contrats).map(([n, x]) => [n, { adresse: x.adresse, bloc: x.bloc_deploiement, tx: "0x" + "00".repeat(32) }])),
  };
  fs.mkdirSync(rep, { recursive: true });
  fs.writeFileSync(path.join(rep, "noorcore.json"), JSON.stringify(dep, null, 2));
  return { NOORTRACE_DEPLOYMENTS_DIR: rep, NOORTRACE_VALIDATORS_FILE: path.join(CAPTURE, "validators.json") };
}

const TX_INSCRIPTION = "0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158"; // bloc 16648, rôle inscription
const RECORDER_REGISTRY = "0xbec49fa140acaa83533fb00a2bb19bddd0290f25";

describe("Revue de sécurité de l'étape 8, CT-4 §9.4 : capture sans écriture avant CP-2 à CP-6, noms dérivés de valeurs validées (EX-7.1)", function () {
  this.timeout(120000);
  const crochets = {};
  let noeud;
  let env;

  before(async function () {
    noeud = await fauxNoeud(crochets);
    env = environnementCapture(path.join(TRAVAIL, "deployments"));
  });
  after(function () {
    noeud?.serveur.close();
  });
  afterEach(function () {
    delete crochets.alterer;
    delete crochets.envelopper;
    delete crochets.brut;
  });

  const capturer = (rep, ...reste) => outil(["capturer", "--transaction", TX_INSCRIPTION, "--role", "inscription", "--contrat", RECORDER_REGISTRY, "--captures", rep, "--rpc", noeud.url, ...reste], env);

  it("CT-4 CP-6 : un élément x/../../<chemin> ajouté par un relais menteur dans transactions est refusé en forme (capture_incomplete, CP-2) avant toute écriture : aucun fichier hors du répertoire des captures, aucun bloc, reçu ni certificat gardé ; la capture suivante chez le nœud honnête, dans le même répertoire, réussit (CT-4 CP-6) ; mutant (contrôle de forme retiré) : la capture n'est plus refusée par CP-2", async function () {
    const base = path.join(TRAVAIL, "forme");
    const rep = path.join(base, "captures");
    fs.mkdirSync(rep, { recursive: true });
    const piege = "x/../../hors-des-captures/plante";
    crochets.alterer = (m, p, result) => {
      if (m === "eth_getBlockByNumber" && result && BigInt(result.number) === 16648n) return { ...result, transactions: [...result.transactions, piege] };
      if (m === "eth_getTransactionReceipt" && String(p[0]).toLowerCase() === piege.toLowerCase()) return { ecrit_par: "le relais RPC", contenu: "libre, choisi par le relais" };
      return result;
    };
    const s = await capturer(rep);
    expect(s.result, JSON.stringify(s.error)).to.equal("incertain");
    expect(s.error.code).to.equal("capture_incomplete");
    expect(s.error.check).to.equal("CP-2");
    expect(s.error.message).to.match(/hors de forme/);
    expect(fs.existsSync(path.join(base, "hors-des-captures")), "rien n'est écrit hors du répertoire des captures").to.equal(false);
    expect(fichiersCapture(rep), "aucun bloc, reçu, certificat ni index après l'échec").to.deep.equal([]);
    expect(tousLesFichiers(base).filter((f) => !/^captures\/issue-0x[0-9a-f]{64}\.json$/.test(f)), "seule l'issue connue de la transaction est écrite").to.deep.equal([]);
    // Même répertoire, nœud honnête : la capture passe (aucune réponse fausse ne bloque la hauteur, CT-4 CP-6).
    delete crochets.alterer;
    const h = await capturer(rep);
    expect(h.result, JSON.stringify(h.error)).to.equal("reussi");
    expect(h.outputs.capture).to.equal("capture-16648-0-inscription.json");
    expect(fichiersCapture(rep)).to.deep.equal(["bloc-16648.json", "capture-16648-0-inscription.json", "certificat-16648.json", `recu-${TX_INSCRIPTION}.json`]);
    // Mutant : le contrôle de forme des réponses du nœud retiré ; l'oracle (refus par CP-2, forme) échoue.
    const mutant = await executerMutant("forme-bloc", "    const motif = motifForme(r.valeur.result);\n    if (motif) throw new Arret(\"capture_incomplete\", check, `${nom} : réponse de ${vueUrl} hors de forme (${motif}) ; rien n'est écrit`, incertain);", "    const motif = null;\n    if (motif) throw new Arret(\"capture_incomplete\", check, `${nom}`, incertain);");
    crochets.alterer = (m, p, result) => (m === "eth_getBlockByNumber" && result && BigInt(result.number) === 16648n ? { ...result, transactions: [...result.transactions, piege] } : result);
    const sm = await lancer(mutant, ["capturer", "--transaction", TX_INSCRIPTION, "--role", "inscription", "--contrat", RECORDER_REGISTRY, "--captures", path.join(TRAVAIL, "forme-mutant"), "--rpc", noeud.url], env);
    expect(sm.error?.check === "CP-2" && /hors de forme/.test(sm.error?.message ?? ""), `mutant : refus de forme attendu par l'oracle, obtenu ${JSON.stringify(sm.error)} (le mutant est tué)`).to.equal(false);
  });

  it("CT-4 CP-6 : un reçu altéré par le nœud (CP-3 en échec) ne laisse aucun fichier ; un bloc présent mais faux ou illisible est mis de côté (ecarte-<instant>-<nom>) et redemandé, la capture réussit ; mutants (échec de vérification ignoré ; mise de côté retirée) : tués par l'oracle", async function () {
    const rep = path.join(TRAVAIL, "recu", "captures");
    fs.mkdirSync(rep, { recursive: true });
    // Reçu altéré (journal modifié) : la racine des reçus ne correspond plus (CP-3) ; rien n'est gardé.
    crochets.alterer = (m, p, result) => (m === "eth_getTransactionReceipt" && result && result.transactionHash === TX_INSCRIPTION ? { ...result, logs: [{ ...result.logs[0], data: "0x" + "ab".repeat(64) }] } : result);
    const s = await capturer(rep);
    expect(s.result, JSON.stringify(s.error)).to.equal("incertain");
    expect(s.error.code).to.equal("capture_incomplete");
    expect(s.error.check).to.equal("CP-3");
    expect(fichiersCapture(rep), "rien n'est écrit quand CP-2 à CP-6 échouent").to.deep.equal([]);
    delete crochets.alterer;
    // Bloc présent mais faux (l'en-tête de 16652 sous le nom de 16648) : mis de côté, redemandé, capture réussie.
    const faux = lireJSON(path.join(CAPTURE, "bloc-16652.json"));
    faux.result.number = "0x4108";
    fs.writeFileSync(path.join(rep, "bloc-16648.json"), JSON.stringify(faux));
    const a = await capturer(rep);
    expect(a.result, JSON.stringify(a.error)).to.equal("reussi");
    const ecartes = fs.readdirSync(rep).filter((f) => /^ecarte-[0-9TZ]+-bloc-16648\.json$/.test(f));
    expect(ecartes, "le fichier faux est mis de côté").to.have.length(1);
    expect(JSON.parse(fs.readFileSync(path.join(rep, ecartes[0]), "utf8")).result.hash).to.equal(faux.result.hash);
    expect(lireJSON(path.join(rep, "bloc-16648.json")).result.hash).to.equal(lireJSON(path.join(CAPTURE, "bloc-16648.json")).result.hash);
    expect(a.stderr).to.match(/mis de côté/);
    // Reçu présent mais illisible (JSON tronqué) : mis de côté sans exception, capture réussie dans un répertoire neuf.
    const rep2 = path.join(TRAVAIL, "recu", "captures-2");
    fs.mkdirSync(rep2, { recursive: true });
    fs.writeFileSync(path.join(rep2, `recu-${TX_INSCRIPTION}.json`), '{"jsonrpc":"2.0","id":1,"result":{"tronqu');
    const b = await capturer(rep2);
    expect(b.result, JSON.stringify(b.error)).to.equal("reussi");
    expect(fs.readdirSync(rep2).filter((f) => f.startsWith("ecarte-"))).to.have.length(1);
    expect(b.stderr).to.match(/JSON illisible/);
    // Mutant 1 : l'échec de la vérification n'arrête plus la capture ; des fichiers sont écrits malgré CP-3 (oracle : aucun fichier).
    const m1 = await executerMutant("echec-ignore", "    throw new Arret(enEchec.code, enEchec.check, enEchec.detail, incertain);\n  }\n  const { index, nomIdx, v } = r;", "    break;\n  }\n  const { index, nomIdx, v } = r;");
    crochets.alterer = (m, p, result) => (m === "eth_getTransactionReceipt" && result && result.transactionHash === TX_INSCRIPTION ? { ...result, logs: [{ ...result.logs[0], data: "0x" + "ab".repeat(64) }] } : result);
    const repM1 = path.join(TRAVAIL, "recu", "mutant-1");
    const sm1 = await lancer(m1, ["capturer", "--transaction", TX_INSCRIPTION, "--role", "inscription", "--contrat", RECORDER_REGISTRY, "--captures", repM1, "--rpc", noeud.url], env);
    expect(sm1.result === "incertain" && fichiersCapture(repM1).length === 0, `mutant 1 : résultat ${sm1.result}, fichiers ${fichiersCapture(repM1).join(", ")} (le mutant est tué)`).to.equal(false);
    delete crochets.alterer;
    // Mutant 2 : la mise de côté retirée ; le bloc faux présent fait échouer la capture (oracle : réussite).
    const m2 = await executerMutant("sans-mise-de-cote", "    if (passe === 1 && relus.length) {", "    if (false && passe === 1 && relus.length) {");
    const repM2 = path.join(TRAVAIL, "recu", "mutant-2");
    fs.mkdirSync(repM2, { recursive: true });
    fs.writeFileSync(path.join(repM2, "bloc-16648.json"), JSON.stringify(faux));
    const sm2 = await lancer(m2, ["capturer", "--transaction", TX_INSCRIPTION, "--role", "inscription", "--contrat", RECORDER_REGISTRY, "--captures", repM2, "--rpc", noeud.url], env);
    expect(sm2.result, `mutant 2 : ${JSON.stringify(sm2.error)} (le mutant est tué)`).to.not.equal("reussi");
  });

  it("rpcBrut compare l'id de la réponse à celui de la requête, ne suit aucune redirection et borne la réponse ; une réponse hostile rend noeud_injoignable (code 2), jamais une erreur interne ; mutant (id non comparé) : le nœud menteur est accepté", async function () {
    crochets.envelopper = (m, r) => ({ ...r, id: 7777 });
    const s1 = await outil(["etat", "--rpc", noeud.url], env);
    expect(s1.result, JSON.stringify(s1.error)).to.equal("inutilisable");
    expect(s1.error.code).to.equal("noeud_injoignable");
    expect(s1.error.message).to.match(/identifiant de réponse/);
    delete crochets.envelopper;
    crochets.brut = (req, res) => {
      res.statusCode = 302;
      res.setHeader("Location", `${noeud.url}/ailleurs`);
      res.end();
      return true;
    };
    const s2 = await outil(["etat", "--rpc", noeud.url], env);
    expect(s2.error?.code, JSON.stringify(s2.error)).to.equal("noeud_injoignable");
    expect(s2.error.message).to.match(/injoignable/);
    crochets.brut = (req, res) => {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Length", String(64 * 1024 * 1024 + 1));
      res.write('{"jsonrpc":"2.0","id":1,"result":"0x84c"}');
      setTimeout(() => res.destroy(), 500);
      return true;
    };
    const s3 = await outil(["etat", "--rpc", noeud.url], env);
    expect(s3.error?.code, JSON.stringify(s3.error)).to.equal("noeud_injoignable");
    expect(s3.error.message).to.match(/au-delà de|interrompue/);
    delete crochets.brut;
    // Témoin : le même nœud, honnête, est accepté.
    const t = await outil(["etat", "--rpc", noeud.url], env);
    expect(t.result, JSON.stringify(t.error)).to.equal("reussi");
    expect(t.outputs.height).to.equal(noeud.tete);
    // Mutant : la comparaison de l'id retirée ; le nœud qui ment sur l'id est accepté (oracle : refus).
    const mutant = await executerMutant("id-rpc", "  if (valeur.id !== id) throw new ErreurRPC(", "  if (false && valeur.id !== id) throw new ErreurRPC(");
    crochets.envelopper = (m, r) => ({ ...r, id: 7777 });
    const sm = await lancer(mutant, ["etat", "--rpc", noeud.url], env);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("noeud_injoignable");
  });

  it("CT-4 EX-7.1 : une URL --rpc qui porte des identifiants ou une chaîne de requête est refusée (usage) avant tout appel et ni la sortie ni les messages ne la recopient ; un nœud injoignable n'écrit que l'URL sans secret ; mutant (refus retiré) : plus de refus usage", async function () {
    const secret = "motdepasse-tres-secret";
    const s = await outil(["etat", "--rpc", `http://operateur:${secret}@127.0.0.1:1/rpc?jeton=jeton-secret`], env);
    expect(s.result).to.equal("inutilisable");
    expect(s.error.code).to.equal("usage");
    expect(s.stdout).to.not.include(secret);
    expect(s.stdout).to.not.include("jeton-secret");
    expect(s.stderr).to.not.include(secret);
    const s2 = await outil(["etat", "--rpc", "http://127.0.0.1:1"], env);
    expect(s2.error?.code).to.equal("noeud_injoignable");
    expect(s2.error.message).to.include("http://127.0.0.1:1");
    const mutant = await executerMutant("url-secret", "    if (x.username || x.password || x.search) throw new Arret(\"usage\", null, `--rpc : ${urlSansSecret(u)} porte des identifiants", "    if (false) throw new Arret(\"usage\", null, `--rpc : ${urlSansSecret(u)} porte des identifiants");
    const sm = await lancer(mutant, ["etat", "--rpc", `http://operateur:${secret}@127.0.0.1:1/rpc`], env);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("usage");
    expect(sm.stdout, "même muté, l'URL n'est écrite que sans secret (urlSansSecret)").to.not.include(secret);
  });

  it("lancé par un chemin qui passe par un lien symbolique, l'outil s'exécute (sortie JSON usage, code 2) au lieu de rendre 0 sans rien faire", function () {
    const lien = path.join(TRAVAIL, "lien-depot");
    fs.symlinkSync(PROJECT_ROOT, lien);
    const r = spawnSync(process.execPath, [path.join(lien, "scripts", "registre", "noortrace-registre.mjs")], { encoding: "utf8", cwd: PROJECT_ROOT });
    expect(r.status, r.stderr).to.equal(2);
    expect(JSON.parse(r.stdout).error.code).to.equal("usage");
  });
});

// ---------------------------------------------------------------------------
// Réseau Hardhat en mémoire (31337), derrière un pont (EX-A.6)
// ---------------------------------------------------------------------------

/** Pont HTTP vers le fournisseur EIP-1193 de Hardhat ; `synthese(method, params)` répond avant le fournisseur quand elle rend autre chose qu'undefined. */
function pont(provider, synthese) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const r = JSON.parse(corps);
    let reponse;
    try {
      const s = synthese ? await synthese(r.method, r.params) : undefined;
      const result = s !== undefined ? s : await provider.request({ method: r.method, params: r.params });
      reponse = { jsonrpc: "2.0", id: r.id, result };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: r.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

/** Manifeste d'essai de l'instance Hardhat (EX-A.6), même forme que test/registreCt4.test.js. */
function manifesteEssai(E, deploiement, validators, fees = C.FRAIS_DEFAUT) {
  const deployeur = deploiement.deployeur.toLowerCase();
  const genese = { chainId: 31337, alloc: [{ address: deployeur, balanceWei: "10000000000000000000000" }], rules: { chainId: "noortrace-31337-essai", ...C.REGLES_SANS_EMISSION } };
  fs.writeFileSync(path.join(E, "genese.json"), JSON.stringify(genese, null, 2) + "\n");
  const csr = deploiement.contrats.CuratorSetRegistry.adresse.toLowerCase();
  const manifeste = {
    version: 0,
    revision: 1,
    previous_sha256: null,
    published_at: "2026-11-13T00:00:00.000Z",
    nature: "developpement",
    bft_chain_id: "noortrace-31337-essai",
    evm_chain_id: 31337,
    evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-11-13T00:00:00.000Z", source: "réseau Hardhat en mémoire des tests (CT-4 EX-A.6)" },
    genesis: { file: "genese.json", sha256: J.sha256(fs.readFileSync(path.join(E, "genese.json"))), rules_line: C.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
    noorcore: { repository: "https://github.com/noorfinances-eng/noorchain-core", commit: "618fcef8805ef5b4cb9291a3dd97be710e489297", go_version: "1.26.9", patches: [], artifacts: [{ kind: "binaire", name: "sans objet : réseau Hardhat", sha256: C.HACHAGE_NUL, build: "sans objet" }] },
    validator_sets: [{ from_height: 1, to_height: null, validators, source: "jeu du réseau de développement, sans effet sur le réseau Hardhat", valset_hash: C.hachageJeuValidateurs(validators), operators: validators.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: null })) }],
    fees: { ...fees },
    contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n, i) => ({ name: n, address: deploiement.contrats[n].adresse.toLowerCase(), deployer: deployeur, nonce: i, constructor_args: n === "AttestationRegistry" ? [] : n === "CuratorSetRegistry" ? [deployeur] : [csr], transaction_hash: deploiement.contrats[n].tx, block_number: deploiement.contrats[n].bloc, block_hash: null, evidence: null, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
    source: "manifeste d'essai du réseau Hardhat en mémoire (CT-4 EX-A.6)",
  };
  return manifeste;
}

describe("Revue de sécurité de l'étape 8, CT-4 §7 et §8 sur le réseau Hardhat en mémoire : confirmation hors bande (EX-8.21), provision recalculée (OP-4), URI (EX-6.8), index relus (EX-8.4), code du jeu", function () {
  this.timeout(300000);
  let conn;
  let srv;
  let url;
  let E;
  let instance;
  let manifeste;
  let deploiement;
  let confirmation;
  let dossier;
  let caps;
  let jeuValidateurs;
  const R = (args, env) => outil([...args, "--instance", instance, "--rpc", url, "--sans-capture"], env);
  const Rcap = (args) => outil([...args, "--instance", instance, "--rpc", url]);
  const cle = (nom) => `fichier:${path.join(E, "cles", `${nom}.cle`)}`;
  const attendreRefus = (s, code, result = "refuse") => {
    expect(s.result, JSON.stringify(s.error)).to.equal(result);
    expect(s.error?.code, JSON.stringify(s.error)).to.equal(code);
  };
  const attendreReussite = (s, result = "reussi") => {
    expect(s.result, JSON.stringify(s.error)).to.equal(result);
    expect(s.error).to.equal(null);
  };

  before(async function () {
    conn = await network.create();
    await conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
    ({ deployment: deploiement } = await deployNoortrace(conn.ethers, { networkName: "essai-revue-l13" }));
    E = path.join(TRAVAIL, "hardhat");
    fs.mkdirSync(E, { recursive: true });
    jeuValidateurs = lireJSON(path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json")).validators;
    manifeste = manifesteEssai(E, deploiement, jeuValidateurs);
    instance = path.join(E, "instance.json");
    fs.writeFileSync(instance, JSON.stringify(manifeste, null, 2) + "\n");
    // Synthèse minimale pour une commande qui lit sans --sans-capture : certificat de la tête et index du nœud (OP-1, OP-2).
    const synthese = async (method) => {
      if (method === "noor_getCommitCertificate") return { height: 1, chainId: "noortrace-31337-essai", valsetHash: manifeste.validator_sets[0].valset_hash, retention: { heights: 300000, pruned: false } };
      if (method === "noor_txindexStatus") return { last_indexed_height: Number(BigInt(await conn.provider.request({ method: "eth_blockNumber", params: [] }))) };
      return undefined;
    };
    ({ serveur: srv, url } = await pont(conn.provider, synthese));
    confirmation = path.join(E, "confirmation-hors-bande.txt");
    fs.writeFileSync(confirmation, "Confirmation hors bande du client essai-revue-l13 (CT-4 EX-8.21), consignée pour l'essai.\n");
    // Client inscrit : clés d'essai, dossier préparé et exécuté, clé inscrite (7.5 à 7.7).
    attendreReussite(await R(["cles-essai", "--sortie", path.join(E, "cles")]));
    dossier = path.join(E, "dossier.json");
    caps = path.join(E, "captures");
    attendreReussite(await R(["inscrire-client", "--preparer", "--org", "essai-revue-l13", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", dossier]));
    attendreReussite(await R(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps]));
    const dem = path.join(E, "demande-inscription.json");
    attendreReussite(await R(["condense", "inscription", "--dossier", dossier, "--key-id", "rec-essai-01", "--sortie", dem]));
    for (const i of [1, 2]) attendreReussite(await outil(["signer", "--demande", dem, "--cle", cle(`approbateur-${i}`)]));
    attendreReussite(await R(["inscrire-cle", "--demande", dem, "--cle-chaine", cle("cle-chaine-rec-essai-01"), "--dossier", dossier, "--captures", caps]));
  });

  after(function () {
    srv?.close();
  });

  /** Demande administration_jeu signée par l'administrateur du jeu, prête à relayer. */
  async function demandeAdministration(nom, seuil) {
    const d = lireJSON(dossier);
    const set = d.steps.find((s) => s.step === "jeu_approbateurs").contract;
    const f = path.join(E, `${nom}.json`);
    attendreReussite(await R(["condense", "administration_jeu", "--jeu", set, "--op", "CuratorSet.setThreshold", "--arg", String(seuil), "--sortie", f]));
    attendreReussite(await outil(["signer", "--demande", f, "--cle", cle("admin-jeu")]));
    return { f, set };
  }

  it("CT-4 EX-8.21, TA-73 : administrer-jeu et approvisionner exigent --confirmation <fichier> non vide (usage sinon, rien n'est relayé) et consignent son SHA-256 dans outputs.confirmation_sha256 ; mutant (exigence retirée d'administrer-jeu) : relais sans confirmation", async function () {
    const { f: dem, set } = await demandeAdministration("demande-admin-1", 3);
    const sans = await R(["administrer-jeu", "--demande", dem, "--relayeur", "hardhat:0", "--captures", caps]);
    attendreRefus(sans, "usage", "inutilisable");
    expect(sans.error.message).to.include("--confirmation");
    expect(await (await conn.ethers.getContractAt("CuratorSet", set)).getThreshold(), "rien n'est relayé sans confirmation").to.equal(2n);
    const vide = path.join(E, "confirmation-vide.txt");
    fs.writeFileSync(vide, "");
    attendreRefus(await R(["administrer-jeu", "--demande", dem, "--relayeur", "hardhat:0", "--captures", caps, "--confirmation", vide]), "entree_illisible", "inutilisable");
    const avec = await R(["administrer-jeu", "--demande", dem, "--relayeur", "hardhat:0", "--captures", caps, "--confirmation", confirmation]);
    attendreReussite(avec);
    expect(avec.outputs.confirmation_sha256).to.equal(J.sha256(fs.readFileSync(confirmation)));
    expect(await (await conn.ethers.getContractAt("CuratorSet", set)).getThreshold()).to.equal(3n);
    // approvisionner : même exigence, consignée aussi quand rien n'est versé (deja_fait).
    const d = lireJSON(dossier);
    const vers = d.recorders[0].chain_key;
    attendreRefus(await R(["approvisionner", "--vers", vers, "--dossier", dossier, "--tresorerie", "hardhat:0", "--captures", caps]), "usage", "inutilisable");
    const ap = await R(["approvisionner", "--vers", vers, "--dossier", dossier, "--tresorerie", "hardhat:0", "--captures", caps, "--confirmation", confirmation]);
    attendreReussite(ap, "deja_fait");
    expect(ap.outputs.confirmation_sha256).to.equal(J.sha256(fs.readFileSync(confirmation)));
    // Mutant : l'exigence retirée d'administrer-jeu ; une demande valide sans confirmation est relayée (oracle : usage).
    const { f: dem2 } = await demandeAdministration("demande-admin-2", 2);
    const mutant = await executerMutant("confirmation", "async function cmdAdministrerJeu(ctx) {\n  const o = ctx.options;\n  const confirmationSha256 = confirmationHorsBande(o);", "async function cmdAdministrerJeu(ctx) {\n  const o = ctx.options;\n  const confirmationSha256 = null;");
    const sm = await lancer(mutant, ["administrer-jeu", "--demande", dem2, "--relayeur", "hardhat:0", "--captures", caps, "--instance", instance, "--rpc", url, "--sans-capture"]);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("usage");
    expect(sm.result).to.equal("reussi");
  });

  it("CT-4 EX-4.19, EX-4.20, EX-8.20 : inscrire-client recalcule la provision depuis fees du manifeste : amount_wei altéré → provision_excessive (OP-4), funder qui n'est pas la trésorerie → compte_inattendu (OP-4), budget au-delà de fees.max_daily_budget_gas → provision_excessive (--preparer comme --dossier), rien n'est envoyé ; le dossier honnête passe, avec les frais propres de l'instance ; mutant (frais du manifeste non passés à OP-4 de la bibliothèque) : le dossier honnête est refusé", async function () {
    const prep = path.join(E, "dossier-provision.json");
    attendreReussite(await R(["inscrire-client", "--preparer", "--org", "essai-provision", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", prep]));
    const honnete = lireJSON(prep);
    expect(BigInt(honnete.funding.amount_wei)).to.equal(C.provision(manifeste.fees, honnete.funding.daily_budget_gas).provision_wei);
    const altere = (f, modifier) => {
      const d = JSON.parse(JSON.stringify(honnete));
      modifier(d);
      fs.writeFileSync(f, JSON.stringify(d, null, 2) + "\n");
      return f;
    };
    const capsB = path.join(E, "captures-provision");
    const m1 = altere(path.join(E, "dossier-provision-montant.json"), (d) => (d.funding.amount_wei = (BigInt(d.funding.amount_wei) * 1000n).toString()));
    const s1 = await R(["inscrire-client", "--dossier", m1, "--exploitant", "hardhat:0", "--captures", capsB]);
    attendreRefus(s1, "provision_excessive");
    expect(s1.error.check).to.equal("OP-4");
    expect(lireJSON(m1).steps.every((s) => s.state === "a_faire"), "aucune étape envoyée").to.equal(true);
    const m2 = altere(path.join(E, "dossier-provision-funder.json"), (d) => (d.funding.funder = Wallet.createRandom().address.toLowerCase()));
    const s2 = await R(["inscrire-client", "--dossier", m2, "--exploitant", "hardhat:0", "--captures", capsB]);
    attendreRefus(s2, "compte_inattendu");
    expect(s2.error.check).to.equal("OP-4");
    // Plafond du manifeste : budget 1 000 gaz contre max_daily_budget_gas 500, à l'exécution et à la préparation.
    const plafonne = path.join(E, "instance-plafond.json");
    fs.writeFileSync(plafonne, JSON.stringify({ ...manifeste, fees: { ...manifeste.fees, max_daily_budget_gas: 500 } }) + "\n");
    const m3 = altere(path.join(E, "dossier-provision-budget.json"), (d) => {
      d.funding.daily_budget_gas = 1000;
      d.funding.amount_wei = C.provision(manifeste.fees, 1000).provision_wei.toString();
    });
    const s3 = await outil(["inscrire-client", "--dossier", m3, "--exploitant", "hardhat:0", "--captures", capsB, "--instance", plafonne, "--rpc", url, "--sans-capture"]);
    attendreRefus(s3, "provision_excessive");
    expect(s3.error.message).to.include("max_daily_budget_gas");
    const s4 = await outil(["inscrire-client", "--preparer", "--org", "essai-provision-plafond", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--budget-jour", "1000", "--sortie", path.join(E, "dossier-provision-plafond.json"), "--instance", plafonne, "--rpc", url, "--sans-capture"]);
    attendreRefus(s4, "provision_excessive");
    expect(fs.existsSync(path.join(E, "dossier-provision-plafond.json"))).to.equal(false);
    // Le dossier honnête est exécuté : la provision versée est celle recalculée.
    const ok = await R(["inscrire-client", "--dossier", prep, "--exploitant", "hardhat:0", "--captures", capsB]);
    attendreReussite(ok);
    const verse = ok.outputs.funded.find((x) => x.chain_key === honnete.recorders[0].chain_key);
    expect(BigInt(verse.amount_wei ?? "0") + BigInt(await conn.provider.request({ method: "eth_getBalance", params: [honnete.recorders[0].chain_key, "latest"] })) >= BigInt(honnete.funding.amount_wei)).to.equal(true);
    // Frais propres à l'instance (gas_limit 2 000 000, provision_days 10) : la provision est recalculée avec eux, à la préparation
    // comme à l'exécution, et la bibliothèque (OP-4, part de la référence) reçoit fees et tresorerie du manifeste : le dossier honnête passe.
    const feesInstance = { ...manifeste.fees, gas_limit: 2000000, provision_days: 10 };
    const instanceFrais = path.join(E, "instance-frais.json");
    fs.writeFileSync(instanceFrais, JSON.stringify({ ...manifeste, fees: feesInstance }) + "\n");
    const prepF = path.join(E, "dossier-provision-frais.json");
    const Rf = (args) => outil([...args, "--instance", instanceFrais, "--rpc", url, "--sans-capture"]);
    attendreReussite(await Rf(["inscrire-client", "--preparer", "--org", "essai-provision-frais", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", prepF]));
    const dF = lireJSON(prepF);
    expect(BigInt(dF.funding.amount_wei)).to.equal(C.provision(feesInstance, dF.funding.daily_budget_gas).provision_wei);
    expect(BigInt(dF.funding.amount_wei)).to.not.equal(C.provision(manifeste.fees, dF.funding.daily_budget_gas).provision_wei);
    const okF = await Rf(["inscrire-client", "--dossier", prepF, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures-provision-frais")]);
    attendreReussite(okF);
    // Mutant : les frais du manifeste ne sont plus passés à OP-4 de la bibliothèque, qui recalcule alors la provision avec ses
    // frais par défaut ; le dossier honnête de l'instance à frais propres est refusé (oracle : reussi). Le mutant qui retire le
    // recalcul propre à l'outil (provisionDuDossier) n'est pas tué par cet oracle : la bibliothèque refuse le même dossier
    // (défense à deux points, part de la référence) ; il est consigné au rapport, pas joué ici.
    const mutant = await executerMutant("fees-op4", "function optionsProvision(m) {\n  const o = {};\n  if (m?.fees) o.fees = m.fees;", "function optionsProvision(m) {\n  const o = {};\n  if (false) o.fees = m.fees;");
    const prepM = path.join(E, "dossier-provision-frais-mutant.json");
    attendreReussite(await Rf(["inscrire-client", "--preparer", "--org", "essai-provision-frais-mutant", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", prepM]));
    const sm = await lancer(mutant, ["inscrire-client", "--dossier", prepM, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures-provision-frais-mutant"), "--instance", instanceFrais, "--rpc", url, "--sans-capture"]);
    expect(sm.result, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("reussi");
  });

  it("CT-4 EX-6.8 : condense cloture refuse une --uri non vide sans --dossier (usage) et, avec le dossier, une URI qui porte le slug ou le nom du journal (periode_invalide, OP-10) ; l'URI vide passe RG-5 ; clore applique la même règle ; mutant (contexte du dossier non passé à RG-5) : l'URI au slug est admise", async function () {
    const d = lireJSON(dossier);
    const t = Math.floor(Date.now() / 1000);
    const man = J.construireManifeste({ org_id: d.organisation.org_id, journal_id: d.journals[0].journal_id, period_start: t - (t % 3600) - 3600, first_seq: 1, hashes: [J.sha256(Buffer.from("a")), J.sha256(Buffer.from("b"))], prev_period_hash: C.HACHAGE_NUL, recorder_key_id: "rec-essai-01", nonce: "0x" + "11".repeat(32), generated_at: new Date().toISOString() });
    const fMan = path.join(E, "manifeste-uri.json");
    fs.writeFileSync(fMan, JSON.stringify(man, null, 2) + "\n");
    const uri = `s3://${d.organisation.slug}/${d.journals[0].name}/p1`;
    const sortie = (n) => path.join(E, `demande-cloture-uri-${n}.json`);
    const s1 = await R(["condense", "cloture", "--manifeste", fMan, "--uri", uri, "--captures", caps, "--sortie", sortie(1)]);
    attendreRefus(s1, "usage", "inutilisable");
    expect(s1.error.message).to.include("--dossier");
    const s2 = await R(["condense", "cloture", "--manifeste", fMan, "--uri", uri, "--dossier", dossier, "--captures", caps, "--sortie", sortie(2)]);
    attendreRefus(s2, "periode_invalide");
    expect(s2.error.check).to.equal("OP-10");
    expect(s2.error.message).to.match(/slug|journal/);
    const s3 = await R(["condense", "cloture", "--manifeste", fMan, "--uri", `s3://x/${d.journals[0].name}/p1`, "--dossier", dossier, "--captures", caps, "--sortie", sortie(3)]);
    attendreRefus(s3, "periode_invalide");
    // URI vide : RG-5 passe, OP-10 continue jusqu'à l'ancre (absente ici).
    const s4 = await R(["condense", "cloture", "--manifeste", fMan, "--dossier", dossier, "--captures", caps, "--sortie", sortie(4)]);
    attendreRefus(s4, "ancre_manquante");
    // clore : même règle sur une demande dont le PeriodMeta porte l'URI au slug (demande fabriquée, signée au seuil).
    const meta = C.metaDuManifeste(man, uri);
    const set = d.steps.find((s) => s.step === "jeu_approbateurs").contract;
    const b = await conn.provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] });
    const demande = { version: 0, operation: "cloture", evm_chain_id: 31337, contract: manifeste.contracts[2].address, fields: { period_meta: meta }, digest: null, eip191_digest: null, signer_set: { curator_set: set, threshold: 3, height: Number(BigInt(b.number)), block_hash: String(b.hash).toLowerCase() }, signatures: [], prepared_at: new Date().toISOString(), expires_at: new Date(Date.now() + 86400000).toISOString() };
    const calc = C.condenseDeDemande(demande);
    const fDem = path.join(E, "demande-cloture-uri-clore.json");
    fs.writeFileSync(fDem, JSON.stringify({ ...demande, digest: calc.digest, eip191_digest: calc.eip191_digest }, null, 2) + "\n");
    for (const i of [1, 2, 3]) attendreReussite(await outil(["signer", "--demande", fDem, "--cle", cle(`approbateur-${i}`)]));
    const s5 = await R(["clore", "--demande", fDem, "--manifeste", fMan, "--cle-chaine", cle("cle-chaine-rec-essai-01"), "--dossier", dossier, "--captures", caps]);
    attendreRefus(s5, "periode_invalide");
    expect(s5.error.check).to.equal("OP-10");
    // Mutant : le slug et le nom du journal ne sont plus passés à RG-5 ; l'URI au slug est admise par OP-10 (oracle : periode_invalide).
    const mutant = await executerMutant("uri", "        const r = C.verifier(\"RG-5\", () => C.verifierChampsCloture(meta, { precedente, ...contexteUri }));", "        const r = C.verifier(\"RG-5\", () => C.verifierChampsCloture(meta, { precedente }));");
    const sm = await lancer(mutant, ["condense", "cloture", "--manifeste", fMan, "--uri", uri, "--dossier", dossier, "--captures", caps, "--sortie", sortie(5), "--instance", instance, "--rpc", url, "--sans-capture"]);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("periode_invalide");
  });

  it("CT-4 EX-8.4 : un index de capture déposé dans --captures, conforme au schéma mais dont les fichiers ne passent pas CP-2 à CP-6, ne vaut pas « ancre capturée » pour condense cloture (ancre_manquante) ; un index ou un envoi illisible ne lève jamais (avertissement, entree_illisible pour un envoi) ; mutant (index relu non vérifié) : la demande de clôture est préparée", async function () {
    // Ancre incluse (sans capture, réseau Hardhat) pour le manifeste d'essai de rec-essai-01.
    const per = path.join(E, "periode-index");
    const me = await R(["manifeste-essai", "--dossier", dossier, "--key-id", "rec-essai-01", "--graine", `graine:${path.join(E, "cles", "rec-essai-01.graine")}`, "--sortie", per]);
    attendreReussite(me);
    const fMan = path.join(per, "manifeste.json");
    const capsB = path.join(E, "captures-index");
    const an = await R(["ancrer", "--manifeste", fMan, "--cle-chaine", cle("cle-chaine-rec-essai-01"), "--dossier", dossier, "--captures", capsB]);
    attendreReussite(an);
    const h = an.outputs.block_number;
    const tx = an.outputs.transaction_hash;
    const att = manifeste.contracts[0].address;
    // Index forgé : conforme à operations-registre-v0, fichiers présents aux SHA-256 annoncés, mais aucun n'est une réponse du nœud certifiée.
    const ecrire = (nom, v) => {
      const b = Buffer.from(JSON.stringify(v));
      fs.writeFileSync(path.join(capsB, nom), b);
      return J.sha256(b);
    };
    const recuForge = { jsonrpc: "2.0", id: 1, result: { transactionHash: tx, blockNumber: C.quantiteRPC(h), blockHash: "0x" + "22".repeat(32), status: "0x1", logs: [{ address: att, topics: [C.EVENEMENTS.Anchored.topic, me.outputs.fingerprint, "0x" + "00".repeat(12) + lireJSON(dossier).recorders[0].chain_key.slice(2), C.DOC_TYPE_PERIODE], data: "0x", logIndex: "0x0" }] } };
    const index = {
      version: 0,
      role: "ancre",
      evm_chain_id: 31337,
      bft_chain_id: "noortrace-31337-essai",
      contract: att,
      transaction_hash: tx,
      block_number: h,
      block_hash: "0x" + "22".repeat(32),
      transaction_index: 0,
      log_index: 0,
      files: {
        block: { name: `bloc-${h}.json`, sha256: ecrire(`bloc-${h}.json`, { jsonrpc: "2.0", id: 1, result: { number: C.quantiteRPC(h), hash: "0x" + "22".repeat(32), transactions: [tx] } }) },
        receipts: [{ name: `recu-${tx}.json`, sha256: ecrire(`recu-${tx}.json`, recuForge) }],
        certificate: { name: `certificat-${h}.json`, sha256: ecrire(`certificat-${h}.json`, { jsonrpc: "2.0", id: 1, result: { height: h, chainId: "noortrace-31337-essai", valsetHash: manifeste.validator_sets[0].valset_hash } }) },
      },
      node: { rpc: url, validator_id: null },
      validator_set_hash: manifeste.validator_sets[0].valset_hash,
      captured_at: new Date().toISOString(),
      attempts: 1,
      checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })),
      sending: null,
    };
    const nomIdx = C.nomIndex(h, 0, "ancre");
    fs.writeFileSync(path.join(capsB, nomIdx), JSON.stringify(index, null, 2));
    // Index et envoi illisibles à côté : écartés avec un avertissement (index), refus nommé pour un envoi (OP-3).
    fs.writeFileSync(path.join(capsB, "capture-7-0-approvisionnement.json"), "{ tronqué");
    const sansCapture = await Rcap(["condense", "cloture", "--manifeste", fMan, "--dossier", dossier, "--captures", capsB, "--sortie", path.join(E, "demande-cloture-index.json")]);
    attendreRefus(sansCapture, "ancre_manquante");
    expect(sansCapture.error.check).to.equal("OP-10");
    expect(sansCapture.error.message).to.include("sans index de capture");
    expect(sansCapture.stderr).to.match(/avertissement : index .* écarté/);
    expect(fs.existsSync(path.join(E, "demande-cloture-index.json")), "aucune demande préparée").to.equal(false);
    // Envoi illisible : une commande qui envoie le refuse par un statut (entree_illisible, OP-3), jamais une erreur interne.
    fs.writeFileSync(path.join(capsB, `envoi-0x${"ab".repeat(32)}.json`), "pas du JSON");
    const { f: dem } = await demandeAdministration("demande-admin-index", 2);
    const env = await R(["administrer-jeu", "--demande", dem, "--relayeur", "hardhat:0", "--captures", capsB, "--confirmation", confirmation]);
    attendreRefus(env, "entree_illisible", "inutilisable");
    expect(env.error.check).to.equal("OP-3");
    expect(env.error.message).to.include(`envoi-0x${"ab".repeat(32)}.json`);
    expect(env.error.message).to.not.include("erreur interne");
    // Mutant : l'index relu n'est plus vérifié ; l'ancre forgée vaut « capturée » et la demande est préparée (oracle : ancre_manquante).
    const mutant = await executerMutant("index-relu", "            if (e) ctx.log(`avertissement : index ${x.nom} de l'ancre ${empreinte} écarté, ${e.check} en échec : ${e.detail}`);\n            return e === null;", "            if (e) ctx.log(`avertissement : index ${x.nom} de l'ancre ${empreinte}`);\n            return true;");
    const sm = await lancer(mutant, ["condense", "cloture", "--manifeste", fMan, "--dossier", dossier, "--captures", capsB, "--sortie", path.join(E, "demande-cloture-index-mutant.json"), "--instance", instance, "--rpc", url]);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("ancre_manquante");
  });

  it("CT-4 EX-8.21 (EX-8.10) : reassigner reconnaît le nouveau jeu à son code déployé (artefact CuratorSet, hors métadonnées) : un contrat imitateur qui répond admin(), getThreshold() et getCuratorCount() est refusé (jeu_invalide, OP-5) ; un CuratorSet réel du même administrateur est admis ; mutant (comparaison de code retirée) : l'imitateur est admis", async function () {
    const d = lireJSON(dossier);
    const publiques = lireJSON(path.join(E, "cles", "cles-essai.json"));
    const [signer] = await conn.ethers.getSigners();
    // Imitateur : PUSH20 <admin> PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN : la même valeur pour tout appel.
    const admin = publiques.set_admin.slice(2);
    const runtime = `73${admin}60005260206000f3`;
    expect(runtime.length / 2).to.equal(29);
    const init = "601d80600b6000396000f3";
    const dep = await (await signer.sendTransaction({ data: "0x" + init + runtime })).wait();
    const imitateur = dep.contractAddress.toLowerCase();
    expect(await conn.provider.request({ method: "eth_getCode", params: [imitateur, "latest"] })).to.equal("0x" + runtime);
    const demandeEcrite = path.join(E, "demande-reassignation.txt");
    fs.writeFileSync(demandeEcrite, "Demande de réassignation du jeu de essai-revue-l13, consignée (EX-8.10).\n");
    const base = ["reassigner", "--org-id", d.organisation.org_id, "--exploitant", "hardhat:0", "--captures", caps, "--confirmer", d.organisation.org_id, "--demande", demandeEcrite];
    const s = await R([...base, "--jeu", imitateur]);
    attendreRefus(s, "jeu_invalide");
    expect(s.error.check).to.equal("OP-5");
    expect(s.error.message).to.include("code déployé");
    const set = d.steps.find((x) => x.step === "jeu_approbateurs").contract;
    expect((await (await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address)).curatorSetOf(d.organisation.org_id)).toLowerCase(), "le jeu n'a pas changé").to.equal(set);
    // Témoin : un CuratorSet réel administré par la même clé de gouvernance passe.
    const fabrique = await conn.ethers.getContractFactory("CuratorSet");
    const reel = await fabrique.deploy(publiques.set_admin, [Wallet.createRandom().address], 1);
    await reel.waitForDeployment();
    const ok = await R([...base, "--jeu", await reel.getAddress()]);
    attendreReussite(ok);
    expect(ok.outputs.curator_set).to.equal((await reel.getAddress()).toLowerCase());
    // Mutant : la comparaison de code retirée ; l'imitateur est admis (oracle : jeu_invalide).
    const mutant = await executerMutant("code-jeu", "    if (!memeCodeHorsMetadonnees(String(code), artefact(\"CuratorSet\").deployedBytecode)) throw new Arret(\"jeu_invalide\", \"OP-5\",", "    if (false) throw new Arret(\"jeu_invalide\", \"OP-5\",");
    const sm = await lancer(mutant, [...base, "--jeu", imitateur, "--instance", instance, "--rpc", url, "--sans-capture"]);
    expect(sm.error?.code, `mutant : ${JSON.stringify(sm.error)} (le mutant est tué)`).to.not.equal("jeu_invalide");
  });
});
