// Outil de référence de CT-4 : plancher du nonce d'EX-8.14 (complément du
// 2026-11-17). L'outil lit le reçu et le nonce au premier point de `--rpc`
// qui répond. Quand ce point ne répond plus à la lecture du nonce, le point
// suivant, s'il n'a pas encore appliqué le bloc du dernier envoi, rend le
// nonce qui vient d'être consommé : la transaction signée à ce nonce n'est
// jamais incluse (« nonce too low » partout, compté comme une copie déjà
// présente) et l'outil rend `recu_absent`. Le nonce signé n'est jamais
// inférieur à n + 1, n étant le plus grand nonce des envois de l'expéditeur
// dont l'inclusion est écrite dans `--captures` ; un plancher qui dépasse de
// plus de 1 la valeur lue ne fait rien signer (`nonce_incoherent`). Le
// déploiement du jeu d'approbateurs retient ce nonce avant de calculer
// l'adresse CREATE.
//
// Recoupement d'EX-8.14 : la valeur des points est la plus grande que rendent
// au moins deux points de `--rpc` ; aucune valeur rendue par deux points, ou
// un point au-delà de cette valeur + 1, et rien n'est signé
// (`nonce_incoherent`). Un point en retard ne bloque pas.
//
// Sans réseau : réseau Hardhat en mémoire (31337, --sans-capture, EX-A.6)
// derrière trois points : le premier à jour, muet sur eth_getTransactionCount
// (connexion coupée), menteur ou en retard selon le cas ; les deux autres en
// retard d'un bloc (ou à jour), muets selon le cas.

import { expect } from "chai";
import { network } from "hardhat";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT, deployNoortrace } from "../scripts/lib/noortrace.mjs";
import * as C from "../scripts/lib/conventions-registre.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { executer } from "../scripts/registre/noortrace-registre.mjs";

const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

async function outil(args) {
  let out = "";
  const { code } = await executer(args, { stdout: { write: (s) => (out += s) }, stderr: { write: () => {} } });
  const s = JSON.parse(out);
  expect(s.exit_code).to.equal(code);
  return s;
}

/** Point JSON-RPC devant le fournisseur Hardhat ; `regle(method, params)` rend `undefined` (fournisseur), `{ couper: true }` ou `{ result }`. */
function point(provider, regle) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const r = JSON.parse(corps);
    let reponse;
    try {
      const s = await regle(r.method, r.params);
      if (s?.couper) {
        res.destroy();
        return;
      }
      const result = s !== undefined ? s.result : await provider.request({ method: r.method, params: r.params });
      reponse = { jsonrpc: "2.0", id: r.id, result };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: r.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

/** Manifeste d'essai de l'instance Hardhat (EX-A.6), forme de test/registre-revue.test.js. */
function manifesteEssai(E, deploiement, validators) {
  const deployeur = deploiement.deployeur.toLowerCase();
  const genese = { chainId: 31337, alloc: [{ address: deployeur, balanceWei: "10000000000000000000000" }], rules: { chainId: "noortrace-31337-essai", ...C.REGLES_SANS_EMISSION } };
  fs.writeFileSync(path.join(E, "genese.json"), JSON.stringify(genese, null, 2) + "\n");
  const csr = deploiement.contrats.CuratorSetRegistry.adresse.toLowerCase();
  return {
    version: 0,
    revision: 1,
    previous_sha256: null,
    published_at: "2026-11-17T00:00:00.000Z",
    nature: "developpement",
    bft_chain_id: "noortrace-31337-essai",
    evm_chain_id: 31337,
    evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-11-17T00:00:00.000Z", source: "réseau Hardhat en mémoire des tests (CT-4 EX-A.6)" },
    genesis: { file: "genese.json", sha256: J.sha256(fs.readFileSync(path.join(E, "genese.json"))), rules_line: C.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
    noorcore: { repository: "https://github.com/noorfinances-eng/noorchain-core", commit: "618fcef8805ef5b4cb9291a3dd97be710e489297", go_version: "1.26.9", patches: [], artifacts: [{ kind: "binaire", name: "sans objet : réseau Hardhat", sha256: C.HACHAGE_NUL, build: "sans objet" }] },
    validator_sets: [{ from_height: 1, to_height: null, validators, source: "jeu du réseau de développement, sans effet sur le réseau Hardhat", valset_hash: C.hachageJeuValidateurs(validators), operators: validators.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: null })) }],
    fees: { ...C.FRAIS_DEFAUT },
    contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n, i) => ({ name: n, address: deploiement.contrats[n].adresse.toLowerCase(), deployer: deployeur, nonce: i, constructor_args: n === "AttestationRegistry" ? [] : n === "CuratorSetRegistry" ? [deployeur] : [csr], transaction_hash: deploiement.contrats[n].tx, block_number: deploiement.contrats[n].bloc, block_hash: null, evidence: null, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
    source: "manifeste d'essai du réseau Hardhat en mémoire (CT-4 EX-A.6)",
  };
}

describe("outil de référence de CT-4 : plancher et recoupement du nonce d'EX-8.14 (§8.6, complément du 2026-11-17), réseau Hardhat en mémoire derrière trois points", function () {
  this.timeout(300000);
  let conn;
  let E;
  let instance;
  let rpc;
  const serveurs = [];
  // `premier` : null (à jour), "muet", "ment" (+ 5) ou "retard" (- 1 sur le nonce) ; `retard` et `muets` : les deux autres points.
  const etat = { muet: false, premier: null, retard: 1n, muets: false };

  before(async function () {
    conn = await network.create();
    await conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
    const { deployment } = await deployNoortrace(conn.ethers, { networkName: "essai-nonce-plancher" });
    E = fs.mkdtempSync(path.join(TMP, "noortrace-registre-nonce-plancher-"));
    const validators = lireJSON(path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json")).validators;
    instance = path.join(E, "instance.json");
    fs.writeFileSync(instance, JSON.stringify(manifesteEssai(E, deployment, validators), null, 2) + "\n");
    const p = conn.provider;
    // Premier point : à jour ; sur eth_getTransactionCount, muet quand `etat.muet` ou `etat.premier === "muet"`, cinq de
    // plus quand `etat.premier === "ment"`, un de moins quand `etat.premier === "retard"`.
    const aJour = await point(p, async (method, params) => {
      if (method !== "eth_getTransactionCount") return undefined;
      if (etat.muet || etat.premier === "muet") return { couper: true };
      if (etat.premier !== "ment" && etat.premier !== "retard") return undefined;
      const n = BigInt(await p.request({ method, params }));
      return { result: "0x" + (etat.premier === "ment" ? n + 5n : n > 0n ? n - 1n : 0n).toString(16) };
    });
    // Deux autres points : `etat.retard` blocs de retard sur la tête (nonce de sa hauteur, reçus des blocs qu'ils n'ont pas
    // appliqués absents) ; muets sur eth_getTransactionCount quand `etat.muets`.
    const regleRetard = async (method, params) => {
      if (etat.muets && method === "eth_getTransactionCount") return { couper: true };
      const tete = BigInt(await p.request({ method: "eth_blockNumber", params: [] }));
      const sienne = tete > etat.retard ? tete - etat.retard : 0n;
      if (method === "eth_getTransactionCount") return { result: await p.request({ method, params: [params[0], "0x" + sienne.toString(16)] }) };
      if (method === "eth_getTransactionReceipt") {
        const r = await p.request({ method, params });
        return { result: r && BigInt(r.blockNumber) > sienne ? null : r };
      }
      return undefined;
    };
    const enRetard = await point(p, regleRetard);
    const enRetard2 = await point(p, regleRetard);
    serveurs.push(aJour.serveur, enRetard.serveur, enRetard2.serveur);
    rpc = `${aJour.url},${enRetard.url},${enRetard2.url}`;
    const R = (args) => outil([...args, "--instance", instance, "--rpc", rpc, "--sans-capture"]);
    const s = await R(["cles-essai", "--sortie", path.join(E, "cles")]);
    expect(s.result, JSON.stringify(s.error)).to.equal("reussi");
  });

  after(function () {
    for (const s of serveurs) s.close();
    if (E) fs.rmSync(E, { recursive: true, force: true });
  });

  const R = (args) => outil([...args, "--instance", instance, "--rpc", rpc, "--sans-capture"]);
  const preparer = async (org) => {
    const dossier = path.join(E, `dossier-${org}.json`);
    const s = await R(["inscrire-client", "--preparer", "--org", org, "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", dossier]);
    expect(s.result, JSON.stringify(s.error)).to.equal("reussi");
    return dossier;
  };
  const envois = (caps) => fs.readdirSync(caps).filter((f) => /^envoi-0x[0-9a-f]{64}\.json$/.test(f)).map((f) => lireJSON(path.join(caps, f)));

  it("inscrire-client : après chaque reçu, le nonce n'est lu que sur les deux points en retard d'un bloc ; chaque transaction suivante est signée au plancher (n + 1) et incluse, nonces consécutifs, aucun recu_absent", async function () {
    const dossier = await preparer("essai-nonce-plancher");
    const caps = path.join(E, "captures");
    await conn.provider.request({ method: "evm_mine", params: [] }); // tête sans transaction de l'exploitant : le premier nonce lu est exact
    etat.muet = true;
    const s = await R(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps, "--delai", "3"]);
    etat.muet = false;
    expect(s.result, `${JSON.stringify(s.error)}`).to.equal("reussi");
    const nonces = envois(caps).map((e) => e.nonce).sort((a, b) => a - b);
    expect(nonces.length, "au moins deux transactions de l'exploitant dans la même commande").to.be.at.least(2);
    expect(nonces, "nonces consécutifs, aucun nonce consommé signé de nouveau").to.deep.equal(nonces.map((_, k) => nonces[0] + k));
    for (const e of envois(caps)) expect(lireJSON(path.join(caps, `issue-${e.transaction_hash}.json`)).block_number, e.transaction_hash).to.be.a("number");
  });

  it("plancher au-delà de la valeur lue + 1 (point très en retard) : le déploiement du jeu ne signe rien et ne calcule aucune adresse (nonce_incoherent) ; rien n'est envoyé", async function () {
    const dossier = await preparer("essai-nonce-plancher-garde");
    const caps = path.join(E, "captures"); // mêmes captures : le plancher est celui des inclusions du premier essai
    const avant = envois(caps).length;
    const bloc = BigInt(await conn.provider.request({ method: "eth_blockNumber", params: [] }));
    etat.muet = true;
    etat.retard = 6n;
    const s = await R(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps, "--delai", "3"]);
    etat.muet = false;
    etat.retard = 1n;
    expect(s.error?.code, JSON.stringify(s.error)).to.equal("nonce_incoherent");
    expect(envois(caps).length, "aucun envoi écrit").to.equal(avant);
    expect(BigInt(await conn.provider.request({ method: "eth_blockNumber", params: [] })), "aucune transaction incluse").to.equal(bloc);
  });

  // Recoupement des points d'EX-8.14 : chaque cas a son répertoire de captures, sans plancher.
  const sansPlancher = async (nom, regler) => {
    const dossier = await preparer(nom);
    const caps = path.join(E, `captures-${nom}`);
    await conn.provider.request({ method: "evm_mine", params: [] }); // tête sans transaction de l'exploitant
    const bloc = BigInt(await conn.provider.request({ method: "eth_blockNumber", params: [] }));
    Object.assign(etat, regler);
    let s;
    try {
      s = await R(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps, "--delai", "3"]);
    } finally {
      Object.assign(etat, { muet: false, premier: null, retard: 1n, muets: false });
    }
    return { s, caps, bloc, envois: fs.existsSync(caps) ? envois(caps) : [] };
  };

  it("recoupement : le premier point rend cinq de plus que les deux autres, à jour ; les points diffèrent de plus de 1, rien n'est signé ni envoyé (nonce_incoherent)", async function () {
    const r = await sansPlancher("essai-nonce-menteur", { premier: "ment", retard: 0n });
    expect(r.s.error?.code, JSON.stringify(r.s.error)).to.equal("nonce_incoherent");
    expect(r.envois.length, "aucun envoi écrit").to.equal(0);
    expect(BigInt(await conn.provider.request({ method: "eth_blockNumber", params: [] })), "aucune transaction incluse").to.equal(r.bloc);
  });

  it("recoupement : seul le premier point répond à eth_getTransactionCount ; aucune valeur rendue par deux points, rien n'est signé ni envoyé (nonce_incoherent)", async function () {
    const r = await sansPlancher("essai-nonce-seul", { retard: 0n, muets: true });
    expect(r.s.error?.code, JSON.stringify(r.s.error)).to.equal("nonce_incoherent");
    expect(r.envois.length, "aucun envoi écrit").to.equal(0);
  });

  it("recoupement : le premier point a un bloc de retard sur le nonce, les deux autres sont à jour ; la valeur recoupée est signée, les transactions sont incluses aux nonces consécutifs", async function () {
    const r = await sansPlancher("essai-nonce-premier-retard", { premier: "retard", retard: 0n });
    expect(r.s.result, JSON.stringify(r.s.error)).to.equal("reussi");
    const nonces = r.envois.map((e) => e.nonce).sort((a, b) => a - b);
    expect(nonces.length).to.be.at.least(2);
    expect(nonces, "nonces consécutifs").to.deep.equal(nonces.map((_, k) => nonces[0] + k));
    for (const e of r.envois) expect(lireJSON(path.join(r.caps, `issue-${e.transaction_hash}.json`)).block_number, e.transaction_hash).to.be.a("number");
  });

  it("recouperNonce (bibliothèque des conventions) : un point, sa valeur ; plusieurs, la plus grande rendue par deux points ; un point en retard ne bloque pas ; au-delà de + 1 ou sans paire, incohérent", function () {
    expect(C.recouperNonce([7n], 1)).to.deep.equal({ nonce: 7n });
    expect(C.recouperNonce([7n], 3).incoherent, "une seule valeur pour trois points").to.be.a("string");
    expect(C.recouperNonce([5n, 5n, 6n, 6n], 4)).to.deep.equal({ nonce: 6n });
    expect(C.recouperNonce([5n, 5n, 6n], 3)).to.deep.equal({ nonce: 5n });
    expect(C.recouperNonce([5n, 5n, 2n], 3)).to.deep.equal({ nonce: 5n });
    expect(C.recouperNonce([5n, 5n, 7n], 3).incoherent).to.be.a("string");
    expect(C.recouperNonce([5n, 6n], 2).incoherent).to.be.a("string");
  });
});
