// Réseau d'essai de l'inscription (étape 6) : le réseau Hardhat en mémoire
// (identifiant EVM 31337), démarré par l'essai, avec les quatre contrats de
// l'instance déployés par le compte Hardhat 0 (CT-4 EX-5.2), le prix de base
// fixé à 1 wei (CT-4 EX-A.6), et un pont JSON-RPC sur 127.0.0.1 qui le
// présente comme un validateur noorcore (CT-4 EX-A.6, dernière phrase) :
// pour chaque hauteur, un en-tête dont `hash` est le `BFTBlockHash` des dix
// champs engagés (CT-6 EX-11.4), des reçus et des journaux qui portent ce
// hachage, et un certificat de commit synthétique signé par le jeu de
// validateurs d'essai de CT-4 annexe A.2 (`noor_getCommitCertificate`,
// `noor_txindexStatus`). Sans le mode noorcore, le pont relaie Hardhat tel
// quel (pas de certificat : les essais s'y servent de la reprise sans
// capture d'EX-7.16).
//
// Aucune clé n'est écrite ici : les clés des validateurs d'essai sont lues au
// moment de l'essai dans `spec/vecteurs/ct-4/constantes.json`, où elles sont
// publiées sans valeur ; les comptes Hardhat dérivent du mnémonique public.
//
// Le pont offre aussi des points d'action pour les essais de reprise :
// `retenir` (une transaction soumise est acceptée mais gardée hors de la
// chaîne, comme une mempool qui ne l'inclut pas), `relacher`, `avantEnvoi`
// (fonction appelée avant de relayer une transaction, pour qu'un essai fasse
// inclure d'abord une transaction concurrente), `certificatsIndisponibles`.

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { network } from "hardhat";
import { sha256, sha256Hex, utf8, octetsVersHex, hexVersOctets, keccak256 } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

export const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..", "..");
export const EVM_ESSAI = 31337;
export const BFT_ESSAI = "noortrace-31337-essai";
export const MNEMONIQUE = "test test test test test test test test test test test junk";

const q = (x) => "0x" + BigInt(x).toString(16);
const ZERO32 = "0x" + "00".repeat(32);

/** Constantes publiées des vecteurs de CT-4 (jeu de validateurs d'essai de A.2). */
export function constantesCt4() {
  return JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-4", "constantes.json"), "utf8"));
}

/** Jeu d'essai de A.2 : `{ validators, cles, hash }`. */
export function jeuEssai() {
  const c = constantesCt4();
  return {
    validators: c.test_validators.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })),
    cles: Object.fromEntries(c.test_validators.validators.map((v) => [v.id, v.private_key])),
    hash: c.test_validators.valset_hash,
  };
}

/** Enveloppe BFT signée (CT-6 EX-11.7), comme le nœud l'écrit. */
function enveloppe({ type, validateur, chainId, valsetHash, height, round, blockHash, corps }) {
  const concat = (...p) => {
    const n = p.reduce((a, b) => a + b.length, 0);
    const o = new Uint8Array(n);
    let k = 0;
    for (const x of p) {
      o.set(x, k);
      k += x.length;
    }
    return o;
  };
  const corpsTexte = JSON.stringify(corps);
  const bodyHash = sha256(utf8(corpsTexte));
  const LP = (o) => {
    const L = new Uint8Array(4);
    new DataView(L.buffer).setUint32(0, o.length);
    return concat(L, o);
  };
  const u64 = (x) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(x));
    return b;
  };
  const condense = sha256(concat(
    utf8("noor/v1/bft-sign|"), LP(utf8("noor/v1/bft")), LP(utf8(chainId)), LP(utf8(type)), LP(utf8(validateur.id)),
    valsetHash, u64(height), u64(round), blockHash, bodyHash,
  ));
  const sig = validateur.cle.signerCondense(condense);
  const sig65 = concat(hexVersOctets(sig.r), hexVersOctets(sig.s), Uint8Array.of(sig.v - 27));
  const ligne = `{"domain":"noor/v1/bft","chainId":${JSON.stringify(chainId)},"type":"${type}","validatorId":${JSON.stringify(validateur.id)},"valsetHash":"${R.encoderBase64(valsetHash)}","height":${height},"round":${round},"blockHash":"${R.encoderBase64(blockHash)}","bodyHash":"${R.encoderBase64(bodyHash)}","body":${corpsTexte},"sig":"${R.encoderBase64(sig65)}"}`;
  return { line: ligne, validatorId: validateur.id, bodyHash: octetsVersHex(bodyHash), sig: octetsVersHex(sig65) };
}

/** Octets bruts d'une transaction de type 2 servie par `eth_getTransactionByHash` (le réseau Hardhat n'a pas `eth_getRawTransactionByHash`). */
function transactionBrute(t) {
  if (t.type !== "0x2" || (Array.isArray(t.accessList) && t.accessList.length > 0)) throw new Error(`transaction ${t.hash} : type 2 sans liste d'accès attendu`);
  const tx = R.construireTransaction({
    chain_id: BigInt(t.chainId), nonce: BigInt(t.nonce), max_priority_fee_per_gas: BigInt(t.maxPriorityFeePerGas), max_fee_per_gas: BigInt(t.maxFeePerGas),
    gas_limit: BigInt(t.gas), to: t.to ? t.to.toLowerCase() : null, value: BigInt(t.value), data: t.input,
  });
  const parite = t.yParity !== undefined ? Number(BigInt(t.yParity)) : Number(BigInt(t.v));
  const { raw, hash } = R.serialiserTransaction(tx, { yParity: parite, r: BigInt(t.r), s: BigInt(t.s) });
  if (octetsVersHex(hash) !== t.hash) throw new Error(`transaction ${t.hash} : octets bruts reconstitués d'un autre hachage`);
  return raw;
}

/**
 * Démarre le réseau Hardhat en mémoire et déploie l'instance (CT-4 EX-5.2),
 * compte Hardhat 0 déployeur et administrateur du registre. Rend
 * `{ conn, provider, ethers, comptes, contrats, deploiements }`.
 */
export async function demarrerReseau() {
  // Une transaction annulée est incluse avec `status` 0x0, comme sur noorcore (CT-4 EX-7.16, état `echec`), au lieu
  // d'être refusée à l'envoi par le réseau Hardhat.
  const conn = await network.create({ network: "hardhat", override: { throwOnTransactionFailures: false } });
  const provider = conn.provider;
  await provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
  const signataires = await conn.ethers.getSigners();
  const admin = signataires[0];
  const deploiements = [];
  const deployer = async (nom, args) => {
    const c = await conn.ethers.deployContract(nom, args);
    await c.waitForDeployment();
    const tx = c.deploymentTransaction();
    const recu = await provider.request({ method: "eth_getTransactionReceipt", params: [tx.hash] });
    const d = { name: nom, address: (await c.getAddress()).toLowerCase(), deployer: admin.address.toLowerCase(), nonce: tx.nonce, constructor_args: args.map((a) => a.toLowerCase()), transaction_hash: tx.hash, block_number: Number(BigInt(recu.blockNumber)) };
    deploiements.push(d);
    return d;
  };
  const attestation = await deployer("AttestationRegistry", []);
  const csr = await deployer("CuratorSetRegistry", [admin.address]);
  const periode = await deployer("PeriodRegistry", [csr.address]);
  const enregistreurs = await deployer("RecorderRegistry", [csr.address]);
  return {
    conn, provider, ethers: conn.ethers, signataires,
    comptes: signataires.slice(0, 10).map((s) => s.address.toLowerCase()),
    contrats: { attestation_registry: attestation.address, curator_set_registry: csr.address, period_registry: periode.address, recorder_registry: enregistreurs.address },
    deploiements,
  };
}

/**
 * Pont JSON-RPC HTTP vers le fournisseur Hardhat. `noorcore` vrai : présente
 * le réseau comme un validateur noorcore (en-têtes BFT, certificats signés par
 * le jeu d'essai, `noor_txindexStatus`). Rend `{ url, fermer, appels, ... }`.
 */
export async function ouvrirPont(provider, { noorcore = true, bftChainId = BFT_ESSAI } = {}) {
  const jeu = jeuEssai();
  const jeuLu = R.lireJeu({ validators: jeu.validators });
  const validateurs = jeu.validators.map((v) => ({ id: v.id, cle: new R.SignataireChaineFichier(hexVersOctets(jeu.cles[v.id])) }));
  const bftParNumero = new Map();
  const etat = {
    appels: [],
    retenues: new Map(), // hachage → transaction brute gardée hors de la chaîne
    retenir: false,
    avantEnvoi: null,
    certificatsIndisponibles: false,
    /** Hauteur à partir de laquelle le certificat est indisponible (null : aucune) ; la tête lue avant reste servie. */
    certificatsIndisponiblesDepuis: null,
    /** Vrai : `noor_txindexStatus` décrit un index vide, comme un suiveur (OP-2). */
    suiveur: false,
    /** Message d'erreur JSON-RPC rendu à toute soumission (null : soumissions relayées). */
    refuserEnvois: null,
    envoisRecus: [],
  };

  const brut = async (methode, params) => provider.request({ method: methode, params });

  async function entete(numero) {
    const b = await brut("eth_getBlockByNumber", [numero, false]);
    if (!b || !noorcore) return b;
    const h = Number(BigInt(b.number));
    const champs = { ...b, number: b.number, timestamp: b.timestamp, gasUsed: b.gasUsed, gasLimit: b.gasLimit, baseFeePerGas: b.baseFeePerGas ?? "0x0" };
    const bft = R.hachageBlocBft(champs);
    const hash = octetsVersHex(bft.hash);
    bftParNumero.set(h, { hash, hardhat: b.hash });
    return { ...b, hash };
  }

  async function hashBft(numeroHex) {
    const h = Number(BigInt(numeroHex));
    if (!bftParNumero.has(h)) await entete(q(h));
    return bftParNumero.get(h).hash;
  }

  async function recu(hash) {
    const r = await brut("eth_getTransactionReceipt", [hash]);
    if (!r || !noorcore) return r;
    const bh = await hashBft(r.blockNumber);
    return { ...r, blockHash: bh, logs: r.logs.map((l) => ({ ...l, blockHash: bh })) };
  }

  async function certificat(param) {
    const tete = Number(BigInt(await brut("eth_blockNumber", [])));
    let h;
    if (param === "latest") h = tete;
    else if (/^0x[0-9a-f]{64}$/.test(param)) {
      const e = [...bftParNumero.entries()].find(([, v]) => v.hash === param);
      if (!e) return { erreur: { code: -32000, message: "unknown block" } };
      h = e[0];
    } else if (/^0x(0|[1-9a-f][0-9a-f]*)$/.test(param)) h = Number(BigInt(param));
    else return { erreur: { code: -32602, message: "invalid params: hex block quantity" } };
    if (h > tete) return { erreur: { code: -32000, message: "unknown block" } };
    if (h === 0) return { erreur: { code: -32000, message: `no commit certificate stored for block ${q(h)}: inside the retention window` } };
    if (etat.certificatsIndisponibles || (etat.certificatsIndisponiblesDepuis !== null && h >= etat.certificatsIndisponiblesDepuis)) return { erreur: { code: -32000, message: `no commit certificate stored for block ${q(h)}: inside the retention window` } };
    const e = await entete(q(h));
    const txsRaw = [];
    for (const th of e.transactions) txsRaw.push(R.encoderBase64(transactionBrute(await brut("eth_getTransactionByHash", [th]))));
    const blockHash = hexVersOctets(e.hash);
    const corpsProposition = {
      height: h, round: 0, proposer: validateurs[0].id, blockHash: e.hash, parentHash: e.parentHash, timestamp: Number(BigInt(e.timestamp)),
      stateRoot: e.stateRoot, receiptsRoot: e.receiptsRoot, txRoot: e.transactionsRoot, gasUsed: Number(BigInt(e.gasUsed)), gasLimit: Number(BigInt(e.gasLimit)),
      baseFeeHex: e.baseFeePerGas ?? "0x0", txsRaw, polkaRound: 0, polkaLines: [], sig: "",
    };
    const base = { chainId: bftChainId, valsetHash: jeuLu.hash, height: h, round: 0, blockHash };
    const proposition = enveloppe({ ...base, type: "CONS_PROPOSAL", validateur: validateurs[0], corps: corpsProposition });
    const precommits = [3, 0, 2].map((k) => enveloppe({
      ...base, type: "CONS_PRECOMMIT", validateur: validateurs[k],
      corps: { Height: h, Round: 0, Voter: validateurs[k].id, Type: 2, BlockHash: e.hash, Sig: null },
    }));
    return {
      resultat: {
        height: q(h), round: "0x0", chainId: bftChainId, valsetHash: octetsVersHex(jeuLu.hash), blockHash: e.hash,
        canonical: { blockHash: e.hash, matchesCertificate: true },
        proposal: { line: proposition.line, validatorId: proposition.validatorId, bodyHash: proposition.bodyHash, sig: proposition.sig },
        precommits: precommits.map((p) => ({ line: p.line, validatorId: p.validatorId, height: q(h), round: "0x0", blockHash: e.hash, bodyHash: p.bodyHash, sig: p.sig })),
        quorum: { validators: 4, required: 3, precommits: 3 },
        validatorSet: jeu.validators,
        validatorSetHash: octetsVersHex(jeuLu.hash), validatorSetMatchesCertificate: true,
        signing: { domain: "noor/v1/bft", digestPrefix: "noor/v1/bft-sign|", scheme: "essai" },
        retention: { heights: 300000, pruned: false },
      },
    };
  }

  async function repondre(requete) {
    const { method: m, params: p = [] } = requete;
    etat.appels.push(m);
    if (noorcore) {
      if (m === "noor_txindexStatus") return { resultat: { enabled: true, ready: true, ok: true, last_indexed_height: etat.suiveur ? 0 : Number(BigInt(await brut("eth_blockNumber", []))) } };
      if (m === "noor_getCommitCertificate") {
        if (!Array.isArray(p) || p.length !== 1 || typeof p[0] !== "string") return { erreur: { code: -32602, message: "invalid params" } };
        return certificat(p[0]);
      }
      if (m === "eth_getBlockByNumber") return { resultat: await entete(p[0]) };
      if (m === "eth_getTransactionReceipt") {
        if (etat.retenues.has(p[0])) return { resultat: null };
        return { resultat: await recu(p[0]) };
      }
      if (m === "eth_getTransactionByHash") {
        if (etat.retenues.has(p[0])) return { resultat: { hash: p[0], blockNumber: null, blockHash: null } };
        const t = await brut(m, p);
        if (t && t.blockNumber) t.blockHash = await hashBft(t.blockNumber);
        return { resultat: t };
      }
      if (m === "eth_getLogs") {
        const l = await brut(m, p);
        for (const j of l) j.blockHash = await hashBft(j.blockNumber);
        return { resultat: l };
      }
    } else if (m.startsWith("noor_")) {
      return { erreur: { code: -32601, message: "method not found" } };
    }
    if (m === "eth_sendRawTransaction") {
      let tx;
      try {
        tx = R.lireTransaction(p[0]);
      } catch {
        return { erreur: { code: -32602, message: "invalid params: invalid raw tx" } };
      }
      const hash = octetsVersHex(tx.hash);
      etat.envoisRecus.push(hash);
      if (etat.refuserEnvois) return { erreur: { code: -32000, message: etat.refuserEnvois } };
      if (etat.retenir) {
        etat.retenues.set(hash, p[0]);
        return { resultat: hash };
      }
      if (etat.avantEnvoi) {
        const f = etat.avantEnvoi;
        etat.avantEnvoi = null;
        await f(tx);
      }
    }
    if (m === "eth_getTransactionReceipt" && etat.retenues.has(p[0])) return { resultat: null };
    return { resultat: await brut(m, p) };
  }

  const serveur = http.createServer((req, res) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", async () => {
      let requete;
      let reponse;
      try {
        requete = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
        const r = await repondre(requete);
        reponse = r.erreur ? { jsonrpc: "2.0", id: requete.id, error: r.erreur } : { jsonrpc: "2.0", id: requete.id, result: r.resultat ?? null };
      } catch (e) {
        reponse = { jsonrpc: "2.0", id: requete?.id ?? null, error: { code: e?.code === -32602 ? -32602 : -32000, message: String(e?.message ?? e).slice(0, 300) } };
      }
      const corps = Buffer.from(JSON.stringify(reponse));
      res.writeHead(200, { "content-type": "application/json", "content-length": corps.length });
      res.end(corps);
    });
  });
  await new Promise((ok) => serveur.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${serveur.address().port}`;
  return Object.assign(etat, {
    url,
    /** Relaie à Hardhat les transactions retenues (rend leurs hachages). */
    async relacher() {
      const h = [...etat.retenues.keys()];
      for (const [, raw] of etat.retenues) await brut("eth_sendRawTransaction", [raw]);
      etat.retenues.clear();
      return h;
    },
    /** Oublie les transactions retenues (une mempool qui les a perdues). */
    perdre() {
      etat.retenues.clear();
    },
    fermer: () => new Promise((ok) => serveur.close(() => ok())),
  });
}

/**
 * Écrit dans `repertoire` un manifeste d'instance d'essai (`instance-r1.json`,
 * `genese.json`) pour le réseau démarré : nature `developpement`,
 * identifiants 31337 et `noortrace-31337-essai`, jeu de validateurs d'essai
 * de A.2, contrats déployés, compte Hardhat 0 dans les quatre rôles. Rend le
 * chemin du manifeste. `jeu` : le jeu à déclarer (par défaut celui d'essai).
 */
export function ecrireManifesteEssai(repertoire, reseau, { nature = "developpement", jeu = null } = {}) {
  fs.mkdirSync(repertoire, { recursive: true });
  const j = jeu ?? jeuEssai();
  const lu = R.lireJeu({ validators: j.validators });
  const admin = reseau.comptes[0];
  const genese = {
    chainId: EVM_ESSAI,
    alloc: [{ address: admin, balanceWei: "10000000000000000000000" }],
    rules: {
      chainId: BFT_ESSAI, possEnabled: false, possRewards: "0x0000000000000000000000000000000000000000", possCapWei: "0",
      possGenesisUnix: 0, possHalvingSec: 0, possSubperiodSec: 0, possEmissionModel: "noormint/v1",
    },
  };
  const geneseOctets = Buffer.from(JSON.stringify(genese, null, 2) + "\n");
  fs.writeFileSync(path.join(repertoire, "genese.json"), geneseOctets);
  const manifeste = {
    version: 0,
    revision: 1,
    previous_sha256: null,
    published_at: "2026-11-11T00:00:00.000Z",
    nature,
    bft_chain_id: BFT_ESSAI,
    evm_chain_id: EVM_ESSAI,
    evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-11-11T00:00:00.000Z", source: "réseau Hardhat en mémoire des essais (CT-4 EX-A.6)" },
    genesis: { file: "genese.json", sha256: sha256Hex(geneseOctets), rules_line: R.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
    noorcore: {
      repository: "https://github.com/noorfinances-eng/noorchain-core",
      commit: "618fcef8805ef5b4cb9291a3dd97be710e489297",
      go_version: "1.26.9",
      patches: [],
      artifacts: [{ kind: "binaire", name: "réseau Hardhat en mémoire", sha256: "0x" + "00".repeat(32), build: "essai : aucun binaire noorcore" }],
    },
    validator_sets: [{
      from_height: 1, to_height: null, validators: j.validators, source: "jeu de validateurs d'essai de CT-4 annexe A.2",
      valset_hash: octetsVersHex(lu.hash),
      operators: j.validators.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: 300000 })),
    }],
    fees: { transaction_type: 2, max_fee_per_gas_wei: "1", max_priority_fee_per_gas_wei: "1", gas_limit: 3000000, gas_limit_max: 16777216, provision_days: 30, refill_below_days: 7 },
    contracts: reseau.deploiements.map((d) => ({ ...d, block_hash: null, evidence: null, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: admin, from_height: 0, to_height: null })),
    source: "manifeste d'essai de l'inscription (étape 6) : réseau Hardhat en mémoire",
  };
  const chemin = path.join(repertoire, "instance-r1.json");
  fs.writeFileSync(chemin, JSON.stringify(manifeste, null, 2) + "\n");
  return chemin;
}

export { ZERO32, keccak256 };
