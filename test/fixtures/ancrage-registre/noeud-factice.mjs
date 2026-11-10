// Nœud noorcore factice pour les tests du sous-module « registre » du
// composant d'ancrage : une chaîne en mémoire, un bloc par transaction,
// dont les en-têtes, reçus et certificats de commit ont la forme exacte des
// réponses JSON-RPC du réseau de développement (spec/vecteurs/ct-6/registre/
// capture). Les racines (reçus, transactions), le hachage BFT et les
// enveloppes signées sont calculés avec les mêmes règles que celles que les
// vecteurs CT-6 éprouvent ; les certificats sont signés par les quatre
// validateurs d'essai de CT-4 annexe A.2 (constantes.json, test_validators,
// clés publiées sans valeur).
//
// Contrats simulés : AttestationRegistry (anchor, lookup, isAnchored,
// anchorDigest), RecorderRegistry (isActiveRecorder, recorderOf,
// recorderByPubKey), PeriodRegistry (submitPeriod, isKnown, latestPeriodOf,
// getPeriod, periodDigest). Le transport factice rend les octets JSON exacts
// de la réponse ; des pannes (point injoignable), des délais d'inclusion et
// des rejets sont programmables par point.

import { sha256, sha256Hex, keccak256, messageEip191 } from "@noortrace/noyau";
import {
  SELECTEURS, SUJETS, DOC_TYPE_PERIODE, anchorDigest, periodDigest, hachageSigne, mots, lireTransaction,
  hachageBlocBft, racineRecus, racineTransactions, lireJeu, encoderBase64,
} from "@noortrace/ancrage/registre";
import { recouvrerSignataire, SignataireChaineFichier } from "../../../paquets/ancrage/src/registre/cle-chaine.mjs";
import { concatener, octetsVersHex, hexVersOctets, u256, utf8Octets } from "../../../paquets/ancrage/src/registre/octets.mjs";

const ZERO32 = "0x" + "00".repeat(32);
const ZERO20 = "0x" + "00".repeat(20);
const q = (x) => "0x" + BigInt(x).toString(16);
const motAdr = (a) => "0x" + "00".repeat(12) + a.slice(2);
const motU = (x) => octetsVersHex(u256(BigInt(x)));

/** Enveloppe BFT signée par un validateur d'essai, telle que le nœud l'écrit (ordre des membres de la capture). */
function enveloppe({ type, validateur, chainId, valsetHash, height, round, blockHash, corps }) {
  const corpsTexte = JSON.stringify(corps);
  const bodyHash = sha256(utf8Octets(corpsTexte));
  const LP = (o) => { const L = new Uint8Array(4); new DataView(L.buffer).setUint32(0, o.length); return concatener(L, o); };
  const u64 = (x) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(x)); return b; };
  const condense = sha256(concatener(
    utf8Octets("noor/v1/bft-sign|"), LP(utf8Octets("noor/v1/bft")), LP(utf8Octets(chainId)), LP(utf8Octets(type)), LP(utf8Octets(validateur.id)),
    valsetHash, u64(height), u64(round), blockHash, bodyHash,
  ));
  // Signature R ‖ S ‖ V (V ∈ {0, 1}, S bas) par la clé du validateur d'essai.
  const sig = validateur.cle.signerCondense(condense);
  const sig65 = concatener(hexVersOctets(sig.r), hexVersOctets(sig.s), Uint8Array.of(sig.v - 27));
  const ligne = `{"domain":"noor/v1/bft","chainId":${JSON.stringify(chainId)},"type":"${type}","validatorId":${JSON.stringify(validateur.id)},"valsetHash":"${encoderBase64(valsetHash)}","height":${height},"round":${round},"blockHash":"${encoderBase64(blockHash)}","bodyHash":"${encoderBase64(bodyHash)}","body":${corpsTexte},"sig":"${encoderBase64(sig65)}"}`;
  return { line: ligne, validatorId: validateur.id, bodyHash: octetsVersHex(bodyHash), sig: octetsVersHex(sig65) };
}

export class NoeudFactice {
  /**
   * @param {object} p
   * @param {{validators: object[], cles: Record<string,string>}} p.validateurs jeu (clés publiques) et clés privées par identifiant
   * @param {string[]} p.points adresses des points (un par validateur, dans l'ordre)
   * @param {object} p.contrats adresses `{ attestation_registry, period_registry, recorder_registry }`
   * @param {number} [p.evmChainId]
   * @param {string} [p.bftChainId]
   */
  constructor({ validateurs, points, contrats, evmChainId = 2124, bftChainId = "noortrace-2124-dev" }) {
    this.evmChainId = evmChainId;
    this.bftChainId = bftChainId;
    this.contrats = contrats;
    this.points = points;
    this.jeu = lireJeu(validateurs);
    this.validateurs = validateurs.validators.map((v) => ({ id: v.id, cle: new SignataireChaineFichier(hexVersOctets(validateurs.cles[v.id])) }));
    this.blocs = new Map(); // hauteur → { entete, transactions: [hash], recus: Map, certificat }
    this.transactions = new Map(); // hash → { raw, hauteur, index, recu, tx }
    this.comptes = new Map(); // adresse → { solde: bigint, nonce: bigint }
    this.ancres = new Map(); // fingerprint → { issuer, docType, issuedAt }
    this.enregistreurs = new Map(); // orgId+chainKey → { chainKey, ed25519PubKey, journalId, registeredAt, revokedAt }
    this.periodes = []; // [{ id, meta, publishedAt, publisher }]
    this.hauteur = 1000;
    this.horodatage = 1793870000;
    this.dernierHash = ZERO32;
    this.pannes = new Set(); // points injoignables
    this.rejets = new Map(); // point → message de rejet d'eth_sendRawTransaction
    this.attenteInclusion = new Map(); // hash → nombre de sondages du reçu avant inclusion
    this.abandonnes = new Set(); // hashes jamais inclus (mempool qui les perd)
    this.certificatsRetardes = new Map(); // hauteur → nombre de réponses « not yet persisted » avant de servir
    this.txindex = { last_indexed_height: () => this.hauteur };
    this.appels = []; // journal des méthodes appelées
    this.genese();
  }

  genese() {
    // Bloc de genèse : hauteur 1000, pour que les hauteurs capturées soient non nulles.
    this.dernierHash = octetsVersHex(sha256(utf8Octets("genese-factice")));
  }

  approvisionner(adresse, wei) {
    const c = this.comptes.get(adresse) ?? { solde: 0n, nonce: 0n };
    c.solde += BigInt(wei);
    this.comptes.set(adresse, c);
  }

  inscrire({ orgId, chainKey, ed25519PubKey, journalId }) {
    this.enregistreurs.set(orgId + chainKey, { chainKey, ed25519PubKey, journalId, registeredAt: BigInt(this.horodatage), revokedAt: 0n });
  }

  // ---------------------------------------------------------- exécution

  #executer(tx, hash) {
    const from = tx.from;
    const compte = this.comptes.get(from) ?? { solde: 0n, nonce: 0n };
    if (tx.nonce !== compte.nonce) return { ecartee: `nonce ${tx.nonce} attendu ${compte.nonce}` };
    const cout = tx.gasLimit * tx.maxFeePerGas + tx.value;
    if (compte.solde < cout) return { ecartee: "solde insuffisant" };
    const data = tx.data;
    const selecteur = octetsVersHex(data.subarray(0, 4));
    let statut = "0x1";
    let logs = [];
    let gasUsed = 96977n;
    if (tx.to === this.contrats.attestation_registry && selecteur === SELECTEURS.anchor) {
      const fingerprint = octetsVersHex(data.subarray(4, 36));
      const docType = octetsVersHex(data.subarray(36, 68));
      const issuer = "0x" + Buffer.from(data.subarray(80, 100)).toString("hex");
      const v = Number(BigInt(octetsVersHex(data.subarray(100, 132))));
      const r = octetsVersHex(data.subarray(132, 164));
      const s = octetsVersHex(data.subarray(164, 196));
      const condense = anchorDigest(this.evmChainId, this.contrats.attestation_registry, fingerprint, docType);
      const recouvre = recouvrerSignataire(hachageSigne(condense), { v, r, s });
      if (fingerprint === ZERO32 || this.ancres.has(fingerprint) || recouvre !== issuer) statut = "0x0";
      else {
        this.ancres.set(fingerprint, { issuer, docType, issuedAt: BigInt(this.horodatage) });
        logs = [{ address: this.contrats.attestation_registry, topics: [SUJETS.Anchored, fingerprint, motAdr(issuer)], data: docType }];
      }
    } else if (tx.to === this.contrats.period_registry && selecteur === SELECTEURS.submitPeriod) {
      gasUsed = 234079n;
      const m = mots(octetsVersHex(data.subarray(4)));
      const meta = {
        org_id: octetsVersHex(m[2]), journal_id: octetsVersHex(m[3]), period_hash: octetsVersHex(m[4]), root: octetsVersHex(m[5]),
        period_start: BigInt(octetsVersHex(m[6])), period_end: BigInt(octetsVersHex(m[7])), first_seq: BigInt(octetsVersHex(m[8])), last_seq: BigInt(octetsVersHex(m[9])),
        version: Number(BigInt(octetsVersHex(m[10]))),
      };
      const uriLen = Number(BigInt(octetsVersHex(m[12])));
      meta.uri = Buffer.from(data.subarray(4 + 13 * 32, 4 + 13 * 32 + uriLen)).toString("utf8");
      const deja = this.periodes.some((p) => p.meta.org_id === meta.org_id && p.meta.period_hash === meta.period_hash);
      if (deja) statut = "0x0";
      else {
        const id = this.periodes.length + 1;
        this.periodes.push({ id, meta, publishedAt: BigInt(this.horodatage), publisher: from });
        const uriOctets = utf8Octets(meta.uri);
        const bourrage = (32 - (uriOctets.length % 32)) % 32;
        const dataLog = "0x" + [
          meta.org_id, meta.journal_id, meta.root, motU(meta.period_start), motU(meta.period_end), motU(meta.first_seq), motU(meta.last_seq),
          motU(meta.version), motU(0x140), motU(this.horodatage), motU(uriOctets.length),
        ].map((x) => x.slice(2)).join("") + Buffer.from(uriOctets).toString("hex") + "00".repeat(bourrage);
        logs = [{ address: this.contrats.period_registry, topics: [SUJETS.PeriodSubmitted, motU(id), meta.period_hash, motAdr(from)], data: dataLog }];
      }
    } else {
      statut = "0x0";
    }
    compte.nonce += 1n;
    compte.solde -= gasUsed * tx.maxFeePerGas;
    this.comptes.set(from, compte);
    return { statut, logs, gasUsed };
  }

  /** Inclut une transaction dans un nouveau bloc (un bloc par transaction). */
  #inclure(hash) {
    const t = this.transactions.get(hash);
    // L'horodatage du bloc est celui que lisent les contrats à l'exécution (`block.timestamp` : `publishedAt`,
    // `issuedAt`, `registeredAt`) ; il avance avant l'exécution (R-9 de CT-6 compare `publishedAt` à l'en-tête).
    this.horodatage += 1;
    const resultat = this.#executer(t.tx, hash);
    if (resultat.ecartee) {
      this.transactions.delete(hash);
      return;
    }
    const h = ++this.hauteur;
    const recuJson = {
      blockHash: null, blockNumber: q(h), contractAddress: null, cumulativeGasUsed: q(resultat.gasUsed), effectiveGasPrice: q(t.tx.maxFeePerGas),
      from: t.tx.from, gasPrice: q(t.tx.maxFeePerGas), gasUsed: q(resultat.gasUsed),
      logs: resultat.logs.map((l, k) => ({ address: l.address, blockHash: null, blockNumber: q(h), data: l.data, logIndex: q(k), removed: false, topics: l.topics, transactionHash: hash, transactionIndex: "0x0" })),
      status: resultat.statut, to: t.tx.to, transactionHash: hash, transactionIndex: "0x0", type: "0x2",
    };
    const recuRoot = octetsVersHex(racineRecus([{ type: "0x2", status: resultat.statut, cumulativeGasUsed: q(resultat.gasUsed), logs: resultat.logs }]));
    const txRoot = octetsVersHex(racineTransactions([t.raw]));
    const entete = {
      number: q(h), hash: null, parentHash: this.dernierHash, nonce: "0x0000000000000000", sha3Uncles: ZERO32,
      logsBloom: "0x" + "00".repeat(256), transactionsRoot: txRoot, stateRoot: octetsVersHex(sha256(utf8Octets("etat-" + h))),
      receiptsRoot: recuRoot, miner: ZERO20, difficulty: "0x0", totalDifficulty: "0x0", extraData: "0x", size: "0x0",
      gasLimit: "0x1c9c380", gasUsed: q(resultat.gasUsed), timestamp: q(this.horodatage), mixHash: ZERO32, baseFeePerGas: "0x1",
      transactions: [hash], uncles: [],
    };
    const bft = hachageBlocBft(entete);
    entete.hash = octetsVersHex(bft.hash);
    recuJson.blockHash = entete.hash;
    for (const l of recuJson.logs) l.blockHash = entete.hash;
    this.dernierHash = entete.hash;
    // Certificat : proposition de v1, precommits de v4, v1, v3 (quorum exact).
    const corpsProposition = {
      height: h, round: 0, proposer: this.validateurs[0].id, blockHash: entete.hash, parentHash: entete.parentHash, timestamp: this.horodatage,
      stateRoot: entete.stateRoot, receiptsRoot: entete.receiptsRoot, txRoot, gasUsed: Number(resultat.gasUsed), gasLimit: 30000000, baseFeeHex: "0x1",
      txsRaw: [encoderBase64(t.raw)], polkaRound: 0, polkaLines: [], sig: "",
    };
    const base = { chainId: this.bftChainId, valsetHash: this.jeu.hash, height: h, round: 0, blockHash: bft.hash };
    const proposition = enveloppe({ ...base, type: "CONS_PROPOSAL", validateur: this.validateurs[0], corps: corpsProposition });
    const precommits = [3, 0, 2].map((k) => enveloppe({
      ...base, type: "CONS_PRECOMMIT", validateur: this.validateurs[k],
      corps: { Height: h, Round: 0, Voter: this.validateurs[k].id, Type: 2, BlockHash: entete.hash, Sig: null },
    }));
    const certificat = {
      height: q(h), round: "0x0", chainId: this.bftChainId, valsetHash: octetsVersHex(this.jeu.hash), blockHash: entete.hash,
      canonical: { blockHash: entete.hash, matchesCertificate: true },
      proposal: { line: proposition.line, validatorId: proposition.validatorId, bodyHash: proposition.bodyHash, sig: proposition.sig },
      precommits: precommits.map((p) => ({ line: p.line, validatorId: p.validatorId, height: q(h), round: "0x0", blockHash: entete.hash, bodyHash: p.bodyHash, sig: p.sig })),
      quorum: { validators: 4, required: 3, precommits: 3 },
      validatorSet: this.jeu.validateurs.map((v) => ({ id: v.id, pubKeyHex: octetsVersHex(v.declaree) })),
      validatorSetHash: octetsVersHex(this.jeu.hash), validatorSetMatchesCertificate: true,
      signing: { domain: "noor/v1/bft", digestPrefix: "noor/v1/bft-sign|", scheme: "factice" },
      retention: { heights: 300000, pruned: false },
    };
    t.hauteur = h;
    t.index = 0;
    t.recu = recuJson;
    this.blocs.set(h, { entete, transactions: [hash], recus: new Map([[hash, recuJson]]), certificat });
  }

  // ----------------------------------------------------------- eth_call

  #appel(to, data) {
    const sel = data.slice(0, 10);
    const args = mots("0x" + data.slice(10)) ?? [];
    const A = this.contrats.attestation_registry;
    const R = this.contrats.recorder_registry;
    const P = this.contrats.period_registry;
    const h32 = (m) => octetsVersHex(m);
    if (to === A) {
      const fp = h32(args[0]);
      if (sel === SELECTEURS.isAnchored) return motU(this.ancres.has(fp) ? 1 : 0);
      if (sel === SELECTEURS.lookup) {
        const a = this.ancres.get(fp);
        return a ? "0x" + motAdr(a.issuer).slice(2) + a.docType.slice(2) + motU(a.issuedAt).slice(2) + motU(0).slice(2) : "0x" + "00".repeat(128);
      }
      if (sel === SELECTEURS.anchorDigest) return anchorDigest(this.evmChainId, A, fp, h32(args[1]));
    }
    if (to === R) {
      const orgId = h32(args[0]);
      if (sel === SELECTEURS.isActiveRecorder) {
        const e = this.enregistreurs.get(orgId + "0x" + Buffer.from(args[1].subarray(12)).toString("hex"));
        return motU(e && e.revokedAt === 0n ? 1 : 0);
      }
      const rendre = (e) => (e
        ? "0x" + motAdr(e.chainKey).slice(2) + e.ed25519PubKey.slice(2) + e.journalId.slice(2) + motU(e.registeredAt).slice(2) + motU(e.revokedAt).slice(2)
        : "0x" + "00".repeat(160));
      if (sel === SELECTEURS.recorderOf) return rendre(this.enregistreurs.get(orgId + "0x" + Buffer.from(args[1].subarray(12)).toString("hex")));
      if (sel === SELECTEURS.recorderByPubKey) return rendre([...this.enregistreurs.values()].find((e) => e.ed25519PubKey === h32(args[1]) && e.revokedAt === 0n));
    }
    if (to === P) {
      if (sel === SELECTEURS.isKnown) return motU(this.periodes.some((p) => p.meta.org_id === h32(args[0]) && p.meta.period_hash === h32(args[1])) ? 1 : 0);
      if (sel === SELECTEURS.latestPeriodOf) {
        const liste = this.periodes.filter((p) => p.meta.org_id === h32(args[0]) && p.meta.journal_id === h32(args[1]));
        return motU(liste.length ? liste[liste.length - 1].id : 0);
      }
      if (sel === SELECTEURS.getPeriod) {
        const p = this.periodes.find((x) => x.id === Number(BigInt(h32(args[0]))));
        if (!p) return "0x";
        const m = p.meta;
        const uri = utf8Octets(m.uri);
        const bourrage = (32 - (uri.length % 32)) % 32;
        return "0x" + [motU(0x20), m.org_id, m.journal_id, m.period_hash, m.root, motU(m.period_start), motU(m.period_end), motU(m.first_seq), motU(m.last_seq), motU(p.publishedAt), motU(m.version), motAdr(p.publisher), motU(0x180), motU(uri.length)].map((x) => x.slice(2)).join("") + Buffer.from(uri).toString("hex") + "00".repeat(bourrage);
      }
      if (sel === SELECTEURS.periodDigest) {
        // Décodage de E(meta) : u256(0x20) ‖ T(meta).
        const t = args.slice(1);
        const uriLen = Number(BigInt(h32(t[10])));
        const meta = {
          org_id: h32(t[0]), journal_id: h32(t[1]), period_hash: h32(t[2]), root: h32(t[3]),
          period_start: BigInt(h32(t[4])).toString(), period_end: BigInt(h32(t[5])).toString(), first_seq: BigInt(h32(t[6])).toString(), last_seq: BigInt(h32(t[7])).toString(),
          version: Number(BigInt(h32(t[8]))), uri: Buffer.from(hexVersOctets("0x" + data.slice(10)).subarray(32 + 11 * 32, 32 + 11 * 32 + uriLen)).toString("utf8"),
        };
        return periodDigest(this.evmChainId, P, meta);
      }
    }
    return null;
  }

  // -------------------------------------------------------------- RPC

  /** Répond à une requête JSON-RPC (objet) pour un point ; rend l'objet de réponse. */
  repondre(point, requete) {
    this.appels.push({ point, method: requete.method, params: requete.params });
    const id = requete.id;
    const ok = (result) => ({ jsonrpc: "2.0", id, result });
    const erreur = (code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
    const p = requete.params ?? [];
    switch (requete.method) {
      case "eth_chainId": return ok(q(this.evmChainId));
      case "noor_txindexStatus": return ok({ enabled: true, ready: true, ok: true, last_indexed_height: this.txindex.last_indexed_height(), finalized_height: this.hauteur - 64, lag_blocks: -64 });
      case "eth_getTransactionCount": return ok(q((this.comptes.get(p[0]) ?? { nonce: 0n }).nonce));
      case "eth_getBalance": return ok(q((this.comptes.get(p[0]) ?? { solde: 0n }).solde));
      case "eth_call": {
        const r = this.#appel(p[0].to, p[0].data);
        return r === null ? erreur(-32000, "execution reverted") : ok(r);
      }
      case "eth_sendRawTransaction": {
        if (this.rejets.has(point)) return erreur(-32000, this.rejets.get(point));
        let tx;
        try {
          tx = lireTransaction(p[0]);
        } catch {
          return erreur(-32602, "invalid params: invalid raw tx");
        }
        if (tx.chainId !== BigInt(this.evmChainId)) return erreur(-32000, "invalid chain id");
        const hash = octetsVersHex(tx.hash);
        const compte = this.comptes.get(tx.from) ?? { nonce: 0n };
        if (tx.nonce < compte.nonce) return erreur(-32000, "nonce too low");
        if (!this.transactions.has(hash)) this.transactions.set(hash, { raw: tx.raw, tx, hauteur: null, recu: null, sondages: 0 });
        return ok(hash);
      }
      case "eth_getTransactionReceipt": {
        const t = this.transactions.get(p[0]);
        if (!t) return ok(null);
        if (t.recu) return ok(t.recu);
        if (this.abandonnes.has(p[0])) return ok(null);
        t.sondages += 1;
        const attente = this.attenteInclusion.get(p[0]) ?? 0;
        if (t.sondages > attente) {
          this.#inclure(p[0]);
          const relu = this.transactions.get(p[0]);
          return ok(relu?.recu ?? null);
        }
        return ok(null);
      }
      case "eth_getTransactionByHash": {
        const t = this.transactions.get(p[0]);
        if (!t || this.abandonnes.has(p[0])) return ok(null);
        return ok({ hash: p[0], blockNumber: t.hauteur === null ? null : q(t.hauteur), from: t.tx.from, nonce: q(t.tx.nonce), input: octetsVersHex(t.tx.data) });
      }
      case "eth_getBlockByNumber": {
        const h = p[0] === "latest" ? this.hauteur : Number(BigInt(p[0]));
        const b = this.blocs.get(h);
        return ok(b ? b.entete : null);
      }
      case "noor_getCommitCertificate": {
        if (p.length !== 1 || typeof p[0] !== "string") return erreur(-32602, "invalid params");
        const h = p[0] === "latest" ? this.hauteur : Number(BigInt(p[0]));
        const retard = this.certificatsRetardes.get(h) ?? 0;
        if (retard > 0) {
          this.certificatsRetardes.set(h, retard - 1);
          return erreur(-32000, `commit certificate for block ${p[0]} not yet persisted; retry shortly`);
        }
        const b = this.blocs.get(h);
        if (!b) return erreur(-32000, "unknown block");
        return ok(b.certificat);
      }
      case "eth_getCode": return ok("0x6080");
      default: return erreur(-32601, "method not found");
    }
  }

  /** Transport injectable pour `ClientRpc` : octets JSON exacts de la réponse ; panne sur un point marqué. */
  transport() {
    return async ({ url, octets }) => {
      if (this.pannes.has(url)) {
        const { ErreurRpc } = await import("@noortrace/ancrage/registre");
        throw new ErreurRpc("noeud_injoignable", `${url} : injoignable (factice)`, url);
      }
      const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
      const reponse = this.repondre(url, requete);
      return { status: 200, octets: utf8Octets(JSON.stringify(reponse)) };
    };
  }
}

/** Jeu de validateurs d'essai de CT-4 (constantes.json), avec ses clés privées publiées. */
export function validateursEssai(constantes) {
  return {
    validators: constantes.test_validators.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })),
    cles: Object.fromEntries(constantes.test_validators.validators.map((v) => [v.id, v.private_key])),
  };
}

export { messageEip191, keccak256, sha256Hex, DOC_TYPE_PERIODE };
