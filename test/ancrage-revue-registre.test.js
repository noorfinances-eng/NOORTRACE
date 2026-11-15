// Revue de sécurité interne de l'étape 8 : registre. Un fait tiré d'un
// seul point JSON-RPC n'est jamais une preuve ni une issue durable (cause
// S-4 : recoupement à deux sources) : CT-4 EX-8.16 (réponses perdues à l'envoi :
// aucune issue `ecartee`, reprise par renvoi), EX-8.14 (nonce recoupé par deux
// points), OP-11 (reçu d'un seul point : aucune issue d'échec), CT-5 EX-9.7
// (`empreinte_squattee` confirmée par un second point), 
// (capture relue vérifiée, émetteur exigé), EX-7.1 (lecture du corps : une
// ErreurRpc par point), (règle de production et jeton du client
// JSON-RPC), CT-6 EX-12.2 (deux validateurs sous la même clé refusés).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256, sha256Hex, utf8, hexVersOctets } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
const ORG = CONSTANTES.organisation.org_id;
const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const K = {
  K2: { hash: "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", fingerprint: "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44" },
  K3: { hash: "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", fingerprint: "0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837" },
};
const CLE = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-01")));
const CLE_TIERS = new R.SignataireChaineFichier(hexVersOctets(CONSTANTES.accounts[0].private_key));
const ED25519_01 = CONSTANTES.recorders[0].public_key;
const mot = (hex) => String(hex).replace(/^0x/, "").padStart(64, "0");
const REPERTOIRES = [];

/**
 * Nœud factice derrière un transport qui laisse un point mentir ou perdre une
 * réponse : `intercepter({ url, requete, suite, noeud })` rend une réponse
 * JSON-RPC, lève une `ErreurRpc`, ou appelle `suite()` (la réponse honnête).
 */
function contexte({ intercepter = null, delais = {} } = {}) {
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
  const honnete = noeud.transport();
  const transport = async ({ url, octets, delaiMs, tailleMax }) => {
    const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
    const suite = async () => JSON.parse(Buffer.from((await honnete({ url, octets, delaiMs, tailleMax })).octets).toString("utf8"));
    const reponse = intercepter ? await intercepter({ url, requete, suite, noeud }) : await suite();
    return { status: 200, octets: new TextEncoder().encode(JSON.stringify(reponse)) };
  };
  const rpc = new R.ClientRpc({ points: POINTS, transport, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const repertoire = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-registre-"));
  REPERTOIRES.push(repertoire);
  let monotone = 0;
  const horloge = { murale: () => Date.UTC(2026, 10, 9, 12, 0, 0) + monotone, monotone: () => monotone };
  const attendre = async (ms) => { monotone += ms; };
  const jeux = { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" };
  const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux };
  const journal = [];
  const nouvelEnvoyeur = () => new R.Envoyeur({ rpc, repertoireEnvois: repertoire, instance, horloge, attendre, delais: { recuMs: 60000, sondageMs: 500, ...delais }, journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }) });
  noeud.approvisionner(CLE.adresse(), 4719000000n);
  noeud.approvisionner(CLE_TIERS.adresse(), 4719000000n);
  noeud.inscrire({ orgId: ORG, chainKey: CLE.adresse(), ed25519PubKey: ED25519_01, journalId: JOURNAL_REF });
  const envoyeur = nouvelEnvoyeur();
  const ancre = (k, e = envoyeur, cle = CLE, extra = {}) => e.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: k.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle, ...extra });
  const fichiers = () => fs.readdirSync(repertoire).sort();
  const envois = () => noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length;
  return { noeud, rpc, repertoire, horloge, envoyeur, nouvelEnvoyeur, instance, journal, ancre, fichiers, envois };
}

describe("ancrage, revue de sécurité de l'étape 8 : envoyeur du registre, recoupement à deux points (CT-4 §8.6 ; S-4)", function () {
  this.timeout(60000);
  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  it("CT-4 EX-8.16 : réponses perdues à l'envoi sur chaque point : l'envoi n'est pas écarté (aucune issue), il est repris par renvoi et son ancre capturée", async function () {
    let perdre = true;
    const c = contexte({
      intercepter: async ({ url, requete, suite }) => {
        if (requete.method === "eth_sendRawTransaction" && perdre) {
          await suite(); // le nœud reçoit et garde la transaction
          throw new R.ErreurRpc("noeud_injoignable", `${url} : délai dépassé`, url);
        }
        return suite();
      },
    });
    const r1 = await c.ancre(K.K2);
    expect(r1.type).to.equal("echec_registre");
    expect(r1.data.code).to.equal("noeud_injoignable");
    const hash = r1.outputs.transaction_hash;
    expect(c.fichiers()).to.deep.equal([`envoi-${hash}.json`]);
    expect(c.envoyeur.envoisEnAttente(CLE.adresse()).map((e) => e.transaction_hash), "l'envoi reste sans issue : une panne n'est pas un refus (EX-8.16)").to.deep.equal([hash]);
    perdre = false;
    // Le réseau a inclus la transaction ; le second `ancrer` attend le nonce (OP-3), le renvoi capture.
    const r2 = await c.ancre(K.K2);
    expect(r2.data.code).to.equal("attente_nonce");
    expect(r2.outputs.pending).to.deep.equal([hash]);
    const r3 = await c.envoyeur.renvoyer(hash);
    expect(r3.type, JSON.stringify(r3)).to.equal("inclusion_registre");
    expect(c.fichiers().some((n) => n.startsWith("capture-"))).to.equal(true);
    // Un refus JSON-RPC de chaque point reste `ecartee` (aucune mempool ne la tient).
    for (const p of POINTS) c.noeud.rejets.set(p, "insufficient funds");
    const r4 = await c.ancre(K.K3);
    expect(r4.data.code).to.equal("transaction_refusee");
    expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${r4.outputs.transaction_hash}.json`), "utf8")).state).to.equal("ecartee");
    // Deux refus et deux pannes : la transaction a pu atteindre un nœud, aucune issue.
    for (const p of POINTS.slice(0, 2)) c.noeud.rejets.delete(p);
    for (const p of POINTS.slice(0, 2)) c.noeud.pannes.add(p);
    const e2 = c.nouvelEnvoyeur();
    const r5 = await e2.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: sha256Hex(utf8("revue/registre/mixte")), docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_TIERS, sansInscription: true });
    expect(r5.data.code).to.equal("noeud_injoignable");
    expect(fs.existsSync(path.join(c.repertoire, `issue-${r5.outputs.transaction_hash}.json`))).to.equal(false);
  });

  it("CT-4 EX-8.14 : un seul point qui ment sur eth_getTransactionCount ne fait rien signer (nonce_incoherent, transitoire) ; corrigé, l'ancre part au vrai nonce", async function () {
    const MENTEUR = POINTS[3];
    let ment = true;
    const c = contexte({
      delais: { recuMs: 2000 },
      intercepter: async ({ url, requete, suite, noeud }) => {
        if (requete.method === "eth_getTransactionCount" && url === MENTEUR && ment) return { jsonrpc: "2.0", id: requete.id, result: "0x3" };
        if (requete.method === "eth_sendRawTransaction") {
          const tx = R.lireTransaction(requete.params[0]);
          const reel = (noeud.comptes.get(tx.from) ?? { nonce: 0n }).nonce;
          if (tx.nonce > reel) {
            if (url === MENTEUR && ment) return { jsonrpc: "2.0", id: requete.id, result: "0x" + Buffer.from(tx.hash).toString("hex") };
            return { jsonrpc: "2.0", id: requete.id, error: { code: -32000, message: "nonce too high" } };
          }
        }
        return suite();
      },
    });
    const r1 = await c.ancre(K.K2);
    expect(r1.type).to.equal("echec_registre");
    expect(r1.data.code).to.equal("lecture_nonce_incoherent");
    expect(c.envois(), "rien n'est signé ni envoyé sur un nonce que les points ne recoupent pas").to.equal(0);
    expect(c.fichiers()).to.deep.equal([]);
    ment = false;
    const r2 = await c.ancre(K.K2);
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
    expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, r2.outputs.envoi), "utf8")).nonce).to.equal(0);
    // Un point en retard d'un bloc (nonce réel − 1) n'empêche rien : le plus grand nonce recoupé par deux points est retenu.
    let retard = true;
    const c2 = contexte({
      intercepter: async ({ url, requete, suite, noeud }) => {
        if (requete.method === "eth_getTransactionCount" && url === POINTS[0] && retard) {
          const n = (noeud.comptes.get(requete.params[0]) ?? { nonce: 0n }).nonce;
          return { jsonrpc: "2.0", id: requete.id, result: "0x" + (n > 0n ? n - 1n : 0n).toString(16) };
        }
        return suite();
      },
    });
    expect((await c2.ancre(K.K2)).type).to.equal("inclusion_registre");
    expect((await c2.ancre(K.K3)).type).to.equal("inclusion_registre");
    retard = false;
  });

  it("CT-4 OP-11 : un reçu inventé par un seul point n'écrit aucune issue d'échec ; la transaction incluse ensuite est capturée au renvoi ; un reçu sans blockNumber lisible ou à hauteur démesurée est ignoré sans exception", async function () {
    for (const [nom, faux, attendu] of [
      ["a : status 0x0, blockNumber 0x1", { status: "0x0", blockNumber: "0x1" }, "recu_incertain"],
      ["b : status 0x1 sans blockNumber", { status: "0x1" }, "recu_absent"],
      ["c : status 0x0, blockNumber 0xffffffffffffffff", { status: "0x0", blockNumber: "0xffffffffffffffff" }, "recu_absent"],
    ]) {
      let ment = true;
      const c = contexte({
        delais: { recuMs: 2000, sondageMs: 500 },
        intercepter: async ({ url, requete, suite }) => {
          if (requete.method === "eth_getTransactionReceipt" && ment) {
            if (url === POINTS[1]) return { jsonrpc: "2.0", id: requete.id, result: { transactionHash: requete.params[0], blockHash: "0x" + "ab".repeat(32), logs: [], ...faux } };
            return { jsonrpc: "2.0", id: requete.id, result: null };
          }
          return suite();
        },
      });
      const r1 = await c.ancre(K.K2);
      expect(r1.type, nom).to.equal("echec_registre");
      expect(r1.data.code, nom).to.equal(attendu);
      const hash = c.fichiers().find((f) => f.startsWith("envoi-")).slice(6, -5);
      expect(c.fichiers().filter((f) => f.startsWith("issue-")), `${nom} : aucune issue sur la parole d'un seul point`).to.deep.equal([]);
      expect(c.envoyeur.envoisEnAttente(CLE.adresse()).length, nom).to.equal(1);
      ment = false;
      const r2 = await c.envoyeur.renvoyer(hash);
      expect(r2.type, `${nom} : ${JSON.stringify(r2)}`).to.equal("inclusion_registre");
      expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${hash}.json`), "utf8")).status, nom).to.equal("0x1");
    }
    // Un reçu à status 0x0 confirmé par un second point écrit l'issue (nonce consommé) ; la clé est libre.
    const c = contexte();
    const original = c.noeud.repondre.bind(c.noeud);
    c.noeud.repondre = (point, requete) => {
      const rep = original(point, requete);
      if (requete.method === "eth_sendRawTransaction" && rep.result && !c.noeud.ancres.has(K.K3.fingerprint)) c.noeud.ancres.set(K.K3.fingerprint, { issuer: CLE.adresse(), docType: R.DOC_TYPE_POINT_DE_CONTROLE, issuedAt: 1n });
      return rep;
    };
    const r3 = await c.ancre(K.K3);
    expect(r3.data.code).to.equal("transaction_annulee");
    expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${r3.outputs.transaction_hash}.json`), "utf8")).status).to.equal("0x0");
    expect(c.envoyeur.envoisEnAttente(CLE.adresse())).to.deep.equal([]);
  });

  it("CT-5 EX-9.7 : empreinte_squattee n'est rendue que confirmée par un second point ; un seul point qui l'invente donne lecture_incoherente, aucune transaction", async function () {
    const c = contexte({
      intercepter: async ({ url, requete, suite }) => {
        if (url === POINTS[0] && requete.method === "eth_call" && requete.params[0].to === CONTRATS.attestation_registry) {
          const d = requete.params[0].data;
          if (d.startsWith(R.SELECTEURS.isAnchored)) return { jsonrpc: "2.0", id: requete.id, result: "0x" + mot("1") };
          if (d.startsWith(R.SELECTEURS.lookup)) return { jsonrpc: "2.0", id: requete.id, result: "0x" + mot("0x" + "be".repeat(20)) + mot(R.DOC_TYPE_POINT_DE_CONTROLE) + mot("0x6543210f") + mot("0") };
        }
        return suite();
      },
    });
    const r = await c.ancre(K.K2);
    expect(r.type).to.equal("echec_registre");
    expect(r.data.code).to.equal("lecture_incoherente");
    expect(c.envois()).to.equal(0);
    // Deux points d'accord : empreinte_squattee (prise réelle par un tiers).
    const c2 = contexte();
    expect((await c2.ancre(K.K2, c2.nouvelEnvoyeur(), CLE_TIERS, { sansInscription: true })).type).to.equal("inclusion_registre");
    const r2 = await c2.ancre(K.K2);
    expect(r2.data.code).to.equal("empreinte_squattee");
    expect(r2.outputs.lookup.issuer).to.equal(CLE_TIERS.adresse());
  });

  it("une capture relue du disque est vérifiée avant d'être rendue (CP-2 à CP-6) et doit être celle de la clé de chaîne ; une capture d'autrui pour la même empreinte n'est jamais rendue inclusion_registre", async function () {
    const c = contexte();
    const r1 = await c.ancre(K.K2);
    expect(r1.type).to.equal("inclusion_registre");
    // Certificat vidé de ses precommits et en-tête altéré sur le disque après la capture.
    const cert = JSON.parse(fs.readFileSync(path.join(c.repertoire, "certificat-1001.json"), "utf8"));
    cert.result.precommits = [];
    fs.writeFileSync(path.join(c.repertoire, "certificat-1001.json"), JSON.stringify(cert));
    const e2 = c.nouvelEnvoyeur();
    const r2 = await c.ancre(K.K2, e2);
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
    const index = JSON.parse(fs.readFileSync(path.join(c.repertoire, "capture-1001-0-ancre.json"), "utf8"));
    const v = R.verifierCapture({ fichiers: c.repertoire, index, jeux: c.instance.jeux, bftChainId: "noortrace-2124-dev" });
    expect(v.premierEchec, "la capture rendue passe CP-2 à CP-6 : le certificat altéré a été mis de côté et redemandé").to.equal(null);
    expect(fs.readdirSync(c.repertoire).some((n) => n.startsWith("certificat-1001.json.rejete-"))).to.equal(true);
    // Capture de l'ancre d'un tiers pour la même empreinte, tous les points disant que l'émetteur est notre clé : deja_fait sans capture, jamais inclusion.
    const c3 = contexte({
      intercepter: async ({ requete, suite }) => {
        if (requete.method === "eth_call" && requete.params[0].to === CONTRATS.attestation_registry && requete.params[0].data.startsWith(R.SELECTEURS.lookup)) {
          const honnete = await suite();
          const issuedAt = BigInt("0x" + honnete.result.slice(2 + 128, 2 + 192));
          if (issuedAt === 0n) return honnete; // empreinte libre : rien à maquiller
          return { ...honnete, result: "0x" + mot(CLE.adresse()) + honnete.result.slice(2 + 64) };
        }
        return suite();
      },
    });
    expect((await c3.ancre(K.K3, c3.nouvelEnvoyeur(), CLE_TIERS, { sansInscription: true })).type).to.equal("inclusion_registre");
    const r3 = await c3.ancre(K.K3);
    expect(r3.type).to.equal("echec_registre");
    expect(r3.data.code).to.equal("deja_fait");
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : client JSON-RPC (CT-4 EX-7.1, EX-8.15)", function () {
  it("CT-4 EX-7.1 : une erreur pendant la lecture du corps est une ErreurRpc du point ; appelerTous rend une panne pour ce point et la réponse des autres", async function () {
    const corpsCoupe = () => ({
      status: 200,
      body: { getReader: () => ({ read: async () => { throw new TypeError("terminated"); }, cancel: async () => {} }) },
    });
    const sain = (id) => ({ status: 200, body: null, arrayBuffer: async () => new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id, result: "0x1" })).buffer });
    const fetchFactice = async (url, init) => (url === POINTS[0] ? corpsCoupe() : sain(JSON.parse(Buffer.from(init.body).toString("utf8")).id));
    const transport = R.transportHttp({ fetch: fetchFactice });
    let erreur = null;
    try {
      await transport({ url: POINTS[0], octets: R.ClientRpc.requete("eth_chainId", [], 1), delaiMs: 1000, tailleMax: 65536 });
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.be.instanceOf(R.ErreurRpc);
    expect(erreur.code).to.equal("noeud_injoignable");
    const rpc = new R.ClientRpc({ points: POINTS, transport });
    const tous = await rpc.appelerTous("eth_chainId", []);
    expect(tous.map((r) => (r.panne ? "panne" : r.resultat))).to.deep.equal(["panne", "0x1", "0x1", "0x1"]);
    const premier = await rpc.appelerPremier("eth_chainId", []);
    expect(premier.point).to.equal(POINTS[1]);
  });

  it("CT-4 EX-7.1 : en production, http:// vers la boucle locale seulement, au moins deux points, aucune chaîne de requête ni identifiant ; le jeton Bearer est envoyé en en-tête et n'apparaît ni dans les points ni dans un index", async function () {
    const transportSain = async ({ octets }) => ({ status: 200, octets: new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: JSON.parse(Buffer.from(octets).toString("utf8")).id, result: "0x1" })) });
    expect(() => new R.ClientRpc({ points: ["http://203.0.113.7:8545", "https://rpc.example"], profil: "production", transport: transportSain })).to.throw(/boucle locale/);
    expect(() => new R.ClientRpc({ points: ["https://rpc.example"], profil: "production", transport: transportSain })).to.throw(/deux/);
    expect(() => new R.ClientRpc({ points: ["https://rpc.example/v1?cle=secret", "https://rpc2.example"], profil: "production", transport: transportSain })).to.throw(/requête|fragment/);
    expect(() => new R.ClientRpc({ points: ["https://rpc.example/v1/jeton-secret#x", "https://rpc2.example"], profil: "production", transport: transportSain })).to.throw(/requête|fragment/);
    expect(() => new R.ClientRpc({ points: ["https://u:p@rpc.example", "https://rpc2.example"], profil: "production", transport: transportSain })).to.throw(/identifiant/);
    // Hors production : un point http:// vers un hôte quelconque reste admis (réseau de développement).
    expect(() => new R.ClientRpc({ points: ["http://203.0.113.7:8545"], transport: transportSain })).to.not.throw();
    const admis = new R.ClientRpc({ points: ["http://127.0.0.1:8645", "https://rpc.example"], profil: "production", transport: transportSain });
    expect(admis.points()).to.deep.equal(["http://127.0.0.1:8645", "https://rpc.example"]);
    // Jeton : en-tête Authorization: Bearer sur chaque requête, jamais dans points() ni dans la requête.
    const entetesVus = [];
    const transportEspion = async ({ octets, entetes }) => {
      entetesVus.push(entetes ?? {});
      return transportSain({ octets });
    };
    const rpc = new R.ClientRpc({ points: ["https://rpc.example", "https://rpc2.example"], profil: "production", transport: transportEspion, jeton: "jeton-d-essai-sans-valeur-0123456789" });
    await rpc.appelerTous("eth_chainId", []);
    expect(entetesVus).to.have.lengthOf(2);
    for (const h of entetesVus) expect(h.authorization).to.equal("Bearer jeton-d-essai-sans-valeur-0123456789");
    expect(JSON.stringify(rpc.points())).to.not.include("jeton-d-essai");
    expect(JSON.stringify(rpc)).to.not.include("jeton-d-essai");
    // Le transport par défaut pose l'en-tête.
    let entetesFetch = null;
    const t = R.transportHttp({ fetch: async (url, init) => { entetesFetch = init.headers; return { status: 200, body: null, arrayBuffer: async () => new TextEncoder().encode("{}").buffer }; } });
    await t({ url: "https://rpc.example", octets: new Uint8Array(2), delaiMs: 1000, tailleMax: 10, entetes: { authorization: "Bearer x" } });
    expect(entetesFetch.authorization).to.equal("Bearer x");
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : jeu de validateurs (CT-6 EX-12.2)", function () {
  it("deux validateurs sous la même clé publique sont refusés par lireJeu, comme par le vérificateur", function () {
    const jeu = validateursEssai(CONSTANTES).validators;
    expect(R.lireJeu(jeu)).to.not.equal(null);
    const doublon = [...jeu.slice(0, 3), { id: "v5", pubKeyHex: jeu[0].pubKeyHex }];
    expect(R.lireJeu(doublon), "deux identifiants sous la même clé : une clé compterait deux fois au quorum").to.equal(null);
    expect(R.lireJeux({ validators: doublon })).to.equal(null);
  });
});
