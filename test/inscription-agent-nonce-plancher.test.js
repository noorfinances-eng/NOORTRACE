// Agent d'inscription : plancher du nonce d'EX-8.14 de CT-4 (complément du
// 2026-11-17). L'agent prend le reçu au premier point qui le rend, puis lit
// le nonce comme le plus grand que rendent les points qui répondent. Si le
// point qui a rendu le reçu ne répond plus à cette lecture, les autres, en
// retard d'un bloc, rendent le nonce qui vient d'être consommé : la
// transaction suivante est refusée partout. Le nonce signé n'est jamais
// inférieur à n + 1, n étant le plus grand nonce des envois de l'expéditeur
// dont l'inclusion est écrite (`issue-<hachage>.json`).
//
// Recoupement d'EX-8.14 : la valeur des points est la plus grande que rendent
// au moins deux points (et non la plus grande de tous les points) ; aucune
// valeur rendue par deux points, ou un point au-delà de cette valeur + 1, et
// rien n'est signé (`nonce_incoherent`), comme dans le composant d'ancrage.
//
// Sans réseau : `envoyer` de l'agent (paquets/inscription/src/agent/envoi.mjs)
// sur le nœud factice du composant d'ancrage, derrière un transport qui fait
// répondre trois points sur quatre avec un bloc de retard, ou fait mentir le
// premier point, ou rend les trois autres muets.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { octetsVersHex, sha256, sha256Hex, utf8 } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";
import { envoyer } from "../paquets/inscription/src/agent/envoi.mjs";
import { FinCommande, Sortie } from "../paquets/inscription/src/agent/sortie.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const CONSTANTES = JSON.parse(fs.readFileSync(path.join(RACINE, "spec/vecteurs/ct-4/constantes.json"), "utf8"));
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
const CLE = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-01")));
const REPERTOIRES = [];

function contexte() {
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
  const honnete = noeud.transport();
  const inclusions = [];
  const etat = { retard: false, muet: false, ment: false, autresMuets: false };
  const transport = async ({ url, octets, delaiMs, tailleMax }) => {
    const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
    const suite = async () => JSON.parse(Buffer.from((await honnete({ url, octets, delaiMs, tailleMax })).octets).toString("utf8"));
    const enRetard = etat.retard && url !== POINTS[0];
    let reponse;
    if (etat.muet && url === POINTS[0] && requete.method === "eth_getTransactionCount") throw new R.ErreurRpc("noeud_injoignable", `${url} : délai dépassé (factice)`, url);
    if (etat.autresMuets && url !== POINTS[0] && requete.method === "eth_getTransactionCount") throw new R.ErreurRpc("noeud_injoignable", `${url} : délai dépassé (factice)`, url);
    if (etat.ment && url === POINTS[0] && requete.method === "eth_getTransactionCount") {
      const n = (noeud.comptes.get(requete.params[0]) ?? { nonce: 0n }).nonce;
      return { status: 200, octets: new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: requete.id, result: "0x" + (n + 5n).toString(16) })) };
    }
    if (enRetard && requete.method === "eth_getTransactionCount") {
      const n = (noeud.comptes.get(requete.params[0]) ?? { nonce: 0n }).nonce;
      reponse = { jsonrpc: "2.0", id: requete.id, result: "0x" + (n > 0n ? n - 1n : 0n).toString(16) };
    } else if (enRetard && requete.method === "eth_getTransactionReceipt" && inclusions.at(-1) === requete.params[0]) {
      reponse = { jsonrpc: "2.0", id: requete.id, result: null };
    } else if (enRetard && requete.method === "eth_sendRawTransaction") {
      const tx = R.lireTransaction(requete.params[0]);
      const reel = (noeud.comptes.get(tx.from) ?? { nonce: 0n }).nonce;
      reponse = tx.nonce === reel - 1n ? { jsonrpc: "2.0", id: requete.id, error: { code: -32000, message: "replacement transaction underpriced" } } : await suite();
    } else {
      reponse = await suite();
      if (requete.method === "eth_getTransactionReceipt" && reponse.result && !inclusions.includes(requete.params[0])) inclusions.push(requete.params[0]);
    }
    return { status: 200, octets: new TextEncoder().encode(JSON.stringify(reponse)) };
  };
  const rpc = new R.ClientRpc({ points: POINTS, transport, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const captures = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-agent-nonce-plancher-"));
  REPERTOIRES.push(captures);
  let monotone = 0;
  const ctx = {
    instance: { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux: { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" } },
    rpc, captures, delaiMs: 5000,
    horloge: { murale: () => Date.UTC(2026, 10, 17, 6, 0, 0) + monotone, monotone: () => monotone },
    attendre: async (ms) => { monotone += ms; },
    consigner: () => {},
  };
  noeud.approvisionner(CLE.adresse(), 4719000000n);
  /** Ancre d'une empreinte d'essai par `envoyer` de l'agent ; rend `{ fin|null, resultat|null }`. */
  const ancrer = async (k) => {
    const fingerprint = sha256Hex(utf8(`noortrace/essai/agent-nonce-plancher/${k}`));
    const docType = R.DOC_TYPE_POINT_DE_CONTROLE;
    const sig = await CLE.signerCondense(R.hachageSigne(R.anchorDigest(2124, CONTRATS.attestation_registry, fingerprint, docType)));
    const donnees = octetsVersHex(R.encoderAnchor({ fingerprint, doc_type: docType, issuer: CLE.adresse(), signature: { v: sig.v, r: sig.r, s: sig.s } }));
    try {
      const resultat = await envoyer(ctx, new Sortie("capturer"), { cle: CLE, objet: "appel", to: CONTRATS.attestation_registry, donnees, role: "ancre", contrat: CONTRATS.attestation_registry, attendu: { fingerprint } });
      return { fin: null, resultat };
    } catch (e) {
      if (!(e instanceof FinCommande)) throw e;
      return { fin: e, resultat: null };
    }
  };
  return { noeud, ctx, etat, ancrer };
}

describe("inscription : agent, plancher du nonce d'EX-8.14 (CT-4 §8.6, complément du 2026-11-17)", function () {
  this.timeout(60000);
  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  it("le point qui a rendu le reçu ne répond plus à la lecture du nonce, les trois autres ont un bloc de retard : la transaction suivante est signée au plancher (n + 1) et incluse, sans refus", async function () {
    const c = contexte();
    const r1 = await c.ancrer(1);
    expect(r1.fin, r1.fin?.message).to.equal(null);
    expect(r1.resultat.envoi.nonce).to.equal(0);
    c.etat.retard = true;
    c.etat.muet = true;
    const r2 = await c.ancrer(2);
    expect(r2.fin, `nonce lu sur les points en retard : ${r2.fin?.code} ${r2.fin?.message}`).to.equal(null);
    expect(r2.resultat.envoi.nonce).to.equal(1);
    expect(r2.resultat.blockNumber).to.be.above(r1.resultat.blockNumber);
  });

  it("plancher au-delà de la valeur des points + 1 : rien n'est signé ni envoyé (nonce_incoherent, refuse)", async function () {
    const c = contexte();
    expect((await c.ancrer(1)).fin).to.equal(null);
    expect((await c.ancrer(2)).fin).to.equal(null);
    c.noeud.comptes.get(CLE.adresse()).nonce = 0n; // les points ne connaissent aucune des deux inclusions écrites
    const avant = c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length;
    const r = await c.ancrer(3);
    expect(r.fin?.code).to.equal("nonce_incoherent");
    expect(r.fin.result).to.equal("refuse");
    expect(c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length).to.equal(avant);
    expect(fs.readdirSync(c.ctx.captures).filter((f) => f.startsWith("envoi-")).length, "aucun envoi écrit").to.equal(2);
  });

  it("recoupement : le premier point rend cinq de plus que les trois autres ; les points diffèrent de plus de 1, rien n'est signé ni envoyé (nonce_incoherent, refuse)", async function () {
    const c = contexte();
    expect((await c.ancrer(1)).fin).to.equal(null);
    c.etat.ment = true;
    const avant = c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length;
    const r = await c.ancrer(2);
    expect(r.fin?.code, `${r.fin?.code} ${r.fin?.message} ; nonce ${r.resultat?.envoi?.nonce}`).to.equal("nonce_incoherent");
    expect(r.fin.result).to.equal("refuse");
    expect(c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length).to.equal(avant);
    expect(fs.readdirSync(c.ctx.captures).filter((f) => f.startsWith("envoi-")).length, "aucun envoi écrit").to.equal(1);
  });

  it("recoupement : seul le premier des quatre points répond à eth_getTransactionCount ; aucune valeur rendue par deux points, rien n'est signé (nonce_incoherent, refuse)", async function () {
    const c = contexte();
    c.etat.autresMuets = true;
    const r = await c.ancrer(1);
    expect(r.fin?.code, `${r.fin?.code} ${r.fin?.message} ; nonce ${r.resultat?.envoi?.nonce}`).to.equal("nonce_incoherent");
    expect(r.fin.result).to.equal("refuse");
    expect(c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length).to.equal(0);
  });

  it("recouperNonce (composant d'ancrage, employé par l'agent) : un point, sa valeur ; plusieurs, la plus grande rendue par deux points ; un point en retard ne bloque pas ; au-delà de + 1 ou sans paire, incohérent", function () {
    expect(R.recouperNonce([7n], 1)).to.deep.equal({ nonce: 7n });
    expect(R.recouperNonce([7n], 4).incoherent).to.be.a("string");
    expect(R.recouperNonce([5n, 5n, 6n, 6n], 4)).to.deep.equal({ nonce: 6n });
    expect(R.recouperNonce([5n, 5n, 6n, 2n], 4)).to.deep.equal({ nonce: 5n });
    expect(R.recouperNonce([5n, 5n, 7n], 3).incoherent).to.be.a("string");
    expect(R.recouperNonce([5n, 6n], 2).incoherent).to.be.a("string");
  });
});
