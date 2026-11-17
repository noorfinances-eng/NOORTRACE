// Composant d'ancrage, registre : plancher du nonce d'EX-8.14 de CT-4
// (complément du 2026-11-17). L'`Envoyeur` conclut l'inclusion au premier
// point qui rend le reçu ; les autres peuvent ne pas avoir encore appliqué ce
// bloc. Le nonce recoupé par deux points est alors celui qui vient d'être
// consommé : refus partout (« nonce too low » du point à jour, « replacement
// transaction underpriced » des points en retard qui tiennent encore la
// transaction incluse), observé sur le réseau de développement. Le nonce
// signé n'est jamais inférieur à n + 1, n étant le plus grand nonce des envois
// de l'expéditeur dont l'inclusion est écrite ; un plancher qui dépasse de
// plus de 1 la valeur des points ne fait rien signer (`nonce_incoherent`).
//
// Sans réseau : nœud factice (test/fixtures/ancrage-registre/noeud-factice.mjs)
// derrière un transport qui fait répondre trois points sur quatre avec un bloc
// de retard ; horloge et attentes injectées.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256, sha256Hex, utf8 } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const CONSTANTES = JSON.parse(fs.readFileSync(path.join(RACINE, "spec/vecteurs/ct-4/constantes.json"), "utf8"));
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
const ORG = CONSTANTES.organisation.org_id;
const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const CLE = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-01")));
const ED25519_01 = CONSTANTES.recorders[0].public_key;
const REPERTOIRES = [];
const objet = (k) => sha256Hex(utf8(`noortrace/essai/nonce-plancher/${k}`));

/**
 * `points` validateurs ; `retard(url)` : nombre de blocs de retard du point
 * pour l'expéditeur (0 : à jour). Un point en retard rend le nonce de sa
 * hauteur, ne rend pas le reçu des transactions qu'il n'a pas appliquées et
 * refuse une transaction au nonce d'une transaction qu'il tient encore
 * (« replacement transaction underpriced »).
 */
function contexte({ points = POINTS, retard = () => 0, repertoire = null } = {}) {
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points, contrats: CONTRATS });
  const honnete = noeud.transport();
  const inclusions = []; // hachages inclus, dans l'ordre (un bloc par transaction)
  const transport = async ({ url, octets, delaiMs, tailleMax }) => {
    const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
    const suite = async () => JSON.parse(Buffer.from((await honnete({ url, octets, delaiMs, tailleMax })).octets).toString("utf8"));
    const d = BigInt(retard(url));
    let reponse;
    if (d > 0n && requete.method === "eth_getTransactionCount") {
      const n = (noeud.comptes.get(requete.params[0]) ?? { nonce: 0n }).nonce;
      reponse = { jsonrpc: "2.0", id: requete.id, result: "0x" + (n > d ? n - d : 0n).toString(16) };
    } else if (d > 0n && requete.method === "eth_getTransactionReceipt" && inclusions.slice(-Number(d)).includes(requete.params[0])) {
      reponse = { jsonrpc: "2.0", id: requete.id, result: null };
    } else if (d > 0n && requete.method === "eth_sendRawTransaction") {
      const tx = R.lireTransaction(requete.params[0]);
      const reel = (noeud.comptes.get(tx.from) ?? { nonce: 0n }).nonce;
      if (tx.nonce < reel && tx.nonce >= reel - d) reponse = { jsonrpc: "2.0", id: requete.id, error: { code: -32000, message: "replacement transaction underpriced" } };
      else reponse = await suite();
    } else {
      reponse = await suite();
      if (requete.method === "eth_getTransactionReceipt" && reponse.result && !inclusions.includes(requete.params[0])) inclusions.push(requete.params[0]);
    }
    return { status: 200, octets: new TextEncoder().encode(JSON.stringify(reponse)) };
  };
  const rpc = new R.ClientRpc({ points, transport, identifiants: Object.fromEntries(points.map((p, k) => [p, `v${k + 1}`])) });
  const rep = repertoire ?? fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-nonce-plancher-"));
  if (!repertoire) REPERTOIRES.push(rep);
  let monotone = 0;
  const horloge = { murale: () => Date.UTC(2026, 10, 17, 6, 0, 0) + monotone, monotone: () => monotone };
  const attendre = async (ms) => { monotone += ms; };
  const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux: { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" } };
  noeud.approvisionner(CLE.adresse(), 4719000000n);
  noeud.inscrire({ orgId: ORG, chainKey: CLE.adresse(), ed25519PubKey: ED25519_01, journalId: JOURNAL_REF });
  const nouvelEnvoyeur = () => new R.Envoyeur({ rpc, repertoireEnvois: rep, instance, horloge, attendre, delais: { recuMs: 5000, sondageMs: 500 } });
  const envoyeur = nouvelEnvoyeur();
  const ancre = (k, e = envoyeur) => e.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: objet(k), docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE });
  const envoi = (r) => JSON.parse(fs.readFileSync(path.join(rep, r.outputs.envoi), "utf8"));
  const soumissions = () => noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length;
  return { noeud, rep, envoyeur, nouvelEnvoyeur, ancre, envoi, soumissions };
}

describe("ancrage, registre : plancher du nonce d'EX-8.14 (CT-4 §8.6, complément du 2026-11-17)", function () {
  this.timeout(60000);
  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  it("trois points sur quatre en retard d'un bloc après le reçu : chaque ancre suivante est signée au plancher (n + 1) et incluse, sans refus ni écart ; un nouvel Envoyeur relit le plancher dans le répertoire", async function () {
    const c = contexte({ retard: (url) => (url === POINTS[0] ? 0 : 1) });
    const r1 = await c.ancre(1);
    expect(r1.type, JSON.stringify(r1)).to.equal("inclusion_registre");
    expect(c.envoi(r1).nonce).to.equal(0);
    const r2 = await c.ancre(2);
    expect(r2.type, `le nonce recoupé par les trois points en retard est celui qui vient d'être consommé : ${JSON.stringify(r2)}`).to.equal("inclusion_registre");
    expect(c.envoi(r2).nonce).to.equal(1);
    const r3 = await c.ancre(3);
    expect(r3.type, JSON.stringify(r3)).to.equal("inclusion_registre");
    expect(c.envoi(r3).nonce).to.equal(2);
    // Après un redémarrage : l'index relu du répertoire porte le même plancher.
    const r4 = await c.ancre(4, c.nouvelEnvoyeur());
    expect(r4.type, JSON.stringify(r4)).to.equal("inclusion_registre");
    expect(c.envoi(r4).nonce).to.equal(3);
    expect(fs.readdirSync(c.rep).filter((f) => f.startsWith("issue-")).map((f) => JSON.parse(fs.readFileSync(path.join(c.rep, f), "utf8")).state ?? "incluse")).to.deep.equal(["incluse", "incluse", "incluse", "incluse"]);
    expect(c.soumissions(), "une soumission par point et par ancre, aucune reprise").to.equal(16);
  });

  it("plancher au-delà de la valeur des points + 1 : rien n'est signé (lecture_nonce_incoherent, transitoire) ; quand les points rejoignent, l'ancre part au plancher", async function () {
    let decalage = 0;
    const c = contexte({ retard: () => decalage });
    expect((await c.ancre(1)).type).to.equal("inclusion_registre");
    expect((await c.ancre(2)).type).to.equal("inclusion_registre");
    decalage = 2; // les quatre points rendent 0, le plancher est 2 : aucune lecture ne rejoint les deux inclusions écrites
    const avant = c.soumissions();
    const r = await c.ancre(3);
    expect(r.type).to.equal("echec_registre");
    expect(r.data.code).to.equal("lecture_nonce_incoherent");
    expect(c.soumissions(), "aucune transaction soumise").to.equal(avant);
    expect(c.envoyeur.envoisEnAttente(CLE.adresse())).to.deep.equal([]);
    decalage = 0;
    const r2 = await c.ancre(3);
    expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
    expect(c.envoi(r2).nonce).to.equal(2);
  });

  it("points en avance sur le plancher (expéditeur qui a signé ailleurs) : la valeur recoupée des points est retenue ; la règle de recoupement est inchangée (deux points qui diffèrent : nonce_incoherent)", async function () {
    const c = contexte();
    expect((await c.ancre(1)).type).to.equal("inclusion_registre");
    c.noeud.comptes.get(CLE.adresse()).nonce += 3n; // trois transactions de la même clé, hors de ce répertoire
    const r = await c.ancre(2);
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    expect(c.envoi(r).nonce).to.equal(4);
    // Deux points seulement, l'un en retard : aucune valeur rendue par deux points, comme avant le plancher.
    const d = contexte({ points: POINTS.slice(0, 2), retard: (url) => (url === POINTS[0] ? 0 : 1) });
    expect((await d.ancre(1)).type).to.equal("inclusion_registre");
    const r2 = await d.ancre(2);
    expect(r2.data.code).to.equal("lecture_nonce_incoherent");
  });

  it("plancherNonceParHash et retenirNonce : issues d'inclusion (status 0x1 et 0x0), écartées, sans issue, autre expéditeur, original inclus après son remplacement", function () {
    const A = "0x" + "aa".repeat(20);
    const B = "0x" + "bb".repeat(20);
    const h = (k) => "0x" + k.toString(16).padStart(64, "0");
    const index = new Map();
    const mettre = (k, from, nonce, issue) => index.set(h(k), { envoi: { from, nonce, transaction_hash: h(k) }, issue });
    expect(R.plancherNonceParHash(index, A)).to.equal(null);
    mettre(1, A, 4, { block_number: 10, status: "0x1" });
    mettre(2, A, 5, { block_number: 11, status: "0x0" });
    mettre(3, A, 9, { state: "ecartee" });
    mettre(4, A, 8, null);
    mettre(5, B, 30, { block_number: 12, status: "0x1" });
    expect(R.plancherNonceParHash(index, A)).to.equal(6n);
    expect(R.plancherNonceParHash(index, B)).to.equal(31n);
    // Original au nonce 7 remplacé, puis inclus : le remplaçant est écarté et le désigne par `replaces` (EX-8.16).
    mettre(6, A, 7, { state: "remplacee", replaced_by: h(7) });
    mettre(7, A, 7, { state: "ecartee", replaces: h(9) });
    expect(R.plancherNonceParHash(index, A), "remplaçant écarté qui désigne un autre envoi").to.equal(6n);
    mettre(7, A, 7, { state: "ecartee", replaces: h(6) });
    expect(R.plancherNonceParHash(index, A)).to.equal(8n);
    expect(R.retenirNonce(5n, null)).to.deep.equal({ nonce: 5n });
    expect(R.retenirNonce(5n, 5n)).to.deep.equal({ nonce: 5n });
    expect(R.retenirNonce(5n, 3n)).to.deep.equal({ nonce: 5n });
    expect(R.retenirNonce(5n, 6n)).to.deep.equal({ nonce: 6n });
    expect(R.retenirNonce(5n, 7n).incoherent).to.be.a("string");
  });
});
