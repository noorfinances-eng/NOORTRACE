// CT-4 OP-8 (complément du 2026-11-16) : le démon transmet au composant
// d'ancrage le bloc de déploiement du `RecorderRegistry` en service, lu dans
// le manifeste d'instance du registre (CT-4 §4.8, `contracts[].block_number`),
// et le relais d'inscription du composant (`Envoyeur.inscrire`, qui sert au
// démon pendant une rotation de la clé de chaîne, CT-2 EX-11.16) lit les
// événements `RecorderRegistered` de ce bloc à la tête, et non depuis le
// bloc 0 : une lecture depuis le bloc 0 reste juste, mais elle coûte une
// lecture par tranche de 16 384 blocs depuis la genèse.
//
// L'instance est celle que rend `instanceDepuisManifeste` du démon
// (paquets/enregistreur/src/ancrage-demon.mjs), lu dans le dépôt ou sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge) ; le relais est celui du
// dépôt, sur le nœud noorcore factice de test/fixtures/ancrage-registre. Le
// mutant est une copie de paquets/enregistreur/src sous NOORTRACE_TMP (défaut
// os.tmpdir()), détruite à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sha256, utf8, octetsVersHex } from "@noortrace/noyau";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CONSTANTES = JSON.parse(fs.readFileSync(path.join(DEPOT, "spec/vecteurs/ct-4/constantes.json"), "utf8"));
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646"];
const CONTRATS = {
  attestation_registry: CONSTANTES.contracts.attestation_registry,
  period_registry: CONSTANTES.contracts.period_registry,
  recorder_registry: CONSTANTES.contracts.recorder_registry,
};
const ORG = CONSTANTES.organisation.org_id;
const JOURNAL = CONSTANTES.journal.journal_id;
const graine = (nom) => sha256(utf8(`noortrace/essai/enregistreur/ancrage-registre-deploiement/${nom}`));
const ORG_AUTRE = octetsVersHex(graine("autre-organisation"));
const ed25519 = (nom) => octetsVersHex(graine(`ed25519-${nom}`));
const SIGNER_SET = { curator_set: "0x" + "a1".repeat(20), threshold: 2, height: 1000, block_hash: "0x" + "9d".repeat(32) };
/** Bloc de déploiement du RecorderRegistry dans le manifeste d'essai ; l'inscription de l'autre organisation est au-delà. */
const DEPLOIEMENT = 18000;
const COPIES = [];
const DIRS = [];

/**
 * Manifeste d'instance de la forme de CT-4 §4.8 (`contracts[]` nommés, avec `block_number`) : un premier
 * `RecorderRegistry`, retiré, puis celui en service, déployé au bloc DEPLOIEMENT.
 */
function manifeste() {
  const entree = (name, address, block_number, to_height = null) => ({ name, address, deployer: "0x" + "f3".repeat(20), nonce: 1, constructor_args: [], transaction_hash: "0x" + "c5".repeat(32), block_number, block_hash: null, evidence: null, to_height });
  return {
    bft_chain_id: "noortrace-2124-dev",
    evm_chain_id: 2124,
    fees: { gas_limit: 3000000, gas_limit_max: 16777216 },
    contracts: [
      entree("AttestationRegistry", CONTRATS.attestation_registry, 8316),
      entree("PeriodRegistry", CONTRATS.period_registry, 8324),
      entree("RecorderRegistry", "0x" + "0b".repeat(20), 8328, 17999),
      entree("RecorderRegistry", CONTRATS.recorder_registry, DEPLOIEMENT),
    ],
    validator_sets: [{ from_height: 0, to_height: null }],
  };
}

/** Module du démon (`instanceDepuisManifeste`) lu sous une racine. */
const demonDe = (racine) => import(pathToFileURL(path.join(racine, "paquets", "enregistreur", "src", "ancrage-demon.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
const registre = () => import(pathToFileURL(path.join(DEPOT, "paquets", "ancrage", "src", "registre", "index.mjs")).href);

/** Copie de paquets/enregistreur/src où le remplacement, unique, est appliqué ; rend sa racine. */
function copieMutante(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-deploiement-mutant-${nom}-`));
  COPIES.push(racine);
  const paquet = path.join(racine, "paquets", "enregistreur");
  fs.mkdirSync(paquet, { recursive: true });
  fs.cpSync(path.join(RACINE, "paquets", "enregistreur", "src"), path.join(paquet, "src"), { recursive: true });
  for (const l of ["schemas", "package.json"]) fs.symlinkSync(path.join(DEPOT, "paquets", "enregistreur", l), path.join(paquet, l));
  fs.symlinkSync(path.join(DEPOT, "node_modules"), path.join(racine, "node_modules"));
  const f = path.join(paquet, "src", "ancrage-demon.mjs");
  const texte = fs.readFileSync(f, "utf8");
  expect(texte.split(ancien).length - 1, `mutant ${nom} : « ${ancien} »`).to.equal(1);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}

/**
 * Le relais du dépôt, avec l'instance que le démon `D` tire du manifeste, inscrit sous ORG une clé de chaîne déjà
 * inscrite sous ORG_AUTRE au bloc 20 000 (tête 40 000). Rend l'issue et les lectures `eth_getLogs`.
 */
async function relaisAvecInstanceDuDemon(D) {
  const R = await registre();
  const { instance, erreur } = D.instanceDepuisManifeste(manifeste());
  expect(erreur).to.equal(null);
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
  const rpc = new R.ClientRpc({ points: POINTS, transport: noeud.transport(), identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const repertoire = fs.mkdtempSync(path.join(TMP, "noortrace-deploiement-envois-"));
  DIRS.push(repertoire);
  let monotone = 0;
  const horloge = { murale: () => Date.UTC(2026, 10, 16, 12, 0, 0) + monotone, monotone: () => monotone };
  const envoyeur = new R.Envoyeur({
    rpc, repertoireEnvois: repertoire, instance: { ...instance, jeux: { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" } }, horloge,
    attendre: async (ms) => { monotone += ms; }, delais: { recuMs: 60000, sondageMs: 500 }, journal: () => {},
  });
  const relais = new R.SignataireChaineFichier(graine("relais"));
  noeud.approvisionner(relais.adresse(), 4719000000n);
  const approbateurs = [1, 2].map((k) => new R.SignataireChaineFichier(graine(`approbateur-${k}`)));
  const x = new R.SignataireChaineFichier(graine("chaine")).adresse();
  noeud.hauteur = 20000;
  noeud.inscrire({ orgId: ORG_AUTRE, chainKey: x, ed25519PubKey: ed25519("ailleurs"), journalId: JOURNAL });
  noeud.hauteur = 40000;
  const digest = R.registerDigest(2124, CONTRATS.recorder_registry, ORG, JOURNAL, x, ed25519("ici"));
  const h = R.hachageSigne(digest);
  const demande = {
    version: 0, operation: "inscription", evm_chain_id: 2124, contract: CONTRATS.recorder_registry,
    fields: { org_id: ORG, journal_id: JOURNAL, chain_key: x, ed25519_public_key: ed25519("ici") },
    digest, eip191_digest: octetsVersHex(h), signer_set: { ...SIGNER_SET },
    signatures: approbateurs.map((a) => ({ signer: a.adresse(), ...a.signerCondense(h) })).sort((p, q) => (p.signer < q.signer ? -1 : 1)),
    prepared_at: "2026-11-16T12:00:00.000Z",
  };
  const r = await envoyeur.inscrire({ demande, cle: relais });
  const lectures = noeud.appels.filter((a) => a.method === "eth_getLogs").map((a) => [a.params[0].fromBlock, a.params[0].toBlock]);
  const envois = noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").length;
  return { instance, r, lectures, envois };
}

describe("démon enregistreur et composant d'ancrage : bloc de déploiement du RecorderRegistry transmis au relais d'inscription (CT-4 OP-8, complément du 2026-11-16)", function () {
  this.timeout(120000);

  after(function () {
    for (const d of [...COPIES, ...DIRS]) fs.rmSync(d, { recursive: true, force: true });
  });

  it("instanceDepuisManifeste porte deploiements.recorder_registry.block_number, celui de l'entrée retenue du RecorderRegistry (son adresse) ; sans block_number, ni deploiements ni bloc inventé", async function () {
    const D = await demonDe(RACINE);
    const { instance } = D.instanceDepuisManifeste(manifeste());
    expect(instance.contrats.recorder_registry).to.equal(CONTRATS.recorder_registry);
    expect(instance.deploiements?.recorder_registry).to.deep.equal({ address: CONTRATS.recorder_registry, block_number: DEPLOIEMENT });
    const sans = manifeste();
    for (const c of sans.contracts) delete c.block_number;
    expect(D.instanceDepuisManifeste(sans).instance).to.not.have.property("deploiements");
    const objet = { ...manifeste(), contracts: { ...CONTRATS } };
    expect(D.instanceDepuisManifeste(objet).instance).to.not.have.property("deploiements");
  });

  it("le relais lit les RecorderRegistered à partir du bloc de déploiement (18 000), tranche de 16 384 blocs, et refuse la clé de chaîne inscrite ailleurs au bloc 20 000, sans envoi", async function () {
    const { r, lectures, envois } = await relaisAvecInstanceDuDemon(await demonDe(RACINE));
    expect(r.type, JSON.stringify(r)).to.equal("echec_registre");
    expect(r.data.code).to.equal("cle_chaine_autre_organisation");
    expect(r.outputs.block_number).to.equal(20000);
    expect(envois).to.equal(0);
    expect(lectures).to.deep.equal([["0x4650", "0x864f"]]);
  });

  it("mutant du démon qui ne transmet pas le bloc de déploiement (lecture depuis le bloc 0) : détecté", async function () {
    const D = await demonDe(copieMutante("bloc-zero", "      ...(blocRegistre !== null ? { deploiements:", "      ...(false ? { deploiements:"));
    const { instance, lectures } = await relaisAvecInstanceDuDemon(D);
    expect(instance).to.not.have.property("deploiements");
    expect(lectures[0][0], "le mutant lit depuis le bloc 0").to.equal("0x0");
    expect(lectures).to.deep.equal([["0x0", "0x3fff"], ["0x4000", "0x7fff"]]);
  });
});
