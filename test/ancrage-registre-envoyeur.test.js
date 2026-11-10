// Composant d'ancrage, lot D : `Envoyeur` (CT-4 §8.6, EX-8.13 à EX-8.17 ;
// CT-5 EX-9.3, EX-9.4, EX-9.7, EX-8.10, AN-44 à AN-48) sur un nœud noorcore
// factice (test/fixtures/ancrage-registre/noeud-factice.mjs) dont les blocs,
// reçus et certificats ont la forme des réponses du réseau de développement
// et sont signés par les validateurs d'essai de CT-4 annexe A.2.
//
// Horloge et attentes injectées : l'horloge monotone avance de la durée
// demandée à chaque `attendre`, sans minuterie réelle.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256, sha256Hex, utf8, hexVersOctets, signerEip191, adresseDepuisClePrivee } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const CONTRATS = {
  attestation_registry: CONSTANTES.contracts.attestation_registry,
  period_registry: CONSTANTES.contracts.period_registry,
  recorder_registry: CONSTANTES.contracts.recorder_registry,
};
const ORG = CONSTANTES.organisation.org_id;
const JOURNAL = CONSTANTES.journal.journal_id;
// Journal de l'exemple de référence de CT-1 §10.8 (`journal-principal`), dont EX-9.1 donne les empreintes des points K1 à K4.
const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
// Points de contrôle de l'exemple de référence de CT-1 §10.8 (checkpointHash K1 à K4) et empreintes d'EX-9.1.
const K = {
  K1: { hash: "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", fingerprint: "0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540" },
  K2: { hash: "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", fingerprint: "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44" },
  K3: { hash: "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", fingerprint: "0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837" },
  K4: { hash: "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107", fingerprint: "0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792" },
};
// Clés de test de ce fichier (graines publiées, sans valeur) et clés de test publiées de CT-4.
const CLE_CHAINE_01 = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-01")));
const CLE_CHAINE_02 = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-02")));
const CLE_TIERS = new R.SignataireChaineFichier(hexVersOctets(CONSTANTES.accounts[0].private_key));
const ED25519_01 = CONSTANTES.recorders[0].public_key;
const APPROBATEURS = [1, 2].map((k) => hexVersOctets(CONSTANTES.accounts[k].private_key));
const PERIODE_1 = lireJson("spec/vecteurs/ct-1/manifestes/periode-1.json");

function horlogeFixe(debutMs = Date.UTC(2026, 10, 9, 12, 0, 0)) {
  let monotone = 0;
  const h = { murale: () => debutMs + monotone, monotone: () => monotone, avancer: (ms) => { monotone += ms; } };
  return { horloge: h, attendre: async (ms) => { monotone += ms; } };
}

const REPERTOIRES = [];

function contexte({ delais } = {}) {
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
  const rpc = new R.ClientRpc({ points: POINTS, transport: noeud.transport(), identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const repertoire = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-registre-envoyeur-"));
  REPERTOIRES.push(repertoire);
  const { horloge, attendre } = horlogeFixe();
  const jeux = { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" };
  const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux };
  const journal = [];
  const envoyeur = new R.Envoyeur({ rpc, repertoireEnvois: repertoire, instance, horloge, attendre, delais: { recuMs: 60000, sondageMs: 500, ...(delais ?? {}) }, journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }) });
  for (const cle of [CLE_CHAINE_01, CLE_CHAINE_02, CLE_TIERS]) noeud.approvisionner(cle.adresse(), 4719000000n);
  noeud.inscrire({ orgId: ORG, chainKey: CLE_CHAINE_01.adresse(), ed25519PubKey: ED25519_01, journalId: JOURNAL });
  return { noeud, rpc, repertoire, horloge, envoyeur, instance, journal };
}

function fichiers(repertoire) {
  return fs.readdirSync(repertoire).sort();
}

function aucunSecret(repertoire) {
  const secrets = [CLE_CHAINE_01, CLE_CHAINE_02].map((c) => Buffer.from(sha256(utf8(c === CLE_CHAINE_01 ? "noortrace/ancrage/test/cle-chaine-01" : "noortrace/ancrage/test/cle-chaine-02"))).toString("hex"))
    .concat(CONSTANTES.accounts.map((a) => a.private_key.slice(2)));
  for (const nom of fs.readdirSync(repertoire)) {
    const texte = fs.readFileSync(path.join(repertoire, nom), "utf8").toLowerCase();
    for (const s of secrets) expect(texte.includes(s), `${nom} porte une clé privée`).to.equal(false);
  }
}

describe("ancrage, lot D : Envoyeur sur un nœud factice (CT-4 §8.6, §9.4 ; CT-5 §9)", function () {
  this.timeout(60000);

  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  it("ancre un point (EX-9.1, EX-9.3) : inclusion_registre avec capture CP-1 à CP-6 écrite avant le retour (AN-44, AN-45, AN-47, AN-48)", async function () {
    const c = contexte();
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, fingerprint: K.K2.fingerprint, clePublique: ED25519_01 });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    expect(r.data.request_id).to.equal(`ancre_registre_point:${K.K2.hash}`);
    expect(r.data.block_number).to.equal(1001);
    expect(Object.keys(r.data).sort()).to.deep.equal(["block_number", "capture_sha256", "request_id"]);
    const noms = fichiers(c.repertoire);
    const hash = r.outputs.transaction_hash;
    expect(noms).to.deep.equal([`bloc-1001.json`, `capture-1001-0-ancre.json`, `certificat-1001.json`, `envoi-${hash}.json`, `issue-${hash}.json`, `recu-${hash}.json`]);
    const octetsIndex = fs.readFileSync(path.join(c.repertoire, "capture-1001-0-ancre.json"));
    expect(sha256Hex(octetsIndex)).to.equal(r.data.capture_sha256);
    const index = JSON.parse(octetsIndex.toString("utf8"));
    expect(R.verifierIndexCapture(index).valide, JSON.stringify(R.verifierIndexCapture(index).erreurs)).to.equal(true);
    expect(index.checks.map((x) => `${x.id}:${x.status}`)).to.deep.equal(["CP-1:reussi", "CP-2:reussi", "CP-3:reussi", "CP-4:reussi", "CP-5:reussi", "CP-6:reussi"]);
    expect(index.role).to.equal("ancre");
    expect(index.contract).to.equal(CONTRATS.attestation_registry);
    expect(index.log_index).to.equal(0);
    expect(index.node).to.deep.equal({ rpc: POINTS[0], validator_id: "v1" });
    expect(index.sending.transaction_hash).to.equal(hash);
    expect(index.sending.max_fee_per_gas).to.equal("1");
    expect(index.sending.from).to.equal(CLE_CHAINE_01.adresse());
    // Les données d'appel portent l'empreinte recalculée (AN-44) et le docType du point (AN-45) ; la transaction passe RG-15 (AN-47).
    const tx = R.lireTransaction(index.sending.raw_transaction);
    const data = Buffer.from(tx.data).toString("hex");
    expect("0x" + data.slice(8, 72)).to.equal(K.K2.fingerprint);
    expect("0x" + data.slice(72, 136)).to.equal(R.DOC_TYPE_POINT_DE_CONTROLE);
    expect(R.verifierRG15(index.sending.raw_transaction, { evm_chain_id: 2124, fees: c.instance.fees, objet: "appel", to: CONTRATS.attestation_registry }).statut).to.equal("reussi");
    expect(BigInt(r.outputs.gas_used)).to.be.at.most(96977n);
    expect(r.outputs.cost_wei).to.equal(r.outputs.gas_used);
    // Relecture hors ligne de la capture : CP-2 à CP-6 réussies, journal Anchored décodé.
    const v = R.verifierCapture({ fichiers: c.repertoire, index, jeux: c.instance.jeux, bftChainId: "noortrace-2124-dev" });
    expect(v.premierEchec).to.equal(null);
    expect(R.decoderJournal("ancre", v.journal)).to.deep.equal({ name: "Anchored", fingerprint: K.K2.fingerprint, issuer: CLE_CHAINE_01.adresse(), docType: R.DOC_TYPE_POINT_DE_CONTROLE });
    // Envoi et issue conformes à leur schéma ; aucun secret écrit (AN-43).
    expect(R.verifierEnvoi(JSON.parse(fs.readFileSync(path.join(c.repertoire, `envoi-${hash}.json`), "utf8"))).valide).to.equal(true);
    const issue = JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${hash}.json`), "utf8"));
    expect(R.verifierIssue(issue).valide).to.equal(true);
    expect(issue).to.include({ transaction_hash: hash, block_number: 1001, status: "0x1" });
    aucunSecret(c.repertoire);
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
    expect(c.journal.map((l) => l.evenement)).to.deep.equal(["registry_sent", "registry_included"]);
  });

  it("empreinte déclarée différente de l'empreinte recalculée : refus avant tout envoi (AN-44)", async function () {
    const c = contexte();
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, fingerprint: K.K1.fingerprint });
    expect(r).to.deep.include({ type: "echec_registre", data: { request_id: `ancre_registre_point:${K.K2.hash}`, code: "empreinte_empreinte_differente" } });
    expect(fichiers(c.repertoire)).to.deep.equal([]);
    expect(c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction")).to.have.length(0);
  });

  it("docType ni point ni période : refusé (AN-45) ; objet mal formé : refusé", async function () {
    const c = contexte();
    let erreur = null;
    try { await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: "0x" + "11".repeat(32), cle: CLE_CHAINE_01 }); } catch (e) { erreur = e; }
    expect(erreur).to.be.instanceOf(TypeError);
    erreur = null;
    try { await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL, objet: "0x1234", docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 }); } catch (e) { erreur = e; }
    expect(erreur).to.be.instanceOf(TypeError);
  });

  it("clé de chaîne non inscrite, ou inscrite pour une autre clé Ed25519 : cle_chaine_non_inscrite (AN-46, OP-9)", async function () {
    const c = contexte();
    const r1 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_02 });
    expect(r1.data.code).to.equal("cle_chaine_non_inscrite");
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, clePublique: CONSTANTES.recorders[1].public_key });
    expect(r2.data.code).to.equal("cle_chaine_non_inscrite");
    expect(fichiers(c.repertoire)).to.deep.equal([]);
  });

  it("seconde ancre de la même empreinte par la même clé : idempotente, la capture existante est rendue (EX-9.3, OP-9 deja_fait)", async function () {
    const c = contexte();
    const r1 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r2.type).to.equal("inclusion_registre");
    expect(r2.data).to.deep.equal(r1.data);
    expect(fichiers(c.repertoire)).to.have.length(6);
    expect(c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction")).to.have.length(4);
  });

  it("empreinte prise par un tiers : empreinte_squattee sans nouvel essai, lookup consigné (EX-9.7, CT-4 EX-8.6)", async function () {
    const c = contexte();
    // Le tiers (compte approvisionné, non inscrit) ancre l'empreinte du point le premier.
    const tiers = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K3.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_TIERS, sansInscription: true });
    expect(tiers.type).to.equal("inclusion_registre");
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K3.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.type).to.equal("echec_registre");
    expect(r.data).to.deep.equal({ request_id: `ancre_registre_point:${K.K3.hash}`, code: "empreinte_squattee" });
    expect(r.outputs.lookup.issuer).to.equal(CLE_TIERS.adresse());
    expect(r.outputs.lookup.doc_type).to.equal(R.DOC_TYPE_POINT_DE_CONTROLE);
    const envois = c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction");
    expect(envois).to.have.length(4, "aucun envoi pour l'empreinte prise");
    // Même empreinte sous le docType de période : empreinte prise aussi (une empreinte s'ancre une fois pour toute la chaîne).
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K3.hash, docType: R.DOC_TYPE_PERIODE, cle: CLE_CHAINE_01 });
    expect(r2.data.code).to.equal("empreinte_squattee");
  });

  it("reçu absent dans le délai : recu_absent, l'envoi reste sans issue ; un second envoi est refusé (attente_nonce, OP-3, EX-9.4) ; renvoyer obtient le reçu (EX-8.16)", async function () {
    const c = contexte({ delais: { recuMs: 2000, sondageMs: 500 } });
    // La transaction n'est incluse qu'au 30e sondage : au-delà du délai (2 s / 500 ms = 4 sondages sur 4 points).
    // L'attente d'inclusion est posée sur le premier hachage envoyé, relevé au passage de l'appel.
    const original = c.noeud.repondre.bind(c.noeud);
    let premier = null;
    c.noeud.repondre = (point, requete) => {
      const r = original(point, requete);
      if (requete.method === "eth_sendRawTransaction" && r.result && premier === null) {
        premier = r.result;
        c.noeud.attenteInclusion.set(premier, 40);
      }
      return r;
    };
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.type).to.equal("echec_registre");
    expect(r.data.code).to.equal("recu_absent");
    const hash = r.outputs.transaction_hash;
    expect(fichiers(c.repertoire)).to.deep.equal([`envoi-${hash}.json`]);
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse()).map((e) => e.transaction_hash)).to.deep.equal([hash]);
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K4.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r2.data.code).to.equal("attente_nonce");
    expect(r2.outputs.pending).to.deep.equal([hash]);
    // Une autre clé n'est pas bloquée.
    const r3 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K4.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_TIERS, sansInscription: true });
    expect(r3.type).to.equal("inclusion_registre");
    // Renvoi des mêmes octets, puis reçu : inclusion et capture.
    c.noeud.attenteInclusion.set(hash, 0);
    expect(hash).to.equal(premier);
    const r4 = await c.envoyeur.renvoyer(hash);
    expect(r4.type, JSON.stringify(r4)).to.equal("inclusion_registre");
    expect(r4.data.request_id).to.equal(`ancre_registre_point:${K.K2.hash}`);
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
    expect(fs.existsSync(path.join(c.repertoire, `issue-${hash}.json`))).to.equal(true);
    // Le renvoi a soumis les mêmes octets à chaque validateur (EX-8.15).
    const brut = JSON.parse(fs.readFileSync(path.join(c.repertoire, `envoi-${hash}.json`), "utf8")).raw_transaction;
    const soumissions = c.noeud.appels.filter((a) => a.method === "eth_sendRawTransaction" && a.params[0] === brut);
    expect(soumissions.map((a) => a.point)).to.deep.equal([...POINTS, ...POINTS]);
  });

  it("transaction perdue par la mempool : remplacement au même nonce à ⌈1,1 × p⌉ = 2 wei, issues remplacee / inclusion, coût consigné (EX-8.16, EX-8.17, EX-4.15)", async function () {
    const c = contexte({ delais: { recuMs: 1000, sondageMs: 500 } });
    const original = c.noeud.repondre.bind(c.noeud);
    let premier = null;
    c.noeud.repondre = (point, requete) => {
      const r = original(point, requete);
      if (requete.method === "eth_sendRawTransaction" && r.result && premier === null) {
        premier = r.result;
        c.noeud.abandonnes.add(premier);
      }
      return r;
    };
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.data.code).to.equal("recu_absent");
    const hash = r.outputs.transaction_hash;
    expect(hash).to.equal(premier);
    // Renvoi sans effet : toujours perdue.
    const r2 = await c.envoyeur.renvoyer(hash);
    expect(r2.data.code).to.equal("recu_absent");
    // Remplacement : même nonce, frais 2 wei.
    const r3 = await c.envoyeur.remplacer(hash, { cle: CLE_CHAINE_01 });
    expect(r3.type, JSON.stringify(r3)).to.equal("inclusion_registre");
    const remplacant = r3.outputs.transaction_hash;
    expect(remplacant).to.not.equal(hash);
    const issueOriginal = JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${hash}.json`), "utf8"));
    expect(issueOriginal).to.include({ state: "remplacee", replaced_by: remplacant });
    expect(R.verifierIssue(issueOriginal).valide).to.equal(true);
    const envoiRemplacant = JSON.parse(fs.readFileSync(path.join(c.repertoire, `envoi-${remplacant}.json`), "utf8"));
    expect(envoiRemplacant.nonce).to.equal(0);
    expect(envoiRemplacant.max_fee_per_gas).to.equal("2");
    expect(envoiRemplacant.max_priority_fee_per_gas).to.equal("2");
    expect(R.verifierRG15(envoiRemplacant.raw_transaction, { evm_chain_id: 2124, fees: c.instance.fees, objet: "appel", to: CONTRATS.attestation_registry, remplace: "1" }).statut).to.equal("reussi");
    expect(R.verifierRG15(envoiRemplacant.raw_transaction, { evm_chain_id: 2124, fees: c.instance.fees, objet: "appel", to: CONTRATS.attestation_registry }).motif).to.equal("frais_non_conformes");
    expect(BigInt(r3.outputs.cost_wei)).to.equal(BigInt(r3.outputs.gas_used) * 2n);
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
    // Un remplacement d'un envoi déjà clos est refusé ; une transaction encore connue d'un point n'est pas remplacée.
    const r4 = await c.envoyeur.remplacer(hash, { cle: CLE_CHAINE_01 });
    expect(r4.data.code).to.equal("envoi_avec_issue");
  });

  it("refus par tous les validateurs à l'envoi : transaction_refusee, envoi écarté ; tous injoignables à la lecture : noeud_injoignable", async function () {
    const c = contexte();
    for (const p of POINTS) c.noeud.rejets.set(p, "transaction underpriced");
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.data.code).to.equal("transaction_refusee");
    expect(r.outputs.refus).to.have.length(4);
    const issue = JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${r.outputs.transaction_hash}.json`), "utf8"));
    expect(issue.state).to.equal("ecartee");
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
    for (const p of POINTS) c.noeud.pannes.add(p);
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K4.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r2.data.code).to.equal("noeud_injoignable");
  });

  it("transaction incluse avec status 0x0 : empreinte prise par un tiers entre la lecture d'OP-9 et l'inclusion, requalifiée empreinte_squattee par lookup (CT-4 §8.3, EX-5.12) ; sinon transaction_annulee ; nonce consommé, issue écrite", async function () {
    const c = contexte();
    const original = c.noeud.repondre.bind(c.noeud);
    c.noeud.repondre = (point, requete) => {
      const r = original(point, requete);
      if (requete.method === "eth_sendRawTransaction" && r.result && !c.noeud.ancres.has(K.K2.fingerprint)) {
        // Un tiers prend l'empreinte avant l'inclusion : l'appel du contrat échouera (AlreadyAnchored).
        c.noeud.ancres.set(K.K2.fingerprint, { issuer: CLE_TIERS.adresse(), docType: R.DOC_TYPE_POINT_DE_CONTROLE, issuedAt: 1n });
      }
      return r;
    };
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.data).to.deep.equal({ request_id: `ancre_registre_point:${K.K2.hash}`, code: "empreinte_squattee" });
    expect(r.outputs.lookup.issuer).to.equal(CLE_TIERS.adresse());
    const issue = JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${r.outputs.transaction_hash}.json`), "utf8"));
    expect(issue.status).to.equal("0x0");
    expect(issue.block_number).to.equal(r.outputs.block_number);
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
    // Refus du contrat sans empreinte prise par un autre (ici : l'état rend l'ancre à la clé elle-même) : transaction_annulee.
    c.noeud.repondre = (point, requete) => {
      const rep = original(point, requete);
      if (requete.method === "eth_sendRawTransaction" && rep.result && !c.noeud.ancres.has(K.K4.fingerprint)) {
        c.noeud.ancres.set(K.K4.fingerprint, { issuer: CLE_CHAINE_01.adresse(), docType: R.DOC_TYPE_POINT_DE_CONTROLE, issuedAt: 1n });
      }
      return rep;
    };
    const r2 = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K4.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r2.data.code).to.equal("transaction_annulee");
    expect(JSON.parse(fs.readFileSync(path.join(c.repertoire, `issue-${r2.outputs.transaction_hash}.json`), "utf8")).status).to.equal("0x0");
    expect(c.envoyeur.envoisEnAttente(CLE_CHAINE_01.adresse())).to.deep.equal([]);
  });

  it("certificat « not yet persisted » : réessai puis capture (CT-4 §9.3) ; attempts consigné", async function () {
    const c = contexte();
    c.noeud.certificatsRetardes.set(1001, 3);
    const r = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01 });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    const index = JSON.parse(fs.readFileSync(path.join(c.repertoire, "capture-1001-0-ancre.json"), "utf8"));
    expect(index.attempts).to.equal(4);
  });

  it("ancre d'une période puis clôture (CT-4 §8.2, EX-8.4) : submitPeriod avec les signatures rangées des approbateurs, capture de rôle cloture ; sans ancre : ancre_manquante ; seconde fois : deja_fait", async function () {
    const c = contexte();
    const meta = { ...R.lirePeriodMeta({ ...periodMetaDe(PERIODE_1), uri: "" }) };
    const periodMeta = periodMetaDe(PERIODE_1);
    const sansAncre = await c.envoyeur.clore({ periodMeta, signatures: [], cle: CLE_CHAINE_01 });
    expect(sansAncre.data.code).to.equal("ancre_manquante");
    const ancre = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL, objet: PERIODE_1.period_hash ?? periodHashDe(), docType: R.DOC_TYPE_PERIODE, cle: CLE_CHAINE_01 });
    expect(ancre.type, JSON.stringify(ancre)).to.equal("inclusion_registre");
    expect(ancre.data.request_id).to.equal(`ancre_registre_periode:${periodHashDe()}`);
    // Signatures des approbateurs (Hardhat 1 et 2) sur periodDigest, rangées par adresse croissante (RG-13).
    const condense = R.periodDigest(2124, CONTRATS.period_registry, periodMeta);
    const signatures = APPROBATEURS.map((cle) => {
      const s = signerEip191(cle, hexVersOctets(condense));
      return { signer: adresseDepuisClePrivee(cle), v: s[64], r: "0x" + Buffer.from(s.subarray(0, 32)).toString("hex"), s: "0x" + Buffer.from(s.subarray(32, 64)).toString("hex") };
    }).sort((a, b) => (a.signer < b.signer ? -1 : 1));
    const desordre = await c.envoyeur.clore({ periodMeta, signatures: [...signatures].reverse(), cle: CLE_CHAINE_01 });
    expect(desordre.data.code).to.equal("signature_non_canonique");
    const r = await c.envoyeur.clore({ periodMeta, signatures, cle: CLE_CHAINE_01, seuil: 2, membres: [1, 2, 3].map((k) => CONSTANTES.accounts[k].address) });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    expect(r.data.request_id).to.equal(`cloture:${periodHashDe()}`);
    const index = JSON.parse(fs.readFileSync(path.join(c.repertoire, "capture-1002-0-cloture.json"), "utf8"));
    expect(index.role).to.equal("cloture");
    expect(index.contract).to.equal(CONTRATS.period_registry);
    const v = R.verifierCapture({ fichiers: c.repertoire, index, jeux: c.instance.jeux, bftChainId: "noortrace-2124-dev" });
    expect(v.premierEchec).to.equal(null);
    const journal = R.decoderJournal("cloture", v.journal);
    expect(journal.periodHash).to.equal(periodHashDe());
    expect(journal.lastSeq).to.equal(meta.last_seq);
    const encore = await c.envoyeur.clore({ periodMeta, signatures, cle: CLE_CHAINE_01 });
    expect(encore.type).to.equal("inclusion_registre");
    expect(encore.data).to.deep.equal(r.data);
    // Export des parties depuis les deux captures : registre.json conforme, deux certificats.
    const captures = R.listerCaptures(c.repertoire).map((x) => ({ index: x.index }));
    const parties = R.exporterPartiesRegistre({ repertoire: c.repertoire, captures, jeux: { sets: [{ from_height: 1, to_height: null, validators: c.instance.jeux.validators, source: "jeu d'essai" }] }, source: "nœud factice" });
    expect(parties.registre.entries.map((e) => e.role)).to.deep.equal(["ancre", "cloture"]);
    expect(parties.certificatCommit.certificates.map((x) => x.height)).to.deep.equal(["0x3e9", "0x3ea"]);
    expect(R.verifierRegistreV0(parties.registre).valide).to.equal(true);
    aucunSecret(c.repertoire);
  });

  it("clôture : PeriodMeta refusé par RG-5 (periode_invalide), doublon d'un autre periodHash à la même position (doublon)", async function () {
    const c = contexte();
    const periodMeta = periodMetaDe(PERIODE_1);
    const invalide = await c.envoyeur.clore({ periodMeta: { ...periodMeta, uri: "x".repeat(65) }, signatures: [], cle: CLE_CHAINE_01 });
    expect(invalide.data.code).to.equal("periode_invalide");
    // Une période déjà connue du contrat sous ce periodHash mais qui n'est pas la dernière du journal : doublon.
    c.noeud.periodes.push({ id: 1, meta: { ...R.lirePeriodMeta(periodMeta) }, publishedAt: 1n, publisher: CLE_TIERS.adresse() });
    c.noeud.periodes.push({ id: 2, meta: { ...R.lirePeriodMeta(periodMeta), period_hash: "0x" + "22".repeat(32) }, publishedAt: 2n, publisher: CLE_TIERS.adresse() });
    const doublon = await c.envoyeur.clore({ periodMeta, signatures: [], cle: CLE_CHAINE_01 });
    expect(doublon.data.code).to.equal("doublon");
  });

  it("nonce d'EX-8.14 (CT-4) : le plus grand eth_getTransactionCount latest des validateurs ; un premier validateur en retard d'un bloc ne fait plus refuser l'envoi suivant (« nonce too low » ailleurs, observé sur le réseau de développement à l'étape 5)", async function () {
    const c = contexte();
    const premier = await c.envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: K.K2.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, fingerprint: K.K2.fingerprint, clePublique: ED25519_01 });
    expect(premier.type, JSON.stringify(premier)).to.equal("inclusion_registre");
    // Le premier point rend le nonce d'avant l'inclusion (bloc pas encore appliqué chez lui) ; les trois autres sont à jour.
    const reel = c.noeud.transport();
    const enRetard = async ({ url, octets, ...reste }) => {
      const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
      if (url === POINTS[0] && requete.method === "eth_getTransactionCount") {
        const nonce = c.noeud.comptes.get(requete.params[0]).nonce;
        return { status: 200, octets: utf8(JSON.stringify({ jsonrpc: "2.0", id: requete.id, result: `0x${(nonce - 1n).toString(16)}` })) };
      }
      return reel({ url, octets, ...reste });
    };
    const rpc = new R.ClientRpc({ points: POINTS, transport: enRetard, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
    const envoyeur = new R.Envoyeur({ rpc, repertoireEnvois: c.repertoire, instance: c.instance, horloge: c.horloge, attendre: async (ms) => c.horloge.avancer(ms), delais: { recuMs: 60000, sondageMs: 500 }, journal: () => {} });
    const objet = sha256Hex(utf8("noortrace/ancrage/test/nonce-validateur-en-retard"));
    const second = await envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, clePublique: ED25519_01 });
    expect(second.type, JSON.stringify(second)).to.equal("inclusion_registre");
    const envoi = JSON.parse(fs.readFileSync(path.join(c.repertoire, second.outputs.envoi), "utf8"));
    expect(envoi.nonce).to.equal(1);
    // Tous les points injoignables : noeud_injoignable, comme avant.
    for (const p of POINTS) c.noeud.pannes.add(p);
    const injoignable = await envoyeur.ancrer({ orgId: ORG, journalId: JOURNAL_REF, objet: sha256Hex(utf8("noortrace/ancrage/test/nonce-injoignable")), docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE_CHAINE_01, clePublique: ED25519_01 });
    expect(injoignable.data.code).to.equal("noeud_injoignable");
  });
});

/** `PeriodMeta` au format `meta_periode` depuis un manifeste de CT-1. */
function periodMetaDe(manifeste) {
  return {
    org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHashDe(), root: manifeste.root,
    period_start: String(manifeste.period_start), period_end: String(manifeste.period_end),
    first_seq: String(manifeste.first_seq), last_seq: String(manifeste.last_seq), version: 0, uri: "",
  };
}

function periodHashDe() {
  // periodHash de la période 1 des vecteurs de CT-1 (CT-4 §6.6.4).
  return "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914";
}
