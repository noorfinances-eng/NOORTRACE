// Étape 8, décision du porteur du 14 novembre 2026 — report de la politique dans la réponse
// `evaluer` (CT-3 §12.3 et EX-12.6, EX-12.20, révision 0.5 ; CT-2 EX-7.16 et
// EX-7.23, révision 0.8). Trois règles nouvelles :
//   1. service : chaque réponse `evaluer` porte `policy_version` et
//      `policy_sha256` de la version chargée sous laquelle elle est rendue —
//      la version de la requête pour une évaluation et pour un ticket
//      `nouveau`, la version du ticket pour un ticket rapproché (CT-3 EX-7.21) ;
//      le service recopie ce que le noyau a déclaré au `charger` (12.2), il ne
//      calcule rien.
//   2. noyau : huit membres exactement, schéma, puis la vérification
//      d'EX-7.16 : la version est détenue par le noyau (ensemble épinglé ou
//      version gardée), l'empreinte est celle qu'il a déclarée au `charger`
//      (EX-8.11), et la version est celle de la requête (sans ticket rapproché)
//      ou celle de l'événement `retenue` du ticket ; un manquement est une
//      réponse invalide (`approval_response_invalid`, raison
//      `politique_non_epinglee`) : `-31010`, raison `approbation`, jamais un
//      relais ; en mode observation, relais marqué `inconnu` (EX-14.15).
//   3. rejeu du pas 5 de l'essai de contournement : un pair qui détient le canal du noyau
//      pré-enregistre une version future (politique permissive, empreinte
//      quelconque) ; après le passage honnête du noyau à cette version, un
//      paiement sous seuil finit en `-31010`, raison `approbation`.
//   4. addendum du 14 novembre (neuvième membre `approval_sha256`) : le service
//      CALCULE au `charger` le SHA-256 du JCS du membre `approval` reçu, le
//      reporte dans la réponse de `charger` et dans chaque réponse `evaluer` ;
//      le noyau le compare au condensé du membre qu'il a lui-même envoyé (réponse
//      de `charger` : sinon `charger` échoué, `approval_charger_refuse` ; réponse
//      `evaluer` : sinon `politique_non_epinglee`) et, règle EX-7.15 nouvelle,
//      n'évalue rien tant que le `charger` de la version épinglée n'a pas réussi
//      ou s'il a été refusé (`-31010`, raison `approbation`). Rejeu du scénario
//      de l'addendum (pré-enregistrement à empreinte honnête, règles
//      permissives) : `-31010`.
// Les preuves par mutant (oracle qui échoue quand la règle est retirée) sont
// jouées hors du dépôt.

import { expect } from "chai";
import fs from "node:fs";
import * as A from "@noortrace/approbation";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, ErreurEnregistreur, ErreurServiceApprobation, ServiceApprobation, validerReponseEvaluer,
  validerConfiguration, empreintePolitique, controlePolitiqueApprobation, condenseApproval,
} from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { monterBanc, attendre } from "./fixtures/enregistreur-politique/outils.mjs";
import {
  ORG_ID, JOURNAL_ID, SESSIONS, ANNUAIRE_REFERENCE, messageCharger, politiqueParcours, requeteEvaluer, retenue, JEU_STATIQUE,
  OUTIL_PAIEMENT, OUTIL_LECTURE,
} from "./fixtures/approbation-service/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const NEUF_MEMBRES = Object.freeze(["approval", "approval_sha256", "approver_set", "decision", "policy_sha256", "policy_version", "rule", "ticket", "ticket_state"]);
/** Condensé du membre approval d'un message charger, calculé indépendamment du noyau (SHA-256 du JCS du service). */
const condenseMessage = (m) => N.sha256Hex(N.utf8(A.jcsIntegral(m.approval)));
const EMPREINTE_QUELCONQUE = `0x${"ee".repeat(32)}`;
/** Empreinte synthétique que `messageCharger` déclare au service (fixture des vecteurs CT-3). */
const empreinteDeclaree = (pv) => N.sha256Hex(N.utf8(`ensemble de politique ${pv}`));
const IBAN = "CH9300762011623852957";
const paiementParcours = (montant, policy_version, claim_id = "2026-90417") =>
  requeteEvaluer(OUTIL_PAIEMENT.tool_announced, { claim_id, amount: montant, currency: "CHF", beneficiary_iban: IBAN }, { policy_version });
const PERMISSIVE = Object.freeze({
  version: 0, default: { name: "tout autorise", description: null, level: "automatique", decision: "autorise", contest_ms: null }, rules: [],
  approver_set: JEU_STATIQUE, separation: { self_approval: "permise", identities: [] },
});

/** Service d'approbation réel, en mémoire (comme dans l'essai de contournement), environnement de développement. */
function serviceEnMemoire(dir) {
  const config = { org_id: ORG_ID, journal_id: JOURNAL_ID, environment: "developpement", set_poll_interval_ms: 30, remise_representation_ms: 30000, body_max_bytes: 1 << 24, escalation: [], administrators: [SESSIONS.admin] };
  const machine = new A.Machine({ org_id: ORG_ID, journal_id: JOURNAL_ID, identifiants: { mode: "compteur" }, administrators: config.administrators });
  const supervision = new A.Supervision({ journal: `${dir}/j.ndjson`, notifications: `${dir}/n.ndjson` });
  const annuaire = new A.EtatAnnuaire({ document: JSON.parse(fs.readFileSync(ANNUAIRE_REFERENCE, "utf8")), defis: [], persiste: false });
  return new A.ServiceApprobation({ config, machine, magasin: null, supervision, lecteur: null, annuaire });
}

// ----------------------------------------------------------------------------
// 1. Service : la réponse evaluer porte la version et l'empreinte du charger
// ----------------------------------------------------------------------------
describe("Protocole d'approbation, 1 : service, la réponse evaluer porte policy_version et policy_sha256 du charger (CT-3 §12.3, EX-12.6, EX-12.20)", function () {
  let service;

  beforeEach(function () {
    service = serviceEnMemoire(repertoireTemporaire("noortrace-s2-service-"));
  });

  it("évaluation sans ticket (autorise, refuse) et ticket nouveau : huit membres exactement, policy_version de la requête, policy_sha256 déclarée au charger", async function () {
    const m = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
    await service.charger(m);
    const couple = { policy_version: "parcours-1", policy_sha256: empreinteDeclaree("parcours-1"), approval_sha256: condenseMessage(m) };
    const lecture = await service.evaluer(requeteEvaluer(OUTIL_LECTURE.tool_announced, { claim_id: "2026-1" }, { policy_version: "parcours-1" }));
    expect(Object.keys(lecture).sort()).to.deep.equal(NEUF_MEMBRES);
    expect(lecture).to.include({ decision: "autorise", ticket: null, ticket_state: null, ...couple });
    const horsChf = await service.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, { claim_id: "2026-2", amount: "10.00", currency: "EUR", beneficiary_iban: IBAN }, { policy_version: "parcours-1" }));
    expect(Object.keys(horsChf).sort()).to.deep.equal(NEUF_MEMBRES);
    expect(horsChf).to.include({ decision: "refuse", ticket: null, ticket_state: null, ...couple });
    const nouveau = await service.evaluer(paiementParcours("9999.00", "parcours-1"));
    expect(Object.keys(nouveau).sort()).to.deep.equal(NEUF_MEMBRES);
    expect(nouveau).to.include({ decision: "a_approuver", ticket_state: "nouveau", ...couple });
    expect(nouveau.ticket).to.be.a("string");
  });

  it("le service recopie l'empreinte déclarée au charger, quelle qu'elle soit : il ne la calcule jamais (EX-12.6)", async function () {
    const declaree = `0x${"ab".repeat(32)}`;
    await service.charger({ ...messageCharger({ policy_version: "parcours-3", rules: politiqueParcours() }), policy_sha256: declaree });
    const r = await service.evaluer(requeteEvaluer(OUTIL_LECTURE.tool_announced, { claim_id: "2026-3" }, { policy_version: "parcours-3" }));
    expect(r).to.include({ decision: "autorise", policy_version: "parcours-3", policy_sha256: declaree });
    expect(declaree).to.not.equal(empreinteDeclaree("parcours-3"));
  });

  it("addendum : charger rend approval_sha256, SHA-256 du JCS du membre approval reçu, et chaque réponse evaluer le reporte (neuf membres) ; il n'est jamais recopié d'un message du noyau", async function () {
    const m1 = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
    const c1 = await service.charger(m1);
    expect(Object.keys(c1).sort()).to.deep.equal(["approval_candidates", "approval_sha256", "policy_sha256", "policy_version"]);
    expect(c1.approval_sha256).to.equal(condenseMessage(m1));
    expect(c1.approval_sha256).to.equal(condenseApproval(m1.approval)); // la fonction du noyau calcule la même valeur
    expect(c1.approval_sha256).to.not.equal(m1.policy_sha256);
    // mêmes règles sous une autre version et une autre empreinte déclarée : même condensé (il ne dépend que du membre approval)
    const m2 = { ...messageCharger({ policy_version: "parcours-2", rules: politiqueParcours() }), policy_sha256: `0x${"ab".repeat(32)}` };
    const c2 = await service.charger(m2);
    expect(c2.approval_sha256).to.equal(c1.approval_sha256);
    // des règles différentes : un autre condensé
    const m3 = messageCharger({ policy_version: "parcours-3", rules: PERMISSIVE });
    const c3 = await service.charger(m3);
    expect(c3.approval_sha256).to.equal(condenseMessage(m3));
    expect(c3.approval_sha256).to.not.equal(c1.approval_sha256);
    // chaque réponse evaluer reporte le condensé de sa version
    const r1 = await service.evaluer(paiementParcours("9999.00", "parcours-1"));
    expect(Object.keys(r1).sort()).to.deep.equal(NEUF_MEMBRES);
    expect(r1).to.include({ ticket_state: "nouveau", policy_version: "parcours-1", approval_sha256: c1.approval_sha256 });
    const r3 = await service.evaluer(paiementParcours("9999.00", "parcours-3"));
    expect(r3).to.include({ decision: "autorise", ticket: null, policy_version: "parcours-3", approval_sha256: c3.approval_sha256 });
  });

  it("ticket rapproché après le chargement d'une version nouvelle : le couple est celui de la version du ticket, non de la version en vigueur (EX-7.21, TK-2)", async function () {
    await service.charger(messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() }));
    const demande = paiementParcours("9999.00", "parcours-1");
    const r1 = await service.evaluer(demande);
    expect(r1).to.include({ ticket_state: "nouveau", policy_version: "parcours-1", policy_sha256: empreinteDeclaree("parcours-1") });
    // ré-émission d'un ticket réservé : de nouveau `nouveau`, même ticket, même couple
    const r1bis = await service.evaluer(demande);
    expect(r1bis).to.include({ ticket: r1.ticket, ticket_state: "nouveau", policy_version: "parcours-1", policy_sha256: empreinteDeclaree("parcours-1") });
    // le noyau scelle la retenue et ouvre le ticket
    const ret = retenue({ requete: demande, rule: r1.rule, ticket: r1.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
    await service.ouvrir(ret.ouvrir);
    // une version nouvelle est chargée : elle est en vigueur
    await service.charger(messageCharger({ policy_version: "parcours-2", rules: politiqueParcours() }));
    expect(service.machine.enVigueur).to.equal("parcours-2");
    // la ré-émission de la demande sous parcours-1 rapproche le ticket : couple de parcours-1
    const r2 = await service.evaluer(demande);
    expect(Object.keys(r2).sort()).to.deep.equal(NEUF_MEMBRES);
    expect(r2).to.include({ decision: "a_approuver", ticket: r1.ticket, ticket_state: "en_attente", policy_version: "parcours-1", policy_sha256: empreinteDeclaree("parcours-1") });
    // sous parcours-2, la même demande est une demande nouvelle (TK-2 : la version fait partie de la clé) : couple de parcours-2
    const r3 = await service.evaluer(paiementParcours("9999.00", "parcours-2"));
    expect(r3).to.include({ decision: "a_approuver", ticket_state: "nouveau", policy_version: "parcours-2", policy_sha256: empreinteDeclaree("parcours-2") });
    expect(r3.ticket).to.not.equal(r1.ticket);
  });

  it("mode observation : la réponse porte les huit membres, sans ticket, avec le couple de la version observée (EX-12.20)", async function () {
    const m = messageCharger({ policy_version: "obs-1", rules: politiqueParcours(), mode: "observation" });
    await service.charger(m);
    const r = await service.evaluer(paiementParcours("9999.00", "obs-1"));
    expect(r).to.deep.equal({
      rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null,
      policy_version: "obs-1", policy_sha256: empreinteDeclaree("obs-1"), approval_sha256: condenseMessage(m),
    });
  });
});

// ----------------------------------------------------------------------------
// 2. Noyau : validerReponseEvaluer (unitaire)
// ----------------------------------------------------------------------------
describe("Protocole d'approbation, 2 : noyau, validerReponseEvaluer vérifie la version et l'empreinte épinglées (CT-2 EX-7.16, EX-7.23)", function () {
  // Ensembles de politique détenus par le noyau : l'empreinte est celle d'EX-8.11 (JCS intégral du document).
  const document = (version) => ({
    version,
    approval: { rules: { nom: `politique ${version}` }, mode: "erreur", hold_timeout_ms: 1000, expire_after_ms: 60000, timeout_ms: 2000, service: { url: "http://127.0.0.1:1/" } },
    redaction: null,
  });
  const detenus = { v1: document("v1"), v2: document("v2") };
  const sha = (v) => empreintePolitique(detenus[v]).policy_sha256;
  // Contexte du noyau : requête sous v1 ; la retenue du ticket apr-1 est sous v1 ; aucune retenue connue pour un autre ticket.
  const ctx = (o = {}) => ({
    decisionScellee: () => null, observation: false, versionRequete: "v1",
    politique: (v) => detenus[v] ?? null, versionRetenue: (t) => (t === "apr-1" ? "v1" : null), ...o,
  });
  const condense = (v) => condenseApproval(detenus[v].approval);
  const base = (pv = "v1") => ({ rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null, policy_version: pv, policy_sha256: sha(pv), approval_sha256: condense(pv) });
  const enAttente = (ticket, pv) => ({ ...base(pv), rule: "paiement > 5000 CHF", decision: "a_approuver", ticket, ticket_state: "en_attente" });
  const JEU = { threshold: { required: 1, size: 1 }, members: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"], source: "jeu statique de la politique de test" };

  it("neuf membres exactement : la réponse à six membres (version 0.4), à sept, à huit (sans approval_sha256) ou à dix membres est refusée ; les neuf membres avec le couple et le condensé du charger sont admis", function () {
    expect(validerReponseEvaluer(base(), ctx())).to.deep.equal({ valide: true, combinaison: "autorise/null" });
    const { approval_sha256, ...huit } = base();
    void approval_sha256;
    expect(validerReponseEvaluer(huit, ctx())).to.include({ valide: false });
    const { policy_sha256, ...sept } = huit;
    void policy_sha256;
    expect(validerReponseEvaluer(sept, ctx())).to.include({ valide: false });
    const { policy_version, ...six } = sept;
    void policy_version;
    expect(validerReponseEvaluer(six, ctx())).to.include({ valide: false });
    expect(validerReponseEvaluer({ ...base(), extra: 1 }, ctx())).to.include({ valide: false });
    expect(validerReponseEvaluer({ ...base(), approval_sha256: "ab" }, ctx())).to.include({ valide: false });
    // forme des membres (schéma) : empreinte mal formée, version vide
    expect(validerReponseEvaluer({ ...base(), policy_sha256: "ee" }, ctx())).to.include({ valide: false });
    expect(validerReponseEvaluer({ ...base(), policy_version: "" }, ctx())).to.include({ valide: false });
  });

  it("policy_sha256 différente de l'empreinte que le noyau a déclarée au charger : invalide, raison politique_non_epinglee", function () {
    expect(validerReponseEvaluer({ ...base(), policy_sha256: EMPREINTE_QUELCONQUE }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
    // l'empreinte d'une autre version détenue ne vaut pas pour celle-ci
    expect(validerReponseEvaluer({ ...base(), policy_sha256: sha("v2") }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("addendum : approval_sha256 différent du condensé du membre approval que le noyau a envoyé au charger : invalide, politique_non_epinglee (même avec version et empreinte justes)", function () {
    expect(validerReponseEvaluer({ ...base(), approval_sha256: EMPREINTE_QUELCONQUE }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
    // le condensé d'une autre version détenue (autres règles) ne vaut pas pour celle-ci
    expect(condense("v2")).to.not.equal(condense("v1"));
    expect(validerReponseEvaluer({ ...base(), approval_sha256: condense("v2") }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
    // le condensé porte sur le membre approval sans service : un service différent ne le change pas
    const autreService = { ...detenus.v1, approval: { ...detenus.v1.approval, service: { url: "http://127.0.0.1:2/" } } };
    expect(condenseApproval(autreService.approval)).to.equal(condense("v1"));
    // observation : même vérification
    const obs = { ...base(), rule: "paiement > 5000 CHF", decision: "a_approuver", approval_sha256: EMPREINTE_QUELCONQUE };
    expect(validerReponseEvaluer(obs, ctx({ observation: true }))).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("policy_version que le noyau ne détient pas : invalide, politique_non_epinglee, même avec une empreinte bien formée", function () {
    expect(validerReponseEvaluer({ ...base(), policy_version: "v9", policy_sha256: EMPREINTE_QUELCONQUE }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer({ ...base(), policy_version: "v9", policy_sha256: sha("v1") }, ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("sans ticket rapproché (ticket nul, ou ticket_state nouveau), policy_version doit être celle de la requête", function () {
    // v2 est détenue (version précédente gardée), son empreinte est juste, mais la requête est sous v1
    expect(validerReponseEvaluer(base("v2"), ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer(base("v2"), ctx({ versionRequete: "v2" }))).to.include({ valide: true });
    const nouveau = (pv) => ({ ...base(pv), rule: "r", decision: "a_approuver", ticket: "apr-9", ticket_state: "nouveau", approver_set: JEU });
    expect(validerReponseEvaluer(nouveau("v1"), ctx())).to.deep.equal({ valide: true, combinaison: "a_approuver/nouveau" });
    expect(validerReponseEvaluer(nouveau("v2"), ctx())).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("ticket rapproché : la version de la retenue du ticket est admise quand elle diffère de celle de la requête ; la version de la requête à sa place est refusée", function () {
    // requête sous v2 (après rechargement), ticket apr-1 retenu sous v1
    const c = ctx({ versionRequete: "v2" });
    expect(validerReponseEvaluer(enAttente("apr-1", "v1"), c)).to.deep.equal({ valide: true, combinaison: "a_approuver/en_attente" });
    expect(validerReponseEvaluer(enAttente("apr-1", "v2"), c)).to.include({ valide: false, raison: "politique_non_epinglee" });
    // la version de la retenue, mais une empreinte qui n'est pas celle déclarée au charger de v1
    expect(validerReponseEvaluer({ ...enAttente("apr-1", "v1"), policy_sha256: sha("v2") }, c)).to.include({ valide: false, raison: "politique_non_epinglee" });
    // ticket rapproché dont le noyau n'a aucune retenue : la version de la requête est exigée
    expect(validerReponseEvaluer(enAttente("apr-7", "v2"), c)).to.include({ valide: true });
    expect(validerReponseEvaluer(enAttente("apr-7", "v1"), c)).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("mode observation (EX-7.23) : même vérification ; le couple juste est admis, un couple faux est invalide", function () {
    const obs = (pv) => ({ ...base(pv), rule: "paiement > 5000 CHF", decision: "a_approuver" });
    expect(validerReponseEvaluer(obs("v1"), ctx({ observation: true }))).to.deep.equal({ valide: true, combinaison: "observation" });
    expect(validerReponseEvaluer({ ...obs("v1"), policy_sha256: EMPREINTE_QUELCONQUE }, ctx({ observation: true }))).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer(obs("v2"), ctx({ observation: true }))).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer({ ...obs("v1"), policy_version: "v9" }, ctx({ observation: true }))).to.include({ valide: false, raison: "politique_non_epinglee" });
  });

  it("un contexte sans ensemble de politique ni version de requête ne saute pas la vérification : invalide", function () {
    expect(validerReponseEvaluer(base(), { decisionScellee: () => null })).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer(base(), ctx({ politique: () => null }))).to.include({ valide: false, raison: "politique_non_epinglee" });
    expect(validerReponseEvaluer(base(), ctx({ versionRequete: null }))).to.include({ valide: false, raison: "politique_non_epinglee" });
  });
});

// ----------------------------------------------------------------------------
// 3. Noyau : cœur et frontal MCP (banc du moteur de politique, service simulé)
// ----------------------------------------------------------------------------
describe("Protocole d'approbation, 3 : noyau, coeur.evaluer et le frontal appliquent la vérification (EX-7.16, 14.2, EX-7.23, EX-14.15)", function () {
  this.timeout(60000);
  const PAIEMENT = Object.freeze({ claim_id: "2026-81044", amount: "9000.00", currency: "CHF", beneficiary_iban: IBAN });
  const PETIT = Object.freeze({ claim_id: "2026-81045", amount: "100.00", currency: "CHF", beneficiary_iban: IBAN });
  const erreur = (r) => r.error;
  const texte = (r) => r.result.content[0].text;
  const etatSignal = (r) => r.result._meta["noortrace/approval"];
  /** Couple que le noyau a déclaré au charger de sa version épinglée. */
  const coupleEpingle = (banc) => ({
    policy_version: banc.coeur.versionPolitique,
    policy_sha256: empreintePolitique(banc.coeur.config.policy).policy_sha256,
    approval_sha256: condenseApproval(banc.coeur.config.policy.approval),
  });
  const autoriseSansTicket = (couple) => ({ rule: "defaut : autorise", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null, ...couple });
  /** Observe les réponses que le service rend au cœur. */
  const observerReponses = (banc) => {
    const vues = [];
    const origine = banc.service.evaluer.bind(banc.service);
    banc.service.evaluer = async (r) => {
      const x = await origine(r);
      vues.push(x);
      return x;
    };
    return vues;
  };
  async function retenir(banc, args = PAIEMENT) {
    const r = await banc.appeler("demo__payments.create", args);
    expect(texte(r)).to.match(/state=en_attente$/);
    const ticket = etatSignal(r).ticket;
    await attendre(() => banc.service.tickets.get(ticket)?.request);
    return ticket;
  }

  describe("mode erreur", function () {
    let banc;
    beforeEach(async function () {
      banc = await monterBanc();
    });
    afterEach(async function () {
      await banc.arreter();
    });

    it("chemin honnête : le service factice recopie le couple du charger ; une écriture autorisée est relayée (pas de faux positif)", async function () {
      const vues = observerReponses(banc);
      const r = await banc.appeler("demo__payments.create", PETIT);
      expect(r.result.isError).to.equal(false);
      expect(vues).to.have.lengthOf(1);
      expect(Object.keys(vues[0]).sort()).to.deep.equal(NEUF_MEMBRES);
      expect(vues[0]).to.include({ decision: "autorise", ticket: null, ...coupleEpingle(banc) });
      expect((await banc.evenements()).at(-1).policy).to.include({ decision: "autorise", ticket: null });
    });

    it("policy_sha256 différente de l'empreinte épinglée : -31010 raison approbation, approval_response_invalid raison politique_non_epinglee, aucun événement ni relais", async function () {
      const n0 = (await banc.evenements()).length;
      const i0 = banc.lignes("approval_response_invalid").length;
      banc.service.reponseForcee = () => autoriseSansTicket({ ...coupleEpingle(banc), policy_sha256: EMPREINTE_QUELCONQUE });
      try {
        const r = await banc.appeler("demo__payments.create", PETIT);
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).length).to.equal(n0);
      const lignes = banc.lignes("approval_response_invalid").slice(i0);
      expect(lignes).to.have.lengthOf(1);
      expect(lignes[0].data).to.include({ raison: "politique_non_epinglee" });
      expect(banc.lignes("call_blocked").at(-1).data).to.include({ code: -31010, reason: "approbation" });
    });

    it("policy_version que le noyau ne détient pas : -31010, politique_non_epinglee", async function () {
      banc.service.reponseForcee = () => autoriseSansTicket({ policy_version: "version-future", policy_sha256: EMPREINTE_QUELCONQUE, approval_sha256: EMPREINTE_QUELCONQUE });
      try {
        const r = await banc.appeler("demo__payments.create", PETIT);
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_response_invalid").at(-1).data).to.include({ raison: "politique_non_epinglee" });
    });

    it("addendum : approval_sha256 de la réponse evaluer différent du condensé envoyé au charger : -31010, politique_non_epinglee", async function () {
      banc.service.reponseForcee = () => autoriseSansTicket({ ...coupleEpingle(banc), approval_sha256: EMPREINTE_QUELCONQUE });
      try {
        const r = await banc.appeler("demo__payments.create", PETIT);
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_response_invalid").at(-1).data).to.include({ raison: "politique_non_epinglee" });
    });

    it("addendum (EX-7.15) : réponse de charger dont approval_sha256 diffère du condensé envoyé : charger tenu pour échoué (approval_charger_refuse), aucune liste CANDIDATS, écriture -31010 sans appel à evaluer", async function () {
      const origine = banc.service.charger.bind(banc.service);
      banc.service.charger = async (r) => ({ ...(await origine(r)), approval_sha256: EMPREINTE_QUELCONQUE });
      const e0 = banc.service.messages.filter((m) => m.methode === "evaluer").length;
      try {
        banc.coeur.definirOutils(banc.coeur.outils);
        await attendre(() => banc.lignes("approval_charger_refuse").some((l) => l.data.message === "charger" && l.data.code === "approval_sha256_different"));
        expect(banc.coeur.candidats).to.equal(null);
        expect(banc.coeur.chargerEtat).to.include({ version: banc.coeur.versionPolitique, statut: "refuse", code: "approval_sha256_different" });
        const r = await banc.appeler("demo__payments.create", PETIT);
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
        expect(banc.service.messages.filter((m) => m.methode === "evaluer").length, "le service n'est pas interrogé").to.equal(e0);
        expect(banc.lignes("approval_charger_refuse").at(-1).data).to.include({ message: "evaluer", statut: "refuse" });
      } finally {
        banc.service.charger = origine;
      }
      // un charger conforme rétablit l'évaluation
      banc.coeur.definirOutils(banc.coeur.outils);
      await attendre(() => banc.coeur.candidats !== null && banc.coeur.chargerEtat?.statut === "reussi");
      const r2 = await banc.appeler("demo__payments.create", PETIT);
      expect(r2.result.isError).to.equal(false);
    });

    it("addendum (EX-7.15) : charger refusé par le service (requete_invalide) : rien n'est évalué sous cette version, -31010 raison approbation, approval_charger_refuse", async function () {
      const origine = banc.service.charger.bind(banc.service);
      banc.service.charger = async (r) => {
        banc.service.enregistrer("charger", r);
        throw new ErreurServiceApprobation("requete_invalide");
      };
      const e0 = banc.service.messages.filter((m) => m.methode === "evaluer").length;
      try {
        banc.coeur.definirOutils(banc.coeur.outils);
        await attendre(() => banc.coeur.chargerEtat?.statut === "refuse");
        expect(banc.coeur.chargerEtat.code).to.equal("requete_invalide");
        expect(banc.lignes("approval_charger_refuse").some((l) => l.data.message === "charger" && l.data.code === "requete_invalide")).to.equal(true);
        const r = await banc.appeler("demo__payments.create", PETIT);
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
        expect(banc.service.messages.filter((m) => m.methode === "evaluer").length).to.equal(e0);
      } finally {
        banc.service.charger = origine;
      }
    });

    it("ticket rapproché après rechargement : la version de la retenue (différente de la requête) est acceptée, la version de la requête à sa place est refusée", async function () {
      const ticket = await retenir(banc);
      const ancienne = coupleEpingle(banc);
      // rechargement : version test-2, même politique par ailleurs
      const brut = JSON.parse(JSON.stringify(banc.config));
      brut.policy.version = "test-2";
      expect((await banc.coeur.recharger(enc(brut), { env: banc.env })).accepte).to.equal(true);
      await attendre(() => banc.coeur.candidats !== null);
      const nouvelle = coupleEpingle(banc);
      expect(nouvelle.policy_version).to.equal("test-2");
      expect(nouvelle.policy_sha256).to.not.equal(ancienne.policy_sha256);
      // ré-émission de la demande retenue sous test-1 : le service répond avec la version du ticket (test-1)
      const vues = observerReponses(banc);
      const r = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "en_attente" });
      expect(vues.at(-1)).to.include({ ticket, ticket_state: "en_attente", ...ancienne });
      // la version de la requête (test-2) à la place de celle de la retenue : refusée
      banc.service.reponseForcee = () => ({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket, ticket_state: "en_attente", approval: null, approver_set: null, ...nouvelle });
      try {
        const r2 = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r2)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_response_invalid").at(-1).data).to.include({ raison: "politique_non_epinglee" });
    });
  });

  describe("mode observation", function () {
    let banc;
    beforeEach(async function () {
      banc = await monterBanc({ mode: "observation" });
    });
    afterEach(async function () {
      await banc.arreter();
    });

    it("réponse à couple faux : relayée avec la marque inconnu, approval_response_invalid raison politique_non_epinglee ; couple juste : marque de la décision", async function () {
      const obs = (couple) => ({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null, ...couple });
      const i0 = banc.lignes("approval_response_invalid").length;
      banc.service.reponseForcee = () => obs({ ...coupleEpingle(banc), policy_sha256: EMPREINTE_QUELCONQUE });
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(r.result.isError).to.equal(false);
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).at(-1).policy.rule).to.equal("evaluation impossible [observation inconnu]");
      const lignes = banc.lignes("approval_response_invalid").slice(i0);
      expect(lignes).to.have.lengthOf(1);
      expect(lignes[0].data).to.include({ raison: "politique_non_epinglee" });
      banc.service.reponseForcee = () => obs(coupleEpingle(banc));
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(r.result.isError).to.equal(false);
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).at(-1).policy.rule).to.equal("paiement > 5000 CHF [observation a_approuver]");
      expect(banc.lignes("approval_response_invalid").length - i0).to.equal(1);
    });
  });
});

// ----------------------------------------------------------------------------
// 4. Rejeu de l'essai de contournement, pas 5 : service réel (en mémoire) et cœur réel
// ----------------------------------------------------------------------------
describe("Protocole d'approbation, 4 : rejeu de l'essai de contournement, pas 5 (pré-enregistrement d'une version future par un pair détenteur du canal du noyau)", function () {
  this.timeout(60000);

  /** Le service réel (objet en mémoire) vu par le cœur comme un service de CT-3 §12 ; `decisions` sans remise. */
  class ServiceDirect extends ServiceApprobation {
    constructor(service) {
      super();
      this.service = service;
    }
    async #appel(methode, requete) {
      try {
        return await this.service[methode](requete);
      } catch (e) {
        if (e instanceof A.ErreurService) throw new ErreurServiceApprobation(e.code, e.data);
        throw e;
      }
    }
    charger(r) { return this.#appel("charger", r); }
    evaluer(r) { return this.#appel("evaluer", r); }
    ouvrir(r) { return this.#appel("ouvrir", r); }
    acquitter(r) { return this.#appel("acquitter", r); }
    consommer(r) { return this.#appel("consommer", r); }
    expiration(r) { return this.#appel("expiration", r); }
    async decisions(r) {
      await new Promise((x) => { setTimeout(x, Math.min(r?.wait_ms ?? 200, 200)).unref?.(); });
      return { remises: [] };
    }
  }

  it("pas 5 : version future pré-enregistrée (permissive, empreinte quelconque) puis paiement sous seuil : -31010 raison approbation, politique_non_epinglee, passant = false", async function () {
    const dir = repertoireTemporaire("noortrace-s2-testB-");
    let { config } = configurationDev(dir, { journal_id: JOURNAL_ID });
    const { env } = configurationDev(dir, { journal_id: JOURNAL_ID });
    config.recorder.org_id = ORG_ID;
    config.policy.version = "parcours-1";
    // jeu statique (le service en mémoire n'a pas de lecteur de registre) ; règles de la configuration de développement
    config.policy.approval.rules.approver_set = { ...JEU_STATIQUE };
    const brut = JSON.parse(JSON.stringify(config));
    config = validerConfiguration(enc(config), { reglesSupplementaires: [controlePolitiqueApprobation] }).config;
    const service = serviceEnMemoire(dir);
    const horloge = new HorlogeReglable(ms("2026-11-14T10:00:00.000Z"));
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service: new ServiceDirect(service), reglesSupplementaires: [controlePolitiqueApprobation] });
    try {
      // Pas 1 : le noyau légitime charge parcours-1 ; le service garde l'empreinte déclarée.
      await attendre(() => coeur.candidats !== null);
      const honnete = empreintePolitique(coeur.config.policy);
      expect(honnete.policy_version).to.equal("parcours-1");
      expect(service.machine.version("parcours-1").policy_sha256).to.equal(honnete.policy_sha256);
      // Pas 2 : paiement de 9 999 999 CHF : soumis à approbation, réponse valide (chemin honnête).
      const gros = await coeur.evaluer(paiementParcours("9999999.00", "parcours-1", "2026-90417"));
      expect(gros).to.include({ decision: "a_approuver", ticket_state: "nouveau", policy_version: "parcours-1", policy_sha256: honnete.policy_sha256 });
      // Pas 5 : l'attaquant, qui détient le jeton du canal du noyau, pré-enregistre parcours-2 (permissive, empreinte quelconque) :
      // le service l'accepte (il ne peut pas recalculer l'empreinte).
      const pre = { ...messageCharger({ policy_version: "parcours-2", rules: PERMISSIVE }), policy_sha256: EMPREINTE_QUELCONQUE };
      expect((await service.charger(pre)).policy_version).to.equal("parcours-2");
      // Le noyau passe honnêtement à parcours-2 ; son charger est refusé par le service (autre empreinte) : aucune liste CANDIDATS.
      const brut2 = { ...brut, policy: { ...brut.policy, version: "parcours-2" } };
      expect((await coeur.recharger(enc(brut2), { env })).accepte).to.equal(true);
      await attendre(() => coeur.journal.trouver("approval_service_unavailable").some((l) => l.data?.message === "charger"));
      expect(coeur.candidats).to.equal(null);
      expect(coeur.versionPolitique).to.equal("parcours-2");
      // Paiement sous seuil sous parcours-2 : le service répond sous la politique permissive de l'attaquant, avec son couple.
      let reponse = null;
      let err = null;
      try {
        reponse = await coeur.evaluer(paiementParcours("900.00", "parcours-2", "2026-90999"));
      } catch (e) {
        err = e;
      }
      expect(reponse, "contournement : le paiement serait relayé sans ticket (passant)").to.equal(null);
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.code).to.equal(-31010);
      expect(err.raison).to.equal("approbation");
      // Addendum (EX-7.15) : le charger honnête ayant été refusé, rien n'est évalué sous parcours-2 ; le service n'est pas interrogé.
      expect(err.donnees?.raison).to.equal("approval_charger_refuse");
      expect(coeur.journal.trouver("approval_charger_refuse").some((l) => l.data.message === "charger" && l.data.code === "requete_invalide")).to.equal(true);
      expect(coeur.journal.trouver("approval_charger_refuse").at(-1).data).to.include({ message: "evaluer", statut: "refuse" });
    } finally {
      await coeur.arreter();
    }
  });

  it("addendum, scénario de pré-enregistrement à empreinte honnête : version future pré-enregistrée avec l'EMPREINTE HONNÊTE et des règles permissives, charger honnête refusé, paiement sous seuil : -31010 raison approbation, passant = false", async function () {
    const dir = repertoireTemporaire("noortrace-s2-residu8-");
    let { config } = configurationDev(dir, { journal_id: JOURNAL_ID });
    const { env } = configurationDev(dir, { journal_id: JOURNAL_ID });
    config.recorder.org_id = ORG_ID;
    config.policy.version = "parcours-1";
    config.policy.approval.rules.approver_set = { ...JEU_STATIQUE };
    const brut = JSON.parse(JSON.stringify(config));
    const brut2 = { ...brut, policy: { ...brut.policy, version: "parcours-2" } };
    // L'attaquant connaît le futur ensemble : empreinte honnête de parcours-2 (EX-8.11).
    const honnete2 = empreintePolitique(validerConfiguration(enc(brut2), { reglesSupplementaires: [controlePolitiqueApprobation] }).config.policy);
    config = validerConfiguration(enc(config), { reglesSupplementaires: [controlePolitiqueApprobation] }).config;
    const service = serviceEnMemoire(dir);
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(ms("2026-11-14T10:00:00.000Z")), service: new ServiceDirect(service), reglesSupplementaires: [controlePolitiqueApprobation] });
    try {
      await attendre(() => coeur.candidats !== null);
      // pré-enregistrement : empreinte honnête, règles permissives : accepté par le service
      const pre = { ...messageCharger({ policy_version: "parcours-2", rules: PERMISSIVE }), policy_sha256: honnete2.policy_sha256 };
      const c = await service.charger(pre);
      expect(c).to.include({ policy_version: "parcours-2", policy_sha256: honnete2.policy_sha256, approval_sha256: condenseApproval(pre.approval) });
      // passage honnête à parcours-2 : le charger du noyau (même empreinte, autre politique) est refusé (CT-3 EX-12.5)
      expect((await coeur.recharger(enc(brut2), { env })).accepte).to.equal(true);
      await attendre(() => coeur.chargerEtat?.version === "parcours-2" && coeur.chargerEtat.statut === "refuse");
      expect(coeur.chargerEtat.code).to.equal("requete_invalide");
      expect(coeur.candidats).to.equal(null);
      // paiement sous seuil : avant l'addendum, autorise/null avec le couple honnête (passant) ; désormais -31010
      let reponse = null;
      let err = null;
      try {
        reponse = await coeur.evaluer(paiementParcours("900.00", "parcours-2", "2026-90999"));
      } catch (e) {
        err = e;
      }
      expect(reponse, "contournement : le paiement serait relayé sous les règles de l'attaquant").to.equal(null);
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.code).to.equal(-31010);
      expect(err.raison).to.equal("approbation");
      expect(err.donnees?.raison).to.equal("approval_charger_refuse");
      // défense en profondeur : même sans la règle d'EX-7.15, la réponse du service porterait le condensé des règles
      // permissives, différent de celui du noyau : invalide (politique_non_epinglee)
      const directe = await service.evaluer(paiementParcours("900.00", "parcours-2", "2026-90999"));
      expect(directe).to.include({ decision: "autorise", policy_sha256: honnete2.policy_sha256 });
      expect(directe.approval_sha256).to.not.equal(condenseApproval(coeur.config.policy.approval));
      const v = validerReponseEvaluer(directe, { decisionScellee: () => null, observation: false, versionRequete: "parcours-2", politique: (x) => coeur._politiqueDetenue(x), versionRetenue: () => null });
      expect(v).to.include({ valide: false, raison: "politique_non_epinglee" });
    } finally {
      await coeur.arreter();
    }
  });
});
