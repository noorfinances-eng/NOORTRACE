// Parcours de bout en bout du service d'approbation lancé comme processus
// (bin/noortrace-approbation), joint par le client du démon
// (`ClientServiceApprobation` de @noortrace/enregistreur, rubrique d) sur une
// prise Unix, avec jeton porteur ; votes signés EIP-191 par les comptes de
// test (CT-3 §9 : secp256k1, objet A de CT-1 §6.3 ; EIP-712 est une piste de
// version 1, section 16) transmis sur le canal de la console.
//
//   1. politique chargée (jeu statique), lecture autorisée, refus sans ticket ;
//   2. paiement soumis à approbation : ticket, ouvrir (événement retenue
//      scellé par la clé de test), votes, remise, contrôle SG-1 à SG-7,
//      acquittement du scellement, ré-émission servie une fois, consommation,
//      nouvel appel identique : nouveau ticket ;
//   3. fenêtre : ticket ouvrant approuvé, appel couvert ;
//   4. expiration : version à échéance courte, remise expire scellée ;
//   5. arrêt brutal du service (SIGKILL) avec un ticket à mi-chemin, une
//      remise non acquittée et une ligne d'état tronquée : reprise, remise
//      re-présentée, décision acquittée ;
//   6. jeu `registre` lu sur le réseau Hardhat (CuratorSetRegistry et
//      CuratorSet du dépôt) par un pont JSON-RPC : non_pret, jeu de repli,
//      gel, confirmation, source d'EX-8.8 (la surveillance des journaux du
//      jeu, EX-8.5, est exercée sur le lecteur par le fichier des exigences).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { network } from "hardhat";
import * as N from "@noortrace/noyau";
import { verifierRemise, MOTIF_SOURCE } from "@noortrace/approbation";
import { ClientServiceApprobation } from "@noortrace/enregistreur";
import {
  ORG_ID, JOURNAL_ID, SESSIONS, adresse, signerVote, repertoireTemporaire, politiqueParcours, messageCharger, requeteEvaluer,
  retenue, ecrireConfiguration, lancerService, appelConsole, pontRpc, attendre,
} from "./fixtures/approbation-service/outils.mjs";

const V1 = "parcours-1";
const paiement = (montant, extra = {}) => ({ claim_id: "2026-90417", amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957", ...extra });
const maintenant = (decalage = 0) => N.ecrireHorodatage(Date.now() + decalage);

/** Contexte SG d'une remise vue du noyau : la retenue ouverte, la séparation de la politique. */
const ctxSG = (ret, ticket, rules, expire_after_ms = 3600000) => ({
  org_id: ORG_ID, journal_id: JOURNAL_ID,
  retained: [{ seq: ret.evenement.seq, ticket, hash: ret.evenement.hash, ts: ret.evenement.ts, launched_by: ret.evenement.delegation.launched_by }],
  decided: [], expire_after_ms, separation: rules.separation, write_at: maintenant(),
});

describe("service d'approbation : parcours de bout en bout (processus)", function () {
  this.timeout(120000);
  let dir;
  let cfg;
  let svc;
  let client;
  let seq = 4;

  const voter = (ticket, hash, i, decision = "approuve", reason = null) =>
    appelConsole(svc.console, cfg.jetonConsole, "voter", {
      ticket, approver: adresse(i), decision, signature: signerVote(i, { decision, ticket, request_hash: hash }), reason, session_identity: SESSIONS[i],
    });

  /** evaluer → retenue scellée → ouvrir ; rend la réponse, la retenue et la requête. */
  async function demanderEtOuvrir(args, o = {}) {
    const requete = requeteEvaluer(o.outil ?? "sap__payments.create", args, { policy_version: o.pv ?? V1 });
    const r = await client.evaluer(requete);
    expect(r.ticket_state, JSON.stringify(r)).to.equal("nouveau");
    seq += 2;
    const ret = retenue({ requete, rule: r.rule, ticket: r.ticket, seq, ts: maintenant(-200) });
    const o2 = await client.ouvrir(ret.ouvrir);
    expect(o2).to.deep.equal({ ticket: r.ticket, state: "ouvert", deadline: N.ecrireHorodatage(N.decoderHorodatage(ret.evenement.ts) + (o.E ?? 3600000)) });
    return { r, ret, requete };
  }

  /** Acquitte le scellement d'une remise comme le noyau (EX-12.9) ; rend l'approval scellé. */
  async function sceller(remise, held = false) {
    seq += 1;
    const approval = { ...remise.approval, at: maintenant() };
    const hash = N.sha256Hex(N.utf8(`decision ${remise.ticket}`));
    const a = await client.acquitter({ remise_id: remise.remise_id, ticket: remise.ticket, result: "scelle", reason: null, seq, hash, at: approval.at, decision: approval.decision, held, approval });
    expect(a).to.deep.equal({ ticket: remise.ticket, state: approval.decision });
    return approval;
  }

  before(async function () {
    dir = repertoireTemporaire();
    cfg = ecrireConfiguration(dir, { epoch: "parcours", remise_representation_ms: 60000 });
    svc = await lancerService(cfg.chemin);
    client = new ClientServiceApprobation({ socket: cfg.socket, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
    expect((fs.statSync(cfg.socket).mode & 0o777).toString(8)).to.equal("660");
  });
  after(async function () {
    await svc?.arreter();
  });

  it("1. charger, lecture autorisée, refus par la politique sans ticket", async function () {
    const ch = await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
    expect(ch).to.deep.equal({ policy_version: V1, policy_sha256: messageCharger({ policy_version: V1, rules: {} }).policy_sha256, approval_candidates: ["sap__claims.delete", "sap__payments.create"] });
    expect(await client.evaluer(requeteEvaluer("sap__claims.get", { claim_id: "2026-90417" }))).to.deep.equal({ rule: "lecture autorisee", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });
    expect(await client.evaluer(requeteEvaluer("sap__payments.create", paiement("700.00", { currency: "EUR" })))).to.deep.equal({ rule: "paiement hors CHF", decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null });
  });

  it("2. demande soumise à approbation : votes signés, remise, scellement, ré-émission servie une fois, consommation", async function () {
    const { r, ret, requete } = await demanderEtOuvrir(paiement("7400.00"));
    expect(r.ticket).to.equal("apr-parcours-0001");
    expect(r.approver_set).to.deep.equal({ threshold: { required: 2, size: 3 }, members: [adresse(1), adresse(2), adresse(3)].sort(), source: `jeu statique de la politique ${V1}` });
    // ré-émission pendant l'attente : en_attente, même ticket
    expect(await client.evaluer(requete)).to.include({ decision: "a_approuver", ticket_state: "en_attente", ticket: r.ticket });
    expect((await voter(r.ticket, ret.evenement.hash, 3)).corps.error.code).to.equal("auto_approbation");
    expect((await voter(r.ticket, ret.evenement.hash, 1)).corps).to.deep.equal({ ticket: r.ticket, state: "ouvert" });
    const attente = client.decisions({ wait_ms: 10000 });
    expect((await voter(r.ticket, ret.evenement.hash, 2, "approuve", "Constat et facture concordants")).corps).to.deep.equal({ ticket: r.ticket, state: "a_remettre" });
    const { remises } = await attente;
    expect(remises).to.have.length(1);
    const remise = remises[0];
    expect(remise.remise_id).to.equal(`${r.ticket}/1`);
    expect(remise.approval).to.deep.include({ decision: "approuve", ticket: r.ticket, request_hash: ret.evenement.hash, approvers: [adresse(1), adresse(2)], reason: "Constat et facture concordants" });
    // le noyau la vérifierait : SG-1 à SG-7 passent
    expect(verifierRemise(remise, ctxSG(ret, r.ticket, politiqueParcours()))).to.deep.equal({ result: "scelle", reason: null, check: null });
    // même forme que la décision de journal-demo (seq 6) : membres de l'approval, ordre des signatures
    expect(Object.keys(remise.approval).sort()).to.deep.equal(["approvers", "decision", "reason", "request_hash", "signatures", "threshold", "ticket"]);
    const approval = await sceller(remise);
    const servie = await client.evaluer(requete);
    expect(servie).to.deep.equal({ rule: "paiement > 5000 CHF", decision: "autorise", ticket: r.ticket, ticket_state: "approuve", approval, approver_set: null });
    expect(await client.evaluer(requete)).to.include({ decision: "a_approuver", ticket_state: "en_attente" });
    expect(await client.consommer({ ticket: r.ticket, seq: 99, hash: N.sha256Hex(N.utf8("relais")) })).to.deep.equal({ ticket: r.ticket, state: "consomme" });
    const nouveau = await client.evaluer(requete);
    expect(nouveau).to.include({ ticket_state: "nouveau" });
    expect(nouveau.ticket).to.not.equal(r.ticket);
  });

  it("3. fenêtre : ticket ouvrant approuvé, puis appel couvert sans approbation", async function () {
    const { r, ret } = await demanderEtOuvrir(paiement("2500.00", { beneficiary_iban: "CH5604835012345678009" }));
    await voter(r.ticket, ret.evenement.hash, 1);
    await voter(r.ticket, ret.evenement.hash, 2);
    const { remises } = await client.decisions({ wait_ms: 5000 });
    const remise = remises.find((x) => x.ticket === r.ticket);
    const approval = await sceller(remise);
    const fin = N.ecrireHorodatage(N.decoderHorodatage(approval.at) + 3600000);
    const couvert = await client.evaluer(requeteEvaluer("sap__payments.create", paiement("3000.00", { beneficiary_iban: "CH5604835012345678009" })));
    expect(couvert).to.deep.equal({ rule: `paiement de 1000 a 5000 CHF [fenetre ${r.ticket} ${fin}]`, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });
  });

  it("4. expiration : échéance sans décision, remise expire, scellement, ré-émission refusée", async function () {
    await client.charger(messageCharger({ policy_version: "parcours-2", rules: politiqueParcours({ contest_ms: 500 }), expire_after_ms: 2000 }));
    const { r, requete } = await demanderEtOuvrir(paiement("9100.00"), { pv: "parcours-2", E: 2000 });
    const { remises } = await attendre(async () => {
      const d = await client.decisions({ wait_ms: 3000 });
      return d.remises.some((x) => x.ticket === r.ticket) ? d : null;
    }, 10000);
    const remise = remises.find((x) => x.ticket === r.ticket);
    expect(remise.approval).to.deep.include({ decision: "expire", approvers: [], signatures: [], reason: "echeance atteinte sans decision" });
    const approval = await sceller(remise);
    expect(await client.evaluer(requete)).to.deep.equal({ rule: "paiement > 5000 CHF", decision: "refuse", ticket: r.ticket, ticket_state: "expire", approval, approver_set: null });
  });

  it("5. arrêt brutal pendant l'attente : reprise, remise re-présentée, décision acquittée", async function () {
    await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
    const { r, ret, requete } = await demanderEtOuvrir(paiement("8800.00"));
    await voter(r.ticket, ret.evenement.hash, 1);
    await svc.tuer(); // SIGKILL : un vote inscrit, aucune remise
    // écriture interrompue : une ligne tronquée en fin de journal d'état
    fs.appendFileSync(path.join(dir, "service", "etat", "journal.ndjson"), "9999 AAAA");
    svc = await lancerService(cfg.chemin);
    client = new ClientServiceApprobation({ socket: cfg.socket, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
    // le vote a survécu : un second vote atteint le seuil
    expect((await voter(r.ticket, ret.evenement.hash, 2)).corps).to.deep.equal({ ticket: r.ticket, state: "a_remettre" });
    const premiere = (await client.decisions({ wait_ms: 5000 })).remises.find((x) => x.ticket === r.ticket);
    await svc.tuer(); // remise livrée, jamais acquittée
    svc = await lancerService(cfg.chemin);
    client = new ClientServiceApprobation({ socket: cfg.socket, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
    const representee = (await client.decisions({ wait_ms: 5000 })).remises.find((x) => x.ticket === r.ticket);
    expect(representee).to.deep.equal(premiere);
    const approval = await sceller(representee);
    expect((await client.evaluer(requete)).approval).to.deep.equal(approval);
    const journal = fs.readFileSync(path.join(dir, "service", "journal-service.ndjson"), "utf8");
    expect(journal).to.contain('"derniere_ligne_tronquee"');
  });

  describe("6. jeu registre lu sur le réseau Hardhat", function () {
    let pont;
    let reg;
    let jeu;
    let svcR;
    let clientR;
    let cfgR;
    before(async function () {
      const conn = network.create ? await network.create() : await network.connect();
      const [admin] = await conn.ethers.getSigners();
      reg = await conn.ethers.deployContract("CuratorSetRegistry", [admin.address]);
      jeu = await conn.ethers.deployContract("CuratorSet", [admin.address, [adresse(1), adresse(2), adresse(3)], 2]);
      pont = await pontRpc(conn.provider);
      const d = repertoireTemporaire();
      cfgR = ecrireConfiguration(d, { epoch: "registre", rpc: { url: pont.url, validator: "developpement", timeout_ms: 5000 }, set_poll_interval_ms: 1000 });
      svcR = await lancerService(cfgR.chemin);
      clientR = new ClientServiceApprobation({ socket: cfgR.socket, jeton: cfgR.jetonNoyau, timeout_ms: 5000 });
    });
    after(async function () {
      await svcR?.arreter();
      await pont?.fermer();
    });

    it("non_pret tant que le jeu n'est pas lu ; repli, gel, confirmation, source d'EX-8.8", async function () {
      const pol = { source: "registre", chain_id: 31337, registry: (await reg.getAddress()).toLowerCase(), set: (await jeu.getAddress()).toLowerCase(), members: null, threshold: null };
      const rules = politiqueParcours({ approver_set: pol });
      await clientR.charger(messageCharger({ policy_version: V1, rules }));
      // le registre ne désigne encore aucun jeu : organisation_sans_jeu, non_pret
      await new Promise((ok) => setTimeout(ok, 300));
      const e = await clientR.evaluer(requeteEvaluer("sap__payments.create", paiement("7400.00"))).catch((x) => x);
      expect(e.code).to.equal("non_pret");
      await (await reg.setCuratorSet(ORG_ID, await jeu.getAddress())).wait();
      const nouveau = await attendre(async () => clientR.evaluer(requeteEvaluer("sap__payments.create", paiement("7400.00"))).catch(() => null), 15000, 200);
      expect(nouveau.approver_set.source).to.match(MOTIF_SOURCE);
      expect(nouveau.approver_set.source).to.match(/^CuratorSet c=31337 r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=(\d+)\.\.\1 b=0x[0-9a-f]{64} repli$/);
      const requete = requeteEvaluer("sap__payments.create", paiement("7400.00"));
      const ret = retenue({ requete, rule: nouveau.rule, ticket: nouveau.ticket, seq: 5, ts: maintenant(-200) });
      await clientR.ouvrir(ret.ouvrir);
      // gel à la lecture qui suit l'ouverture ; puis votes ; confirmation par une lecture après le calcul
      await attendre(async () => {
        const r = await appelConsole(svcR.console, cfgR.jetonConsole, "voter", { ticket: nouveau.ticket, approver: adresse(1), decision: "approuve", signature: signerVote(1, { decision: "approuve", ticket: nouveau.ticket, request_hash: ret.evenement.hash }), reason: null, session_identity: SESSIONS[1] });
        return r.statut === 200 || r.corps.error?.code === "vote_identique";
      }, 15000, 200);
      await appelConsole(svcR.console, cfgR.jetonConsole, "voter", { ticket: nouveau.ticket, approver: adresse(2), decision: "approuve", signature: signerVote(2, { decision: "approuve", ticket: nouveau.ticket, request_hash: ret.evenement.hash }), reason: "ok", session_identity: SESSIONS[2] });
      const remise = await attendre(async () => (await clientR.decisions({ wait_ms: 2000 })).remises.find((x) => x.ticket === nouveau.ticket), 20000);
      expect(remise.approver_set.source).to.match(/^CuratorSet c=31337 r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=\d+\.\.\d+ b=0x[0-9a-f]{64}$/);
      expect(remise.approver_set.members).to.deep.equal([adresse(1), adresse(2), adresse(3)].sort());
      expect(verifierRemise(remise, ctxSG(ret, nouveau.ticket, rules))).to.deep.include({ result: "scelle" });
    });
  });

  it("le journal du service ne porte aucun argument en clair et consigne l'empreinte du logiciel", function () {
    const journal = fs.readFileSync(path.join(dir, "service", "journal-service.ndjson"), "utf8");
    expect(journal).to.not.contain("CH9300762011623852957");
    expect(journal).to.match(/"empreinte":"0x[0-9a-f]{64}"/);
    const notifications = fs.readFileSync(path.join(dir, "service", "notifications.ndjson"), "utf8");
    expect(notifications).to.contain('"kind":"ouverture"');
    expect(notifications).to.not.contain("CH9300762011623852957");
  });
});
