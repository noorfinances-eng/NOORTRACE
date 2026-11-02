// Côté démon de l'interface noyau ↔ service d'approbation (CT-2 §7.5,
// EX-9.4, EX-12.23) contre le service factice : réponses d'`evaluer`
// invalides (EX-7.16), remises refusées par SG-2, SG-3, SG-5, SG-6, SG-7
// (EX-7.5), remise pendant un mode dégradé (EX-7.19 pas 1), expiration par le
// noyau seul (EX-9.4), fichiers des approbations et ligne de contrôle du MAC
// (EX-12.23, EX-7.22), canal HTTP (EX-7.14).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, ErreurEnregistreur, validerConfiguration, validerReponseEvaluer, pieceJson, macRelais,
  ClientServiceApprobation, RAISON_EXPIRATION_NOYAU, ligneControleMac,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { CLE_MAC_HEX, configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

describe("enregistreur, cœur : interface du service d'approbation (§7.5)", function () {
  this.timeout(60000);
  let coeur;
  let service;
  let horloge;
  let config;
  const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null };

  async function retenue(montant) {
    const args = { claim_id: "2026-1", amount: montant, currency: "CHF" };
    const p = pieceJson(args);
    await coeur.ecrirePiece(p);
    const capture = { host: { id: "agent-sinistres-stdio" }, delegation, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: p.reference, context: [], intent: null, code: {} };
    const reponse = await coeur.evaluer({ tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", arguments: args, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [] });
    const r = await coeur.scellerRetenue(capture, reponse, args);
    await new Promise((x) => setTimeout(x, 20));
    return { ticket: reponse.ticket, evenement: r.evenement, args, capture };
  }

  beforeEach(async function () {
    const dir = repertoireTemporaire();
    ({ config } = configurationDev(dir));
    config = validerConfiguration(enc(config)).config;
    horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.000Z"));
    service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: () => ({ decision: "a_approuver", rule: "paiement > 5000 CHF" }) });
    coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service });
  });

  afterEach(async function () {
    await coeur.arreter();
  });

  it("réponse d'evaluer hors des combinaisons d'EX-7.16 : invalide, traitée comme une indisponibilité", async function () {
    const base = { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null };
    const ctx = { decisionScellee: () => null };
    expect(validerReponseEvaluer(base, ctx).valide).to.equal(true);
    expect(validerReponseEvaluer({ ...base, extra: 1 }, ctx).valide).to.equal(false);
    expect(validerReponseEvaluer({ ...base, decision: "a_approuver", rule: "r" }, ctx).valide).to.equal(false);
    expect(validerReponseEvaluer({ ...base, decision: "a_approuver", rule: null, ticket: "apr-1", ticket_state: "en_attente" }, ctx).raison).to.match(/rule nulle/);
    expect(validerReponseEvaluer({ ...base, decision: "autorise", ticket: "apr-1", ticket_state: "approuve", approval: null }, ctx).valide).to.equal(false);
    const jeuNonExploitable = { threshold: { required: 2, size: 3 }, members: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"], source: "jeu statique de la politique x" };
    expect(validerReponseEvaluer({ rule: "r", decision: "a_approuver", ticket: "apr-1", ticket_state: "nouveau", approval: null, approver_set: jeuNonExploitable }, ctx).raison).to.equal("approver_set non exploitable");
    service.evaluer = async () => ({ ...base, decision: "refuse", ticket: "apr-1", ticket_state: "refuse" });
    let err;
    try {
      await coeur.evaluer({});
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(ErreurEnregistreur);
    expect(err.raison).to.equal("approbation");
    expect(coeur.journal.trouver("approval_response_invalid")).to.have.length(1);
  });

  it("retenue : lignes `retenue` et MAC durables avant l'ajout au segment, `ouvrir` envoyé (EX-12.23, EX-7.18)", async function () {
    const r = await retenue("7400.00");
    expect(r.evenement.execution.status).to.equal("retenue");
    const dir = path.join(coeur.repertoire, "approbations");
    const a = fs.readFileSync(path.join(dir, "approbations-00000000000000000001.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(a[0]).to.deep.include({ kind: "retenue", ticket: r.ticket, request_seq: r.evenement.seq, request_hash: r.evenement.hash });
    const m = fs.readFileSync(path.join(dir, "mac-00000000000000000001.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const cle = new Uint8Array(Buffer.from(CLE_MAC_HEX, "hex"));
    expect(m[0]).to.deep.equal(ligneControleMac(cle));
    expect(m[1]).to.deep.equal({ ticket: r.ticket, request_hash: r.evenement.hash, mac: macRelais(cle, r.args) });
    const ouvrir = service.messages.find((x) => x.methode === "ouvrir").corps;
    expect(ouvrir.request_event).to.deep.equal(r.evenement);
    expect(Buffer.from(ouvrir.arguments_piece, "base64").toString("utf8")).to.equal(N.decoderUtf8(pieceJson(r.args).octets));
    // Seconde réponse `nouveau` pour le même ticket : pas de seconde retenue (EX-7.17).
    const d = await coeur.scellerRetenue(r.capture, { rule: "r", decision: "a_approuver", ticket: r.ticket, ticket_state: "nouveau", approval: null, approver_set: service.jeu }, r.args);
    expect(d.evenement).to.equal(null);
  });

  it("remises refusées : SG-2 (ticket inconnu), SG-5 (signature), SG-6 (seuil), SG-7 (auto-approbation), SG-3 (déjà décidé)", async function () {
    const r = await retenue("7400.00");
    const remise = service.decider_ticket(r.ticket);
    const essai = async (x) => (await coeur.traiterRemise(x)).reason;
    expect(await essai({ ...remise, ticket: "apr-inconnu", remise_id: "apr-inconnu/1", approval: { ...remise.approval, ticket: "apr-inconnu" } })).to.equal("ticket_inconnu");
    const sigs = [...remise.approval.signatures];
    sigs[0] = sigs[1];
    expect(await essai({ ...remise, approval: { ...remise.approval, signatures: sigs } })).to.equal("signature_invalide");
    const seul = service.decider_ticket(r.ticket, { signataires: [0] });
    expect(await essai(seul)).to.equal("seuil_non_atteint");
    // Le compte Hardhat 3 est l'adresse du demandeur agent-sinistres dans separation.identities (15.3).
    const auto = service.decider_ticket(r.ticket, { signataires: [0, 2] });
    expect(await essai(auto)).to.equal("auto_approbation");
    expect(coeur.metriques.valeur("noortrace_approval_remises_refused_total", { check: "SG-7" })).to.equal(1);
    const bonne = await coeur.traiterRemise(remise);
    expect(bonne.result).to.equal("scelle");
    expect(bonne.approval.at).to.equal(bonne.at);
    const deja = await coeur.traiterRemise(service.decider_ticket(r.ticket));
    expect(deja).to.deep.include({ result: "refuse", reason: "ticket_deja_decide", seq: bonne.seq, hash: bonne.hash });
    const lignes = fs.readFileSync(path.join(coeur.repertoire, "approbations", "approbations-00000000000000000001.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.filter((l) => l.kind === "remise")).to.have.length(6);
    expect(lignes.filter((l) => l.kind === "decision")).to.deep.equal([{ kind: "decision", ticket: r.ticket, seq: bonne.seq, hash: bonne.hash, approver_set: service.jeu }]);
  });

  it("remise pendant un mode dégradé : acquittée `temporaire`, rien n'est inscrit ni scellé (EX-7.19 pas 1)", async function () {
    const r = await retenue("7400.00");
    coeur.degrade.entrer("stockage");
    const x = await coeur.traiterRemise(service.decider_ticket(r.ticket));
    expect(x).to.deep.include({ result: "temporaire", reason: "mode_degrade" });
    expect(coeur.index.decisions.has(r.ticket)).to.equal(false);
    coeur.degrade.sortir("stockage");
  });

  it("expiration par le noyau seul à l'échéance plus timeout_ms (EX-9.4) ; annonce `expiration`", async function () {
    const r = await retenue("7400.00");
    horloge.aller(ms(r.evenement.ts) + 3600000);
    expect(await coeur.expirerTickets()).to.have.length(0);
    horloge.avancer(2001);
    const [d] = await coeur.expirerTickets();
    expect(d.approval).to.deep.equal({
      decision: "expire",
      ticket: r.ticket,
      request_hash: r.evenement.hash,
      threshold: service.jeu.threshold,
      approvers: [],
      signatures: [],
      at: d.ts,
      reason: RAISON_EXPIRATION_NOYAU,
    });
    await new Promise((x) => setTimeout(x, 20));
    expect(service.messages.find((m) => m.methode === "expiration").corps).to.deep.include({ ticket: r.ticket, seq: d.seq, hash: d.hash });
    // Ré-émission refusée par le refus scellé (EX-7.12).
    const reponse = await coeur.evaluer({ tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", arguments: r.args, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [] });
    expect(reponse.ticket_state).to.equal("expire");
    const refus = await coeur.scellerRefus(r.capture, reponse);
    expect(refus.execution.status).to.equal("refusee");
    expect(refus.policy).to.deep.equal(r.evenement.policy);
    expect(refus.approval).to.deep.equal(d.approval);
  });

  it("canal HTTP (EX-7.14) : messages POST /v0/<méthode>, réponse JSON stricte, erreurs de CT-3 §12.8", async function () {
    const serveur = await service.servir(0);
    try {
      const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${serveur.address().port}`, timeout_ms: 2000 });
      const r = await client.evaluer({ tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", arguments: { a: 1.5 }, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: "v", recorder: "0.1.0" }, context: [] });
      expect(r.ticket_state).to.equal("nouveau");
      let err;
      try {
        await client.ouvrir({ ticket: "apr-inconnu", request_hash: N.ZERO32, request_seq: 1, request_ts: "2026-11-10T10:00:00.000Z", request_event: {}, arguments_piece: null });
      } catch (e) {
        err = e;
      }
      expect(err.code).to.equal("ticket_inconnu");
      const injoignable = new ClientServiceApprobation({ url: "http://127.0.0.1:9", timeout_ms: 500 });
      let e2;
      try {
        await injoignable.charger({});
      } catch (e) {
        e2 = e;
      }
      expect(e2.code).to.equal("indisponible");
    } finally {
      serveur.close();
    }
  });
});
