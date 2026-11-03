// Moteur de politique du démon `noortrace` (INTERFACES.md, section d), écrit
// d'après le seul texte de CT-2 (EX-7.4, EX-7.14 à EX-7.23, EX-9.4,
// EX-12.23, §14.2 lignes « service d'approbation », §14.6, EX-15.4 pas 3 et
// 6, EX-15.8, EX-18.8, mode `erreur` et mode `retenir` de §4) et de CT-3
// (§11, §12, §7.6) : chaque exigence en réussite et en échec, chaque case de
// la matrice de 14.2 qui concerne le service d'approbation, entrées hostiles
// (service muet, réponse illisible, décision pour un ticket inconnu, remise
// rejouée, horloge qui recule). Banc : cœur et frontal MCP dans le
// processus, vrai serveur d'outils stdio, service d'approbation simulé
// d'après CT-3 §12 (test/fixtures/enregistreur-politique/outils.mjs).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { utf8 } from "@noortrace/noyau";
import {
  Coeur, ClientServiceApprobation, ErreurEnregistreur, controlePolitiqueApprobation, validerConfiguration, principal, regleObservation,
  REGLE_EVALUATION_IMPOSSIBLE, analyserJsonIntegral, pieceTexte,
} from "@noortrace/enregistreur";
import { secretsDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { ServiceSimule, monterBanc, attendre, texteSignal, configurationPolitique, politiqueApprobationTest } from "./fixtures/enregistreur-politique/outils.mjs";

const PAIEMENT = Object.freeze({ claim_id: "2026-81044", amount: "9000.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
const PAIEMENT_EUR = Object.freeze({ claim_id: "2026-81047", amount: "120.00", currency: "EUR", beneficiary_iban: "CH9300762011623852957" });
const LECTURE = Object.freeze({ claim_id: "2026-81044" });

const texte = (r) => r.result.content[0].text;
const etatSignal = (r) => r.result._meta["noortrace/approval"];
const erreur = (r) => r.error;

async function ticketOuvert(banc, ticket) {
  await attendre(() => banc.service.tickets.get(ticket)?.request);
}

/** Retenue en mode erreur : rend le ticket créé. */
async function retenir(banc, args = PAIEMENT) {
  const r = await banc.appeler("demo__payments.create", args);
  expect(texte(r)).to.match(/state=en_attente$/);
  const ticket = etatSignal(r).ticket;
  await ticketOuvert(banc, ticket);
  return ticket;
}

async function decider(banc, ticket, o = {}) {
  banc.service.decider_ticket(ticket, o);
  const acq = await banc.coeur.traiterRemises();
  return acq[acq.length - 1];
}

describe("enregistreur, moteur de politique : exigences (CT-2 §7.5, §14.2, §14.6 ; CT-3 §11, §12)", function () {
  this.timeout(60000);

  describe("pas 3 : evaluer, charger et matrice de 14.2 (service d'approbation)", function () {
    let banc;
    before(async function () {
      banc = await monterBanc();
    });
    after(async function () {
      await banc?.arreter();
    });

    it("EX-7.4 : evaluer porte exactement l'objet de ticket-v0, arguments en clair ; relais avec la règle rendue", async function () {
      const r = await banc.appeler("demo__claims.get", LECTURE);
      expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      const m = banc.service.messages.filter((x) => x.methode === "evaluer").at(-1).corps;
      expect(Object.keys(m).sort()).to.deep.equal(["arguments", "class", "code", "context", "delegation", "intent", "server_alias", "tool_announced", "tool_original"]);
      expect(m.arguments).to.deep.equal(LECTURE);
      expect(m).to.include({ tool_announced: "demo__claims.get", tool_original: "claims.get", server_alias: "demo", class: "lecture" });
      expect(m.code).to.deep.equal({ model: null, prompt_version: null, policy_version: "test-1", recorder: "0.1.0" });
      expect(m.context).to.have.length(2);
      const e = (await banc.evenements()).at(-1);
      expect(e.execution.status).to.equal("executee");
      expect(e.policy).to.deep.equal({ rule: "defaut : autorise", decision: "autorise", ticket: null, redaction: null });
    });

    it("EX-7.4, EX-5.21 : une intention portée par une référence est transmise par le texte de sa pièce ; au-delà de 4 096 caractères, null (intent_not_sent)", async function () {
      const courte = pieceTexte("Regler le sinistre 2026-81044 au beneficiaire [REDIGE:iban]", { redacted: true });
      const longue = pieceTexte("x".repeat(4097), { redacted: false });
      await banc.coeur.ecrirePiece(courte);
      await banc.coeur.ecrirePiece(longue);
      const moteur = banc.coeur.politique;
      expect(await moteur.intentionEvaluer("texte en ligne")).to.equal("texte en ligne");
      expect(await moteur.intentionEvaluer(null)).to.equal(null);
      expect(await moteur.intentionEvaluer(courte.reference)).to.equal("Regler le sinistre 2026-81044 au beneficiaire [REDIGE:iban]");
      expect(await moteur.intentionEvaluer(longue.reference)).to.equal(null);
      expect(await moteur.intentionEvaluer({ sha256: "0x" + "0".repeat(64), length: 3, redacted: true, media_type: "text/plain" })).to.equal(null);
      expect(banc.lignes("intent_not_sent").map((l) => l.data.reason)).to.deep.equal(["longueur", "piece_absente"]);
      // De bout en bout : la corrélation rend une référence ; evaluer reçoit le texte, l'événement la référence.
      banc.frontal.correlateur = { correler: () => ({ intent: courte.reference, code: { model: "demo/modele-test", prompt_version: null }, seq: 1 }) };
      try {
        const r = await banc.appeler("demo__claims.get", LECTURE);
        expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      } finally {
        banc.frontal.correlateur = null;
      }
      expect(banc.service.messages.filter((x) => x.methode === "evaluer").at(-1).corps.intent).to.equal("Regler le sinistre 2026-81044 au beneficiaire [REDIGE:iban]");
      expect((await banc.evenements()).at(-1).intent).to.deep.equal(courte.reference);
    });

    it("EX-7.15 : charger (outils triés, approval sans service, requesters fixes) ; liste des candidats consignée et appliquée (EX-7.4)", function () {
      const c = banc.service.messages.filter((x) => x.methode === "charger").at(-1).corps;
      expect(c.tools.map((t) => t.tool_announced)).to.deep.equal([...c.tools.map((t) => t.tool_announced)].sort());
      expect(c.tools.map((t) => t.tool_announced)).to.include("demo__payments.create");
      expect(c.approval).to.not.have.property("service");
      expect(c.approval.mode).to.equal("erreur");
      expect(c.requesters).to.deep.equal(["agent-demo"]);
      expect(c.environment).to.equal("developpement");
      expect(banc.lignes("approval_candidates").at(-1).data.candidates).to.deep.equal(["demo__payments.create"]);
      expect(banc.coeur.susceptible("demo__payments.create")).to.equal(true);
      expect(banc.coeur.susceptible("demo__claims.get")).to.equal(false);
      // Un nom absent de la liste du dernier charger réussi est susceptible (CT-3 4.12).
      expect(banc.coeur.susceptible("autre__outil")).to.equal(true);
    });

    it("14.2, service indisponible, colonne E : une écriture est bloquée (-31010, approbation), sans pièce d'événement ni intention", async function () {
      const avant = (await banc.evenements()).length;
      banc.service.panne = "non_pret";
      try {
        const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "100.00" });
        expect(erreur(r)).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "approbation" } });
      } finally {
        banc.service.panne = null;
      }
      expect((await banc.evenements()).length).to.equal(avant);
      expect(banc.lignes("approval_service_unavailable").at(-1).data.code).to.equal("non_pret");
      expect(banc.lignes("call_blocked").at(-1).data).to.include({ code: -31010, reason: "approbation" });
    });

    it("14.2, colonne L : une lecture non susceptible passe si failure.approval_service.lecture vaut passant (autorise, rule null, défaut consigné)", async function () {
      banc.service.panne = "non_pret";
      try {
        const r = await banc.appeler("demo__claims.get", LECTURE);
        expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      } finally {
        banc.service.panne = null;
      }
      const e = (await banc.evenements()).at(-1);
      expect(e.policy).to.deep.equal({ rule: null, decision: "autorise", ticket: null, redaction: null });
      expect(banc.lignes("approval_default_applied").at(-1).data).to.include({ tool_announced: "demo__claims.get" });
    });

    it("EX-7.4 : sans réponse dans policy.approval.timeout_ms (service muet), indisponibilité : -31010 en moins de 3 s", async function () {
      banc.service.muet = ["evaluer"];
      const t0 = Date.now();
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.service.muet = false;
      }
      expect(Date.now() - t0).to.be.below(3000);
    });

    it("EX-7.16 : réponse hors des combinaisons (membre manquant, ticket incohérent, rule nulle, jeu absent ou inexploitable, approval non scellé) : -31010, approval_response_invalid", async function () {
      const jeu = banc.service.jeu;
      const cas = [
        { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null },
        { rule: null, decision: "autorise", ticket: "apr-x", ticket_state: null, approval: null, approver_set: null },
        { rule: null, decision: "a_approuver", ticket: "apr-x", ticket_state: "nouveau", approval: null, approver_set: jeu },
        { rule: "r", decision: "a_approuver", ticket: "apr-x", ticket_state: "nouveau", approval: null, approver_set: null },
        { rule: "r", decision: "a_approuver", ticket: "apr-x", ticket_state: "nouveau", approval: null, approver_set: { ...jeu, threshold: { required: 2, size: 4 } } },
        { rule: "r", decision: "autorise", ticket: "apr-x", ticket_state: "approuve", approval: { decision: "approuve", ticket: "apr-x" }, approver_set: null },
        { rule: null, decision: "inconnue", ticket: null, ticket_state: null, approval: null, approver_set: null },
      ];
      const avant = banc.lignes("approval_response_invalid").length;
      try {
        for (const c of cas) {
          banc.service.reponseForcee = () => c;
          const r = await banc.appeler("demo__payments.create", PAIEMENT);
          expect(erreur(r)?.data, JSON.stringify(c)).to.deep.equal({ reason: "approbation" });
        }
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_response_invalid").length - avant).to.equal(cas.length);
    });

    it("CT-3 12.8 : politique_inconnue donne un charger puis un seul nouvel essai d'evaluer (réussite) ; deux refus de suite : indisponibilité", async function () {
      banc.service.versions.clear();
      const n = (m) => banc.service.messages.filter((x) => x.methode === m).length;
      const [c0, e0] = [n("charger"), n("evaluer")];
      const r = await banc.appeler("demo__claims.get", LECTURE);
      expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      expect([n("charger") - c0, n("evaluer") - e0]).to.deep.equal([1, 2]);
      // Le service perd encore la version : second refus, écriture bloquée.
      const evaluer = banc.service.evaluer.bind(banc.service);
      banc.service.evaluer = async (x) => {
        banc.service.versions.clear();
        return evaluer(x);
      };
      try {
        const r2 = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r2).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.service.evaluer = evaluer;
      }
    });
  });

  describe("14.2 : lectures susceptibles, lectures bloquantes, avant le premier charger", function () {
    it("failure.approval_service.lecture bloquant : une lecture non susceptible est bloquée pendant l'indisponibilité", async function () {
      const banc = await monterBanc({ lectureService: "bloquant" });
      try {
        banc.service.panne = "non_pret";
        const r = await banc.appeler("demo__claims.get", LECTURE);
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        await banc.arreter();
      }
    });

    it("une lecture candidate du dernier charger (une règle peut la refuser) est bloquante ; avant le premier charger réussi, tout outil l'est", async function () {
      const service = new ServiceSimule({
        org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
        journal_id: "0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1",
        decider: (r) => (r.tool_announced === "demo__claims.search" ? { decision: "refuse", rule: "recherche interdite" } : { decision: "autorise", rule: "defaut : autorise" }),
      });
      service.muet = ["charger", "evaluer"];
      const banc = await monterBanc({ service });
      try {
        expect(banc.coeur.candidats).to.equal(null);
        const r = await banc.appeler("demo__claims.get", LECTURE);
        expect(erreur(r).data, "avant charger").to.deep.equal({ reason: "approbation" });
        service.muet = false;
        banc.coeur.definirOutils(banc.coeur.outils);
        await attendre(() => banc.coeur.candidats !== null);
        expect(banc.coeur.susceptible("demo__claims.search")).to.equal(true);
        service.panne = "non_pret";
        expect(erreur(await banc.appeler("demo__claims.search", { query: "x" })).data).to.deep.equal({ reason: "approbation" });
        expect(texte(await banc.appeler("demo__claims.get", LECTURE))).to.equal("Sinistre 2026-81044 : ouvert");
      } finally {
        await banc.arreter();
      }
    });
  });

  describe("EX-7.14, EX-18.8 : canal HTTP authentifié par jeton porteur", function () {
    let banc;
    let service;
    before(async function () {
      service = new ServiceSimule({ org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", journal_id: "0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1", jeton: "jeton-du-noyau" });
      const s = await service.servirHttp();
      const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${s.address().port}`, jeton: "jeton-du-noyau", timeout_ms: 500 });
      banc = await monterBanc({ service: client });
      banc.simule = service;
      banc.client = client;
    });
    after(async function () {
      await banc?.arreter();
      service.serveurHttp.close();
    });

    it("POST /v0/<méthode> avec Authorization: Bearer ; relais d'une lecture autorisée", async function () {
      const r = await banc.appeler("demo__claims.get", LECTURE);
      expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      expect(service.entetes.authorization).to.equal("Bearer jeton-du-noyau");
      expect(service.messages.map((m) => m.methode)).to.include.members(["charger", "evaluer"]);
    });

    it("réponse illisible (entrée hostile) : erreur du service, -31010 pour une écriture", async function () {
      service.illisible = true;
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        service.illisible = false;
      }
      expect(banc.lignes("approval_service_unavailable").at(-1).data.code).to.equal("reponse_illisible");
    });

    it("jeton refusé par le service : indisponibilité, jamais un relais", async function () {
      banc.client.jeton = "mauvais-jeton";
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.client.jeton = "jeton-du-noyau";
      }
    });
  });

  describe("pas 5 et 6, mode erreur (EX-4.49, EX-7.12, EX-7.17 à EX-7.22, EX-12.23, CT-3 EX-11.3)", function () {
    let banc;
    let ticket;
    before(async function () {
      banc = await monterBanc();
    });
    after(async function () {
      await banc?.arreter();
    });

    it("refus par la politique sans ticket : événement refusee (decision refuse, rule rendue), résultat isError de texte fixe", async function () {
      const r = await banc.appeler("demo__payments.create", PAIEMENT_EUR);
      expect(r.result).to.deep.equal({
        resultType: "complete",
        content: [{ type: "text", text: "noortrace: appel refuse par la politique" }],
        isError: true,
        _meta: { "io.modelcontextprotocol/serverInfo": { name: "noortrace-enregistreur", version: "0.1.0" } },
      });
      const e = (await banc.evenements()).at(-1);
      expect(e.execution.status).to.equal("refusee");
      expect(e.policy).to.include({ rule: "paiement hors CHF", decision: "refuse", ticket: null });
      expect(e.approval).to.equal(null);
    });

    it("ticket nouveau : retenue durable, lignes retenue et MAC (EX-12.23), ouvrir (EX-7.18), signal en_attente aussitôt", async function () {
      const n0 = (await banc.evenements()).length;
      ticket = await retenir(banc);
      const evts = await banc.evenements();
      expect(evts.length).to.equal(n0 + 1);
      const retenue = evts.at(-1);
      expect(retenue.execution.status).to.equal("retenue");
      expect(retenue.policy).to.include({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket });
      const lignes = banc.coeur.approbations.retenues.get(ticket);
      expect(lignes[0]).to.include({ kind: "retenue", request_hash: retenue.hash, request_seq: retenue.seq });
      expect(banc.coeur.approbations.macs.get(retenue.hash)).to.match(/^0x[0-9a-f]{64}$/);
      const ouvrir = banc.service.messages.find((m) => m.methode === "ouvrir" && m.corps.ticket === ticket).corps;
      expect(ouvrir).to.include({ request_hash: retenue.hash, request_seq: retenue.seq, request_ts: retenue.ts });
      expect(ouvrir.request_event).to.deep.equal(retenue);
      expect(Buffer.from(ouvrir.arguments_piece, "base64").toString("utf8")).to.contain("[REDIGE:iban]");
    });

    it("ré-émission en attente : aucun événement, approval_pending, signal en_attente (CT-3 EX-7.19)", async function () {
      const n0 = (await banc.evenements()).length;
      const r = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "en_attente" });
      expect(texte(r)).to.equal(texteSignal(ticket, "en_attente"));
      expect((await banc.evenements()).length).to.equal(n0);
      expect(banc.lignes("approval_pending").length).to.be.greaterThan(0);
    });

    it("EX-7.17 : une seconde réponse nouveau pour une retenue durable ne scelle rien, renvoie ouvrir et rend en_attente", async function () {
      const n0 = (await banc.evenements()).length;
      const o0 = banc.service.messages.filter((m) => m.methode === "ouvrir").length;
      banc.service.reponseForcee = () => ({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket, ticket_state: "nouveau", approval: null, approver_set: banc.service.jeu });
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(etatSignal(r)).to.deep.equal({ ticket, state: "en_attente" });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).length).to.equal(n0);
      await attendre(() => banc.service.messages.filter((m) => m.methode === "ouvrir").length > o0);
    });

    it("décision approuve scellée (SG-1 à SG-7) ; ré-émission relayée avec la policy de la retenue et l'approval scellé (EX-7.12) ; consommer (EX-7.20)", async function () {
      const acq = await decider(banc, ticket, { reason: "Constat et facture concordants" });
      expect(acq).to.include({ result: "scelle", decision: "approuve", held: false });
      const evts = await banc.evenements();
      const decision = evts.at(-1);
      expect(decision.execution.tool).to.equal("noortrace.approbation.decision");
      expect(banc.coeur.approbations.decisions.get(ticket)).to.include({ seq: decision.seq, hash: decision.hash });
      const retenue = evts.find((e) => e.execution.status === "retenue" && e.policy.ticket === ticket);
      const r = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(r.result.structuredContent.payment_id).to.match(/^PAY-2026-/);
      const relaye = (await banc.evenements()).at(-1);
      expect(relaye.execution.status).to.equal("executee");
      expect(relaye.policy).to.deep.equal(retenue.policy);
      expect(relaye.approval).to.deep.equal(decision.approval);
      expect(relaye.effects).to.deep.equal([{ system: "demo", action: "ecriture", object: relaye.effects[0].object, amount: "9000.00", currency: "CHF" }]);
      await attendre(() => banc.service.messages.some((m) => m.methode === "consommer" && m.corps.ticket === ticket));
      const c = banc.service.messages.find((m) => m.methode === "consommer").corps;
      expect(c).to.deep.equal({ ticket, seq: relaye.seq, hash: relaye.hash });
    });

    it("RL-3 : un service compromis qui sert de nouveau l'approbation consommée : -31010 approbation, approval_relay_refused, aucune intention", async function () {
      const decision = banc.coeur.index.decisions.get(ticket);
      banc.service.reponseForcee = () => ({ rule: "paiement > 5000 CHF", decision: "autorise", ticket, ticket_state: "approuve", approval: decision.approval, approver_set: null });
      try {
        const r = await banc.appeler("demo__payments.create", PAIEMENT);
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_relay_refused").at(-1).data.check).to.equal("RL-3");
    });

    it("RL-2 : l'approbation d'un ticket pour d'autres arguments est refusée (blanchiment, CT-3 14.5)", async function () {
      const t2 = await retenir(banc, { ...PAIEMENT, amount: "9100.00" });
      await decider(banc, t2);
      const d = banc.coeur.index.decisions.get(t2);
      banc.service.reponseForcee = () => ({ rule: "paiement > 5000 CHF", decision: "autorise", ticket: t2, ticket_state: "approuve", approval: d.approval, approver_set: null });
      try {
        const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "99000.00" });
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect(banc.lignes("approval_relay_refused").at(-1).data.check).to.equal("RL-2");
    });

    it("RL-4 : une approbation dont le délai de reconnaissance finit avant le délai de l'outil est refusée", async function () {
      const t3 = await retenir(banc, { ...PAIEMENT, amount: "9200.00" });
      await decider(banc, t3);
      banc.horloge.avancer(banc.config.policy.approval.expire_after_ms - 3000);
      const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "9200.00" });
      expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      expect(banc.lignes("approval_relay_refused").at(-1).data.check).to.equal("RL-4");
    });

    it("EX-7.17 : la retenue d'un ticket déjà décidé n'est pas scellée : -31010, identifiant_en_collision", async function () {
      const n0 = (await banc.evenements()).length;
      banc.service.reponseForcee = () => ({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket, ticket_state: "nouveau", approval: null, approver_set: banc.service.jeu });
      try {
        const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "9300.00" });
        expect(erreur(r).data).to.deep.equal({ reason: "approbation" });
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).length).to.equal(n0);
      expect(banc.lignes("identifiant_en_collision").length).to.equal(1);
    });

    it("ticket décidé refuse : la ré-émission scelle un refusee qui reprend la policy de la retenue et porte l'approval scellé, signal refuse", async function () {
      const t4 = await retenir(banc, { ...PAIEMENT, amount: "9400.00" });
      const acq = await decider(banc, t4, { decision: "refuse", reason: "Facture absente" });
      expect(acq).to.include({ result: "scelle", decision: "refuse" });
      const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "9400.00" });
      expect(etatSignal(r)).to.deep.equal({ ticket: t4, state: "refuse" });
      const evts = await banc.evenements();
      const refus = evts.at(-1);
      const retenue = evts.find((e) => e.execution.status === "retenue" && e.policy.ticket === t4);
      expect(refus.execution.status).to.equal("refusee");
      expect(refus.policy).to.deep.equal(retenue.policy);
      expect(refus.approval).to.deep.equal(banc.coeur.index.decisions.get(t4).approval);
    });
  });

  describe("mode retenir (EX-4.50, CT-3 EX-11.2 à EX-11.6)", function () {
    let banc;
    before(async function () {
      banc = await monterBanc({ mode: "retenir", hold_timeout_ms: 1500 });
    });
    after(async function () {
      await banc?.arreter();
    });

    it("la requête qui crée le ticket est retenue ; une autre ré-émission reçoit aussitôt en_attente ; décision approuve : held:true, relais de la requête retenue", async function () {
      const a = banc.lancer("demo__payments.create", PAIEMENT);
      const ticket = await attendre(() => [...banc.frontal.retentions.keys()][0]);
      await ticketOuvert(banc, ticket);
      const b = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(etatSignal(b)).to.deep.equal({ ticket, state: "en_attente" });
      const acq = await decider(banc, ticket);
      expect(acq).to.include({ result: "scelle", held: true });
      const r = await a.reponse;
      expect(r.result.structuredContent.payment_id).to.match(/^PAY-2026-/);
      const e = (await banc.evenements()).at(-1);
      expect(e.execution.status).to.equal("executee");
      expect(e.approval.ticket).to.equal(ticket);
      // CT-3 EX-11.4 : le service sert l'approbation à la requête retenue ; une ré-émission attend.
      expect(etatSignal(await banc.appeler("demo__payments.create", PAIEMENT)).state).to.equal("en_attente");
      await attendre(() => banc.service.messages.some((m) => m.methode === "consommer" && m.corps.ticket === ticket));
    });

    it("à hold_timeout_ms, signal en_attente et le ticket continue ; la première ré-émission qui suit est retenue ; refuse : refusee et signal refuse", async function () {
      const args = { ...PAIEMENT, amount: "7700.00" };
      const t0 = Date.now();
      const a = banc.lancer("demo__payments.create", args);
      const ticket = await attendre(() => [...banc.frontal.retentions.keys()][0]);
      const ra = await a.reponse;
      expect(Date.now() - t0).to.be.at.least(1400);
      expect(etatSignal(ra)).to.deep.equal({ ticket, state: "en_attente" });
      const b = banc.lancer("demo__payments.create", args);
      await attendre(() => banc.frontal.retentions.has(ticket));
      await ticketOuvert(banc, ticket);
      const acq = await decider(banc, ticket, { decision: "refuse", reason: "Montant conteste" });
      // held : « vrai si et seulement si le noyau retient une requête de ce ticket et va la
      // relayer » (CT-2 EX-7.19 pas 3) ; une décision refuse n'est jamais relayée (relecture C).
      expect(acq).to.include({ result: "scelle", decision: "refuse", held: false });
      const rb = await b.reponse;
      expect(etatSignal(rb)).to.deep.equal({ ticket, state: "refuse" });
      const e = (await banc.evenements()).at(-1);
      expect(e.execution.status).to.equal("refusee");
      expect(e.approval.decision).to.equal("refuse");
    });

    it("annulation par l'hôte : la requête retenue prend fin sans réponse ; la ré-émission suivante est retenue (EX-4.50)", async function () {
      const args = { ...PAIEMENT, amount: "7800.00" };
      const a = banc.lancer("demo__payments.create", args, { id: "h-annule" });
      const ticket = await attendre(() => [...banc.frontal.retentions.keys()][0]);
      await banc.frontal.recevoir(banc.session, JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "h-annule" } }));
      expect(await a.reponse).to.equal(null);
      expect(banc.frontal.retentions.has(ticket)).to.equal(false);
      const b = banc.lancer("demo__payments.create", args);
      await attendre(() => banc.frontal.retentions.has(ticket));
      expect(banc.lignes("approval_hold_cancelled").length).to.equal(1);
      await ticketOuvert(banc, ticket);
      await decider(banc, ticket);
      expect((await b.reponse).result.isError).to.equal(false);
    });

    it("expiration par le noyau seul pendant la rétention (EX-9.4) : décision expire, refusee, signal expire, annonce expiration", async function () {
      const args = { ...PAIEMENT, amount: "7900.00" };
      const a = banc.lancer("demo__payments.create", args);
      const ticket = await attendre(() => [...banc.frontal.retentions.keys()][0]);
      await ticketOuvert(banc, ticket);
      banc.horloge.avancer(banc.config.policy.approval.expire_after_ms + banc.config.policy.approval.timeout_ms + 10);
      // Un ticket ouvert par une ré-émission après consommation (CT-3 11.3) expire aussi.
      const scellees = (await banc.coeur.expirerTickets()).filter((e) => e.approval.ticket === ticket);
      expect(scellees.map((e) => e.approval.decision)).to.deep.equal(["expire"]);
      expect(scellees[0].approval).to.include({ reason: "expire par l'enregistreur, service d'approbation sans reponse" });
      expect(scellees[0].approval.approvers).to.deep.equal([]);
      const r = await a.reponse;
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "expire" });
      expect((await banc.evenements()).at(-1).execution.status).to.equal("refusee");
      await attendre(() => banc.service.messages.some((m) => m.methode === "expiration" && m.corps.ticket === ticket));
    });
  });

  describe("boucle decisions (EX-7.19) et expirations au tic (EX-9.4), minuteurs du démon", function () {
    let banc;
    before(async function () {
      banc = await monterBanc({ minuteurs: true });
    });
    after(async function () {
      await banc?.arreter();
    });

    it("une remise est reçue par l'attente longue et scellée sans appel du test ; acquitter scelle", async function () {
      const ticket = await retenir(banc);
      banc.service.decider_ticket(ticket);
      await attendre(() => banc.coeur.index.decisions.get(ticket), 5000);
      const acq = banc.service.messages.filter((m) => m.methode === "acquitter").at(-1).corps;
      expect(acq).to.include({ ticket, result: "scelle", decision: "approuve" });
      // L'attente longue : decisions porte wait_ms = 25000 (au plus 25 000).
      expect(banc.service.messages.find((m) => m.methode === "decisions").corps).to.deep.equal({ wait_ms: 25000 });
    });

    it("à l'échéance plus timeout_ms, le tic scelle l'expiration par le noyau seul et l'annonce", async function () {
      const ticket = await retenir(banc, { ...PAIEMENT, amount: "8100.00" });
      banc.horloge.avancer(banc.config.policy.approval.expire_after_ms + banc.config.policy.approval.timeout_ms + 10);
      await attendre(() => banc.coeur.index.decisions.get(ticket), 5000);
      expect(banc.coeur.index.decisions.get(ticket).approval.decision).to.equal("expire");
      await attendre(() => banc.service.messages.some((m) => m.methode === "expiration" && m.corps.ticket === ticket));
      const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "8100.00" });
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "expire" });
    });

    it("service muet sur decisions (entrée hostile) : indisponibilité consignée une fois, la boucle reprend", async function () {
      // Attente longue réduite à 300 ms pour le test (délai de decisions : wait_ms + timeout_ms).
      banc.coeur.politique.arreter();
      banc.service.muet = ["decisions"];
      banc.service.liberer();
      banc.coeur.politique.demarrerBoucle({ wait_ms: 300 });
      await attendre(() => banc.lignes("approval_service_unavailable").some((l) => l.data.message === "decisions"), 5000);
      banc.service.muet = false;
      await attendre(() => banc.lignes("approval_service_available").length > 0, 15000);
      expect(banc.lignes("approval_service_unavailable").filter((l) => l.data.message === "decisions").length).to.equal(1);
    });
  });

  describe("mode dégradé et entrées hostiles (14.2, EX-7.5, EX-7.19, EX-9.4)", function () {
    let banc;
    before(async function () {
      banc = await monterBanc();
    });
    after(async function () {
      await banc?.arreter();
    });

    it("décision remise pendant un mode dégradé : acquitter temporaire, rien n'est inscrit ; ré-émission en_attente ; scellée à la représentation, après la sortie", async function () {
      const ticket = await retenir(banc);
      const sante = banc.coeur.signataire.sante.bind(banc.coeur.signataire);
      banc.coeur.signataire.sante = async () => "erreur";
      banc.coeur.degrade.entrer("cle");
      const remise = banc.service.decider_ticket(ticket);
      const acq = await banc.coeur.traiterRemises();
      expect(acq[0]).to.include({ result: "temporaire", reason: "mode_degrade" });
      expect(banc.coeur.approbations.remises.get(ticket)).to.equal(undefined);
      const r = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "en_attente" });
      banc.coeur.signataire.sante = sante;
      await banc.coeur.tic();
      expect(banc.coeur.degrade.enModeDegrade).to.equal(false);
      // Le service re-présente la remise acquittée temporaire (CT-3 T12), même remise_id.
      banc.service.delaiRepresentation = 0;
      const acq2 = await banc.coeur.traiterRemises();
      banc.service.delaiRepresentation = 2000;
      expect(acq2[0]).to.include({ result: "scelle", remise_id: remise.remise_id });
    });

    it("expiration atteinte pendant un mode dégradé : différée (approval_expired_deferred), scellée à la sortie ; ré-émission : signal expire", async function () {
      const args = { ...PAIEMENT, amount: "8200.00" };
      const ticket = await retenir(banc, args);
      const sante = banc.coeur.signataire.sante.bind(banc.coeur.signataire);
      banc.coeur.signataire.sante = async () => "erreur";
      banc.coeur.degrade.entrer("cle");
      banc.horloge.avancer(banc.config.policy.approval.expire_after_ms + banc.config.policy.approval.timeout_ms + 10);
      await banc.coeur.tic();
      expect(banc.coeur.index.decisions.get(ticket)).to.equal(undefined);
      expect(banc.lignes("approval_expired_deferred").map((l) => l.seq)).to.include(banc.coeur.index.retenueSansDecision(ticket).seq);
      banc.coeur.signataire.sante = sante;
      await banc.coeur.tic();
      expect(banc.coeur.index.decisions.get(ticket).approval.decision).to.equal("expire");
      const r = await banc.appeler("demo__payments.create", args);
      expect(etatSignal(r)).to.deep.equal({ ticket, state: "expire" });
    });

    it("décision pour un ticket inconnu (SG-2) et remise rejouée (SG-3, avec la décision scellée) : refusées, rien n'est scellé", async function () {
      const ticket = await retenir(banc, { ...PAIEMENT, amount: "8300.00" });
      const remise = banc.service.decider_ticket(ticket);
      banc.service.fileRemises.length = 0;
      const inconnu = JSON.parse(JSON.stringify(remise));
      inconnu.ticket = "apr-inconnu-1";
      inconnu.remise_id = "apr-inconnu-1/1";
      inconnu.approval.ticket = "apr-inconnu-1";
      const n0 = (await banc.evenements()).length;
      const a1 = await banc.coeur.traiterRemise(inconnu);
      expect(a1).to.include({ result: "refuse", reason: "ticket_inconnu" });
      expect((await banc.evenements()).length).to.equal(n0);
      expect((await banc.coeur.traiterRemise(remise)).result).to.equal("scelle");
      const d = banc.coeur.index.decisions.get(ticket);
      const a2 = await banc.coeur.traiterRemise(remise);
      expect(a2).to.include({ result: "refuse", reason: "ticket_deja_decide", seq: d.seq, hash: d.hash, at: d.approval.at, decision: "approuve" });
      expect(a2.approval).to.deep.equal(d.approval);
      expect((await banc.evenements()).length).to.equal(n0 + 1);
      expect(banc.lignes("approval_remise_refused").map((l) => l.data.check)).to.deep.equal(["SG-2", "SG-3"]);
    });

    it("horloge qui recule au-delà du seuil (entrée hostile) : -31010 horloge, remise acquittée temporaire ; sortie au tic quand l'horloge a rejoint le ts précédent (EX-7.9, EX-14.11)", async function () {
      const ticket = await retenir(banc, { ...PAIEMENT, amount: "8400.00" });
      banc.horloge.reculerMurale(60000);
      const r = await banc.appeler("demo__payments.create", PAIEMENT_EUR);
      expect(erreur(r).data).to.deep.equal({ reason: "horloge" });
      expect(banc.coeur.degrade.actif("horloge")).to.equal(true);
      banc.service.decider_ticket(ticket);
      const acq = await banc.coeur.traiterRemises();
      expect(acq[0]).to.include({ result: "temporaire", reason: "mode_degrade" });
      expect(erreur(await banc.appeler("demo__claims.get", LECTURE)).data).to.deep.equal({ reason: "horloge" });
      // Tant que l'horloge murale n'a pas rejoint le ts précédent, le mode reste.
      await banc.coeur.tic();
      expect(banc.coeur.degrade.actif("horloge")).to.equal(true);
      banc.horloge.avancer(60000);
      // Aucun appel ne peut sceller pendant le mode : la sortie est constatée au tic.
      await banc.coeur.tic();
      expect(banc.coeur.degrade.actif("horloge")).to.equal(false);
      expect(texte(await banc.appeler("demo__claims.get", LECTURE))).to.equal("Sinistre 2026-81044 : ouvert");
      // La remise acquittée temporaire est re-présentée et scellée.
      banc.service.delaiRepresentation = 0;
      const acq2 = await banc.coeur.traiterRemises();
      banc.service.delaiRepresentation = 2000;
      expect(acq2[0]).to.include({ result: "scelle", ticket });
    });

    it("saut en avant de l'horloge murale (EX-7.13) : bloquant ; sortie au tic quand elle revient dans la tolérance de l'avance monotone", async function () {
      expect(texte(await banc.appeler("demo__claims.get", LECTURE))).to.equal("Sinistre 2026-81044 : ouvert");
      banc.horloge.d += 10 * 60000;
      expect(erreur(await banc.appeler("demo__payments.create", PAIEMENT_EUR)).data).to.deep.equal({ reason: "horloge" });
      await banc.coeur.tic();
      expect(banc.coeur.degrade.actif("horloge")).to.equal(true);
      banc.horloge.d -= 10 * 60000;
      await banc.coeur.tic();
      expect(banc.coeur.degrade.actif("horloge")).to.equal(false);
      expect(texte(await banc.appeler("demo__claims.get", LECTURE))).to.equal("Sinistre 2026-81044 : ouvert");
    });
  });

  describe("mode observation (14.6, EX-4.51, EX-7.23, EX-14.13 à EX-14.17, EX-17.8)", function () {
    let banc;
    before(async function () {
      banc = await monterBanc({ mode: "observation", ajuster: (c) => (c.policy.failure.pending_max_events = 2) });
    });
    after(async function () {
      await banc?.arreter();
    });

    it("chaque appel est relayé avec la marque de ce que la politique aurait exigé ; aucun ticket, aucune retenue, aucun signal", async function () {
      expect(banc.coeur.metriques.valeur("noortrace_observation_mode", {})).to.equal(1);
      expect(texte(await banc.appeler("demo__claims.get", LECTURE))).to.equal("Sinistre 2026-81044 : ouvert");
      const a = await banc.appeler("demo__payments.create", PAIEMENT);
      expect(a.result.isError).to.equal(false);
      const b = await banc.appeler("demo__payments.create", PAIEMENT_EUR);
      expect(b.result.isError).to.equal(false);
      const evts = (await banc.evenements()).slice(-3);
      expect(evts.map((e) => e.policy.rule)).to.deep.equal([
        "defaut : autorise [observation autorise]",
        "paiement > 5000 CHF [observation a_approuver]",
        "paiement hors CHF [observation refuse]",
      ]);
      for (const e of evts) {
        expect(e.execution.status).to.equal("executee");
        expect(e.policy).to.include({ decision: "autorise", ticket: null });
        expect(e.approval).to.equal(null);
      }
      expect(banc.service.messages.some((m) => m.methode === "ouvrir")).to.equal(false);
      expect(banc.coeur.approbations.retenues.size).to.equal(0);
      const wb = banc.lignes("observation_would_block");
      expect(wb.map((l) => [l.component, l.data.would, l.data.reason, l.data.seq])).to.deep.equal([
        ["politique", "a_approuver", "approbation", evts[1].seq],
        ["politique", "refuse", "politique", evts[2].seq],
      ]);
      expect(banc.coeur.metriques.valeur("noortrace_observation_marks_total", { would: "a_approuver" })).to.equal(1);
      expect(banc.coeur.metriques.valeur("noortrace_observation_would_block_total", { reason: "politique" })).to.equal(1);
      // EX-14.14 : l'intention suit la classe de l'outil (écriture).
      expect(fs.readdirSync(path.join(banc.coeur.repertoire, "intentions")).length).to.be.greaterThan(0);
    });

    it("EX-14.15 : service indisponible, ou réponse invalide (EX-7.23) : evaluation impossible [observation inconnu], relayé sans nouvel essai", async function () {
      const rapport = [];
      banc.service.panne = "non_pret";
      try {
        await banc.appeler("demo__payments.create", PAIEMENT);
        rapport.push((await banc.evenements()).at(-1).policy.rule);
      } finally {
        banc.service.panne = null;
      }
      const invalides = [
        { rule: "x", decision: "a_approuver", ticket: "apr-1", ticket_state: "nouveau", approval: null, approver_set: banc.service.jeu },
        { rule: REGLE_EVALUATION_IMPOSSIBLE, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
        { rule: "regle [observation autorise]", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
        { rule: "r".repeat(999), decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null },
        { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
      ];
      const i0 = banc.lignes("approval_response_invalid").length;
      for (const c of invalides) {
        banc.service.reponseForcee = () => c;
        try {
          const r = await banc.appeler("demo__payments.create", PAIEMENT);
          expect(r.result.isError, JSON.stringify(c).slice(0, 80)).to.equal(false);
        } finally {
          banc.service.reponseForcee = null;
        }
        rapport.push((await banc.evenements()).at(-1).policy.rule);
      }
      expect(rapport).to.deep.equal(Array(6).fill(regleObservation(null, "inconnu")));
      expect(banc.lignes("approval_response_invalid").length - i0).to.equal(invalides.length);
      // 998 caractères : admis, marque de 26 caractères au plus sous 1 024.
      banc.service.reponseForcee = () => ({ rule: "r".repeat(998), decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null });
      try {
        await banc.appeler("demo__payments.create", PAIEMENT);
      } finally {
        banc.service.reponseForcee = null;
      }
      expect((await banc.evenements()).at(-1).policy.rule).to.equal(`${"r".repeat(998)} [observation a_approuver]`);
      // politique_inconnue : charger envoyé sans attendre, un seul evaluer.
      const n = (m) => banc.service.messages.filter((x) => x.methode === m).length;
      const e0 = n("evaluer");
      banc.service.versions.clear();
      await banc.appeler("demo__payments.create", PAIEMENT);
      expect(n("evaluer") - e0).to.equal(1);
      expect((await banc.evenements()).at(-1).policy.rule).to.equal("evaluation impossible [observation inconnu]");
      await attendre(() => banc.service.versions.size > 0);
    });

    it("EX-14.16 : stockage en mode dégradé, une écriture est relayée et son événement mis en attente (seq null), puis scellé à la sortie", async function () {
      const n0 = (await banc.evenements()).length;
      banc.coeur.degrade.entrer("stockage");
      const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "100.00" });
      expect(r.result.isError).to.equal(false);
      expect(banc.coeur.attente.length).to.equal(1);
      const l = banc.lignes("observation_would_block").at(-1);
      expect(l.data).to.include({ reason: "stockage", seq: null });
      // Le stockage répond de nouveau (sortie simulée : le segment n'a pas été fermé par une vraie panne).
      banc.coeur.degrade.sortir("stockage");
      await banc.coeur.tic();
      expect(banc.coeur.attente.length).to.equal(0);
      const evts = await banc.evenements();
      expect(evts.length).to.equal(n0 + 1);
      expect(evts.at(-1).policy.rule).to.equal("defaut : autorise [observation autorise]");
    });

    it("EX-14.16 : au-delà des bornes de 14.5, l'appel est encore relayé et l'événement perdu (event_lost, noortrace_events_lost_total)", async function () {
      banc.coeur.degrade.entrer("stockage");
      const reponses = [];
      for (const k of [1, 2, 3]) reponses.push(await banc.appeler("demo__claims.get", { claim_id: `2026-9000${k}` }));
      expect(reponses.map((r) => r.result.isError)).to.deep.equal([false, false, false]);
      expect(banc.coeur.metriques.valeur("noortrace_events_lost_total", { reason: "attente" })).to.equal(1);
      const perdu = banc.lignes("event_lost").at(-1);
      expect(perdu).to.include({ component: "noyau" });
      expect(perdu.data).to.include({ reason: "attente", count: 1 });
      // La borne atteinte ne bloque rien : une écriture passe encore, son événement est perdu.
      expect((await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "200.00" })).result.isError).to.equal(false);
      banc.coeur.degrade.sortir("stockage");
      await banc.coeur.tic();
      expect(banc.coeur.degrade.enModeDegrade).to.equal(false);
      expect(banc.coeur.attente.length).to.equal(0);
    });

    it("EX-14.16, EX-14.17 : un quota d'hôte ne bloque pas ; un outil inconnu reste refusé par -32602", async function () {
      // Requêtes en cours au-delà de max_concurrent (EX-4.47).
      const q = banc.frontal.quotas.get(banc.session.hote.id);
      q.enCours += 1000;
      try {
        const r = await banc.appeler("demo__claims.get", LECTURE);
        expect(texte(r)).to.equal("Sinistre 2026-81044 : ouvert");
      } finally {
        q.enCours -= 1000;
      }
      expect(banc.lignes("observation_would_block").some((l) => l.data.reason === "quota")).to.equal(true);
      const r = await banc.appeler("demo__inconnu", {});
      expect(erreur(r).code).to.equal(-32602);
    });
  });

  describe("EX-15.4 pas 3 et 6, EX-15.8 : validation, démarrage, rechargement", function () {
    it("validate-config : une politique d'approbation refusée (CT-3 EX-4.2) donne le code 2 et une ligne par erreur sous /policy/approval/rules", async function () {
      const dir = repertoireTemporaire("noortrace-politique-vc-");
      const { config } = configurationPolitique(dir);
      config.policy.approval.rules.rules.push({ ...config.policy.approval.rules.rules[0] });
      config.policy.approval.rules.rules[1].contest_ms = 60000;
      const f = path.join(dir, "configuration.json");
      fs.writeFileSync(f, JSON.stringify(config));
      let sortie = "";
      const code = await principal(["validate-config", f], { stdout: { write: (s) => (sortie += s) }, stderr: { write: () => {} } });
      expect(code).to.equal(2);
      expect(sortie).to.contain("erreur : /policy/approval/rules/rules/1/contest_ms : contest_ms_trop_long (CT-3 EX-4.2)");
      expect(sortie).to.contain("erreur : /policy/approval/rules/rules/2/name : nom_double (CT-3 EX-4.2)");
      // Le document conforme passe ; une règle fenetre à joker est signalée sans refus (EX-4.14).
      const { config: ok } = configurationPolitique(dir);
      ok.policy.approval.rules.rules.push({ name: "fenetre", description: null, tools: ["demo__*"], when: null, level: "fenetre", decision: null, window: { duration_ms: 1000, max_calls: 2, same_arguments: [] }, contest_ms: 0 });
      fs.writeFileSync(f, JSON.stringify(ok));
      sortie = "";
      expect(await principal(["validate-config", f], { stdout: { write: (s) => (sortie += s) }, stderr: { write: () => {} } })).to.equal(0);
      expect(sortie).to.contain("avertissement : /policy/approval/rules/rules/2/tools : fenetre_plusieurs_outils (CT-3 EX-4.14)");
      expect(sortie).to.contain("fenetre_sans_same_arguments");
    });

    it("un jeu statique est refusé en production (CT-3 EX-8.2) ; un demandeur fixe sans identité est signalé quand l'auto-approbation est interdite", function () {
      const dir = repertoireTemporaire("noortrace-politique-p-");
      const { config } = configurationPolitique(dir);
      config.recorder.environment = "production";
      const r = controlePolitiqueApprobation(config);
      expect(r.erreurs.map((e) => e.pointeur)).to.deep.equal(["/policy/approval/rules/approver_set/source"]);
      config.recorder.environment = "developpement";
      config.policy.approval.rules = politiqueApprobationTest({ self_approval: "interdite", identities: [] });
      const r2 = controlePolitiqueApprobation(config);
      expect(r2.erreurs).to.deep.equal([]);
      expect(r2.avertissements.map((a) => a.regle)).to.include("demandeur_sans_identite (CT-3 EX-4.14)");
      const v = validerConfiguration(utf8(JSON.stringify(config)), { reglesSupplementaires: [controlePolitiqueApprobation] });
      expect(v.erreurs).to.deep.equal([]);
    });

    it("EX-15.8 : entrée en observation refusée au rechargement tant qu'un ticket est ouvert (tickets_ouverts) ; admise après la décision", async function () {
      const banc = await monterBanc();
      try {
        const ticket = await retenir(banc);
        const obs = JSON.parse(JSON.stringify(banc.config));
        obs.policy.approval.mode = "observation";
        obs.policy.version = "test-2-observation";
        const octets = utf8(JSON.stringify(obs));
        const r1 = await banc.coeur.recharger(octets, { env: banc.env });
        expect(r1).to.include({ accepte: false, raison: "tickets_ouverts" });
        expect(banc.lignes("config_reload_rejected").at(-1).data.raison).to.equal("tickets_ouverts");
        await decider(banc, ticket);
        const r2 = await banc.coeur.recharger(octets, { env: banc.env });
        expect(r2.accepte).to.equal(true);
        expect(banc.coeur.politique.observation).to.equal(true);
        expect(banc.coeur.metriques.valeur("noortrace_observation_mode", {})).to.equal(1);
        // Appel sous la nouvelle version : marque d'observation, version annoncée.
        const r = await banc.appeler("demo__payments.create", { ...PAIEMENT, amount: "9900.00" });
        expect(r.result.isError).to.equal(false);
        const e = (await banc.evenements()).at(-1);
        expect(e.code.policy_version).to.equal("test-2-observation");
        expect(e.policy.rule).to.equal("paiement > 5000 CHF [observation a_approuver]");
      } finally {
        await banc.arreter();
      }
    });

    it("EX-15.8 au démarrage : erreur (code 2) avec un ticket ouvert ; EX-15.4 pas 6 : au redémarrage, charger, ouvrir pour le ticket sans décision", async function () {
      const banc = await monterBanc();
      const ticket = await retenir(banc);
      await banc.arreter();
      const obs = JSON.parse(JSON.stringify(banc.config));
      obs.policy.approval.mode = "observation";
      obs.policy.version = "test-2-observation";
      let refus = null;
      try {
        await Coeur.demarrer({ config: obs, secrets: secretsDev(), service: banc.service, horloge: banc.horloge });
      } catch (e) {
        refus = e;
      }
      expect(refus).to.be.instanceOf(ErreurEnregistreur);
      expect(refus.raison).to.equal("politique");
      expect(refus.code).to.equal(2);
      expect(refus.message).to.contain("tickets_ouverts");
      const o0 = banc.service.messages.filter((m) => m.methode === "ouvrir" && m.corps.ticket === ticket).length;
      const coeur = await Coeur.demarrer({ config: banc.config, secrets: secretsDev(), service: banc.service, horloge: banc.horloge });
      try {
        await attendre(() => banc.service.messages.filter((m) => m.methode === "ouvrir" && m.corps.ticket === ticket).length > o0);
        expect(banc.service.messages.filter((m) => m.methode === "charger").length).to.be.greaterThan(1);
      } finally {
        await coeur.arreter();
      }
      // La configuration reste analysable par le cœur (référence).
      expect(analyserJsonIntegral(utf8(JSON.stringify(obs))).policy.version).to.equal("test-2-observation");
    });
  });
});
