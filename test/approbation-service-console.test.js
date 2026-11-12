// Canal de la console du service d'approbation de la révision 0.5 (CT-3
// 12.9, EX-12.12 à EX-12.21 ; CT-9 TE-19, TI-14, TA-77) sur le service réel :
// chaque méthode de la table d'EX-12.13 et la forme de sa réponse, statuts
// HTTP de la rubrique e.2 des interfaces ; traces `annuaire/traces/*`
// rejouées par le canal (horloge et nonce imposés par l'essai, identifiants
// d'entrée tirés au hasard par le service et mis en correspondance) ; ordre
// des refus d'EX-12.14, d'EX-12.19 et d'EX-12.21 ; vue de `consulter`
// complète (effets évalués, `unresolved`, séparation, condensés) ; `tickets`
// avec `contest_ms`, `contest` et `related` ; méthodes du noyau refusées sur
// ce canal et réciproquement ; `GET /v0/etat` authentifié. TI-14 : canal réel
// joint par le client du démon de l'étape 4 (sept combinaisons d'`evaluer`
// jugées par la validation du démon, canal non authentifié refusé, mêmes
// sorties après un arrêt brutal). TA-77 : démon pointé vers un faux service
// sans authentification ; mutant du service sans authentification du canal,
// copié hors du dépôt et détruit après.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import * as N from "@noortrace/noyau";
import * as A from "@noortrace/approbation";
import { Coeur, HorlogeReglable, ClientServiceApprobation, validerConfiguration as validerConfigurationDemon, validerReponseEvaluer } from "@noortrace/enregistreur";
import {
  ANNUAIRE_REFERENCE, CONSTANTES, DEMANDEUR, RACINE, SESSIONS, VECTEURS_CT3, attendre, lancerService, messageCharger, politiqueParcours,
  OUTIL_LECTURE, OUTIL_PAIEMENT, OUTIL_SUPPRESSION, repertoireTemporaire, requeteEvaluer, retenue,
} from "./fixtures/approbation-service/outils.mjs";
import {
  adresseDe, appelHttp, configurationEtape6, etatHttp, horlogeReglable, serviceEtape6, signerVoteDerive, vecteur,
} from "./fixtures/approbation-service/etape6.mjs";
import { configurationDev, repertoireTemporaire as repertoireDemon, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const V1 = "parcours-1";
const E = 3600000;
const paiement = (montant, claim = "2026-90417") => ({ claim_id: claim, amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
const HORS_ORG = "oidc https://idp.assureur-demo.example inconnu-7";
const valide = (id, def, v) => A.registreSchemas().valider(`${id}#/$defs/${def}`, v);

/** Statut HTTP de chaque raison (rubrique e.2 des interfaces du service). */
const STATUT = {
  requete_invalide: 400, identite_invalide: 400, message_invalide: 400,
  session_non_autorisee: 403, non_administrateur: 403, auto_validation: 403, revocation_non_autorisee: 403,
  ticket_inconnu: 404, entree_inconnue: 404, adresse_inconnue: 404, nonce_inconnu: 404, demandeur_inconnu: 404,
  plafond_atteint: 429, non_pret: 503,
};
const statutDe = (code) => STATUT[code] ?? 409;

/** Outils du message `charger`, avec un gabarit d'effets pour le paiement (CT-2 EX-7.6). */
const GABARIT = [
  { system: "Comptabilite", action: "ecriture", object: "/arguments/claim_id", extract: null, amount: "/arguments/amount", currency: "/arguments/currency" },
  { system: "Comptabilite", action: "ecriture", object: "/result/document_id", extract: null, amount: "/arguments/amount", currency: "CHF" },
  { system: "Comptabilite", action: "envoi", object: "/arguments/absent", extract: null, amount: null, currency: null },
  { system: "Banque", action: "envoi", object: "/arguments/beneficiary_iban", extract: "^(CH[0-9]{2})", amount: null, currency: null },
];
function chargement() {
  const m = messageCharger({ policy_version: V1, rules: politiqueParcours() });
  m.tools = m.tools.map((t) => (t.tool_announced === OUTIL_PAIEMENT.tool_announced ? { ...t, effects: GABARIT } : t));
  return m;
}

/** Ouvre un ticket sur un service (evaluer, retenue, ouvrir) ; rend { ticket, ret, requete }. */
async function ouvrirSur(s, args, o = {}) {
  const requete = requeteEvaluer(o.outil ?? OUTIL_PAIEMENT.tool_announced, args, { launched_by: o.launched_by });
  const r = await s.client.evaluer(requete);
  expect(r.ticket_state, JSON.stringify(r)).to.equal("nouveau");
  s.seq = (s.seq ?? 3) + 2;
  const ret = retenue({ requete, rule: r.rule, ticket: r.ticket, seq: s.seq, ts: N.ecrireHorodatage(o.ts ?? s.h.t) });
  if (o.ouvrir !== false) await s.client.ouvrir(ret.ouvrir);
  return { ticket: r.ticket, ret, requete };
}

/** Vote du compte i sur un ticket, par sa session. */
const voter = (s, t, i, decision = "approuve", reason = null) => s.appel("voter", {
  ticket: t.ticket, approver: adresseDe(i), decision, signature: signerVoteDerive(i, { decision, ticket: t.ticket, request_hash: t.ret.evenement.hash }), reason, session_identity: SESSIONS[i],
});

/** Livre la remise courante d'un ticket et l'acquitte comme scellée à l'instant de l'horloge ; rend l'approval scellé. */
async function sceller(s, ticket) {
  const { remises } = await s.client.decisions({ wait_ms: 0 });
  const remise = remises.find((x) => x.ticket === ticket);
  expect(remise, `remise de ${ticket}`).to.not.equal(undefined);
  s.seq = (s.seq ?? 3) + 1;
  const approval = { ...remise.approval, at: N.ecrireHorodatage(s.h.t) };
  await s.client.acquitter({ remise_id: remise.remise_id, ticket, result: "scelle", reason: null, seq: s.seq, hash: N.sha256Hex(N.utf8(`decision ${ticket}`)), at: approval.at, decision: approval.decision, held: false, approval });
  return approval;
}

describe("service d'approbation : canal de la console (12.9)", function () {
  this.timeout(180000);

  describe("méthodes, vue et ordre des refus sur un service réel", function () {
    let s;
    let T; // ticket ouvert (paiement 7400 CHF, revue)
    let F; // ticket ouvrant (fenêtre de 1000 à 5000 CHF)
    let R; // ticket réservé, non ouvert
    before(async function () {
      s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, horloge: horlogeReglable("2026-11-10T11:00:00.000Z") });
      await s.client.charger(chargement());
      T = await ouvrirSur(s, paiement("7400.00"));
      F = await ouvrirSur(s, paiement("2500.00", "2026-90420"));
      R = await ouvrirSur(s, paiement("8800.00", "2026-90421"), { ouvrir: false });
      s.h.avancer(1000);
    });
    after(async function () {
      await s?.arreter();
    });

    it("méthodes du noyau refusées sur le canal de la console, méthodes de la console refusées sur le canal du noyau (requete_invalide, 400)", async function () {
      for (const m of A.METHODES_NOYAU) {
        const r = await s.appel(m, { wait_ms: 0 });
        expect([r.statut, r.corps.error.code], m).to.deep.equal([400, "requete_invalide"]);
      }
      for (const m of A.METHODES_CONSOLE) {
        const r = await appelHttp(s.inst.noyau, m, { session_identity: SESSIONS.admin }, s.cfg.jetonNoyau);
        expect([r.statut, r.corps.error.code], m).to.deep.equal([400, "requete_invalide"]);
      }
      // jeton du noyau sur le canal de la console : 401
      expect((await s.appel("tickets", { session_identity: SESSIONS.admin }, s.cfg.jetonNoyau)).statut).to.equal(401);
    });

    it("GET /v0/etat sur le canal de la console : authentifié, forme d'EX-12.12", async function () {
      expect((await etatHttp(s.inst.console)).statut).to.equal(401);
      const r = await etatHttp(s.inst.console, s.cfg.jetonConsole);
      expect(r).to.deep.equal({ statut: 200, corps: { ready: true, set_read_at: null, open_tickets: 3 } });
    });

    it("consulter : vue complète (EX-12.14, EX-12.15), conforme à vue_ticket", async function () {
      const r = await s.appel("consulter", { ticket: T.ticket, session_identity: SESSIONS[1] });
      expect(r.statut).to.equal(200);
      const v = r.corps;
      expect(valide(A.IDS.consoleApprobation, "vue_ticket", v).valide).to.equal(true);
      const t = s.service.machine.tickets.get(T.ticket);
      expect(v).to.deep.include({ version: 0, ticket: T.ticket, state: "ouvert", org_id: CONSTANTES.organization.org_id, journal_id: CONSTANTES.journal.journal_id, request_hash: T.ret.evenement.hash });
      expect(v.request).to.deep.equal({
        tool_announced: OUTIL_PAIEMENT.tool_announced, tool_original: OUTIL_PAIEMENT.tool_original, server_alias: OUTIL_PAIEMENT.server_alias, class: "ecriture", arguments: paiement("7400.00"),
        intent: "Régler un sinistre", delegation: T.requete.delegation, policy_version: V1,
      });
      expect(v.retained_event).to.deep.equal(T.ret.evenement);
      expect(v.arguments_piece).to.equal(T.ret.ouvrir.arguments_piece);
      expect(v.rule).to.deep.equal({ policy_rule: "paiement > 5000 CHF", name: "paiement > 5000 CHF", description: null, level: "revue", contest_ms: 0 });
      expect(v.opening).to.equal(null);
      expect(v.effects).to.deep.equal([
        { system: "Comptabilite", action: "ecriture", object: "2026-90417", amount: "7400.00", currency: "CHF", unresolved: [] },
        { system: "Comptabilite", action: "ecriture", object: null, amount: "7400.00", currency: "CHF", unresolved: [{ member: "object", pointer: "/result/document_id" }] },
        { system: "Banque", action: "envoi", object: "CH93", amount: null, currency: null, unresolved: [] },
      ]);
      expect(v.deadline).to.equal(N.ecrireHorodatage(Date.parse("2026-11-10T11:00:00.000Z") + E));
      expect(v.contest).to.deep.equal({ window_end: null, objections: [], last_threshold_at: null });
      expect(v.approver_set).to.deep.equal({ threshold: { required: 2, size: 3 }, members: [adresseDe(1), adresseDe(2), adresseDe(3)].sort(), source: `jeu statique de la politique ${V1}` });
      expect(v.effective_required).to.equal(2);
      expect(v.added_members).to.deep.equal([]);
      expect([...v.eligible].sort()).to.deep.equal([adresseDe(1), adresseDe(2)].sort());
      expect(v.eligible).to.deep.equal(t.eligible);
      expect(v.separation).to.deep.equal({ self_approval: "interdite", requester_declared: true, requester_addresses: [adresseDe(3)], requester_directory_addresses: [adresseDe(3)] });
      const D = (decision) => A.condenseA({ decision, ticket: T.ticket, request_hash: T.ret.evenement.hash, org_id: CONSTANTES.organization.org_id, journal_id: CONSTANTES.journal.journal_id });
      expect(v.digests).to.deep.equal({ approuve: D("approuve"), refuse: D("refuse") });
      // l'administrateur voit la même vue
      expect((await s.appel("consulter", { ticket: T.ticket, session_identity: SESSIONS.admin })).corps).to.deep.equal(v);
    });

    it("consulter : ticket ouvrant, `opening` de la portée (EX-5.4) ; votes courants sans signature", async function () {
      expect((await voter(s, F, 2, "refuse", "Bénéficiaire inconnu")).statut).to.equal(200);
      const v = (await s.appel("consulter", { ticket: F.ticket, session_identity: SESSIONS.admin })).corps;
      expect(v.opening).to.deep.equal({
        tool: OUTIL_PAIEMENT.tool_announced,
        when: politiqueParcours().rules[3].when,
        same_arguments: [{ pointer: "/arguments/beneficiary_iban", value: "CH9300762011623852957" }],
        max_calls: 2, duration_ms: 3600000,
      });
      expect(v.votes).to.deep.equal([{ approver: adresseDe(2), decision: "refuse", reason: "Bénéficiaire inconnu", at: "2026-11-10T11:00:01.000Z" }]);
      expect(valide(A.IDS.consoleApprobation, "vue_ticket", v).valide).to.equal(true);
    });

    it("ordre des refus de consulter (EX-12.14) : forme, identité, session hors de l'organisation, ticket inconnu, arguments non visibles, ticket_non_ouvert", async function () {
      const cas = [
        [{ ticket: T.ticket, session_identity: "u.martin@assureur-demo.example", x: 1 }, "requete_invalide"],
        [{ ticket: T.ticket, session_identity: "u.martin@assureur-demo.example" }, "identite_invalide"],
        [{ ticket: "apr-inconnu-1", session_identity: HORS_ORG }, "session_non_autorisee"],
        [{ ticket: T.ticket, session_identity: HORS_ORG }, "session_non_autorisee"],
        [{ ticket: "apr-inconnu-1", session_identity: SESSIONS[1] }, "ticket_inconnu"],
        [{ ticket: "apr-inconnu-1", session_identity: SESSIONS[3] }, "ticket_inconnu"],
        [{ ticket: T.ticket, session_identity: SESSIONS[3] }, "session_non_autorisee"],
        [{ ticket: R.ticket, session_identity: SESSIONS[3] }, "session_non_autorisee"],
        [{ ticket: R.ticket, session_identity: SESSIONS[1] }, "ticket_non_ouvert"],
        [{ ticket: R.ticket, session_identity: SESSIONS.admin }, "ticket_non_ouvert"],
      ];
      for (const [corps, code] of cas) {
        const r = await s.appel("consulter", corps);
        expect([r.statut, r.corps.error?.code], JSON.stringify(corps)).to.deep.equal([statutDe(code), code]);
      }
    });

    it("tickets (EX-12.14, EX-12.21) : liste de la session, contest_ms et contest ; related_to suit l'ordre de consulter puis ticket_non_ouvert", async function () {
      const l1 = (await s.appel("tickets", { session_identity: SESSIONS[1] })).corps;
      expect(valide(A.IDS.consoleService, "reponse_tickets", l1).valide).to.equal(true);
      expect(l1.tickets.map((x) => x.ticket)).to.deep.equal([T.ticket, F.ticket, R.ticket].sort());
      expect(l1).to.not.have.property("related");
      for (const x of l1.tickets) expect(x).to.have.all.keys("ticket", "state", "tool_announced", "launched_by", "deadline", "votes_approuve", "votes_refuse", "effective_required", "contest_ms", "contest");
      expect(l1.tickets.find((x) => x.ticket === R.ticket)).to.deep.include({ state: "reserve", deadline: null, effective_required: null, votes_approuve: 0, votes_refuse: 0 });
      // le demandeur, par son alias, voit ses tickets ; une session hors de l'organisation est refusée ; l'administrateur voit tout
      expect((await s.appel("tickets", { session_identity: SESSIONS[3] })).corps.tickets.map((x) => x.ticket)).to.deep.equal([T.ticket, F.ticket, R.ticket].sort());
      expect((await s.appel("tickets", { session_identity: SESSIONS.admin })).corps.tickets).to.have.length(3);
      const cas = [
        [{ session_identity: HORS_ORG }, "session_non_autorisee"],
        [{ session_identity: HORS_ORG, related_to: "apr-inconnu-1" }, "session_non_autorisee"],
        [{ session_identity: SESSIONS[1], related_to: "apr-inconnu-1" }, "ticket_inconnu"],
        [{ session_identity: SESSIONS[3], related_to: T.ticket }, "session_non_autorisee"],
        [{ session_identity: SESSIONS[1], related_to: R.ticket }, "ticket_non_ouvert"],
        [{ session_identity: "admin-1" }, "identite_invalide"],
        [{ session_identity: SESSIONS[1], related_to: "APR-1" }, "requete_invalide"],
      ];
      for (const [corps, code] of cas) {
        const r = await s.appel("tickets", corps);
        expect([r.statut, r.corps.error?.code], JSON.stringify(corps)).to.deep.equal([statutDe(code), code]);
      }
      const r = (await s.appel("tickets", { session_identity: SESSIONS[1], related_to: T.ticket })).corps;
      expect(r.related).to.deep.equal([]);
    });

    it("voter, recuser, retirer : contrôle du canal avant l'entrée (EX-12.16, EX-12.19), refus sans trace dans le ticket", async function () {
      const tk = () => s.service.machine.tickets.get(T.ticket).transitions.length;
      const avant = tk();
      const sig = signerVoteDerive(2, { decision: "approuve", ticket: T.ticket, request_hash: T.ret.evenement.hash });
      const cas = [
        ["voter", { ticket: "apr-inconnu-1", approver: adresseDe(2), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] }, "session_non_autorisee"],
        ["voter", { ticket: "apr-inconnu-1", approver: adresseDe(1), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] }, "ticket_inconnu"],
        ["voter", { ticket: T.ticket, approver: adresseDe(2), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] }, "session_non_autorisee"],
        ["voter", { kind: "voter", ticket: T.ticket, approver: adresseDe(2), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[2] }, "requete_invalide"],
        ["voter", { ticket: T.ticket, approver: adresseDe(4), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[2] }, "session_non_autorisee"],
        ["recuser", { ticket: T.ticket, approver: adresseDe(1), session_identity: SESSIONS[2] }, "session_non_autorisee"],
        ["retirer", { ticket: "apr-inconnu-1", by: DEMANDEUR, reason: null, session_identity: HORS_ORG }, "ticket_inconnu"],
        ["retirer", { ticket: T.ticket, by: DEMANDEUR, reason: null, session_identity: SESSIONS[1] }, "session_non_autorisee"],
        ["retirer", { ticket: T.ticket, by: SESSIONS[1], reason: null, session_identity: SESSIONS[1] }, "session_non_autorisee"],
        ["retirer", { ticket: T.ticket, by: DEMANDEUR, reason: null, session_identity: SESSIONS.admin }, "session_non_autorisee"],
        ["retirer", { ticket: T.ticket, by: DEMANDEUR, reason: null }, "requete_invalide"],
      ];
      for (const [m, corps, code] of cas) {
        const r = await s.appel(m, corps);
        expect([r.statut, r.corps.error?.code], `${m} ${JSON.stringify(corps)}`).to.deep.equal([statutDe(code), code]);
      }
      expect(tk(), "aucune trace des refus du canal").to.equal(avant);
      // raisons d'EX-9.10 : le refus de la machine est l'erreur de 12.8 (statut 409), inscrit dans la trace
      const r = await s.appel("voter", { ticket: R.ticket, approver: adresseDe(1), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] });
      expect([r.statut, r.corps.error.code]).to.deep.equal([409, "ticket_non_ouvert"]);
      const autreV = sig.endsWith("1b") ? "1c" : "1b";
      const faux = await s.appel("voter", { ticket: T.ticket, approver: adresseDe(2), decision: "approuve", signature: sig.slice(0, -2) + autreV, reason: null, session_identity: SESSIONS[2] });
      expect([faux.statut, faux.corps.error.code]).to.deep.equal([409, "signature_invalide"]);
    });

    it("chaque méthode acceptée rend la réponse de sa table (EX-12.13), statut 200", async function () {
      const ok = async (m, corps, def, id = A.IDS.consoleService) => {
        const r = await s.appel(m, corps);
        expect(r.statut, `${m} ${JSON.stringify(r.corps)}`).to.equal(200);
        expect(valide(id, def, r.corps).valide, `${m} → ${def}`).to.equal(true);
        return r.corps;
      };
      await ok("tickets", { session_identity: SESSIONS[2], related_to: T.ticket }, "reponse_tickets");
      await ok("consulter", { ticket: T.ticket, session_identity: SESSIONS[2] }, "vue_ticket", A.IDS.consoleApprobation);
      expect(await ok("voter", { ticket: T.ticket, approver: adresseDe(2), decision: "approuve", signature: signerVoteDerive(2, { decision: "approuve", ticket: T.ticket, request_hash: T.ret.evenement.hash }), reason: "Facture conforme", session_identity: SESSIONS[2] }, "reponse_voter", A.IDS.consoleApprobation)).to.deep.equal({ ticket: T.ticket, state: "ouvert" });
      expect(await ok("recuser", { ticket: F.ticket, approver: adresseDe(1), session_identity: SESSIONS[1] }, "reponse_etat")).to.deep.equal({ ticket: F.ticket, state: "ouvert" });
      expect(await ok("retirer", { ticket: F.ticket, by: DEMANDEUR, reason: "Demande annulée", session_identity: SESSIONS[3] }, "reponse_etat")).to.deep.equal({ ticket: F.ticket, state: "a_remettre" });
      const reduit = await ok("annuaire", { session_identity: SESSIONS[1] }, "reponse_annuaire");
      expect(reduit.entries.map((e) => e.id)).to.deep.equal(["apb-0001"]);
      expect((await ok("annuaire", { session_identity: HORS_ORG }, "reponse_annuaire")).entries).to.deep.equal([]);
      const id = "oidc https://idp.assureur-demo.example approbateur-9";
      const adr = "0x" + "c3".repeat(20);
      const p = await ok("preparer_inscription", { session_identity: id, address: adr }, "reponse_preparer_inscription");
      expect(p.fields.issued_at).to.equal(N.ecrireHorodatage(s.h.t));
      // l'inscription d'une adresse sans la clé est refusée (signature) ; celle du compte 4, révoqué ailleurs, aussi (adresse_deja_attribuee)
      const ins = await s.appel("inscrire", { session_identity: id, address: adr, message: p.message, signature: signerVoteDerive(1, { decision: "approuve", ticket: T.ticket, request_hash: T.ret.evenement.hash }) });
      expect([ins.statut, ins.corps.error.code]).to.deep.equal([409, "signature_invalide"]);
      expect(await ok("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0002", launched_by: "agent-2" }, "reponse_entree")).to.deep.include({ entry: "apb-0002", revision: 10 });
      expect(await ok("delier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0002", launched_by: "agent-2" }, "reponse_entree")).to.deep.include({ revision: 11 });
      expect(await ok("revoquer", { session_identity: SESSIONS[2], entry: "apb-0002", address: adresseDe(2), reason: "Clé perdue" }, "reponse_adresse")).to.deep.equal({ entry: "apb-0002", address: adresseDe(2), state: "revoquee", revision: 12 });
      expect(await ok("desactiver", { session_identity: SESSIONS.admin, entry: "apb-0002", reason: "Départ" }, "reponse_entree")).to.deep.include({ active: false, revision: 13 });
      expect(await ok("reactiver", { session_identity: SESSIONS.admin, entry: "apb-0002", reason: null }, "reponse_entree")).to.deep.include({ active: true, revision: 14 });
      // valider (EX-13.17) : refus dans l'ordre, puis acceptation sur une inscription en attente
      const v = await s.appel("valider", { session_identity: SESSIONS[1], entry: "apb-0003", address: adresseDe(3) });
      expect([v.statut, v.corps.error.code, v.corps.error.data]).to.deep.equal([403, "non_administrateur", { entry: "apb-0003" }]);
      const v2 = await s.appel("valider", { session_identity: SESSIONS.admin, entry: "apb-0003", address: adresseDe(3) });
      expect([v2.statut, v2.corps.error.code]).to.deep.equal([409, "etat_incompatible"]);
      // les opérations de l'annuaire ne touchent aucun ticket (EX-12.18)
      const vue = (await s.appel("consulter", { ticket: T.ticket, session_identity: SESSIONS.admin })).corps;
      expect(vue.eligible.sort()).to.deep.equal([adresseDe(1), adresseDe(2)].sort());
      expect(vue.votes.map((x) => x.approver).sort()).to.deep.equal([adresseDe(2)]);
      // l'adresse révoquée ne vote plus par le canal
      const r = await s.appel("voter", { ticket: T.ticket, approver: adresseDe(2), decision: "refuse", signature: signerVoteDerive(2, { decision: "refuse", ticket: T.ticket, request_hash: T.ret.evenement.hash }), reason: null, session_identity: SESSIONS[2] });
      expect([r.statut, r.corps.error.code]).to.deep.equal([403, "session_non_autorisee"]);
      // une opération refusée est consignée avec sa raison
      await s.service.supervision.vider();
      const j = fs.readFileSync(path.join(s.cfg.doc.state_dir, "journal-service.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      expect(j.filter((l) => l.type === "operation_annuaire_refusee").map((l) => [l.methode, l.reason])).to.deep.equal([
        ["inscrire", "signature_invalide"], ["valider", "non_administrateur"], ["valider", "etat_incompatible"],
      ]);
    });
  });

  describe("révision 0.6 : vue avant le gel, intention de la requête (EX-12.14, EX-7.24)", function () {
    it("avant le gel, eligible liste les membres du jeu de repli privés des adresses du demandeur sous interdite ; request.intent est celle d'evaluer, l'événement retenue portant l'intention par une référence", async function () {
      const { set1, registre } = { set1: CONSTANTES.sets["1"], registre: CONSTANTES.registry };
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, set_poll_interval_ms: 1000, appelRpc: async () => { throw new Error("hors ligne"); } });
      try {
        const lu = {
          status: "lu", cause: null,
          jeu: {
            chain_id: CONSTANTES.chain_id, registry: registre, set: set1, height: 1200, block_hash: N.sha256Hex(N.utf8("bloc/1200")),
            threshold: { required: 2, size: 3 }, members: [1, 2, 3].map(adresseDe).sort(),
          },
        };
        // le registre répond une fois (jeu de repli, ready), puis plus jamais : aucun gel
        let lectures = 0;
        s.service.lecteur = {
          async hauteur() { return 1200; },
          async changements() { return false; },
          async lire() {
            lectures += 1;
            if (lectures > 1) throw new Error("registre hors ligne");
            return JSON.parse(JSON.stringify(lu));
          },
        };
        const politique = politiqueParcours({ approver_set: { source: "registre", chain_id: CONSTANTES.chain_id, registry: registre, set: set1, members: null, threshold: null } });
        await s.client.charger(messageCharger({ policy_version: V1, rules: politique }));
        await attendre(() => s.service.etat().ready);
        const requete = { ...requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00")), intent: "Régler le sinistre 2026-90417 avant l'échéance" };
        const r = await s.client.evaluer(requete);
        const ret = retenue({ requete, rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(s.h.t), intentParReference: true });
        expect(ret.evenement.intent).to.not.be.a("string");
        await s.client.ouvrir(ret.ouvrir);
        const t = s.service.machine.tickets.get(r.ticket);
        expect(t.state).to.equal("ouvert");
        expect(t.approver_set, "ticket ouvert avant le gel").to.equal(null);
        const v = (await s.appel("consulter", { ticket: r.ticket, session_identity: SESSIONS.admin })).corps;
        expect(valide(A.IDS.consoleApprobation, "vue_ticket", v).valide, JSON.stringify(v).slice(0, 300)).to.equal(true);
        expect(v.approver_set).to.equal(null);
        // adresse 3 : celle du demandeur (separation.identities), exclue sous interdite
        expect(v.eligible).to.deep.equal([adresseDe(1), adresseDe(2)].sort());
        expect(v.request.intent).to.equal("Régler le sinistre 2026-90417 avant l'échéance");
        // l'approbateur 1, éligible avant le gel, voit le ticket
        expect((await s.appel("consulter", { ticket: r.ticket, session_identity: SESSIONS[1] })).statut).to.equal(200);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("révision 0.6 : bornes de l'annuaire sur le canal (EX-13.17, limite_annuaire)", function () {
    it("lier_demandeur : le 64e alias d'une entrée accepté, le 65e refusé (limite_annuaire, 409, data { entry }), annuaire inchangé, refus consigné", async function () {
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE });
      try {
        const lire = async () => (await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps;
        const entree = (await lire()).entries.find((e) => e.id === "apb-0002");
        for (let k = entree.requester_identities.length; k < 64; k++) {
          const r = await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0002", launched_by: `agent-borne-${k}` });
          expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
        }
        const avant = await lire();
        expect(avant.entries.find((e) => e.id === "apb-0002").requester_identities).to.have.length(64);
        const r = await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0002", launched_by: "agent-borne-64" });
        expect([r.statut, r.corps.error.code, r.corps.error.data]).to.deep.equal([409, "limite_annuaire", { entry: "apb-0002" }]);
        expect(await lire()).to.deep.equal(avant);
        expect(A.registreSchemas().valider(A.IDS.annuaire, avant).valide).to.equal(true);
        const j = fs.readFileSync(path.join(s.cfg.doc.state_dir, "journal-service.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
        expect(j.filter((l) => l.type === "operation_annuaire_refusee").map((l) => [l.methode, l.reason, l.entry])).to.deep.equal([["lier_demandeur", "limite_annuaire", "apb-0002"]]);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("traces annuaire/traces/* rejouées par le canal, nonce et horloge imposés", function () {
    const traces = fs.readdirSync(path.join(VECTEURS_CT3, "annuaire", "traces")).sort();
    for (const f of traces) {
      it(`trace ${f.replace(/\.json$/, "")} : sort, raison, statut, réponse, revision et entrées de chaque pas`, async function () {
        const tr = vecteur(`annuaire/traces/${f}`);
        const initial = path.join(VECTEURS_CT3, "annuaire", tr.initial);
        const doc0 = JSON.parse(fs.readFileSync(initial, "utf8"));
        const h = horlogeReglable(tr.steps[0].at);
        let nonce;
        const s = await serviceEtape6({
          annuaire: tr.initial === "annuaires/vide.json" ? null : initial, administrators: doc0.administrators, registration_ttl_ms: doc0.registration_ttl_ms,
          horloge: h, essais: { tirerNonce: () => nonce },
        });
        try {
          if (tr.initial === "annuaires/vide.json") expect((await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps).to.deep.equal(doc0);
          // identifiants des vecteurs (convention compteur, A.10) ↔ identifiants tirés par le service
          const versService = new Map(doc0.entries.map((e) => [e.id, e.id]));
          const versVecteur = new Map(doc0.entries.map((e) => [e.id, e.id]));
          const traduire = (o, m) => JSON.parse(JSON.stringify(o), (k, v) => (k === "entry" || k === "id") && typeof v === "string" && m.has(v) ? m.get(v) : v);
          for (const [k, pas] of tr.steps.entries()) {
            h.regler(pas.at);
            nonce = pas.challenges[0];
            const r = await s.appel(pas.method, traduire(pas.request, versService));
            const ici = `${f} pas ${k} (${pas.method})`;
            if (pas.expected.accepted) {
              expect(r.statut, `${ici} ${JSON.stringify(r.corps)}`).to.equal(200);
              if (r.corps.entry && !versVecteur.has(r.corps.entry)) {
                expect(r.corps.entry, ici).to.match(/^apb-[0-9a-f]{16}$/);
                versVecteur.set(r.corps.entry, pas.expected.response.entry);
                versService.set(pas.expected.response.entry, r.corps.entry);
              }
              expect(traduire(r.corps, versVecteur), ici).to.deep.equal(pas.expected.response);
            } else {
              expect([r.statut, r.corps.error?.code], ici).to.deep.equal([statutDe(pas.expected.reason), pas.expected.reason]);
            }
            const a = (await s.appel("annuaire", { session_identity: doc0.administrators[0] })).corps;
            expect(a.revision, ici).to.equal(pas.expected.revision);
            const resume = a.entries.map((e) => ({ id: e.id, active: e.active, requester_identities: e.requester_identities, addresses: e.addresses.map((x) => ({ address: x.address, state: x.state })) }));
            expect(traduire(resume, versVecteur), ici).to.deep.equal(pas.expected.entries);
          }
          const final = (await s.appel("annuaire", { session_identity: doc0.administrators[0] })).corps;
          expect(A.verifierAnnuaireExporte(final, { conforme: A.annuaireConforme }), "annuaire final sans écart d'EX-13.19").to.deep.equal([]);
        } finally {
          await s.arreter();
        }
      });
    }
  });

  describe("TE-19 : tickets enrichis (EX-12.21)", function () {
    it("contest_ms et contest de chaque ticket ; related : refuse ou expire, même demandeur et même outil, scellés depuis moins de E, au plus 20, ordre, sans argument", async function () {
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, max_open_tickets: 50, horloge: horlogeReglable("2026-11-10T08:00:00.000Z") });
      try {
        await s.client.charger(chargement());
        const expirer = async (t, motif = null) => {
          expect((await s.appel("retirer", { ticket: t.ticket, by: SESSIONS.admin, reason: motif, session_identity: SESSIONS.admin })).statut).to.equal(200);
          return sceller(s, t.ticket);
        };
        // deux tickets scellés il y a plus de E : exclus
        const anciens = [await ouvrirSur(s, paiement("6000.00", "2026-70001")), await ouvrirSur(s, paiement("6000.00", "2026-70002"))];
        for (const t of anciens) await expirer(t);
        s.h.avancer(E + 1);
        // 22 tickets du même demandeur et du même outil : 2 refusés par vote, 20 expirés par retrait, deux à instant égal
        const scelles = [];
        for (let k = 0; k < 22; k++) {
          const t = await ouvrirSur(s, paiement("6000.00", `2026-8${String(k).padStart(4, "0")}`));
          if (k < 2) {
            await voter(s, t, 1, "refuse", "Montant différent de la facture");
            await voter(s, t, 2, "refuse", "Pièce manquante");
            scelles.push({ t, a: await sceller(s, t.ticket) });
          } else {
            scelles.push({ t, a: await expirer(t) });
          }
          if (k !== 10) s.h.avancer(1000);
        }
        // exclus : un autre outil, un autre demandeur
        const autreOutil = await ouvrirSur(s, { claim_id: "2026-1" }, { outil: OUTIL_SUPPRESSION.tool_announced });
        await expirer(autreOutil);
        const autreDemandeur = await ouvrirSur(s, paiement("6000.00", "2026-60001"), { launched_by: "autre-demandeur" });
        await expirer(autreDemandeur);
        // ticket ouvert dont la console affiche l'écran
        const ref = await ouvrirSur(s, paiement("6100.00", "2026-99999"));
        const r = await s.appel("tickets", { session_identity: SESSIONS[1], related_to: ref.ticket });
        expect(r.statut).to.equal(200);
        expect(valide(A.IDS.consoleService, "reponse_tickets", r.corps).valide).to.equal(true);
        const attendus = scelles
          .map(({ t, a }) => ({ ticket: t.ticket, decision: a.decision, decided_at: a.at, reason: a.reason }))
          .sort((x, y) => (x.decided_at < y.decided_at ? 1 : x.decided_at > y.decided_at ? -1 : x.ticket < y.ticket ? -1 : 1))
          .slice(0, 20);
        expect(r.corps.related).to.deep.equal(attendus);
        expect(r.corps.related.map((x) => x.decision).filter((d) => d === "refuse")).to.have.length(0);
        expect(r.corps.related.map((x) => x.reason)).to.include("echeance avancee par retrait");
        // les deux refus, les plus anciens, sont au-delà des 20 ; sans aucun argument
        expect(JSON.stringify(r.corps)).to.not.contain("CH9300762011623852957");
        // à instant égal : par identifiant croissant
        const egaux = r.corps.related.filter((x, i, l) => l.some((y, j) => j !== i && y.decided_at === x.decided_at));
        expect(egaux).to.have.length(2);
        expect(egaux[0].ticket < egaux[1].ticket).to.equal(true);
        // même réponse pour un administrateur
        const r2 = (await s.appel("tickets", { session_identity: SESSIONS.admin, related_to: ref.ticket })).corps;
        expect(r2.related).to.deep.equal(r.corps.related);
      } finally {
        await s.arreter();
      }
    });

    it("contest : fenêtre en cours, objections non levées avec leur auteur et leur instant, dernier instant du seuil (EX-10.9)", async function () {
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, horloge: horlogeReglable("2026-11-10T08:00:00.000Z") });
      try {
        await s.client.charger(chargement());
        const t = await ouvrirSur(s, { claim_id: "2026-1" }, { outil: OUTIL_SUPPRESSION.tool_announced });
        const ligne = async () => (await s.appel("tickets", { session_identity: SESSIONS[1] })).corps.tickets.find((x) => x.ticket === t.ticket);
        const deadline = "2026-11-10T09:00:00.000Z";
        const dernier = "2026-11-10T08:59:58.499Z"; // échéance − contest_ms − 1 ms
        expect(await ligne()).to.deep.include({ contest_ms: 1500, deadline, contest: { window_end: null, objections: [], last_threshold_at: dernier } });
        s.h.avancer(1000);
        await voter(s, t, 1, "refuse", "Objection");
        expect((await ligne()).contest).to.deep.equal({ window_end: null, objections: [{ approver: adresseDe(1), at: "2026-11-10T08:00:01.000Z" }], last_threshold_at: dernier });
        s.h.avancer(1000);
        await voter(s, t, 1, "approuve");
        await voter(s, t, 2, "approuve");
        const l = await ligne();
        expect(l).to.deep.include({ state: "seuil_atteint", votes_approuve: 2, votes_refuse: 0 });
        expect(l.contest).to.deep.equal({ window_end: "2026-11-10T08:00:03.500Z", objections: [], last_threshold_at: dernier });
        const v = (await s.appel("consulter", { ticket: t.ticket, session_identity: SESSIONS[1] })).corps;
        expect(v.contest).to.deep.equal(l.contest);
        expect(v.rule).to.deep.include({ name: "suppression", contest_ms: 1500 });
        // gabarit absent, écriture : l'effet par défaut d'EX-7.6 (2)
        expect(v.effects).to.deep.equal([{ system: OUTIL_SUPPRESSION.server_alias, action: "ecriture", object: OUTIL_SUPPRESSION.tool_original, amount: null, currency: null, unresolved: [] }]);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("TI-14 : canal réel joint par le client du démon de l'étape 4", function () {
    it("sept combinaisons d'evaluer jugées par la validation du démon ; canal non authentifié refusé ; mêmes sorties après un arrêt brutal", async function () {
      const dir = repertoireTemporaire("noortrace-ti14-");
      const cfg = configurationEtape6(dir, { annuaire: ANNUAIRE_REFERENCE });
      let svc = await lancerService(cfg.chemin);
      const client = () => new ClientServiceApprobation({ url: `http://127.0.0.1:${svc.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
      const console_ = (m, c) => appelHttp(svc.console, m, c, cfg.jetonConsole);
      const scellees = new Map();
      const juger = (r) => validerReponseEvaluer(r, { decisionScellee: (t) => (scellees.has(t) ? { approval: scellees.get(t) } : null) });
      let seq = 4;
      const s = { h: { t: Date.now() } };
      try {
        let c = client();
        await c.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
        const combinaisons = new Map();
        const evaluer = async (req) => {
          const r = await c.evaluer(req);
          const v = juger(r);
          expect(v.valide, `${JSON.stringify(r)} : ${v.raison}`).to.equal(true);
          combinaisons.set(v.combinaison, r);
          return r;
        };
        const ouvrir = async (req) => {
          const r = await evaluer(req);
          seq += 2;
          const ret = retenue({ requete: req, rule: r.rule, ticket: r.ticket, seq, ts: N.ecrireHorodatage(Date.now() - 100) });
          await c.ouvrir(ret.ouvrir);
          return { ticket: r.ticket, ret };
        };
        const voterP = (t, i, d, motif = null) => console_("voter", { ticket: t.ticket, approver: adresseDe(i), decision: d, signature: signerVoteDerive(i, { decision: d, ticket: t.ticket, request_hash: t.ret.evenement.hash }), reason: motif, session_identity: SESSIONS[i] });
        const scellerP = async (t) => {
          const { remises } = await c.decisions({ wait_ms: 5000 });
          const remise = remises.find((x) => x.ticket === t.ticket);
          seq += 1;
          const approval = { ...remise.approval, at: N.ecrireHorodatage(Date.now()) };
          await c.acquitter({ remise_id: remise.remise_id, ticket: t.ticket, result: "scelle", reason: null, seq, hash: N.sha256Hex(N.utf8(`d${seq}`)), at: approval.at, decision: approval.decision, held: false, approval });
          scellees.set(t.ticket, approval);
        };
        await evaluer(requeteEvaluer(OUTIL_LECTURE.tool_announced, { claim_id: "2026-1" }));
        await evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, { ...paiement("700.00"), currency: "EUR" }));
        const reqA = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00"));
        const tA = await ouvrir(reqA);
        await evaluer(reqA);
        await voterP(tA, 1, "approuve");
        await voterP(tA, 2, "approuve");
        await scellerP(tA);
        await evaluer(reqA);
        const reqR = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7500.00", "2026-2"));
        const tR = await ouvrir(reqR);
        await voterP(tR, 1, "refuse", "Non");
        await voterP(tR, 2, "refuse", "Non");
        await scellerP(tR);
        await evaluer(reqR);
        const reqX = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7600.00", "2026-3"));
        const tX = await ouvrir(reqX);
        expect((await console_("retirer", { ticket: tX.ticket, by: SESSIONS.admin, reason: null, session_identity: SESSIONS.admin })).statut).to.equal(200);
        await scellerP(tX);
        await evaluer(reqX);
        expect([...combinaisons.keys()].sort()).to.deep.equal(["a_approuver/en_attente", "a_approuver/nouveau", "autorise/approuve", "autorise/null", "refuse/expire", "refuse/null", "refuse/refuse"]);
        // une réponse hors des sept combinaisons est refusée par le démon (EX-12.6, EX-7.16)
        expect(juger({ ...combinaisons.get("refuse/refuse"), ticket_state: "approuve" }).valide).to.equal(false);
        expect(juger({ ...combinaisons.get("autorise/null"), ticket: "apr-x", ticket_state: "approuve" }).valide).to.equal(false);
        // canal non authentifié : jeton faux, jeton absent, jeton de l'autre canal ; rien n'est appliqué
        const etatAvant = (await etatHttp(svc.console, cfg.jetonConsole)).corps;
        const reqN = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("9100.00", "2026-4"));
        for (const jeton of ["jeton-faux-de-trente-deux-caracteres", null, cfg.jetonConsole]) {
          const e = await new ClientServiceApprobation({ url: `http://127.0.0.1:${svc.noyau.port}`, jeton, timeout_ms: 5000 }).evaluer(reqN).then(() => null, (x) => x);
          // le client du démon tient un 401 pour une indisponibilité, jamais pour une réponse (CT-3 EX-12.2)
          expect([e?.code, e?.data?.statut, e?.data?.code], String(jeton)).to.deep.equal(["indisponible", 401, "requete_invalide"]);
        }
        expect((await console_("tickets", { session_identity: SESSIONS.admin })).statut).to.equal(200);
        expect((await appelHttp(svc.console, "tickets", { session_identity: SESSIONS.admin }, cfg.jetonNoyau)).statut).to.equal(401);
        expect((await etatHttp(svc.console, cfg.jetonConsole)).corps).to.deep.equal(etatAvant);
        // mêmes sorties après un arrêt brutal (TK-12)
        const tO = await ouvrir(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("8000.00", "2026-5")));
        await voterP(tO, 1, "approuve", "Conforme");
        const sorties = async () => ({
          ouvert: await c.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("8000.00", "2026-5"))),
          refuse: await c.evaluer(reqR),
          expire: await c.evaluer(reqX),
          tickets: (await console_("tickets", { session_identity: SESSIONS.admin, related_to: tO.ticket })).corps,
          vue: (await console_("consulter", { ticket: tO.ticket, session_identity: SESSIONS[2] })).corps,
          annuaire: (await console_("annuaire", { session_identity: SESSIONS[1] })).corps,
          etat: (await etatHttp(svc.console, cfg.jetonConsole)).corps,
        });
        const avant = await sorties();
        expect(avant.tickets.related.map((x) => x.ticket).sort()).to.deep.equal([tR.ticket, tX.ticket].sort());
        await svc.tuer();
        svc = await lancerService(cfg.chemin);
        c = client();
        expect(await sorties()).to.deep.equal(avant);
        void s;
      } finally {
        await svc.arreter();
      }
    });
  });

  describe("TA-77 : canal du service authentifié (CT-2 EX-18.8, CT-3 EX-12.2)", function () {
    let mutant = null;
    const aArreter = [];
    after(async function () {
      while (aArreter.length) await aArreter.pop()().catch(() => {});
      if (mutant) fs.rmSync(mutant, { recursive: true, force: true });
    });

    it("TA-77 : démon pointé vers un faux service sans mTLS ni jeton : ligne approval_response_invalid, appel non relayé ; service réel, jeton faux : 401, rien d'appliqué ; mutant du service sans authentification du canal : la requête au jeton faux est appliquée (tué)", async function () {
      // 1. faux service : n'authentifie rien, forge une autorisation pour un ticket que le démon n'a jamais scellé
      const requetes = [];
      const faux = http.createServer((req, res) => {
        const m = [];
        req.on("data", (x) => m.push(x));
        req.on("end", () => {
          const corps = JSON.parse(Buffer.concat(m).toString("utf8") || "{}");
          requetes.push({ chemin: req.url, autorisation: req.headers.authorization ?? null });
          let r;
          if (req.url.endsWith("/charger")) r = { policy_version: corps.policy_version, policy_sha256: corps.policy_sha256, approval_candidates: [OUTIL_PAIEMENT.tool_announced] };
          else if (req.url.endsWith("/evaluer")) {
            r = {
              rule: "paiement > 5000 CHF", decision: "autorise", ticket: "apr-faux-0001", ticket_state: "approuve", approver_set: null,
              approval: { decision: "approuve", ticket: "apr-faux-0001", request_hash: N.ZERO32, threshold: { required: 1, size: 1 }, approvers: [adresseDe(1)], signatures: ["0x" + "11".repeat(65)], reason: null, at: "2026-11-10T10:14:02.000Z" },
            };
          } else r = { remises: [] };
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(r));
        });
      });
      await new Promise((ok) => faux.listen(0, "127.0.0.1", ok));
      aArreter.push(() => new Promise((ok) => { faux.closeAllConnections(); faux.close(ok); }));
      const dirDemon = repertoireDemon();
      const config = validerConfigurationDemon(new TextEncoder().encode(JSON.stringify(configurationDev(dirDemon).config))).config;
      const coeur = await Coeur.demarrer({
        config, secrets: secretsDev(), horloge: new HorlogeReglable(Date.parse("2026-11-10T10:14:02.000Z")),
        service: new ClientServiceApprobation({ url: `http://127.0.0.1:${faux.address().port}`, jeton: "jeton-faux-de-seize-caracteres", timeout_ms: 2000 }),
      });
      aArreter.push(() => coeur.arreter());
      const args = { claim_id: "2026-1", amount: "7400.00", currency: "CHF" };
      const e = await coeur.evaluer({
        tool_announced: OUTIL_PAIEMENT.tool_announced, tool_original: OUTIL_PAIEMENT.tool_original, server_alias: OUTIL_PAIEMENT.server_alias, arguments: args, class: "ecriture",
        delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null }, intent: null,
        code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [],
      }).then(() => null, (x) => x);
      expect(e?.raison, "appel non relayé").to.equal("approbation");
      expect(coeur.journal.trouver("approval_response_invalid")).to.have.length(1);
      expect(requetes.some((q) => q.chemin.endsWith("/evaluer"))).to.equal(true);

      // 2. service réel, jeton faux : 401, aucun ticket, ligne auth_refusee au journal du service
      const oracle = async (Module) => {
        const dir = repertoireTemporaire("noortrace-ta77-");
        const cfg = configurationEtape6(dir);
        const charge = Module.chargerConfiguration(cfg.chemin);
        const inst = await Module.demarrerService({ config: charge.config, secrets: charge.secrets, base: dir, essais: { minuterie: false } });
        try {
          const vrai = new ClientServiceApprobation({ url: `http://127.0.0.1:${inst.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
          await vrai.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          const fauxJeton = new ClientServiceApprobation({ url: `http://127.0.0.1:${inst.noyau.port}`, jeton: "jeton-faux-de-seize-caracteres", timeout_ms: 5000 });
          const r = await fauxJeton.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00"))).then((x) => x, (x) => x);
          const voterSansJeton = await appelHttp(inst.console, "tickets", { session_identity: SESSIONS.admin }, "jeton-faux-de-seize-caracteres");
          const refusNoyau = r?.code === "indisponible" && r?.data?.statut === 401 && r?.data?.code === "requete_invalide";
          return { refuse: refusNoyau && voterSansJeton.statut === 401, tickets: inst.service.machine.tickets.size, dir: cfg.doc.state_dir };
        } finally {
          await inst.arreter();
        }
      };
      const o = await oracle(A);
      expect(o).to.deep.include({ refuse: true, tickets: 0 });
      expect(fs.readFileSync(path.join(o.dir, "journal-service.ndjson"), "utf8")).to.contain('"type":"auth_refusee"');

      // 3. mutant : copie du paquet dont l'écoute n'authentifie plus
      mutant = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "noortrace-ta77-"));
      fs.cpSync(path.join(RACINE, "paquets", "approbation"), path.join(mutant, "approbation"), { recursive: true });
      fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(mutant, "node_modules"));
      const f = path.join(mutant, "approbation", "src", "transport.mjs");
      const texte = fs.readFileSync(f, "utf8");
      const garde = "  #authentifie(req) {\n";
      expect(texte.includes(garde), "garde trouvée dans la copie").to.equal(true);
      fs.writeFileSync(f, texte.replace(garde, `${garde}    return true;\n`));
      const M = await import(path.join(mutant, "approbation", "src", "index.mjs"));
      const om = await oracle(M);
      expect(om.refuse, "mutant : la requête au jeton faux n'est plus refusée").to.equal(false);
      expect(om.tickets, "mutant tué : un ticket a été créé par un pair non authentifié").to.equal(1);
    });
  });
});
