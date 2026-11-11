// Exigences de CT-3 (sections 3 à 12, et 14.6) tenues par le service
// d'approbation, chacune testée en réussite et en échec, et vérifications
// TK-. Les vecteurs de spec/vecteurs/ct-3 sont rejoués par
// approbation-service-vecteurs.test.js ; ce fichier exerce chaque règle sur
// des cas construits : machine à états (entrées datées), service en
// processus (canal HTTP, persistance, reprise), lecteur du jeu sur le
// réseau Hardhat en mémoire (contrats CuratorSetRegistry et CuratorSet du
// dépôt). Le dernier bloc vérifie que chaque EX- des sections du lot est
// testé ici, ou attribué avec sa raison (console de l'étape 6, mandataire).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { network } from "hardhat";
import * as N from "@noortrace/noyau";
import {
  Machine, LecteurJeu, demarrerService, validerPolitique, avertissementsPolitique, evaluer, candidats, normaliserSignature,
  verifierRemise, sourceJeu, jeuStatique, identifiantAleatoire, controlerConfiguration, RAISONS_EXPIRE, chiffrer, dechiffrer,
} from "@noortrace/approbation";
import { ClientServiceApprobation } from "@noortrace/enregistreur";
import {
  SPEC, ORG_ID, JOURNAL_ID, DEMANDEUR, SESSIONS, CONSTANTES, adresse, signerVote, repertoireTemporaire, hashDemande, hashEvenement,
  politiqueParcours, messageCharger, requeteEvaluer, retenue, ecrireConfiguration, appelConsole, requeteBrute,
} from "./fixtures/approbation-service/outils.mjs";

// ------------------------------------------------------------------ outils

const T0 = N.decoderHorodatage("2026-11-12T09:00:00.000Z");
const at = (ms) => N.ecrireHorodatage(T0 + ms);
const V1 = "v1";
const MIN = 60000;
const couverts = new Set();

/** Une exigence, testée en réussite et en échec. */
function exigence(ids, titre, cas) {
  const liste = Array.isArray(ids) ? ids : [ids];
  for (const id of liste) couverts.add(id);
  describe(`${liste.join(", ")} : ${titre}`, function () {
    it("réussite", cas.reussite);
    it("échec", cas.echec);
  });
}

function nouvelleMachine(o = {}) {
  const journal = [];
  const m = new Machine({
    org_id: ORG_ID, journal_id: JOURNAL_ID, identifiants: o.identifiants ?? { mode: "compteur" },
    max_open_tickets: o.max_open_tickets ?? 20, escalation: o.escalation ?? [], administrators: o.administrators ?? [SESSIONS.admin],
    evenement: (type, detail) => journal.push({ type, ...detail }),
  });
  m.ajouterVersion({ policy_version: V1, approval: { rules: o.rules ?? politiqueParcours(o), mode: o.mode ?? "erreur", expire_after_ms: o.E ?? 3600000, timeout_ms: 2000 } });
  m.fixerEnVigueur(V1);
  m.journal = journal;
  return m;
}

const entree = (m, kind, ms, data, options) => m.entree({ kind, at: at(ms), data }, options);
const paiement = (montant, extra = {}) => ({ claim_id: "2026-90417", amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957", ...extra });
const demande = (args, o = {}) => requeteEvaluer(o.outil ?? "sap__payments.create", args, { policy_version: o.pv ?? V1, launched_by: o.launched_by ?? DEMANDEUR });

/** Évalue et ouvre un ticket ; rend son identifiant. */
function ouvrirTicket(m, args, ms = 0, o = {}) {
  const r = entree(m, "evaluer", ms, { request: demande(args, o) });
  expect(r.accepted, r.reason).to.equal(true);
  const id = r.response.ticket;
  const o2 = entree(m, "ouvrir", ms + 100, { ticket: id, request_hash: hashDemande(id), request_seq: 5, request_ts: at(ms + 50) });
  expect(o2.accepted, o2.reason).to.equal(true);
  return id;
}

function voter(m, id, i, decision, ms, reason = null, extra = {}) {
  const t = m.tickets.get(id);
  const signature = extra.signature ?? signerVote(i, { decision, ticket: id, request_hash: t.request.request_hash });
  return entree(m, "voter", ms, { ticket: id, approver: adresse(i), decision, signature, reason, session_identity: SESSIONS[i] ?? null });
}

/** Approuve et scelle un ticket (comptes 1 et 2) ; rend la remise. */
function approuverEtSceller(m, id, ms, held = false) {
  voter(m, id, 1, "approuve", ms);
  const v = voter(m, id, 2, "approuve", ms + 1000, "motif");
  const remise = v.remises[0];
  const approval = { ...remise.approval, at: at(ms + 2000) };
  const a = entree(m, "acquitter", ms + 2100, {
    remise_id: remise.remise_id, ticket: id, result: "scelle", reason: null, seq: 6, hash: hashEvenement(6), at: approval.at, decision: "approuve", held, approval,
  });
  expect(a.accepted, a.reason).to.equal(true);
  return { remise, approval };
}

const JEU_REGISTRE = {
  source: "registre", chain_id: 2124, registry: CONSTANTES.registry, set: CONSTANTES.sets["1"], members: null, threshold: null,
};
const bloc = (h) => N.sha256Hex(N.utf8(`noortrace/vecteurs/ct3/bloc/${h}`));
function lecture(h, membres = [1, 2, 3], required = 2, set = CONSTANTES.sets["1"]) {
  return { status: "lu", cause: null, jeu: { chain_id: 2124, registry: CONSTANTES.registry, set, height: h, block_hash: bloc(h), threshold: { required, size: membres.length }, members: membres.map(adresse).sort() } };
}

/** Service en processus, horloge réglable, écoute TCP sur la boucle locale. */
async function serviceEnProcessus(o = {}) {
  const dir = o.dir ?? repertoireTemporaire();
  const cfg = ecrireConfiguration(dir, { socket: false, ...o });
  const horloge = { decalage: 0 };
  const inst = await demarrerService({
    config: cfg.config,
    secrets: { cle: N.sha256(N.utf8(dir + "/k")), jetonNoyau: cfg.jetonNoyau, jetonConsole: cfg.jetonConsole },
    horloge: () => Date.now() + horloge.decalage,
    base: dir,
    appelRpc: o.appelRpc,
  });
  const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${inst.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
  return { dir, cfg, inst, client, horloge, service: inst.service };
}

async function avecService(o, f) {
  const s = await serviceEnProcessus(o);
  try {
    return await f(s);
  } finally {
    await s.inst.arreter();
  }
}

const rejet = async (p) => {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("refus attendu");
};

// ------------------------------------------------------------------ §3 Modèle

describe("service d'approbation : exigences de CT-3", function () {
  this.timeout(60000);

  describe("§3 modèle", function () {
    exigence("EX-3.1", "aucun autorise pour une demande liée à un ticket avant l'acquittement du scellement d'une approbation", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, id, MIN);
        const r = entree(m, "evaluer", 2 * MIN, { request: demande(paiement("7400.00")) });
        expect(r.response).to.include({ decision: "autorise", ticket_state: "approuve", ticket: id });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "approuve", MIN + 1000); // remise calculée, non scellée
        const r = entree(m, "evaluer", 2 * MIN, { request: demande(paiement("7400.00")) });
        expect(r.response).to.include({ decision: "a_approuver", ticket_state: "en_attente" });
      },
    });

    exigence("EX-3.2", "un délai écoulé donne expire, jamais une approbation implicite", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const r = entree(m, "horloge", 3600000 + 200, {});
        expect(r.remises[0].approval).to.include({ decision: "expire", reason: RAISONS_EXPIRE.autre });
        expect(r.remises[0].approval.approvers).to.deep.equal([]);
        expect(m.tickets.get(id).state).to.equal("a_remettre");
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN); // sous le seuil
        const r = entree(m, "horloge", 3600000 + 200, {});
        expect(r.remises[0].approval.decision).to.not.equal("approuve");
      },
    });

    exigence(["EX-3.3", "EX-3.4", "EX-12.3"], "le service ne détient ni ne demande aucune clé et ne signe rien", {
      reussite() {
        const src = path.join(SPEC, "..", "paquets", "approbation", "src");
        for (const f of fs.readdirSync(src)) {
          const t = fs.readFileSync(path.join(src, f), "utf8");
          expect(t, f).to.not.match(/signerApprobation|signerEip191|scellerEvenement|signerEd25519|signerManifeste/);
        }
      },
      echec() {
        // la configuration n'a aucun membre de clé de journal ni d'approbateur
        const c = { ...ecrireConfiguration(repertoireTemporaire(), { socket: false }).config, signer: { key: "x" } };
        expect(controlerConfiguration(c)).to.include("/signer : membre inconnu");
      },
    });

    exigence("EX-3.5", "l'évaluation ne lit que le nom annoncé, les arguments et launched_by", {
      reussite() {
        const P = politiqueParcours();
        const d = demande(paiement("2500.00"));
        const variante = { ...d, intent: "autre", context: [{ sha256: N.ZERO32, length: 1, redacted: false, kind: "autre" }], class: "lecture", delegation: { ...d.delegation, run_id: "autre", on_behalf_of: "autre" } };
        expect(evaluer(P, variante, [], T0)).to.deep.equal(evaluer(P, d, [], T0));
      },
      echec() {
        const P = politiqueParcours();
        const w = { scope: { policy_version: V1, rule: "paiement de 1000 a 5000 CHF", tool: "sap__payments.create", launched_by: DEMANDEUR, values: ["CH9300762011623852957"] }, start: at(0), end: at(MIN), remaining: 2, ticket: "apr-0009" };
        expect(evaluer(P, demande(paiement("2500.00")), [w], T0).decision).to.equal("autorise");
        // un autre demandeur n'a pas la même portée : la fenêtre ne le couvre pas
        expect(evaluer(P, demande(paiement("2500.00"), { launched_by: "autre@x" }), [w], T0).decision).to.equal("a_approuver");
      },
    });
  });

  // ------------------------------------------------------------------ §4 Langage

  describe("§4 langage de règles", function () {
    exigence(["EX-4.1", "EX-12.5"], "charger valide approval.rules (politique-approbation-v0) et rend toutes les erreurs", {
      async reussite() {
        await avecService({}, async ({ client }) => {
          const r = await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          expect(r.approval_candidates).to.deep.equal(["sap__claims.delete", "sap__payments.create"]);
          expect(r.policy_version).to.equal(V1);
        });
      },
      async echec() {
        await avecService({}, async ({ client }) => {
          const P = politiqueParcours();
          P.rules[1].name = P.rules[0].name;
          P.default.contest_ms = 3600000;
          const e = await rejet(client.charger(messageCharger({ policy_version: V1, rules: P })));
          expect(e.code).to.equal("politique_invalide");
          expect(e.data.errors).to.deep.equal([{ code: "contest_ms_trop_long", pointer: "/default/contest_ms" }, { code: "nom_double", pointer: "/rules/1/name" }]);
          const e2 = await rejet(client.charger(messageCharger({ policy_version: "v2", rules: { version: 0 } })));
          expect(e2.data.errors).to.deep.equal([{ code: "schema", pointer: null }]);
        });
      },
    });

    exigence("EX-4.2", "points 1 à 7 vérifiés sur un document conforme ; statique refusé en production", {
      reussite() {
        expect(validerPolitique(politiqueParcours(), { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
        expect(validerPolitique(politiqueParcours({ approver_set: JEU_REGISTRE }), { environment: "production", expire_after_ms: 3600000 })).to.deep.equal([]);
      },
      echec() {
        const P = politiqueParcours();
        P.separation.identities.push({ launched_by: DEMANDEUR, addresses: [adresse(4)] });
        expect(validerPolitique(P, { environment: "production", expire_after_ms: 3600000 })).to.deep.equal([
          { code: "jeu_statique_en_production", pointer: "/approver_set/source" },
          { code: "launched_by_double", pointer: "/separation/identities/1/launched_by" },
        ]);
      },
    });

    exigence("EX-4.3", "sélection : nom exact, casse comprise, préfixe joker final", {
      reussite() {
        const P = politiqueParcours();
        P.rules[0].tools = ["sap__claims.*"];
        expect(evaluer(P, demande({}, { outil: "sap__claims.get" }), [], T0).rule).to.equal("lecture autorisee");
      },
      echec() {
        expect(evaluer(politiqueParcours(), demande({}, { outil: "SAP__claims.get" }), [], T0).rule).to.equal("defaut : revue");
      },
    });

    exigence(["EX-4.4", "EX-4.5", "EX-4.6", "EX-4.7", "EX-4.8"], "pointeurs, typage numérique exact, chaînes, logique de Kleene", {
      reussite() {
        const P = politiqueParcours();
        expect(evaluer(P, demande(paiement("5000.000000000000000001")), [], T0).rule).to.equal("paiement > 5000 CHF");
        expect(evaluer(P, demande(paiement(7400)), [], T0).rule).to.equal("paiement > 5000 CHF");
      },
      echec() {
        const P = politiqueParcours();
        for (const montant of [7400.5, "7,400.00", "1e3", " 12", undefined]) {
          const args = paiement(montant);
          if (montant === undefined) delete args.amount;
          expect(evaluer(P, demande(args), [], T0).rule, String(montant)).to.equal("paiement > 5000 CHF [indetermine]");
        }
        expect(evaluer(P, demande(paiement("800", { currency: "chf" })), [], T0).decision).to.equal("refuse");
      },
    });

    exigence(["EX-4.9", "EX-4.10"], "rang maximal, première règle à rang égal, règle par défaut seulement si aucune ne s'applique", {
      reussite() {
        const P = politiqueParcours();
        expect(evaluer(P, demande(paiement("800", { currency: "EUR" })), [], T0).rule).to.equal("paiement hors CHF");
        expect(evaluer(P, demande(paiement("0")), [], T0).rule).to.equal("defaut : revue");
      },
      echec() {
        // la règle par défaut ne décide pas quand une règle s'applique
        expect(evaluer(politiqueParcours(), demande(paiement("800")), [], T0).rule).to.not.equal("defaut : revue");
      },
    });

    exigence("EX-4.11", "CANDIDATS : ordre de L, doublons, conditions 1 et 2", {
      reussite() {
        expect(candidats(politiqueParcours(), ["sap__payments.create", "sap__claims.get", "x__autre", "sap__payments.create"])).to.deep.equal(["sap__payments.create", "x__autre"]);
      },
      echec() {
        const P = politiqueParcours();
        P.default = { name: "defaut", description: null, level: "automatique", decision: "autorise", contest_ms: null };
        expect(candidats(P, ["x__autre", "sap__claims.get"])).to.deep.equal([]);
      },
    });

    exigence("EX-4.12", "une nouvelle version ferme toutes les fenêtres ; une demande sous elle est une autre demande", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("2500.00"));
        approuverEtSceller(m, id, MIN);
        expect(m.fenetres).to.have.length(1);
        m.ajouterVersion({ ...m.version(V1), policy_version: "v2" });
        entree(m, "charger", 5 * MIN, { policy_version: "v2" });
        expect(m.fenetres).to.deep.equal([]);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        m.ajouterVersion({ ...m.version(V1), policy_version: "v2" });
        entree(m, "charger", MIN, { policy_version: "v2" });
        const r = entree(m, "evaluer", 2 * MIN, { request: demande(paiement("7400.00"), { pv: "v2" }) });
        expect(r.response.ticket).to.not.equal(id);
        expect(r.response.ticket_state).to.equal("nouveau");
      },
    });

    exigence("EX-4.13", "aucune expression régulière ni opérateur hors de la table 4.9", {
      reussite() {
        const P = politiqueParcours();
        P.rules[1].when = { path: "/arguments/currency", op: "commence_par", value: "CH" };
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
      },
      echec() {
        const P = politiqueParcours();
        P.rules[1].when = { path: "/arguments/currency", op: "correspond", value: "^CH" };
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([{ code: "schema", pointer: null }]);
      },
    });

    exigence("EX-4.14", "avertissements sans refus : sélecteur sans outil, fenêtre à joker, liste d'exclusion, demandeur sans entrée", {
      reussite() {
        const P = politiqueParcours();
        P.rules[1].when = { path: "/arguments/currency", op: "egal", value: "EUR" }; // exclusion (zéro none)
        P.rules[3].tools = ["sap__*"];
        const w = avertissementsPolitique(P, { outils: ["sap__payments.create"], requesters: ["poste-1", DEMANDEUR] }).map((x) => x.code);
        expect(w).to.include.members(["selecteur_sans_outil", "fenetre_plusieurs_outils", "liste_d_exclusion", "separation_non_verifiable"]);
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
      },
      echec() {
        // liste blanche (none sur egal) et demandeur déclaré : aucun avertissement de ces deux sortes
        const w = avertissementsPolitique(politiqueParcours(), { outils: ["sap__claims.get", "sap__claims.delete", "sap__payments.create"], requesters: [DEMANDEUR] }).map((x) => x.code);
        expect(w).to.not.include("liste_d_exclusion");
        expect(w).to.not.include("separation_non_verifiable");
      },
    });
  });

  // ------------------------------------------------------------------ §5 Niveaux

  describe("§5 niveaux", function () {
    exigence(["EX-5.1", "EX-5.8"], "automatique : autorise ou refuse sans ticket ; combinaisons de CT-1 seulement", {
      reussite() {
        const m = nouvelleMachine();
        expect(entree(m, "evaluer", 0, { request: demande(paiement("800")) }).response).to.deep.equal({ rule: "paiement <= 1000 CHF", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });
        expect(entree(m, "evaluer", 1, { request: demande(paiement("800", { currency: "EUR" })) }).response).to.deep.equal({ rule: "paiement hors CHF", decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null });
        expect(m.tickets.size).to.equal(0);
      },
      echec() {
        const m = nouvelleMachine();
        const r = entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) });
        expect(r.response.ticket).to.not.equal(null);
        expect(r.response.decision).to.equal("a_approuver");
      },
    });

    exigence(["EX-5.2", "EX-5.3", "EX-5.4", "EX-5.5", "EX-5.6"], "fenêtre : portée, ticket ouvrant, ouverture à approval.at, usage, fermeture", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("2500.00"));
        expect(m.tickets.get(id).opening.scope.values).to.deep.equal(["CH9300762011623852957"]);
        const { approval } = approuverEtSceller(m, id, MIN);
        expect(m.fenetres[0]).to.deep.include({ start: approval.at, remaining: 2, ticket: id });
        const r = entree(m, "evaluer", 3 * MIN, { request: demande(paiement("3000.00")) });
        expect(r.response.rule).to.equal(`paiement de 1000 a 5000 CHF [fenetre ${id} ${m.fenetres[0].end}]`);
        expect(m.fenetres[0].remaining).to.equal(1);
        entree(m, "evaluer", 3 * MIN + 1, { request: demande(paiement("3000.01")) });
        expect(m.fenetres).to.deep.equal([]); // épuisée, retirée
      },
      echec() {
        const m = nouvelleMachine();
        const sansIban = paiement("2500.00");
        delete sansIban.beneficiary_iban;
        const id = ouvrirTicket(m, sansIban);
        expect(m.tickets.get(id).opening).to.equal(null); // portée indéterminée : non ouvrant
        const id2 = ouvrirTicket(m, paiement("2600.00"), 10);
        approuverEtSceller(m, id2, MIN);
        // autre bénéficiaire : autre portée, pas couverte ; après la fin : retirée
        expect(entree(m, "evaluer", 3 * MIN, { request: demande(paiement("3000.00", { beneficiary_iban: "CH5604835012345678009" })) }).response.decision).to.equal("a_approuver");
        entree(m, "horloge", 3600000 + 3 * MIN, {});
        expect(m.fenetres).to.deep.equal([]);
      },
    });

    exigence(["EX-5.7", "EX-9.13"], "revue : décision au seuil du jeu figé ; un refus seul n'est pas une décision", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "refuse", MIN);
        const r = voter(m, id, 2, "refuse", MIN + 1);
        expect(r.remises[0].approval.decision).to.equal("refuse");
        expect(r.remises[0].approval.approvers).to.have.length(2);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "refuse", MIN);
        expect(m.tickets.get(id).state).to.equal("ouvert");
      },
    });

    exigence(["EX-5.9", "EX-5.10", "EX-10.6", "EX-10.7", "EX-10.8", "EX-10.9"], "fenêtre de contestation : objection, levée, nouvelle fenêtre complète, échéance", {
      reussite() {
        const m = nouvelleMachine({ contest_ms: 10 * MIN });
        const id = ouvrirTicket(m, {}, 0, { outil: "sap__claims.delete" });
        voter(m, id, 1, "refuse", MIN); // objection avant le seuil
        voter(m, id, 2, "approuve", 2 * MIN);
        expect(m.tickets.get(id).state).to.equal("ouvert");
        voter(m, id, 1, "approuve", 3 * MIN); // levée : nouvelle fenêtre complète
        expect(m.tickets.get(id)).to.include({ state: "seuil_atteint", contest_end: at(13 * MIN) });
        const r = entree(m, "horloge", 13 * MIN, {});
        expect(r.remises[0].approval.decision).to.equal("approuve");
      },
      echec() {
        const m = nouvelleMachine({ contest_ms: 10 * MIN });
        const id = ouvrirTicket(m, {}, 0, { outil: "sap__claims.delete" });
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "approuve", 2 * MIN);
        voter(m, id, 1, "refuse", 5 * MIN); // objection pendant la fenêtre
        expect(m.tickets.get(id).state).to.equal("ouvert");
        const r = entree(m, "horloge", 3600000 + 100, {});
        expect(r.remises[0].approval.reason).to.equal(RAISONS_EXPIRE.objection);
        // contest_ms au moins égal à E : politique refusée (EX-5.10)
        expect(validerPolitique(politiqueParcours({ contest_ms: 3600000 }), { environment: "developpement", expire_after_ms: 3600000 })[0].code).to.equal("contest_ms_trop_long");
      },
    });
  });

  // ------------------------------------------------------------------ §6 Évaluation

  describe("§6 évaluation", function () {
    exigence("EX-6.1", "les erreurs non_pret, politique_inconnue, plafond_atteint ne créent aucun ticket", {
      reussite() {
        const m = nouvelleMachine();
        expect(entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) }).accepted).to.equal(true);
      },
      echec() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        expect(entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) }).reason).to.equal("non_pret");
        expect(entree(m, "evaluer", 1, { request: demande(paiement("7400.00"), { pv: "inconnue" }) }).reason).to.equal("politique_inconnue");
        expect(m.tickets.size).to.equal(0);
      },
    });

    exigence(["EX-6.2", "EX-6.3", "EX-6.4"], "issue d'une règle et chaîne policy.rule", {
      reussite() {
        expect(evaluer(politiqueParcours(), demande(paiement("2500.00")), [], T0)).to.include({ rule: "paiement de 1000 a 5000 CHF", decision: "a_approuver" });
      },
      echec() {
        // INDETERMINE ne rend jamais moins restrictif : pas d'autorisation, marque [indetermine]
        const r = evaluer(politiqueParcours(), demande(paiement("800.5x")), [], T0);
        expect(r).to.include({ rule: "paiement > 5000 CHF [indetermine]", decision: "a_approuver" });
      },
    });

    exigence(["EX-6.5", "EX-11.11", "EX-11.12", "EX-11.13", "EX-11.14", "EX-12.20"], "effets de l'évaluation ; aucun en mode observation", {
      reussite() {
        const m = nouvelleMachine();
        entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) });
        expect(m.tickets.size).to.equal(1);
      },
      echec() {
        const m = nouvelleMachine({ mode: "observation" });
        m.fenetres.push({ scope: { policy_version: V1, rule: "paiement de 1000 a 5000 CHF", tool: "sap__payments.create", launched_by: DEMANDEUR, values: ["CH9300762011623852957"] }, start: at(0), end: at(MIN), remaining: 2, ticket: "apr-0009" });
        const r1 = entree(m, "evaluer", 1, { request: demande(paiement("7400.00")) });
        const r2 = entree(m, "evaluer", 2, { request: demande(paiement("2500.00")) });
        expect(r1.response).to.deep.equal({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null });
        expect(r2.response.rule).to.contain("[fenetre apr-0009");
        expect(m.tickets.size).to.equal(0);
        expect(m.fenetres[0].remaining).to.equal(2);
        expect(m.journal.filter((x) => x.type === "evaluation_observation")).to.have.length(2);
        expect(JSON.stringify(m.journal)).to.not.contain("CH9300762011623852957");
      },
    });

    exigence("EX-6.6", "déterminisme : ordre des membres sans effet", {
      reussite() {
        const a = paiement("2500.00");
        const b = Object.fromEntries(Object.entries(a).reverse());
        expect(evaluer(politiqueParcours(), demande(b), [], T0)).to.deep.equal(evaluer(politiqueParcours(), demande(a), [], T0));
      },
      echec() {
        // seul t, parmi les entrées, distingue ces deux évaluations : la fenêtre ne couvre plus à sa fin
        const w = { scope: { policy_version: V1, rule: "paiement de 1000 a 5000 CHF", tool: "sap__payments.create", launched_by: DEMANDEUR, values: ["CH9300762011623852957"] }, start: at(0), end: at(MIN), remaining: 2, ticket: "apr-0009" };
        expect(evaluer(politiqueParcours(), demande(paiement("2500.00")), [w], T0).decision).to.equal("autorise");
        expect(evaluer(politiqueParcours(), demande(paiement("2500.00")), [w], T0 + MIN).decision).to.equal("a_approuver");
      },
    });

    exigence(["EX-6.7", "EX-12.7"], "évaluation bornée et rapide (1 024 règles de 64 prédicats)", {
      reussite() {
        const P = politiqueParcours();
        const preds = Array.from({ length: 64 }, (_, k) => ({ path: "/arguments/amount", op: "strictement_superieur", value: String(k) }));
        P.rules = Array.from({ length: 1024 }, (_, i) => ({ name: `r${i}`, description: null, tools: ["sap__*"], when: { all: preds }, level: "revue", decision: null, window: null, contest_ms: 0 }));
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
        const debut = performance.now();
        expect(evaluer(P, demande(paiement("7400.00")), [], T0).rule).to.equal("r0");
        expect(performance.now() - debut).to.be.below(2000);
      },
      echec() {
        const P = politiqueParcours();
        P.rules = Array.from({ length: 1025 }, (_, i) => ({ ...P.rules[0], name: `r${i}` }));
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([{ code: "schema", pointer: null }]);
      },
    });

    exigence("EX-6.8", "le service ne pose jamais la marque d'observation ; nom réservé refusé", {
      reussite() {
        const m = nouvelleMachine({ mode: "observation" });
        expect(entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) }).response.rule).to.not.contain("[observation");
      },
      echec() {
        const P = politiqueParcours();
        P.rules[0].name = "evaluation impossible";
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([{ code: "schema", pointer: null }]);
      },
    });
  });

  // ------------------------------------------------------------------ §7 Ticket

  describe("§7 ticket", function () {
    exigence(["EX-7.1", "EX-7.2", "TK-1"], "identifiant : motif, 65 bits aléatoires ou époque, jamais dérivé de la demande", {
      reussite() {
        const ids = new Set(Array.from({ length: 200 }, () => identifiantAleatoire()));
        expect(ids.size).to.equal(200);
        for (const id of ids) expect(id).to.match(/^apr-[0-9a-z]{13}$/);
        const m = nouvelleMachine({ identifiants: { mode: "epoque", epoque: "e7" } });
        expect(ouvrirTicket(m, paiement("7400.00"))).to.equal("apr-e7-0001");
      },
      echec() {
        // deux demandes identiques successives (la première consommée) : deux identifiants
        const m = nouvelleMachine({ identifiants: { mode: "aleatoire" } });
        const a = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, a, MIN);
        entree(m, "evaluer", 3 * MIN, { request: demande(paiement("7400.00")) });
        entree(m, "consommer", 3 * MIN + 1, { ticket: a, seq: 7, hash: hashEvenement(7) });
        const b = entree(m, "evaluer", 4 * MIN, { request: demande(paiement("7400.00")) }).response.ticket;
        expect(b).to.not.equal(a);
        expect(b).to.not.contain("7400");
      },
    });

    exigence(["EX-7.3", "EX-7.4", "EX-7.5", "EX-7.6", "TK-2"], "clé de rapprochement : run_id, intent, class hors de la clé ; un argument différent fait une autre demande", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const d = { ...demande(paiement("7400.00")), intent: "autre", class: "lecture" };
        d.delegation = { ...d.delegation, run_id: "autre" };
        expect(entree(m, "evaluer", MIN, { request: d }).response).to.include({ ticket: id, ticket_state: "en_attente" });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const d = demande(paiement("7400.00"));
        d.delegation = { ...d.delegation, scope: "autre" };
        expect(entree(m, "evaluer", MIN, { request: d }).response.ticket).to.not.equal(id);
        expect(entree(m, "evaluer", MIN + 1, { request: demande(paiement("7400.000")) }).response.ticket).to.not.equal(id);
      },
    });

    exigence(["EX-7.7", "TK-4"], "minuteurs échus avant l'entrée de même instant : un vote à l'échéance est tardif", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", 3600000 + 49);
        expect(m.tickets.get(id).votes).to.have.length(1);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const r = voter(m, id, 1, "approuve", 3600000 + 50);
        expect(r.reason).to.equal("ticket_clos_aux_votes");
      },
    });

    exigence(["EX-7.8", "EX-7.9", "TK-3"], "entrée hors table refusée sans changement, inscrite dans la trace", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(m.tickets.get(id).transitions.map((x) => x.input)).to.deep.equal(["evaluer", "ouvrir"]);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const avant = m.tickets.get(id).state;
        const r = entree(m, "consommer", MIN, { ticket: id, seq: 7, hash: hashEvenement(7) });
        expect(r).to.include({ accepted: false, reason: "requete_invalide" });
        expect(m.tickets.get(id).state).to.equal(avant);
        expect(m.tickets.get(id).transitions.at(-1)).to.include({ input: "consommer", accepted: false, reason: "requete_invalide" });
        expect(entree(m, "voter", MIN, { ticket: id }).reason).to.equal("requete_invalide");
      },
    });

    exigence(["EX-7.10", "EX-7.11"], "échéance request_ts + E et raisons fixes d'expire", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(m.tickets.get(id).deadline).to.equal(at(50 + 3600000));
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        const v = voter(m, id, 2, "approuve", MIN + 1);
        const remise = v.remises[0];
        entree(m, "acquitter", 2 * MIN, { remise_id: remise.remise_id, ticket: id, result: "temporaire", reason: "mode_degrade", seq: null, hash: null, at: null, decision: null, held: null, approval: null });
        const r = entree(m, "horloge", 3600000 + 50, {});
        expect(r.remises[0].approval).to.include({ decision: "expire", reason: RAISONS_EXPIRE.caduque });
      },
    });

    exigence(["EX-7.12", "EX-7.13"], "notification à l'ouverture sans arguments ; escalade sans effet sur le jeu, le seuil, l'échéance", {
      reussite() {
        const m = nouvelleMachine({ escalation: [{ after_ms: 10 * MIN, notify: "jeu" }, { after_ms: 20 * MIN, notify: "administrateur" }] });
        const id = ouvrirTicket(m, paiement("7400.00"));
        const n = m.journal.find((x) => x.type === "notification" && x.kind === "ouverture");
        expect(n).to.deep.include({ ticket: id, tool: "sap__payments.create", deadline: m.tickets.get(id).deadline });
        expect(JSON.stringify(n)).to.not.contain("7400");
        const avant = JSON.stringify({ d: m.tickets.get(id).deadline, j: m.tickets.get(id).approver_set, e: m.tickets.get(id).effective_required });
        entree(m, "horloge", 21 * MIN, {});
        expect(m.tickets.get(id).escalations).to.equal(2);
        expect(JSON.stringify({ d: m.tickets.get(id).deadline, j: m.tickets.get(id).approver_set, e: m.tickets.get(id).effective_required })).to.equal(avant);
        expect(m.journal.filter((x) => x.kind === "escalade").map((x) => x.notify)).to.deep.equal(["jeu", "administrateur"]);
      },
      echec() {
        const m = nouvelleMachine({ escalation: [{ after_ms: 10 * MIN, notify: "jeu" }] });
        const id = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, id, MIN);
        entree(m, "horloge", 11 * MIN, {});
        expect(m.tickets.get(id).escalations).to.equal(0); // ticket décidé : aucune escalade
      },
    });

    exigence(["EX-7.15", "EX-12.19"], "retrait par le demandeur ou un administrateur seulement", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const r = entree(m, "retirer", MIN, { ticket: id, by: SESSIONS.admin, reason: "annulé" });
        expect(r.remises[0].approval).to.include({ decision: "expire", reason: RAISONS_EXPIRE.retrait });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(entree(m, "retirer", MIN, { ticket: id, by: SESSIONS[1], reason: null }).reason).to.equal("retrait_non_autorise");
      },
    });

    exigence(["EX-7.16", "EX-7.17", "EX-7.18", "EX-7.19", "TK-9", "TK-10"], "réponses aux ré-émissions selon l'état ; approbation servie une fois", {
      reussite() {
        const m = nouvelleMachine();
        const r1 = entree(m, "evaluer", 0, { request: demande(paiement("7400.00")) });
        const r2 = entree(m, "evaluer", 1, { request: demande(paiement("7400.00")) });
        expect(r2.response).to.deep.equal(r1.response); // reserve : nouveau, même ticket
        const id = r1.response.ticket;
        entree(m, "ouvrir", 100, { ticket: id, request_hash: hashDemande(id), request_seq: 5, request_ts: at(50) });
        approuverEtSceller(m, id, MIN);
        expect(entree(m, "evaluer", 3 * MIN, { request: demande(paiement("7400.00")) }).response.ticket_state).to.equal("approuve");
        expect(entree(m, "evaluer", 3 * MIN + 1, { request: demande(paiement("7400.00")) }).response.ticket_state).to.equal("en_attente");
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "refuse", MIN);
        const v = voter(m, id, 2, "refuse", MIN + 1);
        const approval = { ...v.remises[0].approval, at: at(2 * MIN) };
        entree(m, "acquitter", 2 * MIN + 1, { remise_id: v.remises[0].remise_id, ticket: id, result: "scelle", reason: null, seq: 6, hash: hashEvenement(6), at: approval.at, decision: "refuse", held: false, approval });
        const r = entree(m, "evaluer", 3 * MIN, { request: demande(paiement("7400.00")) });
        expect(r.response).to.deep.equal({ rule: "paiement > 5000 CHF", decision: "refuse", ticket: id, ticket_state: "refuse", approval, approver_set: null });
      },
    });

    exigence(["EX-7.20", "EX-7.25"], "idempotence d'ouvrir, acquitter, consommer, expiration ; ouvrir d'un ticket inconnu", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const o = entree(m, "ouvrir", MIN, { ticket: id, request_hash: hashDemande(id), request_seq: 5, request_ts: at(50) });
        expect(o.response).to.deep.equal({ ticket: id, state: "ouvert", deadline: at(50 + 3600000) });
        const { remise, approval } = approuverEtSceller(m, id, MIN);
        const ack = { remise_id: remise.remise_id, ticket: id, result: "scelle", reason: null, seq: 6, hash: hashEvenement(6), at: approval.at, decision: "approuve", held: false, approval };
        expect(entree(m, "acquitter", 4 * MIN, ack).response).to.deep.equal({ ticket: id, state: "approuve" });
        entree(m, "consommer", 5 * MIN, { ticket: id, seq: 7, hash: hashEvenement(7) });
        expect(entree(m, "consommer", 6 * MIN, { ticket: id, seq: 7, hash: hashEvenement(7) }).response).to.deep.equal({ ticket: id, state: "consomme" });
      },
      echec() {
        const m = nouvelleMachine();
        expect(entree(m, "ouvrir", 0, { ticket: "apr-0999", request_hash: hashDemande(1), request_seq: 5, request_ts: at(0) }).reason).to.equal("ticket_inconnu");
        const id = ouvrirTicket(m, paiement("7400.00"));
        const r = entree(m, "ouvrir", MIN, { ticket: id, request_hash: hashDemande(99), request_seq: 6, request_ts: at(50) });
        expect(r).to.include({ reason: "ticket_deja_ouvert" });
        expect(r.data).to.deep.equal({ request_hash: hashDemande(id) });
      },
    });

    exigence("EX-7.21", "un changement de politique ne change ni la règle, ni le jeu figé d'un ticket", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const avant = JSON.stringify(m.tickets.get(id).approver_set);
        const P2 = politiqueParcours();
        P2.approver_set = { ...P2.approver_set, members: [adresse(1), adresse(2), adresse(4)] };
        m.ajouterVersion({ policy_version: "v2", approval: { rules: P2, mode: "erreur", expire_after_ms: 3600000, timeout_ms: 2000 } });
        entree(m, "charger", MIN, { policy_version: "v2" });
        expect(JSON.stringify(m.tickets.get(id).approver_set)).to.equal(avant);
        expect(m.tickets.get(id).request.rule).to.equal("paiement > 5000 CHF");
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("2500.00"));
        voter(m, id, 1, "approuve", MIN);
        const v = voter(m, id, 2, "approuve", MIN + 1);
        m.ajouterVersion({ ...m.version(V1), policy_version: "v2" });
        entree(m, "charger", 2 * MIN, { policy_version: "v2" });
        const approval = { ...v.remises[0].approval, at: at(3 * MIN) };
        entree(m, "acquitter", 3 * MIN + 1, { remise_id: v.remises[0].remise_id, ticket: id, result: "scelle", reason: null, seq: 6, hash: hashEvenement(6), at: approval.at, decision: "approuve", held: false, approval });
        expect(m.fenetres).to.deep.equal([]); // la version a changé avant le scellement : aucune fenêtre
      },
    });

    exigence(["EX-7.22", "EX-7.23", "EX-7.24", "TK-12"], "persistance avant réponse, reprise depuis les seuls documents, arguments chiffrés puis effacés", {
      async reussite() {
        const dir = repertoireTemporaire();
        let id;
        await avecService({ dir }, async ({ client }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          const r = await client.evaluer(demande(paiement("7400.00")));
          id = r.ticket;
          // l'état est durable avant la réponse : relu par un second magasin
          const docs = fs.readFileSync(path.join(dir, "service", "etat", "journal.ndjson"), "utf8").trim().split("\n");
          const n = Number(docs.at(-1).split(" ")[0]);
          const enr = dechiffrer(N.sha256(N.utf8(dir + "/k")), "ligne", n, docs.at(-1).split(" ")[1]);
          expect(enr.tickets[0]).to.include({ ticket: id, state: "reserve" });
        });
        await avecService({ dir }, async ({ client }) => {
          const r = await client.evaluer(demande(paiement("7400.00")));
          expect(r).to.include({ ticket: id, ticket_state: "nouveau" });
        });
        // aucune valeur en clair des arguments dans les fichiers du service
        for (const f of fs.readdirSync(dir, { recursive: true })) {
          const p = path.join(dir, f);
          if (fs.statSync(p).isFile()) expect(fs.readFileSync(p, "latin1"), f).to.not.contain("CH9300762011623852957");
        }
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, id, MIN);
        entree(m, "evaluer", 3 * MIN, { request: demande(paiement("7400.00")) });
        entree(m, "consommer", 4 * MIN, { ticket: id, seq: 7, hash: hashEvenement(7) });
        const t = m.tickets.get(id);
        expect(t.request).to.include({ arguments: null, retained_event: null, arguments_piece: null });
        expect(t.opening).to.equal(null);
        // une ligne chiffrée altérée ne se déchiffre pas
        const cle = new Uint8Array(32).fill(1);
        const c = chiffrer(cle, "ligne", 1, { x: 1 });
        const o = Buffer.from(c, "base64");
        o[20] ^= 1;
        expect(() => dechiffrer(cle, "ligne", 1, o.toString("base64"))).to.throw();
        expect(() => dechiffrer(cle, "ligne", 2, c)).to.throw();
      },
    });

    exigence(["EX-7.26", "TK-5"], "règle de vote : un vote courant par approbateur, remplacé ; vote identique sans effet", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 1, "refuse", 2 * MIN);
        expect(m.tickets.get(id).votes.map((v) => v.status)).to.deep.equal(["remplace", "courant"]);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN, "a");
        expect(voter(m, id, 1, "approuve", 2 * MIN, "b").reason).to.equal("vote_identique");
        expect(m.tickets.get(id).votes).to.have.length(1);
      },
    });

    exigence(["EX-7.27", "EX-7.28", "EX-9.14", "TK-6", "TK-8"], "décompte ; remise de t signatures dans l'ordre d'acceptation ; motif du t-ième", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 2, "approuve", MIN, "premier");
        const v = voter(m, id, 1, "approuve", 2 * MIN, "second");
        expect(v.remises[0].approval).to.include({ reason: "second" });
        expect(v.remises[0].approval.approvers).to.deep.equal([adresse(2), adresse(1)]);
        expect(v.remises[0].approver_set.source).to.equal("jeu statique de la politique v1");
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "refuse", 2 * MIN);
        expect(m.tickets.get(id).state).to.equal("ouvert");
      },
    });

    exigence("EX-7.29", "seuil inatteignable signalé ; expire avec sa raison", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        entree(m, "recuser", MIN, { ticket: id, approver: adresse(1), session_identity: SESSIONS[1] });
        expect(m.journal.some((x) => x.type === "seuil_inatteignable" && x.ticket === id)).to.equal(true);
        expect(entree(m, "horloge", 3600000 + 100, {}).remises[0].approval.reason).to.equal(RAISONS_EXPIRE.inatteignable);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(m.journal.some((x) => x.type === "seuil_inatteignable" && x.ticket === id)).to.equal(false);
      },
    });

    exigence(["TK-7", "TK-11", "TK-13"], "gel et nouveau gel, séparation et récusation, fenêtre à l'acquittement seulement (traces de A.6)", {
      reussite() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const id = ouvrirTicket(m, paiement("2500.00"), 10);
        entree(m, "jeu_lu", 200, lecture(1200));
        expect(m.tickets.get(id).approver_set.height).to.equal(1200);
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "approuve", MIN + 1);
        expect(m.fenetres).to.deep.equal([]); // remise calculée : pas encore de fenêtre
        const r = entree(m, "jeu_lu", MIN + 2, lecture(1214));
        expect(r.remises[0].approver_set.source).to.equal(sourceJeu({ ...lecture(1200).jeu }, V1, { height: 1214, block_hash: bloc(1214) }, false));
      },
      echec() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const id = ouvrirTicket(m, paiement("7400.00"), 10);
        expect(voter(m, id, 1, "approuve", 150).reason).to.equal("jeu_non_fige");
        entree(m, "jeu_lu", 200, lecture(1200));
        expect(voter(m, id, 3, "approuve", MIN).reason).to.equal("auto_approbation");
      },
    });
  });

  // ------------------------------------------------------------------ §8 Jeu

  describe("§8 jeu d'approbateurs", function () {
    let ethers;
    let fournisseur;
    let registre;
    let jeu;
    let comptes;
    before(async function () {
      const conn = network.create ? await network.create() : await network.connect();
      ethers = conn.ethers;
      fournisseur = conn.provider;
      comptes = await ethers.getSigners();
      registre = await ethers.deployContract("CuratorSetRegistry", [comptes[0].address]);
      jeu = await ethers.deployContract("CuratorSet", [comptes[0].address, [adresse(1), adresse(2), adresse(3)], 2]);
      await registre.setCuratorSet(ORG_ID, await jeu.getAddress());
    });
    const pol = async () => ({ source: "registre", chain_id: 31337, registry: (await registre.getAddress()).toLowerCase(), set: (await jeu.getAddress()).toLowerCase(), members: null, threshold: null });
    const lecteur = (connues = [adresse(1), adresse(2), adresse(3)]) => new LecteurJeu({ url: "http://127.0.0.1:0", org_id: ORG_ID, adressesConnues: () => connues, appel: (method, params) => fournisseur.request({ method, params }) });

    exigence(["EX-8.1", "EX-8.9"], "lecture au registre à une hauteur : seuil, membres triés en minuscules, hachage du bloc", {
      async reussite() {
        const r = await lecteur().lire(await pol());
        expect(r.status).to.equal("lu");
        expect(r.jeu.threshold).to.deep.equal({ required: 2, size: 3 });
        expect(r.jeu.members).to.deep.equal([adresse(1), adresse(2), adresse(3)].sort());
        const b = await fournisseur.request({ method: "eth_getBlockByNumber", params: ["0x" + r.jeu.height.toString(16), false] });
        expect(r.jeu.block_hash).to.equal(b.hash);
        // membres inconnus du service : reconstitués par les journaux
        const r2 = await lecteur([]).lire(await pol());
        expect(r2.jeu.members).to.deep.equal(r.jeu.members);
      },
      async echec() {
        const p = await pol();
        expect((await lecteur().lire({ ...p, chain_id: 2124 })).cause).to.equal("chaine_differente");
        expect((await lecteur().lire({ ...p, set: adresse(4) })).cause).to.equal("jeu_non_attendu");
        const autre = new LecteurJeu({ url: "x", org_id: N.ZERO32.slice(0, -1) + "1", appel: (method, params) => fournisseur.request({ method, params }) });
        expect((await autre.lire(p)).cause).to.equal("organisation_sans_jeu");
        const panne = new LecteurJeu({ url: "x", org_id: ORG_ID, appel: async () => { throw new Error("-32000 header not found"); } });
        expect((await panne.lire(p)).cause).to.equal("etat_indisponible");
      },
    });

    exigence(["EX-8.5", "EX-8.6"], "surveillance des journaux du jeu ; nouveau gel, seuil effectif qui ne baisse pas", {
      async reussite() {
        const l = lecteur();
        const p = await pol();
        const h = await l.hauteur();
        expect(await l.changements(p, p.set, h, h)).to.equal(false);
        await (await jeu.addCurator(adresse(4))).wait();
        const h2 = await l.hauteur();
        expect(await l.changements(p, p.set, h, h2)).to.equal(true);
        const r = await l.lire(p);
        expect(r.jeu.members).to.include(adresse(4));
        await (await jeu.removeCurator(adresse(4))).wait();
      },
      echec() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const id = ouvrirTicket(m, paiement("7400.00"), 10);
        entree(m, "jeu_lu", 200, lecture(1200));
        entree(m, "jeu_lu", 300, lecture(1201, [1, 2, 3], 1)); // seuil abaissé
        expect(m.tickets.get(id).effective_required).to.equal(2);
      },
    });

    exigence(["EX-8.2", "EX-8.3", "EX-8.4"], "jeu statique ; non_pret avant la première lecture ; votes après le gel", {
      reussite() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const r = entree(m, "evaluer", 10, { request: demande(paiement("7400.00")) });
        expect(r.response.approver_set.source).to.match(/ repli$/);
        expect(jeuStatique(politiqueParcours().approver_set).members).to.deep.equal([adresse(1), adresse(2), adresse(3)].sort());
      },
      echec() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, { status: "illisible", jeu: null, cause: "etat_indisponible" });
        expect(entree(m, "evaluer", 10, { request: demande(paiement("7400.00")) }).reason).to.equal("non_pret");
      },
    });

    exigence(["EX-8.7", "EX-8.8"], "confirmation après le calcul ; source d'EX-8.8 ; réassignation : aucune confirmation", {
      reussite() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const id = ouvrirTicket(m, paiement("7400.00"), 10);
        entree(m, "jeu_lu", 200, lecture(1200));
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "approuve", MIN + 1);
        const r = entree(m, "jeu_lu", MIN + 2, lecture(1214));
        expect(r.remises[0].approver_set.source).to.match(/^CuratorSet c=2124 r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=1200\.\.1214 b=0x[0-9a-f]{64}$/);
      },
      echec() {
        const m = nouvelleMachine({ approver_set: JEU_REGISTRE });
        entree(m, "jeu_lu", 0, lecture(1190));
        const id = ouvrirTicket(m, paiement("7400.00"), 10);
        entree(m, "jeu_lu", 200, lecture(1200));
        voter(m, id, 1, "approuve", MIN);
        voter(m, id, 2, "approuve", MIN + 1);
        expect(entree(m, "jeu_lu", MIN + 2, lecture(1214, [1, 2, 3], 2, CONSTANTES.sets["2"])).remises).to.deep.equal([]);
        expect(entree(m, "horloge", 3600000 + 100, {}).remises[0].approval.reason).to.equal(RAISONS_EXPIRE.reassigne);
      },
    });

    exigence(["EX-8.11", "EX-12.16"], "une adresse active par entrée : un vote d'une autre adresse que celle de la session est refusé sur le canal", {
      async reussite() {
        await avecService({}, async ({ client, inst, cfg }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          const r = await client.evaluer(demande(paiement("7400.00")));
          const ret = retenue({ requete: demande(paiement("7400.00")), rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
          await client.ouvrir(ret.ouvrir);
          const sig = signerVote(1, { decision: "approuve", ticket: r.ticket, request_hash: ret.evenement.hash });
          const v = await appelConsole(inst.console, cfg.jetonConsole, "voter", { ticket: r.ticket, approver: adresse(1), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] });
          expect(v).to.deep.equal({ statut: 200, corps: { ticket: r.ticket, state: "ouvert" } });
        });
      },
      async echec() {
        await avecService({}, async ({ client, inst, cfg }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          const r = await client.evaluer(demande(paiement("7400.00")));
          const ret = retenue({ requete: demande(paiement("7400.00")), rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
          await client.ouvrir(ret.ouvrir);
          // la session de l'approbateur 1 présente la signature valide du compte 2 : refus avant toute entrée
          const sig = signerVote(2, { decision: "approuve", ticket: r.ticket, request_hash: ret.evenement.hash });
          const v = await appelConsole(inst.console, cfg.jetonConsole, "voter", { ticket: r.ticket, approver: adresse(2), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[1] });
          expect(v.corps.error.code).to.equal("session_non_autorisee");
          expect(inst.service.machine.tickets.get(r.ticket).transitions.map((x) => x.input)).to.deep.equal(["evaluer", "ouvrir"]);
        });
      },
    });
  });

  // ------------------------------------------------------------------ §9 Signature

  describe("§9 signature", function () {
    exigence(["EX-9.1", "EX-9.2"], "la décision est dans A : une signature approuve ne vaut pas refuse", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(voter(m, id, 1, "refuse", MIN).accepted).to.equal(true);
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const sig = signerVote(1, { decision: "approuve", ticket: id, request_hash: hashDemande(id) });
        expect(voter(m, id, 1, "refuse", MIN, null, { signature: sig }).reason).to.equal("signature_invalide");
      },
    });

    exigence(["EX-9.3", "EX-9.22"], "normalisation contrôlée avant toute bibliothèque : s haut et v ∈ {0,1} acceptés, autres formes refusées", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const sig = N.hexVersOctets(signerVote(1, { decision: "approuve", ticket: id, request_hash: hashDemande(id) }), 65);
        const haute = N.octetsVersHex(N.formeHauteEip191(sig));
        expect(voter(m, id, 1, "approuve", MIN, null, { signature: haute }).accepted).to.equal(true);
        expect(m.tickets.get(id).votes[0].signature).to.equal(N.octetsVersHex(sig)); // gardée canonique
      },
      echec() {
        const sig = N.hexVersOctets(signerVote(1, { decision: "approuve", ticket: "apr-0001", request_hash: N.ZERO32 }), 65);
        for (const v of [37, 38, 29, 2]) {
          const x = Uint8Array.from(sig);
          x[64] = v;
          expect(normaliserSignature(N.octetsVersHex(x)), String(v)).to.equal(null);
        }
        expect(normaliserSignature(N.octetsVersHex(sig.subarray(0, 64)))).to.equal(null);
      },
    });

    exigence(["EX-9.10", "TK-11"], "ordre des raisons de refus d'un vote", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(voter(m, id, 1, "approuve", MIN, "x".repeat(1024)).accepted).to.equal(true);
      },
      echec() {
        const m = nouvelleMachine();
        expect(entree(m, "voter", 0, { ticket: "apr-0999", approver: adresse(1), decision: "approuve", signature: "0x00", reason: null, session_identity: null }).reason).to.equal("ticket_inconnu");
        const r = entree(m, "evaluer", 1, { request: demande(paiement("7400.00")) });
        expect(entree(m, "voter", 2, { ticket: r.response.ticket, approver: adresse(1), decision: "approuve", signature: "0x00", reason: null, session_identity: null }).reason).to.equal("ticket_non_ouvert");
        const id = ouvrirTicket(m, paiement("7400.01"), 10);
        // signature d'un autre compte et motif trop long : la signature d'abord
        const sig4 = signerVote(4, { decision: "approuve", ticket: id, request_hash: hashDemande(id) });
        expect(voter(m, id, 1, "approuve", MIN, "x".repeat(1025), { signature: sig4 }).reason).to.equal("signature_invalide");
        expect(voter(m, id, 1, "approuve", MIN, "x".repeat(1025)).reason).to.equal("motif_trop_long");
        expect(voter(m, id, 4, "approuve", MIN).reason).to.equal("hors_jeu");
      },
    });

    exigence(["EX-9.11", "EX-9.12"], "remise conforme à SG-1 à SG-7 avant livraison (contrôle propre du service)", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        const remise = voter(m, id, 2, "approuve", MIN + 1).remises[0];
        const t = m.tickets.get(id);
        const ctx = { org_id: ORG_ID, journal_id: JOURNAL_ID, retained: [{ seq: 5, ticket: id, hash: t.request.request_hash, ts: t.request.request_ts, launched_by: DEMANDEUR }], decided: [], expire_after_ms: 3600000, separation: politiqueParcours().separation, write_at: at(2 * MIN) };
        expect(verifierRemise(remise, ctx).result).to.equal("scelle");
      },
      echec() {
        const m = nouvelleMachine({ self_approval: "permise" });
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 3, "approuve", MIN);
        const remise = voter(m, id, 1, "approuve", MIN + 1).remises[0];
        const t = m.tickets.get(id);
        // la même remise, jugée sous une politique « interdite », échoue SG-7
        const ctx = { org_id: ORG_ID, journal_id: JOURNAL_ID, retained: [{ seq: 5, ticket: id, hash: t.request.request_hash, ts: t.request.request_ts, launched_by: DEMANDEUR }], decided: [], expire_after_ms: 3600000, separation: politiqueParcours().separation, write_at: at(2 * MIN) };
        expect(verifierRemise(remise, ctx)).to.include({ result: "refuse", reason: "auto_approbation" });
      },
    });
  });

  // ------------------------------------------------------------------ §10 Séparation

  describe("§10 séparation des tâches", function () {
    exigence(["EX-10.1", "EX-10.2", "EX-10.3", "EX-10.5"], "adresses déclarées du demandeur inéligibles sous interdite ; séparation vide signalée", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(m.tickets.get(id).eligible).to.deep.equal([adresse(1), adresse(2)].sort());
        expect(voter(m, id, 3, "approuve", MIN).reason).to.equal("auto_approbation");
      },
      echec() {
        const m = nouvelleMachine({ self_approval: "permise" });
        const id = ouvrirTicket(m, paiement("7400.00"));
        expect(voter(m, id, 3, "approuve", MIN).accepted).to.equal(true);
        const m2 = nouvelleMachine();
        ouvrirTicket(m2, paiement("7400.00"), 0, { launched_by: "identite-de-service" });
        expect(m2.journal.some((x) => x.type === "separation_non_verifiable")).to.equal(true);
      },
    });

    exigence("EX-10.4", "récusation : retire l'approbation, garde le refus compté", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        entree(m, "recuser", 2 * MIN, { ticket: id, approver: adresse(1), session_identity: SESSIONS[1] });
        expect(m.tickets.get(id).votes[0]).to.include({ status: "ecarte", cause: "recuse" });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "refuse", MIN);
        entree(m, "recuser", 2 * MIN, { ticket: id, approver: adresse(1), session_identity: SESSIONS[1] });
        expect(m.tickets.get(id).votes[0].status).to.equal("courant");
        expect(entree(m, "recuser", 3 * MIN, { ticket: id, approver: adresse(1), session_identity: SESSIONS[1] }).reason).to.equal("recuse");
      },
    });

    exigence(["EX-10.10", "EX-10.11"], "réglages de configuration sans effet sur le jeu, le seuil ou l'échéance d'un ticket", {
      async reussite() {
        const dir = repertoireTemporaire();
        let id;
        let avant;
        await avecService({ dir, max_open_tickets: 20 }, async ({ client, service }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          id = (await client.evaluer(demande(paiement("7400.00")))).ticket;
          avant = JSON.stringify(service.machine.tickets.get(id));
        });
        await avecService({ dir, max_open_tickets: 1, set_poll_interval_ms: 5000 }, async ({ service }) => {
          expect(JSON.stringify(service.machine.tickets.get(id))).to.equal(avant);
        });
      },
      echec() {
        expect(controlerConfiguration({ ...ecrireConfiguration(repertoireTemporaire(), { socket: false }).config, max_open_tickets: 0 })).to.include("/max_open_tickets : entier de 1 à 10 000");
      },
    });
  });

  // ------------------------------------------------------------------ §11 Attente (part du service)

  describe("§11 attente (part du service)", function () {
    exigence(["EX-11.4", "EX-11.5"], "mode retenir : held marque l'approbation servie ; la ré-émission reçoit en_attente", {
      reussite() {
        const m = nouvelleMachine({ mode: "retenir" });
        const id = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, id, MIN, true);
        expect(m.tickets.get(id).served_at).to.equal(at(MIN + 2100));
        expect(entree(m, "evaluer", 3 * MIN, { request: demande(paiement("7400.00")) }).response.ticket_state).to.equal("en_attente");
      },
      echec() {
        const m = nouvelleMachine({ mode: "retenir" });
        const id = ouvrirTicket(m, paiement("7400.00"));
        approuverEtSceller(m, id, MIN, false);
        expect(m.tickets.get(id).served_at).to.equal(null);
      },
    });

    exigence("EX-11.15", "passage d'observation à un autre mode par charger ; tickets créés sous la nouvelle version", {
      reussite() {
        const m = nouvelleMachine({ mode: "observation" });
        m.ajouterVersion({ ...m.version(V1), policy_version: "v2", approval: { ...m.version(V1).approval, mode: "erreur" } });
        entree(m, "charger", 0, { policy_version: "v2" });
        expect(entree(m, "evaluer", 1, { request: demande(paiement("7400.00"), { pv: "v2" }) }).response.ticket_state).to.equal("nouveau");
      },
      echec() {
        const m = nouvelleMachine({ mode: "observation" });
        expect(entree(m, "evaluer", 1, { request: demande(paiement("7400.00")) }).response.ticket).to.equal(null);
      },
    });
  });

  // ------------------------------------------------------------------ §12 Interface

  describe("§12 interface", function () {
    exigence(["EX-12.1", "EX-12.2"], "HTTP POST /v0/<méthode>, JSON strict, clé inconnue refusée, jeton porteur", {
      async reussite() {
        await avecService({}, async ({ inst, cfg }) => {
          const r = await requeteBrute(inst.noyau, { chemin: "/v0/decisions", entetes: { "content-type": "application/json", authorization: `Bearer ${cfg.jetonNoyau}` }, corps: '{"wait_ms":0}' });
          expect(r).to.include({ statut: 200 });
          expect(r.json).to.deep.equal({ remises: [] });
        });
      },
      async echec() {
        await avecService({}, async ({ inst, cfg }) => {
          const auth = { "content-type": "application/json", authorization: `Bearer ${cfg.jetonNoyau}` };
          expect((await requeteBrute(inst.noyau, { chemin: "/v0/decisions", entetes: { "content-type": "application/json" }, corps: '{"wait_ms":0}' })).statut).to.equal(401);
          expect((await requeteBrute(inst.noyau, { chemin: "/v0/decisions", entetes: auth, corps: '{"wait_ms":0,"wait_ms":1}' })).json.error.code).to.equal("requete_invalide");
          expect((await requeteBrute(inst.noyau, { chemin: "/v0/decisions", entetes: auth, corps: '{"wait_ms":0,"x":1}' })).json.error.code).to.equal("requete_invalide");
          expect((await requeteBrute(inst.noyau, { chemin: "/v0/decisions", entetes: { ...auth, "content-type": "text/plain" }, corps: '{"wait_ms":0}' })).json.error.code).to.equal("requete_invalide");
        });
        // TLS exigé hors de la boucle locale
        const c = ecrireConfiguration(repertoireTemporaire(), { socket: false }).config;
        expect(controlerConfiguration({ ...c, noyau: { tcp: { host: "approbation.exemple", port: 1 }, token: { file: "x" } } })).to.include("/noyau/tcp : TLS exigé hors de la boucle locale");
      },
    });

    exigence("EX-12.2", "mTLS : certificat client de l'autorité de la configuration exigé", (() => {
      const pki = () => {
        const d = repertoireTemporaire();
        const ssl = (args) => execFileSync("openssl", args, { cwd: d, stdio: "ignore" });
        ssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=autorite-test", "-days", "2"]);
        for (const n of ["serveur", "client"]) {
          ssl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", `${n}.key`, "-out", `${n}.csr`, "-subj", `/CN=${n === "serveur" ? "localhost" : "noyau"}`]);
          fs.writeFileSync(path.join(d, `${n}.ext`), n === "serveur" ? "subjectAltName=DNS:localhost\n" : "extendedKeyUsage=clientAuth\n");
          ssl(["x509", "-req", "-in", `${n}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", `${n}.pem`, "-days", "2", "-extfile", `${n}.ext`]);
        }
        return d;
      };
      const appel = (port, d, avecClient) => new Promise((ok, ko) => {
        const lire = (f) => fs.readFileSync(path.join(d, f));
        const req = https.request({ host: "localhost", port, method: "POST", path: "/v0/decisions", ca: lire("ca.pem"), ...(avecClient ? { cert: lire("client.pem"), key: lire("client.key") } : {}), headers: { "content-type": "application/json" } }, (res) => {
          const m = [];
          res.on("data", (x) => m.push(x));
          res.on("end", () => ok({ statut: res.statusCode, corps: Buffer.concat(m).toString() }));
        });
        req.on("error", ko);
        req.end('{"wait_ms":0}');
      });
      const lancer = async (d) => {
        const cfg = ecrireConfiguration(d, { socket: false });
        const c = { ...cfg.config, noyau: { tcp: { host: "localhost", port: 0 }, tls: { cert: path.join(d, "serveur.pem"), key: path.join(d, "serveur.key"), client_ca: path.join(d, "ca.pem") }, token: null } };
        return demarrerService({ config: c, secrets: { cle: N.sha256(N.utf8(d)), jetonNoyau: null, jetonConsole: cfg.jetonConsole }, base: d });
      };
      return {
        async reussite() {
          const d = pki();
          const inst = await lancer(d);
          try {
            expect(await appel(inst.noyau.port, d, true)).to.deep.equal({ statut: 200, corps: '{"remises":[]}' });
          } finally {
            await inst.arreter();
          }
        },
        async echec() {
          const d = pki();
          const inst = await lancer(d);
          try {
            const e = await appel(inst.noyau.port, d, false).then((r) => r, (x) => x);
            expect(e instanceof Error || e.statut === 401).to.equal(true);
          } finally {
            await inst.arreter();
          }
        },
      };
    })());

    exigence(["EX-12.4", "EX-12.13"], "canal de la console distinct : jeton distinct, méthodes de chaque canal refusées sur l'autre, identité canonique", {
      async reussite() {
        await avecService({}, async ({ inst, cfg }) => {
          const r = await appelConsole(inst.console, cfg.jetonConsole, "retirer", { ticket: "apr-0999", by: SESSIONS.admin, reason: null, session_identity: SESSIONS.admin });
          expect(r.corps.error.code).to.equal("ticket_inconnu");
        });
      },
      async echec() {
        await avecService({}, async ({ inst, cfg }) => {
          expect((await appelConsole(inst.console, cfg.jetonNoyau, "voter", {})).statut).to.equal(401);
          expect((await appelConsole(inst.console, cfg.jetonConsole, "evaluer", {})).corps.error.code).to.equal("requete_invalide");
          const n = await requeteBrute(inst.noyau, { chemin: "/v0/voter", entetes: { "content-type": "application/json", authorization: `Bearer ${cfg.jetonNoyau}` }, corps: "{}" });
          expect(n.json.error.code).to.equal("requete_invalide");
          const i = await appelConsole(inst.console, cfg.jetonConsole, "retirer", { ticket: "apr-0999", by: "x", reason: null, session_identity: "u.martin@assureur-demo.example" });
          expect(i.corps.error.code).to.equal("identite_invalide");
        });
      },
    });

    exigence(["EX-12.6", "EX-12.9"], "sept combinaisons d'evaluer ; acquitter scelle, temporaire, refuse", {
      async reussite() {
        await avecService({}, async ({ client }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          for (const [args, d] of [[paiement("800"), "autorise"], [paiement("800", { currency: "EUR" }), "refuse"], [paiement("7400.00"), "a_approuver"]]) {
            const r = await client.evaluer(demande(args));
            expect(Object.keys(r).sort()).to.deep.equal(["approval", "approver_set", "decision", "rule", "ticket", "ticket_state"]);
            expect(r.decision).to.equal(d);
          }
        });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        voter(m, id, 1, "approuve", MIN);
        const remise = voter(m, id, 2, "approuve", MIN + 1).remises[0];
        // acquitter refuse d'une autre raison (T16) : votes de la remise écartés, retour en ouvert
        const r = entree(m, "acquitter", 2 * MIN, { remise_id: remise.remise_id, ticket: id, result: "refuse", reason: "signature_invalide", seq: null, hash: null, at: null, decision: null, held: null, approval: null });
        expect(r.response).to.deep.equal({ ticket: id, state: "ouvert" });
        expect(m.tickets.get(id).votes.map((v) => v.cause)).to.deep.equal(["remise_refusee", "remise_refusee"]);
      },
    });

    exigence(["EX-12.8", "EX-12.12"], "attente longue de decisions ; GET /v0/etat", {
      async reussite() {
        await avecService({}, async ({ client, inst, cfg }) => {
          await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
          const r = await client.evaluer(demande(paiement("7400.00")));
          const ret = retenue({ requete: demande(paiement("7400.00")), rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
          await client.ouvrir(ret.ouvrir);
          const attente = client.decisions({ wait_ms: 5000 });
          for (const i of [1, 2]) {
            const sig = signerVote(i, { decision: "approuve", ticket: r.ticket, request_hash: ret.evenement.hash });
            await appelConsole(inst.console, cfg.jetonConsole, "voter", { ticket: r.ticket, approver: adresse(i), decision: "approuve", signature: sig, reason: null, session_identity: SESSIONS[i] });
          }
          const d = await attente;
          expect(d.remises).to.have.length(1);
          const e = await requeteBrute(inst.noyau, { methode: "GET", chemin: "/v0/etat", entetes: { authorization: `Bearer ${cfg.jetonNoyau}` } });
          expect(e.json).to.deep.equal({ ready: true, set_read_at: null, open_tickets: 1 });
        });
      },
      async echec() {
        await avecService({}, async ({ client, inst, cfg }) => {
          const debut = Date.now();
          expect(await client.decisions({ wait_ms: 300 })).to.deep.equal({ remises: [] });
          expect(Date.now() - debut).to.be.at.least(250);
          expect((await rejet(client.decisions({ wait_ms: 25001 }))).code).to.equal("requete_invalide");
          const e = await requeteBrute(inst.noyau, { methode: "GET", chemin: "/v0/etat", entetes: { authorization: `Bearer ${cfg.jetonNoyau}` } });
          expect(e.json.ready).to.equal(false); // aucune version chargée
        });
      },
    });

    exigence(["EX-12.10", "EX-12.11"], "consommer final ; expiration scellée par le noyau seul (T17)", {
      reussite() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const approval = { decision: "expire", ticket: id, request_hash: hashDemande(id), threshold: { required: 2, size: 3 }, approvers: [], signatures: [], at: at(3600000 + 2100), reason: "expire par l'enregistreur, service d'approbation sans reponse" };
        const r = entree(m, "expiration", 3600000 + 2200, { ticket: id, seq: 9, hash: hashEvenement(9), at: approval.at, approval });
        expect(r.response).to.deep.equal({ ticket: id, state: "expire" });
      },
      echec() {
        const m = nouvelleMachine();
        const id = ouvrirTicket(m, paiement("7400.00"));
        const approval = { decision: "expire", ticket: id, request_hash: hashDemande(77), threshold: { required: 2, size: 3 }, approvers: [], signatures: [], at: at(MIN), reason: "x" };
        expect(entree(m, "expiration", MIN, { ticket: id, seq: 9, hash: hashEvenement(9), at: approval.at, approval }).reason).to.equal("requete_invalide");
        expect(entree(m, "consommer", MIN, { ticket: "apr-0999", seq: 9, hash: hashEvenement(9) }).reason).to.equal("ticket_inconnu");
      },
    });
  });

  // ------------------------------------------------------------------ §14.6

  describe("§14.6 déni de service par tickets", function () {
    exigence("EX-14.1", "plafond de tickets non décidés par launched_by ; ré-émission non concernée", {
      reussite() {
        const m = nouvelleMachine({ max_open_tickets: 1 });
        ouvrirTicket(m, paiement("7400.00"));
        expect(entree(m, "evaluer", MIN, { request: demande(paiement("7400.00")) }).response.ticket_state).to.equal("en_attente");
        expect(entree(m, "evaluer", MIN, { request: demande(paiement("7400.00"), { launched_by: "autre@x" }) }).accepted).to.equal(true);
      },
      echec() {
        const m = nouvelleMachine({ max_open_tickets: 1 });
        ouvrirTicket(m, paiement("7400.00"));
        expect(entree(m, "evaluer", MIN, { request: demande(paiement("7400.01")) }).reason).to.equal("plafond_atteint");
        expect(m.journal.some((x) => x.type === "plafond_atteint")).to.equal(true);
      },
    });
  });

  // ------------------------------------------------------------------ couverture

  describe("couverture des exigences du lot", function () {
    // Exigences hors du service, avec la raison ; tout autre EX- des sections
    // 3 à 12 et EX-14.x doit être testé ci-dessus.
    const ATTRIBUEES = {
      "EX-7.14": "annulation par l'hôte : aucun message ne la transmet au service en v0 (section 16) ; le ticket reste ouvert (testé par EX-7.16)",
      "EX-7.30": "chiffrement de l'état de la révision 0.5 de CT-3 (données associées de nature et de numéro, disposition sous state_dir/etat) : service (étape 6) ; le chiffrement actuel est exercé par EX-7.22 à EX-7.24",
      "EX-8.10": "CT-6 inchangé : rien à faire dans le service",
      "EX-9.4": "affichage de la console (étape 6)",
      "EX-9.5": "console (étape 6)",
      "EX-9.6": "console (étape 6) ; le service garde l'événement retenue et la pièce (contrôlés à ouvrir, test hostile)",
      "EX-9.7": "console et portefeuille (étape 6)",
      "EX-9.8": "console (étape 6)",
      "EX-9.9": "recommandation à l'approbateur",
      "EX-9.15": "contrôles de la console (étape 6)",
      "EX-9.16": "console (étape 6)",
      "EX-9.17": "console (étape 6) ; condensés du service : condenseA, servis par consulter à l'étape 6",
      "EX-9.18": "console (étape 6)",
      "EX-9.19": "console (étape 6)",
      "EX-9.20": "consignes de la console (étape 6)",
      "EX-9.21": "console (étape 6)",
      "EX-10.12": "document configuration-approbation-v0 et ses règles hors schéma : service (étape 6) ; la configuration actuelle est exercée par EX-10.10",
      "EX-10.13": "configuration du serveur de console (étape 6)",
      "EX-11.1": "configuration du démon (CT-2 §15.6)",
      "EX-11.2": "configuration du démon",
      "EX-11.3": "mandataire (frontal MCP)",
      "EX-11.6": "mandataire",
      "EX-11.7": "signal d'approbation du mandataire (CT-2 EX-4.49)",
      "EX-11.8": "mandataire",
      "EX-11.9": "fichiers d'intégration des hôtes",
      "EX-11.10": "mandataire",
      "EX-12.14": "méthode consulter (étape 6) ; son contrôle d'identité est rejoué par controles-canal.json",
      "EX-12.15": "vue du ticket (étape 6)",
      "EX-12.17": "méthode annuaire (étape 6)",
      "EX-12.18": "méthodes de l'annuaire (étape 6) ; l'annuaire n'est lu ici que pour le contrôle du canal",
      "EX-12.21": "méthode tickets de la révision 0.5 (contest_ms, contest, related) : service (étape 6)",
      "EX-14.2": "regroupement des notifications et affichage de la console (étape 6)",
    };
    it("chaque EX- des sections 3 à 12 et 14.6 est testé ou attribué", function () {
      const texte = fs.readFileSync(path.join(SPEC, "CT-3-approbations.md"), "utf8");
      const debut = texte.indexOf("## 3. Modèle");
      const fin = texte.indexOf("## 13. Console d'approbation");
      const ids = new Set([...texte.slice(debut, fin).matchAll(/^\*\*(EX-\d+\.\d+)\*\*/gm)].map((m) => m[1]));
      for (const m of texte.slice(texte.indexOf("### 14.6"), texte.indexOf("### 14.7")).matchAll(/^\*\*(EX-\d+\.\d+)\*\*/gm)) ids.add(m[1]);
      const manquants = [...ids].filter((id) => !couverts.has(id) && !ATTRIBUEES[id]);
      expect(manquants, "exigences ni testées ni attribuées").to.deep.equal([]);
      expect([...couverts].filter((x) => x.startsWith("TK-")).sort()).to.include.members(["TK-1", "TK-2", "TK-3", "TK-4", "TK-5", "TK-6", "TK-7", "TK-8", "TK-9", "TK-10", "TK-11", "TK-12", "TK-13"]);
      this.test.title += ` (${[...ids].filter((id) => couverts.has(id)).length} testées, ${Object.keys(ATTRIBUEES).length} attribuées)`;
    });
  });
});
