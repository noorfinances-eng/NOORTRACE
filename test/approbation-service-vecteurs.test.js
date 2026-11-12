// Rejeu des vecteurs de CT-3 (spec/vecteurs/ct-3) par le service
// d'approbation (@noortrace/approbation), écrit d'après le seul texte de la
// spécification. Familles rejouées :
//   - politiques, politiques-invalides : validation d'EX-4.2 et d'EX-8.2 ;
//   - evaluation, candidats, acceptation : EVALUER (§6) et CANDIDATS (EX-4.11) ;
//   - tickets : machine à états (§7, §8, §10), entrée par entrée, puis de
//     nouveau avec une reprise depuis les seuls documents après chaque pas
//     (TK-12), documents conformes à `ticket-v0` ;
//   - decisions : vérification d'une remise SG-1 à SG-7 (EX-9.11) ;
//   - signatures : normalisation d'EX-9.3 ;
//   - annuaire/controles-canal.json et annuaire/annuaires : contrôle de
//     l'identité de session du canal de la console (EX-12.14 à EX-12.19).
// Puis les vecteurs de CT-2 qui portent une réponse du service :
// pieces-mcp/appels/approbation-* et evenements/journal-demo (seq 5 à 7).
// Le dernier bloc est l'inventaire : il dit, fichier par fichier, ce qui est
// rejoué et ce qui relève de l'étape 6 (console), et échoue si un fichier
// n'est ni rejoué ni attribué.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  validerPolitique, evaluer, candidats, Machine, verifierRemise, normaliserSignature, adresseDuVote, annuaireConforme, controleCanal,
  registreSchemas, IDS, FICHIERS_SCHEMAS, REPERTOIRE_SCHEMAS, jeuExploitable,
} from "@noortrace/approbation";
import { VECTEURS_CT3, VECTEURS_CT2, SPEC, lireCt3, machineDeTrace, signerVote } from "./fixtures/approbation-service/outils.mjs";

const consommes = new Set();
const json = (rel) => {
  consommes.add(rel);
  return lireCt3(rel);
};
const lister = (rel) => fs.readdirSync(path.join(VECTEURS_CT3, rel)).sort();

describe("service d'approbation : vecteurs de CT-3", function () {
  describe("schémas embarqués", function () {
    it("sont les copies exactes de spec/schemas", function () {
      for (const f of FICHIERS_SCHEMAS) {
        expect(fs.readFileSync(path.join(REPERTOIRE_SCHEMAS, f)).equals(fs.readFileSync(path.join(SPEC, "schemas", f))), f).to.equal(true);
      }
    });
  });

  describe("constantes (A.2)", function () {
    it("comptes, organisation, journal", function () {
      const c = json("constantes.json");
      for (const a of c.accounts) expect(N.adresseDepuisClePrivee(N.hexVersOctets(a.private_key, 32))).to.equal(a.address);
      expect(N.octetsVersHex(N.keccak256(N.utf8(c.organization.slug)))).to.equal(c.organization.org_id);
      expect(N.octetsVersHex(N.keccak256(N.utf8(c.journal.name)))).to.equal(c.journal.journal_id);
    });
  });

  describe("politiques (AP-1 à AP-4, A.4)", function () {
    for (const f of lister("politiques")) {
      it(`politiques/${f} est valide`, function () {
        const P = json(`politiques/${f}`);
        expect(registreSchemas().estValide(IDS.politique, P)).to.equal(true);
        expect(validerPolitique(P, { environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
      });
    }
    it("politiques-invalides : liste complète des erreurs, triée (attendu.json)", function () {
      const att = json("politiques-invalides/attendu.json");
      const fichiers = lister("politiques-invalides").filter((f) => f !== "attendu.json");
      expect(att.cases.map((c) => c.file).sort()).to.deep.equal(fichiers);
      for (const c of att.cases) {
        const P = json(`politiques-invalides/${c.file}`);
        expect(validerPolitique(P, { environment: c.environment, expire_after_ms: c.expire_after_ms }), c.file).to.deep.equal(c.errors);
      }
    });
  });

  describe("évaluation (AP-5 à AP-17, §6)", function () {
    for (const f of lister("evaluation")) {
      it(`evaluation/${f}`, function () {
        const e = json(`evaluation/${f}`);
        const P = json(e.policy);
        for (const c of e.cases) {
          const { fenetre, ...sortie } = evaluer(P, c.request, c.windows, N.decoderHorodatage(c.t));
          expect(sortie, c.id).to.deep.equal(c.expected);
          // la fenêtre consommée est celle que nomme la marque de policy.rule
          if (fenetre !== null) expect(c.expected.rule).to.contain(` [fenetre ${fenetre} `);
        }
      });
    }
    for (const f of lister("candidats")) {
      it(`candidats/${f}`, function () {
        const e = json(`candidats/${f}`);
        const P = json(e.policy);
        for (const c of e.cases) expect(candidats(P, c.tools), c.id).to.deep.equal(c.approval_candidates);
      });
    }
    it("épreuve d'acceptation : dix cas, décisions de acceptation-attendu.json (A.5)", function () {
      const att = json("acceptation-attendu.json");
      const P = json(att.policy);
      expect(lister("acceptation/cas")).to.have.length(10);
      for (const x of att.expected) {
        const cas = json(`acceptation/cas/${x.id}.json`);
        const r = evaluer(P, cas.request, [], N.decoderHorodatage("2026-11-12T10:00:00.000Z"));
        expect({ rule: r.rule, decision: r.decision }, x.id).to.deep.equal({ rule: x.rule, decision: x.decision });
      }
      // gabarit de réponse des relecteurs : forme seulement (l'épreuve est humaine)
      const g = json("acceptation/gabarit-reponse.json");
      expect(g).to.have.property("answers");
      consommes.add("acceptation/consigne.md");
    });
  });

  describe("tickets (TK-1 à TK-13, A.6)", function () {
    for (const f of lister("tickets")) {
      it(`tickets/${f}`, function () {
        const tr = json(`tickets/${f}`);
        expect(registreSchemas().estValide(`${IDS.ticket}#/$defs/trace`, tr)).to.equal(true);
        for (const reprise of [false, true]) {
          let { m, p, version } = machineDeTrace(tr);
          tr.steps.forEach((s, k) => {
            if (s.input.kind === "charger" && !m.version(s.input.data.policy_version)) m.ajouterVersion(version(s.input.data.policy_version));
            const r = m.entree(s.input, { evaluation: s.input.kind === "evaluer" ? s.input.data.evaluation : undefined });
            const obtenu = { tickets: m.etats(), accepted: r.accepted, reason: r.reason, response: r.response, remises: r.remises, windows: m.copieFenetres() };
            expect(obtenu, `${f} pas ${k + 1} (${s.input.kind}${reprise ? ", reprise" : ""})`).to.deep.equal(s.expected);
            for (const t of m.tickets.values()) {
              const v = registreSchemas().valider(`${IDS.ticket}#/$defs/ticket`, t);
              expect(v.valide, `${f} ${t.ticket} : ${JSON.stringify(v.erreurs[0])}`).to.equal(true);
            }
            for (const r2 of r.remises) expect(jeuExploitable(r2.approver_set)).to.equal(true);
            if (reprise) m = Machine.restaurer(p, JSON.parse(JSON.stringify(m.exporter())));
          });
        }
      });
    }
  });

  describe("décisions (SG-1 à SG-7, A.7) et signatures (A.8)", function () {
    for (const d of ["valides", "invalides"]) {
      it(`decisions/${d}`, function () {
        for (const f of lister(`decisions/${d}`)) {
          const c = json(`decisions/${d}/${f}`);
          const r = verifierRemise(c.remise, c.context);
          expect({ result: r.result, reason: r.reason }, f).to.deep.equal(c.expected);
          if (c.check !== null && !f.startsWith("ordre-")) expect(r.check, f).to.equal(c.check);
          if (d === "valides") expect(registreSchemas().estValide(`${IDS.ticket}#/$defs/remise`, c.remise), f).to.equal(true);
        }
      });
    }
    it("ct1-apr-2201 : la remise augmentée de at redonne l'approval de CT-1 (EX-A.8)", function () {
      const c = json("decisions/valides/ct1-apr-2201.json");
      const evs = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-1", "journal-valide", "evenements.json"), "utf8"));
      const e6 = (Array.isArray(evs) ? evs : evs.events).find((e) => e.seq === 6);
      expect({ ...c.remise.approval, at: e6.approval.at }).to.deep.equal(e6.approval);
    });
    it("signatures/normalisation.json : forme normalisée ou refus, même adresse", function () {
      const n = json("signatures/normalisation.json");
      const champs = { decision: "approuve", ticket: "apr-0001", request_hash: N.ZERO32, org_id: N.ZERO32, journal_id: N.ZERO32 };
      for (const c of n.cases) {
        const r = normaliserSignature(c.signature);
        expect(r, c.id).to.equal(c.expected);
        expect(r === null ? "signature_invalide" : null, c.id).to.equal(c.reason);
      }
      // les formes acceptées d'une même signature recouvrent la même adresse
      const parR = new Map();
      for (const c of n.cases.filter((x) => x.expected)) {
        const a = adresseDuVote(champs, c.expected);
        const r = c.expected.slice(0, 66);
        if (parR.has(r)) expect(a, c.id).to.equal(parR.get(r));
        else parR.set(r, a);
      }
    });
  });

  describe("annuaire : contrôle de l'identité de session sur le canal (AN-10, EX-12.14 à EX-12.19)", function () {
    it("annuaires/ : documents conformes, lus par le service", function () {
      for (const f of lister("annuaire/annuaires")) {
        const a = json(`annuaire/annuaires/${f}`);
        expect(annuaireConforme(a), f).to.equal(true);
        expect(a.org_id).to.match(/^0x[0-9a-f]{64}$/);
      }
    });
    it("controles-canal.json : première raison de controleCanal", function () {
      const c = json("annuaire/controles-canal.json");
      const a = json(`annuaire/${c.annuaire}`);
      for (const x of c.cases) expect(controleCanal(a, x.method, x.request, x.ticket), x.id).to.equal(x.expected.reason);
    });
  });

  describe("vecteurs de CT-2 portant une réponse du service", function () {
    const lire2 = (rel) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, rel), "utf8"));
    const politique = (rules) => ({
      version: 0, default: { name: "defaut : revue", description: null, level: "revue", decision: null, contest_ms: 0 }, rules,
      approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [], threshold: { required: 2, size: 3 } },
      separation: { self_approval: "interdite", identities: [] },
    });
    const machine = (org_id, journal_id, rules, epoque = "demo") => {
      const m = new Machine({ org_id, journal_id, identifiants: { mode: "epoque", epoque } });
      const P = politique(rules);
      P.approver_set.members = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"];
      m.ajouterVersion({ policy_version: "demo-2026-11", approval: { rules: P, mode: "erreur", expire_after_ms: 3600000, timeout_ms: 2000 } });
      m.fixerEnVigueur("demo-2026-11");
      return m;
    };
    const demande = (args) => ({
      tool_announced: "demo__payments.create", tool_original: "payments.create", server_alias: "demo", arguments: args, class: "ecriture",
      delegation: { launched_by: "agent-demo", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-demo-0001" },
      intent: null, code: { model: "demo/modele-demo-1", prompt_version: null, policy_version: "demo-2026-11", recorder: "0.1.0" }, context: [],
    });

    it("pieces-mcp/appels/approbation-refus : réponse refuse sans ticket", function () {
      const att = lire2("pieces-mcp/appels/approbation-refus/attendu.json");
      const m = machine(N.ZERO32, N.ZERO32, [
        { name: "paiement hors CHF", description: null, tools: ["demo__payments.create"], when: { none: [{ path: "/arguments/currency", op: "egal", value: "CHF" }] }, level: "automatique", decision: "refuse", window: null, contest_ms: null },
      ]);
      const r = m.entree({ kind: "evaluer", at: "2026-11-10T10:00:00.000Z", data: { request: demande({ amount: "8200.00", currency: "EUR" }) } });
      expect(r.response).to.deep.equal(att.approval.response);
    });

    it("pieces-mcp/appels/approbation-en-attente : ré-émission reconnue d'un ticket ouvert", function () {
      const att = lire2("pieces-mcp/appels/approbation-en-attente/attendu.json");
      const m = machine(N.ZERO32, N.ZERO32, [
        { name: "paiement > 5000 CHF", description: null, tools: ["demo__payments.create"], when: { path: "/arguments/amount", op: "strictement_superieur", value: "5000" }, level: "revue", decision: null, window: null, contest_ms: 0 },
      ]);
      m.compteur = 41;
      const args = { amount: "8200.00", beneficiary_iban: "CH9300762011623852957", claim_id: "2026-81048", currency: "CHF" };
      const r1 = m.entree({ kind: "evaluer", at: "2026-11-10T10:00:00.000Z", data: { request: demande(args) } });
      expect(r1.response.ticket).to.equal("apr-demo-0042");
      m.entree({ kind: "ouvrir", at: "2026-11-10T10:00:01.000Z", data: { ticket: "apr-demo-0042", request_hash: N.sha256Hex(N.utf8("demande")), request_seq: 5, request_ts: "2026-11-10T10:00:00.500Z" } });
      const r2 = m.entree({ kind: "evaluer", at: "2026-11-10T10:00:02.000Z", data: { request: demande(args) } });
      expect(r2.response).to.deep.equal(att.approval.response);
    });

    it("evenements/journal-demo (seq 5 à 7) : demande, remise, scellement, relais, consommation", function () {
      const evs = lire2("evenements/journal-demo/evenements.json");
      const liste = Array.isArray(evs) ? evs : evs.events;
      const [e5, e6, e7] = [5, 6, 7].map((s) => liste.find((e) => e.seq === s));
      const pieces = lire2("evenements/journal-demo/pieces.json");
      const piece = pieces.find((p) => p.sha256 === e5.execution.arguments.sha256);
      const m = machine(e5.org_id, e5.journal_id, [
        { name: "amount > 5000 CHF", description: null, tools: ["demo__payments.create"], when: { path: "/arguments/amount", op: "strictement_superieur", value: "5000" }, level: "revue", decision: null, window: null, contest_ms: 0 },
      ]);
      const requete = { ...demande({ claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" }), code: e5.code, delegation: e5.delegation };
      const r1 = m.entree({ kind: "evaluer", at: "2026-11-10T10:14:07.803Z", data: { request: requete } });
      expect(r1.response).to.include({ rule: e5.policy.rule, decision: "a_approuver", ticket: e5.policy.ticket, ticket_state: "nouveau" });
      const o = m.entree({
        kind: "ouvrir", at: "2026-11-10T10:14:07.900Z",
        data: { ticket: e5.policy.ticket, request_hash: e5.hash, request_seq: 5, request_ts: e5.ts, request_event: e5, arguments_piece: Buffer.from(piece.bytes, "utf8").toString("base64") },
      });
      expect(o.response).to.deep.equal({ ticket: "apr-demo-0001", state: "ouvert", deadline: "2026-11-10T11:14:07.805Z" });
      const champs = { ticket: "apr-demo-0001", request_hash: e5.hash, org_id: e5.org_id, journal_id: e5.journal_id, decision: "approuve" };
      m.entree({ kind: "voter", at: "2026-11-10T10:18:00.000Z", data: { ticket: "apr-demo-0001", approver: e6.approval.approvers[0], decision: "approuve", signature: signerVote(1, champs), reason: null, session_identity: null } });
      const v = m.entree({ kind: "voter", at: "2026-11-10T10:21:30.000Z", data: { ticket: "apr-demo-0001", approver: e6.approval.approvers[1], decision: "approuve", signature: signerVote(2, champs), reason: e6.approval.reason, session_identity: null } });
      expect(v.remises).to.have.length(1);
      const remise = v.remises[0];
      expect({ ...remise.approval, at: e6.approval.at }).to.deep.equal(e6.approval);
      const a = m.entree({
        kind: "acquitter", at: "2026-11-10T10:21:33.300Z",
        data: { remise_id: remise.remise_id, ticket: "apr-demo-0001", result: "scelle", reason: null, seq: 6, hash: e6.hash, at: e6.approval.at, decision: "approuve", held: false, approval: e6.approval },
      });
      expect(a.response).to.deep.equal({ ticket: "apr-demo-0001", state: "approuve" });
      const r2 = m.entree({ kind: "evaluer", at: "2026-11-10T10:21:35.020Z", data: { request: requete } });
      expect(r2.response).to.deep.equal({ rule: e5.policy.rule, decision: "autorise", ticket: "apr-demo-0001", ticket_state: "approuve", approval: e7.approval, approver_set: null });
      const c = m.entree({ kind: "consommer", at: "2026-11-10T10:21:35.500Z", data: { ticket: "apr-demo-0001", seq: 7, hash: e7.hash } });
      expect(c.response).to.deep.equal({ ticket: "apr-demo-0001", state: "consomme" });
    });
  });

  describe("inventaire", function () {
    // Familles du générateur (A.3) ; verificateur-independant/ et
    // confrontation/ ne sont pas des données et ne sont pas ouverts.
    const ETAPE_6 = {
      console: "console d'approbation (§13, étape 6)",
      "acceptation-console": "épreuve de lecture de la console (A.11, étape 6)",
      "acceptation-console-attendu.json": "épreuve de lecture de la console (A.11, étape 6)",
      "annuaire/messages.json": "inscription par preuve de possession (13.5, étape 6)",
      "annuaire/inscriptions.json": "inscription (13.5, étape 6)",
      "annuaire/domaines.json": "séparation des domaines (EX-13.16, étape 6)",
      "annuaire/traces": "opérations de l'annuaire (13.6, étape 6)",
      "annuaire/controles-vote.json": "contrôles de la console avant un vote (EX-13.18, étape 6)",
      "annuaire/exports": "annuaire exporté (EX-13.19, étape 6)",
      "INDEX.md": "index lisible, sans donnée à rejouer",
    };
    const IGNORES = new Set(["verificateur-independant", "confrontation"]);
    function listerTout(rel) {
      const p = path.join(VECTEURS_CT3, rel);
      if (fs.statSync(p).isFile()) return [rel];
      return fs.readdirSync(p).sort().flatMap((n) => listerTout(`${rel}/${n}`));
    }

    it("chaque fichier de vecteur est rejoué ou attribué à l'étape 6", function () {
      const fichiers = fs.readdirSync(VECTEURS_CT3).filter((n) => !IGNORES.has(n)).sort().flatMap((n) => listerTout(n));
      const rejoues = [];
      const etape6 = [];
      const nonAttribues = [];
      for (const f of fichiers) {
        if (consommes.has(f)) rejoues.push(f);
        else if (Object.keys(ETAPE_6).some((k) => f === k || f.startsWith(`${k}/`))) etape6.push(f);
        else nonAttribues.push(f);
      }
      expect(nonAttribues, "fichiers ni rejoués ni attribués").to.deep.equal([]);
      for (const famille of ["politiques/", "politiques-invalides/", "evaluation/", "candidats/", "tickets/", "decisions/", "signatures/", "acceptation/"]) {
        expect(rejoues.some((f) => f.startsWith(famille)), famille).to.equal(true);
      }
      this.test.title += ` (${rejoues.length} rejoués, ${etape6.length} pour l'étape 6)`;
    });
  });
});
