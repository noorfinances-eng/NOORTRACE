// Étape 8, revue de sécurité interne (service d'approbation) : bornes
// de mémoire et de temps appliquées à l'entrée (cause structurante S-1,
// module `src/bornes.mjs`). Chaque règle a son essai, rouge sur le code
// relu, et son mutant (copie du paquet sans la règle, tué par l'oracle de
// l'essai, fixture `mutants.mjs`).
//    jcsIntegral : plus d'arguments décomposés sur la pile (RangeError à 65 000 éléments)
//    uniqueItems en temps linéaire (jeu de 20 000 membres : 14 s par lecture)
//   CT-3 EX-12.14  extract écrit (?P<nom>…) compilé comme le noyau
//    extract sous une borne de temps ; un evaluer n'attend plus un consulter
//   EX-7.24  trace d'un ticket bornée : 64 refus inscrits, sans motif ni signature
//   EX-13.13   défis d'inscription bornés par identité et au total (part service)
//    instants venus du noyau validés avant tout effet
//   CT-3 EX-7.22  lecture du jeu : corps, journaux, tranches et délai total bornés

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { randomBytes } from "node:crypto";
import * as N from "@noortrace/noyau";
import * as A from "@noortrace/approbation";
import {
  ORG_ID, SESSIONS, adresse, repertoireTemporaire, politiqueParcours, messageCharger, requeteEvaluer, retenue,
  ecrireConfiguration, appelConsole, lireCt3, machineDeTrace,
} from "./fixtures/approbation-service/outils.mjs";
import { copiePaquet } from "./fixtures/approbation-service/mutants.mjs";

const { BORNES } = A;
const paiement = (montant, extra = {}) => ({ claim_id: "2026-90417", amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957", ...extra });
const ms = (f) => {
  const t0 = process.hrtime.bigint();
  const r = f();
  return { r, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
};
const S_JEU = "0x" + "35".repeat(20);
const REGISTRE = "0x" + "ff".repeat(20);
const POL_REGISTRE = { source: "registre", chain_id: 2124, registry: REGISTRE, set: S_JEU, members: null, threshold: null };

/** Service en mémoire (TCP, jetons), comme `approbation-service-hostile`. */
async function service(o = {}, demarrer = A.demarrerService, essais = undefined) {
  const dir = repertoireTemporaire("noortrace-revue-l9-");
  const cfg = ecrireConfiguration(dir, { socket: false, ...o });
  const inst = await demarrer({
    config: cfg.config, secrets: { cle: N.sha256(N.utf8(dir + "/k")), jetonNoyau: cfg.jetonNoyau, jetonConsole: cfg.jetonConsole }, base: dir, essais,
  });
  const noyau = async (methode, corps) => {
    const r = await fetch(`http://127.0.0.1:${inst.noyau.port}/v0/${methode}`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${cfg.jetonNoyau}` }, body: JSON.stringify(corps),
    });
    return { statut: r.status, json: await r.json() };
  };
  const console_ = (methode, corps) => appelConsole(inst.console, cfg.jetonConsole, methode, corps);
  const journal = () => fs.readFileSync(path.join(cfg.config.state_dir, "journal-service.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const tailleEtat = () => fs.statSync(path.join(cfg.config.state_dir, "etat", "journal.ndjson")).size;
  return { dir, cfg, inst, noyau, console: console_, journal, tailleEtat, arreter: () => inst.arreter().then(() => fs.rmSync(dir, { recursive: true, force: true })) };
}

/** Charge la politique (gabarit d'effets facultatif), crée et ouvre un ticket. */
async function ticketOuvert(s, { args = paiement("7400.00"), effects = null } = {}) {
  const ch = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
  if (effects) ch.tools = ch.tools.map((t) => (t.tool_announced === "sap__payments.create" ? { ...t, effects } : t));
  expect((await s.noyau("charger", ch)).statut).to.equal(200);
  const req = requeteEvaluer("sap__payments.create", args);
  const r = await s.noyau("evaluer", req);
  expect(r.json.decision).to.equal("a_approuver");
  const ret = retenue({ requete: req, rule: r.json.rule, ticket: r.json.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
  expect((await s.noyau("ouvrir", ret.ouvrir)).statut).to.equal(200);
  return { ticket: r.json.ticket, hash: ret.evenement.hash };
}

/** Rejoue une trace de l'annexe A.6 sur une machine donnée (classe du paquet ou d'une copie) jusqu'au pas `jusqua` exclu. */
function rejouer(Machine, tr, jusqua = tr.steps.length) {
  const { p, version } = machineDeTrace(tr);
  const m = new Machine(p);
  m.ajouterVersion(version(tr.policy_version));
  m.fixerEnVigueur(tr.policy_version);
  for (const s of tr.steps.slice(0, jusqua)) {
    if (s.input.kind === "charger" && !m.version(s.input.data.policy_version)) m.ajouterVersion(version(s.input.data.policy_version));
    m.entree(s.input, { evaluation: s.input.kind === "evaluer" ? s.input.data.evaluation : undefined });
  }
  return m;
}

const SIGNATURE_FAUSSE = (k = 0) => "0x" + (k + 1).toString(16).padStart(64, "0") + "11".repeat(32) + "1b";

describe("revue de sécurité (étape 8), service d'approbation : bornes à l'entrée (S-1)", function () {
  this.timeout(120000);
  const copies = [];
  after(() => {
    for (const c of copies) c.detruire();
  });
  const mutant = (nom, remplacements, o) => {
    const c = copiePaquet(nom, remplacements, o);
    copies.push(c);
    return c;
  };

  describe("jcsIntegral sans décomposition sur la pile", function () {
    it("un tableau d'un million d'éléments et un objet de 200 000 membres s'écrivent ; mutant qui décompose les tâches sur la pile : RangeError (tué)", async function () {
      expect(A.jcsIntegral(new Array(1000000).fill(0))).to.have.length(2000001);
      const o = {};
      for (let k = 0; k < 200000; k++) o[`k${k}`] = k;
      expect(A.jcsIntegral(o).length).to.be.above(2000000);
      const m = mutant("json-pile", [
        { fichier: "src/json.mjs", ancien: "empiler(taches, { texte: \"]\" }, { texte: \"[\" }, v);", nouveau: "pile.push({ fin: v }, { texte: \"]\" }, ...taches.reverse(), { texte: \"[\" });" },
      ]);
      const M = await m.importer("src/json.mjs");
      expect(() => M.jcsIntegral(new Array(1000000).fill(0))).to.throw(RangeError);
    });
  });

  describe("uniqueItems du validateur en temps linéaire", function () {
    const jeuLu = (members) => ({
      kind: "jeu_lu", at: "2026-11-13T08:00:00.000Z",
      data: { status: "lu", cause: null, jeu: { chain_id: 2124, registry: REGISTRE, set: S_JEU, height: 1200, block_hash: "0x" + "0d".repeat(32), threshold: { required: 2, size: members.length }, members } },
    });
    const membres = (n) => [...new Set(Array.from({ length: n }, () => "0x" + randomBytes(20).toString("hex")))].sort();

    it("entrée jeu_lu de 10 000 membres conforme en moins d'une seconde ; un doublon reste refusé ; politique à jeu statique de 65 535 membres validée en moins de 5 s", function () {
      const m = membres(10000);
      const { r, ms: duree } = ms(() => A.entreeConforme(jeuLu(m)));
      expect(r).to.equal(true);
      expect(duree, "ms").to.be.below(1000);
      const double = [...m];
      double[5000] = double[10];
      expect(A.entreeConforme(jeuLu(double))).to.equal(false);
      const grand = membres(65535);
      const P = politiqueParcours({ approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: grand, threshold: { required: 1, size: grand.length } } });
      const v = ms(() => A.registreSchemas().estValide(A.IDS.politique, P));
      expect(v.r).to.equal(true);
      expect(v.ms, "ms").to.be.below(5000);
    });

    it("mutant à la double boucle : 10 000 membres dépassent la seconde (tué)", async function () {
      const m = mutant("unique-items", [
        {
          fichier: "src/schema.mjs",
          ancien: 'if (s.uniqueItems === true && aDoublon(v)) err("uniqueItems");',
          nouveau: 'if (s.uniqueItems === true) { let double = false; for (let i = 0; i < v.length && !double; i++) for (let j = i + 1; j < v.length && !double; j++) double = egaliteJson(v[i], v[j]); if (double) err("uniqueItems"); }',
        },
      ]);
      const M = await m.importer("src/schema.mjs");
      const { ms: duree } = ms(() => M.registreSchemas().estValide(`${M.IDS.ticket}#/$defs/entree`, jeuLu(membres(10000))));
      expect(duree, "ms").to.be.above(1000);
    });
  });

  describe("CT-3 EX-12.14 : effets prévus de la vue, extract compilé comme le noyau et sous borne de temps", function () {
    const requete = { class: "ecriture", server_alias: "sap", tool_original: "payments.create" };
    const outil = (extract) => ({ effects: [{ system: "SAP", action: "ecriture", object: "/arguments/ref", extract, amount: null, currency: null }] });

    it("CT-3 EX-12.14 : (?P<ref>…) donne l'effet que le noyau évalue ; une suite (?P< échappée ou dans une classe n'est pas réécrite", function () {
      const e = A.effetsPrevus(outil("(?P<ref>PAY-[0-9]{4})"), requete, { ref: "xx PAY-2026 yy" });
      expect(e.map((x) => x.object)).to.deep.equal(["PAY-2026"]);
      expect(A.reecrireGroupesNommes("(?P<a>x)(?P<b>y)")).to.equal("(?<a>x)(?<b>y)");
      expect(A.reecrireGroupesNommes("\\(?P<a>x")).to.equal("\\(?P<a>x");
      expect(A.reecrireGroupesNommes("[(?P<]x")).to.equal("[(?P<]x");
    });

    it("CT-3 EX-12.14 : mutant sans la réécriture : aucun effet (tué)", async function () {
      const m = mutant("groupes-nommes", [{ fichier: "src/vues.mjs", ancien: "new RegExp(reecrireGroupesNommes(g.extract), \"u\")", nouveau: "new RegExp(g.extract, \"u\")" }]);
      const M = await m.importer("src/vues.mjs");
      expect(M.effetsPrevus(outil("(?P<ref>PAY-[0-9]{4})"), requete, { ref: "xx PAY-2026 yy" })).to.deep.equal([]);
    });

    it("CT-3 EX-12.14 : [0-9]+$ sur 80 000 chiffres suivis de x rend la main sous la borne, effet omis et signalé ; un extract court est évalué", function () {
      const omis = [];
      const { r, ms: duree } = ms(() => A.effetsPrevus(outil("[0-9]+$"), requete, { ref: "1".repeat(80000) + "x" }, { budgetMs: 100, omis: (x) => omis.push(x) }));
      expect(r).to.deep.equal([]);
      expect(duree, "ms").to.be.below(1000);
      expect(omis).to.deep.equal([{ member: "object", cause: "budget" }]);
      expect(A.effetsPrevus(outil("[0-9]+"), requete, { ref: "ref 2026 x" }).map((x) => x.object)).to.deep.equal(["2026"]);
      expect(BORNES.vue_budget_ms).to.be.at.most(500);
    });

    it("CT-3 EX-12.14 : mutant sans la borne : plus d'une seconde dans le fil (tué)", async function () {
      const m = mutant("execution-bornee", [{ fichier: "src/vues.mjs", ancien: "executerSousBorne(() => re.exec(objet), restant)", nouveau: "{ ok: true, valeur: re.exec(objet) }" }]);
      const M = await m.importer("src/vues.mjs");
      const { ms: duree } = ms(() => M.effetsPrevus(outil("[0-9]+$"), requete, { ref: "1".repeat(80000) + "x" }, { budgetMs: 100 }));
      expect(duree, "ms").to.be.above(1000);
    });

    it("CT-3 EX-12.14 (service réel) : un consulter d'un argument de 60 000 chiffres ne retarde pas un evaluer envoyé 50 ms après lui ; l'omission est consignée", async function () {
      const s = await service();
      try {
        const { ticket } = await ticketOuvert(s, {
          args: paiement("7400.00", { claim_id: "1".repeat(60000) + "x" }),
          effects: [{ system: "SAP", action: "ecriture", object: "/arguments/claim_id", extract: "[0-9]+$", amount: "/arguments/amount", currency: "/arguments/currency" }],
        });
        const lecture = () => requeteEvaluer("sap__claims.get", { claim_id: "2026-1" });
        const t0 = Date.now();
        const consulter = s.console("consulter", { ticket, session_identity: SESSIONS[1] }).then((x) => ({ x, ms: Date.now() - t0 }));
        await new Promise((ok) => setTimeout(ok, 50));
        const t1 = Date.now();
        const ev = s.noyau("evaluer", lecture()).then((x) => ({ x, ms: Date.now() - t1 }));
        const [c, e] = await Promise.all([consulter, ev]);
        expect(c.x.statut).to.equal(200);
        expect(c.x.corps.effects).to.deep.equal([]);
        expect(c.ms, "consulter ms").to.be.below(1000);
        expect(e.x.json.decision).to.equal("autorise");
        expect(e.ms, "evaluer ms").to.be.below(1000);
        expect(s.journal().filter((l) => l.type === "vue_effet_omis").map((l) => [l.ticket, l.cause])).to.deep.equal([[ticket, "budget"]]);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("CT-3 EX-7.24 : trace d'un ticket bornée par les entrées refusées", function () {
    const tr = () => lireCt3("tickets/signature-hors-jeu.json");
    /** Machine de la trace, rejouée jusqu'au gel du jeu du ticket apr-0001. */
    const machineFigee = (Machine) => {
      const t = tr();
      const k = t.steps.findIndex((s) => s.expected.tickets["apr-0001"] === "ouvert" && s.input.kind === "jeu_lu") + 1;
      expect(k).to.be.above(1);
      const m = rejouer(Machine, t, k);
      expect(m.tickets.get("apr-0001").approver_set).to.not.equal(null);
      return m;
    };
    const voteFaux = (k) => ({
      kind: "voter", at: `2026-11-12T09:${String(10 + Math.floor(k / 60)).padStart(2, "0")}:${String(k % 60).padStart(2, "0")}.000Z`,
      data: { ticket: "apr-0001", approver: adresse(1), decision: "approuve", signature: SIGNATURE_FAUSSE(k), reason: "x".repeat(2000), session_identity: SESSIONS[1] },
    });

    it("100 votes à signature fausse : 100 refus rendus, 64 inscrits, sans motif ni signature, le reste compté ; trace_bornee signalée une fois ; un vote valide passe encore", function () {
      const m = machineFigee(A.Machine);
      const evenements = [];
      m.evenement = (type, d) => evenements.push({ type, ...d });
      for (let k = 0; k < 100; k++) {
        const r = m.entree(voteFaux(k));
        expect([r.accepted, r.reason], `vote ${k}`).to.deep.equal([false, "signature_invalide"]);
      }
      const t = m.tickets.get("apr-0001");
      const refus = t.transitions.filter((x) => !x.accepted);
      expect(refus).to.have.length(BORNES.refus_inscrits_par_ticket);
      expect(BORNES.refus_inscrits_par_ticket).to.equal(64);
      for (const x of refus) {
        expect(x.reason).to.equal("signature_invalide");
        expect(x.data).to.not.have.any.keys("reason", "signature");
        expect(x.data).to.include({ ticket: "apr-0001", approver: adresse(1), decision: "approuve", session_identity: SESSIONS[1] });
      }
      expect(m.refusNonInscrits("apr-0001")).to.deep.equal({ signature_invalide: 36 });
      expect(evenements.filter((e) => e.type === "trace_bornee")).to.deep.equal([{ type: "trace_bornee", ticket: "apr-0001", borne: 64 }]);
      expect(A.registreSchemas().estValide(`${A.IDS.ticket}#/$defs/ticket`, t)).to.equal(true);
      // le 65e refus n'a rien changé : aucune modification à persister
      m.prendreModifications();
      m.entree(voteFaux(100));
      expect(m.prendreModifications().tickets.size).to.equal(0);
    });

    it("mutant sans la borne : 100 refus inscrits (tué) ; mutant qui inscrit les données entières : signature et motif dans la trace (tué)", async function () {
      const sansBorne = mutant("refus-borne", [{ fichier: "src/tickets.mjs", ancien: "if (n < BORNES.refus_inscrits_par_ticket)", nouveau: "if (true)" }]);
      const M1 = await sansBorne.importer("src/tickets.mjs");
      const m1 = machineFigee(M1.Machine);
      for (let k = 0; k < 100; k++) m1.entree(voteFaux(k));
      expect(m1.tickets.get("apr-0001").transitions.filter((x) => !x.accepted)).to.have.length(100);
      const entieres = mutant("refus-donnees", [{ fichier: "src/tickets.mjs", ancien: "donneesRefus(input, data)", nouveau: "data" }]);
      const M2 = await entieres.importer("src/tickets.mjs");
      const m2 = machineFigee(M2.Machine);
      m2.entree(voteFaux(0));
      expect(m2.tickets.get("apr-0001").transitions.at(-1).data).to.have.all.keys("ticket", "approver", "decision", "signature", "reason", "session_identity");
    });

    it("service réel : 100 votes refusés de 16,7 ko écrivent moins de 3 Mo dans le journal d'état (113 Mo relevés avant correction) et le ticket reste servi", async function () {
      const s = await service();
      try {
        const { ticket } = await ticketOuvert(s);
        const motif = "\u{1F512}".repeat(4096);
        const avant = s.tailleEtat();
        const raisons = {};
        for (let k = 0; k < 100; k++) {
          const x = await s.console("voter", { ticket, approver: adresse(1), decision: "approuve", signature: SIGNATURE_FAUSSE(k), reason: motif, session_identity: SESSIONS[1] });
          raisons[`${x.statut} ${x.corps?.error?.code}`] = (raisons[`${x.statut} ${x.corps?.error?.code}`] ?? 0) + 1;
        }
        expect(raisons).to.deep.equal({ "409 signature_invalide": 100 });
        expect(s.tailleEtat() - avant, "octets écrits").to.be.below(3 * 1024 * 1024);
        const v = await s.console("consulter", { ticket, session_identity: SESSIONS[1] });
        expect([v.statut, v.corps.state]).to.deep.equal([200, "ouvert"]);
        expect(s.journal().filter((l) => l.type === "trace_bornee").map((l) => l.ticket)).to.deep.equal([ticket]);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("CT-3 EX-13.13 : défis d'inscription bornés (règle du module d'annuaire) et journal d'état compacté par taille (part service)", function () {
    const identite = "oidc https://idp.assureur-demo.example employe-quelconque";
    const adr = (k) => "0x" + k.toString(16).padStart(40, "0");

    it("service réel : le 5e défi d'une identité est refusé (limite_annuaire, 409, data {}) avant tout changement d'état ; le renouvellement d'un défi passe ; refus consigné", async function () {
      const s = await service();
      try {
        for (let k = 1; k <= 4; k++) {
          const r = await s.console("preparer_inscription", { session_identity: identite, address: adr(k) });
          expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
        }
        const avant = s.tailleEtat();
        const r5 = await s.console("preparer_inscription", { session_identity: identite, address: adr(5) });
        expect([r5.statut, r5.corps.error.code, r5.corps.error.data]).to.deep.equal([409, "limite_annuaire", {}]);
        expect(r5.corps.error.message).to.match(/^[\x20-\x7e]+$/);
        expect(s.tailleEtat()).to.equal(avant);
        expect(s.inst.service.annuaire.defis.filter((d) => d.fields.identity === identite)).to.have.length(4);
        const r4 = await s.console("preparer_inscription", { session_identity: identite, address: adr(4) });
        expect(r4.statut).to.equal(200);
        expect(s.inst.service.annuaire.defis.filter((d) => d.fields.identity === identite)).to.have.length(4);
        expect((await s.console("preparer_inscription", { session_identity: `${identite}-2`, address: adr(7) })).statut).to.equal(200);
        expect(s.journal().filter((l) => l.type === "operation_annuaire_refusee").map((l) => [l.methode, l.reason])).to.deep.equal([["preparer_inscription", "limite_annuaire"]]);
      } finally {
        await s.arreter();
      }
    });

    it("mutant de la règle du module d'annuaire (copie de paquets/console sans la borne) : le service accepte le 5e défi, qui dépend donc de cette règle (tué)", async function () {
      const m = mutant("compactage-console", [], {
        console: [{
          fichier: "src/bibliotheque/annuaire.mjs",
          ancien: 'if (tenus.length >= MAX_DEFIS || tenus.filter((d) => d.fields.identity === requete.session_identity).length >= MAX_DEFIS_PAR_IDENTITE) return refus("limite_annuaire");',
          nouveau: 'if (false) return refus("limite_annuaire");',
        }],
      });
      const D = await m.importer("src/demarrage.mjs");
      const s = await service({}, D.demarrerService);
      try {
        for (let k = 1; k <= 4; k++) expect((await s.console("preparer_inscription", { session_identity: identite, address: adr(k) })).statut).to.equal(200);
        expect((await s.console("preparer_inscription", { session_identity: identite, address: adr(5) })).statut).to.equal(200);
      } finally {
        await s.arreter();
      }
    });

    it("part service : des enregistrements de défis réécrits en entier (300 défis) compactent le journal d'état par taille, qui reste sous 2 Mio au lieu de croître comme le carré du nombre d'appels", async function () {
      const s = await service({}, A.demarrerService, { compacterApresOctets: 1024 * 1024 });
      try {
        const instantane = path.join(s.cfg.config.state_dir, "etat", "instantane.chiffre");
        let pic = 0;
        for (let i = 0; i < 75; i++) {
          for (let k = 1; k <= 4; k++) {
            const r = await s.console("preparer_inscription", { session_identity: `${identite}-${i}`, address: adr(1000 + i * 4 + k) });
            expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
            pic = Math.max(pic, s.tailleEtat());
          }
        }
        expect(s.inst.service.annuaire.defis).to.have.length(300);
        expect(pic, "taille maximale du journal d'état").to.be.below(2 * 1024 * 1024);
        expect(fs.existsSync(instantane)).to.equal(true);
        expect(s.inst.service.magasin.octets).to.be.below(1024 * 1024);
        // l'état relu après arrêt porte bien les 300 défis
        const magasin = new A.MagasinEtat({ repertoire: s.cfg.config.state_dir, cle: N.sha256(N.utf8(s.dir + "/k")) });
        await s.inst.arreter();
        const docs = await magasin.ouvrir();
        expect(docs.defis).to.have.length(300);
        await magasin.fermer();
      } finally {
        await s.arreter().catch(() => {});
      }
    });

    it("mutant sans le compactage par taille : le journal dépasse 2 Mio (tué)", async function () {
      const m = mutant("compactage-taille", [{ fichier: "src/persistance.mjs", ancien: "return this.lignes >= this.compacterApres || this.octets >= this.compacterApresOctets;", nouveau: "return this.lignes >= this.compacterApres;" }]);
      const D = await m.importer("src/demarrage.mjs");
      const s = await service({}, D.demarrerService, { compacterApresOctets: 1024 * 1024 });
      try {
        for (let i = 0; i < 75; i++) {
          for (let k = 1; k <= 4; k++) expect((await s.console("preparer_inscription", { session_identity: `${identite}-${i}`, address: adr(1000 + i * 4 + k) })).statut).to.equal(200);
        }
        expect(s.tailleEtat()).to.be.above(2 * 1024 * 1024);
      } finally {
        await s.arreter();
      }
    });
  });

  describe("instants venus du noyau validés avant tout effet", function () {
    const fenetre = () => lireCt3("tickets/fenetre-ouvrante.json");
    const pasAcquitter = (t) => t.steps.findIndex((s) => s.input.kind === "acquitter" && s.input.data.ticket === "apr-0002");

    it("acquitter scelle daté du 31 février ou de l'an 9999 : requete_invalide, ticket inchangé, aucune exception ; ouvrir et expiration de même", function () {
      const t = fenetre();
      const k = pasAcquitter(t);
      expect(k).to.be.above(0);
      for (const at of ["2026-02-31T00:00:00.000Z", "9999-12-31T23:59:59.999Z", "1969-12-31T23:59:59.999Z"]) {
        const m = rejouer(A.Machine, t, k);
        const e = structuredClone(t.steps[k].input);
        e.data.at = at;
        e.data.approval.at = at;
        expect(A.entreeConforme(e), at).to.equal(true);
        const r = m.entree(e);
        expect([r.accepted, r.reason], at).to.deep.equal([false, "requete_invalide"]);
        const tk = m.tickets.get("apr-0002");
        expect([tk.state, tk.sealed, tk.recognize_until], at).to.deep.equal(["a_remettre", null, null]);
        expect(tk.current_remise).to.not.equal(null);
        expect(tk.transitions.at(-1)).to.include({ accepted: false, reason: "requete_invalide", input: "acquitter" });
        // la remise reste livrable et un acquittement bien daté passe ensuite
        expect(m.remisesCourantes().map((x) => x.remise.ticket)).to.include("apr-0002");
        expect(m.entree(t.steps[k].input).accepted).to.equal(true);
      }
      // ouvrir dont request_ts n'est pas une date du calendrier
      const js = lireCt3("tickets/jeu-statique.json");
      const ko = js.steps.findIndex((s) => s.input.kind === "ouvrir");
      const m2 = rejouer(A.Machine, js, ko);
      const o = structuredClone(js.steps[ko].input);
      o.data.request_ts = "2026-02-31T00:00:00.000Z";
      const r2 = m2.entree(o);
      expect([r2.accepted, r2.reason, m2.tickets.get(o.data.ticket).state]).to.deep.equal([false, "requete_invalide", "reserve"]);
      // expiration datée de l'an 9999
      const ex = lireCt3("tickets/expiration-noyau.json");
      const ke = ex.steps.findIndex((s) => s.input.kind === "expiration");
      const m3 = rejouer(A.Machine, ex, ke);
      const x = structuredClone(ex.steps[ke].input);
      x.data.at = "9999-12-31T23:59:59.999Z";
      x.data.approval.at = x.data.at;
      const r3 = m3.entree(x);
      expect([r3.accepted, r3.reason]).to.deep.equal([false, "requete_invalide"]);
      expect(m3.tickets.get(x.data.ticket).sealed).to.equal(null);
      expect(m3.entree(ex.steps[ke].input).accepted).to.equal(true);
    });

    it("mutant sans le contrôle de l'instant d'acquitter : le 31 février est accepté (tué)", async function () {
      const m = mutant("instant-acquitter", [{ fichier: "src/tickets.mjs", ancien: 'if (instantAdmis(d.at) === null) this.#refuser(t, at, "acquitter", d, "requete_invalide");', nouveau: "", tous: true }]);
      const M = await m.importer("src/tickets.mjs");
      const t = fenetre();
      const k = pasAcquitter(t);
      const mm = rejouer(M.Machine, t, k);
      const e = structuredClone(t.steps[k].input);
      e.data.at = "2026-02-31T00:00:00.000Z";
      e.data.approval.at = e.data.at;
      expect(mm.entree(e).accepted).to.equal(true);
    });
  });

  describe("CT-3 EX-7.22 : lecture du jeu bornée (corps, journaux, tranches, délai total)", function () {
    /** Nœud factice : jeu S de n membres, hauteur H, journaux par tranche donnés par `journaux(de, a)`. */
    function noeud({ H, n = 1, journaux = () => [], attente = 0, maxAppels = 20000 }) {
      const appels = [];
      const mot = (x) => "0x" + x.toString(16).padStart(64, "0");
      const appel = async (methode, params) => {
        appels.push(methode);
        if (appels.length > maxAppels) throw new Error("trop d'appels");
        await new Promise((ok) => (attente ? setTimeout(ok, attente) : setImmediate(ok)));
        switch (methode) {
          case "eth_chainId": return "0x84c";
          case "eth_blockNumber": return "0x" + H.toString(16);
          case "eth_getBlockByNumber": return { hash: "0x" + "0d".repeat(32) };
          case "eth_getCode": return "0x6001";
          case "eth_getLogs": return journaux(Number(BigInt(params[0].fromBlock)), Number(BigInt(params[0].toBlock)));
          case "eth_call": {
            const d = params[0].data;
            if (d.startsWith(A.SELECTEURS.curatorSetOf)) return mot(BigInt(S_JEU));
            if (d.startsWith(A.SELECTEURS.getThreshold)) return mot(1n);
            if (d.startsWith(A.SELECTEURS.getCuratorCount)) return mot(BigInt(n));
            if (d.startsWith(A.SELECTEURS.isCurator)) return mot(1n);
            throw new Error("sélecteur inconnu");
          }
          default: throw new Error(`méthode inconnue ${methode}`);
        }
      };
      return { appel, appels };
    }
    const lecteur = (nd, o = {}) => new A.LecteurJeu({ url: "http://127.0.0.1:0", org_id: ORG_ID, adressesConnues: () => [], appel: nd.appel, ...o });
    const journal = (bloc, k) => ({ address: S_JEU, topics: [A.SUJETS.CuratorAdded, "0x" + "00".repeat(12) + k.toString(16).padStart(40, "0")], blockNumber: "0x" + bloc.toString(16), logIndex: "0x" + (k % 1000).toString(16) });

    it("hauteur démesurée (2^52) : lecture illisible (etat_indisponible) en moins de 100 appels, pas une boucle de 10^11 requêtes", async function () {
      const nd = noeud({ H: 2 ** 52 });
      const r = await lecteur(nd).lire(POL_REGISTRE);
      expect([r.status, r.cause]).to.deep.equal(["illisible", "etat_indisponible"]);
      expect(nd.appels.length).to.be.below(100);
      expect(BORNES.rpc_tranches_max).to.equal(8192);
    });

    it("plus de 100 000 journaux : lecture illisible ; une lecture ordinaire reste lue", async function () {
      const trop = noeud({ H: 100000, maxAppels: 1e6, journaux: (de) => Array.from({ length: 20000 }, (_, k) => journal(de + (k % 100), de * 100000 + k)) });
      const r = await lecteur(trop).lire(POL_REGISTRE);
      expect([r.status, r.cause]).to.deep.equal(["illisible", "etat_indisponible"]);
      expect(trop.appels.filter((x) => x === "eth_call").length, "aucune reconstitution des membres").to.be.below(10);
      const un = noeud({ H: 20000, journaux: (de) => (de === 0 ? [journal(7, 1)] : []) });
      const r2 = await lecteur(un).lire(POL_REGISTRE);
      expect(r2.status).to.equal("lu");
      expect(r2.jeu.members).to.deep.equal(["0x" + (1).toString(16).padStart(40, "0")]);
    });

    it("réponse HTTP de 20 Mio : lecture illisible (etat_indisponible), corps non accumulé au-delà de la borne", async function () {
      const serveur = http.createServer((req, res) => {
        req.resume();
        const debut = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x');
        const fin = Buffer.from('"}');
        const total = 20 * 1024 * 1024;
        res.writeHead(200, { "content-type": "application/json", "content-length": debut.length + total + fin.length });
        res.write(debut);
        const bloc = Buffer.alloc(65536, 0x30);
        let ecrit = 0;
        const suite = () => {
          while (ecrit < total) {
            const b = bloc.subarray(0, Math.min(bloc.length, total - ecrit));
            ecrit += b.length;
            if (!res.write(b)) return res.once("drain", suite);
          }
          res.end(fin);
        };
        suite();
      });
      await new Promise((ok) => serveur.listen(0, "127.0.0.1", ok));
      try {
        const l = new A.LecteurJeu({ url: `http://127.0.0.1:${serveur.address().port}/`, org_id: ORG_ID, timeout_ms: 20000 });
        const r = await l.lire(POL_REGISTRE);
        expect([r.status, r.cause]).to.deep.equal(["illisible", "etat_indisponible"]);
        expect(BORNES.rpc_corps_octets).to.equal(16 * 1024 * 1024);
      } finally {
        serveur.closeAllConnections?.();
        await new Promise((ok) => serveur.close(ok));
      }
    });

    it("délai total d'une lecture : un nœud lent fait rendre etat_indisponible, le prochain sondage repart", async function () {
      const nd = noeud({ H: 1000, attente: 30 });
      const l = lecteur(nd, { timeout_ms: 1000, lecture_max_ms: 40 });
      const r = await l.lire(POL_REGISTRE);
      expect([r.status, r.cause]).to.deep.equal(["illisible", "etat_indisponible"]);
      expect(nd.appels.length).to.be.below(5);
      const rapide = noeud({ H: 1000, journaux: (de) => (de === 0 ? [journal(7, 1)] : []) });
      expect((await lecteur(rapide, { timeout_ms: 1000, lecture_max_ms: 5000 }).lire(POL_REGISTRE)).status).to.equal("lu");
      expect(new A.LecteurJeu({ url: "x", org_id: ORG_ID, timeout_ms: 5000 }).lectureMax).to.equal(5000 * BORNES.rpc_lecture_facteur);
    });

    it("mutants : sans la borne des tranches, la hauteur 2^52 coûte des milliers d'appels (tué) ; sans la borne des journaux, 140 000 journaux sont accumulés (tué)", async function () {
      const tranches = mutant("jeu-tranches", [{ fichier: "src/lecteur-jeu.mjs", ancien: "if (tranches > this.tranchesMax)", nouveau: "if (false)" }]);
      const M1 = await tranches.importer("src/lecteur-jeu.mjs");
      const nd = noeud({ H: 2 ** 52, maxAppels: 3000 });
      const r = await new M1.LecteurJeu({ url: "x", org_id: ORG_ID, adressesConnues: () => [], appel: nd.appel }).lire(POL_REGISTRE);
      expect(r.status).to.equal("illisible");
      expect(nd.appels.length).to.be.above(2000);
      const journaux = mutant("jeu-journaux", [{ fichier: "src/lecteur-jeu.mjs", ancien: "if (sortie.length > this.journauxMax)", nouveau: "if (false)" }]);
      const M2 = await journaux.importer("src/lecteur-jeu.mjs");
      const trop = noeud({ H: 100000, maxAppels: 1e6, journaux: (de) => Array.from({ length: 20000 }, (_, k) => journal(de + (k % 100), de * 100000 + k)) });
      const r2 = await new M2.LecteurJeu({ url: "x", org_id: ORG_ID, adressesConnues: () => [], appel: trop.appel }).lire(POL_REGISTRE);
      expect(r2.cause).to.equal("membres_non_reconstitues");
    });
  });
});
