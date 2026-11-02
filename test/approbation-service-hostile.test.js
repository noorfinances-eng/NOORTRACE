// Entrées hostiles contre le service d'approbation : requêtes malformées,
// signatures forgées, rejeu, approbateur hors jeu, double vote, une personne
// et deux clés, horloge qui recule, arrêt brutal pendant une transition
// (ligne tronquée, ligne corrompue, compactage interrompu, processus tué au
// milieu d'une rafale), second service sur le même répertoire d'état.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { MagasinEtat, demarrerService } from "@noortrace/approbation";
import { ClientServiceApprobation } from "@noortrace/enregistreur";
import { Wallet } from "ethers";
import {
  ORG_ID, SESSIONS, adresse, clePrivee, signerVote, repertoireTemporaire, politiqueParcours, messageCharger, requeteEvaluer, retenue,
  ecrireConfiguration, appelConsole, requeteBrute, lancerService,
} from "./fixtures/approbation-service/outils.mjs";

const V1 = "parcours-1";
const paiement = (montant, extra = {}) => ({ claim_id: "2026-90417", amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957", ...extra });

async function service(o = {}) {
  const dir = o.dir ?? repertoireTemporaire();
  const cfg = ecrireConfiguration(dir, { socket: false, ...o });
  const horloge = { decalage: 0 };
  const inst = await demarrerService({
    config: cfg.config, secrets: { cle: N.sha256(N.utf8(dir + "/k")), jetonNoyau: cfg.jetonNoyau, jetonConsole: cfg.jetonConsole },
    horloge: () => Date.now() + horloge.decalage, base: dir,
  });
  const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${inst.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
  const auth = { "content-type": "application/json", authorization: `Bearer ${cfg.jetonNoyau}` };
  return { dir, cfg, inst, client, horloge, auth };
}

/** Charge la politique, crée et ouvre un ticket ; rend ticket et événement retenue. */
async function ticketOuvert(s, args = paiement("7400.00"), ts = Date.now() - 1000) {
  await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
  const r = await s.client.evaluer(requeteEvaluer("sap__payments.create", args));
  const ret = retenue({ requete: requeteEvaluer("sap__payments.create", args), rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(ts) });
  await s.client.ouvrir(ret.ouvrir);
  return { ticket: r.ticket, hash: ret.evenement.hash, ret };
}

const vote = (s, ticket, i, decision, signature, session = SESSIONS[i], approver = adresse(i)) =>
  appelConsole(s.inst.console, s.cfg.jetonConsole, "voter", { ticket, approver, decision, signature, reason: null, session_identity: session });

const rejet = async (p) => {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("refus attendu");
};

describe("service d'approbation : entrées hostiles", function () {
  this.timeout(60000);

  describe("requêtes malformées", function () {
    let s;
    before(async () => (s = await service()));
    after(async () => s.inst.arreter());

    const brut = (corps, chemin = "/v0/evaluer", entetes = s.auth) => requeteBrute(s.inst.noyau, { chemin, entetes, corps });

    it("JSON invalide, tronqué, clé en double, substitut isolé, nombre infini, profondeur excessive : requete_invalide", async function () {
      for (const corps of ["{", "{\"a\":1,}", "[]", "null", '{"a":1,"a":2}', '{"a":"\\ud800"}', '{"a":1e400}', "[".repeat(300) + "]".repeat(300), "\xff\xfe"]) {
        const r = await brut(corps);
        expect(r.statut, corps.slice(0, 20)).to.equal(400);
        expect(r.json.error.code).to.equal("requete_invalide");
      }
    });

    it("corps au-delà de la borne, méthode HTTP, chemin et méthode inconnus", async function () {
      const gros = await requeteBrute(s.inst.noyau, { chemin: "/v0/evaluer", entetes: s.auth, corps: Buffer.alloc(16 * 1024 * 1024 + 10, 0x20) });
      expect(gros.json.error.code).to.equal("requete_invalide");
      expect((await requeteBrute(s.inst.noyau, { methode: "PUT", chemin: "/v0/evaluer", entetes: s.auth, corps: "{}" })).json.error.code).to.equal("requete_invalide");
      expect((await brut("{}", "/v0/../v0/evaluer")).json.error.code).to.equal("requete_invalide");
      expect((await brut("{}", "/v0/inconnue")).json.error.code).to.equal("requete_invalide");
      expect((await brut("{}", "/v1/evaluer")).json.error.code).to.equal("requete_invalide");
    });

    it("evaluer : membre de plus, nom annoncé hors motif, delegation incomplète", async function () {
      await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
      const d = requeteEvaluer("sap__payments.create", paiement("7400.00"));
      for (const x of [{ ...d, extra: 1 }, { ...d, tool_announced: "../x" }, { ...d, delegation: { launched_by: "x" } }, { ...d, intent: { sha256: N.ZERO32 } }]) {
        expect((await rejet(s.client.evaluer(x))).code).to.equal("requete_invalide");
      }
    });

    it("arguments hostiles : __proto__, objets profonds, grands nombres ; sans pollution ni panne", async function () {
      const args = JSON.parse('{"__proto__":{"polluted":true},"amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957","big":9007199254740993,"x":' + "[".repeat(50) + "]".repeat(50) + "}");
      const r = await s.client.evaluer(requeteEvaluer("sap__payments.create", args));
      expect(r.decision).to.equal("a_approuver");
      expect({}.polluted).to.equal(undefined);
      const r2 = await s.client.evaluer(requeteEvaluer("sap__payments.create", args));
      expect(r2.ticket).to.equal(r.ticket); // même clé : même ticket
    });

    it("charger : approval avec service, politique au substitut isolé, autre journal", async function () {
      const m = messageCharger({ policy_version: "v-x", rules: politiqueParcours() });
      expect((await rejet(s.client.charger({ ...m, approval: { ...m.approval, service: {} } }))).code).to.equal("requete_invalide");
      expect((await rejet(s.client.charger({ ...m, journal_id: N.ZERO32 }))).code).to.equal("requete_invalide");
      const texte = JSON.stringify(m).replace('"lecture autorisee"', '"lecture \\ud800"');
      expect((await requeteBrute(s.inst.noyau, { chemin: "/v0/charger", entetes: s.auth, corps: texte })).json.error.code).to.equal("requete_invalide");
      // même version, autre empreinte : refus
      await s.client.charger(m);
      expect((await rejet(s.client.charger({ ...m, policy_sha256: N.ZERO32 }))).code).to.equal("requete_invalide");
    });

    it("ouvrir : événement qui ne hache pas à request_hash, pièce qui ne correspond pas, autre ticket", async function () {
      await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
      const r = await s.client.evaluer(requeteEvaluer("sap__payments.create", paiement("6000.00")));
      const ret = retenue({ requete: requeteEvaluer("sap__payments.create", paiement("6000.00")), rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
      const autre = retenue({ requete: requeteEvaluer("sap__payments.create", paiement("6000.00")), rule: r.rule, ticket: "apr-autre", seq: 5, ts: N.ecrireHorodatage(Date.now() - 1000) });
      for (const corps of [
        { ...ret.ouvrir, request_event: { ...ret.evenement, seq: 6 } },
        { ...ret.ouvrir, arguments_piece: Buffer.from("{}").toString("base64") },
        { ...ret.ouvrir, arguments_piece: "pas du base64 !" },
        { ...autre.ouvrir, ticket: r.ticket },
        { ...ret.ouvrir, request_ts: N.ecrireHorodatage(Date.now() + 3600000) },
      ]) {
        expect((await rejet(s.client.ouvrir(corps))).code).to.equal("requete_invalide");
      }
      expect((await s.client.ouvrir(ret.ouvrir)).state).to.equal("ouvert");
    });

    it("acquitter et expiration aux données forgées : requete_invalide, état inchangé", async function () {
      const { ticket } = await ticketOuvert(s, paiement("6100.00"));
      const faux = { decision: "approuve", ticket, request_hash: N.ZERO32, threshold: { required: 1, size: 1 }, approvers: [], signatures: [], at: N.ecrireHorodatage(Date.now()), reason: null };
      expect((await rejet(s.client.acquitter({ remise_id: `${ticket}/1`, ticket, result: "scelle", reason: null, seq: 9, hash: N.ZERO32, at: faux.at, decision: "approuve", held: false, approval: faux }))).code).to.equal("requete_invalide");
      expect((await rejet(s.client.expiration({ ticket, seq: 9, hash: N.ZERO32, at: faux.at, approval: { ...faux, decision: "expire" } }))).code).to.equal("requete_invalide");
      expect(s.inst.service.machine.tickets.get(ticket).state).to.equal("ouvert");
    });
  });

  describe("signatures forgées, rejeu, hors jeu, double vote, une personne et deux clés", function () {
    let s;
    let t;
    beforeEach(async () => {
      s = await service();
      t = await ticketOuvert(s);
    });
    afterEach(async () => s.inst.arreter());

    it("signatures forgées : octets aléatoires, autre ticket, autre journal, chaîne « 0x… », v = 37, 64 octets", async function () {
      const champs = { decision: "approuve", ticket: t.ticket, request_hash: t.hash };
      const sig = signerVote(1, champs);
      const variantes = [
        N.octetsVersHex(N.sha256(N.utf8("a")).slice(0, 32)) + N.octetsVersHex(N.sha256(N.utf8("b"))).slice(2) + "1b",
        signerVote(1, { ...champs, ticket: "apr-autre" }),
        signerVote(1, { ...champs, journal_id: N.ZERO32 }),
        N.octetsVersHex(N.signerEip191(clePrivee(1), N.sha256(N.utf8("0x" + "00".repeat(32))))),
        sig.slice(0, -2) + "25",
        sig.slice(0, -2),
      ];
      // signature EIP-191 sur les 66 caractères de la chaîne D_A (piège d'EX-9.7)
      const D = N.condenseApprobation({ decision: "approuve", journal_id: s.cfg.config.journal_id, org_id: ORG_ID, request_hash: t.hash, ticket: t.ticket });
      variantes.push(new Wallet(N.octetsVersHex(clePrivee(1))).signMessageSync(N.octetsVersHex(D)).toLowerCase());
      for (const v of variantes) {
        const r = await vote(s, t.ticket, 1, "approuve", v);
        expect(r.corps.error?.code, v.slice(0, 12)).to.equal("signature_invalide");
      }
      expect((await vote(s, t.ticket, 1, "approuve", sig)).corps).to.deep.equal({ ticket: t.ticket, state: "ouvert" });
    });

    it("rejeu : vote renvoyé, décision servie une fois, remise rejouée, consommation unique", async function () {
      const sig1 = signerVote(1, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
      const sig2 = signerVote(2, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
      await vote(s, t.ticket, 1, "approuve", sig1);
      expect((await vote(s, t.ticket, 1, "approuve", sig1)).corps.error.code).to.equal("vote_identique");
      await vote(s, t.ticket, 2, "approuve", sig2);
      const { remises } = await s.client.decisions({ wait_ms: 1000 });
      const approval = { ...remises[0].approval, at: N.ecrireHorodatage(Date.now()) };
      const ack = { remise_id: remises[0].remise_id, ticket: t.ticket, result: "scelle", reason: null, seq: 6, hash: N.sha256Hex(N.utf8("e6")), at: approval.at, decision: "approuve", held: false, approval };
      await s.client.acquitter(ack);
      expect(await s.client.acquitter(ack)).to.deep.equal({ ticket: t.ticket, state: "approuve" });
      expect((await rejet(s.client.acquitter({ ...ack, seq: 99 }))).code).to.equal("requete_invalide");
      const d = requeteEvaluer("sap__payments.create", paiement("7400.00"));
      expect((await s.client.evaluer(d)).ticket_state).to.equal("approuve");
      expect((await s.client.evaluer(d)).ticket_state).to.equal("en_attente");
      await s.client.consommer({ ticket: t.ticket, seq: 7, hash: N.sha256Hex(N.utf8("e7")) });
      expect((await rejet(s.client.consommer({ ticket: t.ticket, seq: 8, hash: N.sha256Hex(N.utf8("e8")) }))).code).to.equal("requete_invalide");
      const nouveau = await s.client.evaluer(d);
      expect(nouveau.ticket).to.not.equal(t.ticket);
      // un vote de l'ancien ticket rejoué sur le nouveau : autre D_A
      const ret = retenue({ requete: d, rule: nouveau.rule, ticket: nouveau.ticket, seq: 8, ts: N.ecrireHorodatage(Date.now() - 500) });
      await s.client.ouvrir(ret.ouvrir);
      expect((await vote(s, nouveau.ticket, 1, "approuve", sig1)).corps.error.code).to.equal("signature_invalide");
    });

    it("approbateur hors jeu, une personne et deux clés, double vote concurrent", async function () {
      // compte 4 : adresse révoquée de l'approbateur 2 dans l'annuaire, hors du jeu
      const sig4 = signerVote(4, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
      expect((await vote(s, t.ticket, 2, "approuve", sig4, SESSIONS[2], adresse(4))).corps.error.code).to.equal("session_non_autorisee");
      // la session 2 présente la signature valide du compte 1 : refusée sur le canal
      const sig1 = signerVote(1, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
      expect((await vote(s, t.ticket, 2, "approuve", sig1, SESSIONS[2], adresse(1))).corps.error.code).to.equal("session_non_autorisee");
      // le demandeur (compte 3, adresse déclarée) : auto_approbation
      const sig3 = signerVote(3, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
      expect((await vote(s, t.ticket, 3, "approuve", sig3)).corps.error.code).to.equal("auto_approbation");
      // deux votes identiques concurrents : un seul inscrit
      const [a, b] = await Promise.all([vote(s, t.ticket, 1, "approuve", sig1), vote(s, t.ticket, 1, "approuve", sig1)]);
      expect([a.statut, b.statut].sort()).to.deep.equal([200, 409]);
      expect(s.inst.service.machine.tickets.get(t.ticket).votes.filter((v) => v.status === "courant")).to.have.length(1);
      // un approbateur ne compte qu'une fois : la décision exige deux adresses distinctes
      expect(s.inst.service.machine.tickets.get(t.ticket).state).to.equal("ouvert");
    });
  });

  describe("horloge qui recule", function () {
    it("aucune entrée n'est datée avant la précédente ; un ticket échu ne rouvre pas", async function () {
      const s = await service();
      try {
        const t = await ticketOuvert(s);
        s.horloge.decalage = 3600000 + 5000; // au-delà de l'échéance
        await s.inst.service.tic();
        expect(s.inst.service.machine.tickets.get(t.ticket).state).to.equal("a_remettre");
        s.horloge.decalage = -3600000; // l'horloge recule d'une heure
        const sig = signerVote(1, { decision: "approuve", ticket: t.ticket, request_hash: t.hash });
        expect((await vote(s, t.ticket, 1, "approuve", sig)).corps.error.code).to.equal("ticket_clos_aux_votes");
        const tr = s.inst.service.machine.tickets.get(t.ticket).transitions.map((x) => N.decoderHorodatage(x.at));
        expect(tr.every((x, k) => k === 0 || x >= tr[k - 1])).to.equal(true);
      } finally {
        await s.inst.arreter();
      }
    });

    it("après un redémarrage, la dernière date persistée borne encore l'horloge", async function () {
      const dir = repertoireTemporaire();
      const s = await service({ dir });
      const t = await ticketOuvert(s);
      s.horloge.decalage = 10 * 60000;
      await s.inst.service.tic();
      const dernier = s.inst.service.machine.dernierAt;
      await s.inst.arreter();
      const s2 = await service({ dir });
      try {
        s2.horloge.decalage = -10 * 60000;
        await s2.inst.service.tic();
        expect(s2.inst.service.machine.dernierAt).to.be.at.least(dernier);
        expect(s2.inst.service.machine.tickets.get(t.ticket).state).to.equal("ouvert");
      } finally {
        await s2.inst.arreter();
      }
    });
  });

  describe("arrêt brutal pendant une transition", function () {
    const cle = new Uint8Array(32).fill(9);

    it("dernière ligne tronquée : relue jusqu'à la précédente, puis tronquée", async function () {
      const dir = repertoireTemporaire();
      const m = new MagasinEtat({ repertoire: dir, cle });
      await m.ouvrir();
      await m.ajouter({ tickets: [{ ticket: "apr-0001", state: "reserve" }] });
      await m.ajouter({ tickets: [{ ticket: "apr-0001", state: "ouvert" }] });
      await m.fermer();
      const j = path.join(dir, "etat", "journal.ndjson");
      const octets = fs.readFileSync(j);
      fs.writeFileSync(j, octets.subarray(0, octets.length - 7)); // écriture interrompue
      const m2 = new MagasinEtat({ repertoire: dir, cle });
      const docs = await m2.ouvrir();
      expect(docs.tronque).to.equal(true);
      expect(docs.tickets).to.deep.equal([{ ticket: "apr-0001", state: "reserve" }]);
      await m2.ajouter({ tickets: [{ ticket: "apr-0001", state: "ouvert" }] });
      await m2.fermer();
      const m3 = new MagasinEtat({ repertoire: dir, cle });
      expect((await m3.ouvrir()).tickets[0].state).to.equal("ouvert");
      await m3.fermer();
    });

    it("ligne corrompue au milieu, mauvaise clé : démarrage refusé", async function () {
      const dir = repertoireTemporaire();
      const m = new MagasinEtat({ repertoire: dir, cle });
      await m.ouvrir();
      for (let k = 0; k < 3; k++) await m.ajouter({ meta: { k } });
      await m.fermer();
      const j = path.join(dir, "etat", "journal.ndjson");
      const lignes = fs.readFileSync(j, "utf8").split("\n");
      lignes[1] = lignes[1].slice(0, 10) + "A" + lignes[1].slice(11);
      fs.writeFileSync(j, lignes.join("\n"));
      let e = null;
      try {
        await new MagasinEtat({ repertoire: dir, cle }).ouvrir();
      } catch (x) {
        e = x;
      }
      expect(e?.message).to.match(/corrompu/);
      fs.rmSync(path.join(dir, "etat", "verrou"), { force: true });
      e = null;
      try {
        await new MagasinEtat({ repertoire: dir, cle: new Uint8Array(32).fill(1) }).ouvrir();
      } catch (x) {
        e = x;
      }
      expect(e).to.not.equal(null);
    });

    it("compactage interrompu après l'instantané : les lignes déjà reflétées sont sautées", async function () {
      const dir = repertoireTemporaire();
      const m = new MagasinEtat({ repertoire: dir, cle });
      await m.ouvrir();
      await m.ajouter({ tickets: [{ ticket: "apr-0001", state: "reserve" }] });
      await m.ajouter({ tickets: [{ ticket: "apr-0001", state: "ouvert" }] });
      const avant = fs.readFileSync(path.join(dir, "etat", "journal.ndjson"));
      await m.compacter({ meta: null, versions: [], tickets: [{ ticket: "apr-0001", state: "ouvert" }], fenetres: [] });
      await m.fermer();
      fs.writeFileSync(path.join(dir, "etat", "journal.ndjson"), avant); // troncature non faite
      const m2 = new MagasinEtat({ repertoire: dir, cle });
      expect((await m2.ouvrir()).tickets).to.deep.equal([{ ticket: "apr-0001", state: "ouvert" }]);
      await m2.ajouter({ tickets: [{ ticket: "apr-0001", state: "seuil_atteint" }] });
      await m2.fermer();
      const m3 = new MagasinEtat({ repertoire: dir, cle });
      expect((await m3.ouvrir()).tickets[0].state).to.equal("seuil_atteint");
      await m3.fermer();
    });

    it("processus tué au milieu d'une rafale : chaque réponse reçue est durable, le service repart", async function () {
      const dir = repertoireTemporaire();
      const cfg = ecrireConfiguration(dir, { epoch: "rafale" });
      let svc = await lancerService(cfg.chemin);
      let client = new ClientServiceApprobation({ socket: cfg.socket, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
      await client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
      const recus = [];
      const envoyer = (k) =>
        client.evaluer(requeteEvaluer("sap__payments.create", paiement(`${6000 + k}.00`), { launched_by: `demandeur-${k}` })).then((r) => recus.push({ k, ticket: r.ticket }), () => {});
      await Promise.all(Array.from({ length: 10 }, (_, k) => envoyer(k)));
      // seconde rafale : le processus est tué pendant qu'elle est traitée
      const envois = Array.from({ length: 30 }, (_, k) => envoyer(10 + k));
      await new Promise((ok) => setTimeout(ok, 15));
      await svc.tuer();
      await Promise.all(envois);
      svc = await lancerService(cfg.chemin);
      try {
        client = new ClientServiceApprobation({ socket: cfg.socket, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
        // chaque ticket rendu avant l'arrêt est retrouvé : sa ré-émission reçoit le même ticket
        for (const { k, ticket } of recus) {
          const r = await client.evaluer(requeteEvaluer("sap__payments.create", paiement(`${6000 + k}.00`), { launched_by: `demandeur-${k}` }));
          expect(r.ticket, `demande ${k}`).to.equal(ticket);
        }
        expect(recus.length).to.be.at.least(10);
        this.test.title += ` (${recus.length} réponses reçues sur 40)`;
      } finally {
        await svc.arreter();
      }
    });

    it("un second service sur le même répertoire d'état est refusé", async function () {
      const dir = repertoireTemporaire();
      const cfg = ecrireConfiguration(dir, {});
      const svc = await lancerService(cfg.chemin);
      try {
        let e = null;
        try {
          await lancerService(cfg.chemin);
        } catch (x) {
          e = x;
        }
        expect(e?.message).to.match(/déjà tenu|EADDRINUSE|refusé/);
      } finally {
        await svc.arreter();
      }
    });
  });
});
