// Notifications livrées par le service d'approbation (CT-3 13.19, EX-13.39 à
// EX-13.42 ; CT-9 TI-21, TA-102) : document `$defs/notification`, corps JCS
// identique à chaque tentative et ligne de la boîte d'envoi, signature
// `NOORTRACE-Signature` recalculée par un récepteur tiers (Python,
// bibliothèque standard, `hmac.compare_digest`), reprises à 10 s, 60 s, 300 s
// et 1 800 s sous l'horloge du service, abandon sur 3xx et 4xx autre que 408
// et 429, file pleine, boîte tournée, lignes du journal sans corps ni clé,
// aucune identité de personne dans un document. TA-102 : mutant du service
// sans en-tête de signature, copié hors du dépôt et détruit après.
// Étape 6 : délai appliqué jusqu'à la fin du corps de la réponse (prise
// toujours fermée) et magasin d'autorités du système sans
// `notifications.ca` (EX-13.42).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { spawn } from "node:child_process";
import * as N from "@noortrace/noyau";
import * as A from "@noortrace/approbation";
import {
  ANNUAIRE_REFERENCE, CONSTANTES, DEMANDEUR, RACINE, SESSIONS, attendre, messageCharger, politiqueParcours, repertoireTemporaire,
  OUTIL_PAIEMENT, requeteEvaluer, retenue,
} from "./fixtures/approbation-service/outils.mjs";
import {
  ORIGINE, adresseDe, boite, horlogeReglable, journalService, lancerRecepteur, pythonDisponible, serviceEtape6, signerVoteDerive,
} from "./fixtures/approbation-service/etape6.mjs";
import { certificatsTls, enAttente, opensslDisponible } from "./fixtures/ancrage-rfc3161/outils.mjs";

const CT3 = fs.readFileSync(path.join(RACINE, "spec", "CT-3-approbations.md"), "utf8");
const V1 = "parcours-1";
const paiement = (montant, claim = "2026-90417") => ({ claim_id: claim, amount: montant, currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
const NOTIFICATION = `${A.IDS.configuration}#/$defs/notification`;

/** Exemple de document d'EX-13.40, son corps JCS (472 octets) et la clé et la signature d'EX-13.41. */
function exempleEx1341() {
  const k = CT3.indexOf("<!-- exemple: configuration-approbation/notification -->");
  const d = CT3.indexOf("```json\n", k) + 8;
  const doc = JSON.parse(CT3.slice(d, CT3.indexOf("```", d)));
  const t = CT3.indexOf("```text\n", k) + 8;
  const corps = CT3.slice(t, CT3.indexOf("\n```", t));
  const cle = /`K` =\s*`([^`]+)`/.exec(CT3.slice(k))[1];
  const signature = /NOORTRACE-Signature:\s*sha256=([0-9a-f]{64})/.exec(CT3.slice(k))[1];
  return { doc, corps, cle, signature };
}

/** Identités de personnes et données des arguments qu'aucun document ne doit porter (EX-13.11, EX-13.40). */
const INTERDITS = [
  ...Object.values(SESSIONS), DEMANDEUR, "u.martin", "Approbateur 1", "Approbateur 2", "U. Martin", "CH9300762011623852957", "7400.00",
  "Adresse non membre", "Montant", "oidc ", "utilisateur ",
];
function sansIdentite(texte) {
  for (const x of INTERDITS) expect(texte, `identité ou argument : ${x}`).to.not.contain(x);
}

const prerequis = (ctx, tls = false) => {
  if (!pythonDisponible()) enAttente(ctx, "python3 absent (récepteur de webhook tiers)");
  if (tls && !opensslDisponible()) enAttente(ctx, "openssl absent (matériel TLS du récepteur)");
};

/** Notificateur nu sous une horloge réglable, journal en mémoire. */
function notificateur(o = {}) {
  const dir = o.dir ?? repertoireTemporaire("noortrace-ntf-");
  const h = { t: Date.parse("2026-11-10T08:00:00.000Z") };
  const journal = [];
  const n = new A.Notificateur({
    boite: path.join(dir, "notifications.ndjson"), console_origin: ORIGINE, horloge: () => h.t,
    journal: (type, d) => journal.push({ type, ...d }), webhook: o.webhook ?? null, tailleBoite: o.tailleBoite, envoyer: o.envoyer, minuterie: false,
  });
  return { dir, h, journal, n };
}
const doc = (kind, i = 1) => ({
  kind, entries: ["apb-0001"], roles: [], ticket: `apr-${String(i).padStart(4, "0")}`, tool: "compta.paiements.creer",
  deadline: "2026-11-10T09:00:00.000Z", link: `${ORIGINE}/tickets/apr-${String(i).padStart(4, "0")}`, details: null,
});
/** Laisse les écritures et les tentatives en cours finir, puis lance les tentatives échues. */
async function traiter(n) {
  await n.attendre();
  n.traiter();
  await n.attendre();
}

describe("service d'approbation : notifications livrées à un webhook (13.19)", function () {
  this.timeout(120000);
  const aArreter = [];
  afterEach(async function () {
    while (aArreter.length) await aArreter.pop()().catch(() => {});
  });

  it("EX-13.41 : l'exemple fait 472 octets, sa signature est sha256=0ba22888…354c, recalculée par le récepteur tiers", async function () {
    prerequis(this);
    const { doc: d, corps, cle, signature } = exempleEx1341();
    expect(A.registreSchemas().valider(NOTIFICATION, d).valide).to.equal(true);
    const octets = Buffer.from(A.jcsIntegral(d), "utf8");
    expect(octets.toString("utf8")).to.equal(corps);
    expect(octets.length).to.equal(472);
    expect(A.signerNotification(cle, octets)).to.equal(signature);
    expect(signature).to.match(/^0ba22888[0-9a-f]{52}354c$/);
    const dir = repertoireTemporaire("noortrace-ntf-");
    const r = await lancerRecepteur({ dir, cle });
    aArreter.push(r.arreter);
    const res = await A.envoyerNotification({ url: r.url, corps: octets, signature: A.signerNotification(cle, octets), ca: null, timeout_ms: 5000 });
    expect(res).to.deep.equal({ status: 200 });
    const [q] = r.requetes();
    expect(q).to.include({ signature_valide: true, mac_recalcule: signature, content_type: "application/json", signature: `sha256=${signature}` });
    expect(Buffer.from(q.corps_b64, "base64").equals(octets)).to.equal(true);
  });

  describe("TI-21 : le service forme, inscrit et livre chaque sorte de notification", function () {
    let s;
    let recv;
    let seq = 4;
    const ouvrir = async (args, launched_by) => {
      const requete = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, args, { launched_by });
      const r = await s.client.evaluer(requete);
      seq += 2;
      const ret = retenue({ requete, rule: r.rule, ticket: r.ticket, seq, ts: N.ecrireHorodatage(s.h.t) });
      await s.client.ouvrir(ret.ouvrir);
      return { ticket: r.ticket, ret };
    };

    before(async function () {
      prerequis(this, true);
      const dir = repertoireTemporaire("noortrace-ti21-");
      const tls = certificatsTls(path.join(dir, "tls"));
      if (!tls) enAttente(this, "openssl : matériel TLS non produit");
      const cle = randomBytes(32).toString("hex");
      recv = await lancerRecepteur({ dir, cle, cert: path.join(dir, "tls", "serveur.pem"), key: path.join(dir, "tls", "serveur.key") });
      s = await serviceEtape6({
        dir, cleWebhook: cle, annuaire: ANNUAIRE_REFERENCE, max_open_tickets: 1, horloge: horlogeReglable("2026-11-10T11:00:00.000Z"),
        webhook: { url: recv.url, ca: "tls/ca.pem", timeout_ms: 5000 },
        escalation: [{ after_ms: 60000, notify: "jeu" }, { after_ms: 120000, notify: "administrateur" }, { after_ms: 180000, notify: "demandeur" }],
      });
      await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
      // ouverture (jeu statique figé à l'ouverture), vote, trois escalades, récusation (seuil inatteignable),
      // plafond, opération de l'annuaire
      const t = await ouvrir(paiement("7400.00"));
      s.h.avancer(1000);
      const sig = signerVoteDerive(1, { decision: "approuve", ticket: t.ticket, request_hash: t.ret.evenement.hash });
      expect((await s.appel("voter", { ticket: t.ticket, approver: adresseDe(1), decision: "approuve", signature: sig, reason: "Constat et facture concordants", session_identity: SESSIONS[1] })).statut).to.equal(200);
      for (let k = 0; k < 3; k++) {
        s.h.avancer(60000);
        await s.service.tic();
      }
      expect((await s.appel("recuser", { ticket: t.ticket, approver: adresseDe(2), session_identity: SESSIONS[2] })).statut).to.equal(200);
      const plafond = await s.client.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("8100.00", "2026-90418"))).then(() => null, (e) => e);
      expect(plafond.code).to.equal("plafond_atteint");
      expect((await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0001", launched_by: "agent-essai" })).statut).to.equal(200);
      await traiter(s.service.notifications);
    });
    after(async function () {
      await s?.arreter();
      await recv?.arreter();
    });

    const recus = () => recv.requetes().map((q) => ({ ...q, corps: Buffer.from(q.corps_b64, "base64") }));
    const document = (kind) => recus().map((q) => JSON.parse(q.corps.toString("utf8"))).filter((d) => d.kind === kind);

    it("chaque document reçu est un $defs/notification, corps égal au JCS du document et à la ligne de la boîte, signature valide", function () {
      const q = recus();
      const lignes = boite(s.cfg.doc.state_dir);
      expect(q.map((x) => JSON.parse(x.corps).kind).sort()).to.deep.equal(
        ["escalade", "escalade", "escalade", "operation_annuaire", "ouverture", "plafond_atteint", "seuil_inatteignable", "vote_inscrit"],
      );
      expect(lignes).to.have.length(8);
      for (const x of q) {
        const d = JSON.parse(x.corps.toString("utf8"));
        expect(A.registreSchemas().valider(NOTIFICATION, d).valide, x.corps.toString()).to.equal(true);
        expect(x.corps.toString("utf8")).to.equal(A.jcsIntegral(d));
        expect(lignes).to.include(x.corps.toString("utf8"));
        expect(x.signature_valide).to.equal(true);
        expect(x.signature).to.equal(`sha256=${x.mac_recalcule}`);
        expect(x.content_type).to.equal("application/json");
        expect(d.id).to.match(/^ntf-[0-9a-f]{32}$/);
      }
      expect(new Set(q.map((x) => JSON.parse(x.corps).id)).size).to.equal(8);
    });

    it("destinataires, liens et détails de la table d'EX-13.40", function () {
      const [o] = document("ouverture");
      const t = o.ticket;
      const lien = `${ORIGINE}/tickets/${t}`;
      expect(o).to.deep.include({ recipients: { entries: ["apb-0001", "apb-0002"], roles: [] }, ticket: t, tool: OUTIL_PAIEMENT.tool_announced, link: lien, details: null });
      const [v] = document("vote_inscrit");
      expect(v.recipients).to.deep.equal({ entries: ["apb-0001"], roles: [] });
      expect(v.details).to.deep.include({ approver: adresseDe(1), decision: "approuve", at: "2026-11-10T11:00:01.000Z" });
      const tk = s.service.machine.tickets.get(t);
      const D = A.condenseA({ decision: "approuve", ticket: t, request_hash: tk.request.request_hash, org_id: CONSTANTES.organization.org_id, journal_id: CONSTANTES.journal.journal_id });
      expect(v.details.digest).to.equal(`${D.slice(2, 10)}…${D.slice(-8)}`);
      const esc = document("escalade").sort((a, b) => (a.created_at < b.created_at ? -1 : 1));
      expect(esc.map((x) => x.recipients)).to.deep.equal([
        { entries: ["apb-0002"], roles: [] }, // jeu : éligibles sans vote courant
        { entries: [], roles: ["administrateur_jeu"] },
        { entries: ["apb-0003"], roles: [] }, // demandeur : entrée dont l'alias est le launched_by
      ]);
      for (const x of esc) expect(x).to.deep.include({ ticket: t, link: lien, details: null, deadline: tk.deadline });
      const [si] = document("seuil_inatteignable");
      expect(si).to.deep.include({ recipients: { entries: [], roles: ["administrateur", "administrateur_jeu"] }, details: { eligible_count: 1, effective_required: 2 } });
      const [p] = document("plafond_atteint");
      expect(p).to.deep.include({ recipients: { entries: [], roles: ["administrateur"] }, ticket: null, tool: null, deadline: null, link: null, details: { max_open_tickets: 1 } });
      const [op] = document("operation_annuaire");
      expect(op).to.deep.include({ recipients: { entries: ["apb-0001"], roles: [] }, ticket: null, tool: null, deadline: null, link: `${ORIGINE}/inscription` });
      expect(op.details).to.deep.include({ op: "lier_demandeur", entry: "apb-0001", address: null, revision: 10, by_self: false });
    });

    it("aucune identité de personne, aucun motif, aucun argument dans un document ni dans la boîte", function () {
      sansIdentite(boite(s.cfg.doc.state_dir).join("\n"));
      expect(boite(s.cfg.doc.state_dir).join("\n")).to.not.contain("agent-essai");
    });

    it("journal du service : notification_livree par notification, sans corps ni clé", async function () {
      await s.service.supervision.vider();
      const j = journalService(s.cfg.doc.state_dir);
      const livrees = j.filter((l) => l.type === "notification_livree");
      expect(livrees).to.have.length(8);
      for (const l of livrees) expect(Object.keys(l).sort()).to.deep.equal(["attempt", "id", "kind", "status", "ts", "type"]);
      const texte = fs.readFileSync(path.join(s.cfg.doc.state_dir, "journal-service.ndjson"), "utf8");
      expect(texte).to.not.contain(s.cfg.cleWebhook);
      expect(texte).to.not.contain('"recipients"');
      expect(texte).to.not.contain("details");
    });
  });

  it("nouveau_gel : un gel qui change le jeu figé notifie les éligibles après le gel, membres ajoutés depuis l'ouverture", async function () {
    const { set1, registre } = { set1: CONSTANTES.sets["1"], registre: CONSTANTES.registry };
    const lecture = (h, comptes, required = 2) => ({
      status: "lu", cause: null,
      jeu: {
        chain_id: CONSTANTES.chain_id, registry: registre, set: set1, height: h, block_hash: N.sha256Hex(N.utf8(`bloc/${h}`)),
        threshold: { required, size: comptes.length }, members: comptes.map(adresseDe).sort(),
      },
    });
    const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, set_poll_interval_ms: 1000, appelRpc: async () => { throw new Error("hors ligne"); } });
    aArreter.push(s.arreter);
    const faux = { courante: lecture(1200, [1, 2, 3]), changer: false };
    Object.assign(faux, {
      async hauteur() { return faux.courante.jeu.height; },
      async changements() { const c = faux.changer; faux.changer = false; return c; },
      async lire() { return JSON.parse(JSON.stringify(faux.courante)); },
    });
    s.service.lecteur = faux;
    const politique = politiqueParcours({ approver_set: { source: "registre", chain_id: CONSTANTES.chain_id, registry: registre, set: set1, members: null, threshold: null } });
    await s.client.charger(messageCharger({ policy_version: V1, rules: politique }));
    await attendre(() => s.service.etat().ready);
    const requete = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00"));
    const r = await s.client.evaluer(requete);
    await s.client.ouvrir(retenue({ requete, rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(s.h.t) }).ouvrir);
    await attendre(() => s.service.machine.tickets.get(r.ticket).approver_set !== null);
    faux.courante = lecture(1300, [1, 2, 3, 4]);
    faux.changer = true;
    await attendre(() => boite(s.cfg.doc.state_dir).some((l) => l.includes('"nouveau_gel"')));
    const docs = boite(s.cfg.doc.state_dir).map((l) => JSON.parse(l));
    const ng = docs.find((d) => d.kind === "nouveau_gel");
    expect(A.registreSchemas().valider(NOTIFICATION, ng).valide).to.equal(true);
    expect(ng).to.deep.include({
      ticket: r.ticket, recipients: { entries: ["apb-0001", "apb-0002"], roles: [] }, link: `${ORIGINE}/tickets/${r.ticket}`,
      details: { added_members: [adresseDe(4)], effective_required: 2 },
    });
    expect(docs.filter((d) => d.kind === "ouverture")).to.have.length(1);
  });

  describe("livraison (EX-13.42), sous l'horloge du service", function () {
    /** Notificateur et récepteur dont la réponse suit `scenario`. */
    async function banc(ctx, scenario, o = {}) {
      prerequis(ctx, o.tls);
      const cle = randomBytes(32).toString("hex");
      const dir = repertoireTemporaire("noortrace-ntf-");
      let recv;
      if (o.tls) {
        if (!certificatsTls(path.join(dir, "tls"))) enAttente(ctx, "openssl : matériel TLS non produit");
        recv = await lancerRecepteur({ dir, cle, scenario, cert: path.join(dir, "tls", "serveur.pem"), key: path.join(dir, "tls", "serveur.key") });
      } else {
        recv = await lancerRecepteur({ dir, cle, scenario });
      }
      aArreter.push(recv.arreter);
      const ca = o.tls && o.avecCa !== false ? fs.readFileSync(path.join(dir, "tls", "ca.pem"), "utf8") : null;
      const b = notificateur({ dir, webhook: { url: o.url ?? recv.url, cle, ca, timeout_ms: o.timeout_ms ?? 2000 } });
      return { ...b, recv, cle };
    }

    it("reprises 10 s, 60 s, 300 s puis 1 800 s après la fin de la tentative précédente ; abandon après cinq tentatives (reprises_epuisees) ; corps identique à chaque tentative", async function () {
      const { n, h, journal, recv } = await banc(this, [503, 503, 503, 503, 503]);
      const d = n.notifier(doc("ouverture"));
      await traiter(n);
      let t = h.t;
      for (const delai of A.REPRISES_MS) {
        expect(recv.requetes()).to.have.length(A.REPRISES_MS.indexOf(delai) + 1);
        expect(n.prochaineEcheance()).to.equal(t + delai);
        h.t = t + delai - 1;
        await traiter(n);
        expect(recv.requetes(), `pas de reprise avant ${delai} ms`).to.have.length(A.REPRISES_MS.indexOf(delai) + 1);
        h.t = t + delai;
        await traiter(n);
        t = h.t;
      }
      expect(recv.requetes()).to.have.length(5);
      expect(new Set(recv.requetes().map((q) => q.corps_b64)).size).to.equal(1);
      expect(recv.requetes().every((q) => q.signature_valide)).to.equal(true);
      const echecs = journal.filter((l) => l.type === "notification_echec");
      expect(echecs.map((l) => [l.attempt, l.status, l.cause])).to.deep.equal([1, 2, 3, 4, 5].map((k) => [k, 503, "statut"]));
      expect(journal.filter((l) => l.type === "notification_abandonnee")).to.deep.equal([{ type: "notification_abandonnee", id: d.id, kind: "ouverture", attempts: 5, cause: "reprises_epuisees" }]);
      expect(n.prochaineEcheance()).to.equal(null);
      h.t += 10 * 3600000;
      await traiter(n);
      expect(recv.requetes()).to.have.length(5);
    });

    it("503 puis 200 : livrée à la deuxième tentative ; 408, 429, 500 reprennent", async function () {
      const { n, h, journal, recv } = await banc(this, [503, 200, 408, 200, 429, 200, 500, 200]);
      for (let k = 1; k <= 4; k++) {
        n.notifier(doc("ouverture", k));
        await traiter(n);
        h.t += 10000;
        await traiter(n);
      }
      expect(recv.requetes().map((q) => q.reponse)).to.deep.equal([503, 200, 408, 200, 429, 200, 500, 200]);
      expect(journal.filter((l) => l.type === "notification_livree").map((l) => [l.attempt, l.status])).to.deep.equal([[2, 200], [2, 200], [2, 200], [2, 200]]);
      expect(journal.filter((l) => l.type === "notification_abandonnee")).to.deep.equal([]);
    });

    it("3xx et 4xx autre que 408 et 429 : abandon sans reprise (statut_definitif), redirection non suivie", async function () {
      const { n, h, journal, recv } = await banc(this, [301, 404, 401, 302]);
      for (let k = 1; k <= 4; k++) n.notifier(doc("vote_inscrit", k));
      await traiter(n);
      h.t += 3 * 3600000;
      await traiter(n);
      expect(recv.requetes().map((q) => q.reponse).sort()).to.deep.equal([301, 302, 401, 404]);
      expect(recv.requetes().every((q) => q.path === "/noortrace/notifications")).to.equal(true);
      const ab = journal.filter((l) => l.type === "notification_abandonnee");
      expect(ab.map((l) => [l.attempts, l.cause])).to.deep.equal([[1, "statut_definitif"], [1, "statut_definitif"], [1, "statut_definitif"], [1, "statut_definitif"]]);
      expect(journal.filter((l) => l.type === "notification_echec").map((l) => l.cause)).to.deep.equal(["statut", "statut", "statut", "statut"]);
    });

    it("silence au-delà de timeout_ms : échec delai, reprise ; HTTPS d'autorité inconnue : échec tls ; port fermé : échec reseau", async function () {
      const a = await banc(this, ["silence", 200], { timeout_ms: 1000 });
      a.n.notifier(doc("ouverture"));
      const debut = Date.now();
      await traiter(a.n);
      expect(Date.now() - debut).to.be.within(900, 5000);
      expect(a.journal.find((l) => l.type === "notification_echec")).to.deep.include({ attempt: 1, status: null, cause: "delai" });
      a.h.t += 10000;
      await traiter(a.n);
      expect(a.journal.find((l) => l.type === "notification_livree")).to.deep.include({ attempt: 2, status: 200 });
      // certificat d'une autorité absente du magasin du système, notifications.ca nul
      const b = await banc(this, [], { tls: true, avecCa: false });
      b.n.notifier(doc("ouverture"));
      await traiter(b.n);
      expect(b.journal.find((l) => l.type === "notification_echec")).to.deep.include({ status: null, cause: "tls" });
      expect(b.recv.requetes()).to.have.length(0);
      expect(b.n.prochaineEcheance()).to.equal(b.h.t + 10000);
      // même récepteur, autorité déclarée : livrée
      const c = await banc(this, [], { tls: true });
      c.n.notifier(doc("ouverture"));
      await traiter(c.n);
      expect(c.journal.find((l) => l.type === "notification_livree")).to.deep.include({ attempt: 1, status: 200 });
      const d = await banc(this, [], { url: "http://127.0.0.1:1/n" });
      d.n.notifier(doc("ouverture"));
      await traiter(d.n);
      expect(d.journal.find((l) => l.type === "notification_echec")).to.deep.include({ status: null, cause: "reseau" });
    });

    it("file pleine : au-delà de 10 000, la plus ancienne qui attend est abandonnée (file_pleine), vote_inscrit et operation_annuaire épargnés", async function () {
      const envoyer = () => new Promise(() => {});
      const a = notificateur({ envoyer, webhook: { url: "https://webhook.invalid/n", cle: "k".repeat(32), ca: null, timeout_ms: 1000 } });
      const kinds = ["vote_inscrit", "operation_annuaire", "vote_inscrit", "ouverture", "escalade"];
      const premiers = kinds.map((k, i) => a.n.notifier({ ...doc(k, i + 1), ...(k === "operation_annuaire" ? { ticket: null, tool: null, deadline: null, link: `${ORIGINE}/inscription`, details: { op: "inscrire", entry: "apb-0001", address: null, revision: 1, at: "2026-11-10T08:00:00.000Z", by_self: true } } : {}), ...(k === "vote_inscrit" ? { details: { approver: adresseDe(1), decision: "approuve", digest: "00000000…00000000", at: "2026-11-10T08:00:00.000Z" } } : {}) }));
      for (let i = kinds.length; i < A.FILE_MAX; i++) a.n.notifier(doc("ouverture", 10 + i));
      expect(a.n.file.size).to.equal(A.FILE_MAX);
      expect(a.journal.filter((l) => l.type === "notification_abandonnee")).to.deep.equal([]);
      a.n.notifier(doc("escalade", 20000));
      a.n.notifier(doc("escalade", 20001));
      expect(a.journal.filter((l) => l.type === "notification_abandonnee")).to.deep.equal([
        { type: "notification_abandonnee", id: premiers[3].id, kind: "ouverture", attempts: 0, cause: "file_pleine" },
        { type: "notification_abandonnee", id: premiers[4].id, kind: "escalade", attempts: 0, cause: "file_pleine" },
      ]);
      await a.n.attendre();
      // file faite des seuls kinds épargnés : la plus ancienne est abandonnée
      const b = notificateur({ envoyer, webhook: { url: "https://webhook.invalid/n", cle: "k".repeat(32), ca: null, timeout_ms: 1000 } });
      const v = { details: { approver: adresseDe(1), decision: "refuse", digest: "00000000…00000000", at: "2026-11-10T08:00:00.000Z" } };
      const p1 = b.n.notifier({ ...doc("vote_inscrit", 1), ...v });
      for (let i = 1; i <= A.FILE_MAX; i++) b.n.notifier({ ...doc("vote_inscrit", i + 1), ...v });
      expect(b.journal.filter((l) => l.type === "notification_abandonnee")).to.deep.equal([{ type: "notification_abandonnee", id: p1.id, kind: "vote_inscrit", attempts: 0, cause: "file_pleine" }]);
      await b.n.attendre();
    });

    it("boîte d'envoi : une ligne par notification avant la première tentative, tournée au-delà de sa taille (64 Mio par défaut), 8 fichiers tournés au plus", async function () {
      expect(A.TAILLE_BOITE).to.equal(64 * 1024 * 1024);
      expect(A.FICHIERS_TOURNES).to.equal(8);
      const a = notificateur({ tailleBoite: 1000 });
      const ids = [];
      for (let i = 1; i <= 60; i++) {
        ids.push(a.n.notifier(doc("ouverture", i)).id);
        await a.n.attendre();
      }
      // le fichier courant n'existe pas juste après une rotation, et se recrée à la ligne suivante
      const fichiers = fs.readdirSync(a.dir).filter((f) => f !== "notifications.ndjson").sort();
      expect(fichiers).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8].map((k) => `notifications.ndjson.${k}`));
      for (let k = 1; k <= 8; k++) expect(fs.statSync(path.join(a.dir, `notifications.ndjson.${k}`)).size).to.be.above(1000);
      // ordre : le plus ancien gardé est dans .8, le plus récent dans le fichier courant
      const toutes = [8, 7, 6, 5, 4, 3, 2, 1].flatMap((k) => boite(a.dir, `.${k}`)).concat(boite(a.dir));
      const lus = toutes.map((l) => JSON.parse(l).id);
      expect(lus).to.deep.equal(ids.slice(ids.length - lus.length));
      expect(ids.length - lus.length).to.be.above(0);
      for (const l of toutes) expect(l).to.equal(A.jcsIntegral(JSON.parse(l)));
    });

    it("boîte en échec : notification_boite_en_echec (id, kind), livraison faite tout de même ; sans destinataire : ni formée ni inscrite", async function () {
      const { n, journal, recv, dir } = await banc(this, []);
      fs.mkdirSync(path.join(dir, "notifications.ndjson"));
      const d = n.notifier(doc("ouverture"));
      await traiter(n);
      expect(journal.filter((l) => l.type === "notification_boite_en_echec")).to.deep.equal([{ type: "notification_boite_en_echec", id: d.id, kind: "ouverture" }]);
      expect(recv.requetes()).to.have.length(1);
      expect(n.notifier({ ...doc("ouverture", 2), entries: [], roles: [] })).to.equal(null);
      expect(journal.filter((l) => l.type === "notification_sans_destinataire")).to.deep.equal([{ type: "notification_sans_destinataire", kind: "ouverture", ticket: "apr-0002" }]);
    });

    describe("TA-102 : signature des notifications (EX-13.41)", function () {
      let mutant = null;
      after(function () {
        if (mutant) fs.rmSync(mutant, { recursive: true, force: true });
      });

      it("TA-102 : l'en-tête NOORTRACE-Signature est égal au HMAC-SHA256 recalculé sur le corps par le récepteur, exemple d'EX-13.41 compris ; mutant du service sans l'en-tête : l'en-tête manque (tué)", async function () {
        prerequis(this);
        const { cle, signature, doc: ex } = exempleEx1341();
        const oracle = (q) => q.signature !== null && q.signature === `sha256=${q.mac_recalcule}` && q.signature_valide === true;
        const dir = repertoireTemporaire("noortrace-ta102-");
        const recv = await lancerRecepteur({ dir, cle });
        aArreter.push(recv.arreter);
        const essai = async (Module) => {
          const h = { t: Date.parse(ex.created_at) };
          const n = new Module.Notificateur({ boite: path.join(dir, `b-${randomBytes(3).toString("hex")}`), console_origin: ORIGINE, horloge: () => h.t, journal: () => {}, webhook: { url: recv.url, cle, ca: null, timeout_ms: 5000 }, minuterie: false });
          n.notifier({ kind: ex.kind, entries: ex.recipients.entries, roles: [], ticket: ex.ticket, tool: ex.tool, deadline: ex.deadline, link: ex.link, details: ex.details });
          await traiter(n);
          return recv.requetes().at(-1);
        };
        const q = await essai(A);
        expect(oracle(q)).to.equal(true);
        // l'exemple d'EX-13.41 : même clé, le récepteur recalcule la signature publiée
        const octets = Buffer.from(A.jcsIntegral(ex), "utf8");
        await A.envoyerNotification({ url: recv.url, corps: octets, signature: A.signerNotification(cle, octets), ca: null, timeout_ms: 5000 });
        expect(recv.requetes().at(-1)).to.include({ mac_recalcule: signature, signature: `sha256=${signature}`, signature_valide: true });
        // mutant : copie du paquet dont l'envoi omet l'en-tête de signature
        mutant = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "noortrace-ta102-"));
        fs.cpSync(path.join(RACINE, "paquets", "approbation"), path.join(mutant, "approbation"), { recursive: true });
        fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(mutant, "node_modules"));
        const f = path.join(mutant, "approbation", "src", "notifications.mjs");
        const texte = fs.readFileSync(f, "utf8");
        const entete = ', "NOORTRACE-Signature": `sha256=${signature}`';
        expect(texte.includes(entete), "en-tête trouvé dans la copie").to.equal(true);
        fs.writeFileSync(f, texte.replace(entete, ""));
        const M = await import(path.join(mutant, "approbation", "src", "notifications.mjs"));
        const qm = await essai(M);
        expect(qm.signature, "mutant : l'en-tête manque").to.equal(null);
        expect(oracle(qm), "mutant tué : l'oracle échoue").to.equal(false);
      });
    });
  });

  it("arrêt avec des notifications en attente : elles restent dans la boîte, sans ligne livrée ni abandonnée ; aucune reprise après le redémarrage", async function () {
    prerequis(this);
    const dir = repertoireTemporaire("noortrace-ntf-arret-");
    const cle = randomBytes(32).toString("hex");
    const recv = await lancerRecepteur({ dir, cle, scenario: [503, 503, 503] });
    aArreter.push(recv.arreter);
    const h = horlogeReglable("2026-11-10T11:00:00.000Z");
    const s = await serviceEtape6({ dir, cleWebhook: cle, annuaire: ANNUAIRE_REFERENCE, horloge: h, webhook: { url: recv.url } });
    await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
    const requete = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00"));
    const r = await s.client.evaluer(requete);
    await s.client.ouvrir(retenue({ requete, rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(h.t) }).ouvrir);
    await traiter(s.service.notifications);
    expect(recv.requetes()).to.have.length(1);
    await s.arreter();
    const j1 = journalService(s.cfg.doc.state_dir);
    expect(j1.filter((l) => l.type === "notification_echec")).to.have.length(1);
    expect(j1.filter((l) => ["notification_livree", "notification_abandonnee"].includes(l.type))).to.deep.equal([]);
    expect(boite(s.cfg.doc.state_dir)).to.have.length(1);
    const s2 = await serviceEtape6({ dir, garder: s.cfg, horloge: h });
    aArreter.push(s2.arreter);
    h.avancer(4000 * 1000);
    await s2.service.tic();
    await s2.service.notifications.attendre();
    expect(recv.requetes()).to.have.length(1);
    expect(boite(s.cfg.doc.state_dir)).to.have.length(1);
  });

  it("plafond_atteint : une notification au premier refus d'un launched_by par période de 15 minutes ; plafond_refus_non_notifies à la fin de la période", async function () {
    const h = horlogeReglable("2026-11-10T11:00:00.000Z");
    const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, horloge: h, max_open_tickets: 1 });
    aArreter.push(s.arreter);
    await s.client.charger(messageCharger({ policy_version: V1, rules: politiqueParcours() }));
    await s.client.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00")));
    const refuser = async (k) => {
      const e = await s.client.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00", `2026-9${String(k).padStart(4, "0")}`))).then(() => null, (x) => x);
      expect(e?.code).to.equal("plafond_atteint");
    };
    await refuser(1);
    h.avancer(60000);
    await refuser(2);
    await refuser(3);
    await s.service.notifications.attendre();
    const plafonds = () => boite(s.cfg.doc.state_dir).map((l) => JSON.parse(l)).filter((d) => d.kind === "plafond_atteint");
    expect(plafonds()).to.have.length(1);
    // un autre launched_by a sa propre période
    const autre = await s.client.evaluer(requeteEvaluer(OUTIL_PAIEMENT.tool_announced, paiement("7400.00", "2026-80000"), { launched_by: "autre-demandeur" }));
    expect(autre.ticket_state).to.equal("nouveau");
    h.avancer(14 * 60000 - 1);
    await s.service.tic();
    expect(journalService(s.cfg.doc.state_dir).filter((l) => l.type === "plafond_refus_non_notifies")).to.deep.equal([]);
    h.avancer(1);
    await s.service.tic();
    await s.service.supervision.vider();
    const nn = journalService(s.cfg.doc.state_dir).filter((l) => l.type === "plafond_refus_non_notifies");
    expect(nn.map((l) => [l.launched_by, l.count])).to.deep.equal([[DEMANDEUR, 2]]);
    await refuser(4);
    await s.service.notifications.attendre();
    expect(plafonds()).to.have.length(2);
  });

  describe("révision 0.6 de l'étape 6 : prise du webhook toujours fermée, magasin d'autorités du système (EX-13.39, EX-13.42)", function () {
    it("un webhook qui répond 200 puis ne finit jamais son corps : statut rendu, et plus aucune prise ouverte chez lui passé timeout_ms", async function () {
      const ouvertes = new Set();
      const srv = http.createServer((q, r) => {
        q.resume();
        r.writeHead(200, { "content-type": "text/plain" });
        r.write("x"); // jamais r.end()
      });
      srv.on("connection", (c) => {
        ouvertes.add(c);
        c.on("close", () => ouvertes.delete(c));
      });
      await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
      try {
        const url = `http://127.0.0.1:${srv.address().port}/n`;
        const timeout_ms = 1000;
        const resultats = await Promise.all(Array.from({ length: 5 }, () => A.envoyerNotification({ url, corps: Buffer.from("{}"), signature: "0".repeat(64), ca: null, timeout_ms })));
        expect(resultats).to.deep.equal(Array(5).fill({ status: 200 }));
        // condition observée, bornée : chaque prise est fermée au plus tard à l'échéance du délai
        const debut = Date.now();
        while (ouvertes.size > 0 && Date.now() - debut < timeout_ms + 4000) await new Promise((ok) => setTimeout(ok, 50));
        expect(ouvertes.size, "prises encore ouvertes après timeout_ms").to.equal(0);
      } finally {
        srv.closeAllConnections();
        await new Promise((ok) => srv.close(ok));
      }
    });

    it("sans notifications.ca, le certificat du webhook est vérifié contre le magasin d'autorités du système (autorité de l'organisation posée dans le système : livrée)", async function () {
      if (!opensslDisponible()) enAttente(this, "openssl absent (matériel TLS du récepteur)");
      const dir = repertoireTemporaire("noortrace-ntf-systeme-");
      const m = certificatsTls(path.join(dir, "tls"));
      if (!m) enAttente(this, "openssl : matériel TLS non produit");
      const srv = https.createServer({ cert: m.cert, key: m.key }, (q, r) => {
        q.resume();
        q.on("end", () => r.writeHead(204).end());
      });
      await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
      try {
        const url = `https://127.0.0.1:${srv.address().port}/n`;
        // un processus dont le magasin du système (SSL_CERT_FILE) contient l'autorité d'essai
        const script = `import { envoyerNotification } from ${JSON.stringify(path.join(RACINE, "paquets", "approbation", "src", "notifications.mjs"))};
const r = await envoyerNotification({ url: ${JSON.stringify(url)}, corps: Buffer.from("{}"), signature: "0".repeat(64), ca: null, timeout_ms: 5000 });
process.stdout.write(JSON.stringify(r));`;
        const lancer = (env) => new Promise((ok) => {
          const p = spawn(process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
          let sortie = "";
          let erreur = "";
          p.stdout.on("data", (x) => (sortie += x));
          p.stderr.on("data", (x) => (erreur += x));
          p.on("exit", () => ok({ sortie, erreur }));
        });
        const avec = await lancer({ SSL_CERT_FILE: path.join(dir, "tls", "ca.pem"), NODE_EXTRA_CA_CERTS: "" });
        expect(JSON.parse(avec.sortie || "null"), avec.erreur).to.deep.equal({ status: 204 });
        // autorité absente du magasin du système : échec tls
        const sans = await lancer({ SSL_CERT_FILE: path.join(dir, "absent.pem"), NODE_EXTRA_CA_CERTS: "" });
        expect(JSON.parse(sans.sortie || "null"), sans.erreur).to.deep.equal({ cause: "tls" });
        expect(A.autoritesWebhook(null)).to.deep.equal(tls.getCACertificates("system"));
        expect(A.autoritesWebhook("PEM")).to.equal("PEM");
      } finally {
        srv.closeAllConnections();
        await new Promise((ok) => srv.close(ok));
      }
    });
  });

  it("aucune notification n'est portée par une méthode du canal de la console (EX-13.39)", function () {
    expect(A.METHODES_CONSOLE).to.deep.equal(["tickets", "consulter", "voter", "recuser", "retirer", "annuaire", "preparer_inscription", "inscrire", "valider", "revoquer", "desactiver", "reactiver", "lier_demandeur", "delier_demandeur"]);
    for (const f of ["console-service-v0.schema.json", "console-approbation-v0.schema.json"]) {
      expect(fs.readFileSync(path.join(RACINE, "spec", "schemas", f), "utf8"), f).to.not.contain("configuration-approbation.schema.json#/$defs/notification");
    }
  });
});
