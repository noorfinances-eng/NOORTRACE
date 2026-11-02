// Parcours de bout en bout du moteur de politique (INTERFACES.md, section d) :
// un agent de test réel traverse le mandataire MCP, et le vrai service
// d'approbation (`paquets/approbation`, `bin/noortrace-approbation`) tourne
// comme processus à part : il évalue la politique (CT-3 §6), tient les
// tickets et calcule les décisions à partir des votes EIP-191 que des clés de
// test (comptes Hardhat 1 et 2, CT-1 §13) déposent par son canal de la
// console (`voter`, CT-3 7.4, 12.9) ; le test ne fixe aucune décision. L'hôte
// est un vrai processus connecteur `noortrace-connecteur` (prise Unix, preuve
// d'identité du pair), le serveur d'outils un vrai processus stdio. Dans
// l'ordre :
//   1. mode `retenir` : une lecture relayée ; un paiement retenu puis approuvé
//      par deux votes (remise reçue par la boucle `decisions`) et relayé, son
//      intention portée par une référence de pièce (EX-5.21, EX-7.4) ; un autre
//      retenu puis refusé par deux votes ; un autre retenu puis expiré ;
//   2. rechargement en mode `erreur` : signal en_attente aussitôt, votes,
//      ré-émission relayée ;
//   3. rechargement en mode observation : un paiement relayé avec sa marque ;
//   4. clôture de la période ; chaque appel a son événement ; le journal est
//      vérifié par la bibliothèque noyau ; le dossier de chaque appel (dont
//      ceux des appels approuvés, avec leur partie approbations, contrôle 7
//      réussi) est vérifié par le noyau ET par le binaire Go
//      `noortrace-verifier` (go1.27.3, en attente sans lui) ;
//   5. le démon réel `bin/noortrace --config`, joint au vrai service : un
//      paiement retenu, le démon tué (SIGKILL) pendant la rétention,
//      redémarré ; `ouvrir` renvoyé ; la ré-émission est retenue, approuvée par
//      deux votes et relayée ; journal vérifié par le noyau, dossier de
//      l'appel approuvé vérifié par le noyau et par Go ; le journal
//      d'exploitation garde les lignes de l'instance tuée.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import {
  Coeur, ClientServiceApprobation, demarrerFrontalMcp, controlePolitiqueApprobation, validerConfiguration, lireEvenements, pieceTexte,
} from "@noortrace/enregistreur";
import { RACINE, BIN_NOORTRACE, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { ClientHote, metaModerne } from "./fixtures/enregistreur-mcp/client-hote.mjs";
import { HorlogeDecalee, RedacteurTest, configurationPolitique, hoteDemo, attendre, lancerServiceApprobation } from "./fixtures/enregistreur-politique/outils.mjs";

const UTILISATEUR = os.userInfo().username;
const PAIEMENT = (amount) => ({ claim_id: "2026-81044", amount, currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
const INTENTION = "Regler le sinistre 2026-81044 sur l'IBAN [REDIGE:iban] du beneficiaire";

/** Construit noortrace-verifier avec go1.27.3 (GOFLAGS limité à cette commande), ou rend null. */
function construireVerificateur(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOFLAGS: "-mod=vendor", GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  return sortie;
}

/** Rapport du binaire Go sur un dossier : verdict valide, statut de chaque contrôle. */
function verifierParGo(bin, dossier) {
  const r = spawnSync(bin, [dossier, "--json"], { encoding: "utf8" });
  expect(r.status, r.stdout + r.stderr).to.equal(0);
  const rapport = JSON.parse(r.stdout);
  expect(rapport.verdict, dossier).to.equal("valide");
  expect(rapport.failed_checks).to.deep.equal([]);
  return Object.fromEntries(rapport.controls.map((c) => [c.number, [c.status, c.reason ?? null]]));
}

function verifierParNoyau(dossier) {
  const r = verifierRepertoireDossier(dossier);
  expect(r.verdict, `${dossier} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
  return JSON.parse(fs.readFileSync(path.join(dossier, "dossier.json"), "utf8"));
}

/** Configuration du parcours : connexion d'hôte de l'utilisateur courant, vrai service joint en HTTP à jeton. */
function configurationParcours(dir, o = {}) {
  const { config, env } = configurationPolitique(dir, {
    mode: o.mode ?? "retenir",
    version: o.version ?? "parcours-1",
    hold_timeout_ms: 25000,
    expire_after_ms: o.expire_after_ms ?? 15000,
    timeout_ms: 1000,
    hosts: [hoteDemo({ id: "agent-parcours", match: { peer_user: UTILISATEUR }, launched_by: "agent-parcours" })],
    socket: path.join(dir, "prise", "mcp.sock"),
    serviceConfig: { url: "http://127.0.0.1:1", socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null },
  });
  return { config, env };
}

function hote(socket) {
  const h = new ClientHote(["--socket", socket]);
  h.appeler = (nom, args, id) => h.requete("tools/call", { name: nom, arguments: args, _meta: metaModerne() }, id);
  return h;
}

/**
 * Deux votes (comptes Hardhat 1 et 2) sur la demande retenue d'un ticket ; le
 * premier attend que le service ait ouvert le ticket (`ouvrir`, CT-3 12.4).
 */
async function deuxVotes(service, ticket, retenue, decision) {
  for (const k of [0, 1]) {
    const r = await attendre(async () => {
      const x = await service.voter({ ticket, request_hash: retenue().hash, decision, k, reason: decision === "refuse" ? "Facture absente" : null });
      return x.corps?.error?.code === "ticket_non_ouvert" || x.corps?.error?.code === "ticket_inconnu" ? null : x;
    }, 10000, 50);
    expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
  }
}

describe("enregistreur, moteur de politique : parcours de bout en bout (agent réel, mandataire MCP, vrai service d'approbation)", function () {
  this.timeout(240000);
  let dir;
  let bin = null;

  before(function () {
    dir = repertoireTemporaire("noortrace-politique-parcours-");
    fs.mkdirSync(path.join(dir, "prise"), { recursive: true, mode: 0o1777 });
    bin = construireVerificateur(dir);
  });

  describe("cœur et frontal dans le processus ; hôte, serveur d'outils et service d'approbation en processus réels", function () {
    let coeur;
    let mcp;
    let config;
    let env;
    let horloge;
    let service;
    let h;
    const ev = {};

    before(async function () {
      ({ config, env } = configurationParcours(dir));
      service = await lancerServiceApprobation(path.join(dir, "service"), { org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
      config.policy.approval.service.url = service.url;
      env = { ...env, NOORTRACE_TEST_JETON_APPROBATION: service.jetonNoyau };
      const v = validerConfiguration(N.utf8(JSON.stringify(config)), { reglesSupplementaires: [controlePolitiqueApprobation] });
      expect(v.erreurs).to.deep.equal([]);
      config = v.config;
      horloge = new HorlogeDecalee();
      const client = new ClientServiceApprobation({ url: service.url, jeton: service.jetonNoyau, timeout_ms: config.policy.approval.timeout_ms });
      coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service: client, minuteurs: true, reglesSupplementaires: [controlePolitiqueApprobation] });
      // Corrélation (5.6) : l'intention du premier paiement est une référence de pièce (EX-5.21).
      const pieceIntention = pieceTexte(INTENTION, { redacted: true });
      await coeur.ecrirePiece(pieceIntention);
      ev.intention = pieceIntention.reference;
      const correlateur = { correler: (x) => (x.arguments?.amount === "9000.00" ? { intent: pieceIntention.reference, code: { model: "demo/modele-test", prompt_version: null }, seq: 1 } : null) };
      mcp = await demarrerFrontalMcp(coeur, secretsDev(), { redacteur: new RedacteurTest(), correlateur });
      await attendre(() => coeur.candidats !== null, 10000);
      h = hote(config.mcp.socket);
      const liste = await h.requete("tools/list", { _meta: metaModerne() });
      expect(liste.result.tools.map((t) => t.name)).to.include("demo__payments.create");
      const retenueDe = (t) => () => coeur.index.retenues.get(t)?.at(-1);
      const vus = new Set();
      const ticketRetenu = async () => {
        const t = await attendre(() => [...mcp.frontal.retentions.keys()].find((x) => !vus.has(x)), 10000);
        vus.add(t);
        return t;
      };

      // 1. Mode retenir.
      ev.lecture = await h.appeler("demo__claims.get", { claim_id: "2026-81044" });
      const approuve = h.appeler("demo__payments.create", PAIEMENT("9000.00"));
      ev.ticketApprouve = await ticketRetenu();
      await deuxVotes(service, ev.ticketApprouve, retenueDe(ev.ticketApprouve), "approuve");
      ev.approuve = await approuve;
      const refuse = h.appeler("demo__payments.create", PAIEMENT("9100.00"));
      ev.ticketRefuse = await ticketRetenu();
      await deuxVotes(service, ev.ticketRefuse, retenueDe(ev.ticketRefuse), "refuse");
      ev.refuse = await refuse;
      // Aucun vote : l'échéance (request_ts + expire_after_ms) passe pendant la rétention.
      const t0 = Date.now();
      ev.expire = await h.appeler("demo__payments.create", PAIEMENT("9200.00"));
      ev.dureeExpiration = Date.now() - t0;
      ev.ticketExpire = ev.expire.result?._meta?.["noortrace/approval"]?.ticket;

      // 2. Mode erreur.
      const erreur = JSON.parse(JSON.stringify(config));
      erreur.policy.approval.mode = "erreur";
      erreur.policy.version = "parcours-2";
      ev.recharge2 = await coeur.recharger(N.utf8(JSON.stringify(erreur)), { env });
      ev.signal = await h.appeler("demo__payments.create", PAIEMENT("9300.00"));
      ev.ticketErreur = ev.signal.result._meta["noortrace/approval"].ticket;
      await deuxVotes(service, ev.ticketErreur, retenueDe(ev.ticketErreur), "approuve");
      await attendre(() => coeur.index.decisions.get(ev.ticketErreur), 15000);
      ev.reemission = await h.appeler("demo__payments.create", PAIEMENT("9300.00"));

      // 3. Mode observation.
      const obs = JSON.parse(JSON.stringify(erreur));
      obs.policy.approval.mode = "observation";
      obs.policy.version = "parcours-3-observation";
      ev.recharge3 = await coeur.recharger(N.utf8(JSON.stringify(obs)), { env });
      ev.observation = await h.appeler("demo__payments.create", PAIEMENT("9400.00"));
      const consommes = () => coeur.journal.trouver("approval_consume_final").length;
      await attendre(() => consommes() >= 2, 15000);

      // 4. Clôture de la période (horloge du cœur seulement : plus aucun message au service n'en dépend).
      const periode = Math.floor(horloge.murale() / 3600000);
      horloge.avancer((periode + 1) * 3600000 - horloge.murale() + 1500);
      await coeur.tic();
      await attendre(() => fs.readdirSync(path.join(coeur.repertoire, "manifestes")).some((n) => n.endsWith(".sig")));
    });

    after(async function () {
      await h?.fermer().catch(() => {});
      await mcp?.arreter().catch(() => {});
      await coeur?.arreter().catch(() => {});
      await service?.arreter().catch(() => {});
    });

    it("chaque issue est rendue à l'hôte réel : relayé, signal refuse, signal expire, signal en_attente, relayé, relayé en observation", function () {
      expect(ev.lecture.result.content[0].text).to.equal("Sinistre 2026-81044 : ouvert");
      expect(ev.approuve.result.structuredContent.payment_id).to.match(/^PAY-2026-/);
      expect(ev.refuse.result._meta["noortrace/approval"]).to.deep.equal({ ticket: ev.ticketRefuse, state: "refuse" });
      expect(ev.expire.result._meta["noortrace/approval"].state, JSON.stringify(ev.expire)).to.equal("expire");
      expect(ev.dureeExpiration).to.be.at.least(config.policy.approval.expire_after_ms - 1000);
      expect(ev.recharge2.accepte).to.equal(true);
      expect(ev.signal.result._meta["noortrace/approval"].state).to.equal("en_attente");
      expect(ev.reemission.result.structuredContent.payment_id).to.match(/^PAY-2026-/);
      expect(ev.recharge3.accepte).to.equal(true);
      expect(ev.observation.result.isError).to.equal(false);
      // Le service tient ses identifiants (CT-3 EX-7.1) : aucun n'est fixé par le test.
      for (const t of [ev.ticketApprouve, ev.ticketRefuse, ev.ticketExpire, ev.ticketErreur]) expect(t).to.match(/^apr-/);
    });

    it("chaque appel produit un événement, avec la policy de son mode et les décisions issues des votes (EX-7.12, EX-9.4, EX-14.14)", async function () {
      const evts = await lireEvenements(coeur.repertoire);
      const appels = evts.filter((e) => e.execution.tool.startsWith("demo__"));
      expect(appels.map((e) => [e.execution.tool, e.execution.status, e.policy.decision])).to.deep.equal([
        ["demo__claims.get", "executee", "autorise"],
        ["demo__payments.create", "retenue", "a_approuver"],
        ["demo__payments.create", "executee", "a_approuver"],
        ["demo__payments.create", "retenue", "a_approuver"],
        ["demo__payments.create", "refusee", "a_approuver"],
        ["demo__payments.create", "retenue", "a_approuver"],
        ["demo__payments.create", "refusee", "a_approuver"],
        ["demo__payments.create", "retenue", "a_approuver"],
        ["demo__payments.create", "executee", "a_approuver"],
        ["demo__payments.create", "executee", "autorise"],
      ]);
      // La politique est évaluée par le service (CT-3 §6) : noms de règle de la politique.
      expect(appels[0].policy.rule).to.equal("defaut : autorise");
      expect(appels[1].policy.rule).to.equal("paiement > 5000 CHF");
      expect(appels.at(-1).policy.rule).to.equal("paiement > 5000 CHF [observation a_approuver]");
      expect(appels.at(-1).code.policy_version).to.equal("parcours-3-observation");
      // Intention par référence : portée par la retenue et reprise par le relais (EX-7.12).
      expect(appels[1].intent).to.deep.equal(ev.intention);
      expect(appels[2].intent).to.deep.equal(ev.intention);
      const decisions = evts.filter((e) => e.execution.tool === "noortrace.approbation.decision");
      expect(decisions.map((e) => [e.approval.ticket, e.approval.decision])).to.deep.equal([
        [ev.ticketApprouve, "approuve"],
        [ev.ticketRefuse, "refuse"],
        [ev.ticketExpire, "expire"],
        [ev.ticketErreur, "approuve"],
      ]);
      const deux = ["0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"];
      for (const d of [decisions[0], decisions[1], decisions[3]]) {
        expect([...d.approval.approvers].sort()).to.deep.equal(deux);
        expect(d.approval.threshold).to.deep.equal({ required: 2, size: 3 });
      }
      expect(decisions[2].approval.approvers).to.deep.equal([]);
      expect(evts.filter((e) => e.execution.tool === "noortrace.journal.politique").map((e) => e.code.policy_version)).to.deep.equal(["parcours-1", "parcours-2", "parcours-3-observation"]);
      ev.appels = appels;
    });

    it("le journal est vérifié par la bibliothèque noyau (CT-1 §7, E-1 à E-11) et la période est close", async function () {
      const dossier = path.join(dir, "dossier-lecture");
      await coeur.exporterDossier(ev.appels[0].seq, dossier);
      const cles = JSON.parse(fs.readFileSync(path.join(dossier, "cles.json"), "utf8"));
      const r = N.verifierJournal(await lireEvenements(coeur.repertoire), cles);
      expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
    });

    it("le dossier de chaque appel est valide pour le noyau ; ceux des appels qui portent approval ont leur partie approbations", async function () {
      ev.dossiers = [];
      for (const e of ev.appels) {
        const d = path.join(dir, `dossier-seq-${e.seq}`);
        await coeur.exporterDossier(e.seq, d);
        const index = verifierParNoyau(d);
        expect(index.parts.find((p) => p.name === "approbations").present, `seq ${e.seq}`).to.equal(e.approval !== null);
        ev.dossiers.push(d);
      }
      const relaye = ev.appels[2];
      const a = JSON.parse(fs.readFileSync(path.join(dir, `dossier-seq-${relaye.seq}`, "approbations.json"), "utf8"));
      expect(JSON.stringify(a)).to.contain(relaye.approval.ticket);
    });

    it("le dossier de chaque appel est valide pour le binaire Go noortrace-verifier (go1.27.3) ; contrôle 7 réussi pour les appels approuvés", function () {
      if (!bin) this.skip();
      ev.appels.forEach((e, k) => {
        const statuts = verifierParGo(bin, ev.dossiers[k]);
        for (const id of [1, 2, 3, 6]) expect(statuts[id][0], `seq ${e.seq} contrôle ${id}`).to.equal("reussi");
        expect(statuts[7], `seq ${e.seq} contrôle 7`).to.deep.equal(e.approval !== null ? ["reussi", null] : ["non_execute", "partie_absente"]);
        for (const id of [4, 5, 8]) expect(statuts[id], `seq ${e.seq} contrôle ${id}`).to.deep.equal(["non_execute", "hors_perimetre_version"]);
      });
      expect(ev.appels.filter((e) => e.approval?.decision === "approuve").length).to.equal(2);
    });
  });

  describe("démon réel bin/noortrace --config et vrai service : arrêt brutal pendant une rétention", function () {
    let d2;
    let config;
    let env;
    let fichier;
    let journalRep;
    let service;
    const ev = {};
    const processus = [];

    after(async function () {
      // Aucun démon ni connecteur ne survit au test, même en échec.
      for (const p of processus) if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
      await service?.arreter().catch(() => {});
    });

    function lancerDemon() {
      const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", fichier], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      p.sortie = "";
      p.stdout.on("data", (c) => (p.sortie += c));
      p.stderr.on("data", (c) => (p.sortie += c));
      p.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
      processus.push(p);
      return p;
    }

    const lignesExploitation = (evenement) =>
      fs
        .readFileSync(config.supervision.ops_log.path, "utf8")
        .split("\n")
        .filter((l) => l.length)
        .map((l) => JSON.parse(l))
        .filter((l) => l.event === evenement);

    async function retenueDuJournal(ticket) {
      return (await lireEvenements(journalRep)).filter((e) => e.execution.status === "retenue" && e.policy.ticket === ticket).at(-1);
    }

    before(async function () {
      d2 = repertoireTemporaire("noortrace-politique-demon-");
      fs.mkdirSync(path.join(d2, "prise"), { recursive: true, mode: 0o1777 });
      ({ config, env } = configurationParcours(d2, { version: "demon-1", expire_after_ms: 120000 }));
      service = await lancerServiceApprobation(path.join(d2, "service"), { org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
      config.policy.approval.service.url = service.url;
      env = { ...env, NOORTRACE_TEST_JETON_APPROBATION: service.jetonNoyau };
      config.mcp.enabled = true;
      fichier = path.join(d2, "configuration.json");
      fs.writeFileSync(fichier, JSON.stringify(config, null, 2));
      journalRep = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));

      let demon = lancerDemon();
      await attendre(() => demon.sortie.includes("noortrace: demon demarre"), 30000, 50).catch(() => {
        throw new Error(`démon non démarré : ${demon.sortie}`);
      });
      let h = hote(config.mcp.socket);
      processus.push(h.p);
      await h.requete("tools/list", { _meta: metaModerne() });
      const args = PAIEMENT("9500.00");
      const retenu = h.appeler("demo__payments.create", args);
      await attendre(() => lignesExploitation("approval_held").length === 1 && lignesExploitation("approval_opened").length === 1, 15000);
      const retenue = await attendre(async () => (await lireEvenements(journalRep)).find((e) => e.execution.status === "retenue"), 10000);
      ev.ticket = retenue.policy.ticket;
      ev.lignesAvant = fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter((l) => l.length).length;
      // Arrêt brutal du démon pendant la rétention.
      demon.kill("SIGKILL");
      ev.arret = await demon.fin;
      ev.retenuSansReponse = await Promise.race([retenu.then(() => "reponse"), new Promise((r) => setTimeout(() => r("aucune reponse"), 2000))]);
      h.p.kill("SIGTERM");
      await h.fin;

      demon = lancerDemon();
      await attendre(() => demon.sortie.includes("noortrace: demon demarre"), 30000, 50);
      // EX-7.18, EX-15.4 pas 6 : ouvrir renvoyé au redémarrage pour la retenue sans décision.
      await attendre(() => lignesExploitation("approval_opened").length >= 2, 15000);
      h = hote(config.mcp.socket);
      processus.push(h.p);
      await h.requete("tools/list", { _meta: metaModerne() });
      const reemission = h.appeler("demo__payments.create", args);
      await attendre(() => lignesExploitation("approval_held").length >= 2, 15000);
      await deuxVotes(service, ev.ticket, () => retenue, "approuve");
      ev.relaye = await reemission;
      await h.fermer().catch(() => {});
      demon.kill("SIGTERM");
      ev.arretPropre = await demon.fin;
      ev.retenueFinale = await retenueDuJournal(ev.ticket);
    });

    it("le démon tué pendant la rétention : la requête retenue n'a pas de réponse ; au redémarrage, ouvrir est renvoyé (EX-7.18, EX-15.4 pas 6)", function () {
      expect(ev.arret.signal).to.equal("SIGKILL");
      expect(ev.retenuSansReponse).to.equal("aucune reponse");
      expect(lignesExploitation("approval_opened").length).to.be.at.least(2);
    });

    it("le journal d'exploitation garde les lignes de l'instance tuée (même fichier, ajout seul)", function () {
      const lignes = fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter((l) => l.length);
      expect(lignes.length).to.be.greaterThan(ev.lignesAvant);
      expect(lignesExploitation("startup").length).to.equal(2);
      expect(lignesExploitation("approval_held").length).to.equal(2);
    });

    it("la ré-émission est retenue, approuvée par les votes et relayée ; arrêt propre (SIGTERM, code 0)", function () {
      expect(ev.relaye.result?.structuredContent?.payment_id, JSON.stringify(ev.relaye)).to.match(/^PAY-2026-/);
      expect(ev.arretPropre.code).to.equal(0);
      expect(ev.retenueFinale.policy.ticket).to.equal(ev.ticket);
    });

    it("le journal du démon est vérifié par le noyau ; le dossier de l'appel approuvé par le noyau et par le binaire Go (contrôle 7 réussi)", async function () {
      // Reprise dans le processus, une heure plus tard : la période est close au premier tic.
      const horloge = new HorlogeDecalee(Date.now() + 3600000);
      const v = validerConfiguration(N.utf8(JSON.stringify(config)));
      const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge });
      try {
        await coeur.tic();
        await attendre(() => fs.existsSync(path.join(journalRep, "manifestes")) && fs.readdirSync(path.join(journalRep, "manifestes")).some((n) => n.endsWith(".sig")));
        const evts = await lireEvenements(journalRep);
        const relaye = evts.filter((e) => e.execution.tool === "demo__payments.create" && e.execution.status === "executee").at(-1);
        expect(relaye.approval.ticket).to.equal(ev.ticket);
        expect(evts.filter((e) => e.execution.status === "retenue" && e.policy.ticket === ev.ticket)).to.have.length(1);
        const dossier = path.join(d2, "dossier-approuve");
        await coeur.exporterDossier(relaye.seq, dossier);
        const cles = JSON.parse(fs.readFileSync(path.join(dossier, "cles.json"), "utf8"));
        const r = N.verifierJournal(evts, cles);
        expect(r.valide, JSON.stringify(r.diagnostics)).to.equal(true);
        const index = verifierParNoyau(dossier);
        expect(index.parts.find((p) => p.name === "approbations").present).to.equal(true);
        if (bin) expect(verifierParGo(bin, dossier)[7]).to.deep.equal(["reussi", null]);
      } finally {
        await coeur.arreter();
      }
    });
  });
});
