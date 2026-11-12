// Côté démon de l'interface noyau ↔ service d'approbation (CT-2 §7.5,
// EX-9.4, EX-12.23) contre le service factice : réponses d'`evaluer`
// invalides (EX-7.16), remises refusées par SG-2, SG-3, SG-5, SG-6, SG-7
// (EX-7.5), remise pendant un mode dégradé (EX-7.19 pas 1), expiration par le
// noyau seul (EX-9.4), fichiers des approbations et ligne de contrôle du MAC
// (EX-12.23, EX-7.22), canal HTTP (EX-7.14).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, ErreurEnregistreur, validerConfiguration, validerReponseEvaluer, pieceJson, macRelais,
  ClientServiceApprobation, RAISON_EXPIRATION_NOYAU, ligneControleMac,
  ErreurServiceApprobation, FichiersApprobations, verifierRemise, verifierRelais,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { BIN_NOORTRACE, CLE_MAC_HEX, configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

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

// Relecture adversariale A, R-A-7 (EX-18.8, CT-3 EX-12.2) : le pair du service
// d'approbation sur la prise Unix n'était jamais authentifié, et le corps de
// réponse n'était pas borné.
describe("enregistreur, cœur : authentification du service d'approbation sur la prise Unix (R-A-7)", function () {
  this.timeout(30000);
  const reponse = JSON.stringify({ decision: "autorise", rule: null, ticket: null, ticket_state: null });
  async function servir(dir, corps = reponse) {
    const http = await import("node:http");
    const prise = path.join(dir, "approbation.sock");
    const srv = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(corps);
    });
    await new Promise((r) => srv.listen(prise, r));
    return { srv, prise };
  }
  const appeler = async (client) => {
    try {
      return { r: await client.evaluer({ tool_announced: "sap__payments.create" }) };
    } catch (e) {
      return { e };
    }
  };
  const moi = os.userInfo().username;

  it("pair attendu (propriétaire de la prise, répertoire non inscriptible par d'autres) : réponse acceptée", async function () {
    const dir = repertoireTemporaire("noortrace-pair-");
    fs.chmodSync(dir, 0o755);
    const { srv, prise } = await servir(dir);
    try {
      const { r, e } = await appeler(new ClientServiceApprobation({ url: null, socket: prise, jeton: null, timeout_ms: 2000, peer_user: moi }));
      expect(e, e?.message).to.equal(undefined);
      expect(r.decision).to.equal("autorise");
    } finally {
      srv.close();
    }
  });

  it("propriétaire de la prise différent de peer_user, ou peer_user inconnu du système : refus (pair_non_verifie), réponse jamais acceptée", async function () {
    const dir = repertoireTemporaire("noortrace-pair-");
    fs.chmodSync(dir, 0o755);
    const { srv, prise } = await servir(dir);
    try {
      for (const [peer, raison] of [["nobody", "proprietaire_prise"], ["noortrace-approbation", "peer_user_inconnu"]]) {
        const { r, e } = await appeler(new ClientServiceApprobation({ url: null, socket: prise, jeton: null, timeout_ms: 2000, peer_user: peer }));
        expect(r, peer).to.equal(undefined);
        expect(e.code, peer).to.equal("pair_non_verifie");
        expect(e.data, peer).to.deep.equal({ raison });
      }
    } finally {
      srv.close();
    }
  });

  it("répertoire de la prise inscriptible par d'autres : refus (repertoire_inscriptible)", async function () {
    const dir = repertoireTemporaire("noortrace-pair-");
    const { srv, prise } = await servir(dir);
    fs.chmodSync(dir, 0o777);
    try {
      const { e } = await appeler(new ClientServiceApprobation({ url: null, socket: prise, jeton: null, timeout_ms: 2000, peer_user: moi }));
      expect(e?.code).to.equal("pair_non_verifie");
      expect(e.data).to.deep.equal({ raison: "repertoire_inscriptible" });
    } finally {
      srv.close();
    }
  });

  // Étape 7 : CT-8 EX-3.5 place la prise du
  // service dans un répertoire commun aux deux comptes (groupe 10010), que le
  // bit collant protège ; la règle est celle de la prise MCP (EX-4.39,
  // `controlerRepertoirePrise`) : chaque répertoire, du répertoire de la prise
  // à la racine, appartient au compte 0, à `peer_user` ou au démon, et n'est
  // inscriptible par le groupe qu'avec le bit collant ; le répertoire de la
  // prise n'est jamais inscriptible par les autres (EX-18.8 : « non
  // inscriptible par les hôtes ni par les agents »).
  it("EX-18.8, CT-8 EX-3.5 : répertoire de la prise 0:10010 en 3770 (groupe des prises, bit collant) : réponse acceptée ; sans bit collant (2770), inscriptible par les autres même avec le bit collant (1777), ou d'un autre propriétaire : refus (repertoire_inscriptible)", async function () {
    if (process.getuid?.() !== 0) this.skip(); // chown vers 0:10010 : compte 0 requis
    const dir = repertoireTemporaire("noortrace-pair-");
    fs.chmodSync(dir, 0o755);
    const run = path.join(dir, "noortrace");
    fs.mkdirSync(run);
    fs.chownSync(run, 0, 10010);
    fs.chmodSync(run, 0o3770);
    const { srv, prise } = await servir(run);
    const client = () => new ClientServiceApprobation({ url: null, socket: prise, jeton: null, timeout_ms: 2000, peer_user: moi });
    try {
      const ok = await appeler(client());
      expect(ok.e, ok.e?.message + " " + JSON.stringify(ok.e?.data)).to.equal(undefined);
      expect(ok.r.decision).to.equal("autorise");
      for (const [mode, uid] of [[0o2770, 0], [0o1777, 0], [0o3770, 10001]]) {
        fs.chownSync(run, uid, 10010);
        fs.chmodSync(run, mode);
        const { r, e } = await appeler(client());
        expect(r, mode.toString(8)).to.equal(undefined);
        expect(e?.code, mode.toString(8)).to.equal("pair_non_verifie");
        expect(e.data, `${mode.toString(8)} ${uid}`).to.deep.equal({ raison: "repertoire_inscriptible" });
      }
      // Un parent inscriptible par le groupe sans bit collant permet de substituer le répertoire entier.
      fs.chownSync(run, 0, 10010);
      fs.chmodSync(run, 0o3770);
      fs.chmodSync(dir, 0o775);
      const parent = await appeler(client());
      expect(parent.e?.code).to.equal("pair_non_verifie");
      expect(parent.e.data).to.deep.equal({ raison: "repertoire_inscriptible" });
    } finally {
      srv.close();
    }
  });

  it("corps de réponse au-delà de la borne : réponse illisible (trop_grande)", async function () {
    const dir = repertoireTemporaire("noortrace-pair-");
    fs.chmodSync(dir, 0o755);
    const { srv, prise } = await servir(dir, JSON.stringify({ decision: "autorise", rembourrage: "x".repeat(4096) }));
    try {
      const { e } = await appeler(new ClientServiceApprobation({ url: null, socket: prise, jeton: null, timeout_ms: 2000, peer_user: moi, tailleMax: 1024 }));
      expect(e?.code).to.equal("reponse_illisible");
      expect(e.data).to.deep.equal({ raison: "trop_grande" });
    } finally {
      srv.close();
    }
  });
});

// Étape 7 : le
// démon réel (`bin/noortrace --config`) joint le vrai service
// (`bin/noortrace-approbation`) par sa prise, dans le répertoire de CT-8
// EX-3.5 (`/run/noortrace` : compte 0, groupe 10010, mode 3770), où le démon
// crée aussi sa prise MCP. Avant la correction, chaque message était refusé
// (`approval_service_unavailable`, `pair_non_verifie`, raison
// `repertoire_inscriptible`).
describe("enregistreur, démon réel : service d'approbation joint par sa prise dans le répertoire commun de CT-8 EX-3.5 (0:10010, 3770)", function () {
  this.timeout(120000);
  const processus = [];
  let service;

  after(async function () {
    for (const p of processus) if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
    await service?.arreter().catch(() => {});
  });

  it("EX-18.8, CT-3 EX-12.2, CT-8 EX-3.5 : le démon (peer_user, jeton) appelle charger sur approbation.sock dans /run/noortrace 0:10010 3770 et reçoit la liste des candidats (approval_candidates) ; aucune ligne approval_service_unavailable", async function () {
    if (process.getuid?.() !== 0) this.skip(); // chown vers 0:10010 : compte 0 requis
    const { configurationPolitique, lancerServiceApprobation, attendre } = await import("./fixtures/enregistreur-politique/outils.mjs");
    const { spawn } = await import("node:child_process");
    const dir = repertoireTemporaire("noortrace-prise-commune-");
    fs.chmodSync(dir, 0o755);
    const run = path.join(dir, "run", "noortrace");
    fs.mkdirSync(run, { recursive: true });
    fs.chmodSync(path.dirname(run), 0o755);
    fs.chownSync(run, 0, 10010);
    fs.chmodSync(run, 0o3770);
    const socket = path.join(run, "approbation.sock");
    const moi = os.userInfo().username;
    const { config, env } = configurationPolitique(dir, {
      mode: "retenir",
      socket: path.join(run, "mcp.sock"),
      serviceConfig: { url: null, socket, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: moi },
    });
    service = await lancerServiceApprobation(path.join(dir, "service"), { org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, socket });
    expect((fs.statSync(socket).mode & 0o777).toString(8)).to.equal("660");
    config.mcp.enabled = true;
    const fichier = path.join(dir, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(config, null, 2));
    const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", fichier], { env: { ...process.env, ...env, NOORTRACE_TEST_JETON_APPROBATION: service.jetonNoyau }, stdio: ["ignore", "pipe", "pipe"] });
    processus.push(p);
    p.sortie = "";
    p.stdout.on("data", (c) => (p.sortie += c));
    p.stderr.on("data", (c) => (p.sortie += c));
    const fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
    const lignes = () =>
      fs.existsSync(config.supervision.ops_log.path)
        ? fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter((l) => l.length).map((l) => JSON.parse(l))
        : [];
    await attendre(() => p.sortie.includes("noortrace: demon demarre"), 30000, 50).catch(() => {
      throw new Error(`démon non démarré : ${p.sortie}`);
    });
    // Premier `charger` au démarrage (aucun outil encore), puis un second avec
    // la liste du serveur d'outils : le service rend l'outil de paiement candidat.
    const avecOutils = (l) => l.event === "approval_candidates" && l.data.candidates.includes("demo__payments.create");
    await attendre(() => lignes().some((l) => avecOutils(l) || l.event === "approval_service_unavailable"), 20000, 50).catch(() => {
      throw new Error(`ni approval_candidates ni approval_service_unavailable : ${p.sortie}`);
    });
    const indispo = lignes().filter((l) => l.event === "approval_service_unavailable");
    expect(indispo, JSON.stringify(indispo)).to.deep.equal([]);
    expect(lignes().some(avecOutils)).to.equal(true);
    // La prise MCP du démon est dans le même répertoire (EX-4.39, bit collant admis).
    expect(fs.statSync(path.join(run, "mcp.sock")).isSocket()).to.equal(true);
    p.kill("SIGTERM");
    expect((await fin).code).to.equal(0);
  });

  // Étape 7 : le mode `2770` qu'écrit CT-8
  // EX-3.5 est refusé par le démon (EX-4.39, lecture 157) ; `3770` est requis.
  it("CT-8 EX-3.5 (révision demandée) : /run/noortrace 0:10010 en 2770 (sans bit collant) : le démon refuse de démarrer et sort avec le code 2 (frontal_mcp : repertoire_inscriptible ; les serveurs d'outils lancés sont arrêtés) ; en 3770 il démarre (essai précédent)", async function () {
    if (process.getuid?.() !== 0) this.skip();
    const { configurationPolitique } = await import("./fixtures/enregistreur-politique/outils.mjs");
    const { spawnSync } = await import("node:child_process");
    const dir = repertoireTemporaire("noortrace-prise-2770-");
    fs.chmodSync(dir, 0o755);
    const run = path.join(dir, "run", "noortrace");
    fs.mkdirSync(run, { recursive: true });
    fs.chmodSync(path.dirname(run), 0o755);
    fs.chownSync(run, 0, 10010);
    fs.chmodSync(run, 0o2770);
    const { config, env } = configurationPolitique(dir, {
      socket: path.join(run, "mcp.sock"),
      serviceConfig: { url: null, socket: path.join(run, "approbation.sock"), token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: os.userInfo().username },
    });
    config.mcp.enabled = true;
    const fichier = path.join(dir, "configuration.json");
    fs.writeFileSync(fichier, JSON.stringify(config, null, 2));
    const r = spawnSync(process.execPath, [BIN_NOORTRACE, "--config", fichier], { env: { ...process.env, ...env, NOORTRACE_TEST_JETON_APPROBATION: "jeton" }, encoding: "utf8", timeout: 30000 });
    // Le processus sort de lui-même (code 2) : les serveurs d'outils déjà lancés sont arrêtés.
    expect([r.status, r.signal], r.stdout + r.stderr).to.deep.equal([2, null]);
    expect(r.stderr).to.match(/^demarrage_refuse : frontal_mcp : .*repertoire_inscriptible/m);
    expect(fs.existsSync(path.join(run, "mcp.sock"))).to.equal(false);
  });
});

// ------------------------------------------------------------------ relecture adversariale C (non-régression)
//
// Chaque essai de la relecture C côté démon, transformé en test : il échouait
// avant la correction et passe après.

describe("enregistreur, cœur : non-régression de la relecture C (approbations)", function () {
  this.timeout(60000);
  const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null };
  const pause = (ms) => new Promise((r) => setTimeout(r, ms));
  const E_MAX = 86400000;

  /** Cœur sur un répertoire neuf (ou donné) et service factice qui retient les paiements. */
  async function banc(o = {}) {
    const dir = o.dir ?? repertoireTemporaire();
    // `env` n'est passé qu'à `recharger` : rien n'est écrit dans process.env (les tests
    // qui lancent le démon en processus attendent une variable absente).
    const { config: brut, env } = configurationDev(dir);
    const config = validerConfiguration(enc(o.brut ?? brut)).config;
    const horloge = o.horloge ?? new HorlogeReglable(ms("2026-11-10T10:14:02.000Z"));
    const service = o.service ?? new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: () => ({ decision: "a_approuver", rule: "paiement > 5000 CHF" }) });
    const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service });
    return { dir, brut, env, config, horloge, service, coeur };
  }

  async function retenueDe(b, montant = "7400.00", claim = "2026-1") {
    const args = { claim_id: claim, amount: montant, currency: "CHF" };
    const p = pieceJson(args);
    await b.coeur.ecrirePiece(p);
    const capture = { host: { id: "agent-sinistres-stdio" }, delegation, tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", arguments: p.reference, context: [], intent: null, code: {} };
    const requete = { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", arguments: args, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: b.coeur.versionPolitique, recorder: "0.1.0" }, context: [] };
    const reponse = await b.coeur.evaluer(requete);
    const r = await b.coeur.scellerRetenue(capture, reponse, args);
    await pause(20);
    return { ticket: reponse.ticket, evenement: r.evenement, args, capture, requete };
  }

  /** Ticket approuvé, puis relayé (premier `executee` qui porte l'approbation). */
  async function relaisApprouve(b, montant, claim) {
    const x = await retenueDe(b, montant, claim);
    const acq = await b.coeur.traiterRemise(b.service.decider_ticket(x.ticket));
    expect(acq.result).to.equal("scelle");
    const reponse = await b.coeur.evaluer(x.requete);
    expect(reponse.ticket_state).to.equal("approuve");
    const relais = await b.coeur.preparerRelais(x.capture, { reponse, argumentsEnClair: x.args, upstream_id: `amont-${claim}` });
    const resultat = pieceJson({ content: [{ type: "text", text: "ok" }], isError: false });
    const e = await b.coeur.terminerRelais(relais, { resultat, resultatRedige: { content: [{ type: "text", text: "ok" }], isError: false }, argumentsRediges: x.args, duration_ms: 3, is_error: false });
    return { ...x, executee: e, decision: acq };
  }

  it("R-C-3 : sans document de politique de la version, SG-4 et SG-7 échouent ; le noyau expire seul à la borne de E (EX-7.5, EX-9.4)", async function () {
    let b = await banc();
    const x = await retenueDe(b);
    const V1 = b.coeur.versionPolitique;
    const brut2 = structuredClone(b.brut);
    brut2.policy.version = V1 + "-b";
    expect((await b.coeur.recharger(enc(brut2), { env: b.env })).accepte).to.equal(true);
    const cheminV1 = b.coeur.pieces.chemin(b.coeur.index.politiques.get(V1));
    await b.coeur.arreter();
    fs.rmSync(cheminV1);
    b = await banc({ dir: b.dir, brut: brut2, horloge: b.horloge, service: b.service });
    try {
      expect(b.coeur.politiquesParVersion.has(V1)).to.equal(false);
      const Eexp = b.brut.policy.approval.expire_after_ms;
      // après l'échéance réelle, mais avant la borne de E : rien n'est expiré, la remise est refusée
      b.horloge.avancer(Eexp + 10 * 60000);
      expect(await b.coeur.expirerTickets()).to.have.length(0);
      const acq = await b.coeur.traiterRemise(b.service.decider_ticket(x.ticket, { signataires: [0, 2] }));
      expect(acq).to.include({ result: "refuse", reason: "echeance_depassee" });
      // à request_ts + E_max + timeout_ms : expiration par le noyau seul
      const echeance = ms(x.evenement.ts) + E_MAX + b.config.policy.approval.timeout_ms;
      b.horloge.avancer(echeance - b.horloge.murale());
      const expirees = await b.coeur.expirerTickets();
      expect(expirees).to.have.length(1);
      expect(expirees[0].approval).to.include({ decision: "expire", reason: RAISON_EXPIRATION_NOYAU });
    } finally {
      await b.coeur.arreter();
    }
  });

  it("R-C-3 : verifierRemise et verifierRelais : politique introuvable ⇒ échec de SG-4, SG-7 et RL-4 (EX-7.5, EX-7.21)", function () {
    const cle = N.sha256(N.utf8("demandeur"));
    const adr = N.adresseDepuisClePrivee(cle);
    const org = "0x" + "aa".repeat(32);
    const jou = "0x" + "bb".repeat(32);
    const hash = "0x" + "11".repeat(32);
    const remise = (decision) => ({
      remise_id: "apr-1/1", ticket: "apr-1",
      approval: {
        decision, ticket: "apr-1", request_hash: hash, threshold: { required: 1, size: 1 },
        approvers: decision === "expire" ? [] : [adr],
        signatures: decision === "expire" ? [] : [N.signerApprobation(cle, { decision, journal_id: jou, org_id: org, request_hash: hash, ticket: "apr-1" })],
        reason: null,
      },
      approver_set: { threshold: { required: 1, size: 1 }, members: [adr], source: "jeu statique de la politique x" },
    });
    const retenue = { hash, ts: "2026-01-01T00:00:00.000Z", code: { policy_version: "V-absente" }, delegation: { launched_by: "demandeur" } };
    const index = { retenues: new Map([["apr-1", [retenue]]]), decisions: new Map() };
    const ctx = (politique) => ({ index, org_id: org, journal_id: jou, instant: ms("2026-01-01T00:10:00.000Z"), politique });
    const permise = () => ({ approval: { expire_after_ms: 3600000, rules: { separation: { self_approval: "permise", identities: [] } } } });
    const interdite = () => ({ approval: { expire_after_ms: 3600000, rules: { separation: { self_approval: "interdite", identities: [{ launched_by: "demandeur", addresses: [adr] }] } } } });
    expect(verifierRemise(remise("approuve"), ctx(permise)).ok).to.equal(true);
    expect(verifierRemise(remise("approuve"), ctx(interdite))).to.include({ ok: false, verification: "SG-7" });
    expect(verifierRemise(remise("approuve"), ctx(() => null))).to.include({ ok: false, verification: "SG-4", raison: "echeance_depassee" });
    // une remise `expire` n'a ni échéance ni approbateur : elle reste scellable (EX-9.4)
    expect(verifierRemise(remise("expire"), ctx(() => null)).ok).to.equal(true);
    // politique présente sans séparation « interdite » (règles opaques d'un vecteur de CT-2) : SG-7 passe
    expect(verifierRemise(remise("approuve"), ctx(() => ({ approval: { expire_after_ms: 3600000, rules: [] } }))).ok).to.equal(true);
    // RL-4
    const decisionApprouvee = { approval: { decision: "approuve", ticket: "apr-1", request_hash: hash, at: "2026-01-01T00:05:00.000Z" } };
    const retenueEvt = { ...retenue, execution: { tool: "t", arguments: { sha256: "0x" + "22".repeat(32), length: 2, redacted: false } }, delegation: { launched_by: "demandeur", on_behalf_of: null, scope: null } };
    const ctxRelais = (politique) => ({
      index: { decisions: new Map([["apr-1", decisionApprouvee]]), retenuesParHash: new Map([[hash, retenueEvt]]), premiersExecutes: new Map() },
      macs: new Map([[hash, "0xmac"]]), intentionsOuvertes: new Set(), relaisEnCours: new Set(), politique,
    });
    const appel = { ticket: "apr-1", tool: "t", delegation: retenueEvt.delegation, arguments: retenueEvt.execution.arguments, mac: "0xmac", approvalReponse: null, instant: ms("2026-01-01T00:06:00.000Z"), timeoutOutil: 1000 };
    expect(verifierRelais(appel, ctxRelais(permise)).ok).to.equal(true);
    expect(verifierRelais(appel, ctxRelais(() => null))).to.include({ ok: false, verification: "RL-4" });
  });

  it("R-C-4 : une remise `expire` en vol et l'expiration par le noyau seul ne scellent qu'une décision (SG-3, CT-3 14.2)", async function () {
    const b = await banc();
    try {
      const x = await retenueDe(b);
      b.horloge.avancer(b.brut.policy.approval.expire_after_ms + b.brut.policy.approval.timeout_ms + 1000);
      const remise = b.service.decider_ticket(x.ticket, { decision: "expire", reason: "echeance atteinte sans decision" });
      let lacher;
      const retenir = new Promise((r) => (lacher = r));
      b.coeur.o.redaction = { ...(b.coeur.o.redaction ?? {}), redigerMotif: async (m) => { await retenir; return m; } };
      const pRemise = b.coeur.traiterRemise(remise);
      await pause(50); // remise vérifiée (SG-3 passée), en attente de la rédaction du motif
      const pExpiration = b.coeur.expirerTickets();
      await pause(50);
      lacher();
      const [acq, expirees] = await Promise.all([pRemise, pExpiration]);
      const n = expirees.length + (acq.result === "scelle" ? 1 : 0);
      expect(n).to.equal(1);
      expect([...b.coeur.index.retenues.keys()].filter((t) => t === x.ticket)).to.have.length(1);
    } finally {
      await b.coeur.arreter();
    }
  });

  it("R-C-5 : la réponse tardive à un `charger` d'une version remplacée n'est pas adoptée (EX-7.4, CT-3 EX-12.5)", async function () {
    const c = await banc();
    const service = c.service;
    try {
      const V1 = c.coeur.versionPolitique;
      const enAttente = [];
      service.charger = (r) => {
        if (r.policy_version === V1) return new Promise((ok) => enAttente.push(() => ok({ policy_version: r.policy_version, policy_sha256: r.policy_sha256, approval_candidates: [] })));
        return Promise.reject(new ErreurServiceApprobation("indisponible"));
      };
      const lecture = "crm__claims.get";
      c.coeur.definirOutils([{ tool_announced: lecture, tool_original: "claims.get", server_alias: "crm", class: "lecture", effects: null }]);
      expect(enAttente).to.have.length(1);
      const brut2 = structuredClone(c.brut);
      brut2.policy.version = V1 + "-b";
      expect((await c.coeur.recharger(enc(brut2), { env: c.env })).accepte).to.equal(true);
      await pause(20);
      expect(c.coeur.susceptible(lecture)).to.equal(true);
      enAttente[0]();
      await pause(20);
      expect(c.coeur.susceptible(lecture)).to.equal(true);
    } finally {
      await c.coeur.arreter();
    }
  });

  it("R-C-6 : `ouvrir`, `consommer` et `expiration` sont réessayés jusqu'au succès (EX-7.18, EX-7.20, CT-3 12.7)", async function () {
    const b = await banc();
    try {
      let panne = true;
      const compter = (nom) => {
        const vrai = b.service[nom].bind(b.service);
        const c = { essais: 0, reussis: 0 };
        b.service[nom] = async (r) => {
          c.essais++;
          if (panne) throw new ErreurServiceApprobation("indisponible");
          c.reussis++;
          return vrai(r);
        };
        return c;
      };
      const ouvrir = compter("ouvrir");
      const consommer = compter("consommer");
      const expiration = compter("expiration");
      const attendreQue = async (f) => {
        for (let k = 0; k < 100 && !f(); k++) await pause(50);
        return f();
      };
      // service indisponible au moment des deux `retenue`, puis de nouveau disponible
      const x = await retenueDe(b, "7400.00", "2026-1");
      const y = await retenueDe(b, "8100.00", "2026-2");
      await pause(1500);
      expect(ouvrir.reussis).to.equal(0);
      panne = false;
      expect(await attendreQue(() => ouvrir.reussis === 2)).to.equal(true);
      // indisponible pendant le relais approuvé (consommer) et l'expiration par le noyau seul
      panne = true;
      expect((await b.coeur.traiterRemise(b.service.decider_ticket(x.ticket))).result).to.equal("scelle");
      const reponse = await b.coeur.evaluer(x.requete);
      const relais = await b.coeur.preparerRelais(x.capture, { reponse, argumentsEnClair: x.args, upstream_id: "amont-1" });
      await b.coeur.terminerRelais(relais, { resultat: pieceJson({ ok: true }), resultatRedige: { ok: true }, argumentsRediges: x.args, duration_ms: 1, is_error: false });
      b.horloge.avancer(b.brut.policy.approval.expire_after_ms + b.brut.policy.approval.timeout_ms + 1000);
      const expirees = await b.coeur.expirerTickets();
      expect(expirees.map((e) => e.approval.ticket)).to.deep.equal([y.ticket]);
      await pause(1500);
      expect(consommer.reussis + expiration.reussis).to.equal(0);
      expect(consommer.essais).to.be.above(1);
      panne = false;
      expect(await attendreQue(() => consommer.reussis === 1 && expiration.reussis === 1)).to.equal(true);
    } finally {
      await b.coeur.arreter();
    }
  });

  it("R-C-10 : au redémarrage, `consommer` seulement si `approval.at + E` n'est pas passé, en concurrence bornée (EX-7.20)", async function () {
    let b = await banc();
    for (let k = 0; k < 6; k++) await relaisApprouve(b, `${7400 + k}.00`, `2026-${k}`);
    await pause(100);
    await b.coeur.arreter();
    const E = b.brut.policy.approval.expire_after_ms;
    // dans le délai de reconnaissance : six consommer, au plus quatre à la fois
    const lent = new ServiceApprobationFactice({ org_id: b.config.recorder.org_id, journal_id: b.config.recorder.journal_id });
    let enVol = 0;
    let maxEnVol = 0;
    lent.consommer = async (r) => {
      lent.messages.push({ methode: "consommer", corps: r });
      enVol++;
      maxEnVol = Math.max(maxEnVol, enVol);
      await pause(100);
      enVol--;
      return { ticket: r.ticket, state: "consomme" };
    };
    b = await banc({ dir: b.dir, horloge: b.horloge, service: lent });
    await pause(1000);
    await b.coeur.arreter();
    expect(lent.messages.filter((m) => m.methode === "consommer")).to.have.length(6);
    expect(maxEnVol).to.be.at.most(4);
    // délai de reconnaissance écoulé : aucun consommer
    b.horloge.avancer(E + 1000);
    const muet = new ServiceApprobationFactice({ org_id: b.config.recorder.org_id, journal_id: b.config.recorder.journal_id });
    b = await banc({ dir: b.dir, horloge: b.horloge, service: muet });
    await pause(300);
    await b.coeur.arreter();
    expect(muet.messages.filter((m) => m.methode === "consommer")).to.have.length(0);
  });

  it("R-C-11 : une remise mal formée est refusée par SG-1, sans mode dégradé (EX-7.19, EX-9.11)", async function () {
    const b = await banc();
    try {
      for (const r of [{ remise_id: "apr-x/1", ticket: "apr-x" }, null, 42, { remise_id: "apr-x/1", ticket: "apr-x", approval: null, approver_set: null }]) {
        const acq = await b.coeur.traiterRemise(r);
        expect(acq).to.include({ result: "refuse", reason: "remise_mal_formee" });
      }
      expect(b.coeur.degrade.raisons()).to.not.include("stockage");
    } finally {
      await b.coeur.arreter();
    }
  });

  it("R-C-11 : un échec d'écriture du fichier des approbations donne le mode « stockage », dont le tic sort par un nouveau segment (EX-7.19, EX-14.11)", async function () {
    const b = await banc();
    try {
      const x = await retenueDe(b);
      const fA = b.coeur.approbations.fA;
      const vrai = fA.synchroniser.bind(fA);
      let echec = true;
      fA.synchroniser = async () => {
        if (echec) {
          echec = false;
          throw Object.assign(new Error("EIO simulé"), { code: "EIO" });
        }
        return vrai();
      };
      const remise = b.service.decider_ticket(x.ticket);
      const acq = await b.coeur.traiterRemise(remise);
      expect(acq).to.include({ result: "temporaire", reason: "mode_degrade" });
      expect(b.coeur.degrade.raisons()).to.include("stockage");
      b.horloge.avancer(1000);
      await b.coeur.tic();
      expect(b.coeur.degrade.raisons()).to.not.include("stockage");
      const acq2 = await b.coeur.traiterRemise(remise);
      expect(acq2).to.include({ result: "scelle", decision: "approuve" });
      // la ligne `remise` et la ligne `decision` sont relues
      const relu = new FichiersApprobations(b.coeur.repertoire, 99, N.sha256(N.utf8("x")));
      await relu.relire();
      expect(relu.decisions.get(x.ticket)?.hash).to.equal(acq2.hash);
    } finally {
      await b.coeur.arreter();
    }
  });

  it("soupçons du client : 401 et 5xx `requete_invalide` sont une indisponibilité, jamais finale ; délai total d'un message (EX-7.14, EX-7.20)", async function () {
    const http = await import("node:http");
    let mode = "401";
    const srv = http.createServer((req, res) => {
      req.resume();
      if (mode === "goutte") {
        // en-têtes puis un octet toutes les 100 ms, sans fin : le délai d'inactivité ne se déclenche jamais
        res.writeHead(200, { "content-type": "application/json" });
        const t = setInterval(() => res.write(" "), 100);
        res.on("close", () => clearInterval(t));
        return;
      }
      const statut = mode === "401" ? 401 : 500;
      res.writeHead(statut, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "requete_invalide", message: "x", data: {} } }));
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${srv.address().port}`, timeout_ms: 500 });
      for (const m of ["401", "500"]) {
        mode = m;
        let e = null;
        try {
          await client.consommer({ ticket: "apr-1", seq: 1, hash: "0x" + "11".repeat(32) });
        } catch (x) {
          e = x;
        }
        expect(e?.code, m).to.equal("indisponible");
      }
      mode = "goutte";
      const t0 = Date.now();
      let e = null;
      try {
        await client.consommer({ ticket: "apr-1", seq: 1, hash: "0x" + "11".repeat(32) });
      } catch (x) {
        e = x;
      }
      expect(e?.code).to.equal("indisponible");
      expect(Date.now() - t0).to.be.below(1500);
    } finally {
      srv.closeAllConnections?.();
      srv.close();
    }
  });

  it("soupçon `held` : la fin d'une rétention pendant les attentes de la remise donne held:false ; tenue jusqu'au scellement, held:true (EX-7.19 pas 3)", async function () {
    const b = await banc();
    try {
      const retenus = new Set();
      const decidees = [];
      b.coeur.brancherRetention({ retient: (t) => retenus.has(t), decidee: (t) => { if (retenus.delete(t)) decidees.push(t); } });
      let lacher;
      let retenir = new Promise((r) => (lacher = r));
      b.coeur.o.redaction = { ...(b.coeur.o.redaction ?? {}), redigerMotif: async (m) => { await retenir; return m; } };
      // 1. la rétention prend fin (hold_timeout_ms) pendant que la remise attend
      const x = await retenueDe(b, "7400.00", "2026-1");
      retenus.add(x.ticket);
      b.service.decider_ticket(x.ticket);
      const p1 = b.coeur.traiterRemises();
      await pause(50);
      retenus.delete(x.ticket);
      lacher();
      const [acq1] = await p1;
      expect(acq1).to.include({ result: "scelle", decision: "approuve", held: false });
      // 2. la rétention tient jusqu'au scellement : held vrai, et la requête retenue est réclamée
      retenir = new Promise((r) => (lacher = r));
      const y = await retenueDe(b, "8100.00", "2026-2");
      retenus.add(y.ticket);
      b.service.decider_ticket(y.ticket);
      const p2 = b.coeur.traiterRemises();
      await pause(50);
      lacher();
      const [acq2] = await p2;
      expect(acq2).to.include({ result: "scelle", decision: "approuve", held: true });
      expect(decidees).to.include(y.ticket);
    } finally {
      await b.coeur.arreter();
    }
  });
});
