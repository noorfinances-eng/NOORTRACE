// Parcours de bout en bout du SDK et de l'ingestion OpenTelemetry (CT-2 §6,
// section c d'INTERFACES.md) : de vrais processus. Le démon réel
// `bin/noortrace --config` (point d'entrée SDK sur une prise Unix, ingestion
// OTLP/HTTP), le vrai service d'approbation (`paquets/approbation`,
// `bin/noortrace-approbation`) qui évalue la politique et décide sur les
// votes EIP-191 des comptes de test Hardhat 1 et 2 déposés par son canal de
// la console, et un agent Node.js réel (`fixtures/enregistreur-sdk/agent.mjs`)
// qui emploie `noortrace-sdk` : session ouverte, contexte déclaré, appel de
// lecture, appel d'écriture (intention durable avant le retour de
// `debutAppel`), appel refusé, appel soumis à approbation puis relayé, échange
// de modèle déclaré, spans exportés par l'exportateur officiel OTLP/HTTP du
// SDK OpenTelemetry JavaScript (`@opentelemetry/exporter-trace-otlp-http`) et
// par un exportateur minimal en protobuf, fermeture avec un appel
// resté ouvert (événement de reprise). Le journal est vérifié par la
// bibliothèque noyau ; la période close, le dossier d'un événement de chaque
// sorte est vérifié par le noyau et par le binaire Go `noortrace-verifier`
// (construit par verificateur/scripts/construire.sh avec go1.27.3 :
// NOORTRACE_GO_BIN, sinon PATH ; sans lui, ces deux essais sont en attente).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { Coeur, HorlogeReglable, lireEvenements, resoudreSecrets, pieceDeclarationSource } from "@noortrace/enregistreur";
import { CLES_HARDHAT } from "@noortrace/enregistreur/factice";
import { RACINE, SPEC, configurationDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { hoteSdk } from "./fixtures/enregistreur-sdk/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);

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

/** Première ligne JSON d'un flux qui satisfait `f`. */
function attendreLigne(flux, f, delai = 30000) {
  return new Promise((resoudre, rejeter) => {
    const rl = readline.createInterface({ input: flux });
    const t = setTimeout(() => rejeter(new Error("ligne attendue non reçue")), delai);
    rl.on("line", (l) => {
      let m = null;
      try {
        m = JSON.parse(l);
      } catch {
        m = l;
      }
      if (f(m)) {
        clearTimeout(t);
        rl.removeAllListeners("line");
        resoudre(m);
      }
    });
  });
}

const JETON_NOYAU = "jeton-noyau-du-parcours-sdk-0001";
const JETON_CONSOLE = "jeton-console-du-parcours-sdk-0002";

describe("enregistreur, SDK et OpenTelemetry : parcours de bout en bout (démon réel, vrai service d'approbation, agent Node.js réel)", function () {
  this.timeout(300000);
  let dir;
  let config;
  let service;
  let demon;
  const etapes = {};
  let evts;
  let consoleAdresse;
  let fichierConfig;
  let env;
  const dossiers = {};

  before(async function () {
    dir = repertoireTemporaire("noortrace-sdk-parcours-");
    // Service d'approbation réel (CT-3 §12) : canal du noyau et canal de la console, annuaire de référence de CT-3.
    const dirService = path.join(dir, "approbation");
    fs.mkdirSync(dirService, { recursive: true, mode: 0o700 });
    fs.copyFileSync(path.join(SPEC, "vecteurs", "ct-3", "annuaire", "annuaires", "reference.json"), path.join(dirService, "annuaire.json"));
    const cfgService = {
      version: 0,
      environment: "developpement",
      org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
      journal_id: null,
      state_dir: path.join(dirService, "etat"),
      storage_key: { env: "NOORTRACE_ESSAI_CLE_STOCKAGE" },
      noyau: { tcp: { host: "127.0.0.1", port: 0 }, token: { env: "NOORTRACE_ESSAI_JETON_NOYAU" } },
      console: { tcp: { host: "127.0.0.1", port: 0 }, token: { env: "NOORTRACE_ESSAI_JETON_CONSOLE" }, annuaire: "annuaire.json" },
      tickets: { epoch: null },
    };
    const hote = hoteSdk();
    ({ config, env } = configurationDev(dir, { sdk: { hosts: [hote] } }));
    config.sdk.socket = path.join(dir, "p", "sdk.sock");
    cfgService.journal_id = config.recorder.journal_id;
    config.recorder.org_id = cfgService.org_id;
    fs.writeFileSync(path.join(dirService, "config.json"), JSON.stringify(cfgService, null, 2));
    env = {
      ...process.env,
      ...env,
      NOORTRACE_ESSAI_CLE_STOCKAGE: "11".repeat(32),
      NOORTRACE_ESSAI_JETON_NOYAU: JETON_NOYAU,
      NOORTRACE_ESSAI_JETON_CONSOLE: JETON_CONSOLE,
    };
    service = spawn(process.execPath, [path.join(RACINE, "paquets", "approbation", "bin", "noortrace-approbation"), "--config", path.join(dirService, "config.json")], { env, stdio: ["ignore", "pipe", "inherit"] });
    const pret = await attendreLigne(service.stdout, (m) => m && m.pret === true);
    const port = (x) => x?.port ?? x?.tcp?.port;
    consoleAdresse = `http://127.0.0.1:${port(pret.console)}`;

    // Démon : politique d'approbation de l'agent local (lecture et écriture autorisées, suppression refusée,
    // paiement soumis aux approbateurs, jeu statique des comptes Hardhat 1 à 3, seuil 2 sur 3).
    config.policy.version = "2026-11-10-sdk-parcours";
    config.policy.approval.rules = {
      version: 0,
      default: { name: "defaut : revue", description: null, level: "revue", decision: null, contest_ms: 0 },
      rules: [
        { name: "lectures et notes", description: null, tools: ["agent-local__lire_sinistre", "agent-local__ecrire_note"], when: null, level: "automatique", decision: "autorise", window: null, contest_ms: null },
        { name: "suppression interdite", description: null, tools: ["agent-local__supprimer_dossier"], when: null, level: "automatique", decision: "refuse", window: null, contest_ms: null },
        { name: "paiement", description: null, tools: ["agent-local__preparer_paiement"], when: null, level: "revue", decision: null, window: null, contest_ms: 0 },
      ],
      approver_set: {
        source: "statique",
        chain_id: null,
        registry: null,
        set: null,
        members: CLES_HARDHAT.map((c) => N.adresseDepuisClePrivee(N.hexVersOctets(c, 32))).sort(),
        threshold: { required: 2, size: 3 },
      },
      separation: { self_approval: "interdite", identities: [] },
    };
    config.policy.approval.service = { url: `http://127.0.0.1:${port(pret.noyau)}`, socket: null, token: { env: "NOORTRACE_ESSAI_JETON_NOYAU" }, peer_user: null };
    fichierConfig = path.join(dir, "configuration.json");
    fs.writeFileSync(fichierConfig, JSON.stringify(config, null, 2));
    demon = spawn(process.execPath, [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace"), "--config", fichierConfig], { env, stdio: ["ignore", "pipe", "pipe"] });
    let erreurDemon = "";
    demon.stderr.on("data", (x) => (erreurDemon += x));
    try {
      await attendreLigne(demon.stdout, (m) => typeof m === "string" && m.startsWith("noortrace: demon demarre"));
    } catch (e) {
      throw new Error(`démon non démarré : ${erreurDemon}`);
    }
    // Le démon ouvre ses frontaux sans attendre la réponse de `charger` (EX-15.4 pas 6) : l'agent est lancé
    // une fois la liste des outils susceptibles d'approbation obtenue (`approval_candidates`).
    const lireOps = () => fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    for (let k = 0; k < 200 && !lireOps().some((l) => l.event === "approval_candidates"); k++) await new Promise((r) => setTimeout(r, 50));
    const ops = lireOps();
    expect(ops.some((l) => l.event === "approval_candidates"), JSON.stringify(ops.filter((l) => l.component === "politique"))).to.equal(true);
    const otel = ops.find((l) => l.event === "otel_listening").data.address;

    // Agent Node.js réel.
    const racineJournal = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
    const agent = spawn(process.execPath, [path.join(RACINE, "test", "fixtures", "enregistreur-sdk", "agent.mjs")], {
      cwd: RACINE,
      env: {
        ...env,
        NOORTRACE_SDK_SOCKET: config.sdk.socket,
        NOORTRACE_ESSAI_INTENTIONS: path.join(racineJournal, "intentions"),
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: `http://${otel}/v1/traces`,
        OTEL_EXPORTER_OTLP_TRACES_HEADERS: `x-noortrace-token=${env.NOORTRACE_TEST_SECRET_OTEL ?? jetonOtel(config, env)}`,
      },
      stdio: ["pipe", "pipe", "inherit"],
    });
    const rl = readline.createInterface({ input: agent.stdout });
    const fin = new Promise((r) => agent.on("exit", r));
    rl.on("line", async (l) => {
      const m = JSON.parse(l);
      etapes[m.etape] = m;
      if (m.etape === "retenue") {
        // Votes signés (EIP-191, CT-1 §6.3) des approbateurs 1 et 2, par le canal de la console (CT-3 12.9).
        const e = (await lireEvenements(racineJournal)).find((x) => x.execution.status === "retenue" && x.policy.ticket === m.debut.ticket);
        const A = { decision: "approuve", journal_id: config.recorder.journal_id, org_id: config.recorder.org_id, request_hash: e.hash, ticket: m.debut.ticket };
        for (const [k, identite] of [[0, "oidc https://idp.assureur-demo.example approbateur-1"], [1, "oidc https://idp.assureur-demo.example approbateur-2"]]) {
          const cle = N.hexVersOctets(CLES_HARDHAT[k], 32);
          const corps = { ticket: m.debut.ticket, approver: N.adresseDepuisClePrivee(cle), decision: "approuve", signature: N.signerApprobation(cle, A), reason: null, session_identity: identite };
          const r = await fetch(`${consoleAdresse}/v0/voter`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${JETON_CONSOLE}` }, body: JSON.stringify(corps) });
          etapes[`vote${k}`] = { statut: r.status, corps: await r.json() };
        }
        agent.stdin.write("vote\n");
      }
    });
    const code = await fin;
    expect(code, JSON.stringify(etapes)).to.equal(0);
    // Arrêt propre du démon (SIGTERM) et du service.
    demon.kill("SIGTERM");
    await new Promise((r) => demon.on("exit", r));
    service.kill("SIGTERM");
    await new Promise((r) => service.on("exit", r));
    evts = await lireEvenements(racineJournal);
  });

  after(function () {
    if (demon && demon.exitCode === null) demon.kill("SIGKILL");
    if (service && service.exitCode === null) service.kill("SIGKILL");
  });

  it("l'agent a traversé le démon : lecture, écriture à intention durable avant exécution, refus, approbation par votes, échange, OpenTelemetry, fermeture", function () {
    expect(etapes.lecture.resultat).to.deep.equal({ sinistre: "2026-77812", statut: "ouvert" });
    expect(etapes.ecriture.decision).to.equal("autorise");
    expect(etapes.ecriture.intention_durable_avant_execution).to.equal(true);
    expect(etapes.refus.debut).to.deep.equal({ call: null, decision: "refuse", ticket: null, ticket_state: null });
    expect(etapes.retenue.debut.decision).to.equal("a_approuver");
    expect(etapes.retenue.debut.ticket_state).to.equal("nouveau");
    expect(etapes.vote0.statut).to.equal(200);
    expect(etapes.vote1.statut).to.equal(200);
    expect(etapes.approuve.debut.ticket_state).to.equal("approuve");
    expect(etapes.approuve.intention_durable_avant_execution).to.equal(true);
    expect(etapes.echange.scelle.seq).to.be.a("number");
    expect(etapes.otel.reponse).to.deep.equal({ statut: 200, corps: "" });
    // Exportateur officiel : ExportResultCode.SUCCESS (0), deux spans.
    expect(etapes.otel_officiel.resultat).to.deep.equal({ code: 0, erreur: null, spans: 2 });
    expect(etapes.fermee).to.not.equal(undefined);
  });

  it("chaque appel a son événement, de la sorte attendue (7.2, EX-6.7, EX-6.36, EX-7.7, EX-12.15)", function () {
    const outil = (t) => evts.filter((e) => e.execution.tool === t);
    expect(evts[0].execution.tool).to.equal("noortrace.journal.politique");
    const lecture = outil("agent-local__lire_sinistre")[0];
    expect(lecture.context[0].kind).to.equal("document");
    expect(lecture.context[0].redacted).to.equal(true);
    expect(lecture.delegation.run_id).to.equal("run-parcours-0001");
    const notes = outil("agent-local__ecrire_note");
    expect(notes).to.have.length(2);
    expect(notes[0].execution.is_error).to.equal(false);
    expect(notes[0].intent).to.equal("Noter la réception des pièces");
    // Fermeture avec un appel d'écriture ouvert : événement de reprise.
    expect(notes[1].execution.is_error).to.equal(true);
    expect(notes[1].execution.duration_ms).to.equal(0);
    expect(outil("agent-local__supprimer_dossier")[0].execution.status).to.equal("refusee");
    const paiement = outil("agent-local__preparer_paiement");
    expect(paiement.map((e) => e.execution.status)).to.deep.equal(["retenue", "executee"]);
    const decision = outil("noortrace.approbation.decision")[0];
    expect(decision.approval.decision).to.equal("approuve");
    expect(decision.approval.request_hash).to.equal(paiement[0].hash);
    expect(paiement[1].approval).to.deep.equal(decision.approval);
    const echanges = outil("noortrace.modele.echange");
    const sdk = echanges.find((e) => e.context[0]?.sha256 === pieceDeclarationSource("sdk", "agent-local").sha256);
    expect(sdk.code.model).to.equal("gemini/gemini-exemple-001");
    expect(sdk.intent).to.equal("Je consulte le sinistre.");
    const otelInference = echanges.find((e) => e.context[0]?.sha256 === pieceDeclarationSource("otel", "otel-sinistres").sha256);
    expect(otelInference.code.model).to.equal("openai/modele-otel-1");
    expect(otelInference.intent).to.equal("Je classe le dossier.");
    expect(outil("otel-sinistres__classer_dossier")[0].policy.decision).to.equal("autorise");
    // Spans de l'exportateur officiel (OTLP/HTTP JSON) : un échange et un appel d'outil scellés.
    const officielInference = echanges.find((e) => e.code.model === "openai/modele-officiel-1");
    expect(officielInference.context[0].sha256).to.equal(pieceDeclarationSource("otel", "otel-sinistres").sha256);
    expect(officielInference.intent).to.equal("J'archive le dossier.");
    const archive = outil("otel-sinistres__archiver_dossier");
    expect(archive).to.have.length(1);
    expect(archive[0].context[0].sha256).to.equal(pieceDeclarationSource("otel", "otel-sinistres").sha256);
    expect(archive[0].execution.status).to.equal("executee");
  });

  it("le journal vérifie par la bibliothèque noyau (CT-1 §7, E-1 à E-11)", async function () {
    // Clôture de la période dans un démon redémarré à l'heure suivante, puis export des dossiers.
    const s = resoudreSecrets(config, { env });
    const fin = ms(evts.at(-1).ts);
    const horloge = new HorlogeReglable(Math.ceil((fin + 1) / 3600000) * 3600000 + 2000);
    const coeur = await Coeur.demarrer({ config: { ...config, policy: config.policy }, secrets: s.secrets, horloge });
    try {
      await coeur.tic();
      const choisis = {
        politique: evts[0],
        appel_lecture: evts.find((e) => e.execution.tool === "agent-local__lire_sinistre"),
        appel_ecriture: evts.find((e) => e.execution.tool === "agent-local__ecrire_note" && !e.execution.is_error),
        refus: evts.find((e) => e.execution.status === "refusee"),
        retenue: evts.find((e) => e.execution.status === "retenue"),
        decision: evts.find((e) => e.execution.tool === "noortrace.approbation.decision"),
        appel_approuve: evts.find((e) => e.execution.tool === "agent-local__preparer_paiement" && e.execution.status === "executee"),
        reprise: evts.find((e) => e.execution.tool === "agent-local__ecrire_note" && e.execution.is_error),
        echange_sdk: evts.find((e) => e.execution.tool === "noortrace.modele.echange" && e.context[0]?.sha256 === pieceDeclarationSource("sdk", "agent-local").sha256),
        inference_otel: evts.find((e) => e.execution.tool === "noortrace.modele.echange" && e.context[0]?.sha256 === pieceDeclarationSource("otel", "otel-sinistres").sha256),
        outil_otel: evts.find((e) => e.execution.tool === "otel-sinistres__classer_dossier"),
        outil_otel_officiel: evts.find((e) => e.execution.tool === "otel-sinistres__archiver_dossier"),
      };
      for (const [nom, e] of Object.entries(choisis)) {
        expect(e, nom).to.not.equal(undefined);
        dossiers[nom] = path.join(dir, "dossiers", nom);
        await coeur.exporterDossier(e.seq, dossiers[nom]);
      }
    } finally {
      await coeur.arreter();
    }
    const cles = JSON.parse(fs.readFileSync(path.join(dossiers.politique, "cles.json"), "utf8"));
    const r = N.verifierJournal(evts, cles);
    expect(r.valide, JSON.stringify(r.diagnostics ?? r)).to.equal(true);
  });

  it("le dossier d'un événement de chaque sorte est valide pour la bibliothèque noyau", function () {
    for (const [nom, d] of Object.entries(dossiers)) {
      const r = verifierRepertoireDossier(d);
      expect(r.verdict, `${nom} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
    }
  });

  it("le dossier d'un événement de chaque sorte est valide pour le binaire Go noortrace-verifier (go1.27.3)", function () {
    const bin = construireVerificateur(dir);
    if (!bin) this.skip();
    for (const [nom, d] of Object.entries(dossiers)) {
      const r = spawnSync(bin, [d, "--json"], { encoding: "utf8" });
      expect(r.status, `${nom} : ${r.stdout}${r.stderr}`).to.equal(0);
      const rapport = JSON.parse(r.stdout);
      expect(rapport.verdict, nom).to.equal("valide");
      expect(rapport.failed_checks, nom).to.deep.equal([]);
    }
  });
});

/** Jeton de la source OpenTelemetry de l'exemple de 15.3, résolu dans l'environnement de test. */
function jetonOtel(config, env) {
  const ref = config.otel.static_tokens[0].token;
  return env[ref.env];
}
