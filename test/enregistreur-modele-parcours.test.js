// Parcours de bout en bout du frontal modèle (CT-2 §5, corrélation de 5.6) :
// un agent de test réel (processus Node) parle à un fournisseur simulé sur
// 127.0.0.1 à travers la passerelle de l'enregistreur, dans les quatre
// formats de la version 0, en flux puis hors flux, et exécute entre les deux
// l'appel d'outil demandé par le modèle à travers le mandataire MCP du lot
// précédent (serveur d'outils stdio lancé par le démon). Chaque échange et
// chaque appel produit un événement ; chaque appel trouve son échange
// (intent, code.model, code.prompt_version) ; la période est close ; le
// journal est vérifié par la bibliothèque noyau, et les dossiers d'un échange
// et d'un appel corrélé par le noyau et par le binaire Go noortrace-verifier
// (construit par verificateur/scripts/construire.sh avec go1.27.3 pris dans
// NOORTRACE_GO_BIN ; sans lui, ces deux cas sont en attente).
//
// Puis le démon réel `bin/noortrace --config` sert la passerelle : un échange
// en flux est scellé, l'arrêt est propre ; un démon tué pendant un échange en
// vol perd l'échange sans événement, ses pièces de requête restant durables
// (13.5).
//
// Enfin, le démon réel sert le mode ICAP (un mandataire HTTP du client parle
// REQMOD et RESPMOD au serveur ICAP du démon) puis le mode miroir (un
// équipement de copie envoie ses trames au processus bin/noortrace-miroir,
// qui remet les couples à la prise du démon) : les quatre formats sont
// scellés ; après l'arrêt, la période est close, le journal est vérifié par
// la bibliothèque noyau et le dossier d'un échange par le noyau et par le
// binaire Go.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import { demarrerFrontalModele, demarrerFrontalMcp, lireEvenements, piecesRequete, Redacteur } from "@noortrace/enregistreur";
import { RACINE, BIN_NOORTRACE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, configurationIcap, configurationMiroir, valider, demarrerCoeur, horlogeAvancable, JETON_MODELE, JETON_MCP, AGENT, politiquePii } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, TEXTE_AVANT, TEXTE_FIN, evenementsFlux } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import { demarrerMandataire } from "./fixtures/enregistreur-modele/client-icap.mjs";
import { demarrerCopie } from "./fixtures/enregistreur-modele/copie-miroir.mjs";

const BIN_MIROIR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-miroir");

const FORMATS = ["anthropic-messages", "openai-chat", "openai-responses", "gemini"];
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** Construit noortrace-verifier avec go1.27.3, ou rend null (GOFLAGS posé pour cette seule commande). */
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

function lancerAgent(p) {
  return new Promise((res, rej) => {
    const e = spawn(process.execPath, [AGENT, JSON.stringify(p)], { stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreurs = "";
    e.stdout.on("data", (d) => (sortie += d));
    e.stderr.on("data", (d) => (erreurs += d));
    e.on("exit", (code) => (code === 0 ? res(JSON.parse(sortie)) : rej(new Error(`agent (${code}) : ${erreurs}`))));
  });
}

async function portLibre() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
}

describe("enregistreur, frontal modèle : parcours de bout en bout (agent réel, fournisseur simulé, mandataire MCP)", function () {
  this.timeout(180000);
  let dir;
  let fournisseur;
  let coeur;
  let horloge;
  let modele;
  let mcp;
  let resume;
  let evts;
  const parFormat = {};

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-parcours-");
    fournisseur = await new FournisseurSimule({ pauseMs: 3 }).demarrer();
    const c = configurationModele(dir, fournisseur.url, { mcp: true });
    const { config, secrets } = valider(c.config, c.env);
    horloge = horlogeAvancable(N.decoderHorodatage("2026-11-10T10:05:00.000Z"));
    ({ coeur } = await demarrerCoeur(config, secrets, { horloge }));
    modele = await demarrerFrontalModele(coeur, secrets);
    mcp = await demarrerFrontalMcp(coeur, secrets, { correlateur: modele.correlateur });
    resume = await lancerAgent({
      passerelle: `http://127.0.0.1:${modele.passerelle.adresse().port}`,
      jetonModele: JETON_MODELE,
      mcp: `http://127.0.0.1:${mcp.http.adresse().port}/mcp`,
      jetonMcp: JETON_MCP,
      runId: "run-parcours-0001",
    });
    await pause(200);
    evts = await lireEvenements(coeur.repertoire);
    // Événements par format : échange en flux, appel d'outil, échange de conclusion. Un échange
    // n'attend pas son scellement pour rendre la réponse (EX-5.10) : l'appel qui suit peut être
    // scellé avant lui ; les appels, eux, sont dans l'ordre de l'agent.
    const appels = evts.filter((e) => e.execution.tool === "demo__claims.get");
    const prefixes = { "anthropic-messages": "anthropic/", "openai-chat": "openai/modele-chat", "openai-responses": "openai/modele-responses", gemini: "gemini/" };
    FORMATS.forEach((f, k) => {
      const echanges = evts.filter((e) => e.execution.tool === "noortrace.modele.echange" && e.code.model?.startsWith(prefixes[f]));
      parFormat[f] = { flux: echanges.find((e) => e.intent !== TEXTE_FIN), appel: appels[k], fin: echanges.find((e) => e.intent === TEXTE_FIN) };
    });
  });

  after(async function () {
    await mcp?.arreter();
    await modele?.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  it("l'agent a parlé aux quatre formats à travers la passerelle et appelé l'outil par le mandataire MCP", function () {
    expect(resume.outils).to.deep.equal(["demo__claims.get", "demo__payments.create"]);
    for (const f of FORMATS) {
      const r = resume.formats[f];
      expect(r.flux.statut, f).to.equal(200);
      expect(r.flux.type, f).to.equal("text/event-stream");
      expect(r.appel.annonce).to.equal("demo__claims.get");
      expect(r.appel.arguments).to.deep.equal({ claim_id: "2026-81044" });
      expect(r.outil.resultat).to.equal("Sinistre 2026-81044 : ouvert, 7400.00 CHF.");
      expect(r.final.statut).to.equal(200);
    }
    // Le fournisseur n'a reçu que la clé de la route (ou celle de l'hôte, route relayer), jamais un jeton noortrace.
    expect(fournisseur.requetes.length).to.equal(8);
    expect(JSON.stringify(fournisseur.requetes.map((r) => r.entetes))).to.not.match(/jeton-|x-noortrace/);
  });

  it("chaque échange et chaque appel produit un événement", function () {
    expect(evts.length).to.equal(13);
    expect(evts[0].execution.tool).to.equal("noortrace.journal.politique");
    expect(evts.filter((e) => e.execution.tool === "noortrace.modele.echange").length).to.equal(8);
    for (const f of FORMATS) {
      expect(parFormat[f].flux, f).to.not.equal(undefined);
      expect(parFormat[f].fin, f).to.not.equal(undefined);
      expect(parFormat[f].appel.seq, f).to.be.greaterThan(0);
      const { flux, appel, fin } = parFormat[f];
      for (const e of [flux, appel, fin]) {
        expect(e.delegation, f).to.deep.equal({ launched_by: "agent-modele", on_behalf_of: "service-sinistres", scope: "sinistres:lecture", run_id: "run-parcours-0001" });
        expect(e.execution.is_error, f).to.equal(false);
      }
      expect(flux.context).to.deep.equal([]);
      expect(appel.execution.status).to.equal("executee");
      expect(appel.policy.decision).to.equal("autorise");
      expect(appel.context.length).to.equal(2);
    }
  });

  it("corrélation (EX-5.22) : chaque appel reprend intent, code.model et code.prompt_version de l'échange qui l'a demandé", async function () {
    for (const f of FORMATS) {
      const { flux, appel, fin } = parFormat[f];
      expect(appel.code.model, f).to.equal(flux.code.model);
      expect(appel.code.prompt_version, f).to.equal(flux.code.prompt_version);
      expect(flux.code.prompt_version, f).to.match(/^0x[0-9a-f]{64}$/);
      expect(appel.intent, f).to.deep.equal(flux.intent);
      expect(fin.intent, f).to.equal("Le sinistre 2026-81044 est ouvert.");
      // Le prompt système est la pièce rédigée du texte joint ; la requête porte le jeton (EX-8.5).
      const req = JSON.parse(Buffer.from(await coeur.pieces.lire(flux.execution.arguments.sha256)).toString("utf8"));
      expect(JSON.stringify(req)).to.include("[REDIGE:prompt-systeme]");
    }
    expect(parFormat["anthropic-messages"].appel.intent).to.equal(TEXTE_AVANT["anthropic-messages"]);
    expect(parFormat["openai-chat"].appel.intent).to.equal(TEXTE_AVANT["openai-chat"]);
    // Gemini : le texte porte une adresse ; l'intention est une pièce rédigée.
    const g = parFormat.gemini.appel.intent;
    expect(g).to.deep.include({ redacted: true, media_type: "text/plain" });
    expect(Buffer.from(await coeur.pieces.lire(g.sha256)).toString("utf8")).to.equal("Je consulte le sinistre ; contact : [REDIGE:email].");
    expect(parFormat.gemini.appel.policy.redaction).to.equal("pii-v1");
    // Résultat consigné : seq de l'échange, ou de son inscription s'il n'est pas encore scellé (5.6).
    const correlations = fs.readFileSync(coeur.config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((l) => l.event === "correlation");
    expect(correlations.length).to.equal(4);
    correlations.forEach((l, k) => expect([parFormat[FORMATS[k]].flux.seq, "inscription"]).to.include(typeof l.data.seq === "string" ? l.data.seq.split(":")[0] : l.data.seq));
  });

  describe("journal et dossiers de preuve", function () {
    let dossiers;

    before(async function () {
      // Clôture de la période (CT-1 §10) : l'horloge avance d'une heure.
      horloge.avancer(3600 * 1000);
      await coeur.tic();
      dossiers = {};
      for (const [nom, e] of [["echange", parFormat.gemini.flux], ["appel", parFormat["anthropic-messages"].appel]]) {
        const d = path.join(dir, `dossier-${nom}`);
        await coeur.exporterDossier(e.seq, d);
        // Pièces fournies à part : celles que cite l'événement.
        const pieces = path.join(dir, `pieces-${nom}`);
        fs.mkdirSync(pieces, { recursive: true });
        const octets = [];
        for (const ref of [e.execution.arguments, e.execution.result, e.intent, ...e.context].filter((x) => x && typeof x === "object")) {
          const o = await coeur.pieces.lire(ref.sha256);
          fs.writeFileSync(path.join(pieces, ref.sha256.slice(2)), o);
          octets.push(o);
        }
        dossiers[nom] = { d, pieces, octets };
      }
    });

    it("le journal est valide pour la bibliothèque noyau (CT-1 §7, E-1 à E-11) et la période est close", async function () {
      const tous = await lireEvenements(coeur.repertoire);
      const cles = JSON.parse(fs.readFileSync(path.join(dossiers.echange.d, "cles.json"), "utf8"));
      const r = N.verifierJournal(tous, cles);
      expect(r.valide, JSON.stringify(r.diagnostics ?? r)).to.equal(true);
      const m = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "manifestes", "periode-1794304800.json"), "utf8"));
      expect(m.count).to.equal(tous.length);
    });

    it("dossiers d'un échange et d'un appel corrélé valides pour la bibliothèque noyau, pièces comprises (E-6)", function () {
      for (const [nom, { d, octets }] of Object.entries(dossiers)) {
        const r = verifierRepertoireDossier(d, { pieces: octets });
        expect(r.verdict, `${nom} : ${JSON.stringify(r.controles_en_echec)}`).to.equal("valide");
      }
    });

    it("dossiers valides pour le binaire Go noortrace-verifier (go1.27.3)", function () {
      const bin = construireVerificateur(dir);
      if (!bin) this.skip();
      for (const [nom, { d, pieces }] of Object.entries(dossiers)) {
        const r = spawnSync(bin, [d, "--pieces", pieces, "--json"], { encoding: "utf8" });
        expect(r.status, `${nom} : ${r.stdout}${r.stderr}`).to.equal(0);
        const rapport = JSON.parse(r.stdout);
        expect(rapport.verdict, nom).to.equal("valide");
        expect(rapport.failed_checks).to.deep.equal([]);
        const statuts = Object.fromEntries(rapport.controls.map((c) => [c.number, c.status]));
        for (const id of [1, 2, 3, 6]) expect(statuts[id], `${nom}, contrôle ${id}`).to.equal("reussi");
        // Contrôle 7 : approbations, sans objet pour un événement sans `approval` (CT-6).
        expect(statuts[7], `${nom}, contrôle 7`).to.equal("non_execute");
      }
    });
  });
});

describe("enregistreur, frontal modèle : démon réel bin/noortrace", function () {
  this.timeout(120000);
  let fournisseur;

  before(async function () {
    fournisseur = await new FournisseurSimule({ pauseMs: 3 }).demarrer();
  });

  after(async function () {
    await fournisseur?.arreter();
  });

  async function demarrerDemon(dir, o = {}) {
    const c = configurationModele(dir, fournisseur.url);
    const chemin = path.join(dir, "configuration.json");
    fs.writeFileSync(chemin, JSON.stringify(c.config, null, 2));
    const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...c.env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreurs = "";
    p.stderr.on("data", (d) => (erreurs += d));
    await new Promise((res, rej) => {
      p.stdout.on("data", (d) => {
        sortie += d;
        if (/demon demarre/.test(sortie)) res();
      });
      p.on("exit", (code) => rej(new Error(`démon arrêté (${code}) : ${erreurs}`)));
    });
    p.removeAllListeners("exit");
    void o;
    // Port choisi par le système (model.listen 127.0.0.1:0) : lu dans le journal d'exploitation.
    const ligne = fs.readFileSync(c.config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.event === "model_gateway_listening");
    return { p, config: c.config, base: `http://${ligne.data.address}` };
  }

  it("le démon sert la passerelle : un échange en flux est scellé ; SIGTERM : arrêt propre ; journal valide", async function () {
    const dir = repertoireTemporaire("noortrace-modele-demon-");
    const { p, config, base } = await demarrerDemon(dir);
    const r = await fetch(`${base}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": JETON_MODELE }, body: JSON.stringify({ model: "m", max_tokens: 10, system: "Agent.", messages: [{ role: "user", content: "x" }], stream: true }) });
    expect(r.status).to.equal(200);
    expect(await r.text()).to.include("message_stop");
    await pause(300);
    const code = await new Promise((res) => {
      p.on("exit", (c) => res(c));
      p.kill("SIGTERM");
    });
    expect(code).to.equal(0);
    const racine = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
    const evts = await lireEvenements(racine);
    expect(evts.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique", "noortrace.modele.echange"]);
    expect(evts[1].code.model).to.equal("anthropic/m");
    const ops = fs.readFileSync(config.supervision.ops_log.path, "utf8");
    expect(ops).to.include('"event":"model_gateway_listening"');
    expect(ops).to.include('"event":"model_exchange_relayed"');
  });

  it("démon tué pendant un échange en vol : aucun événement, pièces « requête » et « prompt système » durables (13.5)", async function () {
    const dir = repertoireTemporaire("noortrace-modele-demon-");
    const { p, config, base } = await demarrerDemon(dir);
    const corps = { model: "m", max_tokens: 10, system: "Agent du parcours.", messages: [{ role: "user", content: "x" }], stream: true };
    const ev = evenementsFlux("anthropic-messages", corps, 1);
    fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: ev.slice(0, 2), silenceMs: 5000 });
    let recu = false;
    fournisseur.surRequete = () => {
      recu = true;
    };
    const enVol = fetch(`${base}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": JETON_MODELE }, body: JSON.stringify(corps) }).then((x) => x.text()).catch(() => null);
    for (let i = 0; i < 200 && !recu; i++) await pause(10);
    await pause(100);
    p.kill("SIGKILL");
    await enVol;
    fournisseur.surRequete = null;
    fournisseur.scenarios.length = 0;
    const racine = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
    const evts = await lireEvenements(racine);
    expect(evts.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique"]);
    const pr = await piecesRequete({ format: "anthropic-messages", valeur: corps, prompt_in_request: "reference", prompt_system: "redige", redacteur: new Redacteur({ politique: politiquePii(), fils: 0 }) });
    for (const piece of [pr.requete, pr.prompt]) {
      const f = path.join(racine, "pieces", piece.sha256.slice(2, 4), piece.sha256.slice(2));
      expect(fs.existsSync(f), piece.sha256).to.equal(true);
    }
  });
});

describe("enregistreur, frontal modèle : démon réel bin/noortrace en modes icap et miroir", function () {
  this.timeout(180000);
  let fournisseur;
  let bin;
  const CAS = [
    ["/v1/messages", { model: "modele-demon", max_tokens: 16, system: "Agent du démon.", messages: [{ role: "user", content: "Statut ?" }], stream: true }],
    ["/v1/chat/completions", { model: "m", messages: [{ role: "user", content: "x" }] }],
    ["/v1/responses", { model: "m", input: "x", stream: true }],
    ["/v1beta/models/gemini-x:generateContent", { contents: [{ role: "user", parts: [{ text: "x" }] }] }],
  ];
  const MODELES = ["anthropic/modele-demon", "openai/m", "openai/m", "gemini/gemini-simule-001"];

  before(async function () {
    fournisseur = await new FournisseurSimule({ pauseMs: 3 }).demarrer();
  });

  after(async function () {
    await fournisseur?.arreter();
  });

  /** Lance le démon sur une configuration écrite dans `dir` ; rend la ligne d'écoute du journal d'exploitation. */
  async function lancerDemon(dir, c, evenement) {
    const chemin = path.join(dir, "configuration.json");
    fs.writeFileSync(chemin, JSON.stringify(c.config, null, 2));
    const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...c.env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreurs = "";
    p.stderr.on("data", (d) => (erreurs += d));
    await new Promise((res, rej) => {
      p.stdout.on("data", (d) => {
        sortie += d;
        if (/demon demarre/.test(sortie)) res();
      });
      p.on("exit", (code) => rej(new Error(`démon arrêté (${code}) : ${erreurs}`)));
    });
    p.removeAllListeners("exit");
    const ligne = fs.readFileSync(c.config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.event === evenement);
    return { p, ligne };
  }

  const arreterDemon = (p) =>
    new Promise((res) => {
      p.on("exit", (c) => res(c));
      p.kill("SIGTERM");
    });

  async function envoyerCas(base) {
    for (const [chemin, corps] of CAS) {
      const r = await fetch(`${base}${chemin}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps) });
      expect(r.status, chemin).to.equal(200);
      await r.text();
    }
  }

  async function attendreEchanges(racine, n) {
    let e = [];
    for (let i = 0; i < 300; i++) {
      e = (await lireEvenements(racine).catch(() => [])).filter((x) => x.execution.tool === "noortrace.modele.echange");
      if (e.length >= n) break;
      await pause(20);
    }
    return e;
  }

  /**
   * Après l'arrêt du démon : le journal est rouvert une heure plus tard, la
   * période est close (CT-1 §10), le journal est vérifié par le noyau, et le
   * dossier du premier échange par le noyau et par le binaire Go.
   */
  async function prouver(dir, c) {
    const { config, secrets } = valider(c.config, c.env);
    const horloge = horlogeAvancable(Date.now() + 3600 * 1000);
    const { coeur } = await demarrerCoeur(config, secrets, { horloge });
    try {
      await coeur.tic();
      const tous = await lireEvenements(coeur.repertoire);
      const echanges = tous.filter((x) => x.execution.tool === "noortrace.modele.echange");
      const e = echanges[0];
      const d = path.join(dir, "dossier-echange");
      await coeur.exporterDossier(e.seq, d);
      const pieces = path.join(dir, "pieces-echange");
      fs.mkdirSync(pieces, { recursive: true });
      const octets = [];
      for (const ref of [e.execution.arguments, e.execution.result, e.intent, ...e.context].filter((x) => x && typeof x === "object")) {
        const o = await coeur.pieces.lire(ref.sha256);
        fs.writeFileSync(path.join(pieces, ref.sha256.slice(2)), o);
        octets.push(o);
      }
      const cles = JSON.parse(fs.readFileSync(path.join(d, "cles.json"), "utf8"));
      const j = N.verifierJournal(tous, cles);
      expect(j.valide, JSON.stringify(j.diagnostics ?? j)).to.equal(true);
      const manifestes = fs.readdirSync(path.join(coeur.repertoire, "manifestes")).filter((f) => f.startsWith("periode-"));
      expect(manifestes.length).to.be.greaterThan(0);
      const r = verifierRepertoireDossier(d, { pieces: octets });
      expect(r.verdict, JSON.stringify(r.controles_en_echec)).to.equal("valide");
      if (bin === undefined) bin = construireVerificateur(dir);
      if (!bin) return { go: null };
      const g = spawnSync(bin, [d, "--pieces", pieces, "--json"], { encoding: "utf8" });
      expect(g.status, `${g.stdout}${g.stderr}`).to.equal(0);
      const rapport = JSON.parse(g.stdout);
      expect(rapport.verdict).to.equal("valide");
      expect(rapport.failed_checks).to.deep.equal([]);
      const statuts = Object.fromEntries(rapport.controls.map((x) => [x.number, x.status]));
      for (const id of [1, 2, 3, 6]) expect(statuts[id], `contrôle ${id}`).to.equal("reussi");
      return { go: rapport.verdict };
    } finally {
      await coeur.arreter();
    }
  }

  it("mode icap : le mandataire du client passe par REQMOD et RESPMOD du démon ; quatre échanges scellés ; journal et dossier acceptés par le noyau et le binaire Go", async function () {
    const dir = repertoireTemporaire("noortrace-modele-demon-icap-");
    const c = configurationIcap(dir, fournisseur.url);
    const { p, ligne } = await lancerDemon(dir, c, "model_icap_listening");
    expect(ligne.data.services).to.deep.equal(["/noortrace/reqmod", "/noortrace/respmod"]);
    const [host, port] = ligne.data.address.split(":");
    const m = await demarrerMandataire({ icap: { address: host, port: Number(port) }, fournisseur: fournisseur.url });
    const racine = path.join(c.config.storage.root, c.config.recorder.org_id.slice(2), c.config.recorder.journal_id.slice(2));
    try {
      await envoyerCas(m.url);
      const e = await attendreEchanges(racine, 4);
      expect(e.map((x) => x.code.model)).to.deep.equal(MODELES);
      expect(e.every((x) => x.execution.is_error === false && x.delegation.launched_by === "agent-modele")).to.equal(true);
      expect(m.journal.every((t) => t.statut === 200)).to.equal(true);
    } finally {
      await m.arreter();
    }
    expect(await arreterDemon(p)).to.equal(0);
    const ops = fs.readFileSync(c.config.supervision.ops_log.path, "utf8");
    expect(ops).to.include('"mode":"icap"');
    const preuve = await prouver(dir, c);
    if (preuve.go === null) this.skip();
  });

  it("mode miroir : équipement de copie → processus bin/noortrace-miroir → prise du démon ; quatre échanges scellés ; journal et dossier acceptés par le noyau et le binaire Go", async function () {
    const dir = repertoireTemporaire("noortrace-modele-demon-miroir-");
    const c = configurationMiroir(dir, fournisseur.url);
    const { p, ligne } = await lancerDemon(dir, c, "model_mirror_listening");
    expect(ligne.data.socket).to.equal(c.config.model.mirror.socket);
    const ad = spawn(process.execPath, [BIN_MIROIR, "--socket", ligne.data.socket, "--ecoute", "127.0.0.1:0"], { stdio: ["ignore", "pipe", "pipe"] });
    const ecoute = await new Promise((res, rej) => {
      let sortie = "";
      ad.stdout.on("data", (d) => {
        sortie += d;
        const x = /copie ecoutee sur ([0-9.]+):([0-9]+)/.exec(sortie);
        if (x) res({ host: x[1], port: Number(x[2]) });
      });
      ad.on("exit", (code) => rej(new Error(`adaptateur arrêté (${code})`)));
    });
    ad.removeAllListeners("exit");
    const copie = await demarrerCopie({ amont: fournisseur.url, adaptateur: ecoute });
    const racine = path.join(c.config.storage.root, c.config.recorder.org_id.slice(2), c.config.recorder.journal_id.slice(2));
    try {
      await envoyerCas(copie.url);
      const e = await attendreEchanges(racine, 4);
      expect(e.map((x) => x.code.model)).to.deep.equal(MODELES);
      expect(e.every((x) => x.execution.is_error === false && x.delegation.launched_by === "agent-modele")).to.equal(true);
    } finally {
      await copie.arreter();
    }
    expect(await new Promise((res) => {
      ad.on("exit", (code) => res(code));
      ad.kill("SIGTERM");
    })).to.equal(0);
    expect(await arreterDemon(p)).to.equal(0);
    const ops = fs.readFileSync(c.config.supervision.ops_log.path, "utf8");
    expect(ops).to.include('"mode":"miroir"');
    const preuve = await prouver(dir, c);
    if (preuve.go === null) this.skip();
  });
});
