// Frontal MCP (CT-2 §4) : parcours de bout en bout avec de vrais processus.
//
// Un hôte de test lance le connecteur stdio `noortrace-connecteur` et lui
// parle en JSON-RPC ; le connecteur joint la prise Unix du démon (identité du
// pair prouvée par fichier, EX-4.39) ; le frontal relaie vers deux serveurs
// d'outils stdio lancés par lui (l'un de l'ère moderne, l'autre de l'ère
// héritée, EX-4.6) ; un second hôte, hérité, passe aussi par un connecteur ;
// un troisième parle Streamable HTTP avec un jeton statique. Chaque appel
// produit un événement scellé (lecture, écriture retenue puis relayée après
// approbation, refus, délai, erreur JSON-RPC, serveur hérité). La période est
// close, puis le journal est vérifié par le noyau, et le dossier de chaque
// appel par le noyau ET par le binaire Go `noortrace-verifier` (construit par
// verificateur/scripts/construire.sh avec go1.27.3, répertoire de `go` dans
// NOORTRACE_GO_BIN ; sans lui, ce dernier test est en attente).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";
import {
  Coeur, FrontalMcp, ServeurConnecteurs, ServeurHttpMcp, validerConfiguration, resoudreSecrets, lireEvenements, clesDuJournal,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, BIN_NOORTRACE, graine, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, hoteDemo, serveurStdio, reglageOutil, RedacteurTest } from "./fixtures/enregistreur-mcp/outils.mjs";
import { ClientHote, metaModerne } from "./fixtures/enregistreur-mcp/client-hote.mjs";

const SERVEUR = path.join(RACINE, "test", "fixtures", "enregistreur-mcp", "serveur-outils.mjs");
const ms = (x) => N.decoderHorodatage(x);

/** Horloge réelle décalée : murale et monotone avancent ensemble, et d'un bond. */
class HorlogeDecalee {
  constructor(debut) {
    this.base = debut;
    this.t0 = performance.now();
    this.decalage = 0;
  }

  murale() {
    return Math.floor(this.base + (performance.now() - this.t0) + this.decalage);
  }

  monotone() {
    return Math.floor(1000000 + performance.now() - this.t0 + this.decalage);
  }

  avancer(x) {
    this.decalage += x;
  }
}

/** Construit noortrace-verifier avec go1.27.3, ou rend null. */
export function construireVerificateur(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOFLAGS: "-mod=vendor", GOTOOLCHAIN: "local" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  return sortie;
}

function posterHttp(adresse, corps, entetes) {
  return new Promise((res, rej) => {
    const req = http.request({ host: "127.0.0.1", port: adresse.port, path: "/mcp", method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...entetes } }, (r) => {
      const m = [];
      r.on("data", (c) => m.push(c));
      r.on("end", () => res({ statut: r.statusCode, entetes: r.headers, corps: Buffer.concat(m).toString("utf8") }));
    });
    req.on("error", rej);
    req.end(corps);
  });
}

describe("enregistreur, frontal MCP : parcours de bout en bout (hôtes, connecteur, serveurs stdio, journal vérifié)", function () {
  this.timeout(180000);
  let dir;
  let coeur;
  let frontal;
  let connecteurs;
  let serveurHttp;
  let service;
  let horloge;
  const r = {};
  const appelsAttendus = [];
  const clients = [];

  before(async function () {
    dir = repertoireTemporaire("noortrace-mcp-parcours-");
    const moi = os.userInfo().username;
    const servers = {
      demo: serveurStdio([process.execPath, SERVEUR], {
        protocol: "auto",
        tools: { "payments.create": reglageOutil({ class: "ecriture" }), "slow.op": reglageOutil({ timeout_ms: 300 }) },
      }),
      archives: serveurStdio([process.execPath, SERVEUR, "--herite"], { protocol: "auto" }),
    };
    const hotes = [
      { ...hoteDemo({ id: "agent-stdio", match: { peer_user: moi }, launched_by: "${peer_user}" }) },
      { ...hoteDemo({ id: "poste-http", match: { static_token: "poste-http" }, launched_by: "poste-http" }), accept_declared_delegation: false, host_group: "poste-http" },
    ];
    const { config: brute, env } = configurationMcp(dir, {
      servers,
      hosts: hotes,
      socket: path.join(dir, "prise", "mcp.sock"),
      http: { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "poste-http", token: { env: "NOORTRACE_TEST_JETON_HTTP" } }] },
      journal_id: N.octetsVersHex(N.keccak256(N.utf8("journal-mcp-parcours"))),
    });
    brute.model.hosts = [];
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const s = resoudreSecrets(v.config, { env: { ...env, NOORTRACE_TEST_JETON_HTTP: "jeton-http-de-test" } });
    expect(s.erreurs).to.deep.equal([]);
    horloge = new HorlogeDecalee(ms("2026-11-10T10:30:00.000Z"));
    service = new ServiceApprobationFactice({
      org_id: v.config.recorder.org_id,
      journal_id: v.config.recorder.journal_id,
      decider: (q) => {
        if (q.tool_announced === "demo__payments.create") return { decision: "a_approuver", rule: "paiement soumis a approbation" };
        if (q.arguments?.claim_id === "REFUS") return { decision: "refuse", rule: "sinistre bloque" };
        return { decision: "autorise", rule: null };
      },
    });
    coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge, service });
    frontal = new FrontalMcp({ coeur, redacteur: new RedacteurTest() });
    await frontal.demarrer();
    connecteurs = new ServeurConnecteurs({ frontal, socket: v.config.mcp.socket });
    await connecteurs.ecouter();
    serveurHttp = new ServeurHttpMcp({ frontal, jetons: new Map([["poste-http", s.secrets.get("/mcp/http/static_tokens/0/token")]]) });
    await serveurHttp.ecouter();

    // Hôte moderne par le connecteur stdio.
    const a = new ClientHote(["--socket", v.config.mcp.socket]);
    clients.push(a);
    r.listeA = await a.requete("tools/list", { _meta: metaModerne() });
    const meta = metaModerne({ "noortrace/delegation": { run_id: "run-parcours-0001" } });
    r.lecture = await a.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "2026-81044" }, _meta: meta });
    appelsAttendus.push(["demo__claims.get", "executee"]);
    r.progression = await a.requete("tools/call", { name: "demo__claims.search", arguments: { query: "collision" }, _meta: { ...meta, progressToken: "jeton-hote-7" } });
    appelsAttendus.push(["demo__claims.search", "executee"]);
    r.notifications = a.notifications.filter((n) => n.method === "notifications/progress");
    const paiement = { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" };
    r.retenue = await a.requete("tools/call", { name: "demo__payments.create", arguments: paiement, _meta: meta });
    appelsAttendus.push(["demo__payments.create", "retenue"]);
    r.enAttente = await a.requete("tools/call", { name: "demo__payments.create", arguments: paiement, _meta: meta });
    const ticket = r.retenue.result._meta["noortrace/approval"].ticket;
    service.decider_ticket(ticket, { reason: "Pieces validees" });
    r.acquittements = await coeur.traiterRemises();
    r.relaye = await a.requete("tools/call", { name: "demo__payments.create", arguments: paiement, _meta: meta });
    appelsAttendus.push(["demo__payments.create", "executee"]);
    r.herite = await a.requete("tools/call", { name: "archives__documents.get", arguments: { document_id: "DOC-31" }, _meta: meta });
    appelsAttendus.push(["archives__documents.get", "executee"]);
    r.delai = await a.requete("tools/call", { name: "demo__slow.op", arguments: { delay_ms: 3000 }, _meta: meta });
    appelsAttendus.push(["demo__slow.op", "executee"]);
    r.erreur = await a.requete("tools/call", { name: "demo__fail.rpc", arguments: {}, _meta: meta });
    appelsAttendus.push(["demo__fail.rpc", "executee"]);
    r.refus = await a.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "REFUS" }, _meta: meta });
    appelsAttendus.push(["demo__claims.get", "refusee"]);
    r.inconnu = await a.requete("tools/call", { name: "demo__nexiste.pas", arguments: {}, _meta: meta });
    a.envoyerLigne('{"jsonrpc":"2.0","id":"cr","method":"tools/call","params":{"name":"demo__claims.get"}\r}');
    r.cr = JSON.parse(await new Promise((res) => setTimeout(() => res(a.lignes.at(-1)), 300)));
    r.codeA = await a.fermer();

    // Hôte hérité par un second connecteur.
    const b = new ClientHote(["--socket", v.config.mcp.socket]);
    clients.push(b);
    r.initB = await b.requete("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "hote-herite", version: "1.0.0" } }, 1);
    b.envoyerLigne('{"jsonrpc":"2.0","method":"notifications/initialized"}');
    r.listeB = await b.requete("tools/list", {}, 2);
    r.lectureB = await b.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "2026-81045" } }, 3);
    appelsAttendus.push(["demo__claims.get", "executee"]);
    await b.fermer();

    // Hôte Streamable HTTP (jeton statique).
    const adr = serveurHttp.adresse();
    const corps = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "demo__claims.get", arguments: { claim_id: "2026-81046" }, _meta: metaModerne() } });
    const entetes = { authorization: "Bearer jeton-http-de-test", "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "demo__claims.get" };
    r.http = await posterHttp(adr, corps, entetes);
    appelsAttendus.push(["demo__claims.get", "executee"]);
    r.httpSansJeton = await posterHttp(adr, corps, { ...entetes, authorization: "Bearer faux" });
    r.httpEntete = await posterHttp(adr, corps, { ...entetes, "mcp-name": "demo__autre" });

    // Clôture de la période [10:00, 11:00).
    horloge.avancer(ms("2026-11-10T11:00:00.500Z") - horloge.murale());
    await coeur.tic();
    await new Promise((x) => setTimeout(x, 100));
  });

  after(async function () {
    for (const c of clients) c.p.kill("SIGKILL");
    await serveurHttp?.fermer();
    await connecteurs?.fermer();
    await frontal?.arreter();
    await coeur?.arreter();
  });

  it("l'hôte reçoit la liste agrégée, les résultats relayés, le signal d'approbation, les erreurs de la table de 4.4", function () {
    expect(r.listeA.result.tools.map((t) => t.name)).to.deep.equal([
      "archives__documents.get", "demo__claims.get", "demo__claims.search", "demo__crash", "demo__fail.rpc", "demo__payments.create", "demo__slow.op",
    ]);
    expect(r.listeA.result.ttlMs).to.equal(300000);
    expect(r.lecture.result).to.deep.equal({ resultType: "complete", content: [{ type: "text", text: "Sinistre 2026-81044 : ouvert" }], isError: false, _meta: { "io.modelcontextprotocol/serverInfo": { name: "noortrace-enregistreur", version: "0.1.0" } } });
    expect(r.notifications.map((n) => n.params)).to.deep.equal([
      { progressToken: "jeton-hote-7", progress: 1, total: 2 },
      { progressToken: "jeton-hote-7", progress: 2, total: 2 },
    ]);
    expect(r.retenue.result.content[0].text).to.match(/^noortrace: appel soumis a approbation ; ticket=apr-test-0001 ; state=en_attente$/);
    expect(r.enAttente.result._meta["noortrace/approval"].state).to.equal("en_attente");
    expect(r.acquittements.map((x) => x.result)).to.deep.equal(["scelle"]);
    expect(r.relaye.result.structuredContent.payment_id).to.match(/^PAY-2026-1000[0-9]$/);
    expect(r.herite.result.content[0].text).to.equal("DOC-31 : constat");
    expect(r.herite.result.resultType).to.equal("complete");
    expect(r.delai.error).to.deep.equal({ code: -31011, message: "noortrace: delai du serveur d'outils depasse", data: { timeout_ms: 300 } });
    expect(r.erreur.error).to.deep.equal({ code: -32602, message: "Invalid params: test", data: { field: "x" } });
    expect(r.refus.result).to.deep.equal({ resultType: "complete", content: [{ type: "text", text: "noortrace: appel refuse par la politique" }], isError: true, _meta: { "io.modelcontextprotocol/serverInfo": { name: "noortrace-enregistreur", version: "0.1.0" } } });
    expect(r.inconnu.error).to.deep.equal({ code: -32602, message: "Unknown tool: demo__nexiste.pas" });
    expect(r.cr).to.deep.equal({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error", data: { reason: "cr_dans_la_ligne" } } });
    expect(r.codeA).to.equal(0);
  });

  it("un hôte hérité (initialize) et un hôte HTTP à jeton statique passent aussi par le frontal (EX-4.5, EX-4.34, EX-4.35, EX-4.39)", function () {
    expect(r.initB.result).to.deep.equal({ protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "noortrace-enregistreur", version: "0.1.0" } });
    expect(Object.keys(r.listeB.result)).to.deep.equal(["tools"]);
    expect(r.lectureB.result.content[0].text).to.equal("Sinistre 2026-81045 : ouvert");
    expect(r.http.statut).to.equal(200);
    expect(JSON.parse(r.http.corps).result.content[0].text).to.equal("Sinistre 2026-81046 : ouvert");
    expect(r.httpSansJeton.statut).to.equal(401);
    expect(r.httpEntete.statut).to.equal(400);
    expect(JSON.parse(r.httpEntete.corps).error.code).to.equal(-32020);
  });

  it("chaque appel a produit un événement scellé ; délégation, politique, approbation et effets conformes (7.2)", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    const appels = evts.filter((e) => !e.execution.tool.startsWith("noortrace."));
    expect(appels.map((e) => [e.execution.tool, e.execution.status])).to.deep.equal(appelsAttendus);
    const moi = os.userInfo().username;
    expect(appels[0].delegation).to.deep.equal({ launched_by: moi, on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-parcours-0001" });
    expect(appels[0].context.length).to.equal(2);
    const retenue = appels[2];
    const relaye = appels[3];
    expect(retenue.policy.decision).to.equal("a_approuver");
    expect(retenue.execution.arguments.redacted).to.equal(true);
    expect(relaye.policy).to.deep.equal(retenue.policy);
    expect(relaye.approval.decision).to.equal("approuve");
    expect(relaye.approval.request_hash).to.equal(retenue.hash);
    expect(relaye.effects).to.deep.equal([{ system: "demo", action: "ecriture", object: "payments.create", amount: null, currency: null }]);
    expect(appels[5].execution.is_error).to.equal(true);
    expect(appels[5].execution.duration_ms).to.be.at.least(300);
    expect(appels[6].execution.is_error).to.equal(true);
    expect(appels[8].delegation.run_id).to.match(/^s-[0-9a-f]{32}$/);
    expect(appels[9].delegation).to.deep.equal({ launched_by: "poste-http", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: null });
    const consomme = service.messages.filter((m) => m.methode === "consommer");
    expect(consomme.map((m) => m.corps.seq)).to.deep.equal([relaye.seq]);
    // Journal d'exploitation : tool_call_relayed par relais, call_blocked jamais pour ces appels.
    expect(coeur.journal.trouver("tool_call_relayed").length).to.equal(appelsAttendus.filter((x) => x[1] === "executee").length);
    expect(coeur.journal.trouver("stdio_server_command").map((l) => l.data.server)).to.deep.equal(["demo", "archives"]);
  });

  it("le journal est accepté par la bibliothèque noyau (CT-1 §7, E-1 à E-11) et la période est close", async function () {
    const evts = await lireEvenements(coeur.repertoire);
    const journalJson = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "journal.json"), "utf8"));
    const cles = await clesDuJournal({ org_id: evts[0].org_id, journal_id: evts[0].journal_id, evenements: evts, creeLe: journalJson.created_at, clePublique: (id) => coeur.signataire.clePubliqueHex(id) });
    const verdict = N.verifierJournal(evts, cles);
    expect(verdict.valide, JSON.stringify(verdict.diagnostics)).to.equal(true);
    const m = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "manifestes", "periode-1794304800.json"), "utf8"));
    expect(m.count).to.equal(evts.length);
    for (const e of evts.filter((x) => !x.execution.tool.startsWith("noortrace."))) {
      const d = path.join(dir, "dossiers", `seq-${e.seq}`);
      await coeur.exporterDossier(e.seq, d);
      const v = verifierRepertoireDossier(d);
      expect(v.verdict, `seq ${e.seq} : ${JSON.stringify(v.controles_en_echec)}`).to.equal("valide");
    }
  });

  it("le dossier de chaque appel est accepté par le binaire Go noortrace-verifier (go1.27.3)", function () {
    const bin = construireVerificateur(dir);
    if (!bin) this.skip();
    const dossiers = fs.readdirSync(path.join(dir, "dossiers")).sort();
    expect(dossiers.length).to.equal(appelsAttendus.length);
    for (const d of dossiers) {
      const x = spawnSync(bin, [path.join(dir, "dossiers", d), "--json"], { encoding: "utf8" });
      expect(x.status, `${d} : ${x.stdout}${x.stderr}`).to.equal(0);
      const rapport = JSON.parse(x.stdout);
      expect(rapport.verdict, d).to.equal("valide");
      expect(rapport.failed_checks, d).to.deep.equal([]);
    }
  });

  describe("démon réel : bin/noortrace --config, connecteur, serveurs stdio", function () {
    it("le démon démarre le frontal ; un hôte passe par le connecteur ; SIGTERM ; le journal est accepté par le noyau", async function () {
      const d = repertoireTemporaire("noortrace-mcp-demon-");
      const moi = os.userInfo().username;
      const servers = {
        demo: serveurStdio([process.execPath, SERVEUR], { protocol: "auto", tools: { "payments.create": reglageOutil({ class: "ecriture" }) } }),
        archives: serveurStdio([process.execPath, SERVEUR, "--herite"], { protocol: "auto" }),
      };
      const { config, env } = configurationMcp(d, { servers, hosts: [hoteDemo({ id: "agent-stdio", match: { peer_user: moi }, launched_by: "${peer_user}" })] });
      config.model.hosts = [];
      // Service d'approbation de test servi en HTTP (EX-7.14) : les paiements
      // sont refusés par la politique, le reste est autorisé.
      const svc = new ServiceApprobationFactice({
        org_id: config.recorder.org_id,
        journal_id: config.recorder.journal_id,
        decider: (q) => (q.tool_announced === "demo__payments.create" ? { decision: "refuse", rule: "paiements suspendus" } : { decision: "autorise", rule: null }),
      });
      const serveurSvc = await svc.servir(0);
      config.policy.approval.service = { ...config.policy.approval.service, url: `http://127.0.0.1:${serveurSvc.address().port}`, socket: null };
      const chemin = path.join(d, "configuration.json");
      fs.writeFileSync(chemin, JSON.stringify(config, null, 2));
      const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      let sortie = "";
      let erreurs = "";
      p.stderr.on("data", (x) => (erreurs += x));
      await new Promise((res, rej) => {
        p.stdout.on("data", (x) => {
          sortie += x;
          if (/demon demarre/.test(sortie)) res();
        });
        p.on("exit", (c) => rej(new Error(`arrêt ${c} : ${erreurs}`)));
      });
      const a = new ClientHote(["--socket", config.mcp.socket]);
      let ecriture;
      try {
        const l = await a.requete("tools/list", { _meta: metaModerne() });
        expect(l.result.tools.map((t) => t.name)).to.include.members(["demo__claims.get", "archives__documents.get"]);
        const lecture = await a.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "D-1" }, _meta: metaModerne() });
        expect(lecture.result.content[0].text).to.equal("Sinistre D-1 : ouvert");
        const herite = await a.requete("tools/call", { name: "archives__documents.get", arguments: { document_id: "D-2" }, _meta: metaModerne() });
        expect(herite.result.content[0].text).to.equal("D-2 : constat");
        ecriture = await a.requete("tools/call", { name: "demo__payments.create", arguments: { claim_id: "D-1" }, _meta: metaModerne() });
        expect(ecriture.result.content[0].text).to.equal("noortrace: appel refuse par la politique");
      } finally {
        await a.fermer();
        if (p.exitCode === null) setTimeout(() => p.kill("SIGKILL"), 20000).unref();
        serveurSvc.close();
      }
      const code = await new Promise((r) => {
        p.removeAllListeners("exit");
        p.on("exit", (c) => r(c));
        p.kill("SIGTERM");
      });
      expect(code).to.equal(0);
      const repertoire = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
      const evts = await lireEvenements(repertoire);
      expect(evts.filter((e) => !e.execution.tool.startsWith("noortrace.")).map((e) => [e.execution.tool, e.delegation.launched_by, e.policy.decision])).to.deep.equal([
        ["demo__claims.get", moi, "autorise"],
        ["archives__documents.get", moi, "autorise"],
        ["demo__payments.create", moi, "refuse"],
      ]);
      const cle = N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-01")));
      const journalJson = JSON.parse(fs.readFileSync(path.join(repertoire, "journal.json"), "utf8"));
      const cles = await clesDuJournal({ org_id: evts[0].org_id, journal_id: evts[0].journal_id, evenements: evts, creeLe: journalJson.created_at, clePublique: async () => cle });
      const verdict = N.verifierJournal(evts, cles);
      expect(verdict.valide, JSON.stringify(verdict.diagnostics)).to.equal(true);
      const ops = fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((x) => JSON.parse(x));
      expect(ops.map((x) => x.event)).to.include.members(["stdio_server_command", "child_started", "host_connected", "tool_call_relayed", "shutdown"]);
    });
  });
});
