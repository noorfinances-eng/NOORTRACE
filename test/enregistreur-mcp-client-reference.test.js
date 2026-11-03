// TI-3 de CT-9 : protocole MCP réel à travers le frontal du démon. Le client
// MCP de référence, `@modelcontextprotocol/client` 2.4.0 (SDK TypeScript de
// la révision 2026-07-28, ère moderne épinglée : `versionNegotiation: { mode:
// { pin: "2026-07-28" } }`), parle au démon réel `bin/noortrace --config` :
//   - en stdio, par le connecteur `noortrace-connecteur` qu'il lance
//     (`StdioClientTransport`), identité du pair prouvée sur la prise Unix ;
//   - en Streamable HTTP (`StreamableHTTPClientTransport`), jeton statique.
// Le frontal relaie vers un serveur d'outils de test au contrat d'`outils-demo`
// de CT-2 §19.1 (`claims.get`, `claims.search`, `payments.create`), qui
// rejoue les octets des vecteurs `pieces-mcp/appels` (et le serveur hérité
// `archives` des mêmes vecteurs) : chaque appel produit l'événement dont les
// pièces (arguments, résultat, définition servie, liste annoncée) égalent,
// octet pour octet, celles d'`attendu.json` du vecteur qui joue le même
// appel. Une requête sans jeton ou au jeton faux est refusée (401, ligne
// auth_failed, aucun événement). Le serveur coupé en cours d'appel donne
// `-31014` à l'hôte, une ligne consignée, et l'événement du vecteur
// `injoignable` (résultat d'erreur, jamais un succès forgé) ; la perte est
// consignée (`upstream_unreachable`, raison `perte`).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { lireEvenements } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, repertoireTemporaire, RACINE, VECTEURS_CT2 } from "./fixtures/enregistreur-coeur/outils.mjs";
import { REFERENCE, demarrer, arreter, portLibre, repertoireJournal } from "./fixtures/enregistreur-adversarial/demon.mjs";

const SERVEUR = path.join(RACINE, "test", "fixtures", "enregistreur-mcp-reference", "outils-demo.mjs");
const APPELS = path.join(VECTEURS_CT2, "pieces-mcp", "appels");
const CONNECTEUR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-connecteur");
const JETON = "jeton-http-de-test-ti3-0001";
const attendu = (cas) => JSON.parse(fs.readFileSync(path.join(APPELS, cas, "attendu.json"), "utf8"));
const ref = (p) => ({ sha256: p.sha256, length: p.length, redacted: p.redacted });
const VERSION_CLIENT = JSON.parse(fs.readFileSync(path.join(path.dirname(createRequire(import.meta.url).resolve("@modelcontextprotocol/client")), "..", "package.json"), "utf8")).version;

/** Les trois appels d'outils-demo et le vecteur qui joue chacun. */
const APPELS_DEMO = [
  { cas: "blancs-non-significatifs", nom: "demo__claims.get", args: { claim_id: "2026-81044" } },
  { cas: "arguments-non-entiers", nom: "demo__claims.search", args: { query: "collision", seuil: 0.75, limite: 1.0, plafond: 1e3 } },
  { cas: "execute-ecriture", nom: "demo__payments.create", args: { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" } },
];

function hote(id, match, launchedBy) {
  return {
    id, match, launched_by: launchedBy, scope: "sinistres:lecture,paiement", on_behalf_of: "service-sinistres", accept_declared_delegation: true, allowed_on_behalf_of: [],
    tool_name_template: "{tool_announced}", tool_name_sanitize: false, prompt_version_name: null, host_group: "demo",
    quota: { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 }, alias: null,
  };
}

const client = () => new Client({ name: "client-reference-ti3", version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });

describe("TI-3 — protocole MCP réel : client de référence @modelcontextprotocol/client (stdio et Streamable HTTP, ère moderne) à travers le frontal du démon", function () {
  this.timeout(180000);
  let dir;
  let service;
  let serveurService;
  let c;
  let demon;
  let journal;

  before(async function () {
    dir = repertoireTemporaire("noortrace-ti3-");
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
    const { config, env } = configurationDev(dir, { mcp: true });
    const portHttp = await portLibre();
    const portSante = await portLibre();
    config.mcp.socket = path.join(dir, "prise", "mcp.sock");
    config.mcp.http = { listen: `127.0.0.1:${portHttp}`, path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "poste-http", token: { env: "NOORTRACE_TEST_JETON_HTTP" } }] };
    config.mcp.hosts = [hote("agent-stdio", { peer_user: os.userInfo().username }, "agent-demo"), hote("poste-http", { static_token: "poste-http" }, "poste-http")];
    const serveur = (alias, protocol) => ({
      transport: { type: "stdio", command: [process.execPath, SERVEUR, "--vecteurs", APPELS, "--alias", alias], cwd: null, env: {}, sandbox: null, user: null, integrity: null },
      protocol, class_default: null, timeout_ms: null, tools: {}, uri_prefixes: [], relay: alias === "demo" ? { sampling: false, elicitation: true, roots: false } : null,
    });
    config.policy.servers = { demo: serveur("demo", "2026-07-28"), archives: serveur("archives", "auto") };
    config.policy.approval.mode = "erreur";
    config.policy.approval.service = { url: `http://127.0.0.1:${serveurService.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
    config.supervision.health_listen = `127.0.0.1:${portSante}`;
    env.NOORTRACE_TEST_JETON_HTTP = JETON;
    env.NOORTRACE_TEST_JETON_APPROBATION = "jeton-approbation-de-test-ti3";
    service.org_id = config.recorder.org_id;
    service.journal_id = config.recorder.journal_id;
    c = { config, env, portSante, portHttp, ports: [portHttp], dir };
    journal = repertoireJournal(config);
    demon = await demarrer(REFERENCE, c, path.join(dir, "configuration.json"));
  });

  after(async function () {
    await arreter(demon);
    serveurService?.close();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** Événement d'un appel : le dernier de l'outil dont la pièce d'arguments est celle du vecteur. */
  async function evenementDe(a) {
    const evts = await lireEvenements(journal);
    return evts.filter((e) => e.execution.tool === a.nom && e.execution.arguments.sha256 === attendu(a.cas).pieces.arguments.sha256).at(-1) ?? null;
  }

  /** Pièces de l'événement égales à celles du vecteur : arguments, résultat, définition servie et liste annoncée (contexte, EX-4.45). */
  async function comparer(a, o = {}) {
    const x = attendu(a.cas);
    const e = await evenementDe(a);
    expect(e, `${a.nom} : événement`).to.not.equal(null);
    expect(ref(e.execution.arguments), `${a.cas} : arguments`).to.deep.equal(ref(x.pieces.arguments));
    expect(ref(e.execution.result), `${a.cas} : résultat`).to.deep.equal(ref(x.pieces.result));
    expect(e.execution.is_error, `${a.cas} : is_error`).to.equal(x.is_error);
    expect(e.context[0].sha256, `${a.cas} : définition servie`).to.equal(x.pieces.definition.sha256);
    if (o.liste !== false) expect(e.context.map((p) => p.sha256), `${a.cas} : contexte`).to.deep.equal(x.context.map((p) => p.sha256));
    for (const p of [e.execution.arguments, e.execution.result, ...e.context]) {
      const f = path.join(journal, "pieces", p.sha256.slice(2, 4), p.sha256.slice(2));
      expect(fs.existsSync(f), `${a.cas} : pièce ${p.sha256} stockée`).to.equal(true);
    }
    return e;
  }

  async function jouer(transport) {
    const cl = client();
    await cl.connect(transport);
    try {
      expect(cl.getNegotiatedProtocolVersion()).to.equal("2026-07-28");
      const noms = (await cl.listTools()).tools.map((t) => t.name).sort();
      expect(noms).to.deep.equal(["archives__documents.get", "demo__claims.get", "demo__claims.search", "demo__payments.create"]);
      const reponses = [];
      for (const a of APPELS_DEMO) reponses.push(await cl.callTool({ name: a.nom, arguments: a.args }));
      return reponses;
    } finally {
      await cl.close();
    }
  }

  it("client de référence (@modelcontextprotocol/client 2.4.0) en stdio par le connecteur, ère 2026-07-28 : tools/list, puis claims.get, claims.search et payments.create ; chaque appel rendu à l'hôte et scellé avec les pièces du vecteur pieces-mcp qui joue le même appel", async function () {
    expect(VERSION_CLIENT).to.equal("2.4.0");
    const r = await jouer(new StdioClientTransport({ command: process.execPath, args: [CONNECTEUR, "--socket", c.config.mcp.socket] }));
    expect(r.map((x) => x.isError)).to.deep.equal([false, false, false]);
    expect(r[2].structuredContent).to.deep.equal({ payment_id: "PAY-2026-90417" });
    for (const a of APPELS_DEMO) {
      const e = await comparer(a, { liste: a.cas !== "execute-ecriture" });
      expect(e.delegation.launched_by).to.equal("agent-demo");
    }
  });

  it("client de référence en Streamable HTTP, jeton statique, ère 2026-07-28 : mêmes appels, mêmes pièces ; événements attribués à la connexion d'hôte HTTP", async function () {
    const avant = (await lireEvenements(journal)).length;
    const r = await jouer(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${c.portHttp}/mcp`), { requestInit: { headers: { authorization: `Bearer ${JETON}` } } }));
    expect(r.map((x) => x.isError)).to.deep.equal([false, false, false]);
    const nouveaux = (await lireEvenements(journal)).slice(avant).filter((e) => !e.execution.tool.startsWith("noortrace."));
    expect(nouveaux.map((e) => e.execution.tool)).to.deep.equal(APPELS_DEMO.map((a) => a.nom));
    expect(nouveaux.map((e) => e.delegation.launched_by)).to.deep.equal(["poste-http", "poste-http", "poste-http"]);
    for (const a of APPELS_DEMO) await comparer(a, { liste: a.cas !== "execute-ecriture" });
  });

  it("requête non authentifiée (sans jeton, puis jeton faux) : refusée par 401, une ligne auth_failed chacune, aucun événement", async function () {
    const avant = (await lireEvenements(journal)).length;
    const lignesAvant = demon.lignes().filter((l) => l.event === "auth_failed").length;
    for (const entetes of [{}, { authorization: "Bearer jeton-faux-de-test-ti3" }]) {
      const cl = client();
      let err = null;
      try {
        await cl.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${c.portHttp}/mcp`), { requestInit: { headers: entetes } }));
        await cl.listTools();
      } catch (e) {
        err = e;
      } finally {
        await cl.close().catch(() => {});
      }
      expect(err, JSON.stringify(entetes)).to.not.equal(null);
      expect(String(err.message ?? err)).to.match(/401/);
    }
    const lignes = demon.lignes().filter((l) => l.event === "auth_failed").slice(lignesAvant).map((l) => l.data);
    expect(lignes).to.deep.equal([{ transport: "http", reason: "absent", status: 401 }, { transport: "http", reason: "jeton_inconnu", status: 401 }]);
    expect((await lireEvenements(journal)).length).to.equal(avant);
  });

  it("serveur d'outils coupé en cours d'appel (payments.create du vecteur injoignable) : -31014 rendu à l'hôte et consigné ; l'événement est celui du vecteur (résultat d'erreur), aucun succès forgé", async function () {
    const a = { cas: "injoignable", nom: "demo__payments.create", args: { claim_id: "2026-81045", amount: "300.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" } };
    const cl = client();
    await cl.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${c.portHttp}/mcp`), { requestInit: { headers: { authorization: `Bearer ${JETON}` } } }));
    let err = null;
    try {
      await cl.listTools();
      await cl.callTool({ name: a.nom, arguments: a.args });
    } catch (e) {
      err = e;
    } finally {
      await cl.close();
    }
    expect(err?.code, String(err)).to.equal(-31014);
    expect(attendu(a.cas).error_rendered.code).to.equal(-31014);
    // Consigné : serveur perdu pendant l'appel (upstream_unreachable, raison perte), puis l'appel relayé à l'issue en erreur.
    const lignes = demon.lignes();
    expect(lignes.filter((l) => l.event === "upstream_unreachable").map((l) => l.data)).to.deep.include({ server: "demo", reason: "perte" });
    const relaye = lignes.filter((l) => l.event === "tool_call_relayed" && l.data.arguments_sha256 === attendu(a.cas).pieces.arguments.sha256);
    expect(relaye.map((l) => [l.data.is_error, l.data.result_sha256])).to.deep.equal([[true, attendu(a.cas).pieces.result.sha256]]);
    const e = await comparer(a);
    expect(e.execution.is_error).to.equal(true);
    const memes = (await lireEvenements(journal)).filter((x) => x.execution.tool === a.nom && x.execution.arguments.sha256 === e.execution.arguments.sha256);
    expect(memes).to.have.length(1);
  });
});
