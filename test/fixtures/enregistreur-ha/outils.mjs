// Outils des tests de haute disponibilité (test/enregistreur-ha-*.test.js) :
// configuration d'un démon tiré de l'exemple de CT-2 §15.3 (classe D, magasin
// de bail réseau, support WORM S3, frontal MCP en Streamable HTTP à jeton
// statique, un serveur d'outils stdio de test, service d'approbation simulé
// joint en HTTP), client MCP de l'ère héritée (initialize, tools/call), et
// lancement du démon réel `bin/noortrace --config`.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { configurationDev, BIN_NOORTRACE } from "../enregistreur-coeur/outils.mjs";
import { fichierSecret, identifiantsRole } from "../enregistreur-worm/outils.mjs";

export const SERVEUR_OUTILS = path.join(path.dirname(fileURLToPath(import.meta.url)), "serveur-outils.mjs");
export const JETON_HOTE = "jeton-hote-de-test-ha";

/**
 * Configuration d'un démon du parcours.
 * @param {string} dir répertoire commun (stockage partagé par les instances, 13.1)
 * @param {object} o
 * @param {string} o.instance `recorder.instance_id`
 * @param {object} o.store `lease.store` (sans secret : le DSN va dans un fichier)
 * @param {string|null} [o.dsn] DSN PostgreSQL
 * @param {object|null} [o.worm] membre `storage.seal.worm` (identifiants de l'écrivain ajoutés)
 * @param {number} o.approbation port du service d'approbation simulé
 * @param {string} [o.journal_id]
 * @param {number} [o.ttl_ms]
 * @param {number} [o.renew_ms]
 */
export function configurationHa(dir, o) {
  const { config, env } = configurationDev(dir, { mcp: true, journal_id: o.journal_id, instance_id: o.instance });
  config.recorder.instance_id = o.instance;
  config.mcp.socket = path.join(dir, `prise-${o.instance}`, "mcp.sock");
  config.mcp.http = { listen: `127.0.0.1:${o.portHttp ?? 0}`, path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "hote-ha", token: { env: "NOORTRACE_TEST_JETON_HOTE" } }] };
  config.mcp.hosts = [{ ...config.mcp.hosts[1], id: "hote-ha", match: { static_token: "hote-ha" }, launched_by: "agent-ha", host_group: "agent-ha", accept_declared_delegation: false, allowed_on_behalf_of: [] }];
  config.mcp.drain_timeout_ms = 200;
  config.policy.servers = {
    demo: {
      transport: { type: "stdio", command: [process.execPath, SERVEUR_OUTILS], cwd: null, env: {}, sandbox: null, user: null, integrity: null },
      protocol: "legacy",
      class_default: "ecriture",
      timeout_ms: 120000,
      tools: {
        lire: { class: "lecture", timeout_ms: null, effects: null, failure: null },
        ecrire: { class: "ecriture", timeout_ms: null, effects: null, failure: null },
        ecrire_lent: { class: "ecriture", timeout_ms: null, effects: null, failure: null },
      },
      uri_prefixes: [],
      relay: null,
    },
  };
  config.policy.approval.service = { url: `http://127.0.0.1:${o.approbation}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
  config.supervision.ops_log.path = path.join(dir, `exploitation-${o.instance}.ndjson`);
  config.supervision.health_listen = `127.0.0.1:${o.portSante ?? 0}`;
  config.storage.segment_max_bytes = o.segment_max_bytes ?? config.storage.segment_max_bytes;
  const secrets = path.join(dir, "secrets");
  const store = { ...o.store };
  if (store.type === "postgresql") store.dsn = { file: fichierSecret(path.join(secrets, "dsn-bail"), o.dsn) };
  config.lease = { store, ttl_ms: o.ttl_ms ?? 4000, renew_ms: o.renew_ms ?? 1000, acquire_wait_ms: 5000, fencing: o.fencing ?? null };
  if (o.worm) config.storage.seal.worm = { ...o.worm, credentials: { file: fichierSecret(path.join(secrets, "worm-ecrivain"), identifiantsRole("ecrivain")) } };
  return { config, env: { ...env, NOORTRACE_TEST_JETON_HOTE: JETON_HOTE, NOORTRACE_TEST_JETON_APPROBATION: "jeton-approbation-de-test" } };
}

/**
 * Client MCP de l'ère héritée sur Streamable HTTP (jeton statique) :
 * `initialize`, `notifications/initialized`, `tools/call`.
 */
export class ClientMcpHttp {
  /** @param {string} adresse `127.0.0.1:<port>` */
  constructor(adresse) {
    this.adresse = adresse;
    this.session = null;
    this.n = 0;
  }

  _poster(corps) {
    const [hote, port] = this.adresse.split(":");
    return new Promise((res, rej) => {
      const req = http.request(
        {
          host: hote, port: Number(port), path: "/mcp", method: "POST",
          headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${JETON_HOTE}`, ...(this.session ? { "mcp-session-id": this.session } : {}) },
        },
        (r) => {
          const m = [];
          r.on("data", (c) => m.push(c));
          r.on("end", () => {
            if (r.headers["mcp-session-id"]) this.session = r.headers["mcp-session-id"];
            let texte = Buffer.concat(m).toString("utf8");
            if (String(r.headers["content-type"]).startsWith("text/event-stream")) texte = texte.split("\n").filter((l) => l.startsWith("data: ")).at(-1)?.slice(6) ?? "";
            res({ statut: r.statusCode, corps: texte ? JSON.parse(texte) : null });
          });
        },
      );
      req.on("error", rej);
      req.end(JSON.stringify(corps));
    });
  }

  /** `initialize` puis `notifications/initialized` ; attend que le frontal écoute (il s'ouvre après la sonde de santé). */
  async ouvrir(delaiMs = 30000) {
    const limite = Date.now() + delaiMs;
    let r;
    for (;;) {
      try {
        r = await this._poster({ jsonrpc: "2.0", id: ++this.n, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "hote-ha", version: "1.0.0" } } });
        break;
      } catch (e) {
        if (e.code !== "ECONNREFUSED" || Date.now() > limite) throw e;
        await new Promise((x) => setTimeout(x, 100));
      }
    }
    await this._poster({ jsonrpc: "2.0", method: "notifications/initialized" });
    return r;
  }

  /** `tools/call` ; rend la réponse JSON-RPC. */
  async appeler(nom, args) {
    return (await this._poster({ jsonrpc: "2.0", id: ++this.n, method: "tools/call", params: { name: nom, arguments: args } })).corps;
  }
}

/**
 * Démon réel `bin/noortrace --config` ; rend le processus, sa sortie, sa fin et
 * les lignes de son journal d'exploitation.
 */
export function lancerDemon(fichier, env, journalOps, o = {}) {
  // `o.prefixe` : commande qui lance le démon (par exemple `setpriv` pour lui retirer une capacité).
  const commande = [...(o.prefixe ?? []), process.execPath, BIN_NOORTRACE, "--config", fichier];
  const p = spawn(commande[0], commande.slice(1), { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  p.sortie = "";
  p.stdout.on("data", (d) => (p.sortie += d));
  p.stderr.on("data", (d) => (p.sortie += d));
  p.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
  p.lignes = () => (fs.existsSync(journalOps) ? fs.readFileSync(journalOps, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  return p;
}

/** Corps de `GET /healthz` d'un démon (EX-17.1), ou null s'il ne répond pas. */
export function sante(port) {
  return new Promise((res) => {
    const r = http.get({ host: "127.0.0.1", port, path: "/healthz" }, (x) => {
      const m = [];
      x.on("data", (c) => m.push(c));
      x.on("end", () => res({ statut: x.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8") || "null") }));
    });
    r.on("error", () => res(null));
  });
}
