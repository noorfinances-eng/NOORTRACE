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
import { fichierSecret, identifiantsRole, portLibre } from "../enregistreur-worm/outils.mjs";

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
  // Fin des flux de sortie (après `exit`) : la sortie d'erreur est alors complète.
  p.ferme = new Promise((r) => p.on("close", () => r()));
  p.lignes = () => (fs.existsSync(journalOps) ? fs.readFileSync(journalOps, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  return p;
}

/** Nombre d'essais d'un lancement dont une adresse d'écoute était prise (EADDRINUSE). */
export const ESSAIS_PORTS = 5;

/**
 * Le démon s'est-il arrêté parce qu'une adresse d'écoute était déjà prise ?
 * Un port libre choisi par le test (écoute sur le port 0, puis fermeture) peut
 * être pris par un autre processus avant que le démon ne l'ouvre ; le démon
 * refuse alors de démarrer (`demarrage_refuse … EADDRINUSE`, code 2).
 * @param {import("node:child_process").ChildProcess & {sortie: string}} p
 */
export function adresseOccupee(p) {
  return (p.exitCode !== null || p.signalCode !== null) && /EADDRINUSE/.test(p.sortie);
}

/**
 * Remplace, partout dans une configuration, l'adresse d'écoute
 * `127.0.0.1:<ancien>` par `127.0.0.1:<nouveau>` (santé, frontal MCP HTTP,
 * passerelle, ICAP) ; rend le nombre de remplacements.
 */
export function remplacerPort(config, ancien, nouveau) {
  let n = 0;
  const visiter = (o) => {
    if (o === null || typeof o !== "object") return;
    for (const [k, v] of Object.entries(o)) {
      if (v === `127.0.0.1:${ancien}`) {
        o[k] = `127.0.0.1:${nouveau}`;
        n++;
      } else {
        visiter(v);
      }
    }
  };
  visiter(config);
  return n;
}

/**
 * Lance le démon d'une configuration `x` ({ config, env, fichier }) et attend
 * sa santé `etat` (EX-17.1). Si le démon s'arrête parce qu'une de ses
 * adresses d'écoute était prise entre le choix du port et son ouverture
 * (EADDRINUSE), de nouveaux ports libres sont choisis pour la santé et le
 * frontal MCP HTTP, la configuration est réécrite et le démon relancé : au
 * plus ESSAIS_PORTS essais. `x.port` (santé), `x.portSante` et `x.portHttp`
 * suivent les ports retenus ; la configuration écrite est `x.config`.
 * @param {{config: object, env: object, fichier: string, port?: number, portSante?: number, portHttp?: number}} x
 * @param {string} [etat] `ok`, `standby`…
 * @param {{prefixe?: string[], delaiMs?: number}} [o]
 */
export async function demarrerDemon(x, etat = "ok", o = {}) {
  for (let essai = 1; ; essai++) {
    fs.writeFileSync(x.fichier, JSON.stringify(x.config));
    const p = lancerDemon(x.fichier, x.env, x.config.supervision.ops_log.path, o);
    const port = Number(x.config.supervision.health_listen.split(":")[1]);
    const limite = Date.now() + (o.delaiMs ?? 60000);
    let erreur = null;
    for (;;) {
      if (p.exitCode !== null || p.signalCode !== null) {
        erreur = new Error(`démon arrêté (${p.exitCode ?? p.signalCode})`);
        break;
      }
      // Le port peut être tenu par un autre processus qui ne répond pas en HTTP : sonde bornée.
      if ((await santeBornee(port))?.corps?.status === etat) return p;
      if (Date.now() > limite) {
        erreur = new Error(`santé ${etat} non atteinte`);
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (p.exitCode !== null || p.signalCode !== null) await p.ferme;
    if (essai < ESSAIS_PORTS && adresseOccupee(p)) {
      for (const [champ, adresse] of [["sante", x.config.supervision.health_listen], ["http", x.config.mcp?.http?.listen]]) {
        const ancien = Number(String(adresse ?? "").split(":")[1]);
        if (!ancien) continue;
        const nouveau = await portLibre();
        remplacerPort(x.config, ancien, nouveau);
        if (champ === "sante") {
          if ("port" in x) x.port = nouveau;
          if ("portSante" in x) x.portSante = nouveau;
        } else if ("portHttp" in x) {
          x.portHttp = nouveau;
        }
      }
      continue;
    }
    p.kill("SIGKILL");
    throw new Error(`${erreur.message}\n${p.sortie}`);
  }
}

/** `sante`, ou null après `delaiMs`. */
export function santeBornee(port, delaiMs = 2000) {
  return Promise.race([sante(port), new Promise((r) => setTimeout(() => r(null), delaiMs))]);
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
