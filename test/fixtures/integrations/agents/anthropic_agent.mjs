#!/usr/bin/env node
// Agent du scénario d'intégration CT-9 TI-4, variante JavaScript : SDK
// officiel d'Anthropic pour TypeScript (`@anthropic-ai/sdk` 1.3.0, CT-2 §6.4)
// dirigé vers la passerelle par `ANTHROPIC_BASE_URL`, jeton de l'hôte dans
// `ANTHROPIC_API_KEY` (ce que Claude Code fait, 19.5.2) et, à la demande
// (`AGENT_JETON_ENTETE=x-noortrace-token`), dans `X-Noortrace-Token` ; outils
// par le frontal MCP avec le client MCP de référence (`@modelcontextprotocol/client`
// 2.4.0, Streamable HTTP, ère 2026-07-28, le même que CT-9 TI-3). Scénario de
// CT-2 §19.2 : échange hors flux, `claims.get`, échange en flux SSE
// (`messages.stream`), `payments.create` retenu puis redemandé après la
// décision, échange de clôture. Noms assainis pour le modèle (EX-4.12).
//
// Le SDK est résolu depuis le dépôt (`node_modules`, où le travail
// `integrations` de l'intégration continue l'installe à version exacte, hors
// de package.json : CT-2 19.5.7) ou, à défaut, depuis le répertoire donné par
// NOORTRACE_MODULES_INTEGRATION (installation latérale aux versions épinglées).

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const RACINE = path.resolve(ICI, "..", "..", "..", "..");
const SYSTEME = "Tu es l'agent sinistres de l'assureur de démonstration. Contact interne : support@assureur-demo.example (jamais communiqué).";
const DEMANDE = "Traite le sinistre 2026-81044.";
const MODELE = "modele-demo-1";
const PROTOCOLE = "2026-07-28";
const assainir = (nom) => nom.replace(/[^A-Za-z0-9_-]/g, "_");
const dire = (t) => process.stdout.write(`agent : ${t}\n`);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** Charge un module depuis le dépôt, sinon depuis NOORTRACE_MODULES_INTEGRATION. */
export async function charger(nom) {
  for (const base of [path.join(RACINE, "package.json"), process.env.NOORTRACE_MODULES_INTEGRATION ? path.join(process.env.NOORTRACE_MODULES_INTEGRATION, "package.json") : null].filter(Boolean)) {
    try {
      const resolu = createRequire(base).resolve(nom);
      return { module: await import(pathToFileURL(resolu).href), version: versionDe(resolu, nom) };
    } catch (e) {
      if (e?.code !== "MODULE_NOT_FOUND" && e?.code !== "ERR_MODULE_NOT_FOUND") throw e;
    }
  }
  throw new Error(`module absent : ${nom}`);
}

/** Version d'un module résolu : le `package.json` du paquet qui porte son nom, en remontant depuis le fichier résolu. */
function versionDe(resolu, nom) {
  let d = path.dirname(resolu);
  for (let k = 0; k < 8; k++) {
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8"));
      if (pj.name === nom) return pj.version;
    } catch {
      // pas de package.json à ce niveau
    }
    d = path.dirname(d);
  }
  return null;
}

export async function ouvrirMcp(url, jeton, nomClient) {
  const { Client, StreamableHTTPClientTransport } = (await charger("@modelcontextprotocol/client")).module;
  const client = new Client({ name: nomClient, version: "0.1.0" }, { versionNegotiation: { mode: { pin: PROTOCOLE } } });
  const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${jeton}` } } });
  await client.connect(transport);
  return client;
}

export function signalApprobation(r) {
  return r?._meta?.["noortrace/approval"] ?? null;
}

export async function appelerAvecApprobation(appel, ta, pauseMs, attenteMaxMs) {
  const debut = Date.now();
  for (;;) {
    ta.emissions += 1;
    const r = await appel();
    const signal = signalApprobation(r);
    if (!signal) {
      ta.resultat = (r.content ?? []).filter((b) => b.type === "text").map((b) => b.text).join("\n");
      ta.is_error = Boolean(r.isError);
      ta.structured = r.structuredContent ?? null;
      return r;
    }
    ta.tickets.push(signal.ticket);
    if (signal.state !== "en_attente") throw new Error(`${ta.outil} : ticket ${signal.ticket} ${signal.state}, l'appel n'est pas répété`);
    if (Date.now() - debut > attenteMaxMs) throw new Error(`${ta.outil} : toujours en attente d'approbation après ${attenteMaxMs} ms`);
    dire(`${ta.outil} : en attente d'approbation (ticket ${signal.ticket})`);
    await pause(pauseMs);
  }
}

async function principal() {
  const env = process.env;
  const runId = env.NOORTRACE_RUN_ID ?? "run-integration-0001";
  const { module: A, version } = await charger("@anthropic-ai/sdk");
  const Anthropic = A.default ?? A.Anthropic;
  const trace = { sdk: `@anthropic-ai/sdk ${version}`, echanges: [], appels: [], fin: null, notes: {} };
  const entetes = { "X-Noortrace-Run-Id": runId };
  if (env.AGENT_JETON_ENTETE === "x-noortrace-token") entetes["X-Noortrace-Token"] = env.NOORTRACE_GATEWAY_TOKEN ?? "";
  // URL de base et clé lues dans l'environnement par le SDK (ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY).
  const client = new Anthropic({ defaultHeaders: entetes, maxRetries: 0, timeout: 120000 });
  trace.notes.base_url = client.baseURL;
  const mcp = await ouvrirMcp(env.NOORTRACE_MCP_URL, env.NOORTRACE_MCP_TOKEN, "agent-integration-js");
  try {
    const liste = await mcp.listTools();
    const annonces = liste.tools.map((t) => t.name);
    const annonceDe = new Map(annonces.map((n) => [assainir(n), n]));
    const outils = liste.tools.map((t) => ({ name: assainir(t.name), description: t.description ?? "", input_schema: { type: t.inputSchema.type, properties: t.inputSchema.properties ?? {}, ...(t.inputSchema.required ? { required: t.inputSchema.required } : {}) } }));
    dire(`outils annoncés par l'enregistreur : ${annonces.join(", ")}`);
    const messages = [{ role: "user", content: DEMANDE }];
    for (let echange = 1; echange <= 12; echange++) {
      const flux = echange === 2;
      const message = flux ? await client.messages.stream({ model: MODELE, max_tokens: 1024, system: SYSTEME, messages, tools: outils }).finalMessage() : await client.messages.create({ model: MODELE, max_tokens: 1024, system: SYSTEME, messages, tools: outils });
      const appels = message.content.filter((b) => b.type === "tool_use");
      trace.echanges.push({ format: "anthropic-messages", flux, modele: message.model, id: message.id, stop_reason: message.stop_reason, demandes: appels.map((a) => a.name) });
      if (appels.length === 0) {
        trace.fin = message.content.filter((b) => b.type === "text").map((b) => b.text).join("");
        dire(`modèle (fin de tour) : ${trace.fin}`);
        break;
      }
      dire(`modèle (${flux ? "flux SSE" : "hors flux"}) : demande ${appels.map((a) => a.name).join(", ")}`);
      const resultats = [];
      for (const a of appels) {
        const outil = annonceDe.get(a.name);
        if (!outil) throw new Error(`le modèle demande un outil que l'enregistreur n'annonce pas : ${a.name}`);
        const ta = { outil, nom_modele: a.name, arguments: a.input, resultat: "", is_error: false, emissions: 0, tickets: [], structured: null };
        trace.appels.push(ta);
        await appelerAvecApprobation(() => mcp.callTool({ name: outil, arguments: a.input, _meta: { "noortrace/delegation": { run_id: runId } } }), ta, Number(env.AGENT_PAUSE_MS ?? 500), Number(env.AGENT_ATTENTE_MAX_MS ?? 60000));
        dire(`${outil} : ${ta.is_error ? "résultat en erreur" : "résultat reçu"} après ${ta.emissions} émission(s)`);
        resultats.push({ type: "tool_result", tool_use_id: a.id, content: ta.resultat, ...(ta.is_error ? { is_error: true } : {}) });
      }
      messages.push({ role: "assistant", content: message.content }, { role: "user", content: resultats });
      if (echange === 12) throw new Error("le tour n'est pas clos après 12 échanges");
    }
  } finally {
    await mcp.close().catch(() => {});
  }
  process.stdout.write(`noortrace-agent ${JSON.stringify(trace)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  principal().then(
    () => process.exit(0),
    (e) => {
      process.stderr.write(`agent : échec : ${e?.stack ?? e}\n`);
      process.exit(1);
    },
  );
}
