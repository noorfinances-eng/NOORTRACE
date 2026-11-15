#!/usr/bin/env node
// Service `agent-demo` de la démonstration de référence (CT-2 §19.1, §19.2) :
// agent scénarisé. Il ne connaît que l'enregistreur : le frontal MCP
// (Streamable HTTP, ère 2026-07-28) et la passerelle de modèle, dont l'URL de
// base est lue dans `ANTHROPIC_BASE_URL` comme le fait un SDK de l'API
// Messages. Sans dépendance : les requêtes ont la forme documentée de l'API
// Messages et de MCP, envoyées par `fetch`.
//
//   agent-demo.mjs jouer
//
// Variables : `NOORTRACE_MCP_URL` (http://enregistreur:8300/mcp),
// `NOORTRACE_MCP_TOKEN` (jeton statique de l'hôte), `ANTHROPIC_BASE_URL`
// (http://enregistreur:8400), `NOORTRACE_GATEWAY_TOKEN` (jeton de la
// passerelle), `ANTHROPIC_API_KEY` (clé factice : la passerelle porte la
// sienne, `credentials: "propre"`), `AGENT_DEMO_PAUSE_MS` (attente entre deux
// émissions de l'appel soumis à approbation, 2000 par défaut),
// `AGENT_DEMO_ATTENTE_MAX_MS` (90000 par défaut),
// `AGENT_DEMO_CIBLES_INTERDITES` (outils-demo:8000,modele-demo:8080),
// `AGENT_DEMO_MODELE` (modele-demo-1), `AGENT_DEMO_ECHANGES_MAX` (12).
//
// Tour d'agent : le modèle décide des appels, l'agent les exécute par le
// frontal MCP. Avec le simulateur, c'est le scénario de §19.2 (pas 2 à 8) :
// échange de modèle hors flux, `tools/call demo__claims.get`, échange de
// modèle en flux SSE, `tools/call demo__payments.create` retenu pour
// approbation, ré-émission après la décision, échange de modèle de fin de
// tour. Puis l'agent tente de joindre
// directement le serveur d'outils et le simulateur de modèle, et affiche qu'il
// n'y parvient pas (§19.1). Code 0 si le paiement est exécuté, le tour clos
// et aucune cible jointe directement ; 1 sinon.

import fs from "node:fs";
import net from "node:net";
import { fileURLToPath } from "node:url";

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

export const RUN_ID = "run-demo-0001";
export const VERSION_PROTOCOLE = "2026-07-28";
export const SYSTEME = "Tu es l'agent sinistres de l'assureur de démonstration. Contact interne : support@assureur-demo.example (jamais communiqué).";
export const DEMANDE = "Traite le sinistre 2026-81044.";

const dire = (texte) => process.stdout.write(`agent-demo : ${texte}\n`);
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

/** Nom d'outil vu par le modèle : le nom annoncé, tout caractère hors `[A-Za-z0-9_-]` remplacé par `_` (CT-2 EX-4.12). */
export const assainir = (nom) => nom.replace(/[^A-Za-z0-9_-]/g, "_");

/** Lit un corps SSE de l'API Messages et rend le message consolidé, comme un SDK le fait. */
export function consoliderFlux(texte) {
  let message = null;
  const partiels = new Map();
  for (const bloc of texte.replace(/\r\n?/g, "\n").split("\n\n")) {
    const donnees = bloc.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
    if (!donnees) continue;
    const v = JSON.parse(donnees);
    if (v.type === "message_start") message = { ...v.message, content: [] };
    else if (v.type === "content_block_start") {
      message.content[v.index] = { ...v.content_block };
      if (v.content_block.type === "tool_use") partiels.set(v.index, "");
    } else if (v.type === "content_block_delta") {
      if (v.delta.type === "text_delta") message.content[v.index].text += v.delta.text;
      else if (v.delta.type === "input_json_delta") partiels.set(v.index, partiels.get(v.index) + v.delta.partial_json);
    } else if (v.type === "content_block_stop") {
      if (partiels.has(v.index)) message.content[v.index].input = JSON.parse(partiels.get(v.index) || "{}");
    } else if (v.type === "message_delta") {
      Object.assign(message, v.delta);
      message.usage = { ...message.usage, ...v.usage };
    }
  }
  return message;
}

export class Agent {
  constructor(env) {
    this.mcpUrl = env.NOORTRACE_MCP_URL ?? "http://enregistreur:8300/mcp";
    this.mcpJeton = env.NOORTRACE_MCP_TOKEN ?? "";
    this.passerelle = (env.ANTHROPIC_BASE_URL ?? "http://enregistreur:8400").replace(/\/$/, "");
    this.passerelleJeton = env.NOORTRACE_GATEWAY_TOKEN ?? "";
    this.cleFactice = env.ANTHROPIC_API_KEY ?? "cle-factice-agent-demo";
    this.pauseMs = Number(env.AGENT_DEMO_PAUSE_MS ?? 2000);
    this.attenteMaxMs = Number(env.AGENT_DEMO_ATTENTE_MAX_MS ?? 90000);
    this.nomModele = env.AGENT_DEMO_MODELE ?? "modele-demo-1";
    this.echangesMax = Number(env.AGENT_DEMO_ECHANGES_MAX ?? 12);
    this.ciblesInterdites = (env.AGENT_DEMO_CIBLES_INTERDITES ?? "outils-demo:8000,modele-demo:8080").split(",").filter(Boolean);
    this.id = 0;
  }

  /** Requête MCP de l'ère moderne : métadonnées par requête, en-têtes `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`. */
  async mcp(methode, params = {}) {
    const corps = {
      jsonrpc: "2.0", id: `agent-demo-${String(++this.id).padStart(2, "0")}`, method: methode,
      params: {
        ...params,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": VERSION_PROTOCOLE,
          "io.modelcontextprotocol/clientCapabilities": {},
          "io.modelcontextprotocol/clientInfo": { name: "agent-demo", version: "0.1.0" },
          "noortrace/delegation": { run_id: RUN_ID },
        },
      },
    };
    const entetes = {
      "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${this.mcpJeton}`,
      "mcp-protocol-version": VERSION_PROTOCOLE, "mcp-method": methode,
    };
    if (methode === "tools/call") entetes["mcp-name"] = params.name;
    const r = await fetch(this.mcpUrl, { method: "POST", headers: entetes, body: JSON.stringify(corps) });
    const texte = await r.text();
    let json;
    try {
      const donnees = texte.startsWith("event:") || texte.startsWith("data:") ? texte.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).pop() : texte;
      json = JSON.parse(donnees);
    } catch {
      throw new Error(`${methode} : réponse illisible du frontal MCP (HTTP ${r.status})`);
    }
    if (json.error) throw new Error(`${methode} : erreur ${json.error.code} ${json.error.message}${json.error.data?.reason ? ` (${json.error.data.reason})` : ""}`);
    return json.result;
  }

  /** Échange de modèle par la passerelle (`POST /v1/messages`). */
  async modele(messages, outils, flux) {
    const corps = { model: this.nomModele, max_tokens: 1024, system: SYSTEME, messages, tools: outils };
    if (flux) corps.stream = true;
    const r = await fetch(`${this.passerelle}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": this.cleFactice,
        "x-noortrace-token": this.passerelleJeton, "x-noortrace-run-id": RUN_ID, "user-agent": "agent-demo/0.1.0",
      },
      body: JSON.stringify(corps),
    });
    const texte = await r.text();
    if (r.status !== 200) throw new Error(`échange de modèle refusé (HTTP ${r.status}) : ${texte.slice(0, 300)}`);
    return (r.headers.get("content-type") ?? "").startsWith("text/event-stream") ? consoliderFlux(texte) : JSON.parse(texte);
  }

  /**
   * Tour d'agent : le modèle décide des appels, l'agent les exécute par le frontal MCP et lui rend les résultats,
   * jusqu'à la fin du tour. Avec le simulateur, le tour est celui de CT-2 §19.2 (pas 2 à 8) : trois échanges de modèle,
   * le deuxième en flux SSE, deux appels d'outil. Un appel soumis à approbation est ré-émis tel quel après une pause,
   * tant que le ticket est en attente ; refusé ou expiré, il n'est pas répété.
   */
  async jouer() {
    // Liste des outils servie par l'enregistreur : le modèle les voit sous leur nom assaini.
    const liste = await this.mcp("tools/list");
    const annonces = liste.tools.map((t) => t.name);
    const outils = liste.tools.map((t) => ({ name: assainir(t.name), description: t.description, input_schema: { type: t.inputSchema.type, properties: t.inputSchema.properties, required: t.inputSchema.required } }));
    dire(`outils annoncés par l'enregistreur : ${annonces.join(", ")}`);
    const annonceDe = (nomModele) => annonces.find((n) => assainir(n) === nomModele);
    const texteDe = (resultat) => resultat.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    const messages = [{ role: "user", content: DEMANDE }];
    for (let echange = 1; ; echange++) {
      if (echange > this.echangesMax) throw new Error(`le tour n'est pas clos après ${this.echangesMax} échanges de modèle`);
      // Le deuxième échange est demandé en flux SSE, les autres hors flux (§19.2, pas 2, 4 et 8).
      const flux = echange === 2;
      const reponse = await this.modele(messages, outils, flux);
      const appels = reponse.content.filter((b) => b.type === "tool_use");
      if (appels.length === 0) {
        dire(`modèle (fin de tour) : ${texteDe(reponse)}`);
        if (reponse.stop_reason !== "end_turn") throw new Error(`fin de tour attendue, reçu ${reponse.stop_reason}`);
        return;
      }
      dire(`modèle (${flux ? "flux SSE" : "hors flux"}) : demande ${appels.map((a) => a.name).join(", ")}`);
      const resultats = [];
      for (const appel of appels) {
        const outil = annonceDe(appel.name);
        if (!outil) throw new Error(`le modèle demande un outil que l'enregistreur n'annonce pas : ${appel.name}`);
        const r = await this.appeler(outil, appel.input);
        resultats.push({ type: "tool_result", tool_use_id: appel.id, content: texteDe(r), ...(r.isError ? { is_error: true } : {}) });
      }
      messages.push({ role: "assistant", content: reponse.content }, { role: "user", content: resultats });
    }
  }

  /** `tools/call` par le frontal MCP ; attend la décision quand l'appel est soumis à approbation, puis le ré-émet. */
  async appeler(outil, args) {
    const debut = Date.now();
    for (let emission = 1; ; emission++) {
      const r = await this.mcp("tools/call", { name: outil, arguments: args });
      const signal = r._meta?.["noortrace/approval"] ?? null;
      if (!signal) {
        if (r.isError) dire(`${outil} : résultat en erreur rendu au modèle`);
        else dire(emission === 1 ? `${outil} : résultat reçu` : `${outil} : exécuté après approbation (${r.structuredContent?.payment_id ?? "sans identifiant"})`);
        return r;
      }
      if (signal.state !== "en_attente") throw new Error(`${outil} : ticket ${signal.ticket} ${signal.state}, l'appel n'est pas répété`);
      if (emission === 1) dire(`${outil} : en attente d'approbation (ticket ${signal.ticket})`);
      if (Date.now() - debut > this.attenteMaxMs) throw new Error(`${outil} : toujours en attente d'approbation après ${this.attenteMaxMs} ms`);
      await attendre(this.pauseMs);
    }
  }

  /**
   * Ce que la démonstration affiche (CT-2 §19.1) : l'agent tente de joindre directement le serveur d'outils et le
   * simulateur de modèle, par leur nom de service, et n'y parvient pas : il n'est attaché qu'au réseau des hôtes.
   * Rend la liste des cibles jointes (vide dans la composition de référence).
   */
  async tenterDirect() {
    const jointes = [];
    const constats = [];
    for (const cible of this.ciblesInterdites) {
      const r = await connexionTcp(cible, 1500);
      constats.push(`${cible} ${r.ok ? "JOINT" : `injoignable (${r.raison})`}`);
      if (r.ok) jointes.push(cible);
    }
    dire(`connexion directe, sans l'enregistreur : ${constats.join(" ; ")}`);
    if (jointes.length === 0) dire("l'agent ne joint que l'enregistreur");
    return jointes;
  }
}

/** Tente une connexion TCP à `hôte:port` ; rend `{ ok, raison }` (code d'erreur du système, ou `delai`). */
export function connexionTcp(cible, delaiMs) {
  const k = cible.lastIndexOf(":");
  return new Promise((resoudre) => {
    const prise = net.connect({ host: cible.slice(0, k), port: Number(cible.slice(k + 1)) });
    const fin = (r) => {
      prise.destroy();
      resoudre(r);
    };
    prise.setTimeout(delaiMs, () => fin({ ok: false, raison: "delai" }));
    prise.once("connect", () => fin({ ok: true, raison: null }));
    prise.once("error", (e) => fin({ ok: false, raison: e.code ?? e.name }));
  });
}

if (estProgramme(import.meta.url)) {
  if (process.argv[2] !== "jouer") {
    process.stderr.write("usage : agent-demo.mjs jouer\n");
    process.exit(2);
  }
  const agent = new Agent(process.env);
  agent.jouer().then(() => agent.tenterDirect()).then(
    (jointes) => {
      if (jointes.length) process.stderr.write(`agent-demo : échec : l'agent a joint ${jointes.join(", ")} sans passer par l'enregistreur\n`);
      process.exit(jointes.length ? 1 : 0);
    },
    (e) => {
      process.stderr.write(`agent-demo : échec : ${e.message}\n`);
      process.exit(1);
    },
  );
}
