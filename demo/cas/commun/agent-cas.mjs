#!/usr/bin/env node
// Agent scénarisé des cas de démonstration (CT-9 TE-1, TE-2) : l'agent de la
// démonstration de référence (`conteneurs/agent-demo/agent-demo.mjs`, dont il
// tourne dans l'image et dont il reprend le client MCP, le client de l'API
// Messages et la tentative de connexion directe), avec trois différences :
//   - la consigne système et la demande sont lues dans `AGENT_CAS_SYSTEME`
//     et `AGENT_CAS_DEMANDE` ;
//   - un appel soumis à approbation est ré-émis tant que son ticket est
//     `en_attente`, jusqu'à `AGENT_DEMO_ATTENTE_MAX_MS` : les approbateurs
//     décident depuis la console, à la main, et l'agent attend ;
//   - un appel refusé ou expiré n'est pas répété : son résultat d'erreur est
//     rendu au modèle, qui poursuit le tour (cas « administration », TE-2).
//
//   agent-cas.mjs jouer
//
// Mêmes variables que l'agent de la démonstration (`NOORTRACE_MCP_URL`,
// `NOORTRACE_MCP_TOKEN`, `ANTHROPIC_BASE_URL`, `NOORTRACE_GATEWAY_TOKEN`,
// `ANTHROPIC_API_KEY` factice, `AGENT_DEMO_*`). Code 0 si le tour est clos et
// qu'aucune cible n'est jointe directement ; 1 sinon.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Le programme de la démonstration voisin dans l'image (/opt/noortrace-demo), ou dans le dépôt (conteneurs/) pour les essais. */
const ICI = path.dirname(fileURLToPath(import.meta.url));
const { Agent, assainir, consoliderFlux } = await import(fs.existsSync(path.join(ICI, "agent-demo.mjs")) ? "./agent-demo.mjs" : "../../../conteneurs/agent-demo/agent-demo.mjs");

function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

const dire = (texte) => process.stdout.write(`agent-cas : ${texte}\n`);
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

export class AgentCas extends Agent {
  constructor(env) {
    super(env);
    this.systeme = env.AGENT_CAS_SYSTEME ?? "Tu es un agent de démonstration.";
    this.demande = env.AGENT_CAS_DEMANDE ?? "Traite le dossier.";
    this.refuses = [];
  }

  /** Échange de modèle par la passerelle, avec la consigne système du cas. */
  async modele(messages, outils, flux) {
    const corps = { model: this.nomModele, max_tokens: 1024, system: this.systeme, messages, tools: outils };
    if (flux) corps.stream = true;
    const r = await fetch(`${this.passerelle}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": this.cleFactice,
        "x-noortrace-token": this.passerelleJeton, "x-noortrace-run-id": "run-cas-0001", "user-agent": "agent-cas/0.1.0",
      },
      body: JSON.stringify(corps),
    });
    const texte = await r.text();
    if (r.status !== 200) throw new Error(`échange de modèle refusé (HTTP ${r.status}) : ${texte.slice(0, 300)}`);
    return (r.headers.get("content-type") ?? "").startsWith("text/event-stream") ? consoliderFlux(texte) : JSON.parse(texte);
  }

  /** Tour d'agent : le modèle décide des appels ; le deuxième échange est demandé en flux SSE. */
  async jouer() {
    const liste = await this.mcp("tools/list");
    const annonces = liste.tools.map((t) => t.name);
    const outils = liste.tools.map((t) => ({ name: assainir(t.name), description: t.description, input_schema: { type: t.inputSchema.type, properties: t.inputSchema.properties, required: t.inputSchema.required } }));
    dire(`outils annoncés par l'enregistreur : ${annonces.join(", ")}`);
    const annonceDe = (nomModele) => annonces.find((n) => assainir(n) === nomModele);
    const texteDe = (resultat) => resultat.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    const messages = [{ role: "user", content: this.demande }];
    for (let echange = 1; ; echange++) {
      if (echange > this.echangesMax) throw new Error(`le tour n'est pas clos après ${this.echangesMax} échanges de modèle`);
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

  /** `tools/call` par le frontal MCP ; attend la décision des approbateurs ; un refus ou une expiration est rendu au modèle. */
  async appeler(outil, args) {
    const debut = Date.now();
    for (let emission = 1; ; emission++) {
      const r = await this.mcp("tools/call", { name: outil, arguments: args });
      const signal = r._meta?.["noortrace/approval"] ?? null;
      if (!signal) {
        if (r.isError) dire(`${outil} : résultat en erreur rendu au modèle`);
        else dire(emission === 1 ? `${outil} : résultat reçu` : `${outil} : exécuté après approbation (${Object.values(r.structuredContent ?? {})[0] ?? "sans identifiant"})`);
        return r;
      }
      if (signal.state !== "en_attente") {
        dire(`${outil} : ticket ${signal.ticket} ${signal.state} : l'appel n'est pas répété, le modèle en est informé`);
        this.refuses.push({ outil, ticket: signal.ticket, state: signal.state });
        return { content: [{ type: "text", text: `Appel ${outil} ${signal.state} par les approbateurs (ticket ${signal.ticket}) : non exécuté.` }], isError: true };
      }
      if (emission === 1) dire(`${outil} : en attente d'approbation (ticket ${signal.ticket}) ; les approbateurs décident depuis la console`);
      if (Date.now() - debut > this.attenteMaxMs) throw new Error(`${outil} : toujours en attente d'approbation après ${this.attenteMaxMs} ms`);
      await attendre(this.pauseMs);
    }
  }
}

if (estProgramme(import.meta.url)) {
  if (process.argv[2] !== "jouer") {
    process.stderr.write("usage : agent-cas.mjs jouer\n");
    process.exit(2);
  }
  const agent = new AgentCas(process.env);
  agent.jouer().then(() => agent.tenterDirect()).then(
    (jointes) => {
      if (agent.refuses.length) dire(`appels non exécutés : ${agent.refuses.map((x) => `${x.outil} (${x.ticket} ${x.state})`).join(", ")}`);
      if (jointes.length) process.stderr.write(`agent-cas : échec : l'agent a joint ${jointes.join(", ")} sans passer par l'enregistreur\n`);
      process.exit(jointes.length ? 1 : 0);
    },
    (e) => {
      process.stderr.write(`agent-cas : échec : ${e.message}\n`);
      process.exit(1);
    },
  );
}
