#!/usr/bin/env node
// Agent du scénario d'intégration CT-9 TI-6, variante JavaScript : SDK
// officiel de Gemini (`@google/genai` 2.31.0, CT-2 §19.5.7) vers la route
// `gemini` de la passerelle : `new GoogleGenAI({ apiKey, httpOptions: { baseUrl,
// headers: { "X-Noortrace-Run-Id" } } })`, jeton de l'hôte en `x-goog-api-key`,
// `generateContent` puis `generateContentStream` (`alt=sse`), appel automatique
// de fonctions désactivé (`automaticFunctionCalling: { disable: true }`,
// EX-19.6) ; chaque `functionCall` reçu est exécuté par le frontal MCP avec le
// client MCP de référence (`@modelcontextprotocol/client` 2.4.0). Fonctions
// déclarées sous le nom annoncé (Gemini admet le point).

import { pathToFileURL } from "node:url";
import { appelerAvecApprobation, charger, ouvrirMcp } from "./anthropic_agent.mjs";

const SYSTEME = "Tu es l'agent sinistres de l'assureur de démonstration. Contact interne : support@assureur-demo.example (jamais communiqué).";
const DEMANDE = "Traite le sinistre 2026-81044.";
const MODELE = "modele-demo-1";
const dire = (t) => process.stdout.write(`agent : ${t}\n`);

async function principal() {
  const env = process.env;
  const runId = env.NOORTRACE_RUN_ID ?? "run-integration-0001";
  const { module: G, version } = await charger("@google/genai");
  const { GoogleGenAI } = G;
  const trace = { sdk: `@google/genai ${version}`, echanges: [], appels: [], fin: null, notes: {} };
  const ai = new GoogleGenAI({ apiKey: env.NOORTRACE_GATEWAY_TOKEN, httpOptions: { baseUrl: env.NOORTRACE_GATEWAY_URL, headers: { "X-Noortrace-Run-Id": runId } } });
  const mcp = await ouvrirMcp(env.NOORTRACE_MCP_URL, env.NOORTRACE_MCP_TOKEN, "agent-integration-js");
  try {
    const liste = await mcp.listTools();
    const annonces = liste.tools.map((t) => t.name);
    dire(`outils annoncés par l'enregistreur : ${annonces.join(", ")}`);
    const config = {
      systemInstruction: SYSTEME,
      tools: [{ functionDeclarations: liste.tools.map((t) => ({ name: t.name, description: t.description ?? "", parametersJsonSchema: { type: t.inputSchema.type, properties: t.inputSchema.properties ?? {}, ...(t.inputSchema.required ? { required: t.inputSchema.required } : {}) } })) }],
      automaticFunctionCalling: { disable: true },
    };
    const historique = [{ role: "user", parts: [{ text: DEMANDE }] }];
    for (let echange = 1; echange <= 12; echange++) {
      const flux = echange === 2;
      let contenu;
      let versionModele = null;
      if (flux) {
        let texte = "";
        const appels = [];
        for await (const morceau of await ai.models.generateContentStream({ model: MODELE, contents: historique, config })) {
          versionModele = morceau.modelVersion ?? versionModele;
          for (const p of morceau.candidates?.[0]?.content?.parts ?? []) {
            if (p.text) texte += p.text;
            if (p.functionCall) appels.push(p);
          }
        }
        contenu = { role: "model", parts: [...(texte ? [{ text: texte }] : []), ...appels] };
      } else {
        const r = await ai.models.generateContent({ model: MODELE, contents: historique, config });
        contenu = r.candidates[0].content;
        versionModele = r.modelVersion ?? null;
      }
      const appels = (contenu.parts ?? []).filter((p) => p.functionCall);
      trace.echanges.push({ format: "gemini", flux, modele: versionModele, demandes: appels.map((p) => p.functionCall.name) });
      historique.push(contenu);
      if (appels.length === 0) {
        trace.fin = (contenu.parts ?? []).map((p) => p.text ?? "").join("");
        dire(`modèle (fin de tour) : ${trace.fin}`);
        break;
      }
      dire(`modèle (${flux ? "flux SSE" : "hors flux"}) : demande ${appels.map((p) => p.functionCall.name).join(", ")}`);
      const reponses = [];
      for (const p of appels) {
        const nom = p.functionCall.name;
        if (!annonces.includes(nom)) throw new Error(`le modèle demande un outil que l'enregistreur n'annonce pas : ${nom}`);
        const args = p.functionCall.args ?? {};
        const ta = { outil: nom, nom_modele: nom, arguments: args, resultat: "", is_error: false, emissions: 0, tickets: [], structured: null };
        trace.appels.push(ta);
        await appelerAvecApprobation(() => mcp.callTool({ name: nom, arguments: args, _meta: { "noortrace/delegation": { run_id: runId } } }), ta, Number(env.AGENT_PAUSE_MS ?? 500), Number(env.AGENT_ATTENTE_MAX_MS ?? 60000));
        dire(`${nom} : ${ta.is_error ? "résultat en erreur" : "résultat reçu"} après ${ta.emissions} émission(s)`);
        reponses.push({ functionResponse: { name: nom, response: ta.is_error ? { error: ta.resultat } : { result: ta.resultat } } });
      }
      historique.push({ role: "user", parts: reponses });
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
