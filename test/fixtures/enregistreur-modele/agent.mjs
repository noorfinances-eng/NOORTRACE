// Agent de test réel (processus Node) du parcours du frontal modèle : il
// parle au fournisseur simulé à travers la passerelle de l'enregistreur (URL
// de base, jeton statique, `X-Noortrace-Run-Id`), dans chacun des quatre
// formats de la version 0, en flux puis hors flux ; entre les deux, il
// exécute l'appel d'outil demandé par le modèle à travers le mandataire MCP
// (Streamable HTTP, ère héritée), avec le même `run_id` déclaré, comme le
// ferait un hôte (corrélation de CT-2 5.6). Il imprime un résumé JSON sur la
// sortie standard. Importé sans être lancé, il ne fait rien.
//
//   node agent.mjs '<paramètres JSON>'
//   { passerelle, jetonModele, mcp, jetonMcp, runId }

import { pathToFileURL } from "node:url";

const SYSTEME = "Tu es l'agent sinistres de l'assureur de demonstration.";
const QUESTION = "Ou en est le sinistre 2026-81044 ?";

/** Lit un corps SSE en valeurs `data` (lignes `data:` d'un événement). */
function donneesSse(texte) {
  const sortie = [];
  for (const bloc of texte.replace(/\r\n?/g, "\n").split("\n\n")) {
    const lignes = bloc.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, ""));
    if (lignes.length) sortie.push(lignes.join("\n"));
  }
  return sortie;
}

/** Appel d'outil demandé dans une réponse en flux, lu comme un SDK le ferait. */
function appelDuFlux(format, texte) {
  const datas = donneesSse(texte);
  if (format === "anthropic-messages") {
    let appel = null;
    let tampon = "";
    for (const d of datas) {
      const v = JSON.parse(d);
      if (v.type === "content_block_start" && v.content_block.type === "tool_use") appel = { id: v.content_block.id, name: v.content_block.name };
      if (v.type === "content_block_delta" && v.delta.type === "input_json_delta") tampon += v.delta.partial_json;
    }
    return appel ? { ...appel, arguments: JSON.parse(tampon || "{}") } : null;
  }
  if (format === "openai-chat") {
    let appel = null;
    for (const d of datas) {
      if (d === "[DONE]") break;
      const v = JSON.parse(d);
      for (const c of v.choices ?? []) {
        for (const tc of c.delta?.tool_calls ?? []) {
          appel ??= { id: null, name: "", arguments: "" };
          if (tc.id) appel.id = tc.id;
          if (tc.function?.name) appel.name = tc.function.name;
          if (tc.function?.arguments) appel.arguments += tc.function.arguments;
        }
      }
    }
    return appel ? { ...appel, arguments: JSON.parse(appel.arguments) } : null;
  }
  if (format === "openai-responses") {
    for (const d of datas) {
      const v = JSON.parse(d);
      if (v.type === "response.completed") {
        const f = v.response.output.find((x) => x.type === "function_call");
        return f ? { id: f.call_id, name: f.name, arguments: JSON.parse(f.arguments) } : null;
      }
    }
    return null;
  }
  for (const d of datas) {
    const v = JSON.parse(d);
    for (const p of v.candidates?.[0]?.content?.parts ?? []) if (p.functionCall) return { id: null, name: p.functionCall.name, arguments: p.functionCall.args ?? {} };
  }
  return null;
}

/** Corps de requête d'un format, sans puis avec le résultat de l'outil. */
function corpsRequete(format, flux, appel, resultat) {
  if (format === "anthropic-messages") {
    const messages = [{ role: "user", content: QUESTION }];
    if (appel) {
      messages.push({ role: "assistant", content: [{ type: "tool_use", id: appel.id, name: appel.name, input: appel.arguments }] });
      messages.push({ role: "user", content: [{ type: "tool_result", tool_use_id: appel.id, content: resultat }] });
    }
    return { model: "modele-messages-simule", max_tokens: 512, system: SYSTEME, messages, tools: [{ name: "demo__claims_get", description: "Rend le dossier", input_schema: { type: "object", properties: { claim_id: { type: "string" } } } }], stream: flux };
  }
  if (format === "openai-chat") {
    const messages = [{ role: "system", content: SYSTEME }, { role: "user", content: QUESTION }];
    if (appel) {
      messages.push({ role: "assistant", content: null, tool_calls: [{ id: appel.id, type: "function", function: { name: appel.name, arguments: JSON.stringify(appel.arguments) } }] });
      messages.push({ role: "tool", tool_call_id: appel.id, content: resultat });
    }
    return { model: "modele-chat-simule", messages, tools: [{ type: "function", function: { name: "demo__claims_get", parameters: { type: "object" } } }], stream: flux, ...(flux ? { stream_options: { include_usage: true } } : {}) };
  }
  if (format === "openai-responses") {
    const input = [{ role: "user", content: QUESTION }];
    if (appel) {
      input.push({ type: "function_call", call_id: appel.id, name: appel.name, arguments: JSON.stringify(appel.arguments) });
      input.push({ type: "function_call_output", call_id: appel.id, output: resultat });
    }
    return { model: "modele-responses-simule", instructions: SYSTEME, input, tools: [{ type: "function", name: "demo__claims_get", parameters: { type: "object" } }], stream: flux };
  }
  const contents = [{ role: "user", parts: [{ text: QUESTION }] }];
  if (appel) {
    contents.push({ role: "model", parts: [{ functionCall: { name: appel.name, args: appel.arguments } }] });
    contents.push({ role: "user", parts: [{ functionResponse: { name: appel.name, response: { output: resultat } } }] });
  }
  return { contents, systemInstruction: { parts: [{ text: SYSTEME }] }, tools: [{ functionDeclarations: [{ name: "demo__claims_get", parameters: { type: "OBJECT" } }] }] };
}

const CHEMINS = {
  "anthropic-messages": () => "/v1/messages",
  "openai-chat": () => "/v1/chat/completions",
  "openai-responses": () => "/v1/responses",
  gemini: (flux) => (flux ? "/v1beta/models/gemini-simule:streamGenerateContent?alt=sse" : "/v1beta/models/gemini-simule:generateContent"),
};

async function modele(p, format, flux, appel, resultat) {
  const entetes = { "content-type": "application/json", "x-noortrace-run-id": p.runId, "user-agent": "agent-de-test/0.1" };
  if (p.jetonModele) entetes["x-noortrace-token"] = p.jetonModele;
  if (format === "anthropic-messages") entetes["anthropic-version"] = "2023-06-01";
  const r = await fetch(`${p.passerelle}${CHEMINS[format](flux)}`, { method: "POST", headers: entetes, body: JSON.stringify(corpsRequete(format, flux, appel, resultat)) });
  return { statut: r.status, type: r.headers.get("content-type"), texte: await r.text() };
}

async function mcp(p, session, corps) {
  const entetes = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${p.jetonMcp}` };
  if (session) entetes["mcp-session-id"] = session;
  const r = await fetch(p.mcp, { method: "POST", headers: entetes, body: JSON.stringify(corps) });
  const texte = await r.text();
  const json = texte.startsWith("data:") ? JSON.parse(donneesSse(texte).pop()) : texte ? JSON.parse(texte) : null;
  return { statut: r.status, session: r.headers.get("mcp-session-id"), json };
}

const assainir = (n) => n.replace(/[^A-Za-z0-9_-]/g, "_");

async function principal() {
  const p = JSON.parse(process.argv[2]);
  // Sans mandataire MCP (modes icap et miroir du parcours) : l'outil est exécuté par l'agent lui-même.
  let session = null;
  let outils = ["demo__claims.get"];
  if (p.mcp) {
    const init = await mcp(p, null, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "agent-de-test", version: "0.1.0" } } });
    session = init.session;
    await mcp(p, session, { jsonrpc: "2.0", method: "notifications/initialized" });
    const liste = await mcp(p, session, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    outils = liste.json.result.tools.map((t) => t.name);
  }
  const resume = { session, outils, formats: {} };
  let id = 10;
  for (const format of ["anthropic-messages", "openai-chat", "openai-responses", "gemini"]) {
    const premier = await modele(p, format, true);
    const appel = appelDuFlux(format, premier.texte);
    const annonce = outils.find((n) => assainir(n) === appel.name);
    const r = p.mcp
      ? await mcp(p, session, {
          jsonrpc: "2.0",
          id: ++id,
          method: "tools/call",
          params: { name: annonce, arguments: appel.arguments, _meta: { "noortrace/delegation": { run_id: p.runId } } },
        })
      : { statut: 0, json: { result: { content: [{ text: "Sinistre 2026-81044 : ouvert, 7400.00 CHF." }] } } };
    const resultat = r.json.result.content[0].text;
    const second = await modele(p, format, false, appel, resultat);
    resume.formats[format] = { flux: { statut: premier.statut, type: premier.type, octets: Buffer.byteLength(premier.texte) }, appel: { annonce, ...appel }, outil: { statut: r.statut, resultat }, final: { statut: second.statut, corps: JSON.parse(second.texte) } };
  }
  process.stdout.write(`${JSON.stringify(resume)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  principal().catch((e) => {
    process.stderr.write(`agent : ${e?.stack ?? e}\n`);
    process.exit(1);
  });
}
