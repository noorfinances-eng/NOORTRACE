// Client MCP minimal des essais du mode observation (CT-9 TE-10 ; Streamable
// HTTP, CT-2 §4, ère 2025-06-18 : initialize, session, tools/call). Sans
// dépendance : il tourne comme programme dans un conteneur de l'image de
// l'enregistreur, dans l'espace réseau de l'enregistreur (les ports ne sont
// pas publiés sur un réseau interne). Une ligne JSON par appel : nom, code
// HTTP, durée, résultat (ou erreur JSON-RPC) et signal d'approbation.
//
//   node client-mcp.mjs <url> <fichier du jeton> <appels JSON> [pause ms entre deux appels]
//
// <appels JSON> : `[{ "name": "outils__read_file", "arguments": { … } }, …]`.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [url, fichierJeton, appelsJson, pauseMs = "0"] = process.argv.slice(2);
  const jeton = fs.readFileSync(fichierJeton, "utf8").trim();
  const appels = JSON.parse(appelsJson);
  let session = null;
  let id = 0;
  const lireCorps = (texte) => {
    const donnees = texte.startsWith("event:") || texte.startsWith("data:") ? texte.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).pop() : texte;
    try {
      return JSON.parse(donnees);
    } catch {
      return null;
    }
  };
  async function requete(method, params, notification = false) {
    const corps = notification ? { jsonrpc: "2.0", method } : { jsonrpc: "2.0", id: ++id, method, params };
    const h = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${jeton}` };
    if (session) Object.assign(h, { "mcp-session-id": session, "mcp-protocol-version": "2025-06-18" });
    const debut = Date.now();
    const rep = await fetch(url, { method: "POST", headers: h, body: JSON.stringify(corps) });
    session ??= rep.headers.get("mcp-session-id");
    const texte = await rep.text();
    return { status: rep.status, ms: Date.now() - debut, json: lireCorps(texte) };
  }
  await requete("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "client-mcp-observation", version: "0.1.0" } });
  await requete("notifications/initialized", {}, true);
  for (const a of appels) {
    const r = await requete("tools/call", { name: a.name, arguments: a.arguments ?? {} });
    const result = r.json?.result ?? null;
    process.stdout.write(`${JSON.stringify({ name: a.name, status: r.status, ms: r.ms, is_error: result?.isError ?? null, approval: result?._meta?.["noortrace/approval"] ?? null, text: result?.content?.[0]?.text ?? null, error: r.json?.error ?? null })}\n`);
    if (Number(pauseMs) > 0) await new Promise((x) => setTimeout(x, Number(pauseMs)));
  }
}
