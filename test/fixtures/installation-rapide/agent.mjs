// Agent MCP minimal de l'essai de l'installation rapide (CT-8 IR-7 ;
// Streamable HTTP, CT-2 §4) : initialize, tools/list, tools/call, une ligne
// JSON par réponse. Sans dépendance : il tourne dans un conteneur de l'image de
// l'enregistreur, dans l'espace réseau de l'enregistreur (les ports ne sont pas
// publiés sur un réseau interne). Le jeton est lu dans le fichier donné.
//
//   node agent.mjs <url> <fichier du jeton> <outil>
import fs from "node:fs";
import { pathToFileURL } from "node:url";
// Exécuté seulement comme programme (jamais à l'import, par exemple par le chargeur des essais).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [url, fichierJeton, outil] = process.argv.slice(2);
  const jeton = fs.readFileSync(fichierJeton, "utf8").trim();
  let session = null;
  let id = 0;
  async function requete(method, params, notification = false) {
    const corps = notification ? { jsonrpc: "2.0", method } : { jsonrpc: "2.0", id: ++id, method, params };
    const h = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${jeton}` };
    if (session) Object.assign(h, { "mcp-session-id": session, "mcp-protocol-version": "2025-06-18" });
    const rep = await fetch(url, { method: "POST", headers: h, body: JSON.stringify(corps) });
    session ??= rep.headers.get("mcp-session-id");
    const texte = await rep.text();
    console.log(JSON.stringify({ method, status: rep.status, corps: texte.slice(0, 600) }));
  }
  await requete("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "agent-installation-rapide", version: "0.1.0" } });
  await requete("notifications/initialized", undefined, true);
  await requete("tools/list", {});
  await requete("tools/call", { name: outil, arguments: { path: "/rapport.txt" } });
}
