// Serveur d'outils factice de l'essai de l'installation rapide (CT-8 §7,
// IR-7) : MCP en Streamable HTTP sur TLS, réponses JSON, un outil
// `read_file` qui rend un texte fixe. Sans dépendance : il tourne dans un
// conteneur de l'image de l'enregistreur (Node.js seul), sur le réseau
// interne `sortie`, sous le nom du serveur d'outils de la configuration de
// référence (outils.interne.example, domaine réservé). Il ne joint rien.
//
//   node serveur-outils.mjs <cle.pem> <certificat.pem> [port]

import fs from "node:fs";
import https from "node:https";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

// Exécuté seulement comme programme (jamais à l'import, par exemple par le chargeur des essais).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [cle, certificat, port = "443"] = process.argv.slice(2);
  const OUTIL = { name: "read_file", description: "Lit un fichier (serveur factice de l'essai)", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } };

  const serveur = https.createServer({ key: fs.readFileSync(cle), cert: fs.readFileSync(certificat) }, (req, rep) => {
    if (req.url !== "/mcp") return rep.writeHead(404).end();
    if (req.method === "DELETE") return rep.writeHead(204).end();
    if (req.method !== "POST") return rep.writeHead(405, { Allow: "POST, DELETE" }).end();
    const morceaux = [];
    req.on("data", (m) => morceaux.push(m));
    req.on("end", () => {
      let m;
      try {
        m = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        return rep.writeHead(400).end();
      }
      if (m.id === undefined) return rep.writeHead(202).end();
      let result;
      if (m.method === "initialize") result = { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "outils-factices", version: "0.1.0" } };
      else if (m.method === "tools/list") result = { tools: [OUTIL] };
      else if (m.method === "tools/call") result = { content: [{ type: "text", text: `contenu factice de ${m.params?.arguments?.path ?? "?"}` }], isError: false };
      else if (m.method === "ping") result = {};
      const corps = JSON.stringify(result === undefined ? { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "méthode inconnue" } } : { jsonrpc: "2.0", id: m.id, result });
      const entetes = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(corps) };
      if (m.method === "initialize") entetes["Mcp-Session-Id"] = crypto.randomUUID();
      rep.writeHead(200, entetes).end(corps);
    });
  });
  serveur.listen(Number(port), "0.0.0.0", () => process.stderr.write(`serveur d'outils factice à l'écoute sur ${port}\n`));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => serveur.close(() => process.exit(0)));
}
