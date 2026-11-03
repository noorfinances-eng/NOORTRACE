// Serveur d'outils MCP stdio de l'ère héritée (révision 2025-11-25), lancé
// par le démon pour les tests de haute disponibilité : `lire` (lecture),
// `ecrire` (écriture), `ecrire_lent` (écriture qui ne répond qu'après
// `attente_ms`, pour tuer le démon pendant le relais, 13.5). Une ligne
// JSON-RPC par message (4.7.1).

import readline from "node:readline";

const OUTILS = [
  { name: "lire", description: "Lit une fiche de sinistre", inputSchema: { type: "object", properties: { id: { type: "string" } } }, annotations: { readOnlyHint: true } },
  { name: "ecrire", description: "Enregistre un paiement", inputSchema: { type: "object", properties: { id: { type: "string" }, montant: { type: "string" } } } },
  { name: "ecrire_lent", description: "Enregistre un paiement, lentement", inputSchema: { type: "object", properties: { id: { type: "string" }, attente_ms: { type: "number" } } } },
];

const envoyer = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);

readline.createInterface({ input: process.stdin }).on("line", (l) => {
  let m;
  try {
    m = JSON.parse(l);
  } catch {
    return;
  }
  if (m.id === undefined) return;
  if (m.method === "initialize") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "outils-ha", version: "1.0.0" } } });
  } else if (m.method === "tools/list") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: { tools: OUTILS } });
  } else if (m.method === "tools/call") {
    const a = m.params?.arguments ?? {};
    const repondre = () => envoyer({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `${m.params.name} ${a.id ?? ""} fait` }], structuredContent: { reference: `REF-${a.id ?? "x"}` }, isError: false } });
    if (m.params?.name === "ecrire_lent") setTimeout(repondre, a.attente_ms ?? 60000);
    else repondre();
  } else if (m.method === "ping") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: {} });
  } else {
    envoyer({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
  }
});
