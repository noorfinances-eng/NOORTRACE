// Serveur d'outils MCP de l'ère héritée (poignée de main `initialize`), en
// transport stdio, lancé par le démon pour le parcours du frontal modèle : un
// outil de lecture `claims.get` et un outil d'écriture `payments.create`.
// Une ligne JSON-RPC par requête (cadrage LF, EX-4.31). Importé sans être
// lancé (par le chargeur des tests), il ne fait rien.
import readline from "node:readline";
import { pathToFileURL } from "node:url";

const OUTILS = [
  {
    name: "claims.get",
    description: "Rend le dossier d'un sinistre de demonstration",
    inputSchema: { type: "object", properties: { claim_id: { type: "string" } }, required: ["claim_id"] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "payments.create",
    description: "Cree un paiement de sinistre (ecriture)",
    inputSchema: { type: "object", properties: { claim_id: { type: "string" }, amount: { type: "string" }, currency: { type: "string" } }, required: ["claim_id", "amount", "currency"] },
  },
];

function principal() {
  const ecrire = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
  readline.createInterface({ input: process.stdin }).on("line", (ligne) => {
    let m;
    try {
      m = JSON.parse(ligne);
    } catch {
      return;
    }
    if (m.id === undefined || m.id === null) return;
    if (m.method === "initialize") {
      ecrire({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "outils-demo", version: "0.1.0" } } });
    } else if (m.method === "tools/list") {
      ecrire({ jsonrpc: "2.0", id: m.id, result: { tools: OUTILS } });
    } else if (m.method === "tools/call") {
      const a = m.params?.arguments ?? {};
      if (m.params?.name === "claims.get") {
        ecrire({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `Sinistre ${a.claim_id} : ouvert, 7400.00 CHF.` }], structuredContent: { claim_id: a.claim_id, statut: "ouvert" }, isError: false } });
      } else if (m.params?.name === "payments.create") {
        ecrire({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "Paiement cree." }], structuredContent: { payment_id: "PAY-2026-55555" }, isError: false } });
      } else {
        ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Unknown tool" } });
      }
    } else if (m.method === "ping") {
      ecrire({ jsonrpc: "2.0", id: m.id, result: {} });
    } else {
      ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) principal();
