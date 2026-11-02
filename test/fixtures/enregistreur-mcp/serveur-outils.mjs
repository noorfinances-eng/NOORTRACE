#!/usr/bin/env node
// Serveur d'outils MCP de test, transport stdio (une ligne JSON par message).
// Ère moderne par défaut (`server/discover`, métadonnées par requête) ;
// `--herite` : ère héritée (`initialize`, `notifications/initialized`), et
// `server/discover` inconnu (-32601), pour la sonde d'EX-4.6.
//
// Outils : `claims.get` (lecture), `claims.search` (lecture, notifications de
// progression si la requête porte un progressToken), `payments.create`
// (écriture), `slow.op` (répond après `delay_ms`), `fail.rpc` (erreur
// JSON-RPC), `crash` (le processus se termine sans répondre).
// Importé sans être lancé (le chargeur des tests lit tous les fichiers .mjs
// de test/), il ne fait rien.

import readline from "node:readline";
import { pathToFileURL } from "node:url";

const herite = process.argv.includes("--herite");
const nom = herite ? "archives-test" : "outils-test";

const OUTILS = herite
  ? [{ name: "documents.get", description: "Rend une piece archivee", inputSchema: { type: "object", properties: { document_id: { type: "string" } }, required: ["document_id"] }, annotations: { readOnlyHint: true } }]
  : [
      { name: "claims.get", title: "Lire un sinistre", description: "Rend le dossier d'un sinistre de test", inputSchema: { type: "object", properties: { claim_id: { type: "string" } }, required: ["claim_id"] }, annotations: { readOnlyHint: true } },
      { name: "claims.search", description: "Recherche des sinistres de test", inputSchema: { type: "object", properties: { query: { type: "string" } } }, annotations: { readOnlyHint: true } },
      {
        name: "payments.create",
        description: "Cree un paiement de test (ecriture)",
        inputSchema: { type: "object", properties: { claim_id: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, beneficiary_iban: { type: "string" } } },
        annotations: { readOnlyHint: false },
      },
      { name: "slow.op", description: "Operation lente", inputSchema: { type: "object", properties: { delay_ms: { type: "number" } } }, annotations: { readOnlyHint: true } },
      { name: "fail.rpc", description: "Erreur de protocole", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
      { name: "crash", description: "Arret brutal", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
    ];

let paiements = 0;
const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const resultat = (id, r) => ecrire({ jsonrpc: "2.0", id, result: herite ? r : { resultType: "complete", ...r } });

function servir() {
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (ligne) => {
  let m;
  try {
    m = JSON.parse(ligne);
  } catch {
    return;
  }
  if (m.id === undefined) return;
  const p = m.params ?? {};
  switch (m.method) {
    case "server/discover":
      if (herite) return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
      return resultat(m.id, { supportedVersions: ["2026-07-28"], capabilities: { tools: { listChanged: true } }, serverInfo: { name: nom, version: "1.0.0" } });
    case "initialize":
      return ecrire({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: nom, version: "1.0.0" } } });
    case "subscriptions/listen":
      return;
    case "tools/list":
      return resultat(m.id, herite ? { tools: OUTILS } : { tools: OUTILS, ttlMs: 60000, cacheScope: "private" });
    case "tools/call": {
      const a = p.arguments ?? {};
      switch (p.name) {
        case "claims.get":
          return resultat(m.id, { content: [{ type: "text", text: `Sinistre ${a.claim_id} : ouvert` }], isError: false });
        case "claims.search": {
          const jeton = p._meta?.progressToken;
          if (jeton !== undefined) {
            for (const k of [1, 2]) ecrire({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: jeton, progress: k, total: 2 } });
          }
          return resultat(m.id, { content: [{ type: "text", text: `0 sinistre pour ${a.query}` }], isError: false });
        }
        case "payments.create":
          paiements++;
          return resultat(m.id, { content: [{ type: "text", text: `Paiement PAY-2026-${String(10000 + paiements)} cree` }], structuredContent: { payment_id: `PAY-2026-${String(10000 + paiements)}` }, isError: false });
        case "slow.op":
          setTimeout(() => resultat(m.id, { content: [{ type: "text", text: "fini" }], isError: false }), a.delay_ms ?? 1000);
          return;
        case "fail.rpc":
          return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "Invalid params: test", data: { field: "x" } } });
        case "crash":
          process.exit(3);
          return;
        case "documents.get":
          return resultat(m.id, { content: [{ type: "text", text: `${a.document_id} : constat` }], isError: false });
        default:
          return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: `Unknown tool: ${p.name}` } });
      }
    }
    default:
      return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
  }
});
rl.on("close", () => process.exit(0));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) servir();
