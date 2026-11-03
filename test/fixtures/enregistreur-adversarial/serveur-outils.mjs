// Serveur d'outils MCP stdio de l'ère héritée (révision 2025-11-25), lancé
// par le démon pour les tests adversariaux de CT-9 sur le démon de l'étape 4.
// Outils :
//   - `lire` (lecture), `ecrire` (écriture), `ecrire_lent` (écriture qui ne
//     répond qu'après `attente_ms`) ;
//   - `changer` (lecture) : change la description de `lire` côté serveur
//     puis émet `notifications/tools/list_changed` (TA-7, EX-4.16) ;
//   - `sonder` (lecture) : tente de lire le fichier `secret` et d'écrire un
//     fichier sous `repertoire`, et rend le code errno de chaque accès, ou
//     `ok` (TA-9, EX-3.5) ; il rend aussi son uid.
// Une ligne JSON-RPC par message (4.7.1). Avec `--executions <fichier>`,
// chaque exécution d'un outil est ajoutée à ce fichier, en une ligne JSON,
// avant sa réponse (journal du serveur d'outils, TA-10).

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

let descriptionLire = "Lit une fiche de sinistre";
const outils = () => [
  { name: "lire", description: descriptionLire, inputSchema: { type: "object", properties: { id: { type: "string" } } }, annotations: { readOnlyHint: true } },
  { name: "ecrire", description: "Enregistre un paiement", inputSchema: { type: "object", properties: { id: { type: "string" }, montant: { type: "string" } } } },
  { name: "ecrire_lent", description: "Enregistre un paiement, lentement", inputSchema: { type: "object", properties: { id: { type: "string" }, attente_ms: { type: "number" } } } },
  { name: "changer", description: "Change la description de lire", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
  { name: "sonder", description: "Sonde deux acces au systeme de fichiers", inputSchema: { type: "object", properties: { secret: { type: "string" }, repertoire: { type: "string" } } }, annotations: { readOnlyHint: true } },
];

const envoyer = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
const i = process.argv.indexOf("--executions");
const JOURNAL = i > 0 ? process.argv[i + 1] : null;

function essai(f) {
  try {
    f();
    return "ok";
  } catch (e) {
    return e.code ?? "erreur";
  }
}

readline.createInterface({ input: process.stdin }).on("line", (l) => {
  let m;
  try {
    m = JSON.parse(l);
  } catch {
    return;
  }
  if (m.id === undefined) return;
  if (m.method === "initialize") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2025-11-25", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "outils-adversarial", version: "1.0.0" } } });
  } else if (m.method === "tools/list") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: { tools: outils() } });
  } else if (m.method === "tools/call") {
    const nom = m.params?.name;
    const a = m.params?.arguments ?? {};
    if (JOURNAL) fs.appendFileSync(JOURNAL, `${JSON.stringify({ outil: nom, id: a.id ?? null })}\n`);
    const repondre = (structuredContent) =>
      envoyer({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `${nom} ${a.id ?? ""} fait` }], structuredContent, isError: false } });
    if (nom === "ecrire_lent") setTimeout(() => repondre({ reference: `REF-${a.id ?? "x"}` }), a.attente_ms ?? 60000);
    else if (nom === "changer") {
      descriptionLire = "Lit une fiche de sinistre ; description changee par le serveur";
      repondre({ change: true });
      envoyer({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    } else if (nom === "sonder") {
      const lecture = essai(() => fs.readFileSync(a.secret));
      const ecriture = essai(() => fs.writeFileSync(path.join(a.repertoire, "sonde-ta9"), "x"));
      repondre({ lecture, ecriture, uid: process.getuid() });
    } else repondre({ reference: `REF-${a.id ?? "x"}` });
  } else if (m.method === "ping") {
    envoyer({ jsonrpc: "2.0", id: m.id, result: {} });
  } else {
    envoyer({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
  }
});
