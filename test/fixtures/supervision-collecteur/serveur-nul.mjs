#!/usr/bin/env node
// Serveur d'outils MCP nul des essais de la supervision en marche (CT-9
// TE-17, TM-34), transport stdio, une ligne JSON par message, ère moderne
// (`server/discover`, métadonnées par requête). Deux outils sans effet :
// `nul.lire` (lecture) et `nul.ecrire` (écriture) ; chacun rend un texte fixe.
// La liste des outils est annoncée valable 5 s (`ttlMs`), pour que le frontal
// la relise souvent et constate vite un serveur injoignable (CT-2 EX-4.18).
//
//   node serveur-nul.mjs [--etat <répertoire>]
//
// Avec --etat, le serveur relit ce répertoire toutes les 250 ms, pour que
// l'essai provoque deux conditions sans toucher au démon :
//   - fichier `panne` présent : le serveur s'arrête (code 4), et s'arrête
//     aussitôt à chaque relance tant que le fichier existe (serveur d'outils
//     injoignable, CT-2 EX-4.18) ;
//   - fichier `definition` : son contenu devient la description de `nul.lire`
//     et le serveur annonce `notifications/tools/list_changed` (définition
//     d'outil changée, CT-2 EX-4.16).
// Importé sans être lancé (le chargeur des essais lit tous les fichiers .mjs de
// test/), il ne fait rien.

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";

function servir(argv) {
  const k = argv.indexOf("--etat");
  const etat = k >= 0 ? argv[k + 1] : null;
  const fichier = (nom) => (etat ? path.join(etat, nom) : null);
  const lireDefinition = () => {
    try {
      return fs.readFileSync(fichier("definition"), "utf8").trim() || null;
    } catch {
      return null;
    }
  };
  if (etat && fs.existsSync(fichier("panne"))) process.exit(4);
  let definition = etat ? lireDefinition() : null;
  const outils = () => [
    { name: "nul.lire", description: definition ?? "Rend un texte fixe (lecture)", inputSchema: { type: "object", properties: { cle: { type: "string" } } }, annotations: { readOnlyHint: true } },
    { name: "nul.ecrire", description: "Rend un texte fixe (ecriture sans effet)", inputSchema: { type: "object", properties: { cle: { type: "string" } } }, annotations: { readOnlyHint: false } },
  ];
  const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\n");
  const resultat = (id, r) => ecrire({ jsonrpc: "2.0", id, result: { resultType: "complete", ...r } });
  if (etat) {
    setInterval(() => {
      if (fs.existsSync(fichier("panne"))) process.exit(4);
      const d = lireDefinition();
      if (d !== definition) {
        definition = d;
        ecrire({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
      }
    }, 250);
  }
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (ligne) => {
    let m;
    try {
      m = JSON.parse(ligne);
    } catch {
      return;
    }
    if (m.id === undefined) return;
    switch (m.method) {
      case "server/discover":
        return resultat(m.id, { supportedVersions: ["2026-07-28"], capabilities: { tools: { listChanged: true } }, serverInfo: { name: "outils-nuls", version: "1.0.0" } });
      case "subscriptions/listen":
        return;
      case "tools/list":
        return resultat(m.id, { tools: outils(), ttlMs: 5000, cacheScope: "private" });
      case "tools/call": {
        const nom = m.params?.name;
        if (nom === "nul.lire") return resultat(m.id, { content: [{ type: "text", text: "lu" }], isError: false });
        if (nom === "nul.ecrire") return resultat(m.id, { content: [{ type: "text", text: "ecrit" }], isError: false });
        return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: `Unknown tool: ${nom}` } });
      }
      default:
        return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
    }
  });
  rl.on("close", () => process.exit(0));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) servir(process.argv.slice(2));
