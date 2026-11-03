#!/usr/bin/env node
// Serveur d'outils MCP de test au contrat d'`outils-demo` de CT-2 §19.1
// (`claims.get`, `claims.search`, `payments.create`, données fictives), en
// transport stdio (une ligne JSON par message), qui rejoue les octets des
// vecteurs `spec/vecteurs/ct-2/pieces-mcp/appels` : sa liste d'outils est
// celle que les transcriptions servent (définitions d'origine, sans le
// préfixe d'alias), et la réponse à un `tools/call` est le résultat que le
// serveur de la transcription a rendu pour le même outil et les mêmes
// arguments ; une transcription close par une fin de fichier (`injoignable`)
// fait sortir le processus sans répondre (serveur coupé en cours d'appel).
//
//   node outils-demo.mjs --vecteurs <pieces-mcp/appels> [--alias demo|archives]
//
// `demo` parle l'ère 2026-07-28 (`server/discover`, métadonnées par requête),
// `archives` l'ère héritée (`initialize`), comme les serveurs des vecteurs.
// Importé sans être lancé (le chargeur des tests lit les fichiers .mjs de
// test/), il ne fait rien.

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";

const lireJsonl = (f) => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

/** Valeur JSON canonique simple (clés triées) pour comparer des arguments. */
function cle(v) {
  if (Array.isArray(v)) return `[${v.map(cle).join(",")}]`;
  if (v !== null && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${cle(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/**
 * Outils d'un alias et réponses rejouables, tirés de toutes les transcriptions.
 * @returns {{outils: object[], reponses: Map<string, object|null>}} réponse null : fin de fichier
 */
export function chargerVecteurs(repertoire, alias) {
  let outils = null;
  const reponses = new Map();
  for (const cas of fs.readdirSync(repertoire).sort()) {
    const d = path.join(repertoire, cas);
    if (!fs.existsSync(path.join(d, "amont.jsonl"))) continue;
    const hote = lireJsonl(path.join(d, "hote.jsonl"));
    for (const x of hote.filter((y) => y.dir === "out" && y.line)) {
      const m = JSON.parse(x.line);
      if (outils === null && Array.isArray(m.result?.tools) && m.result.tools.some((t) => t.name.startsWith(`${alias}__`))) {
        const noms = new Set(m.result.tools.map((t) => t.name));
        if (alias !== "demo" || noms.has("demo__claims.search")) {
          outils = m.result.tools.filter((t) => t.name.startsWith(`${alias}__`)).map((t) => ({ ...t, name: t.name.slice(alias.length + 2) }));
        }
      }
    }
    const amont = lireJsonl(path.join(d, "amont.jsonl"));
    for (let i = 0; i < amont.length; i++) {
      const x = amont[i];
      if (x.dir !== "out" || !x.line) continue;
      const m = JSON.parse(x.line);
      if (m.method !== "tools/call") continue;
      const suite = amont.slice(i + 1).find((y) => y.dir === "in" && (y.eof || (y.line && JSON.parse(y.line).id === m.id)));
      if (!suite) continue;
      const k = `${m.params.name}\u0000${cle(m.params.arguments ?? {})}`;
      if (!reponses.has(k)) reponses.set(k, suite.eof ? null : JSON.parse(suite.line));
    }
  }
  return { outils: outils ?? [], reponses };
}

function servir() {
  const arg = (n, d) => {
    const i = process.argv.indexOf(n);
    return i > 0 ? process.argv[i + 1] : d;
  };
  const alias = arg("--alias", "demo");
  const herite = alias === "archives";
  const { outils, reponses } = chargerVecteurs(arg("--vecteurs"), alias);
  const ecrire = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
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
        return ecrire({ jsonrpc: "2.0", id: m.id, result: { resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: { tools: { listChanged: true } }, serverInfo: { name: "outils-demo", version: "0.1.0" } } });
      case "initialize":
        return ecrire({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "archives-demo", version: "1.0.0" } } });
      case "subscriptions/listen":
        return undefined;
      case "tools/list":
        return ecrire({ jsonrpc: "2.0", id: m.id, result: herite ? { tools: outils } : { resultType: "complete", tools: outils, ttlMs: 300000, cacheScope: "private" } });
      case "tools/call": {
        const k = `${p.name}\u0000${cle(p.arguments ?? {})}`;
        if (!reponses.has(k)) return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: `Unknown call: ${p.name}` } });
        const r = reponses.get(k);
        if (r === null) process.exit(0);
        return ecrire({ ...r, id: m.id });
      }
      default:
        return ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
    }
  });
  rl.on("close", () => process.exit(0));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) servir();
