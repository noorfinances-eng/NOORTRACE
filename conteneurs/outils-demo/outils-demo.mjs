#!/usr/bin/env node
// Service `outils-demo` de la démonstration de référence (CT-2 §19.1) : serveur
// d'outils MCP en Streamable HTTP, ère 2026-07-28 (`server/discover`,
// métadonnées par requête, aucune session), sans dépendance.
//
//   outils-demo.mjs servir [--ecoute 0.0.0.0:8000]
//   outils-demo.mjs sonde  [--url http://127.0.0.1:8000/sante]
//
// Trois outils : `claims.get` (lecture), `claims.search` (lecture),
// `payments.create` (écriture). Données fictives en mémoire : un sinistre de
// l'assureur de démonstration, un assuré au nom visiblement fictif, une
// adresse du domaine réservé `.example`. Le serveur ne joint rien.
//
// `GET /sante` rend `{ "ok": true, "appels": n }` : `n` compte les
// `tools/call` reçus depuis le démarrage, d'où qu'ils viennent. La
// démonstration s'en sert pour montrer que l'agent n'a joint ce serveur que
// par l'enregistreur.

import fs from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

export const VERSION_PROTOCOLE = "2026-07-28";

/** Définitions d'origine des outils (l'enregistreur les annonce sous l'alias `demo__`). */
export const OUTILS = Object.freeze([
  {
    name: "claims.get",
    title: "Lire un sinistre",
    description: "Rend le dossier d'un sinistre de démonstration",
    inputSchema: { type: "object", properties: { claim_id: { type: "string" } }, required: ["claim_id"], additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "claims.search",
    title: "Rechercher des sinistres",
    description: "Recherche des sinistres de démonstration par texte libre",
    inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "payments.create",
    title: "Créer un paiement",
    description: "Crée un paiement de sinistre (écriture)",
    inputSchema: {
      type: "object",
      properties: { claim_id: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, beneficiary_iban: { type: "string" } },
      required: ["claim_id", "amount", "currency", "beneficiary_iban"],
      additionalProperties: false,
    },
    outputSchema: { type: "object", properties: { payment_id: { type: "string" } }, required: ["payment_id"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
]);

/** Sinistres fictifs de l'assureur de démonstration. */
export const SINISTRES = Object.freeze({
  "2026-81044": "collision du 2026-11-02, dommages 7400.00 CHF, assuré joignable à j.dupont@assure.example ou au +41 44 123 45 67",
});

/** Résultat d'un `tools/call`, ou `{ erreur }` JSON-RPC. `etat.paiements` numérote les paiements créés. */
export function appelerOutil(nom, args, etat) {
  const a = args !== null && typeof args === "object" && !Array.isArray(args) ? args : {};
  const texte = (t, extra = {}) => ({ content: [{ type: "text", text: t }], ...extra, isError: false });
  switch (nom) {
    case "claims.get": {
      const dossier = SINISTRES[a.claim_id];
      if (dossier === undefined) return { content: [{ type: "text", text: `Sinistre ${String(a.claim_id)} inconnu` }], isError: true };
      return texte(`Sinistre ${a.claim_id} : ${dossier}`);
    }
    case "claims.search": {
      const q = typeof a.query === "string" ? a.query : "";
      const trouves = Object.keys(SINISTRES).filter((k) => q !== "" && (k.includes(q) || SINISTRES[k].includes(q)));
      return texte(`${trouves.length} sinistre(s) pour « ${q} »${trouves.length ? ` : ${trouves.join(", ")}` : ""}`);
    }
    case "payments.create": {
      if (SINISTRES[a.claim_id] === undefined) return { content: [{ type: "text", text: `Sinistre ${String(a.claim_id)} inconnu : aucun paiement créé` }], isError: true };
      const id = `PAY-2026-${90417 + etat.paiements}`;
      etat.paiements += 1;
      return texte(`Paiement ${id} créé pour le sinistre ${a.claim_id}`, { structuredContent: { payment_id: id } });
    }
    default:
      return { erreur: { code: -32602, message: `Unknown tool: ${String(nom)}` } };
  }
}

/** Réponse JSON-RPC d'un message (null pour une notification). */
export function repondre(m, etat) {
  if (m === null || typeof m !== "object" || Array.isArray(m) || m.jsonrpc !== "2.0" || typeof m.method !== "string") return { jsonrpc: "2.0", id: m?.id ?? null, error: { code: -32600, message: "Invalid Request" } };
  if (m.id === undefined) return null;
  const resultat = (r) => ({ jsonrpc: "2.0", id: m.id, result: { resultType: "complete", ...r } });
  switch (m.method) {
    case "server/discover":
      return resultat({ supportedVersions: [VERSION_PROTOCOLE], capabilities: { tools: { listChanged: false } }, serverInfo: { name: "outils-demo", version: "0.1.0" } });
    case "tools/list":
      return resultat({ tools: OUTILS, ttlMs: 300000, cacheScope: "private" });
    case "tools/call": {
      etat.appels += 1;
      const r = appelerOutil(m.params?.name, m.params?.arguments, etat);
      return r.erreur ? { jsonrpc: "2.0", id: m.id, error: r.erreur } : resultat(r);
    }
    case "ping":
      return resultat({});
    default:
      return { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } };
  }
}

export function creerServeur() {
  const etat = { appels: 0, paiements: 0 };
  const serveur = http.createServer((req, rep) => {
    const chemin = (req.url ?? "").split("?")[0];
    const json = (statut, objet, entetes = {}) => {
      const corps = JSON.stringify(objet);
      rep.writeHead(statut, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(corps), ...entetes }).end(corps);
    };
    if (chemin === "/sante" && req.method === "GET") return json(200, { ok: true, appels: etat.appels });
    if (chemin !== "/mcp") return json(404, { error: "not_found" });
    if (req.method !== "POST") return rep.writeHead(405, { Allow: "POST" }).end();
    const morceaux = [];
    let taille = 0;
    req.on("data", (x) => {
      taille += x.length;
      if (taille > 1048576) req.destroy();
      else morceaux.push(x);
    });
    req.on("end", () => {
      let m;
      try {
        m = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        return json(400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      }
      const r = repondre(m, etat);
      if (r === null) return rep.writeHead(202).end();
      return json(200, r);
    });
  });
  return { serveur, etat };
}

function option(args, nom, defaut) {
  const i = args.indexOf(nom);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : defaut;
}

async function principal(args) {
  if (args[0] === "servir") {
    const [hote, port] = option(args, "--ecoute", "0.0.0.0:8000").split(":");
    const { serveur } = creerServeur();
    serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: "outils-demo", event: "ecoute", adresse: `${hote}:${port}`, protocole: VERSION_PROTOCOLE })}\n`));
    for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => serveur.close(() => process.exit(0)));
    return;
  }
  if (args[0] === "sonde") {
    try {
      const r = await fetch(option(args, "--url", "http://127.0.0.1:8000/sante"), { signal: AbortSignal.timeout(2500) });
      process.exit(r.status === 200 ? 0 : 1);
    } catch {
      process.exit(1);
    }
  }
  process.stderr.write("usage : outils-demo.mjs servir [--ecoute hôte:port] | sonde [--url <url>]\n");
  process.exit(2);
}

if (estProgramme(import.meta.url)) principal(process.argv.slice(2));
