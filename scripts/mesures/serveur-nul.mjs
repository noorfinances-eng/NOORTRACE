#!/usr/bin/env node
// Serveur d'outils nul du harnais de mesure de CT-2 EX-16.2 (pas 2) :
// Streamable HTTP, ère 2026-07-28 (`server/discover`, métadonnées par requête,
// aucune session), sans dépendance. Il répond à tout `tools/call` par un
// `result` fixe de la taille demandée, sans rien calculer : la réponse est
// préparée au démarrage, seul l'`id` de la requête et le numéro de l'appel y
// sont posés.
//
//   serveur-nul.mjs servir [--ecoute 127.0.0.1:8000] [--resultat-octets 16384]
//
// Un outil : `appeler`, qui accepte tout objet d'arguments. Le numéro de
// l'appel est lu dans `arguments.n` (entier) et recopié dans le résultat, pour
// que chaque résultat soit une pièce distincte, comme en production.
//
// Mesure (EX-16.2, pas 4 ; EX-16.1) : pour chaque `tools/call`, le serveur
// relève sur l'horloge monotone du système (`process.hrtime.bigint()`, la même
// pour tous les processus de la machine) l'instant où la requête est reçue en
// entier et l'instant où la réponse est remise au système. `GET /mesures`
// rend ces instants, en nanosecondes, dans l'ordre de réception :
// `{ "appels": n, "n": [...], "recu_ns": ["…"], "repondu_ns": ["…"] }` ;
// `POST /mesures/vider` les oublie. À son écoute, le serveur écrit sur la
// sortie standard une ligne `{"service":"serveur-nul","event":"ecoute","port":…}`.

import fs from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";

export const VERSION_PROTOCOLE = "2026-07-28";
export const OUTIL = Object.freeze({
  name: "appeler",
  title: "Outil nul",
  description: "Rend un résultat fixe de la taille demandée au démarrage du serveur",
  inputSchema: { type: "object", properties: { n: { type: "integer" }, charge: { type: "string" } }, required: ["n"] },
  annotations: { readOnlyHint: false, destructiveHint: false },
});

/** Texte de remplissage sans donnée personnelle ni motif que `pii-v1` rédige (ni chiffres, ni arobase). */
export function remplissage(octets) {
  const motif = "mesure de la latence ajoutee par appel relaye ; ";
  return motif.repeat(Math.ceil(octets / motif.length)).slice(0, Math.max(0, octets));
}

/**
 * Prépare la réponse d'un `tools/call` : rend `(id, n) → octets` dont la
 * longueur est `resultatOctets` pour un `id` et un `n` d'un chiffre (le corps
 * JSON-RPC entier compte : enveloppe, `result`, texte).
 */
export function preparerReponse(resultatOctets) {
  const gabarit = (texte) => ({ debut: `{"jsonrpc":"2.0","id":`, milieu: `,"result":{"resultType":"complete","content":[{"type":"text","text":"appel `, fin: ` ${texte}"}],"isError":false}}` });
  const vide = gabarit("");
  const fixe = Buffer.byteLength(vide.debut + "0" + vide.milieu + "0" + vide.fin);
  const g = gabarit(remplissage(Math.max(0, resultatOctets - fixe)));
  return (id, n) => Buffer.from(g.debut + JSON.stringify(id) + g.milieu + String(n) + g.fin, "utf8");
}

export function creerServeur({ resultatOctets = 16384 } = {}) {
  const reponse = preparerReponse(resultatOctets);
  const mesures = { n: [], recu: [], repondu: [] };
  const json = (rep, statut, objet) => {
    const corps = Buffer.from(JSON.stringify(objet), "utf8");
    rep.writeHead(statut, { "Content-Type": "application/json", "Content-Length": corps.length }).end(corps);
  };
  const serveur = http.createServer((req, rep) => {
    const chemin = (req.url ?? "").split("?")[0];
    if (chemin === "/mesures" && req.method === "GET") return json(rep, 200, { appels: mesures.n.length, n: mesures.n, recu_ns: mesures.recu.map(String), repondu_ns: mesures.repondu.map(String) });
    if (chemin === "/mesures/vider" && req.method === "POST") {
      mesures.n.length = mesures.recu.length = mesures.repondu.length = 0;
      return json(rep, 200, { ok: true });
    }
    if (chemin !== "/mcp") return json(rep, 404, { error: "not_found" });
    if (req.method !== "POST") return rep.writeHead(405, { Allow: "POST" }).end();
    const morceaux = [];
    req.on("data", (x) => morceaux.push(x));
    req.on("end", () => {
      const recu = process.hrtime.bigint();
      let m;
      try {
        m = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        return json(rep, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      }
      if (m === null || typeof m !== "object" || m.jsonrpc !== "2.0" || typeof m.method !== "string") return json(rep, 400, { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
      if (m.id === undefined) return rep.writeHead(202).end();
      if (m.method === "tools/call") {
        const n = Number.isInteger(m.params?.arguments?.n) ? m.params.arguments.n : -1;
        const corps = reponse(m.id, n);
        rep.writeHead(200, { "Content-Type": "application/json", "Content-Length": corps.length }).end(corps);
        mesures.n.push(n);
        mesures.recu.push(recu);
        mesures.repondu.push(process.hrtime.bigint());
        return undefined;
      }
      const resultat = (r) => json(rep, 200, { jsonrpc: "2.0", id: m.id, result: { resultType: "complete", ...r } });
      if (m.method === "server/discover") return resultat({ supportedVersions: [VERSION_PROTOCOLE], capabilities: { tools: { listChanged: false } }, serverInfo: { name: "serveur-nul", version: "0.1.0" } });
      if (m.method === "tools/list") return resultat({ tools: [OUTIL], ttlMs: 300000, cacheScope: "private" });
      if (m.method === "ping") return resultat({});
      return json(rep, 200, { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
    });
  });
  serveur.keepAliveTimeout = 0;
  return { serveur, mesures };
}

export function option(args, nom, defaut) {
  const i = args.indexOf(nom);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : defaut;
}

function principal(args) {
  if (args[0] !== "servir") {
    process.stderr.write("usage : serveur-nul.mjs servir [--ecoute hôte:port] [--resultat-octets n]\n");
    process.exit(2);
  }
  const [hote, port] = option(args, "--ecoute", "127.0.0.1:8000").split(":");
  const resultatOctets = Number(option(args, "--resultat-octets", "16384"));
  if (!Number.isInteger(resultatOctets) || resultatOctets < 0 || resultatOctets > 16777216) {
    process.stderr.write("--resultat-octets : entier de 0 à 16777216 attendu\n");
    process.exit(2);
  }
  const { serveur } = creerServeur({ resultatOctets });
  serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: "serveur-nul", event: "ecoute", hote, port: serveur.address().port, protocole: VERSION_PROTOCOLE, resultat_octets: resultatOctets })}\n`));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => {
    serveur.close(() => process.exit(0));
    serveur.closeAllConnections();
  });
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) principal(process.argv.slice(2));
