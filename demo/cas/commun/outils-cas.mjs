#!/usr/bin/env node
// Serveur d'outils MCP des cas de démonstration (CT-9 TE-1, TE-2) : la même
// forme que `conteneurs/outils-demo/outils-demo.mjs` (Streamable HTTP, ère
// 2026-07-28, `server/discover`, aucune session), dont il tourne dans l'image,
// mais les outils et les enregistrements sont lus dans un catalogue JSON
// propre au cas (`OUTILS_CAS_CATALOGUE`, `demo/cas/<cas>/outils.json`).
//
//   outils-cas.mjs servir [--ecoute 0.0.0.0:8000]
//
// Catalogue : `{ service, outils: [...], enregistrements: { <id>: { texte, …champs } } }`.
// Chaque outil porte sa définition MCP (`name`, `title`, `description`,
// `inputSchema`, `outputSchema`, `annotations`) et sa conduite :
//   - `lecture_par_id` : rend le champ `champ` (défaut `texte`) de
//     l'enregistrement désigné par l'argument `id_field` ;
//   - `recherche` : rend les identifiants dont le texte contient `query` ;
//   - `ecriture` : exige l'enregistrement désigné par `id_field`, numérote
//     une écriture (`prefixe`, `compteur_depart`) et la rend dans
//     `structuredContent[cle_resultat]`.
// Données fictives seulement : pseudonymes, domaines `.example`, aucune
// valeur monétaire, aucune devise. Le serveur ne joint rien. `GET /sante` rend
// `{ ok, appels }` comme le serveur de la démonstration de référence.

import fs from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";

export const VERSION_PROTOCOLE = "2026-07-28";

function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

/** Charge et contrôle le catalogue : conduites connues, champs présents. */
export function chargerCatalogue(chemin) {
  const c = JSON.parse(fs.readFileSync(chemin, "utf8"));
  if (typeof c.service !== "string" || !Array.isArray(c.outils) || c.enregistrements === null || typeof c.enregistrements !== "object") throw new Error("catalogue : service, outils et enregistrements attendus");
  for (const o of c.outils) {
    if (!["lecture_par_id", "recherche", "ecriture"].includes(o.kind)) throw new Error(`catalogue : conduite inconnue ${o.kind} (${o.name})`);
    if (o.kind !== "recherche" && typeof o.id_field !== "string") throw new Error(`catalogue : id_field manquant (${o.name})`);
    if (o.kind === "ecriture" && (typeof o.prefixe !== "string" || !Number.isInteger(o.compteur_depart) || typeof o.cle_resultat !== "string")) throw new Error(`catalogue : écriture incomplète (${o.name})`);
  }
  return c;
}

/** Définitions MCP annoncées (sans les membres de conduite). */
export function definitions(catalogue) {
  return catalogue.outils.map(({ kind, id_field, champ, prefixe, compteur_depart, cle_resultat, ...definition }) => definition);
}

/** Résultat d'un `tools/call`, ou `{ erreur }` JSON-RPC. `etat.ecritures` numérote les écritures par outil. */
export function appelerOutil(catalogue, nom, args, etat) {
  const outil = catalogue.outils.find((o) => o.name === nom);
  if (!outil) return { erreur: { code: -32602, message: `Unknown tool: ${String(nom)}` } };
  const a = args !== null && typeof args === "object" && !Array.isArray(args) ? args : {};
  const texte = (t, extra = {}) => ({ content: [{ type: "text", text: t }], ...extra, isError: false });
  const erreur = (t) => ({ content: [{ type: "text", text: t }], isError: true });
  if (outil.kind === "recherche") {
    const q = typeof a.query === "string" ? a.query : "";
    const trouves = Object.keys(catalogue.enregistrements).filter((k) => q !== "" && (k.includes(q) || String(catalogue.enregistrements[k].texte).includes(q)));
    return texte(`${trouves.length} dossier(s) pour « ${q} »${trouves.length ? ` : ${trouves.join(", ")}` : ""}`);
  }
  const id = a[outil.id_field];
  const enregistrement = typeof id === "string" ? catalogue.enregistrements[id] : undefined;
  if (enregistrement === undefined) return erreur(`${outil.id_field} ${String(id)} inconnu`);
  if (outil.kind === "lecture_par_id") return texte(`${id} : ${enregistrement[outil.champ ?? "texte"]}`);
  const n = (etat.ecritures.get(outil.name) ?? outil.compteur_depart);
  etat.ecritures.set(outil.name, n + 1);
  const identifiant = `${outil.prefixe}${n}`;
  const detail = Object.entries(a).filter(([k]) => k !== outil.id_field).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(", ");
  return texte(`${identifiant} enregistré pour ${id} (${detail})`, { structuredContent: { [outil.cle_resultat]: identifiant } });
}

/** Réponse JSON-RPC d'un message (null pour une notification). */
export function repondre(catalogue, m, etat) {
  if (m === null || typeof m !== "object" || Array.isArray(m) || m.jsonrpc !== "2.0" || typeof m.method !== "string") return { jsonrpc: "2.0", id: m?.id ?? null, error: { code: -32600, message: "Invalid Request" } };
  if (m.id === undefined) return null;
  const resultat = (r) => ({ jsonrpc: "2.0", id: m.id, result: { resultType: "complete", ...r } });
  switch (m.method) {
    case "server/discover":
      return resultat({ supportedVersions: [VERSION_PROTOCOLE], capabilities: { tools: { listChanged: false } }, serverInfo: { name: catalogue.service, version: "0.1.0" } });
    case "tools/list":
      return resultat({ tools: definitions(catalogue), ttlMs: 300000, cacheScope: "private" });
    case "tools/call": {
      etat.appels += 1;
      const r = appelerOutil(catalogue, m.params?.name, m.params?.arguments, etat);
      return r.erreur ? { jsonrpc: "2.0", id: m.id, error: r.erreur } : resultat(r);
    }
    case "ping":
      return resultat({});
    default:
      return { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } };
  }
}

export function creerServeur(catalogue) {
  const etat = { appels: 0, ecritures: new Map() };
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
      const r = repondre(catalogue, m, etat);
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

if (estProgramme(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args[0] !== "servir") {
    process.stderr.write("usage : outils-cas.mjs servir [--ecoute hôte:port] (catalogue : OUTILS_CAS_CATALOGUE)\n");
    process.exit(2);
  }
  const catalogue = chargerCatalogue(process.env.OUTILS_CAS_CATALOGUE ?? "/etc/noortrace-demo/outils.json");
  const [hote, port] = option(args, "--ecoute", "0.0.0.0:8000").split(":");
  const { serveur } = creerServeur(catalogue);
  serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: catalogue.service, event: "ecoute", adresse: `${hote}:${port}`, protocole: VERSION_PROTOCOLE, outils: catalogue.outils.map((o) => o.name) })}\n`));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => serveur.close(() => process.exit(0)));
}
