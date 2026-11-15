#!/usr/bin/env node
// Simulateur de l'API Messages des cas de démonstration (CT-9 TE-1, TE-2) :
// la même forme que `conteneurs/modele-demo/modele-demo.mjs` (CT-2 §19.3,
// EX-19.2), dont il tourne dans l'image et dont il reprend le flux SSE
// (`corpsFlux`), mais le scénario est lu dans un fichier JSON propre au cas
// (`MODELE_CAS_SCENARIO`, `demo/cas/<cas>/modele.json`). Ce n'est pas un
// modèle : il rend des réponses fixes, choisies par le dernier message
// utilisateur (un texte ouvre le tour ; un `tool_result` est reconnu par son
// `tool_use_id`).
//
//   modele-cas.mjs servir [--ecoute 0.0.0.0:8080]
//
// Scénario : `{ modele, etapes: [ { quand: "texte" | "<tool_use_id>", id, texte,
// outil: { id, name, input } | null, usage: { input_tokens, output_tokens } } ] }`.
// Une étape sans `outil` clôt le tour (`end_turn`).

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

/** Le programme de la démonstration voisin dans l'image (/opt/noortrace-demo), ou dans le dépôt (conteneurs/) pour les essais. */
const ICI = path.dirname(fileURLToPath(import.meta.url));
const { corpsFlux } = await import(fs.existsSync(path.join(ICI, "modele-demo.mjs")) ? "./modele-demo.mjs" : "../../../conteneurs/modele-demo/modele-demo.mjs");

function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

export const empreinteCle = (cle) => createHash("sha256").update(cle, "utf8").digest("hex").slice(0, 16);

/** Coupe un texte en deux morceaux à l'espace le plus proche du milieu (morceaux du flux SSE). */
export function couper(texte) {
  const k = texte.indexOf(" ", Math.floor(texte.length / 2));
  return k > 0 && k < texte.length - 1 ? [texte.slice(0, k + 1), texte.slice(k + 1)] : [texte];
}

/** Entrée du scénario sous la forme qu'attend `corpsFlux` : `{ message, flux }`. */
export function entree(scenario, etape) {
  const content = [{ type: "text", text: etape.texte }];
  const morceaux = [couper(etape.texte)];
  if (etape.outil) {
    content.push({ type: "tool_use", id: etape.outil.id, name: etape.outil.name, input: etape.outil.input });
    morceaux.push(couper(JSON.stringify(etape.outil.input)));
  }
  const usage = etape.usage ?? { input_tokens: 512, output_tokens: 64 };
  return {
    nom: etape.quand,
    message: { id: etape.id, type: "message", role: "assistant", model: scenario.modele, content, stop_reason: etape.outil ? "tool_use" : "end_turn", stop_sequence: null, usage },
    flux: { sortie_initiale: 2, morceaux },
  };
}

/** Choisit l'étape d'après le dernier message utilisateur, ou null. */
export function choisir(scenario, messages) {
  if (!Array.isArray(messages) || messages.length === 0) return null;
  const dernier = messages[messages.length - 1];
  if (dernier === null || typeof dernier !== "object" || dernier.role !== "user") return null;
  const parQuand = (q) => scenario.etapes.find((e) => e.quand === q) ?? null;
  if (typeof dernier.content === "string") return parQuand("texte");
  if (!Array.isArray(dernier.content)) return null;
  const resultat = dernier.content.find((b) => b !== null && typeof b === "object" && b.type === "tool_result");
  if (!resultat) return dernier.content.some((b) => b !== null && typeof b === "object" && b.type === "text") ? parQuand("texte") : null;
  return parQuand(resultat.tool_use_id);
}

export function creerServeur(scenario) {
  const usage = new Map();
  let requetes = 0;
  const serveur = http.createServer((req, rep) => {
    const chemin = (req.url ?? "").split("?")[0];
    const identifiant = `req_cas_${String(++requetes).padStart(6, "0")}`;
    const json = (statut, objet, entetes = {}) => {
      const corps = JSON.stringify(objet);
      rep.writeHead(statut, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(corps), "request-id": identifiant, ...entetes }).end(corps);
    };
    const erreur = (statut, type, message, entetes) => json(statut, { type: "error", error: { type, message }, request_id: identifiant }, entetes);
    if (chemin === "/sante" && req.method === "GET") return json(200, { ok: true });
    if (chemin === "/demo/usage" && req.method === "GET") {
      const lignes = [...usage.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, n]) => ({ key_sha256_16: k.split(" ")[0], route: k.split(" ")[1], requests: n }));
      return json(200, { version: 0, usage: lignes });
    }
    if (chemin !== "/v1/messages") return erreur(404, "not_found_error", "route inconnue du simulateur");
    if (req.method !== "POST") return erreur(405, "invalid_request_error", "POST attendu", { Allow: "POST" });
    const morceaux = [];
    let taille = 0;
    req.on("data", (x) => {
      taille += x.length;
      if (taille > 33554432) req.destroy();
      else morceaux.push(x);
    });
    req.on("end", () => {
      const porteur = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
      const cle = req.headers["x-api-key"] ?? (porteur ? porteur[1] : "");
      const k = `${empreinteCle(String(cle))} /v1/messages`;
      usage.set(k, (usage.get(k) ?? 0) + 1);
      const version = req.headers["anthropic-version"];
      if (typeof version !== "string" || version === "") return erreur(400, "invalid_request_error", "anthropic-version: header is required");
      const entetes = { "anthropic-version": version };
      let corps;
      try {
        corps = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        return erreur(400, "invalid_request_error", "corps JSON illisible", entetes);
      }
      if (corps === null || typeof corps !== "object" || Array.isArray(corps) || !Array.isArray(corps.messages)) return erreur(400, "invalid_request_error", "messages: Field required", entetes);
      const etape = choisir(scenario, corps.messages);
      if (etape === null) return erreur(400, "invalid_request_error", "le dernier message utilisateur n'appartient pas au scénario du simulateur", entetes);
      const e = entree(scenario, etape);
      if (corps.stream === true) {
        rep.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "request-id": identifiant, ...entetes });
        for (const x of corpsFlux(e)) rep.write(x);
        return rep.end();
      }
      return json(200, e.message, entetes);
    });
  });
  return { serveur, usage };
}

function option(args, nom, defaut) {
  const i = args.indexOf(nom);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : defaut;
}

if (estProgramme(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args[0] !== "servir") {
    process.stderr.write("usage : modele-cas.mjs servir [--ecoute hôte:port] (scénario : MODELE_CAS_SCENARIO)\n");
    process.exit(2);
  }
  const scenario = JSON.parse(fs.readFileSync(process.env.MODELE_CAS_SCENARIO ?? "/etc/noortrace-demo/modele.json", "utf8"));
  const [hote, port] = option(args, "--ecoute", "0.0.0.0:8080").split(":");
  const { serveur } = creerServeur(scenario);
  serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: "modele-cas", event: "ecoute", adresse: `${hote}:${port}`, modele: scenario.modele, etapes: scenario.etapes.length })}\n`));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => serveur.close(() => process.exit(0)));
}
