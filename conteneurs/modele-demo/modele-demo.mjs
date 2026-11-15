#!/usr/bin/env node
// Service `modele-demo` de la démonstration de référence (CT-2 §19.3,
// EX-19.2) : simulateur de l'API Messages. Il reproduit la forme documentée
// de `POST /v1/messages`, hors flux et en flux SSE, sans clé, d'après un
// scénario fixe. Ce n'est pas un modèle et il ne prétend pas l'être : il
// existe pour que la démonstration n'exige aucune clé. Sans dépendance.
//
//   modele-demo.mjs servir [--ecoute 0.0.0.0:8080]
//   modele-demo.mjs sonde  [--url http://127.0.0.1:8080/sante]
//
// `POST /v1/messages` : en-tête `x-api-key` ou `Authorization: Bearer`
// accepté sans vérification ; `anthropic-version` requis et recopié tel quel
// dans la réponse ; corps `model`, `max_tokens`, `messages`, `system`,
// `tools`, `stream`. Le scénario est choisi par le contenu du dernier message
// utilisateur : trois réponses fixes, aux identifiants `msg_…` et `toolu_…`
// fixes. Erreurs au format `{"type":"error","error":{"type","message"},"request_id"}`.
//
// `GET /demo/usage` (hors de l'API Messages) : nombre de requêtes
// `POST /v1/messages` reçues par clé et par route depuis le démarrage, la clé
// étant nommée par les 16 premiers chiffres du SHA-256 de sa valeur, jamais
// par sa valeur. C'est le relevé d'usage « clé par clé » qu'un fournisseur
// publie, que le rapprochement de CT-7 EX-3.8 compare au journal.

import fs from "node:fs";
import http from "node:http";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

export const MODELE = "modele-demo-1";

/**
 * Les trois réponses du scénario. `flux` : découpage du texte et du JSON
 * d'entrée en morceaux, et jetons de sortie annoncés par `message_start`,
 * fixes pour que les octets du flux soient reproductibles (vecteurs
 * `pieces-modele` et `journal-demo` de CT-2, annexe B).
 */
export const SCENARIO = Object.freeze([
  {
    nom: "ouverture",
    message: {
      id: "msg_demo_0001", type: "message", role: "assistant", model: MODELE,
      content: [
        { type: "text", text: "Je consulte le dossier du sinistre 2026-81044 avant de proposer un règlement." },
        { type: "tool_use", id: "toolu_demo_0001", name: "demo__claims_get", input: { claim_id: "2026-81044" } },
      ],
      stop_reason: "tool_use", stop_sequence: null, usage: { input_tokens: 512, output_tokens: 48 },
    },
    flux: { sortie_initiale: 2, morceaux: [["Je consulte le dossier du sinistre 2026-81044 ", "avant de proposer un règlement."], ['{"claim_id": "2026-81044"}']] },
  },
  {
    nom: "reglement",
    message: {
      id: "msg_demo_0002", type: "message", role: "assistant", model: MODELE,
      content: [
        { type: "text", text: "Le dossier est complet : je propose de régler 7400.00 CHF sur l'IBAN CH93 0076 2011 6238 5295 7 du bénéficiaire." },
        { type: "tool_use", id: "toolu_demo_0002", name: "demo__payments_create", input: { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" } },
      ],
      stop_reason: "tool_use", stop_sequence: null, usage: { input_tokens: 690, output_tokens: 97 },
    },
    flux: {
      sortie_initiale: 2,
      morceaux: [
        ["Le dossier est complet : je propose de régler 7400.00 CHF ", "sur l'IBAN CH93 0076 2011 6238 5295 7 du bénéficiaire."],
        ['{"claim_id": "2026-81044", "amount": "7400.00", ', '"currency": "CHF", "beneficiary_iban": "CH93 0076 2011 6238 5295 7"}'],
      ],
    },
  },
  {
    nom: "cloture",
    message: {
      id: "msg_demo_0003", type: "message", role: "assistant", model: MODELE,
      content: [{ type: "text", text: "Le paiement PAY-2026-90417 de 7400.00 CHF est créé ; le sinistre 2026-81044 est réglé." }],
      stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 830, output_tokens: 31 },
    },
    flux: { sortie_initiale: 2, morceaux: [["Le paiement PAY-2026-90417 de 7400.00 CHF est créé ; ", "le sinistre 2026-81044 est réglé."]] },
  },
]);

/**
 * Choisit la réponse d'après le dernier message utilisateur : un texte ouvre
 * le tour ; un `tool_result` de `toolu_demo_0001` appelle le règlement ; un
 * `tool_result` de `toolu_demo_0002` clôt le tour. Rend l'entrée du scénario,
 * ou null si le dernier message n'est aucun des trois.
 */
export function choisir(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return null;
  const dernier = messages[messages.length - 1];
  if (dernier === null || typeof dernier !== "object" || dernier.role !== "user") return null;
  if (typeof dernier.content === "string") return SCENARIO[0];
  if (!Array.isArray(dernier.content)) return null;
  const resultat = dernier.content.find((b) => b !== null && typeof b === "object" && b.type === "tool_result");
  if (!resultat) return dernier.content.some((b) => b !== null && typeof b === "object" && b.type === "text") ? SCENARIO[0] : null;
  if (resultat.tool_use_id === "toolu_demo_0001") return SCENARIO[1];
  if (resultat.tool_use_id === "toolu_demo_0002") return SCENARIO[2];
  return null;
}

/** Corps `text/event-stream` d'une réponse : la séquence documentée, un `ping` après le premier morceau de texte. */
export function corpsFlux(entree) {
  const m = entree.message;
  const evenements = [];
  const ev = (type, data) => evenements.push(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  ev("message_start", { type: "message_start", message: { ...m, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: m.usage.input_tokens, output_tokens: entree.flux.sortie_initiale } } });
  let pingEmis = false;
  m.content.forEach((bloc, index) => {
    const morceaux = entree.flux.morceaux[index];
    if (bloc.type === "text") {
      ev("content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } });
      morceaux.forEach((texte) => {
        ev("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: texte } });
        if (!pingEmis) {
          ev("ping", { type: "ping" });
          pingEmis = true;
        }
      });
    } else {
      ev("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: bloc.id, name: bloc.name, input: {} } });
      // Premier `partial_json` vide, comme le fournisseur l'émet.
      for (const partiel of ["", ...morceaux]) ev("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: partiel } });
    }
    ev("content_block_stop", { type: "content_block_stop", index });
  });
  ev("message_delta", { type: "message_delta", delta: { stop_reason: m.stop_reason, stop_sequence: m.stop_sequence }, usage: { output_tokens: m.usage.output_tokens } });
  ev("message_stop", { type: "message_stop" });
  return evenements;
}

/** Empreinte publique d'une clé présentée : 16 premiers chiffres hexadécimaux de son SHA-256. */
export const empreinteCle = (cle) => createHash("sha256").update(cle, "utf8").digest("hex").slice(0, 16);

export function creerServeur() {
  /** Compteurs par `<empreinte de clé> <route>`. */
  const usage = new Map();
  let requetes = 0;
  const serveur = http.createServer((req, rep) => {
    const chemin = (req.url ?? "").split("?")[0];
    const identifiant = `req_demo_${String(++requetes).padStart(6, "0")}`;
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
      // La clé est comptée, jamais vérifiée ni gardée (EX-19.2).
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
      const entree = choisir(corps.messages);
      if (entree === null) return erreur(400, "invalid_request_error", "le dernier message utilisateur n'appartient pas au scénario du simulateur", entetes);
      if (corps.stream === true) {
        rep.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "request-id": identifiant, ...entetes });
        for (const e of corpsFlux(entree)) rep.write(e);
        return rep.end();
      }
      return json(200, entree.message, entetes);
    });
  });
  return { serveur, usage };
}

function option(args, nom, defaut) {
  const i = args.indexOf(nom);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : defaut;
}

async function principal(args) {
  if (args[0] === "servir") {
    const [hote, port] = option(args, "--ecoute", "0.0.0.0:8080").split(":");
    const { serveur } = creerServeur();
    serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: "modele-demo", event: "ecoute", adresse: `${hote}:${port}`, modele: MODELE })}\n`));
    for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => serveur.close(() => process.exit(0)));
    return;
  }
  if (args[0] === "sonde") {
    try {
      const r = await fetch(option(args, "--url", "http://127.0.0.1:8080/sante"), { signal: AbortSignal.timeout(2500) });
      process.exit(r.status === 200 ? 0 : 1);
    } catch {
      process.exit(1);
    }
  }
  process.stderr.write("usage : modele-demo.mjs servir [--ecoute hôte:port] | sonde [--url <url>]\n");
  process.exit(2);
}

if (estProgramme(import.meta.url)) principal(process.argv.slice(2));
