// Simulateur de fournisseur de modèle pour les scénarios d'intégration de
// CT-9 TI-5, TI-6, TI-7 à TI-10 : il rejoue le scénario de CT-2 §19.2 (le
// même que `modele-demo`, simulateur de l'API Messages de §19.3) dans les
// trois autres formats de la version 0 (CT-2 5.2) : Chat Completions
// (`/v1/chat/completions`), Responses (`/v1/responses`) et Gemini
// (`/v1beta/models/<modèle>:generateContent`, `:streamGenerateContent?alt=sse`),
// hors flux et en flux, d'après la forme documentée de chaque format telle que
// `test/fixtures/enregistreur-modele/fournisseur.mjs` la reproduit.
//
// Le scénario est choisi par l'état de la conversation reçue : aucun résultat
// d'outil → appel de `claims.get` ; un résultat → appel de `payments.create`
// (IBAN fictif dans les arguments, rédigé par la passerelle) ; deux résultats
// → texte de clôture. Les noms des deux outils sont lus dans les déclarations
// d'outils de la requête (chaque cadre présente les outils MCP du frontal sous
// son propre nom, annoncé ou assaini) ; à défaut, les noms assainis de
// `modele-demo`. Deux compléments pour les cadres qui mènent eux-mêmes la
// boucle d'agent : un résultat d'outil qui est le signal d'approbation
// `en_attente` (CT-2 EX-4.49) fait redemander le même appel après une pause,
// comme la conduite de CT-3 EX-11.9 le demande à un agent ; et un outil local
// `…calculer_franchise`, s'il est déclaré, est appelé entre la lecture et
// l'écriture (outil local d'un cadre, déclaré par l'adaptateur de CT-2 6.6).
// Comme `modele-demo`, le simulateur n'est pas un modèle, ne vérifie aucune
// clé et compte les requêtes par empreinte de clé (`GET /demo/usage`).

import http from "node:http";
import { createHash } from "node:crypto";

export const MODELE = "modele-demo-1";
export const TEXTES = Object.freeze({
  lecture: "Je consulte le dossier du sinistre 2026-81044 avant de proposer un règlement.",
  local: "Je calcule la franchise applicable au sinistre 2026-81044.",
  ecriture: "Le dossier est complet : je propose de régler 7400.00 CHF sur l'IBAN CH93 0076 2011 6238 5295 7 du bénéficiaire.",
  fin: "Le paiement PAY-2026-90417 de 7400.00 CHF est créé ; le sinistre 2026-81044 est réglé.",
});
export const ARGUMENTS = Object.freeze({
  lecture: Object.freeze({ claim_id: "2026-81044" }),
  local: Object.freeze({ claim_id: "2026-81044", amount: "7400.00" }),
  ecriture: Object.freeze({ claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" }),
});
const MOTIFS = Object.freeze({ lecture: /claims[._]get$/, local: /calculer_franchise$/, ecriture: /payments[._]create$/ });
const DEFAUTS = Object.freeze({ lecture: "demo__claims_get", local: "calculer_franchise", ecriture: "demo__payments_create" });
/** Texte du signal d'approbation rendu au modèle par le frontal (CT-2 EX-4.49). */
export const SIGNAL_EN_ATTENTE = /noortrace: appel soumis a approbation ; ticket=\S+ ; state=en_attente/;
/** Pause avant de redemander un appel soumis à approbation (le temps que l'approbateur décide). */
export const PAUSE_REEMISSION_MS = 400;

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const sse = (evenement, data) => `${evenement ? `event: ${evenement}\n` : ""}data: ${typeof data === "string" ? data : JSON.stringify(data)}\n\n`;
export const empreinteCle = (cle) => createHash("sha256").update(String(cle), "utf8").digest("hex").slice(0, 16);

/** Format d'un chemin, ou null. */
export function formatDuChemin(chemin) {
  if (/\/v1\/chat\/completions$/.test(chemin)) return "openai-chat";
  if (/\/v1\/responses$/.test(chemin)) return "openai-responses";
  if (/\/models\/[^/]+:(stream)?[gG]enerateContent$/.test(chemin)) return "gemini";
  return null;
}

/** Noms des outils déclarés par la requête, par format. */
export function nomsDeclares(format, corps) {
  const outils = Array.isArray(corps?.tools) ? corps.tools : [];
  if (format === "gemini") return outils.flatMap((t) => (Array.isArray(t?.functionDeclarations) ? t.functionDeclarations.map((d) => d?.name) : [])).filter((n) => typeof n === "string");
  if (format === "openai-responses") return outils.map((t) => t?.name ?? t?.function?.name).filter((n) => typeof n === "string");
  return outils.map((t) => t?.function?.name ?? t?.name).filter((n) => typeof n === "string");
}

/** Nom sous lequel le modèle demande l'outil d'une étape (`lecture`, `local`, `ecriture`). */
export function nomOutil(format, corps, etape) {
  return nomsDeclares(format, corps).find((n) => MOTIFS[etape].test(n)) ?? DEFAUTS[etape];
}

const texteDe = (v) => (typeof v === "string" ? v : JSON.stringify(v ?? null));

/** Textes des résultats d'outil de la conversation, dans l'ordre. */
export function resultats(format, corps) {
  if (format === "openai-chat") return (Array.isArray(corps?.messages) ? corps.messages : []).filter((m) => m?.role === "tool").map((m) => texteDe(m.content));
  if (format === "openai-responses") return (Array.isArray(corps?.input) ? corps.input : []).filter((m) => m?.type === "function_call_output").map((m) => texteDe(m.output));
  return (Array.isArray(corps?.contents) ? corps.contents : []).flatMap((c) => (Array.isArray(c?.parts) ? c.parts : [])).filter((p) => p && typeof p === "object" && "functionResponse" in p).map((p) => texteDe(p.functionResponse?.response));
}

/**
 * Étape du scénario pour une requête : `{ etape, reemission }`, où `etape`
 * est `lecture`, `local` (si l'outil local est déclaré), `ecriture` ou `fin`,
 * et `reemission` vrai quand le dernier résultat est le signal `en_attente`
 * (le même appel est redemandé).
 */
export function plan(format, corps) {
  const r = resultats(format, corps);
  const dernier = r.at(-1);
  const reemission = dernier !== undefined && SIGNAL_EN_ATTENTE.test(dernier);
  const reels = r.filter((t) => !SIGNAL_EN_ATTENTE.test(t)).length;
  const etapes = nomsDeclares(format, corps).some((n) => MOTIFS.local.test(n)) ? ["lecture", "local", "ecriture", "fin"] : ["lecture", "ecriture", "fin"];
  return { etape: etapes[Math.min(reels, etapes.length - 1)], reemission };
}

/** Nombre de résultats d'outil réels (hors signaux) : l'état du scénario, pour les relevés. */
export const etat = (format, corps) => resultats(format, corps).filter((t) => !SIGNAL_EN_ATTENTE.test(t)).length;

/** Contenu de la réponse à une requête ; les identifiants portent le numéro de la requête `n` (un modèle réel n'en répète jamais un). */
function contenu(format, corps, n) {
  const { etape } = plan(format, corps);
  const fin = etape === "fin";
  return { etape, fin, texte: TEXTES[etape], nom: fin ? null : nomOutil(format, corps, etape), args: fin ? null : { ...ARGUMENTS[etape] }, id: `demo_${etape}_${String(n).padStart(4, "0")}` };
}

/** Réponse hors flux. `n` : numéro de la requête. */
export function reponseEntiere(format, corps, n) {
  const { fin, texte, nom, args, id } = contenu(format, corps, n);
  const modele = corps?.model ?? MODELE;
  const usage = { entree: 512 + 100 * etat(format, corps), sortie: 48 };
  if (format === "openai-chat") {
    const message = fin ? { role: "assistant", content: texte } : { role: "assistant", content: texte, tool_calls: [{ id: `call_${id}`, type: "function", function: { name: nom, arguments: JSON.stringify(args) } }] };
    return { id: `chatcmpl-${id}`, object: "chat.completion", created: 1794306000, model: modele, choices: [{ index: 0, message, logprobs: null, finish_reason: fin ? "stop" : "tool_calls" }], usage: { prompt_tokens: usage.entree, completion_tokens: usage.sortie, total_tokens: usage.entree + usage.sortie } };
  }
  if (format === "openai-responses") {
    const output = [{ type: "message", id: `msg_${id}`, status: "completed", role: "assistant", content: [{ type: "output_text", text: texte, annotations: [] }] }];
    if (!fin) output.push({ type: "function_call", id: `fc_${id}`, call_id: `call_${id}`, name: nom, arguments: JSON.stringify(args), status: "completed" });
    return { id: `resp_${id}`, object: "response", created_at: 1794306000, status: "completed", model: modele, output, usage: { input_tokens: usage.entree, output_tokens: usage.sortie, total_tokens: usage.entree + usage.sortie } };
  }
  const parts = [{ text: texte }];
  if (!fin) parts.push({ functionCall: { name: nom, args } });
  return {
    candidates: [{ content: { parts, role: "model" }, finishReason: "STOP", index: 0 }],
    usageMetadata: { promptTokenCount: usage.entree, candidatesTokenCount: usage.sortie, totalTokenCount: usage.entree + usage.sortie },
    modelVersion: `${modele}-001`,
    responseId: `rep-${id}-${n}`,
  };
}

/** Événements SSE d'une réponse en flux, dans la forme documentée de chaque format. */
export function evenementsFlux(format, corps, n) {
  const { fin, texte, nom, args, id } = contenu(format, corps, n);
  const modele = corps?.model ?? MODELE;
  const usage = { entree: 512 + 100 * etat(format, corps), sortie: 48 };
  const argsTexte = fin ? null : JSON.stringify(args);
  const coupe = Math.floor(texte.length / 2);
  const e = [];
  if (format === "openai-chat") {
    const base = { id: `chatcmpl-${id}`, object: "chat.completion.chunk", created: 1794306000, model: modele };
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { content: texte.slice(0, coupe) }, finish_reason: null }] }));
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { content: texte.slice(coupe) }, finish_reason: null }] }));
    if (!fin) {
      const moitie = Math.floor(argsTexte.length / 2);
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: `call_${id}`, type: "function", function: { name: nom, arguments: "" } }] }, finish_reason: null }] }));
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: argsTexte.slice(0, moitie) } }] }, finish_reason: null }] }));
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: argsTexte.slice(moitie) } }] }, finish_reason: null }] }));
    }
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: {}, finish_reason: fin ? "stop" : "tool_calls" }] }));
    e.push(sse(null, { ...base, choices: [], usage: { prompt_tokens: usage.entree, completion_tokens: usage.sortie, total_tokens: usage.entree + usage.sortie } }));
    e.push("data: [DONE]\n\n");
    return e;
  }
  if (format === "openai-responses") {
    const complet = reponseEntiere(format, corps, n);
    const enCours = { ...complet, status: "in_progress", output: [], usage: null };
    let s = 0;
    e.push(sse("response.created", { type: "response.created", sequence_number: s++, response: enCours }));
    e.push(sse("response.in_progress", { type: "response.in_progress", sequence_number: s++, response: enCours }));
    complet.output.forEach((it, i) => {
      if (it.type === "message") {
        e.push(sse("response.output_item.added", { type: "response.output_item.added", sequence_number: s++, output_index: i, item: { ...it, status: "in_progress", content: [] } }));
        e.push(sse("response.content_part.added", { type: "response.content_part.added", sequence_number: s++, item_id: it.id, output_index: i, content_index: 0, part: { type: "output_text", text: "", annotations: [] } }));
        e.push(sse("response.output_text.delta", { type: "response.output_text.delta", sequence_number: s++, item_id: it.id, output_index: i, content_index: 0, delta: texte.slice(0, coupe) }));
        e.push(sse("response.output_text.delta", { type: "response.output_text.delta", sequence_number: s++, item_id: it.id, output_index: i, content_index: 0, delta: texte.slice(coupe) }));
        e.push(sse("response.output_text.done", { type: "response.output_text.done", sequence_number: s++, item_id: it.id, output_index: i, content_index: 0, text: texte }));
        e.push(sse("response.content_part.done", { type: "response.content_part.done", sequence_number: s++, item_id: it.id, output_index: i, content_index: 0, part: it.content[0] }));
      } else {
        e.push(sse("response.output_item.added", { type: "response.output_item.added", sequence_number: s++, output_index: i, item: { ...it, arguments: "", status: "in_progress" } }));
        e.push(sse("response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", sequence_number: s++, item_id: it.id, output_index: i, delta: it.arguments }));
        e.push(sse("response.function_call_arguments.done", { type: "response.function_call_arguments.done", sequence_number: s++, item_id: it.id, output_index: i, arguments: it.arguments }));
      }
      e.push(sse("response.output_item.done", { type: "response.output_item.done", sequence_number: s++, output_index: i, item: it }));
    });
    e.push(sse("response.completed", { type: "response.completed", sequence_number: s++, response: complet }));
    return e;
  }
  const m = (parts, extra = {}) => ({ candidates: [{ content: { parts, role: "model" }, index: 0, ...extra }], modelVersion: `${modele}-001`, responseId: `rep-${id}-${n}` });
  e.push(sse(null, { ...m([{ text: texte.slice(0, coupe) }]), usageMetadata: { promptTokenCount: usage.entree, totalTokenCount: usage.entree } }));
  e.push(sse(null, m([{ text: texte.slice(coupe) }])));
  const derniers = fin ? [] : [{ functionCall: { name: nom, args } }];
  e.push(sse(null, { ...m(derniers, { finishReason: "STOP" }), usageMetadata: { promptTokenCount: usage.entree, candidatesTokenCount: usage.sortie, totalTokenCount: usage.entree + usage.sortie } }));
  return e;
}

export class SimulateurFormats {
  constructor(o = {}) {
    this.pauseMs = o.pauseMs ?? 2;
    /** Requêtes reçues : méthode, cible, en-têtes, corps, format, étape. */
    this.requetes = [];
    /** Compteurs d'usage par `<empreinte de clé> <route>` (CT-7 EX-3.8). */
    this.usage = new Map();
    this.compteur = 0;
  }

  async demarrer() {
    this.serveur = http.createServer((req, res) => this._servir(req, res).catch(() => res.destroy()));
    await new Promise((r) => this.serveur.listen(0, "127.0.0.1", r));
    return this;
  }

  get url() {
    return `http://127.0.0.1:${this.serveur.address().port}`;
  }

  async arreter() {
    this.serveur.closeAllConnections?.();
    await new Promise((r) => this.serveur.close(() => r()));
  }

  async _servir(req, res) {
    const morceaux = [];
    for await (const c of req) morceaux.push(c);
    const brut = Buffer.concat(morceaux);
    const [chemin, requete = ""] = (req.url ?? "").split("?");
    const n = ++this.compteur;
    const json = (statut, objet) => {
      const corps = JSON.stringify(objet);
      res.writeHead(statut, { "content-type": "application/json", "content-length": Buffer.byteLength(corps), "request-id": `req_formats_${n}` }).end(corps);
    };
    if (req.method === "GET" && chemin === "/sante") return json(200, { ok: true });
    if (req.method === "GET" && chemin === "/demo/usage") {
      const lignes = [...this.usage.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => ({ key_sha256_16: k.split(" ")[0], route: k.split(" ")[1], requests: v }));
      return json(200, { version: 0, usage: lignes });
    }
    const format = formatDuChemin(chemin);
    if (!format || req.method !== "POST") return json(404, { error: { message: "route inconnue du simulateur", type: "invalid_request_error" } });
    let corps = null;
    try {
      corps = JSON.parse(brut.toString("utf8"));
    } catch {
      return json(400, { error: { message: "corps JSON illisible", type: "invalid_request_error" } });
    }
    // La clé est comptée (empreinte), jamais vérifiée ni gardée.
    const porteur = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    const cle = req.headers["x-goog-api-key"] ?? req.headers["x-api-key"] ?? (porteur ? porteur[1] : "");
    const route = format === "gemini" ? chemin.replace(/\/models\/.*$/, "/models") : chemin;
    const k = `${empreinteCle(cle)} ${route}`;
    this.usage.set(k, (this.usage.get(k) ?? 0) + 1);
    const p = plan(format, corps);
    this.requetes.push({ n, methode: req.method, cible: req.url, format, entetes: req.headers, corps, etape: p.etape, reemission: p.reemission, etat: etat(format, corps) });
    const flux = format === "gemini" ? chemin.endsWith(":streamGenerateContent") : corps?.stream === true;
    if (format === "gemini" && flux && !/(^|&)alt=sse(&|$)/.test(requete)) return json(400, { error: { code: 400, message: "alt=sse attendu pour streamGenerateContent", status: "INVALID_ARGUMENT" } });
    if (p.reemission) await pause(PAUSE_REEMISSION_MS);
    if (!flux) return json(200, reponseEntiere(format, corps, n));
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", "request-id": `req_formats_${n}` });
    for (const ev of evenementsFlux(format, corps, n)) {
      res.write(ev);
      await pause(this.pauseMs);
    }
    res.end();
  }
}
