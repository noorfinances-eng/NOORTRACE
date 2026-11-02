// Fournisseur de modèle simulé pour les tests du frontal modèle : un serveur
// HTTP sur 127.0.0.1 qui répond aux quatre formats de la version 0 de CT-2
// (5.2) dans leurs formes documentées : API Messages d'Anthropic (réponse
// entière, ou flux `message_start`, blocs, `input_json_delta` dont le premier
// est vide, `ping`, `message_delta` cumulatif, `message_stop`), Chat
// Completions (objet `chat.completion`, ou morceaux `data:` sans `event:`,
// appels d'outils fragmentés par `index`, morceau `usage`, `data: [DONE]`),
// Responses (objet `response`, ou événements typés jusqu'à
// `response.completed`) et Gemini (`generateContent`, ou
// `streamGenerateContent?alt=sse`, un `GenerateContentResponse` par `data`).
// Chaque flux est écrit événement par événement, avec une courte pause, pour
// que la passerelle le relaie au fil de l'eau.
//
// Le modèle simulé demande l'outil `demo__claims_get` tant que la requête ne
// porte pas son résultat, puis conclut. Un scénario peut remplacer la réponse
// suivante (statut, en-têtes, octets, pauses, coupure, compression) pour les
// tests d'entrées hostiles. Aucune clé réelle : les valeurs sont fictives.

import http from "node:http";
import zlib from "node:zlib";

/** Arguments que le modèle simulé demande pour l'outil. */
export const ARGS_OUTIL = Object.freeze({ claim_id: "2026-81044" });
/** Nom de l'outil vu par le modèle (point remplacé, tool_name_sanitize). */
export const NOM_OUTIL = "demo__claims_get";
/** Texte qui précède l'appel d'outil, par format ; l'adresse de Gemini est rédigée (pii-v1). */
export const TEXTE_AVANT = Object.freeze({
  "anthropic-messages": "Je consulte le dossier du sinistre 2026-81044.",
  "openai-chat": "Je consulte le dossier.",
  "openai-responses": "Je verifie le dossier du sinistre.",
  gemini: "Je consulte le sinistre ; contact : gestion@assureur-demo.example.",
});
export const TEXTE_FIN = "Le sinistre 2026-81044 est ouvert.";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const sse = (evenement, data) => `${evenement ? `event: ${evenement}\n` : ""}data: ${typeof data === "string" ? data : JSON.stringify(data)}\n\n`;

/** La requête porte-t-elle déjà le résultat de l'outil ? */
function aResultat(format, corps) {
  const t = JSON.stringify(corps ?? {});
  if (format === "anthropic-messages") return t.includes('"tool_result"');
  if (format === "openai-chat") return t.includes('"role":"tool"');
  if (format === "openai-responses") return t.includes('"function_call_output"');
  return t.includes('"functionResponse"');
}

/** Réponse entière (hors flux) d'un format. */
export function reponseEntiere(format, corps, n) {
  const fin = aResultat(format, corps);
  const modele = corps?.model ?? "modele-simule";
  if (format === "anthropic-messages") {
    const content = fin
      ? [{ type: "text", text: TEXTE_FIN }]
      : [{ type: "text", text: TEXTE_AVANT[format] }, { type: "tool_use", id: `toolu_simule_${n}`, name: NOM_OUTIL, input: ARGS_OUTIL }];
    return { id: `msg_simule_${n}`, type: "message", role: "assistant", model: modele, content, stop_reason: fin ? "end_turn" : "tool_use", stop_sequence: null, usage: { input_tokens: 120, output_tokens: 30 } };
  }
  if (format === "openai-chat") {
    const message = fin
      ? { role: "assistant", content: TEXTE_FIN }
      : { role: "assistant", content: TEXTE_AVANT[format], tool_calls: [{ id: `call_simule_${n}`, type: "function", function: { name: NOM_OUTIL, arguments: JSON.stringify(ARGS_OUTIL) } }] };
    return { id: `chatcmpl-simule-${n}`, object: "chat.completion", created: 1794306000, model: modele, choices: [{ index: 0, message, logprobs: null, finish_reason: fin ? "stop" : "tool_calls" }], usage: { prompt_tokens: 90, completion_tokens: 20, total_tokens: 110 } };
  }
  if (format === "openai-responses") {
    const output = fin
      ? [{ type: "message", id: `msg_simule_${n}`, status: "completed", role: "assistant", content: [{ type: "output_text", text: TEXTE_FIN, annotations: [] }] }]
      : [
          { type: "message", id: `msg_simule_${n}`, status: "completed", role: "assistant", content: [{ type: "output_text", text: TEXTE_AVANT[format], annotations: [] }] },
          { type: "function_call", id: `fc_simule_${n}`, call_id: `call_simule_${n}`, name: NOM_OUTIL, arguments: JSON.stringify(ARGS_OUTIL), status: "completed" },
        ];
    return { id: `resp_simule_${n}`, object: "response", created_at: 1794306000, status: "completed", model: modele, output, usage: { input_tokens: 80, output_tokens: 25, total_tokens: 105 } };
  }
  const parts = fin ? [{ text: TEXTE_FIN }] : [{ text: TEXTE_AVANT.gemini }, { functionCall: { name: NOM_OUTIL, args: ARGS_OUTIL } }];
  return {
    candidates: [{ content: { parts, role: "model" }, finishReason: "STOP", index: 0 }],
    usageMetadata: { promptTokenCount: 70, candidatesTokenCount: 15, totalTokenCount: 85 },
    modelVersion: "gemini-simule-001",
    responseId: `rep-simule-${n}`,
  };
}

/** Événements SSE d'une réponse en flux, dans la forme documentée de chaque format. */
export function evenementsFlux(format, corps, n) {
  const fin = aResultat(format, corps);
  const modele = corps?.model ?? "modele-simule";
  const e = [];
  if (format === "anthropic-messages") {
    e.push(sse("message_start", { type: "message_start", message: { id: `msg_simule_${n}`, type: "message", role: "assistant", model: modele, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 120, output_tokens: 1 } } }));
    e.push(sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
    const t = fin ? TEXTE_FIN : TEXTE_AVANT[format];
    e.push(sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t.slice(0, 10) } }));
    e.push(sse("ping", { type: "ping" }));
    e.push(sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: t.slice(10) } }));
    e.push(sse("content_block_stop", { type: "content_block_stop", index: 0 }));
    if (!fin) {
      e.push(sse("content_block_start", { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: `toolu_simule_${n}`, name: NOM_OUTIL, input: {} } }));
      e.push(sse("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: "" } }));
      e.push(sse("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"claim_id": ' } }));
      e.push(sse("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '"2026-81044"}' } }));
      e.push(sse("content_block_stop", { type: "content_block_stop", index: 1 }));
    }
    e.push(sse("message_delta", { type: "message_delta", delta: { stop_reason: fin ? "end_turn" : "tool_use", stop_sequence: null }, usage: { output_tokens: 30 } }));
    e.push(sse("message_stop", { type: "message_stop" }));
    return e;
  }
  if (format === "openai-chat") {
    const base = { id: `chatcmpl-simule-${n}`, object: "chat.completion.chunk", created: 1794306000, model: modele };
    e.push(": commentaire du fournisseur\n\n");
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
    const t = fin ? TEXTE_FIN : TEXTE_AVANT[format];
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { content: t.slice(0, 5) }, finish_reason: null }], obfuscation: "x1" }));
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: { content: t.slice(5) }, finish_reason: null }] }));
    if (!fin) {
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: `call_simule_${n}`, type: "function", function: { name: NOM_OUTIL, arguments: "" } }] }, finish_reason: null }] }));
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"claim_id":' } }] }, finish_reason: null }] }));
      e.push(sse(null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '"2026-81044"}' } }] }, finish_reason: null }] }));
    }
    e.push(sse(null, { ...base, choices: [{ index: 0, delta: {}, finish_reason: fin ? "stop" : "tool_calls" }] }));
    e.push(sse(null, { ...base, choices: [], usage: { prompt_tokens: 90, completion_tokens: 20, total_tokens: 110 } }));
    e.push("data: [DONE]\n\n");
    return e;
  }
  if (format === "openai-responses") {
    const complet = reponseEntiere(format, corps, n);
    const enCours = { ...complet, status: "in_progress", output: [], usage: null };
    e.push(sse(null, { type: "response.created", sequence_number: 0, response: enCours }));
    e.push(sse(null, { type: "response.in_progress", sequence_number: 1, response: enCours }));
    complet.output.forEach((it, i) => {
      if (it.type === "message") e.push(sse(null, { type: "response.output_text.delta", sequence_number: 2 + i, item_id: it.id, output_index: i, content_index: 0, delta: it.content[0].text }));
      else e.push(sse(null, { type: "response.function_call_arguments.delta", sequence_number: 2 + i, item_id: it.id, output_index: i, delta: it.arguments }));
      e.push(sse(null, { type: "response.output_item.done", sequence_number: 10 + i, output_index: i, item: it }));
    });
    e.push(sse(null, { type: "response.completed", sequence_number: 20, response: complet }));
    return e;
  }
  const t = fin ? TEXTE_FIN : TEXTE_AVANT.gemini;
  const m = (parts, extra = {}) => ({ candidates: [{ content: { parts, role: "model" }, index: 0, ...extra }], modelVersion: "gemini-simule-001", responseId: `rep-simule-${n}` });
  e.push(sse(null, { ...m([{ text: t.slice(0, 12) }]), usageMetadata: { promptTokenCount: 70, totalTokenCount: 70 } }));
  e.push(sse(null, m([{ text: t.slice(12) }])));
  const derniers = fin ? [] : [{ functionCall: { name: NOM_OUTIL, args: ARGS_OUTIL } }];
  e.push(sse(null, { ...m(derniers, { finishReason: "STOP" }), usageMetadata: { promptTokenCount: 70, candidatesTokenCount: 15, totalTokenCount: 85 } }));
  return e;
}

/** Format d'un chemin reçu par le fournisseur. */
export function formatDuChemin(chemin) {
  if (/\/v1\/messages$/.test(chemin)) return "anthropic-messages";
  if (/\/v1\/chat\/completions$/.test(chemin)) return "openai-chat";
  if (/\/v1\/responses$/.test(chemin)) return "openai-responses";
  if (/\/models\/[^/]+:(stream)?[gG]enerateContent$/.test(chemin)) return "gemini";
  return null;
}

export class FournisseurSimule {
  constructor(o = {}) {
    this.pauseMs = o.pauseMs ?? 5;
    /** Requêtes reçues : méthode, cible, en-têtes, corps. */
    this.requetes = [];
    /** Scénarios des réponses suivantes (file) : remplacent la réponse par défaut. */
    this.scenarios = [];
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

  /** Remplace la réponse suivante. */
  prochaine(scenario) {
    this.scenarios.push(scenario);
  }

  async arreter() {
    this.serveur.closeAllConnections?.();
    await new Promise((r) => this.serveur.close(() => r()));
  }

  async _servir(req, res) {
    const morceaux = [];
    for await (const c of req) morceaux.push(c);
    const brut = Buffer.concat(morceaux);
    let corps = null;
    try {
      corps = JSON.parse(brut.toString("utf8"));
    } catch {
      corps = null;
    }
    const n = ++this.compteur;
    const r = { methode: req.method, cible: req.url, entetes: req.headers, brut, corps, n };
    this.requetes.push(r);
    // Crochet des tests : état observé à l'instant où la requête arrive (EX-5.10).
    if (this.surRequete) await this.surRequete(r);
    const s = this.scenarios.shift();
    if (s) return this._scenario(s, req, res, r);
    const chemin = req.url.split("?")[0];
    const format = formatDuChemin(chemin);
    if (req.method === "GET" && /\/models$/.test(chemin)) {
      res.writeHead(200, { "content-type": "application/json", "request-id": `req_simule_${n}` }).end(JSON.stringify({ data: [{ id: "modele-simule" }] }));
      return;
    }
    if (req.method === "POST" && /count_tokens$/.test(chemin)) {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ input_tokens: 42 }));
      return;
    }
    if (!format) {
      res.writeHead(404, { "content-type": "application/json" }).end('{"error":"inconnu"}');
      return;
    }
    const flux = format === "gemini" ? chemin.endsWith(":streamGenerateContent") : corps?.stream === true;
    const entetes = { "request-id": `req_simule_${n}`, "x-request-id": `req_simule_${n}`, "x-fournisseur-interne": "retire" };
    if (!flux) {
      res.writeHead(200, { ...entetes, "content-type": "application/json" }).end(JSON.stringify(reponseEntiere(format, corps, n)));
      return;
    }
    res.writeHead(200, { ...entetes, "content-type": "text/event-stream", "cache-control": "no-cache" });
    for (const ev of evenementsFlux(format, corps, n)) {
      res.write(ev);
      await pause(this.pauseMs);
    }
    res.end();
  }

  async _scenario(s, req, res, r) {
    if (s.avantEntetesMs) await pause(s.avantEntetesMs);
    if (s.detruire) {
      req.socket.destroy();
      return;
    }
    res.on("close", () => {
      if (!res.writableFinished) r.fermeParClient = true;
    });
    const entetes = { ...(s.entetes ?? {}) };
    let morceaux = (s.morceaux ?? []).map((m) => (typeof m === "string" ? Buffer.from(m, "utf8") : Buffer.from(m)));
    if (s.gzip) {
      morceaux = [zlib.gzipSync(Buffer.concat(morceaux))];
      entetes["content-encoding"] = "gzip";
    }
    res.writeHead(s.statut ?? 200, entetes);
    res.flushHeaders();
    for (const m of morceaux) {
      res.write(m);
      await pause(s.pauseMs ?? this.pauseMs);
    }
    if (s.silenceMs) await pause(s.silenceMs);
    if (s.couper) {
      res.socket.destroy();
      return;
    }
    if (res.destroyed) return;
    res.end();
    s.vu?.(r);
  }
}
