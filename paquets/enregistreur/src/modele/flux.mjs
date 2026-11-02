// Réassemblage des flux de réponse du frontal modèle (CT-2 §5.4) : analyseur
// SSE commun (EX-5.14, EX-5.34) et forme consolidée fournisseur par
// fournisseur, API Messages d'Anthropic (EX-5.15), Chat Completions
// (EX-5.16), Responses (EX-5.17) et Gemini (EX-5.35), sous les règles
// communes d'EX-5.27. Tout est incrémental : la passerelle remet chaque
// fragment lu du fournisseur avant de l'écrire vers l'hôte (5.6), et sait
// ainsi, au fragment près, quand la forme en clair est close.
//
// Une donnée d'un flux est une donnée d'entrée : un événement mal formé est
// ignoré et compté (EX-5.27 (4)), jamais une erreur de l'enregistreur
// (EX-7.1). Les seules clés ajoutées à une forme sont celles d'EX-5.18.

import { analyserTexte, valeurDe, ErreurTexteJson } from "../mcp/json-texte.mjs";
import { jcsIntegral } from "../jcs-integral.mjs";

/** Clés que l'enregistreur ajoute à une forme consolidée (EX-5.18). */
export const CLE_INCOMPLET = "noortrace_flux_incomplet";
export const CLE_ERREUR_FLUX = "noortrace_erreur_flux";
export const CLE_INPUT_INVALIDE = "noortrace_input_json_invalide";

/** Plus grand index admis (EX-5.27 (1)). */
const INDEX_MAX = 2 ** 53;

/**
 * Analyse JSON stricte (4.4 pas 1 : clé en double, substitut isolé, nombre
 * qui déborde la double, bornes de profondeur et de membres) d'un texte.
 * @param {string} texte
 * @param {{profondeurMax?: number, membresMax?: number}} [bornes]
 * @returns {{ok: true, valeur: unknown}|{ok: false, raison: string}}
 */
export function analyserJsonStrict(texte, bornes = {}) {
  try {
    return { ok: true, valeur: valeurDe(analyserTexte(texte, bornes)) };
  } catch (e) {
    if (e instanceof ErreurTexteJson) return { ok: false, raison: e.raison };
    if (e instanceof RangeError) return { ok: false, raison: "profondeur" };
    throw e;
  }
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const cloner = (v) => (v === undefined ? undefined : structuredClone(v));

/**
 * Index admis (EX-5.27 (1)) : nombre JSON dont la valeur (double la plus
 * proche du texte reçu) est entière, au moins 0 et au plus 2^53 ; sinon null.
 * @param {unknown} v
 * @returns {number|null}
 */
export function indexAdmis(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= INDEX_MAX ? v : null;
}

// ------------------------------------------------------------ analyseur SSE (EX-5.14, EX-5.34)

/**
 * Analyseur SSE de la section « Parsing an event stream » du HTML Living
 * Standard : UTF-8 avec retrait d'une marque d'ordre d'octets initiale, fins
 * de ligne CRLF, LF ou CR, champs `event` et `data`, `id` et `retry` lus et
 * ignorés. Avec `final` (route `gemini`, EX-5.34), la dernière ligne sans fin
 * de ligne est lue, puis un tampon `data` resté sans ligne vide est distribué.
 */
export class AnalyseurSse {
  /**
   * @param {{final?: boolean, distribuer: (type: string, data: string) => void, compter?: (quoi: string) => void}} o
   */
  constructor(o) {
    this.final = o.final === true;
    this.distribuer = o.distribuer;
    this.compter = o.compter ?? (() => {});
    // Décodage UTF-8 du standard : marque initiale retirée, séquences
    // invalides remplacées par U+FFFD.
    this.decodeur = new TextDecoder("utf-8");
    this.ligne = "";
    this.apresCr = false;
    this.type = "";
    this.donnees = "";
    this.donneesPresentes = false;
    this.ferme = false;
  }

  /**
   * Remet des octets du corps.
   * @param {Uint8Array} octets
   */
  ecrire(octets) {
    if (this.ferme) return;
    this._texte(this.decodeur.decode(octets, { stream: true }));
  }

  _texte(t) {
    let debut = 0;
    for (let i = 0; i < t.length; i++) {
      const c = t.charCodeAt(i);
      if (c === 0x0a && this.apresCr && i === debut && this.ligne === "") {
        // LF d'un CRLF dont le CR terminait le fragment précédent.
        this.apresCr = false;
        debut = i + 1;
        continue;
      }
      this.apresCr = false;
      if (c === 0x0d || c === 0x0a) {
        this._ligne(this.ligne + t.slice(debut, i));
        this.ligne = "";
        if (c === 0x0d) {
          if (i + 1 < t.length) {
            if (t.charCodeAt(i + 1) === 0x0a) i++;
          } else {
            this.apresCr = true;
          }
        }
        debut = i + 1;
      }
    }
    this.ligne += t.slice(debut);
  }

  _ligne(l) {
    if (this.ferme) return;
    if (l === "") {
      this._distribuer();
      return;
    }
    if (l.charCodeAt(0) === 0x3a) {
      this.compter("commentaire");
      return;
    }
    const k = l.indexOf(":");
    let champ;
    let valeur;
    if (k < 0) {
      champ = l;
      valeur = "";
    } else {
      champ = l.slice(0, k);
      valeur = l.slice(k + 1);
      if (valeur.charCodeAt(0) === 0x20) valeur = valeur.slice(1);
    }
    if (champ === "event") this.type = valeur;
    else if (champ === "data") {
      this.donnees += `${valeur}\n`;
      this.donneesPresentes = true;
    }
    // id, retry et tout autre champ : lus et ignorés.
  }

  _distribuer() {
    if (!this.donneesPresentes || this.donnees === "") {
      this.donnees = "";
      this.donneesPresentes = false;
      this.type = "";
      return;
    }
    const data = this.donnees.endsWith("\n") ? this.donnees.slice(0, -1) : this.donnees;
    const type = this.type === "" ? "message" : this.type;
    this.donnees = "";
    this.donneesPresentes = false;
    this.type = "";
    this.distribuer(type, data);
  }

  /** Arrête l'analyse (borne atteinte, erreur) : plus rien n'est distribué. */
  arreter() {
    this.ferme = true;
  }

  /** Fin du corps amont, quelle qu'en soit la cause. */
  terminer() {
    if (this.ferme) return;
    this._texte(this.decodeur.decode());
    if (this.final) {
      if (this.ligne !== "") {
        const l = this.ligne;
        this.ligne = "";
        this._ligne(l);
      }
      if (this.donneesPresentes && this.donnees !== "") {
        this.compter("sse_data_final_sans_ligne_vide");
        this._distribuer();
      }
    }
    this.ferme = true;
  }
}

// ------------------------------------------------------------ réassemblages

/**
 * Base d'un réassemblage : comptes des événements ignorés (EX-5.27 (4)),
 * analyse des valeurs `data`.
 */
class Reassemblage {
  constructor(o = {}) {
    this.bornes = { profondeurMax: o.profondeurMax ?? 128, membresMax: o.membresMax ?? 100000 };
    this.ignores = 0;
    /** Fin normale du flux selon le fournisseur. */
    this.finNormale = false;
    /** Événement terminal reçu : la forme en clair est close (5.6). */
    this.terminal = false;
    this.erreur = false;
    this.coupe = false;
  }

  ignorer() {
    this.ignores++;
  }

  _objet(data) {
    const r = analyserJsonStrict(data, this.bornes);
    return r.ok && estObjet(r.valeur) ? r.valeur : null;
  }

  /** Le corps amont ne s'est pas terminé normalement (coupure, délai, hôte parti, borne). */
  couper() {
    if (!this._clos) this.coupe = true;
  }

  /**
   * Clôt la forme (une seule fois) : à l'événement terminal, ou à la fin du
   * corps amont.
   * @returns {{forme: object|null, incomplet: boolean, is_error: boolean}}
   */
  clore() {
    if (!this._clos) this._clos = this._clore();
    return this._clos;
  }
}

/**
 * Forme consolidée de l'API Messages d'Anthropic (EX-5.15).
 */
export class ReassemblageAnthropic extends Reassemblage {
  constructor(o) {
    super(o);
    this.forme = null;
    this.reduite = null;
    this.tampons = new Map();
    this.avantDebut = false;
    this.arrete = false;
  }

  /**
   * @param {string} _type type SSE (`event:`)
   * @param {string} data
   */
  donnee(_type, data) {
    if (this.arrete || this.terminal) {
      this.ignorer();
      return;
    }
    const v = this._objet(data);
    if (!v) return this.ignorer();
    const t = v.type;
    if (this.forme === null) {
      if (t === "message_start") {
        if (!estObjet(v.message)) return this.ignorer();
        this.forme = cloner(v.message);
        return;
      }
      if (t === "error") {
        this.reduite = { [CLE_ERREUR_FLUX]: cloner(v) };
        this.erreur = true;
        this.arrete = true;
        return;
      }
      if (t !== "ping") this.avantDebut = true;
      return this.ignorer();
    }
    const f = this.forme;
    switch (t) {
      case "message_start":
        return this.ignorer();
      case "content_block_start": {
        const n = indexAdmis(v.index);
        if (n === null || !estObjet(v.content_block)) return this.ignorer();
        if (!Array.isArray(f.content)) f.content = [];
        if (n > f.content.length) return this.ignorer();
        f.content[n] = cloner(v.content_block);
        this.tampons.delete(n);
        if (v.content_block.type === "tool_use") this.tampons.set(n, "");
        return;
      }
      case "content_block_delta": {
        const n = indexAdmis(v.index);
        const b = n === null || !Array.isArray(f.content) ? undefined : f.content[n];
        const d = v.delta;
        if (!estObjet(b) || !estObjet(d)) return this.ignorer();
        if (d.type === "text_delta" && typeof d.text === "string") b.text = (typeof b.text === "string" ? b.text : "") + d.text;
        else if (d.type === "input_json_delta" && typeof d.partial_json === "string") this.tampons.set(n, (this.tampons.get(n) ?? "") + d.partial_json);
        else if (d.type === "thinking_delta" && typeof d.thinking === "string") b.thinking = (typeof b.thinking === "string" ? b.thinking : "") + d.thinking;
        else if (d.type === "signature_delta" && typeof d.signature === "string") b.signature = d.signature;
        else if (d.type === "citations_delta" && estObjet(d.citation)) {
          if (!Array.isArray(b.citations)) b.citations = [];
          b.citations.push(cloner(d.citation));
        } else return this.ignorer();
        return;
      }
      case "content_block_stop": {
        const n = indexAdmis(v.index);
        const b = n === null || !Array.isArray(f.content) ? undefined : f.content[n];
        if (!estObjet(b)) return this.ignorer();
        if (!this.tampons.has(n)) return;
        const tampon = this.tampons.get(n);
        this.tampons.delete(n);
        if (tampon === "") {
          b.input = {};
          return;
        }
        const r = analyserJsonStrict(tampon, this.bornes);
        if (r.ok) b.input = r.valeur;
        else {
          b.input = {};
          b[CLE_INPUT_INVALIDE] = tampon;
        }
        return;
      }
      case "message_delta": {
        if (estObjet(v.delta)) {
          for (const k of ["stop_reason", "stop_sequence", "stop_details"]) if (k in v.delta) f[k] = cloner(v.delta[k]);
        }
        if (estObjet(v.usage)) {
          if (!estObjet(f.usage)) f.usage = {};
          for (const [k, x] of Object.entries(v.usage)) f.usage[k] = cloner(x);
        }
        if (!estObjet(v.delta) && !estObjet(v.usage)) return this.ignorer();
        return;
      }
      case "message_stop":
        this.finNormale = true;
        this.terminal = true;
        return;
      case "error":
        f[CLE_ERREUR_FLUX] = cloner(v);
        this.erreur = true;
        this.arrete = true;
        return;
      default:
        // ping et types inconnus : ignorés, comptés.
        return this.ignorer();
    }
  }

  _clore() {
    if (this.forme === null) {
      if (this.reduite) return { forme: this.reduite, incomplet: true, is_error: true };
      return { forme: null, incomplet: true, is_error: true };
    }
    const incomplet = !this.finNormale || this.avantDebut || this.coupe;
    if (incomplet) this.forme[CLE_INCOMPLET] = true;
    return { forme: this.forme, incomplet, is_error: incomplet || this.erreur };
  }
}

/**
 * Forme consolidée de Chat Completions (EX-5.16).
 */
export class ReassemblageChat extends Reassemblage {
  constructor(o) {
    super(o);
    this.forme = null;
    this.idPremier = null;
    this.arrete = false;
    /** Membres d'un appel d'outil déjà fixés par un fragment (hors de la forme). */
    this.fixes = new WeakMap();
  }

  donnee(_type, data) {
    if (this.arrete || this.terminal) return this.ignorer();
    if (data === "[DONE]") {
      if (this.forme === null) return this.ignorer();
      this.finNormale = true;
      this.terminal = true;
      return;
    }
    const v = this._objet(data);
    if (!v) return this.ignorer();
    const id = jcsIntegral("id" in v ? v.id : null);
    if (this.forme === null) {
      this.idPremier = id;
      const f = {};
      for (const k of ["id", "created", "model", "system_fingerprint", "service_tier"]) if (k in v) f[k] = cloner(v[k]);
      f.object = "chat.completion";
      f.choices = [];
      this.forme = f;
    } else if (id !== this.idPremier) {
      // Un autre identifiant arrête le réassemblage (EX-5.16 pas 5).
      this.arrete = true;
      return this.ignorer();
    }
    const f = this.forme;
    if (Array.isArray(v.choices)) {
      for (const c of v.choices) {
        const n = estObjet(c) ? indexAdmis(c.index) : null;
        if (n === null || !estObjet(c.delta)) {
          this.ignorer();
          continue;
        }
        let ch = f.choices.find((x) => x.index === n);
        if (!ch) {
          ch = { index: n, message: { role: "assistant", content: null }, finish_reason: null };
          f.choices.push(ch);
        }
        const d = c.delta;
        const m = ch.message;
        if (typeof d.role === "string") m.role = d.role;
        if (typeof d.content === "string") m.content = (m.content ?? "") + d.content;
        if (typeof d.refusal === "string") m.refusal = (m.refusal ?? "") + d.refusal;
        if (Array.isArray(d.tool_calls)) {
          for (const fr of d.tool_calls) {
            const j = estObjet(fr) ? indexAdmis(fr.index) : null;
            if (j === null) {
              this.ignorer();
              continue;
            }
            if (!Array.isArray(m.tool_calls)) m.tool_calls = [];
            let tc = m.tool_calls.find((x) => x.index === j);
            if (!tc) {
              tc = { index: j, id: null, type: "function", function: { name: "", arguments: "" } };
              this.fixes.set(tc, new Set());
              m.tool_calls.push(tc);
            }
            const fixes = this.fixes.get(tc);
            if (fr.id !== null && fr.id !== undefined && !fixes.has("id")) {
              tc.id = cloner(fr.id);
              fixes.add("id");
            }
            if (fr.type !== null && fr.type !== undefined && !fixes.has("type")) {
              tc.type = cloner(fr.type);
              fixes.add("type");
            }
            if (estObjet(fr.function)) {
              if (fr.function.name !== null && fr.function.name !== undefined && !fixes.has("name")) {
                tc.function.name = cloner(fr.function.name);
                fixes.add("name");
              }
              if (typeof fr.function.arguments === "string") tc.function.arguments += fr.function.arguments;
            } else if (fr.function !== undefined) this.ignorer();
          }
        }
        if (c.finish_reason !== null && c.finish_reason !== undefined) ch.finish_reason = cloner(c.finish_reason);
      }
    }
    if ("usage" in v && v.usage !== null) f.usage = cloner(v.usage);
  }

  _clore() {
    if (this.forme === null) return { forme: null, incomplet: true, is_error: true };
    const incomplet = !this.finNormale || this.coupe;
    if (incomplet) this.forme[CLE_INCOMPLET] = true;
    return { forme: this.forme, incomplet, is_error: incomplet };
  }
}

const TERMINAUX_RESPONSES = new Set(["response.completed", "response.failed", "response.incomplete"]);
const PORTEURS_RESPONSES = new Set(["response.created", "response.in_progress", ...TERMINAUX_RESPONSES]);

/**
 * Forme consolidée de Responses (EX-5.17).
 */
export class ReassemblageResponses extends Reassemblage {
  constructor(o) {
    super(o);
    this.dernier = null;
    this.items = new Map();
    this.erreurFlux = null;
  }

  donnee(_type, data) {
    if (this.terminal) return this.ignorer();
    const v = this._objet(data);
    if (!v) return this.ignorer();
    if (PORTEURS_RESPONSES.has(v.type)) {
      if (!estObjet(v.response)) return this.ignorer();
      this.dernier = { type: v.type, response: cloner(v.response) };
      this.terminal = TERMINAUX_RESPONSES.has(v.type);
      return;
    }
    if (v.type === "response.output_item.done") {
      const n = indexAdmis(v.output_index);
      if (n === null || !estObjet(v.item)) return this.ignorer();
      this.items.set(n, cloner(v.item));
      return;
    }
    if (v.type === "error") {
      this.erreurFlux = { code: "code" in v ? cloner(v.code) : null, message: "message" in v ? cloner(v.message) : null };
      this.erreur = true;
      return;
    }
    // Deltas et autres types : non accumulés (la réponse terminale les contient).
  }

  _clore() {
    if (this.dernier === null) {
      if (this.erreurFlux) return { forme: { [CLE_ERREUR_FLUX]: this.erreurFlux }, incomplet: true, is_error: true };
      return { forme: null, incomplet: true, is_error: true };
    }
    const f = this.dernier.response;
    const normale = TERMINAUX_RESPONSES.has(this.dernier.type) && !this.coupe;
    let isError = this.dernier.type === "response.failed";
    if (!normale) {
      f[CLE_INCOMPLET] = true;
      if (!Array.isArray(f.output)) f.output = [];
      for (const n of [...this.items.keys()].sort((a, b) => a - b)) {
        if (n < f.output.length) f.output[n] = this.items.get(n);
        else if (n === f.output.length) f.output.push(this.items.get(n));
      }
      isError = true;
    }
    if (this.erreurFlux) {
      f[CLE_ERREUR_FLUX] = this.erreurFlux;
      isError = true;
    }
    return { forme: f, incomplet: !normale, is_error: isError };
  }
}

/**
 * Forme consolidée de Gemini (EX-5.35). Sert aussi aux morceaux déclarés par
 * le SDK (EX-6.8 pas 2) : chaque élément est remis comme une valeur `data`.
 */
export class ReassemblageGemini extends Reassemblage {
  constructor(o) {
    super(o);
    this.forme = null;
    this.reduite = null;
    this.candidats = [];
    this.arrete = false;
  }

  donnee(_type, data) {
    const v = this._objet(data);
    this.objet(v);
  }

  /**
   * Remet un morceau déjà analysé (ou null s'il ne s'analysait pas).
   * @param {object|null} v
   */
  objet(v) {
    if (this.arrete) return this.ignorer();
    if (!estObjet(v)) return this.ignorer();
    if (estObjet(v.error)) {
      if (this.forme === null) this.reduite = { [CLE_ERREUR_FLUX]: cloner(v.error) };
      else this.forme[CLE_ERREUR_FLUX] = cloner(v.error);
      this.erreur = true;
      this.arrete = true;
      return;
    }
    if (this.forme === null) this.forme = {};
    for (const [k, x] of Object.entries(v)) {
      if (k !== "candidates") this.forme[k] = cloner(x);
    }
    if (!("candidates" in v)) return;
    if (!Array.isArray(v.candidates)) return this.ignorer();
    for (const fr of v.candidates) {
      if (!estObjet(fr)) {
        this.ignorer();
        continue;
      }
      let n = 0;
      if ("index" in fr) {
        n = indexAdmis(fr.index);
        if (n === null) {
          this.ignorer();
          continue;
        }
      }
      let c = this.candidats.find((x) => x.index === n);
      if (!c) {
        c = { index: n, content: { parts: [] } };
        this.candidats.push(c);
      }
      for (const [k, x] of Object.entries(fr)) {
        if (k === "index") continue;
        if (k === "content") {
          if (!estObjet(x)) {
            this.ignorer();
            continue;
          }
          for (const [kc, xc] of Object.entries(x)) {
            if (kc === "parts") {
              if (!Array.isArray(xc)) {
                this.ignorer();
                continue;
              }
              for (const p of xc) {
                if (estObjet(p)) c.content.parts.push(cloner(p));
                else this.ignorer();
              }
            } else {
              c.content[kc] = cloner(xc);
            }
          }
          continue;
        }
        c[k] = cloner(x);
      }
    }
  }

  _clore() {
    if (this.forme === null) {
      if (this.reduite) return { forme: this.reduite, incomplet: true, is_error: true };
      return { forme: null, incomplet: true, is_error: true };
    }
    const f = this.forme;
    if (this.candidats.length) f.candidates = this.candidats;
    const fin = this.candidats.length
      ? this.candidats.some((c) => typeof c.finishReason === "string" && c.finishReason !== "")
      : estObjet(f.promptFeedback);
    const incomplet = this.coupe || !fin;
    if (incomplet) f[CLE_INCOMPLET] = true;
    return { forme: f, incomplet, is_error: incomplet || this.erreur };
  }
}

/**
 * Réassemblage du format d'une route.
 * @param {"anthropic-messages"|"openai-chat"|"openai-responses"|"gemini"} format
 * @param {{profondeurMax?: number, membresMax?: number}} [bornes]
 */
export function reassemblagePour(format, bornes) {
  switch (format) {
    case "anthropic-messages":
      return new ReassemblageAnthropic(bornes);
    case "openai-chat":
      return new ReassemblageChat(bornes);
    case "openai-responses":
      return new ReassemblageResponses(bornes);
    case "gemini":
      return new ReassemblageGemini(bornes);
    default:
      throw new TypeError(`format inconnu : ${format}`);
  }
}

/**
 * Consolide un flux complet (transcription SSE) : outil des tests et des
 * réponses déjà reçues.
 * @param {string} format
 * @param {Uint8Array} octets
 * @param {{coupe?: boolean, bornes?: object}} [o]
 * @returns {{forme: object|null, incomplet: boolean, is_error: boolean, ignores: number, comptes: Map<string, number>}}
 */
export function consoliderFlux(format, octets, o = {}) {
  const r = reassemblagePour(format, o.bornes);
  const comptes = new Map();
  const a = new AnalyseurSse({
    final: format === "gemini",
    distribuer: (t, d) => r.donnee(t, d),
    compter: (q) => comptes.set(q, (comptes.get(q) ?? 0) + 1),
  });
  a.ecrire(octets);
  a.terminer();
  if (o.coupe) r.couper();
  return { ...r.clore(), ignores: r.ignores, comptes };
}

/**
 * Consolide les morceaux Gemini déclarés en tableau (EX-6.8 pas 2) : la fin du
 * tableau vaut fin normale ; un tableau vide donne `{noortrace_flux_incomplet: true}`.
 * @param {unknown[]} morceaux
 * @returns {{forme: object, incomplet: boolean, is_error: boolean}}
 */
export function consoliderMorceauxGemini(morceaux) {
  if (morceaux.length === 0) return { forme: { [CLE_INCOMPLET]: true }, incomplet: true, is_error: true };
  const r = new ReassemblageGemini();
  for (const m of morceaux) r.objet(m);
  const c = r.clore();
  return c.forme === null ? { forme: { [CLE_INCOMPLET]: true }, incomplet: true, is_error: true } : c;
}
