// Ingestion OpenTelemetry (CT-2 §6.8, EX-6.25 à EX-6.41) : une requête OTLP
// reçue est jugée dans l'ordre des décisions d'EX-6.27 — (a) chemin, (b)
// méthode, (c) jeton, (d) quota de la source, (e) mode dégradé, (f) type de
// contenu, (g) codage de contenu, (h) octets reçus, (i) décompression, (j)
// décodage et bornes, (k) nombre de spans — puis chaque span est normalisé
// (EX-6.31), classé (EX-6.32), écarté s'il est un doublon (EX-6.33) ou un
// recouvrement (EX-6.34), projeté sur ses pièces rédigées et son événement
// (EX-6.35, EX-6.36) et remis à l'écrivain dans l'ordre du document ; la
// réponse `200` n'est rendue qu'une fois tous les événements de la requête
// durables (EX-6.38). L'ingestion n'évalue aucune politique, n'écrit aucune
// intention, ne met jamais un événement en attente (EX-6.39) et ne met pas, à
// elle seule, le démon en mode dégradé.

import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { decoderHorodatage } from "@noortrace/noyau";
import { ErreurEnregistreur, ErreurConstruction } from "../erreurs.mjs";
import { jcsIntegralOctets } from "../jcs-integral.mjs";
import { normaliserCible } from "../modele/formats.mjs";
import { egauxTempsConstant } from "../mcp/hote-stdio.mjs";
import { QuotasHote } from "../mcp/quotas.mjs";
import { LimiteurEchecs } from "../sdk/limiteur.mjs";
import { decoderJson } from "./decodage-json.mjs";
import { decoderProtobuf } from "./decodage-protobuf.mjs";
import { ErreurDecodage, normaliser, classer, nombreSpans } from "./representation.mjs";
import { projeterSpan, partielSpan, effetsSpan } from "./projection.mjs";
import { TableDoublons, RegistreRecouvrement } from "./tables.mjs";
import { corpsSucces, corpsRefus, TYPE_JSON, TYPE_PROTOBUF } from "./reponses.mjs";

/** Bornes de l'histogramme `noortrace_otel_reception_lag_ms` (EX-6.41). */
export const BORNES_RETARD = Object.freeze([1000, 5000, 10000, 30000, 60000, 300000, 3600000]);
/** Issues d'un span (EX-6.41). */
export const ISSUES = Object.freeze(["scelle", "ignore", "doublon", "recouvrement", "rejete"]);
const MOTIF_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MINUTE = 60000;

/**
 * Retard de réception (EX-6.41) : `ts` de l'événement moins la fin déclarée du
 * span, en millisecondes entières (partie entière de l'écart exact), 0 si
 * négatif ; null quand la fin déclarée vaut 0 (aucune observation).
 * @param {string} ts
 * @param {string} fin `end_time_unix_nano` en chaîne décimale
 * @returns {number|null}
 */
export function retardReception(ts, fin) {
  const f = BigInt(fin);
  if (f === 0n) return null;
  const ecart = BigInt(decoderHorodatage(ts)) * 1000000n - f;
  return ecart <= 0n ? 0 : Number(ecart / 1000000n);
}

class Fenetre {
  constructor() {
    this.e = [];
  }
  ajouter(t, n) {
    this.e.push([t, n]);
  }
  total(t) {
    while (this.e.length && this.e[0][0] <= t - MINUTE) this.e.shift();
    return this.e.reduce((s, x) => s + x[1], 0);
  }
}

/**
 * Type de contenu admis (EX-6.27).
 * @param {string|undefined} ct
 * @param {string[]} encodings `otel.encodings`
 * @returns {"json"|"protobuf"|null}
 */
export function encodageDe(ct, encodings) {
  const t = typeof ct === "string" ? ct.split(";")[0].trim().toLowerCase() : "";
  if (t === TYPE_PROTOBUF && encodings.includes("protobuf")) return "protobuf";
  if (t === TYPE_JSON && encodings.includes("json")) return "json";
  return null;
}

export class IngestionOtel {
  /**
   * @param {object} o
   * @param {() => object} o.config configuration en vigueur (rechargements compris)
   * @param {object} o.journal journal d'exploitation
   * @param {object} o.metriques
   * @param {object|null} o.redacteur rédacteur (section e)
   * @param {Map<string, Uint8Array>} o.jetons `id` d'un jeton de `otel.static_tokens` → jeton résolu
   * @param {() => number} o.monotone
   * @param {(piece: object) => Promise<object>} o.ecrirePiece
   * @param {(partiel: object) => Promise<object>} o.sceller scellement durable (priorité basse, EX-6.28)
   * @param {() => string|null} o.panne raison de mode dégradé qui refuse l'ingestion (EX-6.39), ou null
   * @param {() => Promise<number|null>} [o.octetsLibres] volume libre du disque des segments (EX-6.28 `min_free_bytes`)
   * @param {() => {policy_version: string, recorder: string, nomRedaction: string|null}} o.version
   * @param {RegistreRecouvrement} [o.recouvrement]
   * @param {TableDoublons} [o.doublons]
   */
  constructor(o) {
    this.o = o;
    this.jetons = o.jetons ?? new Map();
    this.limiteur = new LimiteurEchecs({ monotone: o.monotone });
    const otel = o.config().otel;
    this.doublons =
      o.doublons ??
      new TableDoublons({
        fenetreMs: otel.dedup_window_ms,
        surSortie: (n) => this.journal.consigner("warning", "otel", "otel_dedup_evicted", { count: n }),
      });
    this.recouvrement = o.recouvrement ?? new RegistreRecouvrement({ fenetreMs: otel.overlap_window_ms });
    this.quotas = new Map();
    this.evenementsMinute = new Map();
    this.octetsMinute = new Map();
  }

  get config() {
    return this.o.config();
  }

  get journal() {
    return this.o.journal;
  }

  get metriques() {
    return this.o.metriques;
  }

  _quotas(hote) {
    let q = this.quotas.get(hote.id);
    if (!q) {
      q = new QuotasHote(hote.quota);
      this.quotas.set(hote.id, q);
    }
    return q;
  }

  /** Source authentifiée par le jeton présenté (EX-6.37), ou null. */
  _source(entetes) {
    const x = entetes["x-noortrace-token"];
    const a = entetes.authorization;
    let jeton = null;
    if (typeof x === "string") jeton = x;
    else if (typeof a === "string" && /^Bearer /i.test(a)) jeton = a.slice(7).trim();
    if (jeton === null || jeton === "") return { hote: null, cle: null };
    const recu = Buffer.from(jeton, "utf8");
    const cle = this.limiteur.cleJeton(recu);
    let id = null;
    for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
    const hote = id === null ? null : (this.config.otel.hosts ?? []).find((h) => h.match?.static_token === id) ?? null;
    return { hote, cle };
  }

  /**
   * Jugement des en-têtes, avant la lecture du corps : causes (a) à (g)
   * d'EX-6.27.
   * @param {{methode: string, cible: string, entetes: object, connexion: string}} r
   * @returns {{refus: object}|{suite: object}}
   */
  async prejuger(r) {
    const otel = this.config.otel;
    const encodage = encodageDe(r.entetes["content-type"], otel.encodings);
    const etat = { encodage, query_string: false, hote: null, recu: 0, decomprime: 0, spans: 0, comptes: Object.fromEntries(ISSUES.map((i) => [i, 0])), raisons: {}, connexion: r.connexion, t: this.o.monotone() };
    const refus = (statut, raison, extra = {}) => ({ refus: { statut, raison, etat, ...extra } });
    // (a) chemin, normalisation d'EX-5.2 comprise.
    const n = normaliserCible(r.cible);
    if (!n.ok || n.chemin !== otel.path) return refus(404, "chemin");
    etat.query_string = n.requete !== null;
    // (b) méthode.
    if (r.methode !== "POST") return refus(405, "methode");
    // (c) jeton (EX-6.37, EX-18.3 : limité par identifiant de jeton et par connexion).
    const s = this._source(r.entetes);
    const cleConnexion = `connexion:${r.connexion}`;
    if (!s.hote || (s.cle && this.limiteur.bloque(s.cle)) || this.limiteur.bloque(cleConnexion)) {
      if (s.cle) this.limiteur.echec(s.cle);
      this.limiteur.echec(cleConnexion);
      this.journal.consigner("warning", "otel", "auth_failed", { transport: "otlp_http", reason: s.cle ? "jeton" : "jeton_absent", token_id: s.cle ? s.cle.slice(6) : null });
      return refus(401, "authentification");
    }
    etat.hote = s.hote;
    // (d) quota de la source (EX-6.28, EX-4.47).
    const q = this._quotas(s.hote).depasse(etat.t, { appel: true });
    if (q) return refus(429, "quota", { limites: q });
    // (e) mode dégradé (EX-6.39) et volume libre propre à l'ingestion (EX-6.28).
    const p = this.o.panne();
    if (p) return refus(503, p);
    if (this.config.otel.min_free_bytes !== undefined && this.o.octetsLibres) {
      const libres = await this.o.octetsLibres();
      if (libres !== null && libres < this.config.otel.min_free_bytes) return refus(503, "volume_ingestion");
    }
    // (f) type de contenu.
    if (encodage === null) return refus(415, "type_de_contenu");
    // (g) codage de contenu, jugé avant la taille.
    const ce = r.entetes["content-encoding"];
    const codage = typeof ce === "string" ? ce.trim().toLowerCase() : "identity";
    if (codage !== "identity" && codage !== "gzip") return refus(415, "codage");
    etat.codage = codage;
    return { suite: etat };
  }

  /**
   * Suite d'une requête dont les en-têtes sont admis : (h) à (k), puis les spans.
   * @param {object} etat état de `prejuger`
   * @param {Uint8Array|null} corps corps reçu, ou null s'il a dépassé `otel.max_body_bytes`
   * @param {number} recus octets reçus
   * @returns {Promise<object>} issue (`statut`, `raison`, `etat`)
   */
  async traiter(etat, corps, recus) {
    const otel = this.config.otel;
    const lim = this.config.limits;
    etat.recu = recus;
    const quotas = this._quotas(etat.hote);
    quotas.recevoir(this.o.monotone(), recus);
    const refus = (statut, raison, extra = {}) => ({ statut, raison, etat, ...extra });
    // (h) octets reçus au-delà de la borne.
    if (corps === null || recus > otel.max_body_bytes) return refus(413, "taille");
    quotas.enCours++;
    try {
      // (i) gzip invalide (400), puis octets décomprimés au-delà de la borne (413) ; arrêt avant toute allocation au-delà.
      let octets = corps;
      if (etat.codage === "gzip") {
        try {
          octets = new Uint8Array(zlib.gunzipSync(corps, { maxOutputLength: otel.max_body_bytes }));
        } catch (e) {
          if (e?.code === "ERR_BUFFER_TOO_LARGE" || e instanceof RangeError) return refus(413, "taille_decomprimee");
          return refus(400, "gzip");
        }
        if (octets.length > otel.max_body_bytes) return refus(413, "taille_decomprimee");
      }
      etat.decomprime = octets.length;
      // (j) décodage et bornes.
      const t0 = this.o.monotone();
      let requete;
      try {
        const bornes = { profondeurMax: lim.json_max_depth, membresMax: lim.json_max_members };
        requete = etat.encodage === "json" ? decoderJson(octets, bornes) : decoderProtobuf(octets, bornes);
      } catch (e) {
        if (!(e instanceof ErreurDecodage)) throw e;
        return refus(400, "decodage", { detail: e.raison });
      }
      // (k) nombre de spans.
      etat.spans = nombreSpans(requete);
      if (otel.spans_per_request !== undefined && etat.spans > otel.spans_per_request) return refus(413, "spans_par_requete");
      const n = normaliser(requete, { profondeurMax: lim.json_max_depth });
      quotas.tempsCapture(this.o.monotone(), this.o.monotone() - t0);
      if (n.doubles) this.journal.consigner("debug", "otel", "otel_cle_double", { count: n.doubles }, { host: etat.hote.id });
      return await this._spans(etat, n.spans);
    } finally {
      quotas.enCours = Math.max(0, quotas.enCours - 1);
    }
  }

  _compter(etat, issue, raison) {
    etat.comptes[issue]++;
    if (raison) etat.raisons[raison] = (etat.raisons[raison] ?? 0) + 1;
    this.metriques.compter("noortrace_otel_spans_total", { source: etat.hote.alias, issue, reason: raison ?? "" });
  }

  async _spans(etat, spans) {
    const cfg = this.config;
    const otel = cfg.otel;
    const hote = etat.hote;
    const alias = hote.alias;
    const source = cfg.policy.otel?.sources?.[alias] ?? { ingest: [], overlap: "ignorer", class_default: null, tools: {} };
    const vusIci = new Map();
    let rejetes = 0;
    const scelles = [];
    for (const { path, N } of spans) {
      const c = classer(N, source.ingest);
      if (c.issue === "ignore") {
        this._compter(etat, "ignore", c.raison);
        continue;
      }
      if (c.issue === "rejete") {
        rejetes++;
        this._compter(etat, "rejete", c.raison);
        this.journal.consigner("warning", "otel", "otel_span_rejected", { trace_id: N.trace_id, span_id: N.span_id, reason: c.raison }, { host: hote.id });
        continue;
      }
      // Doublons (EX-6.33).
      const cle = TableDoublons.cle(alias, N.trace_id, N.span_id);
      const empreinte = createHash("sha256").update(jcsIntegralOctets(N)).digest("hex");
      const deja = vusIci.get(cle) ?? this.doublons.chercher(cle, etat.t);
      if (deja !== undefined) {
        const e0 = typeof deja === "string" ? deja : deja.empreinte;
        // Une clé inscrite sans empreinte connue (table reconstituée) ne donne pas de conflit.
        if (e0 !== null && e0 !== empreinte) {
          this.journal.consigner("warning", "otel", "otel_span_conflict", { trace_id: N.trace_id, span_id: N.span_id, sha256: [`0x${e0}`, `0x${empreinte}`] }, { host: hote.id });
          this.metriques.compter("noortrace_otel_conflicts_total", { source: alias });
        }
        this._compter(etat, "doublon", null);
        continue;
      }
      vusIci.set(cle, empreinte);
      // Pièces en mémoire (rédaction), avant le recouvrement qui en dépend (M, EX-6.36).
      const t0 = this.o.monotone();
      const x = await projeterSpan({ N, sorte: c.sorte, alias, hote, source, model: cfg.model, pieceMax: cfg.limits.piece_max_bytes, redacteur: this.o.redacteur, ctx: { host: hote.id } });
      this._quotas(hote).tempsCapture(this.o.monotone(), this.o.monotone() - t0);
      // Recouvrement (EX-6.34).
      if (source.overlap === "ignorer" && !(c.sorte === "inference" && x.M === null)) {
        const seq = this.recouvrement.apparier(
          c.sorte === "outil" ? { genre: "appel", host_group: hote.host_group, nom: x.N, t: etat.t } : { genre: "echange", host_group: hote.host_group, modele: x.M, t: etat.t },
        );
        if (seq !== null) {
          this.doublons.inscrire(cle, empreinte, etat.t);
          this.journal.consigner("info", "otel", "otel_span_overlap", { trace_id: N.trace_id, span_id: N.span_id, seq }, { host: hote.id });
          this._compter(etat, "recouvrement", null);
          continue;
        }
      }
      for (const t of x.trop) this.journal.consigner("warning", "otel", "otel_piece_too_large", { trace_id: N.trace_id, span_id: N.span_id, piece: t.piece, length: t.length }, { host: hote.id });
      // Bornes propres à l'ingestion, span par span (EX-6.28).
      const tm = this.o.monotone();
      const ev = this._fenetre(this.evenementsMinute, alias);
      const oc = this._fenetre(this.octetsMinute, alias);
      if ((otel.events_per_minute !== undefined && ev.total(tm) >= otel.events_per_minute) || (otel.event_bytes_per_minute !== undefined && oc.total(tm) >= otel.event_bytes_per_minute)) {
        return { statut: 429, raison: "evenements_par_minute", etat, rejetes, scelles };
      }
      // Run_id déclaré (EX-6.36, EX-7.2).
      const run_id = await this._runId(N, hote);
      // Pièces durables, puis événement (priorité basse, EX-6.28).
      let partiel;
      let octetsPieces = 0;
      try {
        for (const p of x.pieces) {
          await this.o.ecrirePiece(p);
          octetsPieces += p.octets.length;
        }
        this._quotas(hote).piece(this.o.monotone(), octetsPieces);
        const v = this.o.version();
        const effets = c.sorte === "outil" ? await effetsSpan(x, { alias, source, redacteur: this.o.redacteur }) : { effets: [], omis: [] };
        for (const om of effets.omis) this.journal.consigner("info", "noyau", "effect_omitted", { gabarit: om.index, raison: om.raison }, { host: hote.id });
        partiel = partielSpan(x, { N, hote, run_id, policy_version: v.policy_version, recorder: v.recorder, nomRedaction: v.nomRedaction, effets: effets.effets });
        const e = await this.o.sceller(partiel);
        scelles.push({ path, evenement: e, projection: x });
        this.doublons.inscrire(cle, empreinte, etat.t);
        this._compter(etat, "scelle", null);
        ev.ajouter(this.o.monotone(), 1);
        oc.ajouter(this.o.monotone(), octetsPieces + jcsIntegralOctets(e).length);
        // Retard de réception (EX-6.41) : ts moins la fin déclarée ; aucune observation si la fin vaut 0.
        if (N.end_time_unix_nano !== "0") {
          this.metriques.observer("noortrace_otel_reception_lag_ms", { source: alias }, retardReception(e.ts, N.end_time_unix_nano), BORNES_RETARD);
        }
      } catch (e) {
        if (e instanceof ErreurEnregistreur || e instanceof ErreurConstruction) {
          // EX-6.39 : 503, aucun événement en attente ; l'exportateur renverra le lot.
          return { statut: 503, raison: e.raison ?? (e instanceof ErreurConstruction ? "evenement_invalide" : "stockage"), etat, rejetes, scelles };
        }
        throw e;
      }
    }
    return { statut: 200, raison: null, etat, rejetes, scelles };
  }

  _fenetre(m, alias) {
    let f = m.get(alias);
    if (!f) {
      f = new Fenetre();
      m.set(alias, f);
    }
    return f;
  }

  async _runId(N, hote) {
    const v = N.attributes["gen_ai.conversation.id"];
    if (hote.accept_declared_delegation !== true || v === undefined) return null;
    const r = this.o.redacteur;
    let refus = null;
    if (typeof v !== "string" || !MOTIF_RUN_ID.test(v)) refus = "motif";
    else if (r?.admettreRunId && !(await r.admettreRunId(v))) refus = "detecteur";
    if (refus === null) return v;
    this.journal.consigner("warning", "otel", "delegation_refused", { component: "otel", field: "run_id", reason: refus, length: typeof v === "string" ? v.length : 0 }, { host: hote.id });
    return null;
  }

  /**
   * Réponse d'une issue (EX-6.27) et ligne `otel_request` (EX-6.41).
   * @param {object} issue
   * @returns {{statut: number, entetes: object, corps: Uint8Array}}
   */
  repondre(issue) {
    const etat = issue.etat;
    const enc = etat.encodage ?? "json";
    const entetes = { "content-type": enc === "protobuf" ? TYPE_PROTOBUF : TYPE_JSON };
    let corps;
    if (issue.statut === 200) corps = corpsSucces(enc, issue.rejetes ?? 0);
    else corps = corpsRefus(enc, issue.statut);
    if (issue.statut === 405) entetes.allow = "POST";
    if (issue.statut === 429 || issue.statut === 503) entetes["retry-after"] = String(this.config.otel.retry_after_s);
    entetes["content-length"] = String(corps.length);
    const alias = etat.hote?.alias ?? "";
    this.metriques.compter("noortrace_otel_requests_total", { source: alias, status: String(issue.statut) });
    if (issue.statut !== 200) {
      this.journal.consigner("warning", "otel", "otel_refused", { status: issue.statut, reason: issue.raison }, { host: etat.hote?.id ?? null });
    }
    this.journal.consigner(
      "info",
      "otel",
      "otel_request",
      {
        source: alias || null,
        content_type: enc === "protobuf" ? TYPE_PROTOBUF : etat.encodage === "json" ? TYPE_JSON : null,
        encoding: etat.codage ?? null,
        query_string: etat.query_string === true,
        bytes_received: etat.recu,
        bytes_decompressed: etat.decomprime,
        spans: etat.spans,
        issues: etat.comptes,
        reasons: etat.raisons,
        status: issue.statut,
      },
      { host: etat.hote?.id ?? null },
    );
    return { statut: issue.statut, entetes, corps };
  }
}
