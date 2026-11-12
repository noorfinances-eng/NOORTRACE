// Moteur des échanges de modèle (CT-2 §5.3, 5.5, 5.6, §14.2 colonne M,
// EX-14.12, EX-4.47) : ce que la passerelle (5.1.1), le serveur ICAP
// (5.1.2) et le récepteur du miroir (5.1.3) font de la même façon. Il
// prépare une requête (délégation, colonne M de 14.2, quotas de la connexion
// d'hôte, pièces « prompt système » et « requête » durables avant l'envoi,
// EX-5.10), capture la réponse au fil de l'eau (décompression d'EX-5.9,
// borne d'EX-5.33, réassemblage de 5.4, inscription au registre de 5.6 dès
// que la forme en clair est close), puis écrit la pièce « réponse » et scelle
// l'échange, ou le met en attente (14.2 « Panne après relais », EX-14.8,
// EX-14.12). Les transports (HTTP, ICAP, prise du miroir) restent hors d'ici.

import zlib from "node:zlib";
import { ErreurEnregistreur, ErreurConstruction } from "../erreurs.mjs";
import { partielEchange } from "../capture.mjs";
import { VERSION_ENREGISTREUR } from "../coeur.mjs";
import { resoudreDelegation } from "../mcp/delegation.mjs";
import { QuotasHote } from "../mcp/quotas.mjs";
import { typeMedia, estTypeJson } from "./formats.mjs";
import { AnalyseurSse, reassemblagePour } from "./flux.mjs";
import { piecesRequete, pieceReponse, modeleDe, intentionDe, intentionBornee, analyserCorpsJson, SANS_REDACTION } from "./extraction.mjs";
import { RegistreCorrelation } from "./correlation.mjs";

/** Codages de contenu que le frontal sait décomprimer (EX-5.9). */
export const DECOMPRESSEURS = Object.freeze({ gzip: () => zlib.createGunzip(), "x-gzip": () => zlib.createGunzip(), deflate: () => zlib.createInflate(), br: () => zlib.createBrotliDecompress() });

/** Paires d'`usage` comptées par `noortrace_model_tokens_total` (17.2). */
const JETONS = Object.freeze({
  "anthropic-messages": ["input_tokens", "output_tokens"],
  "openai-chat": ["prompt_tokens", "completion_tokens"],
  "openai-responses": ["input_tokens", "output_tokens"],
  gemini: ["promptTokenCount", "candidatesTokenCount"],
});

export class MoteurEchanges {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {object|null} [o.redacteur] rédacteur (section e) ; à défaut celui du cœur
   * @param {RegistreCorrelation} [o.registre]
   * @param {object} [o.config] configuration (défaut : celle du cœur, rechargements compris)
   * @param {{echange?: Function, refus?: Function}} [o.observateur] crochets des tests, dans le processus
   */
  constructor(o) {
    this.coeur = o.coeur;
    this._config = o.config ?? null;
    const r = o.redacteur ?? this.coeur.o?.redaction ?? null;
    this.redacteur = r && typeof r.redigerPiece === "function" ? r : null;
    this.registre =
      o.registre ??
      new RegistreCorrelation({
        fenetreMs: this.config.model.correlation_window_ms,
        monotone: () => this.monotone(),
        ecrirePiece: (p) => this.coeur.ecrirePiece(p),
        journal: this.journal,
      });
    this.observateur = o.observateur ?? {};
    this.quotasParHote = new Map();
    if (!this.redacteur) this.journal.consigner("warning", "redaction", "redaction_absente", { component: "frontal_modele" });
  }

  get config() {
    return this._config ?? this.coeur.config;
  }

  get journal() {
    return this.coeur.journal;
  }

  get metriques() {
    return this.coeur.metriques;
  }

  monotone() {
    return this.coeur.horlogeBrute.monotone();
  }

  murale() {
    return this.coeur.horlogeBrute.murale();
  }

  get observation() {
    return this.config.policy.approval?.mode === "observation";
  }

  get bornes() {
    return { profondeurMax: this.config.limits.json_max_depth, membresMax: this.config.limits.json_max_members };
  }

  // ---------------------------------------------------------------- quotas (EX-4.47)

  quotas(hote) {
    let q = this.quotasParHote.get(hote.id);
    if (!q) {
      q = new QuotasHote(hote.quota);
      this.quotasParHote.set(hote.id, q);
    }
    return q;
  }

  /**
   * Quotas de la connexion d'hôte (EX-4.47) : octets reçus, requêtes en cours,
   * octets de pièces et temps de capture par minute glissante. Un quota atteint
   * bloque l'échange (14.2, ligne « Mémoire », colonne M : `503`), sauf en mode
   * observation (EX-14.16) ; jamais appelé par le miroir (LISEZMOI, lecture 73).
   * @returns {object|null} `limit_*` du quota atteint, ou null si l'échange passe
   */
  controlerQuota(hote, t, o = { echange: true }) {
    const q = this.quotas(hote).depasse(t, { appel: o.echange });
    if (!q) return null;
    const { direction, ...limites } = q;
    void direction;
    if (this.observation) {
      this.journal.consigner("warning", "politique", "observation_would_block", { would: "quota", reason: "quota", class: "modele", seq: null }, { host: hote.id });
      this.metriques.compter("noortrace_observation_would_block_total", { reason: "quota" });
      return null;
    }
    this.journal.consigner("warning", "frontal_modele", "call_blocked", { code: 503, reason: "quota", class: "modele", ...limites }, { host: hote.id });
    this.metriques.compter("noortrace_calls_blocked_total", { code: "503", reason: "quota", class: "modele" });
    return limites;
  }

  // ---------------------------------------------------------------- colonne M de 14.2

  /**
   * Raison du blocage d'un échange (colonne M de 14.2), ou null. En mode
   * « stockage » avec `failure.modele: "passant"`, et en mode observation
   * (EX-14.16), l'échange passe ; son événement est mis en attente.
   */
  blocage() {
    const c = this.coeur;
    // Journal terminé par la clôture anticipée (EX-19.4) : tout nouvel échange refusé, mode observation compris.
    if (c.bailDetenu && c.journalClos) return "journal_clos";
    const raisons = c.intervention || !c.ecrivain ? ["stockage"] : c.degrade.raisons().filter((r) => r !== "approbation");
    if (!c.bailDetenu) raisons.unshift("bail");
    if (!raisons.length) return null;
    if (this.observation) {
      this.journal.consigner("warning", "politique", "observation_would_block", { would: "bloquant", reason: raisons[0], class: "modele", seq: null });
      this.metriques.compter("noortrace_observation_would_block_total", { reason: raisons[0] });
      return null;
    }
    // Bornes d'EX-14.9, contrôlées avant l'envoi : au-delà, l'échange passant devient bloquant.
    // Avec `stockage` et `attente` actifs, la raison est `attente`, la plus restrictive
    // (EX-14.4) : le stockage seul laisserait passer l'échange, la borne le bloque.
    if (raisons.every((r) => r === "stockage" || r === "attente") && this.config.policy.failure?.modele === "passant") {
      return raisons.includes("attente") || c.attenteBornee() ? "attente" : null;
    }
    return raisons[0];
  }

  _bloque(hote, raison, route) {
    this.journal.consigner("warning", "frontal_modele", "call_blocked", { code: 503, reason: raison, class: "modele", route: route?.path ?? null }, { host: hote?.id ?? null });
    this.metriques.compter("noortrace_calls_blocked_total", { code: "503", reason: raison, class: "modele" });
  }

  // ---------------------------------------------------------------- délégation (7.2, EX-7.2, EX-8.6)

  async delegation(hote, h, identite = {}) {
    const declaree = {};
    if (typeof h["x-noortrace-run-id"] === "string") declaree.run_id = h["x-noortrace-run-id"];
    if (typeof h["x-noortrace-on-behalf-of"] === "string") declaree.on_behalf_of = h["x-noortrace-on-behalf-of"];
    let runRefuse = false;
    if (hote.accept_declared_delegation === true && typeof declaree.run_id === "string" && this.redacteur?.admettreRunId) {
      runRefuse = !(await this.redacteur.admettreRunId(declaree.run_id));
    }
    const d = resoudreDelegation({
      hote,
      identite,
      declaree: Object.keys(declaree).length ? declaree : undefined,
      sessionHeritee: null,
      detecte: () => runRefuse,
      refus: (champ, raison, longueur) =>
        this.journal.consigner("warning", "frontal_modele", "delegation_refused", { component: "frontal_modele", field: champ, reason: raison, length: longueur }, { host: hote.id }),
    });
    if (Object.keys(declaree).length && hote.accept_declared_delegation === true) {
      this.journal.consigner("info", "frontal_modele", "delegation_declared", { fields: Object.keys(declaree) }, { host: hote.id });
    }
    return d;
  }

  async nomPrompt(hote, h) {
    const declare = h["x-noortrace-prompt-version"];
    if (typeof declare === "string" && hote.accept_declared_delegation === true) {
      const admis = this.redacteur?.admettreNomPrompt ? await this.redacteur.admettreNomPrompt(declare) : /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(declare);
      if (admis) return declare;
      this.journal.consigner("warning", "frontal_modele", "delegation_refused", { component: "frontal_modele", field: "prompt_version", reason: "detecteur", length: declare.length }, { host: hote.id });
    }
    return hote.prompt_version_name ?? null;
  }

  // ---------------------------------------------------------------- requête (5.3.1 pas 2 et 3)

  /**
   * Prépare un échange : délégation, colonne M de 14.2, pièces de la requête
   * écrites et forcées sur disque avant l'envoi (EX-5.10).
   * @param {object} x
   * @param {object} x.route
   * @param {{segment?: string}} [x.trouve]
   * @param {object} x.hote entrée de `model.hosts`
   * @param {Object<string, string>} x.entetes en-têtes de la requête de l'hôte (noms en minuscules)
   * @param {unknown} x.valeur corps analysé
   * @param {number} x.t_recu
   * @param {"passerelle"|"icap"|"miroir"} x.mode
   * @param {object} [x.identite] `{ oauth_subject }`
   * @returns {Promise<{etat: object}|{refus: string, raison?: string}>}
   */
  async preparer(x) {
    const { route, hote } = x;
    const cfg = this.config;
    const delegation = await this.delegation(hote, x.entetes, x.identite ?? {});
    if (delegation.launched_by === null) return { refus: "hote_inconnu" };
    // Le miroir ne bloque rien (EX-5.6, EX-14.12).
    if (x.mode !== "miroir") {
      const b = this.blocage();
      if (b) {
        this._bloque(hote, b, route);
        return { refus: "degrade", raison: b };
      }
    }
    const t0 = this.monotone();
    const pr = await piecesRequete({
      format: route.format,
      valeur: x.valeur,
      prompt_in_request: cfg.model.prompt_in_request,
      prompt_system: cfg.model.prompt_system,
      nomPrompt: cfg.model.prompt_system === "named" ? await this.nomPrompt(hote, x.entetes) : null,
      redacteur: this.redacteur ?? SANS_REDACTION,
      ctx: { host: hote.id },
    });
    const pieces = [pr.prompt, pr.requete].filter(Boolean);
    let enMemoire = false;
    try {
      for (const p of pieces) await this.coeur.ecrirePiece(p);
    } catch (e) {
      const raison = e instanceof ErreurEnregistreur ? e.raison : "stockage";
      // Stockage indisponible : bloquant, sauf échange passant (14.2), observation (EX-14.16) ou miroir (EX-14.12).
      if (x.mode !== "miroir" && (this.blocage() !== null || !(raison === "stockage" || this.observation))) {
        this._bloque(hote, raison, route);
        return { refus: "degrade", raison };
      }
      enMemoire = true;
    }
    const quotas = this.quotas(hote);
    quotas.tempsCapture(this.monotone(), this.monotone() - t0);
    if (!enMemoire) quotas.piece(this.monotone(), pieces.reduce((s, p) => s + p.octets.length, 0));
    quotas.enCours++;
    return {
      etat: { route, hote, delegation, pr, pieces, enMemoire, mode: x.mode, segment: x.trouve?.segment ?? null, t_recu: x.t_recu, t_envoi: this.monotone(), label: route.provider_label },
    };
  }

  /**
   * État d'un échange dont la requête n'a pas été vue (RESPMOD sans REQMOD
   * retrouvé, EX-5.4) : pièce « requête » `{"noortrace_requete_inconnue": true}`.
   */
  async preparerInconnue(x) {
    const r = this.redacteur ?? SANS_REDACTION;
    const req = await r.redigerPiece({ genre: "json", portee: "requete", valeur: { noortrace_requete_inconnue: true }, avecValeur: true }, { host: x.hote.id });
    const pr = { attendue: false, prompt: null, requete: req.piece, requeteRedigee: req.valeur, nonRedigeable: null };
    let enMemoire = false;
    try {
      await this.coeur.ecrirePiece(req.piece);
    } catch {
      enMemoire = true;
    }
    this.quotas(x.hote).enCours++;
    return { route: x.route, hote: x.hote, delegation: await this.delegation(x.hote, {}), pr, pieces: [req.piece], enMemoire, mode: x.mode, segment: x.segment ?? null, t_recu: x.t_recu, t_envoi: x.t_recu, label: x.route.provider_label };
  }

  /** Capture au fil de l'eau d'une réponse amont. */
  capture(etat, o) {
    return new CaptureReponse(this, etat, o);
  }

  // ---------------------------------------------------------------- clôture d'un échange

  /**
   * Pièce « réponse », valeurs, scellement de `noortrace.modele.echange`, ou
   * mise en attente (14.2, EX-14.8, EX-14.12).
   * @param {object} etat
   * @param {{genre: "reponse"|"delai"|"hote_parti"|"inactivite"|"coupure", phase?: string, timeout_ms?: number}} issue
   * @returns {Promise<object|null>} événement durable, ou null
   */
  async sceller(etat, issue) {
    const t_reponse = etat.t_reponse ?? this.monotone();
    const captured_at = etat.captured_at ?? this.murale();
    const route = etat.route;
    const hote = etat.hote;
    const label = etat.label;
    const duration_ms = Math.max(0, Math.round(t_reponse - etat.t_envoi));
    const redacteur = this.redacteur ?? SANS_REDACTION;
    const ctx = { host: hote.id };
    const t0 = this.monotone();
    let rep;
    const timeout = async (phase, ms) => {
      const v = { noortrace_http_error: { status: 504, content_type: null, body: { noortrace_timeout: { phase, timeout_ms: ms } } } };
      const x = await redacteur.redigerPiece({ genre: "json", portee: "reponse", valeur: v, avecValeur: true }, ctx);
      return { piece: x.piece, valeurRedigee: x.valeur, formeClair: null, is_error: true, incomplet: false };
    };
    if (issue.genre === "delai") {
      this.journal.consigner("warning", "frontal_modele", "provider_error", { route: route.path, phase: issue.phase, status: null }, { host: hote.id });
      this.metriques.compter("noortrace_upstream_errors_total", { provider: label, kind: issue.phase === "connexion" ? "injoignable" : "delai" });
      rep = await timeout(issue.phase, issue.timeout_ms);
    } else if (issue.genre === "hote_parti" && etat.statut === undefined) {
      // L'hôte ferme avant toute réponse : aucun octet reçu (EX-5.13).
      this.journal.consigner("warning", "frontal_modele", "host_disconnected", { route: route.path }, { host: hote.id });
      const x = await redacteur.redigerPiece({ genre: "octets", portee: "reponse", octets: new Uint8Array(0), content_type: null }, ctx);
      rep = { piece: x.piece, valeurRedigee: undefined, formeClair: null, is_error: true, incomplet: true };
    } else if (issue.genre === "inactivite" && !etat.flux) {
      this.journal.consigner("warning", "frontal_modele", "provider_error", { route: route.path, phase: "inactivite", status: etat.statut }, { host: hote.id });
      rep = await timeout("inactivite", issue.timeout_ms);
    } else {
      if (issue.genre === "inactivite") this.journal.consigner("warning", "frontal_modele", "provider_error", { route: route.path, phase: "inactivite", status: etat.statut }, { host: hote.id });
      rep = await pieceReponse({
        format: route.format,
        statut: etat.statut,
        contentType: etat.contentType,
        corps: etat.corps ?? new Uint8Array(0),
        flux: etat.flux,
        consolidee: etat.consolidee,
        tronque: etat.tronque,
        codageInconnu: etat.codageInconnu,
        bornes: this.bornes,
        analyse: etat.analyse,
        redacteur,
        ctx,
      });
      if (issue.genre === "coupure" && !etat.flux) rep.is_error = true;
      if (etat.statut >= 400 || etat.statut < 200) {
        this.journal.consigner("warning", "frontal_modele", "provider_error", { route: route.path, status: etat.statut, request_id: etat.notesReponse?.["request-id"] ?? etat.notesReponse?.["x-request-id"] ?? null }, { host: hote.id });
        this.metriques.compter("noortrace_upstream_errors_total", { provider: label, kind: etat.statut >= 500 ? "http_5xx" : "http_4xx" });
      } else if (rep.incomplet) {
        this.metriques.compter("noortrace_upstream_errors_total", { provider: label, kind: "flux_incomplet" });
      }
    }
    // code.model (EX-5.19, EX-5.36) : segment de modèle admis seulement s'il passe les détecteurs.
    let segment = null;
    if (route.format === "gemini" && etat.segment !== null) {
      const admis = this.redacteur?.admettreValeurLigne ? await this.redacteur.admettreValeurLigne(etat.segment) : true;
      if (admis) segment = etat.segment;
      else this.journal.consigner("warning", "frontal_modele", "model_segment_refused", { route: route.path, raison: "detecteur", length: etat.segment.length }, { host: hote.id });
    }
    const model = modeleDe({ format: route.format, label, reponseRedigee: rep.valeurRedigee, requeteRedigee: etat.pr.requeteRedigee, attendue: etat.pr.attendue, segment });
    const prompt_version = etat.pr.prompt?.sha256 ?? null;
    const ib = intentionBornee(rep.valeurRedigee === undefined ? null : intentionDe(route.format, rep.valeurRedigee), intentionDe(route.format, rep.formeClair));
    const code = { model, prompt_version };
    if (etat.entree) this.registre.completer(etat.entree, { formeRedigee: rep.valeurRedigee, code });
    const quotas = this.quotas(hote);
    quotas.tempsCapture(this.monotone(), this.monotone() - t0);
    const pieces = [...etat.pieces, rep.piece, ...(ib.piece ? [ib.piece] : [])];
    // `host` : connexion d'hôte de l'échange, pour le registre de recouvrement de l'ingestion OpenTelemetry (EX-6.34).
    const c = { delegation: etat.delegation, code, intent: ib.intent, requete: etat.pr.requete.reference, reponse: rep.piece.reference, duration_ms, is_error: rep.is_error, context: [], host: hote.id };
    let evenement = null;
    let pendingId = null;
    try {
      if (etat.enMemoire) throw new ErreurEnregistreur("stockage", "noortrace: pieces gardees en memoire");
      await this.coeur.ecrirePiece(rep.piece);
      if (ib.piece) await this.coeur.ecrirePiece(ib.piece);
      quotas.piece(this.monotone(), rep.piece.octets.length + (ib.piece?.octets.length ?? 0));
      evenement = await this.coeur.scellerEchange(c);
      if (etat.entree) this.registre.sceller(etat.entree, evenement.seq);
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur || e instanceof ErreurConstruction)) throw e;
      // Panne après l'envoi : la réponse est partie ; l'événement est gardé en attente (14.2, EX-14.8, EX-14.12).
      const partiel = partielEchange({ ...c, code: { ...code, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR }, nomRedaction: this.coeur.nomRedaction });
      try {
        pendingId = this.coeur.mettreEnAttente(partiel, pieces, { captured_at, host: hote.id, genre: "echange" });
        this.journal.consigner("error", "frontal_modele", "call_executed_not_durable", { kind: "echange_modele", pending_id: pendingId }, { host: hote.id });
      } catch {
        if (this.observation) {
          this.journal.consigner("error", "noyau", "event_lost", { reason: "attente", count: 1 });
          this.metriques.compter("noortrace_events_lost_total", { reason: "attente" });
        } else {
          this.journal.consigner("error", "frontal_modele", "exchange_lost", { route: route.path, mode: etat.mode }, { host: hote.id });
        }
      }
    } finally {
      quotas.enCours = Math.max(0, quotas.enCours - 1);
    }
    const usage = rep.formeClair && typeof rep.formeClair === "object" ? (rep.formeClair.usage ?? rep.formeClair.usageMetadata ?? null) : null;
    this._compterJetons(route.format, label, usage);
    this.metriques.observer("noortrace_upstream_latency_ms", { provider: label }, duration_ms);
    this.journal.consigner(
      "info",
      "frontal_modele",
      "model_exchange_relayed",
      {
        route: route.path,
        mode: etat.mode,
        provider: label,
        model,
        status: etat.statut ?? null,
        pieces: { request: etat.pr.requete.sha256, system_prompt: etat.pr.prompt?.sha256 ?? null, response: rep.piece.sha256, intent: ib.piece?.sha256 ?? null },
        usage,
        incomplete: rep.incomplet,
        ignored_events: etat.reass?.ignores ?? 0,
        headers: { ...(etat.notes ?? {}), ...(etat.notesReponse ?? {}) },
        headers_removed: etat.retires ?? [],
        query_sha256: etat.requeteSha ?? null,
        // EX-5.36, EX-9.6 : le segment admis par les détecteurs, sinon null (sa
        // longueur est dans model_segment_refused) ; jamais le segment refusé.
        model_segment: segment,
        pending_id: pendingId,
      },
      { seq: evenement?.seq ?? null, host: hote.id, request_id: etat.notesReponse?.["request-id"] ?? etat.notesReponse?.["x-request-id"] ?? null },
    );
    this.observateur.echange?.({
      route,
      mode: etat.mode,
      formeClair: rep.formeClair,
      consolidee: etat.consolidee ?? null,
      appels: etat.entree?.appels ?? [],
      evenement,
      pendingId,
      pieces: { requete: etat.pr.requete, prompt: etat.pr.prompt, reponse: rep.piece, intention: ib.piece },
      amont: etat.cheminAmont ?? null,
      is_error: rep.is_error,
      incomplet: rep.incomplet,
    });
    return evenement;
  }

  _compterJetons(format, label, usage) {
    if (!usage || typeof usage !== "object") return;
    const paires = JETONS[format];
    if (!paires) return;
    const [e, s] = paires;
    if (Number.isSafeInteger(usage[e]) && usage[e] >= 0) this.metriques.compter("noortrace_model_tokens_total", { provider: label, direction: "entree" }, usage[e]);
    if (Number.isSafeInteger(usage[s]) && usage[s] >= 0) this.metriques.compter("noortrace_model_tokens_total", { provider: label, direction: "sortie" }, usage[s]);
  }
}

/**
 * Capture d'une réponse amont, au fil de l'eau (5.3.1 pas 5, EX-5.9,
 * EX-5.11, EX-5.33) : octets reçus remis par `ecrire` avant d'être relayés ;
 * `inscrite` dit si la forme en clair est close et inscrite au registre (5.6),
 * ce qui se fait à l'événement terminal d'un flux, sinon à `terminer`.
 */
export class CaptureReponse {
  /**
   * @param {MoteurEchanges} moteur
   * @param {object} etat état de l'échange (`preparer`)
   * @param {{statut: number, entetes: Object<string, string|string[]>, notesReponse?: object}} o
   */
  constructor(moteur, etat, o) {
    this.moteur = moteur;
    this.etat = etat;
    const lim = moteur.config.limits;
    const ct = o.entetes["content-type"];
    etat.statut = o.statut;
    etat.contentType = typeof ct === "string" ? ct : null;
    etat.notesReponse = o.notesReponse ?? {};
    const deuxCent = o.statut >= 200 && o.statut < 300;
    this.deuxCent = deuxCent;
    this.flux = deuxCent && typeMedia(etat.contentType) === "text/event-stream";
    etat.flux = this.flux;
    this.borne = lim.model_response_max_bytes;
    const ce = o.entetes["content-encoding"];
    const codage = typeof ce === "string" ? ce.trim().toLowerCase() : "identity";
    etat.codageInconnu = !(codage === "identity" || codage === "" || Object.hasOwn(DECOMPRESSEURS, codage));
    this.reass = this.flux ? reassemblagePour(etat.route.format, moteur.bornes) : null;
    this.comptes = new Map();
    this.sse = this.flux
      ? new AnalyseurSse({ final: etat.route.format === "gemini", distribuer: (t, d) => this.reass.donnee(t, d), compter: (q) => this.comptes.set(q, (this.comptes.get(q) ?? 0) + 1) })
      : null;
    etat.reass = this.reass;
    this.capture = [];
    this.brut = [];
    this.brutOctets = 0;
    this.capturees = 0;
    this.recues = 0;
    this.tronque = false;
    this.inscrite = false;
    this.decomp = null;
    if (!etat.codageInconnu && Object.hasOwn(DECOMPRESSEURS, codage)) {
      this.decomp = DECOMPRESSEURS[codage]();
      this.decomp.on("data", (x) => this._traiter(new Uint8Array(x)));
      this.decomp.on("error", () => {
        etat.codageInconnu = true;
        etat.decompressionEchouee = true;
      });
    }
  }

  _traiter(o) {
    this.recues += o.length;
    if (this.tronque) return;
    if (this.capturees + o.length > this.borne) {
      // Borne d'EX-5.33 : la capture s'arrête, le relais continue.
      this.tronque = true;
      const reste = this.borne - this.capturees;
      if (reste > 0) {
        this.capture.push(o.subarray(0, reste));
        this.sse?.ecrire(o.subarray(0, reste));
      }
      this.capturees = this.borne;
      this.sse?.arreter();
      this.reass?.couper();
      return;
    }
    this.capture.push(o);
    this.capturees += o.length;
    this.sse?.ecrire(o);
  }

  /**
   * Octets reçus du fournisseur (comprimés s'il y a lieu), avant leur relais.
   * @param {Uint8Array} o
   */
  ecrire(o) {
    const etat = this.etat;
    if (etat.codageInconnu && !this.decomp) {
      // Codage inconnu : octets gardés tels quels, dans la borne, pour la pièce de 8.3.
      this.recues += o.length;
      if (this.brutOctets + o.length <= this.borne) {
        this.brut.push(o);
        this.brutOctets += o.length;
      } else this.tronque = true;
    } else if (this.decomp && !etat.decompressionEchouee) {
      if (this.brutOctets + o.length <= this.borne) {
        this.brut.push(o);
        this.brutOctets += o.length;
      }
      this.decomp.write(o);
    } else {
      this._traiter(new Uint8Array(o));
    }
    // Forme close à l'événement terminal : inscrite avant le relais de ces octets (5.6).
    if (this.reass?.terminal && !this.inscrite) this._inscrire();
  }

  _inscrire() {
    if (this.inscrite) return;
    this.inscrite = true;
    const etat = this.etat;
    etat.consolidee = this.reass ? this.reass.clore() : null;
    etat.corps = new Uint8Array(Buffer.concat(etat.codageInconnu ? this.brut : this.capture));
    etat.tronque = this.tronque ? this.recues : null;
    if (!this.flux && !this.tronque && !etat.codageInconnu && this.deuxCent && estTypeJson(typeMedia(etat.contentType))) etat.analyse = analyserCorpsJson(etat.corps, this.moteur.bornes);
    const formeClair = this.flux ? (etat.consolidee?.forme ?? null) : etat.analyse?.ok ? etat.analyse.valeur : null;
    etat.formeClair = formeClair;
    etat.entree = this.moteur.registre.inscrire({ host: etat.hote, host_group: etat.hote.host_group, run_id: etat.delegation.run_id, format: etat.route.format, formeClair, interpose: true });
  }

  /**
   * Fin du corps amont : normale (`coupe: false`, la décompression est
   * vidée), ou coupure, délai, hôte parti, borne (`coupe: true`, forme
   * incomplète). Inscrit la forme si ce n'est pas fait.
   * @param {{coupe?: boolean}} [o]
   */
  async terminer(o = {}) {
    const etat = this.etat;
    if (this.decomp && !o.coupe && !etat.decompressionEchouee) {
      await new Promise((r) => {
        this.decomp.once("end", r);
        this.decomp.once("error", r);
        this.decomp.end();
      });
    }
    if (o.coupe) this.reass?.couper();
    this.sse?.terminer();
    if (etat.decompressionEchouee) this.reass?.couper();
    if (this.tronque) this.moteur.journal.consigner("warning", "frontal_modele", "model_response_truncated", { route: etat.route.path, bytes: this.recues }, { host: etat.hote.id });
    if (this.sse && this.comptes.get("sse_data_final_sans_ligne_vide")) {
      this.moteur.journal.consigner("info", "frontal_modele", "sse_data_final_sans_ligne_vide", { route: etat.route.path }, { host: etat.hote.id });
    }
    if (!this.inscrite) this._inscrire();
    // Taille totale d'un corps hors flux au-delà de la borne (EX-5.33).
    if (etat.tronque !== null) etat.tronque = this.recues;
    etat.t_reponse = this.moteur.monotone();
    etat.captured_at = this.moteur.murale();
  }
}
