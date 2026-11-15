// Supervision (CT-2 §17) : santé (`GET /healthz`, `/readyz`), métriques au
// format texte Prometheus (`GET /metrics`), pour ce qui touche le cœur :
// écrivain (`noortrace_events_total`, `noortrace_fsync_duration_ms`,
// `noortrace_fsync_group_size`, `noortrace_segment_bytes`,
// `noortrace_pending_events`), clé (`noortrace_sign_duration_ms`,
// contrôle `health()` du signataire), bail (`noortrace_lease_epoch`), mode
// dégradé (`noortrace_degraded{reason}`), horloge (`noortrace_clock_skew_ms`).
// Aucune étiquette ne porte un argument, un nom d'utilisateur, un ticket ou un
// nom d'hôte de client (17.2). Chaque métrique de la table de 17.2 et de celle
// de CT-5 EX-8.15 est déclarée (ligne `# TYPE`) dès le démarrage, série ou non.

import http from "node:http";

const BORNES_DEFAUT = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

function cleEtiquettes(etiquettes) {
  const noms = Object.keys(etiquettes).sort();
  return noms.map((n) => `${n}="${String(etiquettes[n]).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`).join(",");
}

/** Registre de métriques en mémoire, exposé au format texte Prometheus. */
export class Metriques {
  constructor() {
    /** @type {Map<string, {type: string, series: Map<string, any>, bornes?: number[]}>} */
    this.familles = new Map();
  }

  famille(nom, type, bornes) {
    let f = this.familles.get(nom);
    if (!f) {
      f = { type, series: new Map(), bornes };
      this.familles.set(nom, f);
    }
    return f;
  }

  /** Incrémente un compteur. */
  compter(nom, etiquettes = {}, n = 1) {
    const f = this.famille(nom, "counter");
    const c = cleEtiquettes(etiquettes);
    f.series.set(c, (f.series.get(c) ?? 0) + n);
  }

  /**
   * Déclare une famille et pose à 0 chaque combinaison d'étiquettes qui n'a pas
   * encore de série (CT-2 §17.2, CT-8 §10.3) : une règle `increase(x[w]) > 0`
   * voit ainsi la première occurrence, qu'une série née à 1 lui cacherait. Une
   * série déjà comptée n'est pas touchée ; sans combinaison, la famille est
   * déclarée (ligne `# TYPE`) sans série.
   * @param {string} nom
   * @param {"counter"|"gauge"} type
   * @param {Record<string, string>[]} combinaisons
   */
  declarer(nom, type, combinaisons) {
    const f = this.famille(nom, type);
    for (const e of combinaisons) {
      const c = cleEtiquettes(e);
      if (!f.series.has(c)) f.series.set(c, 0);
    }
  }

  /** Fixe une jauge. */
  jauge(nom, etiquettes = {}, valeur) {
    this.famille(nom, "gauge").series.set(cleEtiquettes(etiquettes), valeur);
  }

  /** Observe une valeur d'histogramme. */
  observer(nom, etiquettes = {}, valeur, bornes = BORNES_DEFAUT) {
    const f = this.famille(nom, "histogram", bornes);
    // Histogramme déclaré sans bornes : celles de sa première observation.
    if (!f.bornes) f.bornes = bornes;
    const c = cleEtiquettes(etiquettes);
    let s = f.series.get(c);
    if (!s) {
      s = { compte: 0, somme: 0, seaux: f.bornes.map(() => 0) };
      f.series.set(c, s);
    }
    s.compte++;
    s.somme += valeur;
    f.bornes.forEach((b, k) => {
      if (valeur <= b) s.seaux[k]++;
    });
  }

  /** Valeur d'un compteur ou d'une jauge (tests, santé). */
  valeur(nom, etiquettes = {}) {
    const f = this.familles.get(nom);
    if (!f) return undefined;
    const s = f.series.get(cleEtiquettes(etiquettes));
    return typeof s === "object" && s !== null ? s.compte : s;
  }

  /**
   * Exposition texte Prometheus.
   * @param {Set<string>} [sauf] familles sans série à ne pas écrire (déclarées par une autre exposition)
   */
  exposer(sauf = new Set()) {
    const lignes = [];
    for (const nom of [...this.familles.keys()].sort()) {
      const f = this.familles.get(nom);
      if (sauf.has(nom) && f.series.size === 0) continue;
      lignes.push(`# TYPE ${nom} ${f.type}`);
      for (const [c, v] of f.series) {
        const e = c ? `{${c}}` : "";
        if (f.type !== "histogram") {
          lignes.push(`${nom}${e} ${v}`);
          continue;
        }
        f.bornes.forEach((b, k) => lignes.push(`${nom}_bucket{${c ? c + "," : ""}le="${b}"} ${v.seaux[k]}`));
        lignes.push(`${nom}_bucket{${c ? c + "," : ""}le="+Inf"} ${v.compte}`);
        lignes.push(`${nom}_sum${e} ${v.somme}`);
        lignes.push(`${nom}_count${e} ${v.compte}`);
      }
    }
    return lignes.join("\n") + "\n";
  }
}

/** Produit cartésien de listes d'étiquettes : `[{a:[..]}, {b:[..]}]` → combinaisons. */
function combinaisons(dimensions) {
  let r = [{}];
  for (const [nom, valeurs] of Object.entries(dimensions)) {
    const suite = [];
    for (const base of r) for (const v of valeurs) suite.push({ ...base, [nom]: v });
    r = suite;
  }
  return r;
}

/** Raisons des modes dégradés et des pertes (17.2 : `noortrace_observation_would_block_total`, `noortrace_events_lost_total`). */
const RAISONS_BLOCAGE = Object.freeze(["approbation", "politique", "redaction", "quota", "stockage", "cle", "bail", "horloge", "attente"]);
/** Classes d'appel (CT-2 table 6.2). */
const CLASSES_APPEL = Object.freeze(["lecture", "ecriture"]);

/**
 * Métriques de la table de CT-2 §17.2 (45) et de celle de CT-5 EX-8.15 (9 de
 * plus, `noortrace_anchor_pending` étant commune), par nom et par type : le
 * démon les déclare toutes dès le démarrage, série ou non, de sorte qu'une
 * métrique d'une fonction absente (WORM, OpenTelemetry, composant d'ancrage
 * non branché) soit lue comme déclarée et vide, jamais comme inconnue. Le
 * composant d'ancrage, quand il est branché, expose les siennes (EX-8.15).
 */
export const METRIQUES_DEMON = Object.freeze([
  ["noortrace_events_total", "counter"],
  ["noortrace_relay_latency_ms", "histogram"],
  ["noortrace_upstream_latency_ms", "histogram"],
  ["noortrace_fsync_duration_ms", "histogram"],
  ["noortrace_fsync_group_size", "histogram"],
  ["noortrace_sign_duration_ms", "histogram"],
  ["noortrace_sse_first_byte_ms", "histogram"],
  ["noortrace_model_tokens_total", "counter"],
  ["noortrace_calls_blocked_total", "counter"],
  ["noortrace_approval_signals_total", "counter"],
  ["noortrace_approval_remises_refused_total", "counter"],
  ["noortrace_approval_relays_refused_total", "counter"],
  ["noortrace_redaction_budget_exceeded_total", "counter"],
  ["noortrace_otel_requests_total", "counter"],
  ["noortrace_otel_spans_total", "counter"],
  ["noortrace_otel_conflicts_total", "counter"],
  ["noortrace_otel_reception_lag_ms", "histogram"],
  ["noortrace_pending_events", "gauge"],
  ["noortrace_pending_oldest_ms", "gauge"],
  ["noortrace_degraded", "gauge"],
  ["noortrace_lease_epoch", "gauge"],
  ["noortrace_lease_renew_failures_total", "counter"],
  ["noortrace_redactions_total", "counter"],
  ["noortrace_pieces_bytes_total", "counter"],
  ["noortrace_segment_bytes", "gauge"],
  ["noortrace_tools_announced", "gauge"],
  ["noortrace_tools_rejected_total", "counter"],
  ["noortrace_tool_definition_changes_total", "counter"],
  ["noortrace_upstream_errors_total", "counter"],
  ["noortrace_anchor_pending", "gauge"],
  ["noortrace_worm_copy_pending", "gauge"],
  ["noortrace_worm_lock_checks_total", "counter"],
  ["noortrace_worm_lock_nonconforming", "gauge"],
  ["noortrace_worm_last_audit_age_s", "gauge"],
  ["noortrace_worm_versions_unexpected", "gauge"],
  ["noortrace_worm_legal_holds_active", "gauge"],
  ["noortrace_clock_skew_ms", "gauge"],
  ["noortrace_integrity_check_failures_total", "counter"],
  ["noortrace_ops_log_dropped_total", "counter"],
  ["noortrace_calls_executed_not_durable_total", "counter"],
  ["noortrace_build_info", "gauge"],
  ["noortrace_observation_mode", "gauge"],
  ["noortrace_observation_marks_total", "counter"],
  ["noortrace_observation_would_block_total", "counter"],
  ["noortrace_events_lost_total", "counter"],
  ["noortrace_anchoring_queue_entries", "gauge"],
  ["noortrace_anchoring_attempts_total", "counter"],
  ["noortrace_anchoring_last_success_age_s", "gauge"],
  ["noortrace_anchoring_deadlines_total", "counter"],
  ["noortrace_anchoring_window_s", "gauge"],
  ["noortrace_anchoring_d_jeton_s", "histogram"],
  ["noortrace_anchoring_d_point_s", "histogram"],
  ["noortrace_anchoring_d_registre_s", "histogram"],
  ["noortrace_anchoring_ots_pending_age_s", "gauge"],
].map((x) => Object.freeze(x)));

/**
 * Déclare, au démarrage du démon, chaque métrique de `METRIQUES_DEMON`
 * (ligne `# TYPE`, série ou non), puis pose à 0 les compteurs de CT-2 §17.2
 * dont les étiquettes sont énumérées par le texte ou par la configuration :
 * la première occurrence d'un événement rare (contrôle d'intégrité en échec,
 * relais refusé, appel relayé sans événement durable…) lève alors sa règle
 * d'alerte. Les compteurs dont une étiquette vient d'une valeur libre (code
 * HTTP, raison de rejet d'outil, portée de rédaction) n'ont pas de série
 * posée ; les séries de leurs valeurs connues des règles en ont une.
 * @param {Metriques} m
 * @param {object} config document de configuration validé
 */
export function declarerCompteursDemon(m, config) {
  for (const [nom, type] of METRIQUES_DEMON) m.declarer(nom, type, []);
  const serveurs = Object.keys(config?.policy?.servers ?? {});
  const sources = Object.keys(config?.policy?.otel?.sources ?? {});
  m.declarer("noortrace_integrity_check_failures_total", "counter", combinaisons({ check: ["relecture", "copie_worm", "configuration_worm", "registre_gels", "manifeste", "signature", "continuite", "signataire"] }));
  m.declarer("noortrace_worm_lock_checks_total", "counter", combinaisons({ verdict: ["conforme", "non_conforme"], when: ["copie", "releve"] }));
  m.declarer("noortrace_calls_executed_not_durable_total", "counter", combinaisons({ class: CLASSES_APPEL }));
  m.declarer("noortrace_approval_signals_total", "counter", combinaisons({ state: ["en_attente", "refuse", "expire"] }));
  m.declarer("noortrace_approval_remises_refused_total", "counter", combinaisons({ check: ["SG-1", "SG-2", "SG-3", "SG-4", "SG-5", "SG-6", "SG-7"] }));
  m.declarer("noortrace_approval_relays_refused_total", "counter", combinaisons({ check: ["RL-1", "RL-2", "RL-3", "RL-4", "retenue_decidee"] }));
  m.declarer("noortrace_observation_marks_total", "counter", combinaisons({ would: ["autorise", "a_approuver", "refuse", "inconnu"] }));
  m.declarer("noortrace_observation_would_block_total", "counter", combinaisons({ reason: RAISONS_BLOCAGE }));
  m.declarer("noortrace_events_lost_total", "counter", combinaisons({ reason: RAISONS_BLOCAGE }));
  m.declarer("noortrace_ops_log_dropped_total", "counter", [{}]);
  if (config?.lease?.store?.type) m.declarer("noortrace_lease_renew_failures_total", "counter", [{ store: config.lease.store.type }]);
  // Blocages que les règles nomment (rédaction, quota) : une série par classe.
  m.declarer("noortrace_calls_blocked_total", "counter", combinaisons({ code: ["-31010"], reason: ["redaction"], class: CLASSES_APPEL }));
  m.declarer("noortrace_calls_blocked_total", "counter", [{ code: "-31013", reason: "quota", class: "" }, { code: "503", reason: "quota", class: "modele" }]);
  for (const server of serveurs) {
    m.declarer("noortrace_tool_definition_changes_total", "counter", [{ server }]);
    m.declarer("noortrace_upstream_errors_total", "counter", combinaisons({ server: [server], kind: ["injoignable", "delai", "jsonrpc", "http_4xx", "http_5xx", "flux_incomplet"] }));
  }
  for (const source of sources) {
    m.declarer("noortrace_otel_conflicts_total", "counter", [{ source }]);
    m.declarer("noortrace_otel_spans_total", "counter", combinaisons({ source: [source], issue: ["scelle", "ignore", "doublon", "recouvrement", "rejete"], reason: ["hors_genai", "operation_non_retenue", "sorte_desactivee", "identifiants_invalides", ""] }));
  }
}

/**
 * Exposition de `/metrics` du démon : ses métriques, puis celles du composant
 * d'ancrage branché (CT-5 EX-8.15), sans écrire deux fois la ligne `# TYPE`
 * d'une famille que le composant déclare lui-même.
 * @param {Metriques} m
 * @param {string} [supplement] exposition du composant d'ancrage
 * @returns {string}
 */
export function exposerMetriquesDemon(m, supplement = "") {
  const noms = new Set();
  for (const l of supplement.split("\n")) {
    const t = /^# TYPE (\S+) /.exec(l);
    if (t) noms.add(t[1]);
  }
  return m.exposer(noms) + supplement;
}

/**
 * Corps de `GET /healthz` (EX-17.1) d'après l'état du cœur.
 * @param {{bailDetenu: boolean, passive?: boolean, raisons: string[], depuis: string|null, cleIndisponible: boolean}} etat
 * @returns {{statut: number, corps: object}}
 */
export function sante(etat) {
  if (etat.passive) return { statut: 200, corps: { status: "standby" } };
  if (!etat.bailDetenu || etat.cleIndisponible) {
    const raisons = [...etat.raisons];
    if (!etat.bailDetenu && !raisons.includes("bail")) raisons.push("bail");
    if (etat.cleIndisponible && !raisons.includes("cle")) raisons.push("cle");
    return { statut: 503, corps: { status: "down", reasons: raisons } };
  }
  if (etat.raisons.length) return { statut: 200, corps: { status: "degraded", reasons: etat.raisons, since: etat.depuis } };
  return { statut: 200, corps: { status: "ok" } };
}

/**
 * Serveur de supervision sur `supervision.health_listen` (local par défaut).
 * @param {{adresse: string, port: number, etat: () => object, pret: () => boolean, metriques: Metriques|null}} p
 * @returns {Promise<http.Server>}
 */
export function servirSupervision(p) {
  const serveur = http.createServer((req, res) => {
    if (req.method !== "GET") {
      res.writeHead(405).end();
      return;
    }
    if (req.url === "/healthz") {
      const { statut, corps } = sante(p.etat());
      res.writeHead(statut, { "content-type": "application/json" }).end(JSON.stringify(corps));
    } else if (req.url === "/readyz") {
      res.writeHead(p.pret() ? 200 : 503).end();
    } else if (req.url === "/metrics" && p.metriques) {
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end(p.metriques.exposer());
    } else {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve, reject) => {
    serveur.once("error", reject);
    serveur.listen(p.port, p.adresse, () => resolve(serveur));
  });
}
