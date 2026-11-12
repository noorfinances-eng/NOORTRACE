// Supervision de CT-5 §8.9 (EX-8.15) : métriques aux noms exacts de la table,
// dans l'espace de noms de CT-2 §17.2 (étiquettes en anglais, valeurs en
// français sans accent, jamais un nom d'hôte ni un identifiant de compte),
// exposées au format texte ; lignes du journal d'exploitation au format de
// CT-2 EX-9.5 par un `journal` injecté (celui de l'enregistreur). Aucune
// ligne ne porte un jeton, une pièce, un secret (AN-43).

import { decoderHorodatage } from "@noortrace/noyau";

/** Métriques d'EX-8.15 : nom → { type, etiquettes, aide }. */
export const METRIQUES_ANCRAGE = Object.freeze({
  noortrace_anchor_pending: { type: "gauge", etiquettes: ["anchor"], aide: "Periodes dont l'ancre n'est pas confirmee" },
  noortrace_anchoring_queue_entries: { type: "gauge", etiquettes: ["kind", "state"], aide: "Demandes de la file par sorte et par etat" },
  noortrace_anchoring_attempts_total: { type: "counter", etiquettes: ["kind", "provider", "outcome"], aide: "Tentatives et issues (CT-5 EX-5.13)" },
  noortrace_anchoring_last_success_age_s: { type: "gauge", etiquettes: ["kind", "provider"], aide: "Age du dernier obtenue" },
  noortrace_anchoring_deadlines_total: { type: "counter", etiquettes: ["state"], aide: "Echeances de points (CT-5 EX-4.3, EX-4.4)" },
  noortrace_anchoring_window_s: { type: "gauge", etiquettes: ["journal"], aide: "Age du dernier point ou manifeste contresigne par un prestataire exterieur" },
  noortrace_anchoring_d_jeton_s: { type: "histogram", etiquettes: ["kind", "provider"], aide: "d_jeton (CT-5 EX-5.11)" },
  noortrace_anchoring_d_point_s: { type: "histogram", etiquettes: [], aide: "d_point (CT-5 EX-3.5)" },
  noortrace_anchoring_d_registre_s: { type: "histogram", etiquettes: ["kind"], aide: "d_registre (CT-5 P-2)" },
  noortrace_anchoring_ots_pending_age_s: { type: "gauge", etiquettes: [], aide: "Age de la preuve en attente la plus ancienne" },
});

/** Bornes des histogrammes (secondes). */
export const BORNES_HISTOGRAMME = Object.freeze([1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 86400]);

/** Lignes du journal d'exploitation prescrites par EX-8.15. */
export const EVENEMENTS_JOURNAL = Object.freeze([
  "anchoring_started", "anchoring_stopped", "anchoring_queue_rebuilt", "anchor_pending", "registry_pending", "checkpoint_countersigned",
  "checkpoint_closing_fallback", "point_manquant", "checkpoint_not_anchored", "checkpoint_anchor_late", "deadline_sans_objet", "period_timestamped",
  "anchor_retry", "anchor_fallback", "anchor_response_rejected", "anchor_replaced", "anchor_refused", "ots_submitted", "ots_upgraded", "ots_complete",
  "anchor_queue_full", "anchor_queue_write_failed", "anchor_queue_truncated_line", "anchor_duplicate_ignored", "ordre_ancres_non_respecte",
  // Révision 0.6 (EX-8.5, règle 5) :
  "anchor_queue_compacted", "anchor_queue_compaction_failed",
]);

/** Lignes qui rendent compte d'une tentative : elles portent son rang `n` (`attempt`) et son `attempt_id` (EX-8.15, révision 0.6). */
export const EVENEMENTS_TENTATIVE = Object.freeze(["anchor_retry", "anchor_fallback", "anchor_response_rejected"]);

/** Clés qui ne vont jamais dans une ligne du journal (AN-43, CT-2 EX-9.6). */
const CLES_INTERDITES = new Set(["token", "jeton", "secret", "password", "mot_de_passe", "authorization", "cookie", "piece", "proof", "preuve", "der", "ots", "private_key", "cle_privee", "account", "compte", "url"]);
const MOTIF_ETIQUETTE = /^[a-z_][a-z0-9_]*$/;
const MOTIF_VALEUR = /^[a-z0-9_:.-]*$/;
/** Borne par défaut des lignes gardées en mémoire (`Supervision.lignes`, correction R-F-5). */
export const MAX_LIGNES_DEFAUT = 10000;

/**
 * Valeur d'étiquette normalisée (EX-8.15 : valeurs en français sans accent,
 * minuscules) : les majuscules sont abaissées et tout caractère hors du motif
 * `[a-z0-9_:.-]` remplacé par `_` ; un identifiant de prestataire tel que
 * `TSA-Interne` (admis par le schéma `ancrage-v0`) ne fait plus lever la
 * métrique (correction R-F-2).
 */
export function normaliserValeurEtiquette(valeur) {
  const texte = String(valeur).toLowerCase();
  if (MOTIF_VALEUR.test(texte)) return texte;
  return [...texte].map((c) => (/[a-z0-9_:.-]/.test(c) ? c : "_")).join("");
}
const PREFIXE_EVENEMENT = /^[a-z][a-zA-Z0-9_-]{0,63}$/;

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const cleSerie = (etiquettes) => JSON.stringify(Object.keys(etiquettes).sort().map((k) => [k, etiquettes[k]]));

/**
 * Supervision du composant d'ancrage : métriques et journal.
 */
export class Supervision {
  /**
   * @param {{journal?: {consigner: (niveau: string, composant: string, evenement: string, data: object) => unknown}|null,
   *   horloge?: {murale: () => number}|null, composant?: string, prestatairesExterieurs?: string[], journalAbrege?: string,
   *   maxLignes?: number}} [options] `maxLignes` : lignes gardées en mémoire (les plus anciennes écartées, `dropped` compté)
   */
  constructor(options = {}) {
    this.journal = options.journal ?? null;
    this.horloge = options.horloge ?? null;
    this.composant = options.composant ?? "ancrage";
    this.prestatairesExterieurs = new Set(options.prestatairesExterieurs ?? []);
    this.journalAbrege = options.journalAbrege ?? "journal";
    this.maxLignes = Number.isSafeInteger(options.maxLignes) && options.maxLignes >= 0 ? options.maxLignes : MAX_LIGNES_DEFAUT;
    /** @type {Map<string, Map<string, {etiquettes: object, valeur: number, bornes?: Map<number, number>, somme?: number, nombre?: number}>>} */
    this.series = new Map();
    this.lignes = [];
    /** Lignes écartées de la fenêtre mémoire (toutes ont été remises au journal injecté). */
    this.dropped = 0;
    for (const nom of Object.keys(METRIQUES_ANCRAGE)) this.series.set(nom, new Map());
  }

  #serie(nom, etiquettes) {
    const def = METRIQUES_ANCRAGE[nom];
    if (!def) throw new RangeError(`métrique inconnue : ${nom}`);
    const propres = {};
    for (const e of def.etiquettes) {
      const v = etiquettes[e];
      if (v === undefined || v === null) throw new TypeError(`métrique ${nom} : étiquette ${e} manquante`);
      propres[e] = normaliserValeurEtiquette(v);
    }
    for (const k of Object.keys(etiquettes)) if (!def.etiquettes.includes(k)) throw new TypeError(`métrique ${nom} : étiquette ${k} hors de la table d'EX-8.15`);
    const table = this.series.get(nom);
    const k = cleSerie(propres);
    let s = table.get(k);
    if (!s) {
      s = { etiquettes: propres, valeur: 0 };
      if (def.type === "histogram") {
        s.bornes = new Map(BORNES_HISTOGRAMME.map((b) => [b, 0]));
        s.somme = 0;
        s.nombre = 0;
      }
      table.set(k, s);
    }
    return s;
  }

  /** Fixe une jauge. */
  jauge(nom, etiquettes, valeur) {
    if (METRIQUES_ANCRAGE[nom]?.type !== "gauge") throw new RangeError(`${nom} n'est pas une jauge`);
    this.#serie(nom, etiquettes).valeur = valeur;
  }

  /** Incrémente un compteur. */
  compter(nom, etiquettes, increment = 1) {
    if (METRIQUES_ANCRAGE[nom]?.type !== "counter") throw new RangeError(`${nom} n'est pas un compteur`);
    if (!Number.isFinite(increment) || increment < 0) throw new RangeError("incrément non négatif attendu");
    this.#serie(nom, etiquettes).valeur += increment;
  }

  /** Observe une valeur d'histogramme. */
  observer(nom, etiquettes, valeur) {
    if (METRIQUES_ANCRAGE[nom]?.type !== "histogram") throw new RangeError(`${nom} n'est pas un histogramme`);
    const s = this.#serie(nom, etiquettes);
    for (const b of BORNES_HISTOGRAMME) if (valeur <= b) s.bornes.set(b, s.bornes.get(b) + 1);
    s.somme += valeur;
    s.nombre += 1;
  }

  /**
   * Met à jour les métriques depuis une liste d'actions du planificateur et
   * l'état de sa file (une passe par entrée traitée).
   * @param {{actions?: object[], file?: object[], maintenant?: number}} p `maintenant` en ms UTC (sinon l'horloge injectée)
   */
  releverActions({ actions = [], file = null, maintenant = null }) {
    for (const a of actions) {
      if (a.action === "echeance" && a.detail.state !== "ouverte") this.compter("noortrace_anchoring_deadlines_total", { state: a.detail.state });
      if (a.action === "envoyer_rfc3161") this.compter("noortrace_anchoring_attempts_total", { kind: a.request_id.split(":")[0], provider: a.detail.provider, outcome: "en_cours" });
      if (a.action === "rejeter_reponse") this.compter("noortrace_anchoring_attempts_total", { kind: a.request_id.split(":")[0], provider: "inconnu", outcome: a.detail.class === "permanente" ? "echec_permanente" : "echec_transitoire" });
      if (a.action === "journaliser") {
        const d = a.detail;
        if (d.event === "checkpoint_countersigned") {
          this.observer("noortrace_anchoring_d_jeton_s", { kind: "jeton_point", provider: d.provider }, d.d_jeton_s);
          this.observer("noortrace_anchoring_d_point_s", {}, d.d_point_s);
          this.compter("noortrace_anchoring_attempts_total", { kind: "jeton_point", provider: d.provider, outcome: "obtenue" });
        }
        if (d.event === "period_timestamped") {
          this.observer("noortrace_anchoring_d_jeton_s", { kind: "jeton_periode", provider: d.provider }, d.d_jeton_s);
          this.compter("noortrace_anchoring_attempts_total", { kind: "jeton_periode", provider: d.provider, outcome: "obtenue" });
        }
        if (d.event === "anchor_response_rejected" && d.provider) this.compter("noortrace_anchoring_attempts_total", { kind: a.request_id.split(":")[0], provider: d.provider, outcome: d.error_code === "reponse_tardive" ? "reponse_tardive" : "rejetee" });
      }
    }
    if (file) {
      // d_registre (EX-8.15) : une observation par ancre, à la passe où elle
      // devient obtenue (action `ecrire_file`), jamais aux passes suivantes ni à
      // la relecture d'une file (étape 7 : défaut relevé par l'écriture des règles d'alerte).
      const parId = new Map(file.map((d) => [d.id, d]));
      for (const a of actions) {
        if (a.action !== "ecrire_file" || a.detail?.state !== "obtenue" || !a.request_id?.startsWith("ancre_registre")) continue;
        const d = parId.get(a.request_id);
        if (!d?.result) continue;
        const t = decoderHorodatage(d.result.obtained_at);
        const declare = decoderHorodatage(d.subject.declared_at);
        if (t !== null && declare !== null) this.observer("noortrace_anchoring_d_registre_s", { kind: d.kind }, Math.max(0, Math.trunc((t - declare) / 1000)));
      }
      this.releverFile(file, maintenant ?? this.horloge?.murale() ?? null);
    }
  }

  /**
   * Jauges tirées de l'état de la file : demandes par sorte et état, ancres de
   * périodes non confirmées, âge du dernier succès, fenêtre de date, âge de la
   * preuve en attente la plus ancienne (`d_registre` est observé par
   * `releverActions`, au passage de chaque ancre à `obtenue`).
   * @param {object[]} file
   * @param {number|null} maintenant ms UTC
   */
  releverFile(file, maintenant) {
    const comptes = new Map();
    const pending = { registre: new Set(), rfc3161: new Set(), ots: new Set() };
    const derniers = new Map();
    let plusVieillePreuve = null;
    let borneExterieure = null;
    for (const d of file) {
      const k = `${d.kind}|${d.state}`;
      comptes.set(k, (comptes.get(k) ?? 0) + 1);
      const finale = ["obtenue", "complete", "sans_objet", "refusee", "remplacee"].includes(d.state);
      if (d.subject.kind === "periode" && !finale && !(d.kind === "ots_periode" && d.state === "en_attente")) {
        const anchor = d.kind.startsWith("ancre_registre") ? "registre" : d.kind.startsWith("jeton") ? "rfc3161" : "ots";
        pending[anchor].add(d.subject.period_start);
      }
      if (d.result && (d.state === "obtenue" || d.state === "complete" || d.state === "en_attente")) {
        const t = decoderHorodatage(d.result.obtained_at);
        const cleDernier = `${d.kind}|${d.result.provider ?? "aucun"}`;
        if (t !== null && (derniers.get(cleDernier) ?? -1) < t) derniers.set(cleDernier, t);
        if (d.kind.startsWith("jeton") && d.state === "obtenue" && d.result.bound && this.prestatairesExterieurs.has(d.result.provider)) {
          const b = decoderHorodatage(d.result.bound);
          if (b !== null && (borneExterieure === null || b > borneExterieure)) borneExterieure = b;
        }
      }
      if (d.kind.startsWith("ots") && d.state === "en_attente" && d.result) {
        const t = decoderHorodatage(d.result.obtained_at);
        if (t !== null && (plusVieillePreuve === null || t < plusVieillePreuve)) plusVieillePreuve = t;
      }
    }
    for (const [k, n] of comptes) {
      const [kind, state] = k.split("|");
      this.jauge("noortrace_anchoring_queue_entries", { kind, state }, n);
    }
    for (const anchor of ["registre", "rfc3161", "ots"]) this.jauge("noortrace_anchor_pending", { anchor }, pending[anchor].size);
    if (maintenant !== null) {
      for (const [k, t] of derniers) {
        const [kind, provider] = k.split("|");
        this.jauge("noortrace_anchoring_last_success_age_s", { kind, provider }, Math.max(0, Math.trunc((maintenant - t) / 1000)));
      }
      this.jauge("noortrace_anchoring_ots_pending_age_s", {}, plusVieillePreuve === null ? 0 : Math.max(0, Math.trunc((maintenant - plusVieillePreuve) / 1000)));
      if (borneExterieure !== null) this.jauge("noortrace_anchoring_window_s", { journal: this.journalAbrege }, Math.max(0, Math.trunc((maintenant - borneExterieure) / 1000)));
    }
  }

  /**
   * Format d'exposition texte (une famille par métrique : `# HELP`, `# TYPE`,
   * puis les séries ; histogrammes en `_bucket`, `_sum`, `_count`).
   * @returns {string}
   */
  metriques() {
    const lignes = [];
    const etiquettesTexte = (e) => {
      const parts = Object.entries(e).map(([k, v]) => `${k}="${v}"`);
      return parts.length ? `{${parts.join(",")}}` : "";
    };
    for (const [nom, def] of Object.entries(METRIQUES_ANCRAGE)) {
      lignes.push(`# HELP ${nom} ${def.aide}`);
      lignes.push(`# TYPE ${nom} ${def.type}`);
      for (const s of this.series.get(nom).values()) {
        if (def.type === "histogram") {
          for (const b of BORNES_HISTOGRAMME) lignes.push(`${nom}_bucket${etiquettesTexte({ ...s.etiquettes, le: String(b) })} ${s.bornes.get(b)}`);
          lignes.push(`${nom}_bucket${etiquettesTexte({ ...s.etiquettes, le: "+Inf" })} ${s.nombre}`);
          lignes.push(`${nom}_sum${etiquettesTexte(s.etiquettes)} ${s.somme}`);
          lignes.push(`${nom}_count${etiquettesTexte(s.etiquettes)} ${s.nombre}`);
        } else {
          lignes.push(`${nom}${etiquettesTexte(s.etiquettes)} ${s.valeur}`);
        }
      }
    }
    return lignes.join("\n") + "\n";
  }

  /**
   * Consigne une ligne d'EX-8.15 par le journal injecté (format de CT-2
   * EX-9.5 : `ts`, `level`, `component`, `event`, `data`). Refuse toute clé ou
   * valeur qui ressemble à un jeton, une pièce ou un secret (AN-43).
   * @param {"debug"|"info"|"warning"|"error"} niveau
   * @param {string} evenement
   * @param {object} [champs]
   * @returns {object} la ligne consignée
   */
  consigner(niveau, evenement, champs = {}) {
    if (!["debug", "info", "warning", "error"].includes(niveau)) throw new RangeError(`niveau inconnu : ${String(niveau)}`);
    if (typeof evenement !== "string" || !PREFIXE_EVENEMENT.test(evenement)) throw new RangeError(`événement mal formé : ${String(evenement)}`);
    if (!estObjet(champs)) throw new TypeError("champs : objet attendu");
    const data = {};
    for (const [k, v] of Object.entries(champs)) {
      if (!MOTIF_ETIQUETTE.test(k) || CLES_INTERDITES.has(k)) throw new TypeError(`champ ${k} refusé dans le journal d'exploitation (AN-43)`);
      if (typeof v === "string" && (v.length > 512 || /^-----BEGIN/.test(v))) throw new TypeError(`champ ${k} : valeur refusée dans le journal (longueur ou pièce)`);
      if (v instanceof Uint8Array) throw new TypeError(`champ ${k} : octets refusés dans le journal`);
      data[k] = v;
    }
    const ligne = { level: niveau, component: this.composant, event: evenement, data };
    if (this.horloge) ligne.ts = new Date(this.horloge.murale()).toISOString();
    this.lignes.push(ligne);
    while (this.lignes.length > this.maxLignes) {
      this.lignes.shift();
      this.dropped += 1;
    }
    if (this.journal) this.journal.consigner(niveau, this.composant, evenement, data);
    return ligne;
  }

  /**
   * Consigne les actions `journaliser` et `alerter` d'une passe du planificateur.
   * @param {object[]} actions
   */
  consignerActions(actions) {
    for (const a of actions) {
      if (a.action === "journaliser") {
        const { event, ...reste } = a.detail;
        const niveau = ["anchor_queue_full", "anchor_queue_write_failed", "anchor_queue_truncated_line", "anchor_refused"].includes(event) ? "error" :
          ["checkpoint_anchor_late", "point_manquant", "anchor_response_rejected", "anchor_fallback", "anchor_retry", "registry_pending", "anchor_pending", "ordre_ancres_non_respecte", "anchor_duplicate_ignored"].includes(event) ? "warning" : "info";
        this.consigner(niveau, event, { request_id: a.request_id, at: a.t, ...reste });
      } else if (a.action === "alerter") {
        this.consigner(a.detail.severity === "critique" ? "error" : "warning", `alerte_${a.detail.code}`, { request_id: a.request_id, at: a.t, severity: a.detail.severity });
      }
    }
  }
}
