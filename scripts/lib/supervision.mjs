// Supervision de référence de NOORTRACE (CT-8 §10) : règles d'alerte au
// format de Prometheus (EX-10.1, EX-10.2, EX-10.6), extracteur des journaux
// (10.3, EX-10.5), tests des règles au format de `promtool test rules`
// (EX-10.10), configuration de collecte (EX-10.4) et tableau de bord
// (EX-10.8). Fonctions pures : ni réseau, ni horloge lue, ni fichier écrit ;
// les outils de scripts/deploiement/ (regles.mjs, extraire-journaux.mjs,
// sonde.mjs) font les entrées et sorties.
//
// Noms lus dans le code des paquets (écart E-10 de l'inventaire de l'étape
// 7) : là où les tables de CT-8 §10.3 à §10.7 nomment une ligne ou un membre
// que le code ne consigne pas sous ce nom, la règle et l'extracteur suivent
// le code et la différence est listée dans ECARTS_CT8 (chaque entrée est une
// demande de révision de CT-8).
//
// Aucune valeur exposée n'est tirée d'une pièce, d'un argument ou d'un
// identifiant de compte : les valeurs d'étiquette viennent des tables
// ci-dessous ou de membres énumérés des lignes, refusés (valeur vide) hors du
// motif VALEUR_SURE.

/** Version du format des fichiers écrits par ce module. */
export const VERSION_SUPERVISION = "0.1.0";

// ---------------------------------------------------------------------------
// Paramètres des règles (EX-10.6)
// ---------------------------------------------------------------------------

/**
 * Bornes des histogrammes `noortrace_anchoring_d_*_s` exposées par le
 * composant d'ancrage (`paquets/ancrage/src/planificateur/supervision.mjs`,
 * BORNES_HISTOGRAMME). CT-8 §10.5 fixe 1 à 7 200 s ; le code ajoute 86 400.
 * `registry.inclusion_alert_s` doit être l'une d'elles pour que la règle
 * d'inclusion lente s'exprime.
 */
export const BORNES_D_REGISTRE = Object.freeze([1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 86400]);

/**
 * Budget journalier de gaz de référence d'une clé de chaîne qui tient un
 * journal horaire (CT-4 EX-4.19 : 24 × (100 000 + 350 000)).
 */
export const BUDGET_JOURNALIER_GAZ_DEFAUT = 24 * (100000 + 350000);

/**
 * Valeurs de référence : défauts des spécifications (EX-10.6), racine du
 * modèle de production (`deploiement/config/modele-production`), `<A_h>`
 * de l'exemple de CT-8 §9.5 (665 760 requêtes par an / 8 760 h), `<S>` de
 * l'exemple de CT-4 EX-4.19 (7 jours, `gas_limit` 3 000 000), `<RPO>` d'un
 * jour (EX-11.24) et `<M>` sur l'hypothèse `-txpool-max-pending` = 4 096,
 * non vérifiée (noorcore n'imprime pas son défaut ; TM-35 la mesure).
 */
export const PARAMETRES_DEFAUT = Object.freeze({
  pending_max_ms: 300000,
  warn_skew_ms: 1000,
  lock_audit_interval_days: 30,
  min_free_bytes: 1073741824,
  storage_root: "/var/lib/noortrace",
  anchor_pending_alert_s: 7200,
  inclusion_alert_s: 60,
  give_up_after_s: 1209600,
  requetes_ancrage_par_heure: 76,
  txpool_max_pending: 4096,
  refill_below_days: 7,
  gas_limit: 3000000,
  budget_journalier_gaz: BUDGET_JOURNALIER_GAZ_DEFAUT,
  rpo_s: 86400,
});

const estEntier = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;

/** Erreur d'un document d'entrée de genererRegles (code 1 de regles.mjs). */
export class ErreurParametres extends Error {}

function lireEntier(doc, chemin, min, max, quoi) {
  let v = doc;
  for (const k of chemin) {
    if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
    v = v[k];
  }
  if (v === undefined) return undefined;
  if (!estEntier(v, min, max)) throw new ErreurParametres(`${quoi} : ${chemin.join(".")} doit être un entier de ${min} à ${max}`);
  return v;
}

/** Arrondi à trois décimales (demi vers le haut pour une valeur positive). */
const arrondi3 = (x) => Math.round(x * 1000) / 1000;

/**
 * Requêtes d'ancrage nominales par heure d'un journal (`<A_h>`, CT-8 §10.5) :
 * (`tokens_qualified_per_year` + `tokens_other_per_year` +
 * `ots_submissions_per_year` + `registry_anchors_per_year_max` +
 * `registry_closures_per_year`) / `hours_per_year`, le plus grand des
 * journaux de la sortie du calculateur (section 9).
 * @param {{entrees: object, sortie: object}} d
 */
export function requetesAncrageParHeure(d) {
  const heures = d?.entrees?.hours_per_year;
  if (!estEntier(heures, 1, 100000)) throw new ErreurParametres("dimensionnement : hours_per_year absent ou invalide");
  const journaux = d?.sortie?.journals;
  if (!Array.isArray(journaux) || journaux.length === 0) throw new ErreurParametres("dimensionnement : sortie du calculateur sans journals");
  let max = 0;
  for (const j of journaux) {
    const membres = ["tokens_qualified_per_year", "tokens_other_per_year", "ots_submissions_per_year", "registry_anchors_per_year_max", "registry_closures_per_year"];
    let s = 0;
    for (const m of membres) {
      if (!Number.isSafeInteger(j[m]) || j[m] < 0) throw new ErreurParametres(`dimensionnement : ${j.id ?? "journal"}.${m} invalide`);
      s += j[m];
    }
    max = Math.max(max, s / heures);
  }
  return arrondi3(max);
}

/**
 * Paramètres des règles tirés des documents du client (EX-10.6). Chaque
 * membre absent garde sa valeur de PARAMETRES_DEFAUT.
 * @param {{configuration?: object|null, ancrage?: object|null, instance?: object|null,
 *   dimensionnement?: {entrees: object, sortie: object}|null, txpool_max_pending?: number|null, rpo_s?: number|null}} [docs]
 */
export function parametresRegles(docs = {}) {
  const p = { ...PARAMETRES_DEFAUT };
  const c = docs.configuration ?? null;
  if (c !== null) {
    if (typeof c !== "object" || Array.isArray(c)) throw new ErreurParametres("configuration : objet attendu");
    const fixer = (cle, v) => { if (v !== undefined) p[cle] = v; };
    fixer("pending_max_ms", lireEntier(c, ["policy", "failure", "pending_max_ms"], 0, 86400000, "configuration"));
    fixer("warn_skew_ms", lireEntier(c, ["clock", "warn_skew_ms"], 0, 86400000, "configuration"));
    fixer("lock_audit_interval_days", lireEntier(c, ["storage", "seal", "worm", "lock_audit_interval_days"], 1, 366, "configuration"));
    fixer("min_free_bytes", lireEntier(c, ["storage", "min_free_bytes"], 1024, 1099511627776, "configuration"));
    const root = c.storage?.root;
    if (root !== undefined) {
      if (typeof root !== "string" || !/^\/[^\u0000"\\\n]{1,4095}$/.test(root)) throw new ErreurParametres("configuration : storage.root invalide");
      p.storage_root = root.length > 1 ? root.replace(/\/+$/, "") : root;
    }
  }
  const a = docs.ancrage ?? null;
  if (a !== null) {
    if (typeof a !== "object" || Array.isArray(a)) throw new ErreurParametres("ancrage : objet attendu");
    const fixer = (cle, v) => { if (v !== undefined) p[cle] = v; };
    fixer("anchor_pending_alert_s", lireEntier(a, ["queue", "anchor_pending_alert_s"], 60, 604800, "ancrage"));
    fixer("inclusion_alert_s", lireEntier(a, ["registry", "inclusion_alert_s"], 1, 3600, "ancrage"));
    fixer("give_up_after_s", lireEntier(a, ["opentimestamps", "upgrade", "give_up_after_s"], 3600, 7776000, "ancrage"));
  }
  if (!BORNES_D_REGISTRE.includes(p.inclusion_alert_s)) {
    throw new ErreurParametres(`ancrage : registry.inclusion_alert_s = ${p.inclusion_alert_s} n'est pas une borne de noortrace_anchoring_d_registre_s (${BORNES_D_REGISTRE.join(", ")}) : la règle d'inclusion lente ne peut pas s'exprimer`);
  }
  const i = docs.instance ?? null;
  if (i !== null) {
    if (typeof i !== "object" || Array.isArray(i)) throw new ErreurParametres("instance : objet attendu");
    const r = lireEntier(i, ["fees", "refill_below_days"], 1, 366, "instance");
    const g = lireEntier(i, ["fees", "gas_limit"], 1000000, 16777216, "instance");
    if (r !== undefined) p.refill_below_days = r;
    if (g !== undefined) p.gas_limit = g;
  }
  if (docs.dimensionnement != null) p.requetes_ancrage_par_heure = requetesAncrageParHeure(docs.dimensionnement);
  if (docs.txpool_max_pending != null) {
    if (!estEntier(docs.txpool_max_pending, 2, 1e9)) throw new ErreurParametres("txpool_max_pending : entier de 2 à 10^9 attendu");
    p.txpool_max_pending = docs.txpool_max_pending;
  }
  if (docs.rpo_s != null) {
    if (!estEntier(docs.rpo_s, 60, 31622400)) throw new ErreurParametres("rpo_s : entier de 60 à 31 622 400 attendu");
    p.rpo_s = docs.rpo_s;
  }
  return p;
}

/** Seuils dérivés des paramètres, tels que les expressions les écrivent. */
export function seuils(p) {
  return {
    attente: Math.floor(p.pending_max_ms / 2),
    releve: 2 * p.lock_audit_interval_days * 86400,
    horloge: p.warn_skew_ms,
    racine: p.storage_root,
    disque: 2 * p.min_free_bytes,
    ancre_for: duree(p.anchor_pending_alert_s),
    inclusion: p.inclusion_alert_s,
    ots: p.give_up_after_s,
    a_h: p.requetes_ancrage_par_heure,
    mempool: Math.floor(p.txpool_max_pending / 2),
    solde: p.refill_below_days * p.budget_journalier_gaz + p.gas_limit,
    rpo: p.rpo_s,
  };
}

/** Durée de Prometheus : en heures si elle en est un multiple, sinon en secondes (forme des tables de CT-8). */
export function duree(s) {
  return s % 3600 === 0 ? `${s / 3600}h` : `${s}s`;
}

// ---------------------------------------------------------------------------
// Règles (CT-8 §10.4 à §10.7, et EX-10.9 : proposition PD-28 de CT-9)
// ---------------------------------------------------------------------------

/** Énumérations d'EX-10.2. */
export const GRAVITES = Object.freeze(["critique", "majeure", "mineure"]);
export const COMPOSANTS = Object.freeze(["enregistreur", "ancrage", "approbation", "registre", "hote", "exploitation"]);
export const ETIQUETTES_REGLE = Object.freeze(["severity", "component", "exigence", "runbook"]);
export const ANNOTATIONS_REGLE = Object.freeze(["summary", "description"]);

const LJ = "noortrace_journal_lignes_total";

/**
 * Une entrée par règle, dans l'ordre des tables : groupe (section de CT-8),
 * nom, expression (fonction des seuils), clause `for` (fonction ou null),
 * gravité, composant, exigence (texte de la colonne, sans accents graves),
 * runbook, résumé. `ecart` nomme l'entrée d'ECARTS_CT8 quand l'expression
 * diffère de celle de la table.
 */
export const REGLES = Object.freeze([
  // §10.4 Règles de l'enregistreur
  ["10.4", "noortrace_mode_degrade_critique", () => 'max by (instance, reason) (noortrace_degraded{reason=~"cle|bail|horloge"}) == 1', "60s", "critique", "enregistreur", "CT-2 §17.4 Mode dégradé", "RB-1, RB-2, RB-6, RB-8", "Mode dégradé pour la clé, le bail ou l'horloge"],
  ["10.4", "noortrace_mode_degrade_majeur", () => 'max by (instance, reason) (noortrace_degraded{reason=~"stockage|attente|approbation"}) == 1', "60s", "majeure", "enregistreur", "CT-2 §17.4 Mode dégradé", "RB-1", "Mode dégradé pour le stockage, l'attente ou l'approbation"],
  ["10.4", "noortrace_mode_degrade_serveur", () => 'max by (instance, reason) (noortrace_degraded{reason=~"serveur:.*"}) == 1', "60s", "mineure", "enregistreur", "CT-2 §17.4 Mode dégradé", "aucun", "Serveur d'outils injoignable"],
  ["10.4", "noortrace_appels_bloques", () => "rate(noortrace_calls_blocked_total[5m]) > 0", null, "majeure", "enregistreur", "CT-2 §17.4 Appels bloqués", "RB-1", "Appels bloqués par l'enregistreur"],
  ["10.4", "noortrace_attente_non_vide", () => "noortrace_pending_events > 0", "300s", "majeure", "enregistreur", "CT-2 §17.4 Événements en attente", "RB-1", "Événements en attente depuis cinq minutes"],
  ["10.4", "noortrace_attente_ancienne", (s) => `noortrace_pending_oldest_ms > ${s.attente}`, null, "majeure", "enregistreur", "CT-2 §17.4 Événements en attente", "RB-1", "Plus ancien événement en attente au-delà de la moitié de pending_max_ms"],
  ["10.4", "noortrace_bail_non_detenu", () => 'noortrace_lease_epoch{role="active"} == 0', null, "critique", "enregistreur", "CT-2 §17.4 Bail", "RB-2", "Bail non détenu par l'instance attendue active"],
  ["10.4", "noortrace_bail_renouvellement", () => "increase(noortrace_lease_renew_failures_total[5m]) > 0", null, "critique", "enregistreur", "CT-2 §17.4 Bail", "RB-2", "Échec de renouvellement du bail"],
  ["10.4", "noortrace_ancre_en_retard", () => "noortrace_anchor_pending > 0", (s) => s.ancre_for, "majeure", "enregistreur", "CT-2 §17.4 Ancre en retard ; CT-5 §8.9 « ancre en retard »", "RB-3", "Ancre de période non confirmée au-delà de queue.anchor_pending_alert_s"],
  ["10.4", "noortrace_copie_worm_en_retard", () => "noortrace_worm_copy_pending > 0", "1h", "majeure", "enregistreur", "CT-2 §17.4 Copie WORM en retard", "RB-5", "Copie WORM en retard depuis une heure"],
  ["10.4", "noortrace_verrou_worm_non_conforme", () => "noortrace_worm_lock_nonconforming > 0", null, "critique", "enregistreur", "CT-2 §17.4 Verrou WORM non conforme", "RB-5", "Version du support WORM au verrou non conforme"],
  ["10.4", "noortrace_retention_support_non_conforme", () => `increase(${LJ}{event="worm_lock_config_check",detail="non_conforme"}[1d]) > 0`, null, "critique", "enregistreur", "CT-2 §17.4 Verrou WORM non conforme", "RB-5", "Configuration de rétention du support WORM non conforme"],
  ["10.4", "noortrace_releve_en_retard", (s) => `noortrace_worm_last_audit_age_s > ${s.releve}`, null, "majeure", "enregistreur", "CT-2 §17.4 Relevé de verrouillage en retard", "RB-5", "Relevé de verrouillage plus vieux que deux intervalles"],
  ["10.4", "noortrace_versions_inattendues", () => "noortrace_worm_versions_unexpected > 0", null, "majeure", "enregistreur", "CT-2 §17.4 Versions inattendues", "RB-5", "Versions inattendues sur le support WORM"],
  ["10.4", "noortrace_registre_gels_invalide", () => `increase(${LJ}{event="worm_legal_hold_observed",detail="garde_violee"}[1d]) > 0`, null, "critique", "enregistreur", "CT-2 §17.4 Registre des gels invalide", "RB-5", "Registre des gels qui viole la règle de garde"],
  ["10.4", "noortrace_gel_non_pose", () => `increase(${LJ}{event="worm_lock_check",detail="gel_absent"}[1d]) > 0`, null, "critique", "enregistreur", "CT-2 §17.4 Gel non posé sur une version d'un gel actif", "RB-5", "Gel attendu absent sur une version d'un gel actif"],
  ["10.4", "noortrace_controle_integrite", () => 'increase(noortrace_integrity_check_failures_total{check!="configuration_worm"}[1h]) > 0', null, "critique", "enregistreur", "CT-2 §17.4 Contrôle d'intégrité en échec", "RB-1, RB-5", "Contrôle d'intégrité en échec"],
  ["10.4", "noortrace_gel_leve", () => `increase(${LJ}{event="worm_legal_hold_observed",detail="levee"}[1d]) > 0`, null, "mineure", "enregistreur", "CT-2 §17.4 Gel levé", "aucun", "Gel juridique levé (rapprocher d'EX-11.16)"],
  ["10.4", "noortrace_horloge_ecart", (s) => `abs(noortrace_clock_skew_ms) > ${s.horloge}`, null, "mineure", "enregistreur", "CT-2 §17.4 Horloge", "RB-6", "Écart d'horloge au-delà de clock.warn_skew_ms"],
  ["10.4", "noortrace_definition_outil_changee", () => "increase(noortrace_tool_definition_changes_total[1h]) > 0", null, "mineure", "enregistreur", "CT-2 §17.4 Définition d'outil changée", "aucun", "Définition d'un outil changée"],
  ["10.4", "noortrace_fourche", () => `increase(${LJ}{event="journal_fork"}[5m]) > 0`, null, "critique", "enregistreur", "CT-2 §17.4 Fourche", "RB-2", "Fourche du journal"],
  ["10.4", "noortrace_panne_apres_relais", () => "increase(noortrace_calls_executed_not_durable_total[5m]) > 0", null, "critique", "enregistreur", "CT-2 §17.4 Panne après relais", "RB-1", "Appel exécuté sans événement durable"],
  ["10.4", "noortrace_relais_refuse", () => "increase(noortrace_approval_relays_refused_total[5m]) > 0", null, "critique", "enregistreur", "CT-2 §17.4 Relais refusé ou identifiant en collision", "RB-8", "Relais d'approbation refusé"],
  ["10.4", "noortrace_remise_refusee", () => "increase(noortrace_approval_remises_refused_total[1h]) > 0", null, "majeure", "enregistreur", "CT-2 §17.4 Remise refusée", "RB-8", "Remise d'approbation refusée"],
  ["10.4", "noortrace_politique_invalide_au_charger", () => `increase(${LJ}{event="approval_service_unavailable",detail="politique_invalide_au_charger"}[1h]) > 0`, null, "majeure", "enregistreur", "CT-2 §17.4 Remise refusée (politique_invalide, CT-2 EX-7.15)", "aucun", "Politique d'approbation refusée par le service au chargement", "E-C1"],
  ["10.4", "noortrace_budget_redaction", () => "increase(noortrace_redaction_budget_exceeded_total[1h]) > 0", null, "mineure", "enregistreur", "CT-2 §17.4 Budget de rédaction", "aucun", "Budget de rédaction dépassé"],
  ["10.4", "noortrace_budget_redaction_bloquant", () => 'increase(noortrace_calls_blocked_total{reason="redaction"}[1h]) > 0', null, "majeure", "enregistreur", "CT-2 §17.4 Budget de rédaction", "aucun", "Appel bloqué par la rédaction"],
  ["10.4", "noortrace_cle_mac_relais", () => `increase(${LJ}{event="relay_mac_key_mismatch"}[5m]) > 0`, null, "critique", "enregistreur", "CT-2 §17.4 Clé du MAC de relais", "RB-2", "Clé du MAC de relais différente"],
  ["10.4", "noortrace_quota_hote", () => 'increase(noortrace_calls_blocked_total{code="-31013",reason="quota"}[5m]) > 0', null, "mineure", "enregistreur", "CT-2 §17.4 Quota d'un hôte", "aucun", "Quota d'un hôte atteint"],
  ["10.4", "noortrace_otel_refusee", () => 'increase(noortrace_otel_requests_total{status=~"429|503"}[5m]) > 0', null, "majeure", "enregistreur", "CT-2 §17.4 Ingestion OpenTelemetry refusée", "aucun", "Ingestion OpenTelemetry refusée"],
  ["10.4", "noortrace_otel_spans_rejetes", () => 'increase(noortrace_otel_spans_total{issue="rejete"}[1h]) > 0', null, "mineure", "enregistreur", "CT-2 §17.4 Spans rejetés", "aucun", "Spans OpenTelemetry rejetés"],
  ["10.4", "noortrace_otel_retard", () => "histogram_quantile(0.99, sum by (le) (rate(noortrace_otel_reception_lag_ms_bucket[15m]))) > 60000", null, "mineure", "enregistreur", "CT-2 §17.4 Retard de réception", "aucun", "Retard de réception OpenTelemetry au-delà d'une minute (p99)"],
  ["10.4", "noortrace_otel_conventions", () => 'sum by (source) (increase(noortrace_otel_spans_total[1h])) > 0 and sum by (source) (increase(noortrace_otel_spans_total[1h])) == sum by (source) (increase(noortrace_otel_spans_total{issue="ignore",reason="hors_genai"}[1h]))', null, "mineure", "enregistreur", "CT-2 §17.4 Conventions OpenTelemetry renommées", "aucun", "Aucun span d'une source n'est reconnu (conventions renommées)"],
  ["10.4", "noortrace_otel_conflits", () => "increase(noortrace_otel_conflicts_total[1h]) > 0", null, "mineure", "enregistreur", "CT-2 §17.4 Span OpenTelemetry rejoué", "aucun", "Span OpenTelemetry rejoué en conflit"],
  ["10.4", "noortrace_latence", () => "histogram_quantile(0.99, sum by (le) (rate(noortrace_relay_latency_ms_bucket[15m]))) > 50", null, "mineure", "enregistreur", "CT-2 §17.4 Latence", "aucun", "Latence ajoutée au-delà de 50 ms (p99)"],
  ["10.4", "noortrace_disque_ligne", () => `increase(${LJ}{event="disk_low"}[5m]) > 0`, null, "majeure", "enregistreur", "CT-2 §17.4 Disque", "RB-1", "Disque presque plein consigné"],
  ["10.4", "noortrace_disque_espace", (s) => `node_filesystem_avail_bytes{mountpoint="${s.racine}"} < ${s.disque}`, null, "majeure", "enregistreur", "CT-2 §17.4 Disque", "RB-1", "Espace libre de la racine sous deux fois min_free_bytes"],
  ["10.4", "noortrace_pieces_attente_perdues", () => `increase(${LJ}{event="pending_pieces_lost"}[5m]) > 0`, null, "majeure", "enregistreur", "CT-2 §17.4 Pièces en attente perdues", "RB-1", "Pièces en attente perdues"],
  ["10.4", "noortrace_gel_pose_en_retard", () => 'time() - noortrace_journal_derniere_ligne_s{source="gel",event="worm_legal_hold_set"} > 7200', null, "majeure", "enregistreur", "CT-2 §12.6 (tâche de poser et alerte de retard)", "RB-5", "Gel non posé depuis deux heures (support sans mode Compliance validé)"],
  ["10.4", "noortrace_export_lecture_impossible", () => `increase(${LJ}{event="dossier_export_refused",detail="lecture_impossible"}[1h]) > 0`, null, "majeure", "enregistreur", "CT-2 EX-15.12, raison lecture_impossible (segment, manifeste, série de points ou fichier des approbations illisible)", "RB-1", "Export d'un dossier refusé : lecture impossible"],
  ["10.4", "noortrace_export_refuse", () => `increase(${LJ}{event="dossier_export_refused",detail=~"exports_indisponible|ecriture_impossible"}[1h]) > 0`, null, "majeure", "enregistreur", "CT-2 EX-15.12, raisons exports_indisponible et ecriture_impossible (volume des exports absent, confondu avec storage.root, plein ou en lecture seule ; en production, droits du volume ou groupe du parent d'une destination non conformes, CT-2 EX-15.13, point 2)", "aucun", "Export d'un dossier refusé : volume des exports indisponible ou écriture impossible"],
  // §10.5 Règles du composant d'ancrage
  ["10.5", "noortrace_ancrage_en_attente", () => `increase(${LJ}{event=~"anchor_pending|registry_pending"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 anchor_pending, registry_pending", "RB-3", "Ancre ou demande au registre en attente"],
  ["10.5", "noortrace_ancrage_point_en_retard_exterieur", () => `increase(${LJ}{event="alerte_checkpoint_anchor_late",detail="exterieur"}[1h]) > 0`, null, "majeure", "ancrage", "CT-5 §8.9 checkpoint_anchor_late", "RB-4", "Point contresigné en retard par un prestataire extérieur", "E-C2"],
  ["10.5", "noortrace_ancrage_point_en_retard_interne", () => `increase(${LJ}{event="alerte_checkpoint_anchor_late",detail="interne"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 checkpoint_anchor_late", "RB-4", "Point contresigné en retard par le prestataire interne", "E-C2"],
  ["10.5", "noortrace_ancrage_inclusion_lente", (s) => `increase(noortrace_anchoring_d_registre_s_count[1h]) - ignoring (le) increase(noortrace_anchoring_d_registre_s_bucket{le=~"${s.inclusion}(\\\\.0)?"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 inclusion_late", "RB-7", "Inclusion au registre au-delà de inclusion_alert_s", "E-C3"],
  ["10.5", "noortrace_ancrage_inclusion_lente_repetee", (s) => `increase(noortrace_anchoring_d_registre_s_count[1h]) - ignoring (le) increase(noortrace_anchoring_d_registre_s_bucket{le=~"${s.inclusion}(\\\\.0)?"}[1h]) > 3`, null, "majeure", "ancrage", "CT-5 §8.9 inclusion_late", "RB-7", "Inclusion lente répétée plus de trois fois par heure", "E-C3"],
  ["10.5", "noortrace_ancrage_prestataire_injoignable", () => 'noortrace_anchoring_last_success_age_s{kind=~"jeton_periode|jeton_point"} > 900 and on (kind, provider) increase(noortrace_anchoring_attempts_total[15m]) > 0', null, "majeure", "ancrage", "CT-5 §8.9 prestataire_injoignable", "RB-4", "Prestataire d'horodatage sans succès depuis quinze minutes malgré des tentatives"],
  ["10.5", "noortrace_ancrage_prestataires_epuises_periode", () => 'noortrace_anchoring_queue_entries{kind="jeton_periode",state="a_reprendre"} > 0 and on () increase(noortrace_anchoring_attempts_total{kind="jeton_periode",outcome="echec_permanente"}[1h]) > 0', null, "critique", "ancrage", "CT-5 §8.9 prestataires_epuises (période)", "RB-4", "Prestataires épuisés pour le jeton d'une période"],
  ["10.5", "noortrace_ancrage_prestataires_epuises_point", () => `increase(${LJ}{event="anchor_refused",detail="autre"}[1h]) > 0`, null, "majeure", "ancrage", "CT-5 §8.9 prestataires_epuises (point)", "RB-4", "Prestataires épuisés pour un point"],
  ["10.5", "noortrace_ancrage_file", () => `increase(${LJ}{event=~"anchor_queue_full|anchor_queue_truncated_line|anchor_queue_write_failed"}[5m]) > 0 or increase(${LJ}{event="anchoring_queue_rebuilt",detail="recree"}[5m]) > 0`, null, "critique", "ancrage", "CT-5 §8.9 file_pleine, file_perdue", "RB-3", "File d'ancrage pleine ou perdue"],
  ["10.5", "noortrace_ancrage_ots_abandon", (s) => `noortrace_anchoring_ots_pending_age_s > ${s.ots}`, null, "majeure", "ancrage", "CT-5 §8.9 ots_give_up", "RB-3", "Preuve OpenTimestamps sans attestation au-delà de give_up_after_s"],
  ["10.5", "noortrace_ancrage_ordre", () => `increase(${LJ}{event="ordre_ancres_non_respecte"}[1d]) > 1`, null, "mineure", "ancrage", "CT-5 §8.9 ordre_ancres_non_respecte répété", "aucun", "Ordre des ancres non respecté à plusieurs reprises"],
  ["10.5", "noortrace_ancrage_empreinte_squattee", () => `increase(${LJ}{event="anchor_refused",detail="empreinte_squattee"}[1h]) > 0`, null, "critique", "ancrage", "CT-5 §8.9 empreinte_squattee", "RB-7", "Empreinte déjà ancrée par un tiers"],
  ["10.5", "noortrace_ancrage_horloge_suspecte", () => `increase(${LJ}{source="acquisitions",detail="horloge_suspecte"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 horloge_suspecte", "RB-6", "Jeton d'horodatage à l'horloge suspecte"],
  ["10.5", "noortrace_ancrage_revoque", () => `increase(${LJ}{source="acquisitions",detail="revoque"}[1h]) > 0`, null, "critique", "ancrage", "CT-5 §8.9 revoque", "RB-4", "Jeton d'horodatage révoqué"],
  ["10.5", "noortrace_ancrage_reponse_tardive_promue", () => `increase(${LJ}{source="acquisitions",detail="reponse_tardive_promue"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 reponse_tardive_promue", "RB-4", "Réponse tardive promue"],
  ["10.5", "noortrace_ancrage_point_manquant", () => `increase(${LJ}{event="point_manquant"}[5m]) > 0`, null, "majeure", "ancrage", "CT-5 §8.9 point_manquant", "RB-1", "Point de contrôle manquant"],
  ["10.5", "noortrace_ancrage_jeton_anterieur", () => `increase(${LJ}{event="alerte_jeton_anterieur_au_point"}[1h]) > 0`, null, "majeure", "ancrage", "CT-5 §8.9 jeton_anterieur_au_point", "RB-6", "Jeton antérieur au point qu'il contresigne", "E-C4"],
  ["10.5", "noortrace_ancrage_contresignature_tardive", () => `increase(${LJ}{event="alerte_contresignature_tardive"}[1h]) > 0`, null, "mineure", "ancrage", "CT-5 §8.9 contresignature_tardive", "RB-4", "Contresignature tardive d'un point", "E-C4"],
  ["10.5", "noortrace_ancrage_volume", (s) => `sum(increase(noortrace_anchoring_attempts_total[1h])) > 2 * ${s.a_h}`, null, "majeure", "ancrage", "CT-5 §8.9 volume de requêtes", "RB-8, RB-4", "Volume de requêtes d'ancrage au-delà du double du nominal (ventiler avant RB-8)"],
  // §10.6 Règles du registre et du nœud
  ["10.6", "noortrace_registre_cible_muette", () => 'up{job="noorcore"} == 0', "2m", "critique", "registre", "reprise de NoorcoreTargetDown (ops/observability/alerts/noorcore.rules.yml l. 37-43, R8-F42)", "RB-7", "Nœud du registre muet pour la collecte"],
  ["10.6", "noortrace_registre_sonde", () => "noortrace_registre_sonde_ok == 0", "2m", "critique", "registre", "CT-4 EX-10.5", "RB-7", "Point RPC du registre sans réponse à travers le relais"],
  ["10.6", "noortrace_registre_hauteur_figee", () => "changes(noortrace_registre_hauteur[5m]) == 0", null, "majeure", "registre", "CT-4 §10", "RB-7", "Hauteur du registre figée depuis cinq minutes"],
  ["10.6", "noortrace_registre_equivocation", () => "increase(noor_bft_equivocations_total[5m]) > 0", null, "critique", "registre", "CT-4 EX-10.8, §13", "RB-7", "Équivocation d'un validateur"],
  ["10.6", "noortrace_registre_mempool", (s) => `noortrace_registre_mempool > ${s.mempool}`, "5m", "majeure", "registre", "CT-4 EX-4.20, EX-10.8 ; CT-7 MN-55", "RB-7", "File en attente du nœud au-delà de la moitié de -txpool-max-pending"],
  ["10.6", "noortrace_registre_sous_tarif", () => `increase(${LJ}{event="registry_send_refused",detail="transaction_underpriced"}[1h]) > 0`, null, "majeure", "registre", "CT-4 §4.5, EX-10.8", "RB-7", "Envoi au registre refusé sous le tarif (ligne proposée, PD-12)"],
  ["10.6", "noortrace_registre_cloture_non_soumise", () => 'noortrace_anchoring_last_success_age_s{kind="ancre_registre_periode"} > 90000', null, "majeure", "registre", "CT-4 EX-8.3", "RB-7", "Clôture de période non soumise depuis une période plus vingt-quatre heures"],
  ["10.6", "noortrace_registre_capture_en_retard", () => 'noortrace_anchoring_last_success_age_s{kind="ancre_registre_periode"} > 7200', null, "majeure", "registre", "CT-4 EX-9.4", "RB-7", "Capture de l'ancre de période en retard"],
  ["10.6", "noortrace_registre_solde_bas", (s) => `noortrace_registre_solde_wei < ${s.solde}`, null, "majeure", "registre", "CT-4 EX-8.18", "aucun", "Solde d'un expéditeur sous le seuil de recomplément"],
  ["10.6", "noortrace_registre_examen_requis", () => `increase(${LJ}{source="registre",detail="examen_requis"}[1d]) > 0`, null, "majeure", "registre", "CT-4 EX-4.20", "aucun", "Outil du registre : examen requis"],
  ["10.6", "noortrace_registre_marge_retention", () => `increase(${LJ}{source="registre",detail="marge_retention_basse"}[1d]) > 0`, null, "majeure", "registre", "CT-4 EX-9.6", "RB-7", "Marge de rétention du registre basse"],
  // §10.7 Règles de l'hôte, de l'exploitation et du mode observation
  ["10.7", "noortrace_hote_disque", () => '(node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}) < 0.10', "10m", "majeure", "hote", "reprise de HostDiskSpaceLow (l. 11-17, R8-F42)", "RB-1", "Espace disque de l'hôte sous 10 %"],
  ["10.7", "noortrace_hote_memoire", () => "(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) < 0.10", "10m", "majeure", "hote", "reprise de HostMemoryPressure (l. 19-25)", "aucun", "Mémoire disponible de l'hôte sous 10 %"],
  ["10.7", "noortrace_hote_processeur", () => '(1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 0.90', "15m", "mineure", "hote", "reprise de HostCPUHigh (l. 27-33)", "aucun", "Processeur de l'hôte occupé au-delà de 90 %"],
  ["10.7", "noortrace_approbation_non_pret", () => "noortrace_approbation_pret == 0", "5m", "majeure", "approbation", "CT-3 EX-12.12", "RB-1", "Service d'approbation non prêt ou sans réponse"],
  ["10.7", "noortrace_console_non_prete", () => "noortrace_console_prete == 0", "5m", "majeure", "approbation", "CT-3 EX-13.44", "aucun", "Serveur de console non prêt ou sans réponse"],
  ["10.7", "noortrace_notification_echec", () => `increase(${LJ}{source="approbation",event="notification_echec"}[1h]) > 0`, null, "mineure", "approbation", "CT-3 EX-13.42", "aucun", "Livraison d'une notification en échec (une reprise suit)"],
  ["10.7", "noortrace_notification_abandonnee", () => `increase(${LJ}{source="approbation",event="notification_abandonnee"}[1h]) > 0`, null, "majeure", "approbation", "CT-3 EX-13.42", "aucun", "Notification abandonnée"],
  ["10.7", "noortrace_notification_sans_destinataire", () => `increase(${LJ}{source="approbation",event="notification_sans_destinataire"}[1d]) > 0`, null, "majeure", "approbation", "CT-3 EX-13.40", "aucun", "Notification sans destinataire"],
  ["10.7", "noortrace_sauvegarde_en_retard", (s) => `time() - noortrace_proces_verbal_dernier_s{kind="sauvegarde"} > ${s.rpo}`, null, "majeure", "exploitation", "CT-8 EX-11.5", "aucun", "Dernière sauvegarde plus ancienne que le RPO"],
  ["10.7", "noortrace_exercice_restauration_en_retard", () => 'time() - noortrace_proces_verbal_dernier_s{kind="exercice_restauration"} > 34560000', null, "mineure", "exploitation", "CT-8 EX-11.8", "aucun", "Dernier exercice de restauration plus vieux que 400 jours"],
  ["10.7", "noortrace_acces_non_declare", () => `increase(${LJ}{source="consultations",detail="inconnu"}[1h]) > 0`, null, "majeure", "exploitation", "CT-8 EX-11.20 (CA-6)", "RB-8", "Accès d'un principal non déclaré"],
  ["10.7", "noortrace_consultations_muettes", () => 'time() - max(noortrace_journal_derniere_ligne_s{source="consultations"}) > 86400', null, "majeure", "exploitation", "CT-8 EX-11.19", "aucun", "Journal des consultations muet depuis un jour"],
  ["10.7", "noortrace_journal_illisible", () => "increase(noortrace_journal_illisibles_total[1h]) > 0", null, "majeure", "exploitation", "CT-8 EX-10.5", "aucun", "Ligne de journal illisible"],
  ["10.7", "noortrace_mode_observation_actif", () => "noortrace_observation_mode == 1", null, "mineure", "enregistreur", "CT-2 §17.4 Mode observation actif (EX-17.8) ; CT-8 EX-12.8", "aucun", "Mode observation actif : aucun appel n'est bloqué"],
  ["10.7", "noortrace_observation_pertes", () => "increase(noortrace_events_lost_total[5m]) > 0", null, "majeure", "enregistreur", "CT-2 §17.4 Pertes en mode observation (EX-17.8) ; CT-2 EX-14.16", "RB-1", "Événements perdus en mode observation"],
  // EX-10.9 : relectures hors du composant (proposition PD-28 de CT-9 : les tables ne portent pas cette règle)
  ["EX-10.9", "noortrace_releve_externe_echec", () => "noortrace_releve_externe_ok == 0", null, "critique", "exploitation", "CT-8 EX-10.9", "aucun", "Relecture hors du composant en échec", "E-C5"],
  ["EX-10.9", "noortrace_releve_externe_perime", () => "time() - noortrace_releve_externe_dernier_s > 172800", null, "critique", "exploitation", "CT-8 EX-10.9", "aucun", "Relecture hors du composant non mise à jour depuis deux jours", "E-C5"],
].map(([section, alert, expr, pour, severity, component, exigence, runbook, summary, ecart = null]) => Object.freeze({ section, alert, expr, pour, severity, component, exigence, runbook, summary, ecart })));

/** Titre de groupe par section. */
const GROUPES = [
  ["10.4", "noortrace-enregistreur", "CT-8 §10.4 Règles de l'enregistreur"],
  ["10.5", "noortrace-ancrage", "CT-8 §10.5 Règles du composant d'ancrage"],
  ["10.6", "noortrace-registre", "CT-8 §10.6 Règles du registre et du nœud"],
  ["10.7", "noortrace-hote-exploitation", "CT-8 §10.7 Règles de l'hôte, de l'exploitation et du mode observation"],
  ["EX-10.9", "noortrace-releves-externes", "CT-8 EX-10.9 Relectures hors du composant (proposition PD-28 de CT-9)"],
];

/** Règles dont l'expression ou la clause `for` dépend d'un paramètre d'EX-10.6. */
export const REGLES_PARAMETREES = Object.freeze({
  noortrace_attente_ancienne: ["pending_max_ms"],
  noortrace_ancre_en_retard: ["anchor_pending_alert_s"],
  noortrace_releve_en_retard: ["lock_audit_interval_days"],
  noortrace_horloge_ecart: ["warn_skew_ms"],
  noortrace_disque_espace: ["storage_root", "min_free_bytes"],
  noortrace_ancrage_inclusion_lente: ["inclusion_alert_s"],
  noortrace_ancrage_inclusion_lente_repetee: ["inclusion_alert_s"],
  noortrace_ancrage_ots_abandon: ["give_up_after_s"],
  noortrace_ancrage_volume: ["requetes_ancrage_par_heure"],
  noortrace_registre_mempool: ["txpool_max_pending"],
  noortrace_registre_solde_bas: ["refill_below_days", "gas_limit", "budget_journalier_gaz"],
  noortrace_sauvegarde_en_retard: ["rpo_s"],
});

/**
 * Écarts entre les tables de CT-8 §10.3 à §10.7 et le code des paquets ou
 * Prometheus 3.5 ; chacun est une demande de révision de CT-8.
 */
export const ECARTS_CT8 = Object.freeze({
  "E-C1": "La ligne approval_policy_invalid (nom proposé par PD-10) n'existe pas : au charger, le démon consigne approval_service_unavailable avec data.message = \"charger\" et data.code = \"politique_invalide\" (paquets/enregistreur/src/coeur.mjs) ; l'extracteur en fait le detail politique_invalide_au_charger.",
  "E-C2": "La ligne checkpoint_anchor_late ne porte pas le rôle du prestataire (PD-11) ; le composant consigne à sa suite alerte_checkpoint_anchor_late avec data.severity majeure pour un prestataire extérieur et mineure pour le prestataire interne (paquets/ancrage/src/planificateur/planificateur.mjs, supervision.mjs) ; l'extracteur en fait le detail exterieur ou interne.",
  "E-C3": "Deux défauts de l'expression de la table : la soustraction entre _count (sans le) et _bucket (avec le) ne s'apparie sur aucune série sans ignoring (le) ; Prometheus 3 normalise à la collecte le=\"60\" en le=\"60.0\" (guide de migration de la version 3), d'où le=~\"60(\\\\.0)?\".",
  "E-C4": "Les lignes jeton_anterieur_au_point et contresignature_tardive (noms proposés par PD-11) sont consignées sous alerte_jeton_anterieur_au_point et alerte_contresignature_tardive (action alerter du planificateur, consignée par Supervision.consignerActions).",
  "E-C5": "EX-10.9 prescrit une alerte critique sur noortrace_releve_externe_ok (vaut 0, ou non mise à jour depuis 2 jours) que les tables de 10.4 à 10.7 ne portent pas (proposition PD-28 de CT-9) ; la seconde condition exige la jauge noortrace_releve_externe_dernier_s{check}, que CT-8 ne nomme pas, écrite par sonde.mjs releve.",
});

/** Échappement d'une chaîne YAML entre apostrophes. */
const yq = (s) => `'${String(s).replace(/'/g, "''")}'`;

/** Description d'une règle : résumé, gravité, exigence, runbook. */
export function descriptionRegle(r) {
  return `${r.summary}. Gravité ${r.severity}, composant ${r.component}. Exigence : ${r.exigence}. Runbook : ${r.runbook}.`;
}

/**
 * Règles calculées : chaque règle avec son expression et sa clause `for`.
 * @param {object} p paramètres (parametresRegles)
 */
export function reglesCalculees(p = PARAMETRES_DEFAUT) {
  const s = seuils(p);
  return REGLES.map((r) => ({
    ...r,
    expr: r.expr(s),
    pour: typeof r.pour === "function" ? r.pour(s) : r.pour,
    labels: { severity: r.severity, component: r.component, exigence: r.exigence, runbook: r.runbook },
    annotations: { summary: r.summary, description: descriptionRegle(r) },
  }));
}

/**
 * Fichier de règles (EX-10.6) : texte YAML déterministe, identique octet pour
 * octet pour les mêmes paramètres.
 * @param {{configuration?: object|null, ancrage?: object|null, instance?: object|null,
 *   dimensionnement?: object|null, txpool_max_pending?: number|null, rpo_s?: number|null}} [docs]
 * @returns {string}
 */
export function genererRegles(docs = {}) {
  const p = parametresRegles(docs);
  const regles = reglesCalculees(p);
  const L = [];
  L.push("# Règles d'alerte de référence de NOORTRACE (CT-8 §10.4 à §10.7, EX-10.1,");
  L.push("# EX-10.2), au format des règles d'alerte de Prometheus.");
  L.push("#");
  L.push("# Écrit par node scripts/deploiement/regles.mjs ; ne pas éditer à la main.");
  L.push("# Un client qui change un réglage régénère ce fichier (EX-10.6) :");
  L.push("#   node scripts/deploiement/regles.mjs --configuration <configuration> \\");
  L.push("#     --ancrage <ancrage.json> [--instance <manifeste>] [--dimensionnement <entrées>]");
  L.push("#");
  L.push("# Paramètres de ce fichier :");
  for (const [k, v] of Object.entries(p)) L.push(`#   ${k}: ${v}`);
  L.push("#");
  L.push("# Les noms de lignes et de membres sont ceux du code des paquets ; les");
  L.push("# écarts aux tables de CT-8 sont listés dans scripts/lib/supervision.mjs");
  L.push("# (ECARTS_CT8).");
  L.push("groups:");
  for (const [section, nom, titre] of GROUPES) {
    L.push(`  # ${titre}`);
    L.push(`  - name: ${nom}`);
    L.push("    rules:");
    for (const r of regles.filter((x) => x.section === section)) {
      L.push(`      - alert: ${r.alert}`);
      L.push(`        expr: ${yq(r.expr)}`);
      if (r.pour !== null) L.push(`        for: ${r.pour}`);
      L.push("        labels:");
      for (const k of ETIQUETTES_REGLE) L.push(`          ${k}: ${yq(r.labels[k])}`);
      L.push("        annotations:");
      for (const k of ANNOTATIONS_REGLE) L.push(`          ${k}: ${yq(r.annotations[k])}`);
    }
  }
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Métriques admises (SV-2, SV-7)
// ---------------------------------------------------------------------------

/**
 * Noms admis dans une expression, avec leur source : 10.3, EX-10.7, EX-10.9,
 * CT-2 §17.2 et EX-17.8, CT-5 EX-8.15, noor_* relevés (R8-F43), up et node_*
 * des trois règles de l'hôte. Les histogrammes sont admis avec leurs
 * suffixes _bucket, _sum et _count.
 */
export const METRIQUES_ADMISES = Object.freeze({
  // 10.3 (extracteur)
  noortrace_journal_lignes_total: "CT-8 10.3",
  noortrace_journal_derniere_ligne_s: "CT-8 10.3",
  noortrace_journal_illisibles_total: "CT-8 10.3",
  noortrace_proces_verbal_dernier_s: "CT-8 10.3",
  // EX-10.7 (sonde)
  noortrace_approbation_pret: "CT-8 EX-10.7",
  noortrace_approbation_tickets_ouverts: "CT-8 EX-10.7",
  noortrace_approbation_jeu_lu_age_s: "CT-8 EX-10.7",
  noortrace_console_prete: "CT-8 EX-10.7",
  noortrace_registre_sonde_ok: "CT-8 EX-10.7",
  noortrace_registre_hauteur: "CT-8 EX-10.7",
  noortrace_registre_mempool: "CT-8 EX-10.7",
  noortrace_registre_solde_wei: "CT-8 EX-10.7",
  // EX-10.9 (relectures) ; noortrace_releve_externe_dernier_s : écart E-C5
  noortrace_releve_externe_ok: "CT-8 EX-10.9",
  noortrace_releve_externe_dernier_s: "CT-8 EX-10.9 (E-C5)",
  // CT-2 §17.2, EX-17.8 (noms exposés par paquets/enregistreur)
  noortrace_events_total: "CT-2 §17.2",
  noortrace_calls_blocked_total: "CT-2 §17.2",
  noortrace_calls_executed_not_durable_total: "CT-2 §17.2",
  noortrace_relay_latency_ms: "CT-2 §17.2",
  noortrace_upstream_latency_ms: "CT-2 §17.2",
  noortrace_upstream_errors_total: "CT-2 §17.2",
  noortrace_fsync_duration_ms: "CT-2 §17.2",
  noortrace_fsync_group_size: "CT-2 §17.2",
  noortrace_segment_bytes: "CT-2 §17.2",
  noortrace_sign_duration_ms: "CT-2 §17.2",
  noortrace_pending_events: "CT-2 §17.2",
  noortrace_pending_oldest_ms: "CT-2 §17.2",
  noortrace_lease_epoch: "CT-2 §17.2",
  noortrace_lease_renew_failures_total: "CT-2 §17.2",
  noortrace_degraded: "CT-2 §17.2",
  noortrace_clock_skew_ms: "CT-2 §17.2",
  noortrace_anchor_pending: "CT-2 §17.2",
  noortrace_worm_copy_pending: "CT-2 §17.2",
  noortrace_worm_lock_checks_total: "CT-2 §17.2",
  noortrace_worm_lock_nonconforming: "CT-2 §17.2",
  noortrace_worm_last_audit_age_s: "CT-2 §17.2",
  noortrace_worm_versions_unexpected: "CT-2 §17.2",
  noortrace_worm_legal_holds_active: "CT-2 §17.2",
  noortrace_integrity_check_failures_total: "CT-2 §17.2",
  noortrace_tools_announced: "CT-2 §17.2",
  noortrace_tools_rejected_total: "CT-2 §17.2",
  noortrace_tool_definition_changes_total: "CT-2 §17.2",
  noortrace_approval_signals_total: "CT-2 §17.2",
  noortrace_approval_relays_refused_total: "CT-2 §17.2",
  noortrace_approval_remises_refused_total: "CT-2 §17.2",
  noortrace_redactions_total: "CT-2 §17.2",
  noortrace_redaction_budget_exceeded_total: "CT-2 §17.2",
  noortrace_pieces_bytes_total: "CT-2 §17.2",
  noortrace_model_tokens_total: "CT-2 §17.2",
  noortrace_otel_requests_total: "CT-2 §17.2",
  noortrace_otel_spans_total: "CT-2 §17.2",
  noortrace_otel_conflicts_total: "CT-2 §17.2",
  noortrace_otel_reception_lag_ms: "CT-2 §17.2",
  noortrace_ops_log_dropped_total: "CT-2 §17.2",
  noortrace_build_info: "CT-2 §17.2",
  noortrace_observation_mode: "CT-2 EX-17.8",
  noortrace_observation_marks_total: "CT-2 EX-17.8",
  noortrace_observation_would_block_total: "CT-2 EX-17.8",
  noortrace_events_lost_total: "CT-2 EX-17.8",
  // CT-5 EX-8.15
  noortrace_anchoring_queue_entries: "CT-5 EX-8.15",
  noortrace_anchoring_attempts_total: "CT-5 EX-8.15",
  noortrace_anchoring_last_success_age_s: "CT-5 EX-8.15",
  noortrace_anchoring_deadlines_total: "CT-5 EX-8.15",
  noortrace_anchoring_window_s: "CT-5 EX-8.15",
  noortrace_anchoring_d_jeton_s: "CT-5 EX-8.15",
  noortrace_anchoring_d_point_s: "CT-5 EX-8.15",
  noortrace_anchoring_d_registre_s: "CT-5 EX-8.15",
  noortrace_anchoring_ots_pending_age_s: "CT-5 EX-8.15",
  // noor_* (R8-F43, noms nommés par CT-8 §10.2)
  noor_bft_equivocations_total: "R8-F43",
  noor_chain_height: "R8-F43",
  noor_finalized_height: "R8-F43",
  noor_rpc_errors_total: "R8-F43",
  // Hôte (trois règles de 10.7) et collecte
  up: "Prometheus",
  node_filesystem_avail_bytes: "node_exporter",
  node_filesystem_size_bytes: "node_exporter",
  node_memory_MemAvailable_bytes: "node_exporter",
  node_memory_MemTotal_bytes: "node_exporter",
  node_cpu_seconds_total: "node_exporter",
});

const HISTOGRAMMES = new Set(["noortrace_relay_latency_ms", "noortrace_upstream_latency_ms", "noortrace_fsync_duration_ms", "noortrace_fsync_group_size", "noortrace_sign_duration_ms", "noortrace_otel_reception_lag_ms", "noortrace_anchoring_d_jeton_s", "noortrace_anchoring_d_point_s", "noortrace_anchoring_d_registre_s"]);

/** Le nom est-il admis par SV-2 (histogrammes avec leurs suffixes) ? */
export function metriqueAdmise(nom) {
  if (Object.hasOwn(METRIQUES_ADMISES, nom)) return true;
  const m = /^(.*)_(bucket|sum|count)$/.exec(nom);
  return m !== null && HISTOGRAMMES.has(m[1]);
}

const MOTS_PROMQL = new Set(["sum", "max", "min", "avg", "count", "by", "without", "on", "ignoring", "group_left", "group_right", "and", "or", "unless", "bool",
  "rate", "increase", "changes", "abs", "time", "histogram_quantile", "offset", "le", "inf", "nan"]);

/**
 * Noms de métriques d'une expression PromQL : identifiants hors des chaînes,
 * des listes d'étiquettes (`{…}`, `by (…)`, `on (…)`, `ignoring (…)`), des
 * durées et des mots de la langue.
 * @param {string} expr
 * @returns {string[]}
 */
export function nomsMetriques(expr) {
  const sans = expr
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/\{[^}]*\}/g, "")
    .replace(/\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)/g, "")
    .replace(/\[[^\]]*\]/g, "");
  const noms = new Set();
  for (const m of sans.matchAll(/[A-Za-z_:][A-Za-z0-9_:]*/g)) {
    const mot = m[0];
    const suite = sans.slice(m.index + mot.length).trimStart();
    if (MOTS_PROMQL.has(mot) || (suite.startsWith("(") && MOTS_PROMQL.has(mot))) continue;
    if (/^[0-9]/.test(mot)) continue;
    noms.add(mot);
  }
  return [...noms].sort();
}

// ---------------------------------------------------------------------------
// Extracteur des journaux (10.3, EX-10.5)
// ---------------------------------------------------------------------------

/** Sources d'EX-10.5, dans l'ordre de l'exposition. */
export const SOURCES = Object.freeze(["exploitation", "gel", "acquisitions", "registre", "consultations", "approbation"]);

/** Valeur d'étiquette tirée d'une ligne : exposée seulement si elle suit ce motif. */
export const VALEUR_SURE = /^[a-z][a-z0-9_]{0,63}$/;
const sure = (v) => (typeof v === "string" && VALEUR_SURE.test(v) ? v : "");
const NIVEAUX = new Set(["debug", "info", "warning", "error"]);

/**
 * `detail` d'une ligne de journal d'exploitation ou de l'outil de gel (table
 * de 10.3, noms du code ; écarts E-C1 et E-C2).
 * @param {string} event
 * @param {object} data
 */
export function detailExploitation(event, data) {
  const d = data !== null && typeof data === "object" && !Array.isArray(data) ? data : {};
  switch (event) {
    case "worm_lock_config_check":
      return d.verdict === "conforme" ? "conforme" : "non_conforme";
    case "worm_lock_check":
      if (Array.isArray(d.reasons) && d.reasons.includes("gel_absent")) return "gel_absent";
      return d.verdict === "conforme" ? "conforme" : "non_conforme";
    case "worm_legal_hold_observed":
      if (typeof d.garde === "string" && d.garde !== "respectee") return "garde_violee";
      return d.kind === "levee" ? "levee" : "autre";
    case "anchoring_queue_rebuilt":
      return typeof d.recreated === "number" && d.recreated > 0 ? "recree" : "aucune";
    case "anchor_refused":
      return d.error_code === "empreinte_squattee" ? "empreinte_squattee" : "autre";
    case "alerte_checkpoint_anchor_late":
      return d.severity === "majeure" ? "exterieur" : d.severity === "mineure" ? "interne" : "";
    case "dossier_export_refused":
      return sure(d.raison);
    case "approval_service_unavailable":
      return d.message === "charger" && d.code === "politique_invalide" ? "politique_invalide_au_charger" : "";
    default:
      return "";
  }
}

/** `detail` d'un enregistrement d'acquisition (CT-5 EX-5.13 ; noms du code). */
export function detailAcquisition(e) {
  const avert = Array.isArray(e.warnings) ? e.warnings : [];
  if (e.freshness === "horloge_suspecte" || avert.includes("horloge_suspecte")) return "horloge_suspecte";
  if (avert.includes("reponse_tardive") && e.promoted === true) return "reponse_tardive_promue";
  if (e.revoked === true) return "revoque";
  return sure(e.outcome);
}

/** `detail` d'une sortie de l'outil du registre (operations-registre-v0#/$defs/sortie). */
export function detailRegistre(s) {
  if (s.outputs?.retention?.alert === true) return "marge_retention_basse";
  if (s.error?.code === "examen_requis") return "examen_requis";
  return "";
}

const MOTIF_HORODATAGE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z$/;

/**
 * Horodatage UTC (`AAAA-MM-JJTHH:MM:SS[.fraction]Z`) en millisecondes, ou
 * null (fraction tronquée à la milliseconde).
 */
export function msDepuisHorodatage(t) {
  if (typeof t !== "string") return null;
  const m = MOTIF_HORODATAGE.exec(t);
  if (!m) return null;
  const [an, mo, j, h, mi, s] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || j < 1 || h > 23 || mi > 59 || s > 59) return null;
  const jours = new Date(Date.UTC(an, mo, 0)).getUTCDate();
  if (j > jours) return null;
  const frac = m[7] ? Number((m[7].slice(1) + "00").slice(0, 3)) : 0;
  return Date.UTC(an, mo - 1, j, h, mi, s) + frac;
}

/** Secondes UNIX d'un instant en millisecondes : entier, ou décimales sans zéro final. */
export function secondes(ms) {
  const e = Math.floor(ms / 1000);
  const r = ms - e * 1000;
  if (r === 0) return String(e);
  return `${e}.${String(r).padStart(3, "0").replace(/0+$/, "")}`;
}

/**
 * Analyse JSON stricte d'une ligne (octets UTF-8) : texte UTF-8 valide, sans
 * marque d'ordre d'octets, grammaire de la RFC 8259, aucun nom de membre en
 * double. Rend la valeur ou lève une erreur.
 * @param {Uint8Array|string} entree
 */
export function analyserJSONStrict(entree) {
  const texte = typeof entree === "string" ? entree : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(entree);
  if (texte.charCodeAt(0) === 0xfeff) throw new SyntaxError("marque d'ordre d'octets refusée");
  let i = 0;
  const err = (m) => { throw new SyntaxError(`${m} (position ${i})`); };
  const blancs = () => { while (i < texte.length && " \t\n\r".includes(texte[i])) i++; };
  const chaine = () => {
    const debut = i;
    i++;
    for (;;) {
      if (i >= texte.length) err("chaîne non terminée");
      const c = texte.charCodeAt(i);
      if (c === 0x22) { i++; break; }
      if (c < 0x20) err("caractère de contrôle dans une chaîne");
      if (c === 0x5c) {
        const e = texte[i + 1];
        if (e === "u") { if (!/^[0-9a-fA-F]{4}$/.test(texte.slice(i + 2, i + 6))) err("échappement \\u invalide"); i += 6; continue; }
        if (!'"\\/bfnrt'.includes(e ?? "x")) err("échappement invalide");
        i += 2;
        continue;
      }
      i++;
    }
    return JSON.parse(texte.slice(debut, i));
  };
  const valeur = (prof) => {
    if (prof > 256) err("profondeur excessive");
    blancs();
    const c = texte[i];
    if (c === "{") {
      i++;
      const o = {};
      const vus = new Set();
      blancs();
      if (texte[i] === "}") { i++; return o; }
      for (;;) {
        blancs();
        if (texte[i] !== '"') err("nom de membre attendu");
        const k = chaine();
        if (vus.has(k)) err(`nom de membre en double : ${k}`);
        vus.add(k);
        blancs();
        if (texte[i] !== ":") err("« : » attendu");
        i++;
        const v = valeur(prof + 1);
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        blancs();
        if (texte[i] === ",") { i++; continue; }
        if (texte[i] === "}") { i++; return o; }
        err("« , » ou « } » attendu");
      }
    }
    if (c === "[") {
      i++;
      const a = [];
      blancs();
      if (texte[i] === "]") { i++; return a; }
      for (;;) {
        a.push(valeur(prof + 1));
        blancs();
        if (texte[i] === ",") { i++; continue; }
        if (texte[i] === "]") { i++; return a; }
        err("« , » ou « ] » attendu");
      }
    }
    if (c === '"') return chaine();
    const m = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(texte.slice(i, i + 400));
    if (!m) err("valeur attendue");
    i += m[0].length;
    return JSON.parse(m[0]);
  };
  const v = valeur(0);
  blancs();
  if (i !== texte.length) err("données après la valeur");
  return v;
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Lignes complètes d'un fichier NDJSON : chaque ligne terminée par LF (une
 * fin sans LF, en cours d'écriture, n'est pas lue), lignes vides ignorées.
 * @param {Uint8Array} octets
 * @returns {Uint8Array[]}
 */
export function lignesCompletes(octets) {
  const out = [];
  let debut = 0;
  for (let k = 0; k < octets.length; k++) {
    if (octets[k] !== 0x0a) continue;
    let fin = k;
    if (fin > debut && octets[fin - 1] === 0x0d) fin--;
    if (fin > debut) out.push(octets.subarray(debut, fin));
    debut = k + 1;
  }
  return out;
}

const enOctets = (x) => (typeof x === "string" ? new TextEncoder().encode(x) : x instanceof Uint8Array ? x : new Uint8Array(x));

/**
 * Compteurs de l'extracteur, cumulés d'un appel à l'autre (mode « en ajout » :
 * l'outil ne passe que les octets nouveaux de chaque fichier).
 */
export class Extracteur {
  constructor() {
    /** @type {Map<string, {source: string, event: string, level: string, detail: string, n: number}>} */
    this.lignes = new Map();
    /** @type {Map<string, {source: string, event: string, ms: number}>} */
    this.dernieres = new Map();
    /** @type {Map<string, number>} */
    this.illisibles = new Map();
    /** @type {Map<string, number>} */
    this.procesVerbaux = new Map();
  }

  compter(source, event, level, detail, instant) {
    const k = JSON.stringify([source, event, level, detail]);
    const e = this.lignes.get(k) ?? { source, event, level, detail, n: 0 };
    e.n += 1;
    this.lignes.set(k, e);
    if (instant !== null) {
      const kd = JSON.stringify([source, event]);
      const d = this.dernieres.get(kd);
      if (!d || instant > d.ms) this.dernieres.set(kd, { source, event, ms: instant });
    }
  }

  /**
   * Lit des lignes complètes d'une source NDJSON.
   * @param {string} source l'une de SOURCES (sauf registre, voir ajouterDocument)
   * @param {Uint8Array[]} lignes
   */
  ajouterLignes(source, lignes) {
    if (!SOURCES.includes(source)) throw new RangeError(`source inconnue : ${source}`);
    if (!this.illisibles.has(source)) this.illisibles.set(source, 0);
    for (const l of lignes) {
      let v;
      try {
        v = analyserJSONStrict(l);
      } catch {
        this.illisibles.set(source, this.illisibles.get(source) + 1);
        continue;
      }
      this.ajouterValeur(source, v);
    }
  }

  /** Lit un document JSON entier (sortie de l'outil du registre, un document par fichier). */
  ajouterDocument(source, octets) {
    if (!this.illisibles.has(source)) this.illisibles.set(source, 0);
    let v;
    try {
      v = analyserJSONStrict(octets);
    } catch {
      this.illisibles.set(source, this.illisibles.get(source) + 1);
      return;
    }
    this.ajouterValeur(source, v);
  }

  ajouterValeur(source, v) {
    if (!estObjet(v)) {
      this.compter(source, "", "", "", null);
      return;
    }
    const niveau = NIVEAUX.has(v.level) ? v.level : "";
    switch (source) {
      case "exploitation":
      case "gel": {
        const event = sure(v.event);
        this.compter(source, event, niveau, event ? detailExploitation(event, v.data) : "", msDepuisHorodatage(v.ts));
        break;
      }
      case "acquisitions":
        this.compter(source, "acquisition", niveau, detailAcquisition(v), msDepuisHorodatage(v.received_at));
        break;
      case "registre":
        this.compter(source, sure(v.command), niveau, detailRegistre(v), null);
        break;
      case "consultations":
        this.compter(source, sure(v.action), niveau, sure(v.role), msDepuisHorodatage(v.ts));
        break;
      case "approbation": {
        const event = sure(v.type);
        const detail = event === "notification_echec" || event === "notification_abandonnee" ? sure(v.cause) : "";
        this.compter(source, event, niveau, detail, msDepuisHorodatage(v.ts));
        break;
      }
      default:
        throw new RangeError(`source inconnue : ${source}`);
    }
  }

  /**
   * Procès-verbal d'exploitation : retenu pour sa sorte quand `valide` (PV-1,
   * jugé par l'appelant) ; garde le plus grand `finished_at`.
   * @param {object} pv
   * @param {boolean} valide
   */
  ajouterProcesVerbal(pv, valide) {
    if (!valide || !estObjet(pv)) return;
    const kind = sure(pv.kind);
    const t = msDepuisHorodatage(pv.finished_at);
    if (!kind || t === null) return;
    if (!this.procesVerbaux.has(kind) || t > this.procesVerbaux.get(kind)) this.procesVerbaux.set(kind, t);
  }

  /**
   * Exposition au format texte de Prometheus, déterministe : les quatre
   * familles dans l'ordre de la table de 10.3, chacune précédée de HELP et
   * TYPE, ses séries triées par ordre d'octets de leur texte ; étiquettes dans
   * l'ordre source, event, level, detail.
   */
  exposer() {
    const L = [];
    const tri = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    L.push("# HELP noortrace_journal_lignes_total Lignes lues par source, event, level et detail (CT-8 10.3).");
    L.push("# TYPE noortrace_journal_lignes_total counter");
    const lignes = [...this.lignes.values()].map((e) => [`noortrace_journal_lignes_total{source="${e.source}",event="${e.event}",level="${e.level}",detail="${e.detail}"}`, e.n]);
    for (const [k, n] of lignes.sort(tri)) L.push(`${k} ${n}`);
    L.push("# HELP noortrace_journal_derniere_ligne_s Horodatage de la derniere ligne lue de cet event, en secondes UNIX (CT-8 10.3).");
    L.push("# TYPE noortrace_journal_derniere_ligne_s gauge");
    const dern = [...this.dernieres.values()].map((e) => [`noortrace_journal_derniere_ligne_s{source="${e.source}",event="${e.event}"}`, secondes(e.ms)]);
    for (const [k, v] of dern.sort(tri)) L.push(`${k} ${v}`);
    L.push("# HELP noortrace_journal_illisibles_total Lignes qui ne s'analysent pas en JSON strict (CT-8 10.3).");
    L.push("# TYPE noortrace_journal_illisibles_total counter");
    for (const s of [...this.illisibles.keys()].sort()) L.push(`noortrace_journal_illisibles_total{source="${s}"} ${this.illisibles.get(s)}`);
    L.push("# HELP noortrace_proces_verbal_dernier_s finished_at du dernier proces-verbal valide (PV-1) de chaque sorte (CT-8 10.3).");
    L.push("# TYPE noortrace_proces_verbal_dernier_s gauge");
    for (const k of [...this.procesVerbaux.keys()].sort()) L.push(`noortrace_proces_verbal_dernier_s{kind="${k}"} ${secondes(this.procesVerbaux.get(k))}`);
    return L.join("\n") + "\n";
  }
}

/**
 * Extracteur des journaux (10.3), sans fichier : chaque source est une liste
 * de contenus de fichiers (octets ou texte). `registre` : un document JSON par
 * élément ; `proces_verbaux` : `{ document, valide }` (PV-1 jugé par
 * l'appelant) ou un document seul, alors tenu pour valide.
 * @param {{exploitation?: (Uint8Array|string)[], gel?: (Uint8Array|string)[], acquisitions?: (Uint8Array|string)[],
 *   registre?: (Uint8Array|string)[], consultations?: (Uint8Array|string)[], approbation?: (Uint8Array|string)[],
 *   proces_verbaux?: (object|{document: object, valide: boolean})[]}} sources
 * @returns {string} exposition au format texte de Prometheus
 */
export function extraireJournaux(sources = {}) {
  const x = new Extracteur();
  for (const s of SOURCES) {
    for (const contenu of sources[s] ?? []) {
      if (s === "registre") x.ajouterDocument(s, enOctets(contenu));
      else x.ajouterLignes(s, lignesCompletes(enOctets(contenu)));
    }
  }
  for (const pv of sources.proces_verbaux ?? []) {
    if (estObjet(pv) && Object.hasOwn(pv, "document") && Object.hasOwn(pv, "valide")) x.ajouterProcesVerbal(pv.document, pv.valide === true);
    else x.ajouterProcesVerbal(pv, true);
  }
  return x.exposer();
}

// ---------------------------------------------------------------------------
// Tests des règles au format de `promtool test rules` (EX-10.10)
// ---------------------------------------------------------------------------

/** Étiquettes de collecte des séries des tests : démon et hôte (extracteur et sonde par le collecteur textfile). */
const E = { instance: "127.0.0.1:8500", job: "enregistreur", role: "active" };
const X = { instance: "127.0.0.1:9100", job: "hote", role: "hote" };
const MONTE = "0 0 0 1 1 1 1";
const PLAT = "0x6";

/** Sélecteur de série : nom{étiquettes triées} (étiquettes vides omises). */
function serie(nom, et) {
  const k = Object.keys(et).filter((x) => et[x] !== "").sort();
  return `${nom}{${k.map((x) => `${x}="${et[x]}"`).join(", ")}}`;
}
const sans = (et, ...noms) => Object.fromEntries(Object.entries(et).filter(([k, v]) => !noms.includes(k) && v !== ""));

/** Cas d'une règle sur un compteur de l'extracteur : lignes de `ligne` montent, celles de `silence` aussi. */
function casLigne(ligne, silence) {
  const a = { source: "exploitation", level: "", detail: "", ...ligne, ...X };
  const b = { source: "exploitation", level: "", detail: "", ...silence, ...X };
  return { t: "6m", f: [[serie(LJ, a), MONTE]], s: [[serie(LJ, b), MONTE]], e: sans(a) };
}
/** Cas d'une règle sur un compteur du démon. */
function casCompteur(nom, et, silence = null, base = E) {
  const a = { ...et, ...base };
  return { t: "6m", f: [[serie(nom, a), MONTE]], s: [[serie(nom, silence ? { ...silence, ...base } : a), silence ? MONTE : PLAT]], e: sans(a) };
}
/** Cas d'une jauge : `haut` déclenche, `bas` non ; `t` après la clause for. */
function casJauge(nom, et, haut, bas, t = "10m", base = E) {
  const a = { ...et, ...base };
  return { t, f: [[serie(nom, a), `${haut}x140`]], s: [[serie(nom, a), `${bas}x140`]], e: sans(a) };
}

/** Un cas par règle : t (eval_time), f (séries qui déclenchent), s (séries qui ne déclenchent pas), e (étiquettes de l'alerte venues de l'expression). */
export function casRegles(p = PARAMETRES_DEFAUT) {
  const s = seuils(p);
  const d = (r) => ({ ...E, reason: r });
  const C = {
    noortrace_mode_degrade_critique: { t: "3m", f: [[serie("noortrace_degraded", d("cle")), "1x10"]], s: [[serie("noortrace_degraded", d("cle")), "0x10"], [serie("noortrace_degraded", d("stockage")), "1x10"]], e: { instance: E.instance, reason: "cle" } },
    noortrace_mode_degrade_majeur: { t: "3m", f: [[serie("noortrace_degraded", d("stockage")), "1x10"]], s: [[serie("noortrace_degraded", d("cle")), "1x10"]], e: { instance: E.instance, reason: "stockage" } },
    noortrace_mode_degrade_serveur: { t: "3m", f: [[serie("noortrace_degraded", d("serveur:outils")), "1x10"]], s: [[serie("noortrace_degraded", d("serveur:outils")), "0x10"]], e: { instance: E.instance, reason: "serveur:outils" } },
    noortrace_appels_bloques: casCompteur("noortrace_calls_blocked_total", { code: "-31010", reason: "politique", class: "ecriture" }),
    noortrace_attente_non_vide: casJauge("noortrace_pending_events", {}, 3, 0, "10m"),
    noortrace_attente_ancienne: casJauge("noortrace_pending_oldest_ms", {}, s.attente + 1, s.attente),
    noortrace_bail_non_detenu: { t: "3m", f: [[serie("noortrace_lease_epoch", E), "0x10"]], s: [[serie("noortrace_lease_epoch", E), "4x10"], [serie("noortrace_lease_epoch", { ...E, instance: "127.0.0.1:8501", role: "passive" }), "0x10"]], e: sans(E) },
    noortrace_bail_renouvellement: casCompteur("noortrace_lease_renew_failures_total", { store: "postgresql" }),
    noortrace_ancre_en_retard: casJauge("noortrace_anchor_pending", { anchor: "registre" }, 1, 0, duree(p.anchor_pending_alert_s + 600)),
    noortrace_copie_worm_en_retard: casJauge("noortrace_worm_copy_pending", {}, 1, 0, "70m"),
    noortrace_verrou_worm_non_conforme: casJauge("noortrace_worm_lock_nonconforming", {}, 1, 0, "3m"),
    noortrace_retention_support_non_conforme: casLigne({ event: "worm_lock_config_check", level: "error", detail: "non_conforme" }, { event: "worm_lock_config_check", level: "info", detail: "conforme" }),
    noortrace_releve_en_retard: casJauge("noortrace_worm_last_audit_age_s", {}, s.releve + 1, s.releve, "3m"),
    noortrace_versions_inattendues: casJauge("noortrace_worm_versions_unexpected", {}, 2, 0, "3m"),
    noortrace_registre_gels_invalide: casLigne({ event: "worm_legal_hold_observed", level: "error", detail: "garde_violee" }, { event: "worm_legal_hold_observed", level: "info", detail: "autre" }),
    noortrace_gel_non_pose: casLigne({ event: "worm_lock_check", level: "error", detail: "gel_absent" }, { event: "worm_lock_check", level: "error", detail: "non_conforme" }),
    noortrace_controle_integrite: casCompteur("noortrace_integrity_check_failures_total", { check: "segments" }, { check: "configuration_worm" }),
    noortrace_gel_leve: casLigne({ event: "worm_legal_hold_observed", level: "info", detail: "levee" }, { event: "worm_legal_hold_observed", level: "info", detail: "autre" }),
    noortrace_horloge_ecart: casJauge("noortrace_clock_skew_ms", {}, -(s.horloge + 1), s.horloge, "3m"),
    noortrace_definition_outil_changee: casCompteur("noortrace_tool_definition_changes_total", { server: "outils" }),
    noortrace_fourche: casLigne({ event: "journal_fork", level: "error" }, { event: "journal_forked_ignored", level: "error" }),
    noortrace_panne_apres_relais: casCompteur("noortrace_calls_executed_not_durable_total", { class: "ecriture" }),
    noortrace_relais_refuse: casCompteur("noortrace_approval_relays_refused_total", { check: "signature" }),
    noortrace_remise_refusee: casCompteur("noortrace_approval_remises_refused_total", { check: "signature" }),
    noortrace_politique_invalide_au_charger: casLigne({ event: "approval_service_unavailable", level: "warning", detail: "politique_invalide_au_charger" }, { event: "approval_service_unavailable", level: "warning" }),
    noortrace_budget_redaction: casCompteur("noortrace_redaction_budget_exceeded_total", { operation: "detection", scope: "arguments" }),
    noortrace_budget_redaction_bloquant: casCompteur("noortrace_calls_blocked_total", { code: "-31010", reason: "redaction", class: "ecriture" }, { code: "-31010", reason: "politique", class: "ecriture" }),
    noortrace_cle_mac_relais: casLigne({ event: "relay_mac_key_mismatch", level: "error" }, { event: "relay_mac_key_changed", level: "info" }),
    noortrace_quota_hote: casCompteur("noortrace_calls_blocked_total", { code: "-31013", reason: "quota" }, { code: "503", reason: "quota", class: "modele" }),
    noortrace_otel_refusee: casCompteur("noortrace_otel_requests_total", { source: "hote-a", status: "429" }, { source: "hote-a", status: "200" }),
    noortrace_otel_spans_rejetes: casCompteur("noortrace_otel_spans_total", { source: "hote-a", issue: "rejete", reason: "schema" }, { source: "hote-a", issue: "accepte" }),
    noortrace_otel_retard: {
      t: "10m",
      f: [[serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "60000" }), "0x20"], [serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "300000" }), "0+1x20"], [serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "+Inf" }), "0+1x20"]],
      s: [[serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "60000" }), "0+1x20"], [serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "300000" }), "0+1x20"], [serie("noortrace_otel_reception_lag_ms_bucket", { ...E, source: "hote-a", le: "+Inf" }), "0+1x20"]],
      e: {},
    },
    noortrace_otel_conventions: {
      t: "6m",
      f: [[serie("noortrace_otel_spans_total", { ...E, source: "hote-a", issue: "ignore", reason: "hors_genai" }), MONTE]],
      s: [[serie("noortrace_otel_spans_total", { ...E, source: "hote-a", issue: "ignore", reason: "hors_genai" }), MONTE], [serie("noortrace_otel_spans_total", { ...E, source: "hote-a", issue: "accepte" }), MONTE]],
      e: { source: "hote-a" },
    },
    noortrace_otel_conflits: casCompteur("noortrace_otel_conflicts_total", { source: "hote-a" }),
    noortrace_latence: {
      t: "10m",
      f: [[serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "50" }), "0x20"], [serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "100" }), "0+1x20"], [serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "+Inf" }), "0+1x20"]],
      s: [[serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "50" }), "0+1x20"], [serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "100" }), "0+1x20"], [serie("noortrace_relay_latency_ms_bucket", { ...E, path: "mcp", class: "lecture", le: "+Inf" }), "0+1x20"]],
      e: {},
    },
    noortrace_disque_ligne: casLigne({ event: "disk_low", level: "error" }, { event: "storage_unavailable", level: "error" }),
    noortrace_disque_espace: (() => {
      const a = { ...X, device: "/dev/vdb1", fstype: "ext4", mountpoint: s.racine };
      return { t: "3m", f: [[serie("node_filesystem_avail_bytes", a), `${s.disque - 1}x10`]], s: [[serie("node_filesystem_avail_bytes", a), `${s.disque}x10`], [serie("node_filesystem_avail_bytes", { ...a, mountpoint: "/autre" }), "0x10"]], e: sans(a) };
    })(),
    noortrace_pieces_attente_perdues: casLigne({ event: "pending_pieces_lost", level: "error" }, { event: "pending_flushed", level: "info" }),
    noortrace_gel_pose_en_retard: casJauge("noortrace_journal_derniere_ligne_s", { source: "gel", event: "worm_legal_hold_set" }, -7300, 0, "1m", X),
    noortrace_export_lecture_impossible: casLigne({ event: "dossier_export_refused", level: "error", detail: "lecture_impossible" }, { event: "dossier_export_refused", level: "error", detail: "demande_invalide" }),
    noortrace_export_refuse: casLigne({ event: "dossier_export_refused", level: "error", detail: "exports_indisponible" }, { event: "dossier_export_refused", level: "error", detail: "lecture_impossible" }),
    noortrace_ancrage_en_attente: casLigne({ event: "registry_pending", level: "warning" }, { event: "registry_sent", level: "info" }),
    noortrace_ancrage_point_en_retard_exterieur: casLigne({ event: "alerte_checkpoint_anchor_late", level: "warning", detail: "exterieur" }, { event: "alerte_checkpoint_anchor_late", level: "warning", detail: "interne" }),
    noortrace_ancrage_point_en_retard_interne: casLigne({ event: "alerte_checkpoint_anchor_late", level: "warning", detail: "interne" }, { event: "alerte_checkpoint_anchor_late", level: "warning", detail: "exterieur" }),
    noortrace_ancrage_inclusion_lente: (() => {
      const a = { ...E, kind: "ancre_registre_point" };
      return { t: "6m", f: [[serie("noortrace_anchoring_d_registre_s_count", a), MONTE], [serie("noortrace_anchoring_d_registre_s_bucket", { ...a, le: String(s.inclusion) }), PLAT]], s: [[serie("noortrace_anchoring_d_registre_s_count", a), MONTE], [serie("noortrace_anchoring_d_registre_s_bucket", { ...a, le: String(s.inclusion) }), MONTE]], e: sans(a) };
    })(),
    noortrace_ancrage_inclusion_lente_repetee: (() => {
      const a = { ...E, kind: "ancre_registre_point" };
      return { t: "6m", f: [[serie("noortrace_anchoring_d_registre_s_count", a), "0 0 0 5 5 5 5"], [serie("noortrace_anchoring_d_registre_s_bucket", { ...a, le: `${s.inclusion}.0` }), MONTE]], s: [[serie("noortrace_anchoring_d_registre_s_count", a), "0 0 0 3 3 3 3"], [serie("noortrace_anchoring_d_registre_s_bucket", { ...a, le: `${s.inclusion}.0` }), PLAT]], e: sans(a) };
    })(),
    noortrace_ancrage_prestataire_injoignable: (() => {
      const a = { ...E, kind: "jeton_periode", provider: "tsa-principal" };
      return { t: "6m", f: [[serie("noortrace_anchoring_last_success_age_s", a), "1000x10"], [serie("noortrace_anchoring_attempts_total", { ...a, outcome: "en_cours" }), MONTE]], s: [[serie("noortrace_anchoring_last_success_age_s", a), "1000x10"], [serie("noortrace_anchoring_attempts_total", { ...a, outcome: "en_cours" }), PLAT]], e: sans(a) };
    })(),
    noortrace_ancrage_prestataires_epuises_periode: (() => {
      const a = { ...E, kind: "jeton_periode", state: "a_reprendre" };
      const t = { ...E, kind: "jeton_periode", provider: "inconnu", outcome: "echec_permanente" };
      return { t: "6m", f: [[serie("noortrace_anchoring_queue_entries", a), "1x10"], [serie("noortrace_anchoring_attempts_total", t), MONTE]], s: [[serie("noortrace_anchoring_queue_entries", a), "1x10"], [serie("noortrace_anchoring_attempts_total", { ...t, outcome: "echec_transitoire" }), MONTE]], e: sans(a) };
    })(),
    noortrace_ancrage_prestataires_epuises_point: casLigne({ event: "anchor_refused", level: "error", detail: "autre" }, { event: "anchor_refused", level: "error", detail: "empreinte_squattee" }),
    noortrace_ancrage_file: casLigne({ event: "anchor_queue_full", level: "error" }, { event: "anchoring_queue_rebuilt", level: "info", detail: "aucune" }),
    noortrace_ancrage_ots_abandon: casJauge("noortrace_anchoring_ots_pending_age_s", {}, s.ots + 1, s.ots, "3m"),
    noortrace_ancrage_ordre: (() => {
      const a = { source: "exploitation", event: "ordre_ancres_non_respecte", level: "warning", ...X };
      return { t: "6m", f: [[serie(LJ, a), "0 0 0 2 2 2 2"]], s: [[serie(LJ, a), MONTE]], e: sans(a) };
    })(),
    noortrace_ancrage_empreinte_squattee: casLigne({ event: "anchor_refused", level: "error", detail: "empreinte_squattee" }, { event: "anchor_refused", level: "error", detail: "autre" }),
    noortrace_ancrage_horloge_suspecte: casLigne({ source: "acquisitions", event: "acquisition", detail: "horloge_suspecte" }, { source: "acquisitions", event: "acquisition", detail: "obtenue" }),
    noortrace_ancrage_revoque: casLigne({ source: "acquisitions", event: "acquisition", detail: "revoque" }, { source: "acquisitions", event: "acquisition", detail: "obtenue" }),
    noortrace_ancrage_reponse_tardive_promue: casLigne({ source: "acquisitions", event: "acquisition", detail: "reponse_tardive_promue" }, { source: "acquisitions", event: "acquisition", detail: "obtenue" }),
    noortrace_ancrage_point_manquant: casLigne({ event: "point_manquant", level: "warning" }, { event: "checkpoint_countersigned", level: "info" }),
    noortrace_ancrage_jeton_anterieur: casLigne({ event: "alerte_jeton_anterieur_au_point", level: "warning" }, { event: "alerte_contresignature_tardive", level: "warning" }),
    noortrace_ancrage_contresignature_tardive: casLigne({ event: "alerte_contresignature_tardive", level: "warning" }, { event: "alerte_jeton_anterieur_au_point", level: "warning" }),
    noortrace_ancrage_volume: (() => {
      const a = { ...E, kind: "jeton_point", provider: "tsa-principal", outcome: "obtenue" };
      const haut = Math.ceil((s.a_h * 2 * 1.5) / 60) + 1;
      return { t: "65m", f: [[serie("noortrace_anchoring_attempts_total", a), `0+${haut}x70`]], s: [[serie("noortrace_anchoring_attempts_total", a), `0+${Math.max(1, Math.floor(s.a_h / 60))}x70`]], e: {} };
    })(),
    noortrace_registre_cible_muette: { t: "4m", f: [[serie("up", { instance: "127.0.0.1:9645", job: "noorcore", role: "validateur" }), "0x10"]], s: [[serie("up", { instance: "127.0.0.1:9645", job: "noorcore", role: "validateur" }), "1x10"], [serie("up", { ...X }), "0x10"]], e: { instance: "127.0.0.1:9645", job: "noorcore", role: "validateur" } },
    noortrace_registre_sonde: casJauge("noortrace_registre_sonde_ok", { target: "validateur-1" }, 0, 1, "4m", X),
    noortrace_registre_hauteur_figee: { t: "8m", f: [[serie("noortrace_registre_hauteur", { ...X, target: "validateur-1" }), "100x10"]], s: [[serie("noortrace_registre_hauteur", { ...X, target: "validateur-1" }), "100+1x10"]], e: sans({ ...X, target: "validateur-1" }) },
    noortrace_registre_equivocation: casCompteur("noor_bft_equivocations_total", {}, null, { instance: "127.0.0.1:9645", job: "noorcore", role: "validateur" }),
    noortrace_registre_mempool: casJauge("noortrace_registre_mempool", { target: "validateur-1" }, s.mempool + 1, s.mempool, "8m", X),
    noortrace_registre_sous_tarif: casLigne({ event: "registry_send_refused", level: "error", detail: "transaction_underpriced" }, { event: "registry_send_refused", level: "error", detail: "nonce_too_low" }),
    noortrace_registre_cloture_non_soumise: casJauge("noortrace_anchoring_last_success_age_s", { kind: "ancre_registre_periode", provider: "registre" }, 90001, 90000, "3m"),
    noortrace_registre_capture_en_retard: casJauge("noortrace_anchoring_last_success_age_s", { kind: "ancre_registre_periode", provider: "registre" }, 7201, 7200, "3m"),
    noortrace_registre_solde_bas: casJauge("noortrace_registre_solde_wei", { sender: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" }, s.solde - 1, s.solde, "3m", X),
    noortrace_registre_examen_requis: casLigne({ source: "registre", event: "ancrer", detail: "examen_requis" }, { source: "registre", event: "ancrer" }),
    noortrace_registre_marge_retention: casLigne({ source: "registre", event: "capturer", detail: "marge_retention_basse" }, { source: "registre", event: "capturer" }),
    noortrace_hote_disque: (() => {
      const a = { ...X, device: "/dev/vda1", fstype: "ext4", mountpoint: "/" };
      return { t: "15m", f: [[serie("node_filesystem_avail_bytes", a), "5x20"], [serie("node_filesystem_size_bytes", a), "100x20"]], s: [[serie("node_filesystem_avail_bytes", a), "50x20"], [serie("node_filesystem_size_bytes", a), "100x20"], [serie("node_filesystem_avail_bytes", { ...a, fstype: "tmpfs", mountpoint: "/run" }), "1x20"], [serie("node_filesystem_size_bytes", { ...a, fstype: "tmpfs", mountpoint: "/run" }), "100x20"]], e: sans(a) };
    })(),
    noortrace_hote_memoire: { t: "15m", f: [[serie("node_memory_MemAvailable_bytes", X), "5x20"], [serie("node_memory_MemTotal_bytes", X), "100x20"]], s: [[serie("node_memory_MemAvailable_bytes", X), "50x20"], [serie("node_memory_MemTotal_bytes", X), "100x20"]], e: sans(X) },
    noortrace_hote_processeur: { t: "25m", f: [[serie("node_cpu_seconds_total", { ...X, cpu: "0", mode: "idle" }), "0+3x30"]], s: [[serie("node_cpu_seconds_total", { ...X, cpu: "0", mode: "idle" }), "0+57x30"]], e: { instance: X.instance } },
    noortrace_approbation_non_pret: casJauge("noortrace_approbation_pret", {}, 0, 1, "8m", X),
    noortrace_console_non_prete: casJauge("noortrace_console_prete", {}, 0, 1, "8m", X),
    noortrace_notification_echec: casLigne({ source: "approbation", event: "notification_echec", detail: "reseau" }, { source: "approbation", event: "notification_livree" }),
    noortrace_notification_abandonnee: casLigne({ source: "approbation", event: "notification_abandonnee", detail: "reprises_epuisees" }, { source: "approbation", event: "notification_echec", detail: "reseau" }),
    noortrace_notification_sans_destinataire: casLigne({ source: "approbation", event: "notification_sans_destinataire" }, { source: "approbation", event: "notification_livree" }),
    noortrace_sauvegarde_en_retard: casJauge("noortrace_proces_verbal_dernier_s", { kind: "sauvegarde" }, -(s.rpo + 100), 0, "1m", X),
    noortrace_exercice_restauration_en_retard: casJauge("noortrace_proces_verbal_dernier_s", { kind: "exercice_restauration" }, -34560100, 0, "1m", X),
    noortrace_acces_non_declare: casLigne({ source: "consultations", event: "lecture", detail: "inconnu" }, { source: "consultations", event: "lecture", detail: "lecteur" }),
    noortrace_consultations_muettes: { t: "1m", f: [[serie("noortrace_journal_derniere_ligne_s", { ...X, source: "consultations", event: "lecture" }), "-86500x5"]], s: [[serie("noortrace_journal_derniere_ligne_s", { ...X, source: "consultations", event: "lecture" }), "-86500x5"], [serie("noortrace_journal_derniere_ligne_s", { ...X, source: "consultations", event: "export" }), "0x5"]], e: {} },
    noortrace_journal_illisible: casCompteur("noortrace_journal_illisibles_total", { source: "exploitation" }, null, X),
    noortrace_mode_observation_actif: casJauge("noortrace_observation_mode", {}, 1, 0, "3m"),
    noortrace_observation_pertes: casCompteur("noortrace_events_lost_total", { reason: "attente" }),
    noortrace_releve_externe_echec: casJauge("noortrace_releve_externe_ok", { check: "registre_gels" }, 0, 1, "3m", X),
    noortrace_releve_externe_perime: casJauge("noortrace_releve_externe_dernier_s", { check: "registre_gels" }, -172900, 0, "1m", X),
  };
  return C;
}

/**
 * Fichier des tests des règles (EX-10.10) : pour chaque règle, une série qui
 * la déclenche et une qui ne la déclenche pas.
 * @param {object} [p] paramètres du fichier de règles testé
 * @param {string} [fichierRegles]
 */
export function genererTestsRegles(p = PARAMETRES_DEFAUT, fichierRegles = "regles-noortrace.yml") {
  const cas = casRegles(p);
  const regles = reglesCalculees(p);
  const L = [];
  L.push("# Tests des règles d'alerte de référence (CT-8 EX-10.10), au format de");
  L.push("# promtool test rules : pour chaque règle, des séries qui la déclenchent et");
  L.push("# des séries qui ne la déclenchent pas. Écrit par");
  L.push("# node scripts/deploiement/regles.mjs --reference ; ne pas éditer à la main.");
  L.push("#");
  L.push("#   promtool check rules deploiement/observabilite/regles-noortrace.yml");
  L.push("#   promtool test rules deploiement/observabilite/tests-regles.yml");
  L.push("rule_files:");
  L.push(`  - ${fichierRegles}`);
  L.push("evaluation_interval: 1m");
  L.push("tests:");
  for (const r of regles) {
    const c = cas[r.alert];
    if (!c) throw new Error(`aucun cas de test pour ${r.alert}`);
    for (const [nom, series, attendue] of [[`${r.alert} déclenchée`, c.f, true], [`${r.alert} silencieuse`, c.s, false]]) {
      L.push(`  - name: ${yq(nom)}`);
      L.push("    interval: 1m");
      L.push("    input_series:");
      for (const [sr, v] of series) {
        L.push(`      - series: ${yq(sr)}`);
        L.push(`        values: ${yq(v)}`);
      }
      L.push("    alert_rule_test:");
      L.push(`      - eval_time: ${c.t}`);
      L.push(`        alertname: ${r.alert}`);
      if (!attendue) {
        L.push("        exp_alerts: []");
        continue;
      }
      L.push("        exp_alerts:");
      L.push("          - exp_labels:");
      const et = { ...c.e, ...r.labels };
      for (const k of Object.keys(et).sort()) L.push(`              ${k}: ${yq(et[k])}`);
      L.push("            exp_annotations:");
      for (const k of ANNOTATIONS_REGLE) L.push(`              ${k}: ${yq(r.annotations[k])}`);
    }
  }
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Collecte de référence (EX-10.4) et tableau de bord (EX-10.8)
// ---------------------------------------------------------------------------

/** Configuration de collecte de référence (deploiement/observabilite/prometheus.yml). */
export function genererCollecte() {
  return [
    "# Collecte de référence de NOORTRACE (CT-8 §10.2, EX-10.4), pour Prometheus 3.5.",
    "#",
    "# Chaque point de collecte écoute sur l'adresse de bouclage (EX-10.4) ; chaque",
    "# cible porte l'étiquette role : active ou passive pour une instance de",
    "# l'enregistreur (CT-2 §13), validateur ou relais pour un nœud, hote pour",
    "# l'exportateur de nœud. La règle noortrace_bail_non_detenu lit role.",
    "#",
    "# L'extracteur (scripts/deploiement/extraire-journaux.mjs) et la sonde",
    "# (scripts/deploiement/sonde.mjs) écrivent leurs métriques dans le répertoire",
    "# du collecteur textfile de l'exportateur de nœud, lancé avec",
    "#   --collector.textfile.directory=/var/lib/noortrace-supervision",
    "# ils tournent sous une identité distincte de chaque composant supervisé,",
    "# en lecture seule sur les journaux (EX-10.3).",
    "#",
    "# Deux instances de l'enregistreur : dupliquer la cible enregistreur avec",
    "# role passive pour l'instance de secours. Le nœud du registre n'expose ses",
    "# métriques qu'avec -metrics-addr (désactivé par défaut ; 9645 à 9648 sur le",
    "# réseau de développement).",
    "global:",
    "  scrape_interval: 15s",
    "  evaluation_interval: 15s",
    "rule_files:",
    "  - regles-noortrace.yml",
    "scrape_configs:",
    "  - job_name: enregistreur",
    "    metrics_path: /metrics",
    "    static_configs:",
    "      - targets: ['127.0.0.1:8500']",
    "        labels:",
    "          role: active",
    "  - job_name: hote",
    "    static_configs:",
    "      - targets: ['127.0.0.1:9100']",
    "        labels:",
    "          role: hote",
    "  - job_name: noorcore",
    "    static_configs:",
    "      - targets: ['127.0.0.1:9645']",
    "        labels:",
    "          role: validateur",
    "",
  ].join("\n");
}

/** Panneaux du tableau de bord (EX-10.8) : rangée, titre, expressions. */
export const PANNEAUX = Object.freeze([
  ["Capture", "Événements par sorte et statut", ["sum by (kind, status) (rate(noortrace_events_total[5m]))"]],
  ["Capture", "Latence ajoutée p50 et p99 (ms)", ["histogram_quantile(0.5, sum by (le) (rate(noortrace_relay_latency_ms_bucket[5m])))", "histogram_quantile(0.99, sum by (le) (rate(noortrace_relay_latency_ms_bucket[5m])))"]],
  ["Capture", "Appels bloqués par raison", ["sum by (reason) (rate(noortrace_calls_blocked_total[5m]))"]],
  ["Durabilité", "fdatasync p99 (ms)", ["histogram_quantile(0.99, sum by (le) (rate(noortrace_fsync_duration_ms_bucket[5m])))"]],
  ["Durabilité", "Taille du groupe d'écriture p99", ["histogram_quantile(0.99, sum by (le) (rate(noortrace_fsync_group_size_bucket[5m])))"]],
  ["Durabilité", "Événements en attente", ["noortrace_pending_events"]],
  ["Durabilité", "Mode dégradé par raison", ["max by (reason) (noortrace_degraded)"]],
  ["Durabilité", "Époque du bail par instance", ["noortrace_lease_epoch"]],
  ["Copies WORM", "Copies WORM en attente", ["noortrace_worm_copy_pending"]],
  ["Copies WORM", "Âge du dernier relevé (s)", ["noortrace_worm_last_audit_age_s"]],
  ["Copies WORM", "Versions non conformes", ["noortrace_worm_lock_nonconforming"]],
  ["Copies WORM", "Gels actifs", ["noortrace_worm_legal_holds_active"]],
  ["Ancrage", "Périodes non confirmées par ancre", ["noortrace_anchor_pending"]],
  ["Ancrage", "Fenêtre de date (s)", ["noortrace_anchoring_window_s"]],
  ["Ancrage", "d_jeton p99 (s)", ["histogram_quantile(0.99, sum by (le, kind) (rate(noortrace_anchoring_d_jeton_s_bucket[1h])))"]],
  ["Ancrage", "Demandes par état", ["sum by (kind, state) (noortrace_anchoring_queue_entries)"]],
  ["Registre", "Hauteur par cible", ["noortrace_registre_hauteur"]],
  ["Registre", "Mempool par cible", ["noortrace_registre_mempool"]],
  ["Registre", "Équivocations", ["increase(noor_bft_equivocations_total[1h])"]],
  ["Registre", "Soldes des expéditeurs (wei)", ["noortrace_registre_solde_wei"]],
  ["Approbation", "Signaux d'approbation par état", ["sum by (state) (rate(noortrace_approval_signals_total[5m]))"]],
  ["Approbation", "Remises et relais refusés", ["sum(increase(noortrace_approval_remises_refused_total[1h]))", "sum(increase(noortrace_approval_relays_refused_total[1h]))"]],
  ["Approbation", "Service d'approbation prêt", ["noortrace_approbation_pret"]],
  ["Approbation", "Serveur de console prêt", ["noortrace_console_prete"]],
  ["Approbation", "Livraison des notifications par event", ['sum by (event) (increase(noortrace_journal_lignes_total{source="approbation"}[1h]))']],
  ["Mode observation", "Mode observation", ["noortrace_observation_mode"]],
  ["Mode observation", "Marques par décision", ["sum by (would) (increase(noortrace_observation_marks_total[1h]))"]],
  ["Mode observation", "Événements perdus", ["sum by (reason) (increase(noortrace_events_lost_total[1h]))"]],
  ["Hôte", "Processeur occupé", ['1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))']],
  ["Hôte", "Mémoire disponible", ["node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes"]],
  ["Hôte", "Espace libre de la racine", (s) => [`node_filesystem_avail_bytes{mountpoint="${s.racine}"} / node_filesystem_size_bytes{mountpoint="${s.racine}"}`]],
].map(([rangee, titre, exprs]) => Object.freeze({ rangee, titre, exprs })));

/**
 * Tableau de bord de référence (deploiement/observabilite/tableau-noortrace.json),
 * de la forme d'un tableau de bord (uid, panneaux, rangées).
 * @param {object} [p] paramètres (racine)
 */
export function genererTableau(p = PARAMETRES_DEFAUT) {
  const s = seuils(p);
  const panels = [];
  let id = 1;
  let y = 0;
  const rangees = [...new Set(PANNEAUX.map((x) => x.rangee))];
  for (const r of rangees) {
    panels.push({ id: id++, type: "row", title: r, collapsed: false, gridPos: { h: 1, w: 24, x: 0, y: y++ }, panels: [] });
    let x = 0;
    for (const pn of PANNEAUX.filter((q) => q.rangee === r)) {
      const exprs = typeof pn.exprs === "function" ? pn.exprs(s) : pn.exprs;
      if (x >= 24) { x = 0; y += 8; }
      panels.push({
        id: id++,
        type: "timeseries",
        title: pn.titre,
        datasource: { type: "prometheus", uid: "${DS_PROMETHEUS}" },
        gridPos: { h: 8, w: 6, x, y },
        targets: exprs.map((e, k) => ({ refId: String.fromCharCode(65 + k), expr: e })),
      });
      x += 6;
    }
    y += 8;
  }
  return {
    uid: "noortrace",
    title: "NOORTRACE",
    description: "Tableau de bord de référence de NOORTRACE (CT-8 EX-10.8) ; chaque expression ne nomme que des métriques de CT-8 10.2 et 10.3 (SV-7).",
    tags: ["noortrace"],
    timezone: "utc",
    schemaVersion: 39,
    version: 1,
    refresh: "30s",
    time: { from: "now-6h", to: "now" },
    templating: { list: [{ name: "DS_PROMETHEUS", type: "datasource", query: "prometheus", label: "Source Prometheus" }] },
    panels,
  };
}

/** Expressions d'un tableau de bord (panneaux et rangées imbriquées). */
export function expressionsTableau(t) {
  const out = [];
  const visiter = (ps) => {
    for (const p of ps ?? []) {
      for (const tg of p.targets ?? []) if (typeof tg.expr === "string") out.push(tg.expr);
      visiter(p.panels);
    }
  };
  visiter(t.panels);
  return out;
}
