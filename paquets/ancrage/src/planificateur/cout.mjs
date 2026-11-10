// Formule de coût de CT-5 §12 (EX-12.1, EX-12.2, AN-59) : nombres de jetons,
// d'ancres et de gaz par journal et par an, coût en unités symboliques. Les
// prix sont des paramètres (`unit_price_*`, `subscription_fee`) : aucun prix
// réel ne figure ici (AN-60). Les entrées sont celles de `$defs/cas_cout`.

/** Gaz au plus d'un appel `anchor` (CT-4 §4.5, CT-5 §9.3). */
export const GAZ_ANCRE_MAX = 96977;
/** Gaz au plus d'un `submitPeriod` mesuré (CT-4 §4.5). */
export const GAZ_CLOTURE_MAX = 314256;

const estEntier = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;
const estNombre = (v, min, max = Infinity) => typeof v === "number" && Number.isFinite(v) && v >= min && v <= max;
/** Arrondi à 10^-9, qui efface les résidus binaires des prix décimaux (0,2 × 96 360). */
const arrondir = (x) => Math.round(x * 1e9) / 1e9;

/**
 * Contrôle les entrées d'un cas de coût (bornes de `$defs/cas_cout.input`).
 * @param {object} e
 */
function controler(e) {
  if (e === null || typeof e !== "object" || Array.isArray(e)) throw new TypeError("entrées de coût : objet attendu");
  if (!estEntier(e.journals, 1, 1000000)) throw new RangeError("journals : entier de 1 à 1 000 000");
  if (!estEntier(e.hours_per_year, 1, 8784)) throw new RangeError("hours_per_year : entier de 1 à 8 784");
  if (!estEntier(e.checkpoint_interval_s, 10, 3600) || 3600 % e.checkpoint_interval_s !== 0) throw new RangeError("checkpoint_interval_s : diviseur de 3600 entre 10 et 3600");
  if (!estEntier(e.rfc3161_checkpoint_interval_s, 60, 3600) || 3600 % e.rfc3161_checkpoint_interval_s !== 0) throw new RangeError("rfc3161_checkpoint_interval_s : diviseur de 3600 entre 60 et 3600");
  if (!estNombre(e.activity_ratio, 0, 1)) throw new RangeError("activity_ratio : nombre de 0 à 1");
  if (!["principal", "second_rang", "interne", "aucun"].includes(e.checkpoints_provider_role)) throw new RangeError("checkpoints_provider_role hors énumération");
  if (typeof e.countersign_idle !== "boolean") throw new TypeError("countersign_idle : booléen attendu");
  if (!["nouveaux_evenements", "tous", "aucun"].includes(e.registry_checkpoints)) throw new RangeError("registry_checkpoints hors énumération");
  if (!estNombre(e.unit_price_qualified, 0)) throw new RangeError("unit_price_qualified : nombre non négatif");
  if (!estNombre(e.unit_price_second_rank, 0)) throw new RangeError("unit_price_second_rank : nombre non négatif");
  if (!estNombre(e.subscription_fee, 0)) throw new RangeError("subscription_fee : nombre non négatif");
  if (e.subscription_quota !== null && !estEntier(e.subscription_quota, 0, Number.MAX_SAFE_INTEGER)) throw new RangeError("subscription_quota : entier non négatif ou null");
  if (!estNombre(e.billable_retry_ratio, 0, 10)) throw new RangeError("billable_retry_ratio : nombre de 0 à 10");
}

/**
 * EX-12.1 et EX-12.2 : les six grandeurs de `$defs/cas_cout.expected`.
 * @param {object} entrees `$defs/cas_cout.input`
 * @returns {{qualified_tokens_per_journal: number, second_rank_tokens_per_journal: number, registry_anchors_per_journal: number,
 *   gas_upper_bound_per_journal: number, cost_per_journal: number, cost_total: number}}
 */
export function cout(entrees) {
  controler(entrees);
  const e = entrees;
  const nH = e.hours_per_year;
  const nT = 3600 / e.rfc3161_checkpoint_interval_s;
  const a = e.countersign_idle ? 1 : e.activity_ratio;
  const deltaQ = e.checkpoints_provider_role === "principal" ? 1 : 0;
  const deltaS = e.checkpoints_provider_role === "second_rang" || e.checkpoints_provider_role === "interne" ? 1 : 0;
  const deltaR = e.registry_checkpoints === "aucun" ? 0 : 1;
  const nQ = arrondir(nH * (1 + deltaQ * (nT - 1) * a));
  const nS = arrondir(nH * deltaS * (nT - 1) * a);
  const nA = nH * (1 + deltaR * (1 + 3600 / e.checkpoint_interval_s));
  const gaz = nA * GAZ_ANCRE_MAX + nH * GAZ_CLOTURE_MAX;
  const r = 1 + e.billable_retry_ratio;
  const pQ = e.unit_price_qualified;
  const pS = e.unit_price_second_rank;
  let coutJournal;
  if (e.subscription_fee === 0 && e.subscription_quota === null) {
    coutJournal = pQ * nQ * r + pS * nS * r;
  } else {
    const depassement = e.subscription_quota === null ? 0 : Math.max(0, nQ * r - e.subscription_quota);
    coutJournal = e.subscription_fee + pQ * depassement + pS * nS * r;
  }
  coutJournal = arrondir(coutJournal);
  return {
    qualified_tokens_per_journal: nQ,
    second_rank_tokens_per_journal: nS,
    registry_anchors_per_journal: nA,
    gas_upper_bound_per_journal: gaz,
    cost_per_journal: coutJournal,
    cost_total: arrondir(coutJournal * e.journals),
  };
}
