// Frais de l'instance que l'agent applique (CT-4 EX-7.23 et EX-7.9, complément du 2026-11-25, décision du porteur
// sur l'outil d'inscription ; INTERFACES.md 3.6) : `provision_days`, `refill_below_days`, `gas_limit` et
// `max_daily_budget_gas` de `fees` du manifeste d'instance (4.8), complétés par les défauts d'EX-7.2, tels que
// l'agent les lit. L'agent les écrit dans ses données (`frais-instance.json`), à son démarrage et à chaque relecture
// du manifeste qui les change ; l'interface les lit pour dire combien de jours de la consommation prévue un
// versement couvre. Ce fichier n'entre dans aucun dossier, aucune sortie ni le paquet.
//
// Module pur : l'agent écrit la forme par `fraisInstance`, l'interface la relit par `lireFraisLus` (une forme
// inattendue vaut absence : l'écran ne dit alors aucun nombre de jours tiré de ces réglages).

/** Nom du fichier dans les données de l'agent (INTERFACES.md 3.6). */
export const FICHIER_FRAIS = "frais-instance.json";

const entierPositif = (v) => Number.isSafeInteger(v) && v >= 0;

/** Le document écrit par l'agent depuis l'instance chargée (`fees` normalisés, SHA-256 du manifeste ou null). */
export function fraisInstance(instance) {
  const f = instance.fees;
  return {
    version: 0,
    provision_days: f.provision_days,
    refill_below_days: f.refill_below_days,
    gas_limit: f.gas_limit,
    max_daily_budget_gas: entierPositif(f.max_daily_budget_gas) ? f.max_daily_budget_gas : null,
    manifest_sha256: instance.manifestSha256 ?? null,
  };
}

/**
 * Relit le document : `{ provision_days, refill_below_days, gas_limit, max_daily_budget_gas, manifest_sha256 }`
 * aux formes attendues (entiers positifs ; plafond nul admis), ou null.
 */
export function lireFraisLus(o) {
  if (!o || typeof o !== "object" || Array.isArray(o) || o.version !== 0) return null;
  for (const k of ["provision_days", "refill_below_days", "gas_limit"]) if (!entierPositif(o[k])) return null;
  if (o.max_daily_budget_gas !== null && !entierPositif(o.max_daily_budget_gas)) return null;
  if (o.manifest_sha256 !== null && !/^0x[0-9a-f]{64}$/.test(String(o.manifest_sha256))) return null;
  return { provision_days: o.provision_days, refill_below_days: o.refill_below_days, gas_limit: o.gas_limit, max_daily_budget_gas: o.max_daily_budget_gas, manifest_sha256: o.manifest_sha256 };
}
