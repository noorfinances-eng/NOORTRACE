// Sélection et comptages de CT-5 §4.3 et §4.6 (AN-4) : points à ancrer au
// registre selon `registry.checkpoints` (EX-4.6), nombres de jetons, d'ancres
// et de soumissions par heure, par jour et par an pour une configuration
// (EX-4.11), calculés sans réseau.

import { decoderHorodatage, estHex, hacherPoint } from "@noortrace/noyau";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Empreinte d'un point : `checkpoint_hash` s'il est donné, sinon H(K) recalculée
 * d'un point signé au format CT-1 (noyau `hacherPoint`) ; null si impossible.
 * @param {object} p
 * @returns {string|null}
 */
function empreintePoint(p) {
  if (estHex(p.checkpoint_hash, 32)) return p.checkpoint_hash;
  if (p.checkpoint_hash !== undefined || !estHex(p.root, 32) || typeof p.key_id !== "string") return null;
  try {
    return hacherPoint(p);
  } catch {
    return null;
  }
}

/**
 * EX-4.6, EX-9.3 : les points d'une série à ancrer au registre.
 * @param {{points: {checkpoint_hash: string, tree_size: number, checkpoint_ts: string}[], regle: "nouveaux_evenements"|"tous"|"aucun"}} p
 *   `points` dans l'ordre de la série
 * @returns {{checkpoint_hash: string, tree_size: number, checkpoint_ts: string, raison: "nouveaux_evenements"|"tous"}[]}
 */
export function pointsAAncrer({ points, regle }) {
  if (!Array.isArray(points)) throw new TypeError("tableau de points attendu");
  if (!["nouveaux_evenements", "tous", "aucun"].includes(regle)) throw new RangeError(`règle inconnue : ${String(regle)}`);
  const retenus = [];
  if (regle === "aucun") return retenus;
  let base = 0;
  let tsPrecedent = null;
  for (const p of points) {
    const empreinte = estObjet(p) ? empreintePoint(p) : null;
    if (empreinte === null || !Number.isSafeInteger(p.tree_size) || p.tree_size < 0) throw new TypeError("point : checkpoint_hash et tree_size attendus");
    const ts = decoderHorodatage(p.checkpoint_ts);
    if (ts === null) throw new TypeError(`point : checkpoint_ts invalide (${String(p.checkpoint_ts)})`);
    if (tsPrecedent !== null && ts < tsPrecedent) throw new RangeError("série non ordonnée par checkpoint_ts");
    tsPrecedent = ts;
    if (regle === "tous" || p.tree_size > base) {
      retenus.push({ checkpoint_hash: empreinte, tree_size: p.tree_size, checkpoint_ts: p.checkpoint_ts, raison: regle });
      base = Math.max(base, p.tree_size);
    }
  }
  return retenus;
}

/**
 * Lit les cadences d'une configuration `ancrage-v0` ou de sa projection.
 * @param {object} c
 */
function cadences(c) {
  if (!estObjet(c) || !estObjet(c.rfc3161) || !estObjet(c.rfc3161.checkpoints) || !estObjet(c.registry) || !estObjet(c.opentimestamps)) {
    throw new TypeError("configuration ancrage-v0 ou projection attendue");
  }
  const cK = c.checkpoint_interval_s;
  const cT = c.rfc3161.checkpoints.interval_s;
  if (!Number.isSafeInteger(cK) || cK < 10 || cK > 3600 || 3600 % cK !== 0) throw new RangeError("checkpoint_interval_s : diviseur de 3600 entre 10 et 3600");
  if (!Number.isSafeInteger(cT) || cT < 60 || cT > 3600 || 3600 % cT !== 0 || cT % cK !== 0) throw new RangeError("rfc3161.checkpoints.interval_s : multiple de c_K et diviseur de 3600");
  return { cK, cT, role: c.rfc3161.checkpoints.provider_role, registre: c.registry.checkpoints, ots: c.opentimestamps.enabled, miPeriode: c.opentimestamps.checkpoint === "mi_periode" };
}

/**
 * EX-4.11 : comptages par heure, par jour et par an en fonctionnement nominal
 * (maxima : au moins un nouvel événement par intervalle `c_T`).
 * @param {object} configuration document `ancrage-v0` ou projection d'EX-8.2
 * @param {{heuresParAn?: number}} [options] 8 760 par défaut, 8 784 pour une année bissextile
 * @returns {{n_T: number, par_heure: object, par_jour: object, par_an: object}}
 */
export function compterJetons(configuration, options = {}) {
  const heuresParAn = options.heuresParAn ?? 8760;
  if (!Number.isSafeInteger(heuresParAn) || heuresParAn < 1 || heuresParAn > 8784) throw new RangeError("heuresParAn : entier de 1 à 8 784");
  const { cK, cT, role, registre, ots, miPeriode } = cadences(configuration);
  const nT = 3600 / cT;
  const points = role === "aucun" ? 0 : nT - 1;
  const qualifies = 1 + (role === "principal" ? points : 0);
  const autres = role === "second_rang" || role === "interne" ? points : 0;
  const ancresPoints = registre === "aucun" ? 0 : 1 + 3600 / cK;
  const parHeure = {
    jetons: 1 + points,
    jetons_points: points,
    jetons_qualifies: qualifies,
    jetons_autres: autres,
    jeton_cloture: 1,
    ancres: 1 + ancresPoints,
    ancres_points: ancresPoints,
    submit_period: 1,
    soumissions_ots: ots ? 1 + (miPeriode && nT > 1 ? 1 : 0) : 0,
  };
  const multiplier = (n) => Object.fromEntries(Object.entries(parHeure).map(([k, v]) => [k, v * n]));
  return { n_T: nT, heures_par_an: heuresParAn, par_heure: parHeure, par_jour: multiplier(24), par_an: multiplier(heuresParAn) };
}

/**
 * Table d'EX-4.11 pour les cadences usuelles (N_h = 8 760) : jetons par heure,
 * dont points, par jour, par an, qualifiés par an selon le rôle des points.
 * @returns {{c_T: number, jetons_par_heure: number, dont_points: number, jetons_par_jour: number, jetons_par_an: number,
 *   qualifies_par_an_principal: number, qualifies_par_an_autre: number, autres_par_an_autre: number}[]}
 */
export function tableComptages() {
  return [60, 120, 180, 300, 600, 900, 1800, 3600].map((cT) => {
    const nT = 3600 / cT;
    return {
      c_T: cT,
      jetons_par_heure: nT,
      dont_points: nT - 1,
      jetons_par_jour: 24 * nT,
      jetons_par_an: 8760 * nT,
      qualifies_par_an_principal: 8760 * nT,
      qualifies_par_an_autre: 8760,
      autres_par_an_autre: 8760 * (nT - 1),
    };
  });
}
