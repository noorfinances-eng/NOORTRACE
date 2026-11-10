// Échéances et fenêtres (CT-5 EX-4.2, EX-4.3, EX-4.4, AN-2) : liste des D_k
// d'une période, point sélectionné à chaque échéance d'après une série de
// points et des ancres obtenues (le dernier point contresigné n'avance que
// sur les jetons obtenus, toutes demandes closes), échéances satisfaites,
// `sans_objet` et `remplacee`, délais `d_jeton` et `d_registre`, constat de
// cadence (EX-4.1) et alertes `jeton_anterieur_au_point`,
// `contresignature_tardive`, `checkpoint_anchor_late`, `point_manquant`.

import { decoderHorodatage, ecrireHorodatage, estHex, hacherPoint } from "@noortrace/noyau";

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
const sEntieres = (dms) => Math.trunc(dms / 1000);
const msDe = (h, nom) => {
  const v = typeof h === "string" ? decoderHorodatage(h) : null;
  if (v === null) throw new TypeError(`${nom} : horodatage invalide (${String(h)})`);
  return v;
};
/** `gen_time` en secondes (décimales facultatives) ou horodatage complet, en millisecondes. */
const msGen = (g, nom) => {
  const m = typeof g === "string" ? /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?Z$/.exec(g) : null;
  if (!m) throw new TypeError(`${nom} : gen_time invalide (${String(g)})`);
  return msDe(`${m[1]}.${(m[2] ?? ".000").slice(1).padEnd(3, "0")}Z`, nom);
};

/**
 * EX-4.2 : les échéances `D_k = period_start + k × c_T`, `k = 1 … n_T − 1`, et
 * la clôture, `n_T`-ième échéance.
 * @param {{periodStart: number, intervalS: number}} p
 * @returns {{n_T: number, period_end: number, liste: {k: number, at: string, at_ms: number}[], cloture: {k: number, at: string, at_ms: number}}}
 */
export function echeances({ periodStart, intervalS }) {
  if (!Number.isSafeInteger(periodStart) || periodStart < 0 || periodStart % 3600 !== 0) throw new RangeError("period_start : heure UTC pleine en secondes attendue");
  if (!Number.isSafeInteger(intervalS) || intervalS < 60 || intervalS > 3600 || 3600 % intervalS !== 0) throw new RangeError("interval_s : diviseur de 3600 entre 60 et 3600");
  const nT = 3600 / intervalS;
  const liste = [];
  for (let k = 1; k <= nT - 1; k++) {
    const at = (periodStart + k * intervalS) * 1000;
    liste.push({ k, at: ecrireHorodatage(at), at_ms: at });
  }
  const fin = (periodStart + 3600) * 1000;
  return { n_T: nT, period_end: periodStart + 3600, liste, cloture: { k: nT, at: ecrireHorodatage(fin), at_ms: fin } };
}

/**
 * Lit et ordonne une série de points.
 * @param {object[]} points
 */
function lirePoints(points, periodStart) {
  if (!Array.isArray(points)) throw new TypeError("tableau de points attendu");
  const lus = points.map((p, i) => {
    const empreinte = estObjet(p) ? empreintePoint(p) : null;
    if (empreinte === null || !Number.isSafeInteger(p.tree_size) || p.tree_size < 0) throw new TypeError(`points[${i}] : checkpoint_hash et tree_size attendus`);
    const ts = msDe(p.checkpoint_ts, `points[${i}].checkpoint_ts`);
    if (ts < periodStart * 1000) throw new RangeError(`points[${i}] : checkpoint_ts antérieur à period_start`);
    return { checkpoint_hash: empreinte, tree_size: p.tree_size, checkpoint_ts: p.checkpoint_ts, ts };
  });
  for (let i = 1; i < lus.length; i++) {
    if (lus[i].ts < lus[i - 1].ts) throw new RangeError(`points[${i}] : checkpoint_ts décroît`);
    if (lus[i].tree_size < lus[i - 1].tree_size) throw new RangeError(`points[${i}] : tree_size décroît`);
  }
  return lus;
}

/**
 * EX-4.1, AN-2 : constat de cadence d'une série. Un écart est signalé entre
 * deux points consécutifs, ou entre le début de la période et le premier
 * point, au-delà de `c_K + 1 s` ; `point_manquant` quand il atteint `2 × c_K`.
 * @param {{periodStart: number, checkpointIntervalS: number, points: {checkpoint_hash: string, tree_size: number, checkpoint_ts: string}[]}} p
 * @returns {{conforme: boolean, tolerance_s: number, ecarts: {de: string|null, a: string, gap_s: number}[], points_manquants: {last_checkpoint_ts: string, gap_s: number}[]}}
 */
export function constaterCadence({ periodStart, checkpointIntervalS, points }) {
  if (!Number.isSafeInteger(checkpointIntervalS) || checkpointIntervalS < 10 || checkpointIntervalS > 3600 || 3600 % checkpointIntervalS !== 0) {
    throw new RangeError("checkpoint_interval_s : diviseur de 3600 entre 10 et 3600");
  }
  const lus = lirePoints(points, periodStart);
  const tolerance = checkpointIntervalS * 1000 + 1000;
  const ecarts = [];
  const manquants = [];
  let precedent = periodStart * 1000;
  let precedentTs = null;
  for (const p of lus) {
    const gap = p.ts - precedent;
    if (gap > tolerance) ecarts.push({ de: precedentTs, a: p.checkpoint_ts, gap_s: sEntieres(gap) });
    if (precedentTs !== null && gap >= 2 * checkpointIntervalS * 1000) manquants.push({ last_checkpoint_ts: precedentTs, gap_s: sEntieres(gap) });
    precedent = p.ts;
    precedentTs = p.checkpoint_ts;
  }
  return { conforme: ecarts.length === 0, tolerance_s: checkpointIntervalS + 1, ecarts, points_manquants: manquants };
}

/**
 * AN-2 : table des échéances d'une période d'après la série des points et les
 * ancres obtenues (toutes demandes closes). À `D_k`, le point sélectionné est
 * le premier de `checkpoint_ts ≥ D_k` ; il est `satisfaite` s'il porte un
 * jeton, `sans_objet` s'il n'engage aucun nouvel événement par rapport au
 * dernier point contresigné (jetons obtenus seulement), `remplacee` si une
 * échéance postérieure (ou la clôture) est satisfaite d'abord, `en_attente`
 * sinon. Les délais sont ceux de 3.3 : `d_jeton = genTime + précision − D_k`,
 * `d_registre = reçu − checkpoint_ts`.
 * @param {{periodStart: number, configuration: object, points: object[],
 *   ancres?: {checkpoint_hash: string, jeton?: {gen_time: string, accuracy_s?: number, provider?: string|null}|null, registre?: {received_at: string, block_number?: number}|null}[],
 *   cloture?: {jeton?: {gen_time: string, accuracy_s?: number, provider?: string|null}|null, registre?: {received_at: string}|null, generated_at?: string}|null}} p
 *   `configuration` : document `ancrage-v0` ou projection (c_K, c_T, countersign_idle, clock_tolerance_s, inclusion_alert_s)
 */
export function tableEcheances({ periodStart, configuration, points, ancres = [], cloture = null }) {
  if (!estObjet(configuration) || !estObjet(configuration.rfc3161)) throw new TypeError("configuration attendue");
  const cK = configuration.checkpoint_interval_s;
  const cT = configuration.rfc3161.checkpoints.interval_s;
  const idle = configuration.rfc3161.checkpoints.countersign_idle === true;
  const tolerance = configuration.rfc3161.freshness.clock_tolerance_s;
  const alerteInclusion = configuration.registry.inclusion_alert_s;
  const e = echeances({ periodStart, intervalS: cT });
  const lus = lirePoints(points, periodStart);
  if (!Array.isArray(ancres)) throw new TypeError("tableau d'ancres attendu");
  const parHash = new Map();
  for (const a of ancres) {
    if (!estObjet(a) || !estHex(a.checkpoint_hash, 32)) throw new TypeError("ancre : checkpoint_hash attendu");
    const jeton = a.jeton ? { borne: msGen(a.jeton.gen_time, "jeton.gen_time") + (a.jeton.accuracy_s ?? 0) * 1000, provider: a.jeton.provider ?? null } : null;
    const registre = a.registre ? { recu: msDe(a.registre.received_at, "registre.received_at") } : null;
    parHash.set(a.checkpoint_hash, { jeton, registre });
  }
  const alertes = [];
  // Délais et alertes par point ancré.
  const ancresTable = lus
    .filter((p) => parHash.has(p.checkpoint_hash))
    .map((p) => {
      const a = parHash.get(p.checkpoint_hash);
      const ligne = { checkpoint_hash: p.checkpoint_hash, tree_size: p.tree_size, checkpoint_ts: p.checkpoint_ts, d_registre_s: null, bound: null };
      if (a.registre) {
        ligne.d_registre_s = sEntieres(a.registre.recu - p.ts);
        if (a.registre.recu - p.ts > alerteInclusion * 1000) alertes.push({ code: "inclusion_late", checkpoint_hash: p.checkpoint_hash, d_registre_s: ligne.d_registre_s });
      }
      if (a.jeton) {
        ligne.bound = ecrireHorodatage(a.jeton.borne);
        if (a.jeton.borne < p.ts - tolerance * 1000) alertes.push({ code: "jeton_anterieur_au_point", checkpoint_hash: p.checkpoint_hash, ecart_s: sEntieres(p.ts - a.jeton.borne) });
        if (a.jeton.borne - p.ts > cT * 1000) alertes.push({ code: "contresignature_tardive", checkpoint_hash: p.checkpoint_hash, ecart_s: sEntieres(a.jeton.borne - p.ts) });
      }
      return ligne;
    });
  // Sélection par échéance : le premier point de checkpoint_ts ≥ D_k ; un jeton
  // obtenu sur un point satisfait toutes les échéances qui le sélectionnent ;
  // le dernier point contresigné n'avance que sur les jetons obtenus.
  const table = [];
  let base = 0;
  for (const d of e.liste) {
    const point = lus.find((p) => p.ts >= d.at_ms) ?? null;
    const ligne = { k: d.k, at: d.at, point: point?.checkpoint_hash ?? null, tree_size: point?.tree_size ?? null, state: "non_servie", d_jeton_s: null, d_point_s: null, bound: null };
    if (point) {
      ligne.d_point_s = sEntieres(point.ts - d.at_ms);
      const a = parHash.get(point.checkpoint_hash);
      if (a?.jeton) {
        ligne.state = "satisfaite";
        ligne.d_jeton_s = sEntieres(a.jeton.borne - d.at_ms);
        ligne.bound = a.jeton.borne;
        base = Math.max(base, point.tree_size);
      } else if (!idle && point.tree_size <= base) ligne.state = "sans_objet";
      else ligne.state = "en_attente";
    }
    table.push(ligne);
  }
  // EX-4.4 : une échéance en attente est remplacée par la première échéance postérieure satisfaite, ou par la clôture.
  const clotureJeton = cloture?.jeton ? msGen(cloture.jeton.gen_time, "cloture.jeton.gen_time") + (cloture.jeton.accuracy_s ?? 0) * 1000 : null;
  for (let i = 0; i < table.length; i++) {
    if (table[i].state !== "en_attente") continue;
    const suivante = table.slice(i + 1).find((x) => x.state === "satisfaite");
    const borne = suivante ? suivante.bound : clotureJeton;
    if (borne !== null) {
      table[i].state = "remplacee";
      table[i].replaced_by_k = suivante ? suivante.k : e.n_T;
      alertes.push({ code: "checkpoint_anchor_late", k: table[i].k, window_s: sEntieres(borne - msDe(table[i].at, "at")) });
    }
  }
  for (const ligne of table) ligne.bound = ligne.bound === null ? null : ecrireHorodatage(ligne.bound);
  const clotureLigne = { k: e.n_T, at: e.cloture.at, state: clotureJeton !== null ? "satisfaite" : "en_attente", d_jeton_s: clotureJeton !== null ? sEntieres(clotureJeton - e.cloture.at_ms) : null };
  if (cloture?.registre && cloture.generated_at) {
    clotureLigne.d_registre_s = sEntieres(msDe(cloture.registre.received_at, "cloture.registre.received_at") - msDe(cloture.generated_at, "cloture.generated_at"));
  }
  const cadence = constaterCadence({ periodStart, checkpointIntervalS: cK, points });
  for (const m of cadence.points_manquants) alertes.push({ code: "point_manquant", ...m });
  // Fenêtre de date observée : borne du dernier jeton extérieur moins l'échéance servie.
  const observee = table.filter((x) => x.state === "satisfaite").map((x) => x.d_jeton_s);
  return {
    n_T: e.n_T,
    echeances: table,
    cloture: clotureLigne,
    ancres: ancresTable,
    cadence,
    alertes,
    fenetres: { W_date_max_s: observee.length ? cT + Math.max(...observee) : null, c_T: cT, c_K: cK },
  };
}
