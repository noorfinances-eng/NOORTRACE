// Coût annuel par agent (CT-2 révision 0.5, §16.4, EX-16.4 à EX-16.6).
//
// Référence de la formule d'EX-16.4 : chaque ligne est calculée dans l'ordre
// du texte, de gauche à droite avec les parenthèses écrites, en double
// précision IEEE 754 ; les sorties sont arrondies à trois décimales
// (`Math.round(x × 1000) / 1000`, EX-16.5), comme `cout` d'ancrage.mjs (CT-5
// AN-59). Les prix sont des PARAMÈTRES en unités symboliques `p` : aucun prix
// réel ne figure dans ce module ni dans ses vecteurs. Entrées et sorties :
// schéma spec/schemas/cout-agent-v0.schema.json (`$defs/entrees`,
// `$defs/sorties`) ; vecteurs spec/vecteurs/ct-2/cout-agent/cas.json.

/** Gio : 2^30 octets. */
export const GIB = 1073741824;

const a3 = (x) => Math.round(x * 1000) / 1000;

function exigerNombre(v, nom, { entier = false, min = 0, max = Infinity } = {}) {
  if (typeof v !== "number" || !Number.isFinite(v)) throw new TypeError(`coutAgent : ${nom} doit être un nombre fini`);
  if (entier && !Number.isInteger(v)) throw new TypeError(`coutAgent : ${nom} doit être un entier`);
  if (v < min || v > max) throw new RangeError(`coutAgent : ${nom} hors de [${min}, ${max}]`);
}

/** Contrôles d'entrée (types et bornes de `$defs/entrees` qui conditionnent la formule). */
export function verifierEntrees(i) {
  if (i === null || typeof i !== "object") throw new TypeError("coutAgent : objet d'entrées attendu");
  exigerNombre(i.active_hours_per_year, "active_hours_per_year (H)", { entier: true, max: 8784 });
  exigerNombre(i.events_per_hour, "events_per_hour (e)");
  exigerNombre(i.event_bytes, "event_bytes (b_e)", { entier: true, min: 1 });
  exigerNombre(i.piece_bytes_per_event, "piece_bytes_per_event (b_p)");
  exigerNombre(i.pieces_per_event, "pieces_per_event (n_p)");
  exigerNombre(i.agents_per_journal, "agents_per_journal (A)", { entier: true, min: 1 });
  exigerNombre(i.hours_per_year, "hours_per_year (N_h)", { entier: true, min: 8760, max: 8784 });
  exigerNombre(i.journal_objects_per_hour, "journal_objects_per_hour (o_j)");
  exigerNombre(i.journal_bytes_per_hour, "journal_bytes_per_hour (b_j)");
  exigerNombre(i.segment_max_bytes, "segment_max_bytes (S)", { entier: true, min: 1024 });
  exigerNombre(i.anchoring_cost_per_journal, "anchoring_cost_per_journal (C_anc)");
  exigerNombre(i.local_retention_days, "local_retention_days (D_l)", { entier: true, min: 1 });
  exigerNombre(i.local_pieces_retention_days, "local_pieces_retention_days (D_lp)", { entier: true });
  const p = i.prices;
  if (p === null || typeof p !== "object") throw new TypeError("coutAgent : prices attendu");
  for (const k of ["local_gib_year", "worm_gib_year", "write_request", "read_request", "legal_hold_request", "egress_gib", "ingress_gib"]) exigerNombre(p[k], `prices.${k}`);
  const w = i.worm;
  if (w !== null) {
    if (typeof w !== "object") throw new TypeError("coutAgent : worm doit être null ou un objet");
    exigerNombre(w.retain_days, "worm.retain_days (D_w)", { entier: true, min: 1 });
    if (typeof w.pieces_in_worm !== "boolean") throw new TypeError("coutAgent : worm.pieces_in_worm doit être un booléen");
    exigerNombre(w.min_billable_object_bytes, "worm.min_billable_object_bytes (m)", { entier: true });
    exigerNombre(w.lock_audits_per_year, "worm.lock_audits_per_year (k)", { max: 366 });
    exigerNombre(w.legal_hold_fraction, "worm.legal_hold_fraction (g)", { max: 1 });
    exigerNombre(w.legal_hold_extra_days, "worm.legal_hold_extra_days (D_g)", { entier: true });
  }
}

/**
 * Formule d'EX-16.4. Rend les sorties de `$defs/sorties` arrondies selon
 * EX-16.5. `worm: null` met à zéro tous les termes WORM.
 */
export function coutAgent(i) {
  verifierEntrees(i);
  const H = i.active_hours_per_year;
  const e = i.events_per_hour;
  const b_e = i.event_bytes;
  const b_p = i.piece_bytes_per_event;
  const n_p = i.pieces_per_event;
  const A = i.agents_per_journal;
  const N_h = i.hours_per_year;
  const o_j = i.journal_objects_per_hour;
  const b_j = i.journal_bytes_per_hour;
  const S = i.segment_max_bytes;
  const D_l = i.local_retention_days;
  const D_lp = i.local_pieces_retention_days;
  const p = i.prices;
  const w = i.worm;

  const E = e * H;
  const V_e = E * b_e;
  const V_p = E * b_p;
  const N_p = E * n_p;
  const B_h = A * e * b_e;
  const s_h = e > 0 ? Math.max(1, Math.ceil(B_h / S)) : 0;
  const O_s = (H * s_h) / A;
  const O_j = (N_h * o_j) / A;
  const V_j = (N_h * b_j) / A;
  const L = ((V_e + V_j) / GIB) * p.local_gib_year * (D_l / 365) + (V_p / GIB) * p.local_gib_year * (D_lp / 365);

  let O_w = 0;
  let B_w = 0;
  let W_st = 0;
  let W_gel = 0;
  let W_put = 0;
  let W_get = 0;
  let W_net = 0;
  if (w !== null) {
    const pw = w.pieces_in_worm;
    const m = w.min_billable_object_bytes;
    const k = w.lock_audits_per_year;
    const g = w.legal_hold_fraction;
    const D_g = w.legal_hold_extra_days;
    O_w = O_s + O_j + (pw ? N_p : 0);
    B_w = Math.max(V_e, O_s * m) + Math.max(V_j, O_j * m) + (pw ? Math.max(V_p, N_p * m) : 0);
    const R_w = w.retain_days / 365;
    W_st = (B_w / GIB) * p.worm_gib_year * R_w;
    W_gel = g * (B_w / GIB) * p.worm_gib_year * (D_g / 365) + g * O_w * 2 * p.legal_hold_request;
    const T_k = O_w * R_w;
    W_put = O_w * p.write_request + ((k * T_k) / 1000) * p.write_request;
    W_get = O_w * 2 * p.read_request + k * T_k * p.read_request;
    const V_c = V_e + V_j + (pw ? V_p : 0);
    W_net = (V_c / GIB) * p.egress_gib + (V_c / GIB) * p.ingress_gib;
  }
  const C_a = i.anchoring_cost_per_journal / A;
  const C = L + W_st + W_gel + W_put + W_get + W_net + C_a;
  const C_J = C * A;
  return {
    events_per_year: a3(E),
    event_bytes_per_year: a3(V_e),
    piece_bytes_per_year: a3(V_p),
    segments_per_year: a3(O_s),
    journal_objects_per_year: a3(O_j),
    worm_objects_per_year: a3(O_w),
    worm_billable_bytes_per_year: a3(B_w),
    cost: {
      local_storage: a3(L),
      worm_storage: a3(W_st),
      legal_hold: a3(W_gel),
      write_requests: a3(W_put),
      read_requests: a3(W_get),
      network: a3(W_net),
      anchoring: a3(C_a),
      total: a3(C),
    },
    cost_journal_total: a3(C_J),
  };
}

/** `k` d'EX-16.4 depuis `lock_audit_interval_days` (EX-17.6) : `365 / intervalle`. */
export const relevesParAn = (lock_audit_interval_days) => 365 / lock_audit_interval_days;
