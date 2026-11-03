// Registre des gels (CT-2 EX-12.37) et règle de garde de la levée par deux
// personnes (EX-12.38), sans réseau ; gels actifs et état attendu de leurs
// versions (EX-17.7) ; versions à lever et versions conservées quand d'autres
// gels actifs couvrent certaines versions (EX-12.40). Les familles
// `worm/gardes.json` et `worm/levees.json` (annexe B.9) fixent ces calculs.

import { decoderHorodatage, sha256Hex } from "@noortrace/noyau";
import { jcsIntegralOctets } from "../jcs-integral.mjs";

/** Codes de la règle de garde, dans l'ordre de la table d'EX-12.38. */
export const CODES_GARDE = Object.freeze([
  "chaine_rompue", "premier_non_pose", "ordre_invalide", "meme_identite", "demande_inconnue",
  "demande_expiree", "levee_en_double", "objets_differents", "periode_differente",
]);

/** Sortes d'enregistrements (EX-12.37). */
export const SORTES = Object.freeze(["pose", "pose_resultat", "demande_levee", "levee", "levee_resultat"]);

/** Délai maximal entre une demande et sa levée : sept jours (EX-12.38). */
export const DELAI_LEVEE_MS = 604800000;

const SUCCESSIONS = {
  pose: ["pose_resultat"],
  pose_resultat: ["pose_resultat", "demande_levee"],
  demande_levee: ["demande_levee", "levee"],
  levee: ["levee_resultat"],
  levee_resultat: ["levee_resultat"],
};

/** Octets d'un enregistrement : JCS intégral (EX-12.37). */
export function octetsEnregistrement(r) {
  return jcsIntegralOctets(r);
}

/** Empreinte d'un enregistrement : SHA-256 de son JCS intégral, `0x`. */
export function empreinteEnregistrement(r) {
  return sha256Hex(octetsEnregistrement(r));
}

/** Nom d'objet d'un enregistrement : `<nnnn>-<kind>.json`. */
export function nomEnregistrement(n, kind) {
  return `${String(n).padStart(4, "0")}-${kind}.json`;
}

function egal(a, b) {
  return JSON.stringify(jcsOuNull(a)) === JSON.stringify(jcsOuNull(b));
}

function jcsOuNull(v) {
  try {
    return Buffer.from(jcsIntegralOctets(v ?? null)).toString("utf8");
  } catch {
    return String(v);
  }
}

/**
 * Règle de garde sur une suite d'enregistrements relus (EX-12.38) : erreurs
 * `{ n, code }` où `n` est le rang (1, 2, …), au plus une par rang et par
 * code, triées par rang puis dans l'ordre de la table.
 * @param {object[]} records
 * @returns {{valid: boolean, record_sha256: string[], errors: {n: number, code: string}[]}}
 */
export function verifierGarde(records) {
  const hashes = records.map((r) => empreinteEnregistrement(r));
  const errors = [];
  if (records.length === 0) return { valid: false, record_sha256: [], errors: [{ n: 1, code: "premier_non_pose" }] };
  const r1 = records[0];
  const at = records.map((r) => (typeof r?.at === "string" ? decoderHorodatage(r.at) : null));
  const approuvees = new Set();
  records.forEach((r, i) => {
    const rang = i + 1;
    const codes = new Set();
    // chaine_rompue
    if (r.n !== rang) codes.add("chaine_rompue");
    if (i === 0 ? r.prev_sha256 !== null : r.prev_sha256 !== hashes[i - 1]) codes.add("chaine_rompue");
    if (i > 0 && (r.gel_id !== r1.gel_id || r.org_id !== r1.org_id || r.journal_id !== r1.journal_id || !egal(r.support, r1.support))) codes.add("chaine_rompue");
    // premier_non_pose
    if (i === 0 && r.kind !== "pose") codes.add("premier_non_pose");
    // ordre_invalide
    if (at[i] === null) codes.add("ordre_invalide");
    if (i > 0) {
      const prec = records[i - 1].kind;
      if (!(SUCCESSIONS[prec] ?? []).includes(r.kind)) codes.add("ordre_invalide");
      if (at[i] !== null && at[i - 1] !== null && at[i] < at[i - 1]) codes.add("ordre_invalide");
    }
    if (!SORTES.includes(r.kind)) codes.add("ordre_invalide");
    // Levée : demande approuvée, dernière demande.
    if (r.kind === "levee") {
      let derniere = null;
      let demande = null;
      for (let j = 0; j < i; j++) {
        if (records[j].kind !== "demande_levee") continue;
        derniere = j;
        if (hashes[j] === r.request_sha256) demande = j;
      }
      if (derniere === null || hashes[derniere] !== r.request_sha256) codes.add("demande_inconnue");
      if (demande !== null) {
        if (r.actor === records[demande].actor) codes.add("meme_identite");
        const ecart = at[i] !== null && at[demande] !== null ? at[i] - at[demande] : null;
        if (ecart === null || ecart < 0 || ecart > DELAI_LEVEE_MS) codes.add("demande_expiree");
        if (approuvees.has(demande)) codes.add("levee_en_double");
        approuvees.add(demande);
      }
    }
    if (i > 0 && !egal(r.objects, r1.objects)) codes.add("objets_differents");
    if (i > 0 && !egal(r.periods, r1.periods)) codes.add("periode_differente");
    for (const c of CODES_GARDE) if (codes.has(c)) errors.push({ n: rang, code: c });
  });
  return { valid: errors.length === 0, record_sha256: hashes, errors };
}

/**
 * Plus long préfixe sans erreur de garde d'une suite (EX-17.7 : « dernier
 * enregistrement valide »).
 * @param {object[]} records
 * @returns {object[]}
 */
export function prefixeValide(records) {
  const { errors } = verifierGarde(records);
  if (records.length === 0) return [];
  const premier = errors.length ? Math.min(...errors.map((e) => e.n)) : records.length + 1;
  return records.slice(0, premier - 1);
}

/**
 * État d'un gel d'après sa suite relue (EX-17.7) : actif tant que son dernier
 * enregistrement valide n'est pas un `levee_resultat` sans échec ; état
 * attendu de chaque version : `on` tant qu'aucune `levee` valide n'est
 * inscrite, `on` ou `off` tolérés pendant une levée en cours ; versions de
 * `results.kept` attendues `on`.
 * @param {object[]} records suite relue, dans l'ordre
 * @returns {{actif: boolean, leveeEnCours: boolean, valide: boolean, kept: {key: string, version_id: string, gel_id: string}[]}}
 */
export function etatGel(records) {
  const valides = prefixeValide(records);
  const dernier = valides.at(-1) ?? null;
  const leveeValide = valides.some((r) => r.kind === "levee");
  const termine = dernier?.kind === "levee_resultat" && Array.isArray(dernier.results?.failed) && dernier.results.failed.length === 0;
  const kept = [];
  for (const r of valides) if (r.kind === "levee_resultat" && Array.isArray(r.results?.kept)) kept.push(...r.results.kept);
  return {
    actif: valides.length > 0 && !termine,
    leveeEnCours: leveeValide && !termine,
    valide: valides.length === records.length,
    kept,
  };
}

/**
 * Versions à lever et versions conservées (EX-12.40) : une version couverte
 * par un autre gel actif n'est pas levée ; elle est conservée sous le premier
 * gel reçu qui la couvre.
 * @param {{key: string, version_id: string}[]} objets liste du gel levé
 * @param {{gel_id: string, objects: {key: string, version_id: string}[]}[]} autres autres gels actifs
 * @returns {{lift: {key: string, version_id: string}[], keep: {key: string, version_id: string, gel_id: string}[]}}
 */
export function versionsALever(objets, autres) {
  const lift = [];
  const keep = [];
  for (const o of objets) {
    const g = autres.find((h) => h.objects.some((x) => x.key === o.key && x.version_id === o.version_id));
    if (g) keep.push({ key: o.key, version_id: o.version_id, gel_id: g.gel_id });
    else lift.push({ key: o.key, version_id: o.version_id });
  }
  return { lift, keep };
}

/**
 * Identifiant d'un gel (EX-12.37) : `gel-<AAAAMMJJ>T<hhmmss>Z-<8 hex>`.
 * @param {number} instant ms
 * @param {Uint8Array} quatreOctets
 */
export function identifiantGel(instant, quatreOctets) {
  const d = new Date(instant);
  const p = (n, k = 2) => String(n).padStart(k, "0");
  const date = `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return `gel-${date}-${Buffer.from(quatreOctets).toString("hex")}`;
}
