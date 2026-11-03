// Périmètre d'un gel juridique (CT-2 EX-12.35, pas 2 à 6), sans réseau : à
// partir de la liste des versions sous `<prefix>` (pas 1, lue par la couche
// d'accès), des manifestes lus et des empreintes de pièces référencées par
// les segments retenus. La famille `worm/perimetres.json` (annexe B.9) fixe ce
// calcul cas par cas.

import { sha256Hex } from "@noortrace/noyau";
import { jcsIntegralOctets } from "../jcs-integral.mjs";

/** Ordre des clés : octets UTF-8 croissants (EX-12.35 pas 5 et 6). */
export function comparerCles(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

const dix = (n) => String(n).padStart(10, "0");

/** Clé du manifeste d'une période. */
export const cleManifeste = (prefix, P) => `${prefix}manifestes/periode-${dix(P)}.json`;

/**
 * Octets de `objets-<nnnn>.ndjson` : une ligne JCS intégral par objet,
 * suivie de `\n` (`$defs/ligne_objet_gel`).
 * @param {{key: string, version_id: string}[]} objets
 * @returns {Uint8Array}
 */
export function octetsListeObjets(objets) {
  const parts = [];
  for (const o of objets) {
    parts.push(Buffer.from(jcsIntegralOctets({ key: o.key, version_id: o.version_id })));
    parts.push(Buffer.from("\n"));
  }
  return new Uint8Array(Buffer.concat(parts));
}

/**
 * Lit `objets-<nnnn>.ndjson` (lignes JCS intégral suivies de `\n`).
 * @param {Uint8Array} octets
 * @returns {{key: string, version_id: string}[]}
 */
export function lireListeObjets(octets) {
  const texte = Buffer.from(octets).toString("utf8");
  if (texte === "") return [];
  if (!texte.endsWith("\n")) throw new Error("liste des objets sans fin de ligne");
  return texte
    .slice(0, -1)
    .split("\n")
    .map((l) => {
      const o = JSON.parse(l);
      if (typeof o?.key !== "string" || typeof o?.version_id !== "string" || Object.keys(o).length !== 2) throw new Error("ligne d'objet invalide");
      return { key: o.key, version_id: o.version_id };
    });
}

/**
 * Calcule le périmètre d'un gel (EX-12.35).
 * @param {object} p
 * @param {string} p.prefix `storage.seal.worm.prefix`
 * @param {number} p.from `period_start` de début (compris)
 * @param {number} p.to `period_start` de fin (compris)
 * @param {{key: string, version_id: string, is_latest: boolean, delete_marker: boolean}[]} p.versions liste des versions (pas 1)
 * @param {{period_start: number, first_seq: number, last_seq: number}[]} p.manifests manifestes lus (pas 2)
 * @param {string[]|null} p.pieces empreintes `0x…` référencées par les segments retenus, si les pièces sont copiées ; `null` sinon
 * @param {boolean} [p.piecesPurgeables] `storage.retention.pieces_days` n'est pas `null`
 * @returns {{objects: {key: string, version_id: string}[], objects_sha256: string, count: number,
 *   anomalies: {key: string, kind: string}[], octets: Uint8Array, segments: string[]}}
 */
export function calculerPerimetre(p) {
  const prefix = p.prefix;
  const parCle = new Map();
  for (const v of p.versions) {
    if (!v.key.startsWith(prefix)) continue;
    if (!parCle.has(v.key)) parCle.set(v.key, []);
    parCle.get(v.key).push(v);
  }
  const retenues = new Set();
  const segmentsRetenus = [];
  const anomalies = [];
  const lus = new Map(p.manifests.map((m) => [m.period_start, m]));
  const motifSegment = /^segments\/seg-([0-9]{16})-([0-9]{20})\.ndjson$/;
  const cles = [...parCle.keys()];

  for (let P = p.from; P <= p.to; P += 3600) {
    // Pas 2 : manifeste.
    const km = cleManifeste(prefix, P);
    let m = null;
    if (!parCle.has(km)) {
      anomalies.push({ key: km, kind: "manifeste_absent" });
      anomalies.push({ key: `${prefix}segments/`, kind: "segments_indetermines" });
    } else {
      retenues.add(km);
      m = lus.get(P) ?? null;
      if (!m) {
        anomalies.push({ key: km, kind: "manifeste_illisible" });
        anomalies.push({ key: `${prefix}segments/`, kind: "segments_indetermines" });
      }
    }
    // Pas 3 : clés attendues.
    for (const k of [`${prefix}manifestes/periode-${dix(P)}.sig`, `${prefix}points/periode-${dix(P)}.ndjson`]) {
      if (parCle.has(k)) retenues.add(k);
      else anomalies.push({ key: k, kind: "objet_absent" });
    }
    const ancres = `${prefix}ancres/periode-${dix(P)}/`;
    for (const k of cles) if (k.startsWith(ancres)) retenues.add(k);
    if (m) {
      let premier = false;
      for (const k of cles) {
        const r = motifSegment.exec(k.slice(prefix.length));
        if (!r) continue;
        const f = Number(r[1]);
        if (f >= m.first_seq && f <= m.last_seq) {
          retenues.add(k);
          segmentsRetenus.push(k);
          if (f === m.first_seq) premier = true;
        }
      }
      if (m.last_seq >= m.first_seq && !premier) {
        anomalies.push({ key: `${prefix}segments/seg-${String(m.first_seq).padStart(16, "0")}-${"0".repeat(20)}.ndjson`, kind: "segment_absent" });
      }
    }
  }

  // Pas 4 : pièces.
  if (p.pieces !== null && p.pieces !== undefined) {
    for (const s of p.pieces) {
      const h = s.startsWith("0x") ? s.slice(2) : s;
      const k = `${prefix}pieces/${h.slice(0, 2)}/${h}`;
      if (parCle.has(k)) retenues.add(k);
      else anomalies.push({ key: k, kind: "piece_absente" });
    }
  } else if (p.piecesPurgeables) {
    anomalies.push({ key: `${prefix}pieces/`, kind: "pieces_non_copiees" });
  }

  // Pas 5 : versions retenues ; pas 6 : liste des objets.
  const objets = [];
  for (const k of [...retenues].sort(comparerCles)) {
    const vs = parCle.get(k);
    const reelles = vs.filter((v) => !v.delete_marker);
    if (reelles.length > 1) anomalies.push({ key: k, kind: "versions_multiples" });
    if (vs.some((v) => v.is_latest && v.delete_marker)) anomalies.push({ key: k, kind: "marqueur_de_suppression" });
    for (const v of reelles) objets.push({ key: k, version_id: v.version_id });
  }
  const octets = octetsListeObjets(objets);
  return { objects: objets, objects_sha256: sha256Hex(octets), count: objets.length, anomalies, octets, segments: segmentsRetenus };
}
