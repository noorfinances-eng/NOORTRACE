// Rejeu des traces normatives de CT-5 §8.10 (EX-8.16, AN-42) : une trace est
// un document conforme à la racine de `planificateur-ancrage-v0` ; le
// planificateur, alimenté par sa projection, sa file de départ, ses gigues
// injectées et des nonces dérivés des étiquettes de l'annexe A.2, doit rendre
// exactement `expected` (égalité des formes canoniques JCS v0, action par
// action, dans l'ordre) et `queue_after`.

import { jcs, sha256, utf8 } from "@noortrace/noyau";
import { ID_SCHEMA_PLANIFICATEUR, REGISTRE_ANCRAGE } from "./configuration.mjs";
import { Planificateur } from "./planificateur.mjs";

/** Journaux des vecteurs (annexe A.2) : identifiant → nom d'étiquette. */
export const JOURNAUX_VECTEURS = Object.freeze({
  "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b": "journal-principal",
  "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164": "journal-sinistres",
});

/** Préfixes des étiquettes de dérivation (annexe A.2). */
export const ETIQUETTES = Object.freeze({
  nonceRfc3161: "noortrace/vecteurs/v0/ct-5/nonce-tsa",
  nonceOts: "noortrace/vecteurs/v0/ct-5/ots/nonce",
});

/**
 * Nonce RFC 3161 d'une tentative des vecteurs : 64 premiers bits de
 * SHA-256(UTF-8("…/nonce-tsa/<journal>/<periode|point>/<empreinte>/<n>")).
 * @param {{journal: string, sujet: "periode"|"point", empreinte: string, n: number}} p
 * @returns {bigint}
 */
export function nonceVecteur({ journal, sujet, empreinte, n }) {
  const h = sha256(utf8(`${ETIQUETTES.nonceRfc3161}/${journal}/${sujet}/${empreinte.replace(/^0x/, "")}/${n}`));
  let v = 0n;
  for (const o of h.subarray(0, 8)) v = (v << 8n) | BigInt(o);
  return v;
}

/**
 * Nonce OpenTimestamps des vecteurs : 16 premiers octets de
 * SHA-256(UTF-8("…/ots/nonce/<journal>/<periode|point>/<empreinte>")).
 * @param {{journal: string, sujet: "periode"|"point", empreinte: string}} p
 * @returns {Uint8Array}
 */
export function nonceOtsVecteur({ journal, sujet, empreinte }) {
  return sha256(utf8(`${ETIQUETTES.nonceOts}/${journal}/${sujet}/${empreinte.replace(/^0x/, "")}`)).subarray(0, 16);
}

/**
 * Source de nonces des vecteurs, par étiquettes (annexe A.2).
 * @param {Record<string, string>} [journaux] identifiant de journal → nom
 */
export function noncesVecteurs(journaux = JOURNAUX_VECTEURS) {
  const nom = (journal_id) => {
    const n = journaux[journal_id];
    if (!n) throw new Error(`journal inconnu des vecteurs : ${journal_id}`);
    return n;
  };
  return {
    rfc3161: ({ journal_id, subjectKind, hash, n }) => nonceVecteur({ journal: nom(journal_id), sujet: subjectKind, empreinte: hash, n }),
    ots: ({ journal_id, subjectKind, hash }) => nonceOtsVecteur({ journal: nom(journal_id), sujet: subjectKind, empreinte: hash }),
    gigue: () => 0,
  };
}

/**
 * Rejoue une trace : rend les actions produites et la file finale, avec la
 * comparaison à `expected` et `queue_after`.
 * @param {object} trace document conforme à la racine de `planificateur-ancrage-v0`
 * @param {{journaux?: Record<string, string>, valider?: boolean}} [options]
 * @returns {{actions: object[], file: object[], conforme: boolean, ecarts: {ou: string, indice: number, attendu: object|null, obtenu: object|null}[]}}
 */
export function rejouerTrace(trace, options = {}) {
  if (options.valider !== false) {
    const v = REGISTRE_ANCRAGE.valider(ID_SCHEMA_PLANIFICATEUR, trace);
    if (!v.valide) throw new TypeError(`trace non conforme au schéma : ${v.erreurs[0]}`);
  }
  const planificateur = new Planificateur(trace.config, {
    gigues: trace.jitter_ms,
    nonces: noncesVecteurs(options.journaux),
    fileInitiale: trace.queue_before,
  });
  const actions = [];
  for (const entree of trace.inputs) actions.push(...planificateur.traiter(entree));
  const file = planificateur.file();
  const ecarts = comparer(trace.expected, actions, "expected").concat(comparer(trace.queue_after, file, "queue_after"));
  return { actions, file, conforme: ecarts.length === 0, ecarts };
}

/**
 * Compare deux listes d'objets par leurs formes canoniques JCS v0, dans l'ordre.
 * @param {object[]} attendu
 * @param {object[]} obtenu
 * @param {string} ou
 */
export function comparer(attendu, obtenu, ou) {
  const ecarts = [];
  const n = Math.max(attendu.length, obtenu.length);
  for (let i = 0; i < n; i++) {
    const a = attendu[i] ?? null;
    const o = obtenu[i] ?? null;
    if (a === null || o === null || jcs(a) !== jcs(o)) ecarts.push({ ou, indice: i, attendu: a, obtenu: o });
  }
  return ecarts;
}
