// Lecture du registre des gels par toutes les versions de chaque clé (CT-2
// EX-12.37, EX-17.6 pas 3, EX-17.7 ; étape 8, S-8 ;
// EX-12.38), partagée par la supervision du démon (`controles.mjs`) et par
// l'outil de gel (`gel.mjs`, rôle Lecteur) :
//   - toutes les versions d'un enregistrement `<nnnn>-<kind>.json` sont
//     classées ; la version retenue est la plus ancienne (la seule que
//     l'écriture conditionnelle à l'absence a pu créer) ; une seconde version,
//     un marqueur de suppression et un nom inattendu sous `<prefix>gels/` sont
//     des anomalies, consignées par l'appelant (`worm_versions_unexpected`) :
//     jamais un silence, jamais une disparition du gel ;
//   - chaque enregistrement lu est analysé en JSON strict et validé contre
//     `$defs/enregistrement_gel` du schéma `worm-v0` avant la règle de garde ;
//     un enregistrement illisible ou hors schéma est `{ illisible: true,
//     raison }` : la garde le classe au rang fautif sans lever.

import { analyserJsonIntegral } from "../jcs-integral.mjs";
import { registreSchemas, IDS } from "../schema.mjs";

/** Nom d'un enregistrement du registre des gels (EX-12.37). */
export const MOTIF_ENREGISTREMENT_GEL = /^([0-9]{4})-(pose|pose_resultat|demande_levee|levee|levee_resultat)\.json$/;
/** Nom d'une liste d'objets d'un gel (EX-12.37). */
export const MOTIF_LISTE_OBJETS = /^objets-([0-9]{4})\.ndjson$/;
/** Identifiant d'un gel (EX-12.37). */
export const MOTIF_GEL_ID = /^gel-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/;

/**
 * Valide un objet contre `$defs/enregistrement_gel` du schéma `worm-v0`.
 * @param {unknown} o
 * @returns {{valide: boolean, erreurs: {pointeur: string, regle: string}[]}}
 */
export function validerEnregistrementGel(o) {
  const r = registreSchemas().valider(`${IDS.worm}#/$defs/enregistrement_gel`, o);
  return { valide: r.valide, erreurs: r.erreurs.map((e) => ({ pointeur: e.pointeur, regle: e.regle })) };
}

/**
 * Décode le corps d'un enregistrement : JSON strict puis schéma.
 * @param {Uint8Array|Buffer} corps
 * @returns {{record: object}|{record: {illisible: true, raison: string}, raison: string}}
 */
export function decoderEnregistrementGel(corps) {
  let o;
  try {
    o = analyserJsonIntegral(new Uint8Array(corps));
  } catch {
    return { record: { illisible: true, raison: "json_invalide" }, raison: "json_invalide" };
  }
  const v = validerEnregistrementGel(o);
  if (!v.valide) return { record: { illisible: true, raison: "schema_invalide", erreurs: v.erreurs.slice(0, 8) }, raison: "schema_invalide" };
  return { record: o };
}

/** Instant d'une date de version du support, ou null. */
const instant = (t) => {
  if (typeof t !== "string") return null;
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? null : ms;
};

/**
 * Version originale d'une clé : la plus ancienne des versions qui ne sont pas
 * des marqueurs (par `last_modified` ; à défaut la dernière listée, S3 listant
 * les versions de la plus récente à la plus ancienne).
 * @param {{version_id: string, delete_marker: boolean, last_modified?: string|null}[]} versions
 * @returns {object|null}
 */
export function versionOriginale(versions) {
  const reelles = versions.filter((v) => !v.delete_marker);
  if (reelles.length === 0) return null;
  let choix = null;
  let tChoix = null;
  for (const v of reelles) {
    const t = instant(v.last_modified);
    if (choix === null || (t !== null && (tChoix === null || t < tChoix)) || (t === null && tChoix === null)) {
      choix = v;
      tChoix = t;
    }
  }
  return choix;
}

/**
 * Classe les versions listées sous `<prefix>gels/` par gel, par
 * enregistrement et par liste d'objets, avec les anomalies de forme.
 * @param {{key: string, version_id: string, is_latest: boolean, delete_marker: boolean, last_modified?: string|null}[]} versions
 * @param {string} prefixeGels `<prefix>gels/`
 * @returns {Map<string, {enregistrements: Map<string, object[]>, listes: Map<string, object[]>, anomalies: {key: string, raison: string, versions: number, marqueur: boolean}[]}>}
 */
export function classerVersionsGels(versions, prefixeGels) {
  const parCle = new Map();
  for (const v of versions) {
    if (typeof v?.key !== "string" || !v.key.startsWith(prefixeGels)) continue;
    if (!parCle.has(v.key)) parCle.set(v.key, []);
    parCle.get(v.key).push(v);
  }
  const gels = new Map();
  const gel = (g) => {
    if (!gels.has(g)) gels.set(g, { enregistrements: new Map(), listes: new Map(), anomalies: [] });
    return gels.get(g);
  };
  for (const [cle, vs] of [...parCle].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    const reste = cle.slice(prefixeGels.length);
    const k = reste.indexOf("/");
    const g = k < 0 ? reste : reste.slice(0, k);
    const nom = k < 0 ? "" : reste.slice(k + 1);
    const e = gel(g);
    const reelles = vs.filter((v) => !v.delete_marker);
    const marqueur = vs.some((v) => v.delete_marker);
    const anomalie = (raison) => e.anomalies.push({ key: cle, raison, versions: reelles.length, marqueur });
    if (!MOTIF_GEL_ID.test(g) || k < 0 || nom.includes("/") || (!MOTIF_ENREGISTREMENT_GEL.test(nom) && !MOTIF_LISTE_OBJETS.test(nom))) {
      anomalie("nom_inattendu");
      continue;
    }
    if (marqueur) anomalie("marqueur_de_suppression");
    if (reelles.length > 1) anomalie("versions_multiples");
    (MOTIF_ENREGISTREMENT_GEL.test(nom) ? e.enregistrements : e.listes).set(nom, vs);
  }
  return gels;
}

/**
 * Lit les enregistrements d'un gel, dans l'ordre des rangs, par leur version
 * originale ; une lecture en échec, un corps illisible ou hors schéma donnent
 * `{ illisible: true, raison }`.
 * @param {{lire: (key: string, versionId: string) => Promise<{statut: number, corps: Buffer}>}} operations
 * @param {Map<string, object[]>} enregistrements nom → versions (classerVersionsGels)
 * @returns {Promise<{records: object[], versions: {key: string, version_id: string|null, n: number}[], lectureOk: boolean}>}
 */
export async function lireEnregistrementsGel(operations, enregistrements) {
  const noms = [...enregistrements.keys()].sort();
  const records = [];
  const versions = [];
  let lectureOk = true;
  for (const nom of noms) {
    const vs = enregistrements.get(nom);
    const n = Number(MOTIF_ENREGISTREMENT_GEL.exec(nom)[1]);
    const v = versionOriginale(vs);
    if (!v) {
      // Toutes les versions sont des marqueurs : rien à lire sous ce nom.
      records.push({ illisible: true, raison: "marqueur_seul" });
      versions.push({ key: vs[0].key, version_id: null, n });
      continue;
    }
    versions.push({ key: v.key, version_id: v.version_id, n });
    let r;
    try {
      r = await operations.lire(v.key, v.version_id);
    } catch {
      r = { statut: null };
    }
    if (r.statut !== 200) {
      lectureOk = false;
      records.push({ illisible: true, raison: "lecture_en_echec", http_status: r.statut ?? null });
      continue;
    }
    records.push(decoderEnregistrementGel(r.corps).record);
  }
  return { records, versions, lectureOk };
}

/**
 * Lit la liste des objets d'un gel par la version dont l'empreinte est celle
 * que la `pose` déclare (`objects.sha256`), parmi toutes les versions listées
 * (EX-12.37 : la liste est écrite une fois ; une seconde version est une
 * anomalie déjà classée).
 * @param {{lire: Function}} operations
 * @param {{key: string, sha256: string, count: number}} objects
 * @param {object[]|undefined} versionsListe versions listées sous `objects.key`
 * @param {{sha256Hex: (o: Uint8Array) => string, lireListeObjets: (o: Uint8Array) => object[]}} f
 * @returns {Promise<{objets: object[]|null, raison: string|null}>}
 */
export async function lireListeObjetsGel(operations, objects, versionsListe, f) {
  const candidates = versionsListe?.length ? [...versionsListe.filter((v) => !v.delete_marker)] : [];
  const original = versionOriginale(candidates);
  if (original) candidates.sort((a, b) => (a === original ? -1 : b === original ? 1 : 0));
  const essais = candidates.length ? candidates.map((v) => v.version_id) : [null];
  let derniere = "liste_absente";
  for (const vid of essais) {
    let r;
    try {
      r = await operations.lire(objects.key, vid);
    } catch {
      r = { statut: null };
    }
    if (r.statut !== 200) {
      derniere = "lecture_en_echec";
      continue;
    }
    const octets = new Uint8Array(r.corps);
    if (f.sha256Hex(octets) !== objects.sha256) {
      derniere = "empreinte_differente";
      continue;
    }
    try {
      const liste = f.lireListeObjets(octets);
      if (liste.length !== objects.count) {
        derniere = "nombre_different";
        continue;
      }
      return { objets: liste, raison: null };
    } catch {
      derniere = "liste_illisible";
    }
  }
  return { objets: null, raison: derniere };
}
