// Reconstruction d'un journal depuis ses copies WORM (CT-2 EX-12.17 : « À la
// reprise d'une instance dont le stockage local est perdu (section 13), le
// journal est reconstruit depuis les copies ») selon la procédure de CT-8
// §11.4 : chemin B (liste des versions sous `<prefix>` et restauration dans un
// répertoire neuf ; `journal.json` recréé depuis la configuration ; fichiers
// sans copie perdus et listés) et commande `noortrace-ctl worm restaurer
// <clé> --version <id>` d'EX-10.14 de CT-8 (une version relue, SHA-256
// comparé au registre des copies, écrite dans un répertoire neuf, jamais sur
// l'original). Tout est fait sans réseau vers le démon ; les identifiants
// sont ceux de l'écrivain (droits de lecture seulement, EX-12.32) ou ceux du
// rôle Lecteur.
//
// Contrôles de chaque objet relu : longueur et SHA-256 égaux à la ligne du
// registre des copies (EX-12.29) quand un registre est donné ; puis, toujours,
// le répertoire reconstruit en entier (`verifierRepertoireJournal`) : en-têtes
// (`org_id`, `journal_id` de la configuration), `first_seq` qui se suivent,
// `prev_hash` d'un segment à l'autre, chaque ligne (schéma, chaînage, hash
// recalculé, signature sous la clé en vigueur, EX-12.10 pas 2), la chaîne
// entière par le noyau (CT-1 E-1 à E-11, C-1 à C-3) avec les clés de la
// chaîne (clé initiale : `--cles`, ou celle du signataire de classe D de la
// configuration ; puis chaque clé annoncée par une rotation), époques non
// décroissantes, chaque manifeste recalculé sur les événements de sa période
// et sa signature (CT-1 §10.2, P-5), la continuité (§10.3), chaque série de
// points (§10.5) et le SHA-256 de chaque pièce contre son nom (8.4). Sans
// registre des copies, c'est ce qui prouve que les fichiers restaurés sont
// « identiques octet pour octet » à ceux qu'a écrits l'écrivain (CT-8
// EX-11.6) : une copie altérée et rechaînée garde des signatures qui ne
// vérifient plus. Un écart refuse la reconstruction : rien n'est laissé dans
// la destination.

import fs from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { lireSegmentFerme } from "../segments.mjs";
import { verifierRepertoireJournal } from "../verification.mjs";
import { SignataireFichier } from "../signataires.mjs";
import { resoudreSecret } from "../secrets.mjs";
import { lireRegistres, piecesReferencees } from "./registre.mjs";
import { comparerCles } from "./perimetre.mjs";
import { VERSION_ENREGISTREUR } from "../coeur.mjs";

/** Chemins relatifs restaurables (12.1) : rien d'autre n'est écrit. */
const RESTAURABLES = [
  /^segments\/seg-[0-9]{16}-[0-9]{20}\.ndjson$/,
  /^manifestes\/periode-[0-9]{10}\.(json|sig)$/,
  /^points\/periode-[0-9]{10}\.ndjson$/,
  /^ancres\/periode-[0-9]{10}\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/,
  /^pieces\/[0-9a-f]{2}\/[0-9a-f]{64}$/,
];

/** Fichiers sans copie WORM, perdus au chemin B (CT-8 §11.4). */
export const SANS_COPIE = Object.freeze(["intentions/", "attente/", "approbations/", "worm/"]);

const sur = (rel) => RESTAURABLES.some((m) => m.test(rel)) && !rel.split("/").includes("..");

/** Erreur d'une reconstruction : incidents nommés, rien n'est écrit. */
export class ErreurRestauration extends Error {
  constructor(incidents, code = 1) {
    super(`restauration refusée : ${incidents.map((i) => i.kind).join(", ")}`);
    this.name = "ErreurRestauration";
    this.incidents = incidents;
    this.code = code;
  }
}

/**
 * Registre des copies en carte clé → lignes (EX-12.29).
 * @param {string|null} dirWorm
 */
export async function registreParCle(dirWorm) {
  if (!dirWorm) return null;
  const m = new Map();
  for (const { ligne } of await lireRegistres(dirWorm)) {
    if (!m.has(ligne.key)) m.set(ligne.key, []);
    m.get(ligne.key).push(ligne);
  }
  return m;
}

/**
 * Vérifie un répertoire de journal reconstruit (module commun
 * `verification.mjs`) : chaîne, signatures avec les clés de la chaîne,
 * manifestes, signatures des manifestes, continuité, séries de points,
 * pièces.
 * @param {string} rep répertoire du journal
 * @param {{org_id: string, journal_id: string, clePublique?: (keyId: string) => Promise<Uint8Array|string|null>}} id
 * @returns {Promise<{incidents: object[], lastSeq: number, lastHash: string|null, evenements: number}>}
 */
export async function verifierChaineReconstruite(rep, id) {
  const v = await verifierRepertoireJournal(rep, { org_id: id.org_id, journal_id: id.journal_id, clePublique: id.clePublique, dernierOuvert: false });
  return { incidents: v.incidents, lastSeq: v.lastSeq, lastHash: v.lastSeq ? v.lastHash : null, evenements: v.evenements.length };
}

/**
 * Clé publique initiale d'un journal tirée de la configuration : signataire
 * de classe D (`signer.backend.type: "file"`, développement), clés `key_id`
 * et `next_key_id`. Les autres classes ne se lisent pas hors du démon :
 * `--cles` (cles.json de CT-1 §11.2, comme l'outil de CT-8 EX-11.7) les donne.
 * @param {object} config
 * @param {{env?: object}} [o]
 * @returns {(keyId: string) => Promise<Uint8Array|null>}
 */
export function clePubliqueDepuisConfiguration(config, o = {}) {
  return async (keyId) => {
    const s = config.signer;
    if (s?.backend?.type !== "file" || config.recorder.environment === "production") return null;
    try {
      const phrase = s.backend.passphrase ? resoudreSecret(s.backend.passphrase, "/signer/backend/passphrase", { env: o.env ?? process.env }) : null;
      const b = SignataireFichier.charger({ environment: config.recorder.environment, keyId: s.key_id, chemin: s.backend.path, nextKeyId: s.rotation?.next_key_id ?? null, phrase });
      const p = await b.clePublique(keyId);
      b.effacer?.();
      return p;
    } catch {
      return null;
    }
  };
}

/**
 * Clés publiques d'un fichier `cles.json` (CT-1 §11.2).
 * @param {object} cles
 * @returns {(keyId: string) => Promise<string|null>}
 */
export function clePubliqueDepuisCles(cles) {
  const parId = new Map((cles?.keys ?? []).map((k) => [k.key_id, k.public_key]));
  return async (keyId) => parId.get(keyId) ?? null;
}

/**
 * Reconstruit le journal de la configuration depuis les copies WORM dans
 * `destination` (répertoire neuf qui devient `storage.root`).
 * @param {object} p
 * @param {object} p.config configuration validée
 * @param {object} p.operations opérations du support (lecture)
 * @param {string} p.destination répertoire neuf (inexistant)
 * @param {Map<string, object[]>|null} p.registre registre des copies relu, ou null (chemin B sans archive)
 * @param {() => number} [p.murale]
 * @param {(niveau: string, composant: string, evenement: string, data: object) => void} [p.consigner]
 * @param {(keyId: string) => Promise<Uint8Array|string|null>} [p.clePublique] clé publique d'un `key_id`
 *   que la chaîne n'annonce pas (clé initiale) ; défaut : signataire de classe D de la configuration
 * @returns {Promise<object>} synthèse
 */
export async function reconstruireJournal(p) {
  const { config, operations } = p;
  const worm = config.storage.seal.worm;
  const prefixe = worm.prefix;
  const murale = p.murale ?? (() => Date.now());
  const org = config.recorder.org_id;
  const jid = config.recorder.journal_id;
  if (await fs.stat(p.destination).then(() => true, () => false)) throw new ErreurRestauration([{ key: p.destination, kind: "destination_existante" }], 2);
  const l = await operations.listerVersions(prefixe);
  if (l.statut !== 200) throw new ErreurRestauration([{ key: prefixe, kind: "liste_impossible", http_status: l.statut }], 4);
  // Choix d'une version par clé : la version inscrite au registre, sinon l'unique version.
  const parCle = new Map();
  let epoqueMax = 0;
  for (const v of l.versions) {
    if (!v.key.startsWith(prefixe)) continue;
    const rel = v.key.slice(prefixe.length);
    const m = /^segments\/seg-[0-9]{16}-([0-9]{20})\.ndjson$/.exec(rel);
    if (m) epoqueMax = Math.max(epoqueMax, Number(m[1]));
    if (!sur(rel)) continue;
    if (!parCle.has(v.key)) parCle.set(v.key, []);
    parCle.get(v.key).push(v);
  }
  const incidents = [];
  const choix = [];
  if (p.registre) {
    for (const [cle, lignes] of [...p.registre].sort((a, b) => comparerCles(a[0], b[0]))) {
      if (!cle.startsWith(prefixe) || !sur(cle.slice(prefixe.length))) continue;
      const ligne = lignes.at(-1);
      const v = (parCle.get(cle) ?? []).find((x) => !x.delete_marker && x.version_id === ligne.version_id);
      if (!v) incidents.push({ key: cle, version_id: ligne.version_id, kind: "copie_absente" });
      else choix.push({ cle, version_id: v.version_id, ligne });
    }
  }
  // Clés sans ligne au registre (toutes sans registre ; avec un registre
  // archivé, les copies postérieures à l'archive) : le registre « ne fait foi
  // de rien et se reconstruit depuis la liste des versions » (12.1) ; la
  // version unique est relue, contrôlée par la seule chaîne ; plusieurs
  // versions ne se départagent pas sans registre.
  for (const [cle, vs] of [...parCle].sort((a, b) => comparerCles(a[0], b[0]))) {
    if (p.registre?.has(cle)) continue;
    const reelles = vs.filter((x) => !x.delete_marker);
    if (reelles.length === 1) {
      choix.push({ cle, version_id: reelles[0].version_id, ligne: null });
      if (p.registre) p.consigner?.("warning", "worm", "worm_restore_unregistered", { key: cle, version_id: reelles[0].version_id });
    } else if (reelles.length > 1) incidents.push({ key: cle, kind: "versions_multiples", versions: reelles.length });
  }
  choix.sort((a, b) => comparerCles(a.cle, b.cle));
  if (incidents.length) throw new ErreurRestauration(incidents);
  // Relecture et contrôle de chaque objet, dans un répertoire provisoire.
  const provisoire = `${p.destination}.partiel-${randomBytes(4).toString("hex")}`;
  const rep = path.join(provisoire, org.slice(2), jid.slice(2));
  await fs.mkdir(rep, { recursive: true, mode: 0o700 });
  try {
    const fichiers = [];
    for (const c of choix) {
      const rel = c.cle.slice(prefixe.length);
      const r = await operations.lire(c.cle, c.version_id);
      if (r.statut !== 200) {
        incidents.push({ key: c.cle, version_id: c.version_id, kind: r.statut === 404 ? "copie_absente" : "lecture_impossible", http_status: r.statut });
        continue;
      }
      const octets = new Uint8Array(r.corps);
      const sha256 = sha256Hex(octets);
      if (c.ligne && (c.ligne.sha256 !== sha256 || c.ligne.length !== octets.length)) {
        incidents.push({ key: c.cle, version_id: c.version_id, kind: "copie_alteree", attendu: c.ligne.sha256, lu: sha256 });
        continue;
      }
      const cible = path.join(rep, ...rel.split("/"));
      await fs.mkdir(path.dirname(cible), { recursive: true, mode: 0o700 });
      await fs.writeFile(cible, octets, { mode: 0o600, flag: "wx" });
      fichiers.push({ key: c.cle, version_id: c.version_id, sha256, length: octets.length });
    }
    if (incidents.length) throw new ErreurRestauration(incidents);
    // journal.json recréé depuis la configuration (CT-8 EX-11.1 point 1, PD-13).
    // `created_at` n'est fixé par aucun texte au chemin B : le journal a été
    // créé au plus tard au premier événement de sa chaîne, dont le `ts` est
    // repris (sinon l'heure de la reconstruction, pour un journal sans
    // segment). Une heure postérieure placerait la première clé hors de sa
    // validité annoncée dans `cles.json` (CT-1 E-11) : le journal reconstruit
    // ne serait plus vérifiable, ce qu'EX-11.1 exclut.
    const premiers = (await fs.readdir(path.join(rep, "segments")).catch(() => [])).sort();
    let creeLe = ecrireHorodatage(murale());
    if (premiers.length) {
      const e0 = lireSegmentFerme(new Uint8Array(await fs.readFile(path.join(rep, "segments", premiers[0])))).evenements[0];
      if (e0?.ts) creeLe = e0.ts;
    }
    await fs.writeFile(
      path.join(rep, "journal.json"),
      `${JSON.stringify({ version: 0, org_id: org, journal_id: jid, created_at: creeLe, recorder: p.recorder ?? VERSION_ENREGISTREUR }, null, 2)}\n`,
      { mode: 0o600, flag: "wx" },
    );
    const v = await verifierChaineReconstruite(rep, { org_id: org, journal_id: jid, clePublique: p.clePublique ?? clePubliqueDepuisConfiguration(config) });
    if (v.incidents.length) throw new ErreurRestauration(v.incidents);
    // Pièces référencées sans copie (copy_pieces faux) : perdues (CT-8 §11.4).
    const piecesManquantes = [];
    for (const n of (await fs.readdir(path.join(rep, "segments")).catch(() => [])).sort()) {
      const evts = lireSegmentFerme(new Uint8Array(await fs.readFile(path.join(rep, "segments", n)))).evenements;
      for (const s of piecesReferencees(evts)) {
        const h = s.slice(2);
        if (!(await fs.stat(path.join(rep, "pieces", h.slice(0, 2), h)).then(() => true, () => false)) && !piecesManquantes.includes(s)) piecesManquantes.push(s);
      }
    }
    await fs.rename(provisoire, p.destination);
    const synthese = {
      destination: p.destination,
      fichiers: fichiers.length,
      last_seq: v.lastSeq,
      last_hash: v.lastHash,
      evenements: v.evenements,
      epoque_max: epoqueMax,
      perdus: [...SANS_COPIE, ...(piecesManquantes.length ? ["pieces/"] : [])],
      pieces_absentes: piecesManquantes.length,
      registre: Boolean(p.registre),
    };
    p.consigner?.("info", "worm", "worm_restored", synthese);
    return { synthese, fichiers };
  } catch (e) {
    await fs.rm(provisoire, { recursive: true, force: true });
    throw e;
  }
}

/**
 * `noortrace-ctl worm restaurer <clé> --version <id>` (CT-8 EX-10.14) : relit
 * une version, compare son SHA-256 et sa longueur à la ligne du registre des
 * copies, l'écrit dans un répertoire neuf sous son chemin relatif.
 * @param {{config: object, operations: object, cle: string, version_id: string, destination: string,
 *   registre: Map<string, object[]>, original: string}} p
 */
export async function restaurerVersion(p) {
  const prefixe = p.config.storage.seal.worm.prefix;
  if (!p.cle.startsWith(prefixe) || !sur(p.cle.slice(prefixe.length))) throw new ErreurRestauration([{ key: p.cle, kind: "cle_refusee" }], 2);
  const dest = path.resolve(p.destination);
  if (dest === path.resolve(p.original) || dest.startsWith(`${path.resolve(p.original)}${path.sep}`)) throw new ErreurRestauration([{ key: p.destination, kind: "destination_originale" }], 2);
  if (await fs.stat(dest).then(() => true, () => false)) throw new ErreurRestauration([{ key: p.destination, kind: "destination_existante" }], 2);
  const ligne = (p.registre.get(p.cle) ?? []).find((x) => x.version_id === p.version_id);
  if (!ligne) throw new ErreurRestauration([{ key: p.cle, version_id: p.version_id, kind: "version_non_inscrite" }]);
  const r = await p.operations.lire(p.cle, p.version_id);
  if (r.statut !== 200) throw new ErreurRestauration([{ key: p.cle, version_id: p.version_id, kind: r.statut === 404 ? "copie_absente" : "lecture_impossible", http_status: r.statut }], r.statut === 404 ? 1 : 4);
  const octets = new Uint8Array(r.corps);
  const sha256 = sha256Hex(octets);
  if (sha256 !== ligne.sha256 || octets.length !== ligne.length) throw new ErreurRestauration([{ key: p.cle, version_id: p.version_id, kind: "copie_alteree", attendu: ligne.sha256, lu: sha256 }]);
  const cible = path.join(dest, ...p.cle.slice(prefixe.length).split("/"));
  await fs.mkdir(path.dirname(cible), { recursive: true, mode: 0o700 });
  await fs.writeFile(cible, octets, { mode: 0o600, flag: "wx" });
  return { key: p.cle, version_id: p.version_id, sha256, length: octets.length, chemin: cible };
}
