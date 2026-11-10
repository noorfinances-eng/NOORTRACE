// Exportateur du composant d'ancrage (CT-5 §10.1, EX-10.1 à EX-10.5, AN-50 à
// AN-53 ; lot F2). Il lit, pour la période d'un événement, le répertoire
// d'ancres d'EX-5.14 (jetons `rfc3161/`, preuves `ots/`, `entetes-bitcoin.json`,
// `acquisitions.ndjson`), la série des points écrite par l'enregistreur et
// les index de capture des ancres au registre (CT-4 §9.4), et assemble le
// dossier de CT-1 §11 : les parties réservées de CT-5 (`jeton-rfc3161.der`,
// `preuve.ots`) et de CT-4 (`registre.json`, `certificat-commit.json`,
// `validateurs.json`), la treizième partie `points-de-controle.json` bâtie
// sur le point couvrant d'EX-10.2 avec ses ancres embarquées en base64
// (EX-10.3), l'entrée `ancre_point_de_controle` de `registre.json` (EX-10.4),
// et `entetes-bitcoin.json` à côté des parties (EX-6.10). Il ne lit pas la
// file : `acquisitions.ndjson` et son champ `promoted` disent quel jeton
// remettre (EX-5.8). Il ne modifie jamais un dossier remis : un réexport est
// un nouveau dossier à `generated_at` postérieur (EX-10.5). Rien n'est
// réencodé (règle 3 d'INTERFACES.md) : les pièces sont copiées octet pour
// octet, puis encodées en base64 canonique quand la partie l'exige.
//
// Aucune horloge n'est lue ici : `generated_at` est fourni par l'appelant
// (règle 2 d'INTERFACES.md).

import fs from "node:fs";
import path from "node:path";
import {
  coherencePoint, decoderBase64Canonique, decoderHorodatage, ecrireHorodatage, empreinteAncre, encoderBase64, hacherPoint, indexerDossier,
  sha256Hex, utf8,
} from "@noortrace/noyau";
import { DepotAncres, TAILLE_MAX_JETON, copieAutonome } from "./rfc3161/index.mjs";
import { DepotOts, BORNES as BORNES_OTS, etatPreuve, lireOts } from "./ots/index.mjs";
import {
  DOC_TYPE_POINT_DE_CONTROLE, choisirCaptures, decoderJournal, exporterPartiesRegistre, lecteurRepertoire, lireFichierRpc, lireRecu, listerCaptures,
} from "./registre/index.mjs";

const MOTIF_HEX32 = /^0x[0-9a-f]{64}$/;
const MOTIF_HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/** Rangs du choix du point couvrant (EX-10.2) : 1 jeton promu, 2 preuve complète, 3 ancre capturée, 4 sans ancre. */
export const RANGS = Object.freeze({ jeton: 1, preuve: 2, registre: 3, aucune: 4 });

/** Raisons des parties absentes (CT-1 §11.1, chaînes non vides). */
export const RAISONS = Object.freeze({
  pointAbsent: "aucun point de contrôle",
  jetonAbsent: "aucun jeton RFC 3161 promu pour le manifeste de la période",
  preuveAbsente: "aucune preuve OpenTimestamps du manifeste de la période",
  registreAbsent: "registre non configuré",
});

/** Noms et bornes des pièces embarquées (CT-6 EX-4.14 : 64 Kio pour le jeton, 256 Kio pour la preuve). */
export const BORNES_EXPORTATEUR = Object.freeze({ jeton: TAILLE_MAX_JETON, preuve: BORNES_OTS.TAILLE_FICHIER, entetes: 64 * 1024 * 1024, hashes: 1_000_000 });

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Octets d'un fichier JSON du dossier : `JSON.stringify(objet, null, 2)` suivi d'un saut de ligne (CT-1 §11.1). */
export function octetsJsonDossier(objet) {
  return utf8(JSON.stringify(objet, null, 2) + "\n");
}

/** Nom d'objet d'un point dans le répertoire d'ancres (EX-5.14). */
export function nomObjetPoint(checkpointHash) {
  if (!MOTIF_HEX32.test(checkpointHash)) throw new TypeError("checkpointHash hex32 attendu");
  return `point-${checkpointHash.slice(2)}`;
}

/** Contrôle de forme minimal d'un point de la série (CT-1 §10.5) ; lève sur une forme refusée. */
function controlerPoint(point, k) {
  if (!estObjet(point)) throw new TypeError(`série : point ${k} : objet attendu`);
  if (!Number.isSafeInteger(point.tree_size) || point.tree_size < 0) throw new TypeError(`série : point ${k} : tree_size entier attendu`);
  if (typeof point.checkpoint_ts !== "string" || !MOTIF_HORODATAGE.test(point.checkpoint_ts) || decoderHorodatage(point.checkpoint_ts) === null) {
    throw new TypeError(`série : point ${k} : checkpoint_ts RFC 3339 attendu`);
  }
  if (!Number.isSafeInteger(point.period_start)) throw new TypeError(`série : point ${k} : period_start entier attendu`);
}

/** Dernier état de chaque tentative d'un tableau d'enregistrements d'acquisition (EX-5.13, ajout seul). */
export function derniersEtats(enregistrements) {
  const par = new Map();
  let k = 0;
  for (const e of enregistrements) {
    if (!estObjet(e)) continue;
    par.set(typeof e.attempt_id === "string" ? e.attempt_id : `sans_attempt_id:${k++}`, e);
  }
  return [...par.values()];
}

/**
 * L'enregistrement du jeton promu d'un point parmi des enregistrements
 * d'acquisition (dernier état de chaque tentative ; EX-5.8), ou null : le
 * dernier marqué `promoted` et non révoqué, de `outcome` `obtenue`, dont
 * l'objet est ce point.
 * @param {object[]} enregistrements
 * @param {string} checkpointHash
 */
export function jetonPromuDuPoint(enregistrements, checkpointHash) {
  const nom = nomObjetPoint(checkpointHash);
  let retenu = null;
  for (const e of derniersEtats(enregistrements)) {
    if (e.object !== "point" || (e.object_name !== nom && e.imprint !== checkpointHash)) continue;
    if (e.outcome === "obtenue" && e.promoted === true && e.revoked !== true && typeof e.files?.token === "string") retenu = e;
  }
  return retenu;
}

/** Normalise une source d'ancres (`Map`, objet, tableau, `Set`, fonction) en fonction `hash → valeur|null`. */
function accesseur(source, { ensemble = false } = {}) {
  if (source === null || source === undefined) return () => null;
  if (typeof source === "function") return (h) => source(h) ?? null;
  if (source instanceof Map) return (h) => (source.has(h) ? source.get(h) : null);
  if (source instanceof Set) return (h) => (source.has(h) ? true : null);
  if (Array.isArray(source)) {
    if (ensemble) return (h) => (source.includes(h) ? true : null);
    // Tableau d'enregistrements d'acquisition (EX-5.13).
    return (h) => jetonPromuDuPoint(source, h);
  }
  if (estObjet(source)) return (h) => (Object.prototype.hasOwnProperty.call(source, h) ? source[h] : null);
  throw new TypeError("source d'ancres : Map, objet, tableau, Set ou fonction attendus");
}

/** État d'une preuve OpenTimestamps donnée en octets ou déjà qualifiée (`{ etat }`, `"complete"`). */
function etatDePreuve(v) {
  if (v === null || v === undefined || v === false) return null;
  if (v === true) return "inconnu";
  if (typeof v === "string") return v;
  if (v instanceof Uint8Array) {
    try {
      return etatPreuve(v);
    } catch {
      return null;
    }
  }
  if (estObjet(v)) {
    if (typeof v.etat === "string") return v.etat;
    if (v.octets instanceof Uint8Array) return etatDePreuve(v.octets);
    return "inconnu";
  }
  return null;
}

/**
 * EX-10.2 (AN-51) : choisit le point couvrant d'un événement d'indice de
 * feuille `leafIndex` parmi les points de la série de sa période : rang
 * jeton RFC 3161 promu > preuve `.ots` complète > ancre au registre capturée
 * > sans ancre ; à rang égal le plus petit `tree_size`, puis le premier de la
 * série (plus petit `checkpoint_ts`, puis l'ordre de la série).
 *
 * `acquisitions` : enregistrements d'acquisition de la période (tableau), ou
 * `hash → enregistrement|null` ; `preuves` : `hash → octets | { etat } | état`
 * (une preuve en attente ne donne pas le rang 2) ; `captures` : `hash → index
 * de capture|true` (Map, Set, tableau de hachages ou fonction).
 * @returns {{point: object, checkpointHash: string, rang: number, index: number,
 *   ancres: {rfc3161: object|null, ots: unknown, registre: unknown}}|null}
 */
export function choisirPointCouvrant({ serie, leafIndex, acquisitions = null, preuves = null, captures = null }) {
  if (!Array.isArray(serie)) throw new TypeError("serie : tableau de points attendu");
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) throw new TypeError("leafIndex : entier positif ou nul attendu");
  const jeton = accesseur(acquisitions);
  const preuve = accesseur(preuves);
  const capture = accesseur(captures, { ensemble: true });
  let meilleur = null;
  serie.forEach((point, k) => {
    controlerPoint(point, k);
    if (point.tree_size <= leafIndex) return;
    const checkpointHash = hacherPoint(point);
    const ancres = { rfc3161: jeton(checkpointHash), ots: preuve(checkpointHash), registre: capture(checkpointHash) };
    const etatOts = etatDePreuve(ancres.ots);
    const rang = ancres.rfc3161 ? RANGS.jeton : etatOts === "complete" ? RANGS.preuve : ancres.registre ? RANGS.registre : RANGS.aucune;
    const ts = decoderHorodatage(point.checkpoint_ts);
    const candidat = { point, checkpointHash, rang, index: k, ts, ancres };
    if (meilleur === null || rang < meilleur.rang || (rang === meilleur.rang && (point.tree_size < meilleur.point.tree_size || (point.tree_size === meilleur.point.tree_size && ts < meilleur.ts)))) {
      meilleur = candidat;
    }
  });
  if (meilleur === null) return null;
  const { ts, ...resultat } = meilleur;
  void ts;
  return resultat;
}

/**
 * Référence `anchors.registry` d'un point (CT-1 §11.2, EX-10.3) depuis un
 * index de capture de CT-4 §9.4 : `chain_id` (identifiant EVM), `contract`,
 * `fingerprint` recalculée, `doc_type`, `block_number`, `block_hash`,
 * `transaction_hash`, `log_index`. Lève si l'index n'a pas la forme attendue.
 */
export function referenceRegistre({ index, orgId, journalId, checkpointHash }) {
  if (!estObjet(index)) throw new TypeError("index de capture attendu");
  const entier = (v, nom) => {
    if (!Number.isSafeInteger(v) || v < 0) throw new TypeError(`index de capture : ${nom} entier attendu`);
    return v;
  };
  const hex32 = (v, nom) => {
    if (!MOTIF_HEX32.test(v)) throw new TypeError(`index de capture : ${nom} hex32 attendu`);
    return v;
  };
  if (!/^0x[0-9a-f]{40}$/.test(index.contract)) throw new TypeError("index de capture : contract (adresse) attendu");
  return {
    chain_id: entier(index.evm_chain_id, "evm_chain_id"),
    contract: index.contract,
    fingerprint: empreinteAncre(orgId, journalId, checkpointHash),
    doc_type: DOC_TYPE_POINT_DE_CONTROLE,
    block_number: entier(index.block_number, "block_number"),
    block_hash: hex32(index.block_hash, "block_hash"),
    transaction_hash: hex32(index.transaction_hash, "transaction_hash"),
    log_index: entier(index.log_index, "log_index"),
  };
}

/**
 * EX-10.3 (AN-50, AN-52) : construit la partie `points-de-controle.json`
 * (CT-1 §11.2) : le point, `checkpoint_hash` recalculé par le noyau, la preuve
 * de cohérence `PROOF(tree_size, D[count])` recalculée depuis les feuilles de
 * la période, et les trois ancres : `rfc3161.token` (base64 canonique du
 * `.der` promu), `ots.proof` (base64 canonique de la dernière version du
 * `.ots`), `registry` (référence lue dans l'index de capture) ; chaque ancre
 * absente vaut `null`. Rend `{ partie, octets, checkpointHash }`.
 * @param {{point: object, hashes: string[], jeton?: Uint8Array|null, preuve?: Uint8Array|null, capture?: object|null}} p
 */
export function construirePartiePointsDeControle({ point, hashes, jeton = null, preuve = null, capture = null }) {
  controlerPoint(point, 0);
  if (!Array.isArray(hashes) || hashes.length > BORNES_EXPORTATEUR.hashes || hashes.some((h) => !MOTIF_HEX32.test(h))) throw new TypeError("hashes : tableau de hex32 attendu");
  if (point.tree_size < 1 || point.tree_size > hashes.length) throw new RangeError(`tree_size ${point.tree_size} hors de [1, ${hashes.length}] (K-1)`);
  if (!MOTIF_HEX32.test(point.org_id) || !MOTIF_HEX32.test(point.journal_id)) throw new TypeError("point : org_id et journal_id hex32 attendus");
  const checkpointHash = hacherPoint(point);
  const anchors = { rfc3161: null, registry: null, ots: null };
  if (jeton !== null && jeton !== undefined) {
    if (!(jeton instanceof Uint8Array) || jeton.length === 0 || jeton.length > BORNES_EXPORTATEUR.jeton) throw new RangeError(`jeton : octets de 1 à ${BORNES_EXPORTATEUR.jeton} attendus (EX-9.3)`);
    anchors.rfc3161 = { token: encoderBase64(jeton) };
  }
  if (capture !== null && capture !== undefined) anchors.registry = referenceRegistre({ index: capture, orgId: point.org_id, journalId: point.journal_id, checkpointHash });
  if (preuve !== null && preuve !== undefined) {
    if (!(preuve instanceof Uint8Array) || preuve.length === 0 || preuve.length > BORNES_EXPORTATEUR.preuve) throw new RangeError(`preuve : octets de 1 à ${BORNES_EXPORTATEUR.preuve} attendus (EX-10.2)`);
    const lue = lireOts(preuve); // une preuve illisible n'est jamais embarquée (O-1)
    if (lue.empreinteHex !== checkpointHash) throw new RangeError("preuve : empreinte de fichier différente du checkpointHash (K-9)");
    anchors.ots = { proof: encoderBase64(preuve) };
  }
  const partie = { version: 0, checkpoint: point, checkpoint_hash: checkpointHash, consistency: coherencePoint(point.tree_size, hashes), anchors };
  return { partie, octets: octetsJsonDossier(partie), checkpointHash };
}

/**
 * Dépôts d'un journal sous la racine de stockage de l'enregistreur (CT-2
 * EX-12.1 ; EX-5.14) : lecture seule ici.
 */
export function depotsJournal({ racineStockage, orgId, journalId }) {
  return {
    ancres: new DepotAncres({ racine: racineStockage, orgId, journalId }),
    ots: DepotOts.ouvrir({ racine: racineStockage, orgId, journalId }),
  };
}

function lireOctets(chemin, max) {
  let st;
  try {
    st = fs.statSync(chemin);
  } catch {
    return null;
  }
  if (!st.isFile() || st.size > max) return null;
  return new Uint8Array(fs.readFileSync(chemin));
}

/**
 * Pièces d'un objet (`manifeste` ou `point-<hash>`) d'une période (EX-10.1,
 * EX-6.10, AN-50) : le fichier `.der` du jeton promu désigné par
 * `acquisitions.ndjson` (octets, SHA-256 confronté à `token_sha256`), la
 * dernière version de la preuve `.ots` avec son état, ou `null`. Une
 * incohérence (fichier absent ou SHA-256 différent de l'enregistrement) est
 * rendue dans `defauts`, jamais corrigée.
 */
export function piecesObjet({ depots, periodStart, objet, checkpointHash = null }) {
  const defauts = [];
  const nom = objet === "manifeste" ? "manifeste" : nomObjetPoint(checkpointHash);
  let jeton = null;
  let enregistrement = null;
  try {
    enregistrement = depots.ancres.promu(objet === "manifeste" ? "manifeste" : "point", periodStart, objet === "manifeste" ? null : checkpointHash);
  } catch (e) {
    defauts.push({ piece: "acquisitions", raison: String(e?.message ?? e).slice(0, 200) });
  }
  if (enregistrement && enregistrement.outcome === "obtenue" && typeof enregistrement.files?.token === "string") {
    const rel = enregistrement.files.token;
    const chemin = path.join(depots.ancres.repertoireJournal, `periode-${String(periodStart).padStart(10, "0")}`, rel);
    const octets = /^rfc3161\/[^/\\]+\.der$/.test(rel) ? lireOctets(chemin, BORNES_EXPORTATEUR.jeton) : null;
    if (!octets) defauts.push({ piece: rel, raison: "jeton promu illisible ou absent" });
    else if (sha256Hex(octets) !== enregistrement.token_sha256) defauts.push({ piece: rel, raison: "SHA-256 différent de token_sha256 (AN-50)" });
    else jeton = { octets, enregistrement, fichier: rel, sha256: enregistrement.token_sha256 };
  }
  let preuve = null;
  try {
    const derniere = depots.ots.derniere({ periodStart, objet: nom });
    if (derniere) preuve = { octets: derniere.octets, version: derniere.version, fichier: derniere.fichier, etat: etatPreuve(derniere.octets), sha256: sha256Hex(derniere.octets) };
  } catch (e) {
    defauts.push({ piece: `ots/${nom}`, raison: String(e?.message ?? e).slice(0, 200) });
  }
  return { jeton, preuve, defauts };
}

/**
 * EX-10.1 : pièces de la période d'un événement : `jeton-rfc3161.der` (jeton
 * promu du manifeste), `preuve.ots` (dernière version), `entetes-bitcoin.json`
 * (octets du fichier d'EX-6.8), et les enregistrements d'acquisition (dernier
 * état) pour le choix du point.
 */
export function piecesPeriode({ depots, periodStart }) {
  const { jeton, preuve, defauts } = piecesObjet({ depots, periodStart, objet: "manifeste" });
  let entetes = null;
  const cheminEntetes = path.join(depots.ots.repertoirePeriode(periodStart), "entetes-bitcoin.json");
  const octetsEntetes = lireOctets(cheminEntetes, BORNES_EXPORTATEUR.entetes);
  if (octetsEntetes) entetes = { octets: octetsEntetes, chemin: cheminEntetes };
  let acquisitions = [];
  let tronquee = false;
  try {
    const lu = depots.ancres.dernieresAcquisitions(periodStart);
    acquisitions = lu.enregistrements;
    tronquee = lu.tronquee;
  } catch (e) {
    defauts.push({ piece: "acquisitions.ndjson", raison: String(e?.message ?? e).slice(0, 200) });
  }
  return { jeton, preuve, entetes, acquisitions, tronquee, defauts };
}

/**
 * Index de capture des ancres de points (rôle `ancre`, `docType` du point)
 * d'un répertoire de captures, par empreinte d'ancre (CT-4 §9.4, EX-10.4).
 * @returns {{parEmpreinte: Map<string, object>, indexes: object[]}}
 */
export function indexAncresPoints(repertoireCaptures) {
  const parEmpreinte = new Map();
  const captures = listerCaptures(repertoireCaptures);
  const lecteur = lecteurRepertoire(repertoireCaptures);
  for (const { index } of captures) {
    if (index.role !== "ancre") continue;
    const recu = lireFichierRpc(lecteur.lire(index.files.receipts[index.transaction_index]?.name));
    const lu = recu ? lireRecu(recu.resultat) : null;
    const j = lu && Number.isInteger(index.log_index) ? lu.logs[index.log_index] : null;
    const d = j ? decoderJournal("ancre_point_de_controle", j) : null;
    if (d && !parEmpreinte.has(d.fingerprint)) parEmpreinte.set(d.fingerprint, index);
  }
  return { parEmpreinte, indexes: captures.map((c) => c.index) };
}

/**
 * EX-10.4 : parties du registre d'un dossier (CT-4 §9.6) : clôture et ancre
 * de la période, inscriptions des clés demandées dont la capture existe, et
 * l'entrée `ancre_point_de_controle` quand la capture de l'ancre du point
 * couvrant existe. Rend `{ octets: { registre, certificatCommit, validateurs },
 * choix, inscriptionsAbsentes }` ou lève (`capture_incomplete`, CT-4 EX-9.11).
 * @param {{repertoireCaptures: string, periodHash: string, fingerprint: string, inscriptions?: {clePublique: string, chainKey?: string|null}[],
 *   empreintePoint?: string|null, jeux: object, source: string}} p
 */
export function partiesRegistre({ repertoireCaptures, periodHash, fingerprint, inscriptions = [], empreintePoint = null, jeux, source }) {
  const captures = listerCaptures(repertoireCaptures);
  const indexes = captures.map((c) => c.index);
  const lecteur = lecteurRepertoire(repertoireCaptures);
  // Inscriptions présentes dans les captures (celles de la clé du manifeste et des clés qui signent dans le dossier, CT-4 EX-9.8).
  const inscrites = new Set();
  for (const index of indexes) {
    if (index.role !== "inscription") continue;
    const recu = lireFichierRpc(lecteur.lire(index.files.receipts[index.transaction_index]?.name));
    const lu = recu ? lireRecu(recu.resultat) : null;
    const j = lu && Number.isInteger(index.log_index) ? lu.logs[index.log_index] : null;
    const d = j ? decoderJournal("inscription", j) : null;
    if (d) inscrites.add(d.ed25519PubKey);
  }
  const demandees = [];
  const absentes = [];
  const vues = new Set();
  for (const i of inscriptions) {
    if (!estObjet(i) || !MOTIF_HEX32.test(i.clePublique) || vues.has(i.clePublique)) continue;
    vues.add(i.clePublique);
    if (inscrites.has(i.clePublique)) demandees.push({ clePublique: i.clePublique, chainKey: i.chainKey ?? null });
    else absentes.push(i.clePublique);
  }
  const choix = choisirCaptures({ repertoire: repertoireCaptures, indexes, periodHash, fingerprint, inscriptions: demandees.slice(0, 8), empreintePoint });
  const parties = exporterPartiesRegistre({ repertoire: repertoireCaptures, captures: choix, jeux, source });
  return { ...parties, choix, inscriptionsAbsentes: absentes };
}

/**
 * Exporte le dossier CT-1 §11 d'un événement avec ses ancres (EX-10.1 à
 * EX-10.4). L'appelant (l'enregistreur) fournit les sept parties de CT-1
 * déjà sérialisées (`partiesBase` : `evenement.json`, `voisins.json`,
 * `chemin.json`, `manifeste.json`, `manifeste.sig`, `cles.json`,
 * `approbations.json` si elle existe) et leurs raisons d'absence
 * (`raisonsBase`), les hashes des événements de la période dans l'ordre des
 * `seq`, l'indice de feuille, la série des points, le manifeste, et ce qui
 * désigne les ancres : la racine de stockage (dépôts d'EX-5.14) et, s'il y a
 * un registre, le répertoire des captures, le manifeste d'instance (jeux de
 * validateurs) et les clés dont l'inscription est demandée.
 *
 * Rend `{ dossier, fichiers, point, pieces, raisons, resume }` et écrit le
 * dossier dans `destination` (les parties, `dossier.json` par
 * `indexerDossier` du noyau, et `entetes-bitcoin.json` non déclaré à côté).
 * `resume` est l'état des ancres embarquées, l'entrée de `reexportsDus`.
 * @param {object} p
 * @param {{seq: number, hash: string}} p.event
 * @param {string} p.org_id
 * @param {string} p.journal_id
 * @param {Map<string, Uint8Array>} p.partiesBase
 * @param {Record<string, string>} [p.raisonsBase]
 * @param {number} p.leafIndex
 * @param {string[]} p.hashes
 * @param {object} p.manifeste manifeste de la période (objet)
 * @param {string} p.periodHash
 * @param {object[]} p.serie points de la période
 * @param {string} p.racineStockage
 * @param {{repertoireCaptures: string, jeux: object, source: string, inscriptions?: object[]}|null} [p.registre]
 * @param {string} p.destination
 * @param {number} p.generated_at ms UTC
 * @param {boolean} [p.ecrire] écrire les fichiers (vrai par défaut)
 */
export function exporterDossier(p) {
  if (!estObjet(p.event) || !Number.isSafeInteger(p.event.seq) || !MOTIF_HEX32.test(p.event.hash)) throw new TypeError("event { seq, hash } attendu");
  if (!MOTIF_HEX32.test(p.org_id) || !MOTIF_HEX32.test(p.journal_id)) throw new TypeError("org_id et journal_id hex32 attendus");
  if (!(p.partiesBase instanceof Map)) throw new TypeError("partiesBase : Map attendue");
  if (!estObjet(p.manifeste) || !Number.isSafeInteger(p.manifeste.period_start)) throw new TypeError("manifeste attendu");
  if (!Number.isSafeInteger(p.generated_at)) throw new TypeError("generated_at : ms entières attendues");
  const periodStart = p.manifeste.period_start;
  const depots = depotsJournal({ racineStockage: p.racineStockage, orgId: p.org_id, journalId: p.journal_id });
  const fichiers = new Map(p.partiesBase);
  const raisons = { ...(p.raisonsBase ?? {}) };
  const defauts = [];

  // Parties de la période (EX-10.1).
  const periode = piecesPeriode({ depots, periodStart });
  defauts.push(...periode.defauts);
  if (periode.jeton) fichiers.set("jeton-rfc3161.der", periode.jeton.octets);
  else raisons.jeton_rfc3161 = RAISONS.jetonAbsent;
  if (periode.preuve) fichiers.set("preuve.ots", periode.preuve.octets);
  else raisons.preuve_ots = RAISONS.preuveAbsente;

  // Point couvrant (EX-10.2) et ses ancres (EX-10.3).
  const captures = p.registre ? indexAncresPoints(p.registre.repertoireCaptures) : { parEmpreinte: new Map(), indexes: [] };
  const preuvesPoints = (hash) => {
    const d = depots.ots.derniere({ periodStart, objet: nomObjetPoint(hash) });
    return d ? d.octets : null;
  };
  const choix = choisirPointCouvrant({
    serie: p.serie.filter((x) => estObjet(x) && x.period_start === periodStart),
    leafIndex: p.leafIndex,
    acquisitions: periode.acquisitions,
    preuves: preuvesPoints,
    captures: (hash) => captures.parEmpreinte.get(empreinteAncre(p.org_id, p.journal_id, hash)) ?? null,
  });
  let point = null;
  let partiePoint = null;
  if (choix) {
    const pieces = piecesObjet({ depots, periodStart, objet: "point", checkpointHash: choix.checkpointHash });
    defauts.push(...pieces.defauts);
    const capture = choix.ancres.registre ?? null;
    partiePoint = construirePartiePointsDeControle({ point: choix.point, hashes: p.hashes, jeton: pieces.jeton?.octets ?? null, preuve: pieces.preuve?.octets ?? null, capture });
    fichiers.set("points-de-controle.json", partiePoint.octets);
    point = {
      checkpointHash: choix.checkpointHash, tree_size: choix.point.tree_size, checkpoint_ts: choix.point.checkpoint_ts, rang: choix.rang,
      ancres: { rfc3161: pieces.jeton?.sha256 ?? null, ots: pieces.preuve ? { sha256: pieces.preuve.sha256, etat: pieces.preuve.etat, version: pieces.preuve.version } : null, registre: capture ? capture.transaction_hash : null },
    };
  } else raisons.points_de_controle = RAISONS.pointAbsent;

  // Parties du registre (EX-10.4).
  let registre = null;
  if (p.registre) {
    try {
      registre = partiesRegistre({
        repertoireCaptures: p.registre.repertoireCaptures, periodHash: p.periodHash, fingerprint: empreinteAncre(p.org_id, p.journal_id, p.periodHash),
        inscriptions: p.registre.inscriptions ?? [], empreintePoint: point?.ancres.registre ? empreinteAncre(p.org_id, p.journal_id, point.checkpointHash) : null,
        jeux: p.registre.jeux, source: p.registre.source,
      });
      fichiers.set("registre.json", registre.octets.registre);
      fichiers.set("certificat-commit.json", registre.octets.certificatCommit);
      fichiers.set("validateurs.json", registre.octets.validateurs);
    } catch (e) {
      const raison = String(e?.message ?? e).slice(0, 200);
      for (const nom of ["registre", "certificat_commit", "validateurs"]) raisons[nom] = raison;
      defauts.push({ piece: "registre", raison });
    }
  } else for (const nom of ["registre", "certificat_commit", "validateurs"]) raisons[nom] = RAISONS.registreAbsent;

  const dossier = indexerDossier({ event: p.event, org_id: p.org_id, journal_id: p.journal_id, generated_at: ecrireHorodatage(p.generated_at), fichiers, points: true, raisons });
  const octetsIndex = octetsJsonDossier(dossier);
  if (p.ecrire !== false) {
    fs.mkdirSync(p.destination, { recursive: true, mode: 0o700 });
    for (const [nom, octets] of fichiers) fs.writeFileSync(path.join(p.destination, nom), octets);
    fs.writeFileSync(path.join(p.destination, "dossier.json"), octetsIndex);
    if (periode.entetes) fs.writeFileSync(path.join(p.destination, "entetes-bitcoin.json"), periode.entetes.octets);
  }
  // Le résumé est gardé par l'appelant pour EX-10.5 : ses chaînes sont recopiées pour ne retenir aucun texte de fichier relu.
  const resume = copieAutonome({
    seq: p.event.seq,
    hash: p.event.hash,
    period_start: periodStart,
    generated_at: ecrireHorodatage(p.generated_at),
    destination: p.destination,
    periode: { rfc3161: periode.jeton?.sha256 ?? null, ots: periode.preuve ? { sha256: periode.preuve.sha256, etat: periode.preuve.etat, version: periode.preuve.version } : null, registre: registre !== null, entetes: periode.entetes !== null },
    point,
  });
  return { dossier, octetsIndex, fichiers, point, pieces: { entetes: periode.entetes ? path.join(p.destination, "entetes-bitcoin.json") : null }, raisons, defauts, resume };
}

/**
 * État courant des ancres d'une période (entrée d'`exporterDossier` pour la
 * comparaison d'EX-10.5) : ancres du manifeste et, par point de la série,
 * jeton promu, dernière preuve et capture.
 */
export function etatAncresPeriode({ racineStockage, orgId, journalId, periodStart, serie = [], repertoireCaptures = null, periodHash = null }) {
  const depots = depotsJournal({ racineStockage, orgId, journalId });
  const periode = piecesPeriode({ depots, periodStart });
  const captures = repertoireCaptures ? indexAncresPoints(repertoireCaptures) : { parEmpreinte: new Map(), indexes: [] };
  const points = new Map();
  for (const point of serie) {
    if (!estObjet(point) || point.period_start !== periodStart) continue;
    const hash = hacherPoint(point);
    const pieces = piecesObjet({ depots, periodStart, objet: "point", checkpointHash: hash });
    const index = captures.parEmpreinte.get(empreinteAncre(orgId, journalId, hash)) ?? null;
    points.set(hash, {
      rfc3161: pieces.jeton?.sha256 ?? null,
      ots: pieces.preuve ? { sha256: pieces.preuve.sha256, etat: pieces.preuve.etat, version: pieces.preuve.version } : null,
      registre: index ? index.transaction_hash : null,
    });
  }
  let cloture = false;
  if (repertoireCaptures && periodHash) {
    const lecteur = lecteurRepertoire(repertoireCaptures);
    for (const index of captures.indexes) {
      if (index.role !== "cloture") continue;
      const recu = lireFichierRpc(lecteur.lire(index.files.receipts[index.transaction_index]?.name));
      const lu = recu ? lireRecu(recu.resultat) : null;
      const j = lu && Number.isInteger(index.log_index) ? lu.logs[index.log_index] : null;
      const d = j ? decoderJournal("cloture", j) : null;
      if (d && d.periodHash === periodHash) cloture = true;
    }
  }
  return {
    period_start: periodStart,
    periode: { rfc3161: periode.jeton?.sha256 ?? null, ots: periode.preuve ? { sha256: periode.preuve.sha256, etat: periode.preuve.etat, version: periode.preuve.version } : null, registre: cloture, entetes: periode.entetes !== null },
    points,
  };
}

function ancreNouvelle(avant, apres) {
  if (apres === null || apres === undefined) return false;
  if (avant === null || avant === undefined) return true;
  if (typeof apres === "object" && typeof avant === "object") return apres.sha256 !== avant.sha256 || (avant.etat !== "complete" && apres.etat === "complete");
  return apres !== avant;
}

/**
 * EX-10.5 (AN-53) : dossiers déjà produits qu'une ancre arrivée depuis rend à
 * réexporter : preuve OpenTimestamps passée de `en_attente` à `complete`
 * (période ou point), jeton promu obtenu après l'export (relève promue plus
 * tard), ancre de registre capturée après coup, clôture au registre
 * relayée, fichier d'en-têtes écrit. `dossiersProduits` : les `resume`
 * d'`exporterDossier` ; `etatAncres` : `period_start → état` (objet, Map ou
 * fonction) de la forme d'`etatAncresPeriode`. Rend, pour chaque dossier dû,
 * `{ seq, hash, period_start, destination, generated_at, raisons }` ; le
 * dossier antérieur n'est jamais modifié : le nouveau a un `generated_at`
 * postérieur, fixé par l'appelant. Pour un même événement (`hash`), seul le
 * dossier le plus récent compte : un dossier déjà réexporté n'est plus dû.
 */
export function reexportsDus({ dossiersProduits, etatAncres }) {
  if (!Array.isArray(dossiersProduits)) throw new TypeError("dossiersProduits : tableau attendu");
  const etatDe = typeof etatAncres === "function" ? etatAncres : etatAncres instanceof Map ? (P) => etatAncres.get(P) ?? null : (P) => (estObjet(etatAncres) ? etatAncres[P] ?? null : null);
  const dus = [];
  const derniers = new Map();
  for (const d of dossiersProduits) {
    if (!estObjet(d) || !Number.isSafeInteger(d.period_start)) continue;
    const cle = `${d.hash ?? ""}:${d.seq ?? ""}`;
    const t = typeof d.generated_at === "string" ? decoderHorodatage(d.generated_at) ?? 0 : 0;
    const precedent = derniers.get(cle);
    if (!precedent || t >= precedent.t) derniers.set(cle, { d, t });
  }
  for (const { d } of derniers.values()) {
    const etat = etatDe(d.period_start);
    if (!estObjet(etat)) continue;
    const raisons = [];
    const avant = d.periode ?? {};
    const apres = etat.periode ?? {};
    if (ancreNouvelle(avant.rfc3161, apres.rfc3161)) raisons.push("jeton_periode");
    if (ancreNouvelle(avant.ots, apres.ots)) raisons.push("ots_periode");
    if (!avant.registre && apres.registre) raisons.push("registre_periode");
    if (!avant.entetes && apres.entetes) raisons.push("entetes_bitcoin");
    if (d.point && estObjet(d.point.ancres) && etat.points instanceof Map) {
      const courant = etat.points.get(d.point.checkpointHash);
      if (courant) {
        if (ancreNouvelle(d.point.ancres.rfc3161, courant.rfc3161)) raisons.push("jeton_point");
        if (ancreNouvelle(d.point.ancres.ots, courant.ots)) raisons.push("ots_point");
        if (ancreNouvelle(d.point.ancres.registre, courant.registre)) raisons.push("registre_point");
      }
      // Un point de rang meilleur apparu depuis (jeton promu sur un autre point couvrant) rend aussi le dossier à réexporter.
      if (d.point.rang > RANGS.jeton) {
        for (const [hash, c] of etat.points) {
          if (hash === d.point.checkpointHash) continue;
          if (c.rfc3161 && d.point.rang > RANGS.jeton) {
            raisons.push("point_couvrant_meilleur");
            break;
          }
        }
      }
    } else if (d.point === null && etat.points instanceof Map && etat.points.size) {
      // Aucun point au premier export : la partie peut maintenant exister (série relue).
      raisons.push("point_apparu");
    }
    if (raisons.length) dus.push({ seq: d.seq, hash: d.hash, period_start: d.period_start, destination: d.destination ?? null, generated_at: d.generated_at ?? null, raisons: [...new Set(raisons)] });
  }
  return dus;
}

/** Décode une ancre embarquée (base64 canonique) ; null si non canonique ou au-delà de la borne (CT-6 EX-4.14). */
export function decoderAncreEmbarquee(texte, borne) {
  return decoderBase64Canonique(texte, borne);
}

/**
 * AN-50 : compare les ancres d'un dossier écrit (fichiers `jeton-rfc3161.der`,
 * `preuve.ots`, `points-de-controle.json`) aux fichiers promus du répertoire
 * d'ancres désignés par `acquisitions.ndjson` et au dépôt des preuves. Rend
 * `{ conforme, ecarts }`.
 */
export function controlerAncresDossier({ repertoireDossier, racineStockage, orgId, journalId, periodStart }) {
  const ecarts = [];
  const depots = depotsJournal({ racineStockage, orgId, journalId });
  const periode = piecesPeriode({ depots, periodStart });
  const lire = (nom) => lireOctets(path.join(repertoireDossier, nom), BORNES_EXPORTATEUR.entetes);
  const comparer = (nom, attendu) => {
    const octets = lire(nom);
    if (!attendu && !octets) return;
    if (!attendu || !octets) return void ecarts.push({ piece: nom, raison: attendu ? "partie absente du dossier" : "partie présente sans pièce promue" });
    if (sha256Hex(octets) !== sha256Hex(attendu)) ecarts.push({ piece: nom, raison: "octets différents de la pièce promue" });
  };
  comparer("jeton-rfc3161.der", periode.jeton?.octets ?? null);
  comparer("preuve.ots", periode.preuve?.octets ?? null);
  const partieOctets = lire("points-de-controle.json");
  if (partieOctets) {
    let partie;
    try {
      partie = JSON.parse(Buffer.from(partieOctets).toString("utf8"));
    } catch {
      partie = null;
    }
    if (!estObjet(partie) || !estObjet(partie.anchors)) ecarts.push({ piece: "points-de-controle.json", raison: "partie illisible" });
    else {
      const hash = hacherPoint(partie.checkpoint);
      if (hash !== partie.checkpoint_hash) ecarts.push({ piece: "points-de-controle.json", raison: "checkpoint_hash différent du point (K-2)" });
      const pieces = piecesObjet({ depots, periodStart, objet: "point", checkpointHash: hash });
      const jeton = partie.anchors.rfc3161 ? decoderAncreEmbarquee(partie.anchors.rfc3161.token, BORNES_EXPORTATEUR.jeton) : null;
      if (partie.anchors.rfc3161 && !jeton) ecarts.push({ piece: "rfc3161.token", raison: "base64 non canonique" });
      else if ((jeton === null) !== (pieces.jeton === null) || (jeton && sha256Hex(jeton) !== pieces.jeton.sha256)) ecarts.push({ piece: "rfc3161.token", raison: "différent du jeton promu du point" });
      const preuve = partie.anchors.ots ? decoderAncreEmbarquee(partie.anchors.ots.proof, BORNES_EXPORTATEUR.preuve) : null;
      if (partie.anchors.ots && !preuve) ecarts.push({ piece: "ots.proof", raison: "base64 non canonique" });
      else if ((preuve === null) !== (pieces.preuve === null) || (preuve && sha256Hex(preuve) !== pieces.preuve.sha256)) ecarts.push({ piece: "ots.proof", raison: "différente de la dernière version de la preuve du point" });
    }
  }
  return { conforme: ecarts.length === 0, ecarts };
}
