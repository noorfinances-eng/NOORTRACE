// Export d'un dossier de preuve (CT-1 §11) depuis le stockage du cœur
// (segments, manifestes, séries de points, fichiers des approbations). Sans
// composant d'ancrage, ce module produit les douze parties v0, les cinq
// parties réservées absentes avec la raison « hors périmètre CT-1 », et la
// treizième partie `points-de-controle.json` sans ancre. Avec le composant
// d'ancrage branché (`anchoring.ancrage`, lot F2), l'assemblage des sept
// parties de CT-1 est le même et l'exportateur du composant (CT-5 §10,
// `@noortrace/ancrage`) complète le dossier : point couvrant d'EX-10.2 avec
// ses ancres embarquées, `jeton-rfc3161.der`, `preuve.ots`, parties du
// registre et `entetes-bitcoin.json` à côté. Les fichiers sont écrits par
// `JSON.stringify(objet, null, 2)` suivi d'un saut de ligne (CT-1 §11.1) ; le
// manifeste et sa signature sont copiés octet pour octet depuis `manifestes/`.

import fs from "node:fs/promises";
import path from "node:path";
import {
  decoderHorodatage, ecrireHorodatage, hacherPoint, indexerDossier, preuveInclusion, coherencePoint,
} from "@noortrace/noyau";
import { listerSegments, lireSegmentFerme } from "./segments.mjs";
import { lireManifeste, octetsJsonLisible, debutPeriode } from "./periodes.mjs";
import { choisirPoint, nomSerie, relireSerie } from "./points.mjs";

/**
 * Lit tous les événements durables d'un journal (segments dans l'ordre).
 * @param {string} repertoire
 * @returns {Promise<object[]>}
 */
export async function lireEvenements(repertoire) {
  const sortie = [];
  for (const s of await listerSegments(path.join(repertoire, "segments"))) {
    const { evenements } = lireSegmentFerme(new Uint8Array(await fs.readFile(s.chemin)));
    sortie.push(...evenements);
  }
  return sortie;
}

/**
 * `cles.json` d'un journal (CT-1 §11.2) : la clé initiale, valide depuis la
 * création du journal (`journal.json`), puis chaque clé introduite par une
 * rotation, validités fixées par CT-1 §8 règle 3.
 * @param {{org_id: string, journal_id: string, evenements: object[], creeLe: string,
 *   clePublique: (keyId: string) => Promise<string>}} p
 * @returns {Promise<object>}
 */
export async function clesDuJournal(p) {
  const cles = [];
  const premier = p.evenements[0];
  if (!premier) throw new Error("journal vide");
  let courante = { key_id: premier.recorder_key_id, algorithm: "ed25519", public_key: await p.clePublique(premier.recorder_key_id), valid_from: p.creeLe, valid_to: null };
  const source = "journal de l'enregistreur : journal.json et événements de rotation";
  for (const e of p.evenements) {
    if (e.execution.tool !== "noortrace.journal.rotation-cle") continue;
    const a = e.execution.arguments.value;
    courante.valid_to = e.ts;
    cles.push({ ...courante, source });
    courante = { key_id: a.new_key_id, algorithm: "ed25519", public_key: a.new_public_key, valid_from: e.ts, valid_to: null };
  }
  cles.push({ ...courante, source });
  return { version: 0, org_id: p.org_id, journal_id: p.journal_id, keys: cles };
}

/**
 * Lecture complète du journal pour l'assemblage d'un dossier (voie des essais
 * et de `Coeur.exporterDossier`) : l'événement, ses voisins, les événements
 * qu'emploie `cles.json` (le premier et ceux de rotation), les décisions du
 * ticket de son approbation et les hash de sa période close.
 * @param {string} repertoire
 * @param {number} seq
 */
async function lectureComplete(repertoire, seq) {
  const evenements = await lireEvenements(repertoire);
  const e = evenements.find((x) => x.seq === seq);
  if (!e) throw new Error(`événement ${seq} absent du journal`);
  const start = debutPeriode(decoderHorodatage(e.ts));
  const m = await lireManifeste(path.join(repertoire, "manifestes"), start);
  if (!m) throw new Error(`période ${start} non close : pas de manifeste`);
  const ticket = e.approval?.ticket ?? null;
  return {
    evenements,
    evenement: e,
    precedent: evenements.find((x) => x.seq === seq - 1) ?? null,
    suivant: evenements.find((x) => x.seq === seq + 1) ?? null,
    pourCles: evenements.filter((x, k) => k === 0 || x.execution.tool === "noortrace.journal.rotation-cle"),
    decisions: ticket === null ? [] : evenements.filter((x) => x.execution.tool === "noortrace.approbation.decision" && x.approval?.ticket === ticket),
    hashesPeriode: evenements.filter((x) => x.seq >= m.manifeste.first_seq && x.seq <= m.manifeste.last_seq).map((x) => x.hash),
    manifeste: m,
  };
}

/**
 * Assemble les sept parties de CT-1 d'un dossier (événement, voisins, chemin,
 * manifeste, signature, clés, approbations) et ce que l'exportateur du
 * composant d'ancrage attend en plus (hashes de la période, indice de feuille,
 * manifeste, série des points). `lecture` : ce que l'export du démon a déjà lu
 * du journal (export-dossier.mjs : l'événement, ses voisins, `pourCles`,
 * `decisions`, `hashesPeriode`, le manifeste lu) ; sans elle, le journal est
 * relu en entier.
 * @param {{repertoire: string, seq: number, clePublique: (keyId: string) => Promise<string>, jeuDecision: (decision: object) => object|null,
 *   lecture?: object}} p
 */
export async function assemblerBase(p) {
  const cheminJournal = path.join(p.repertoire, "journal.json");
  let journalJson;
  try {
    journalJson = JSON.parse(await fs.readFile(cheminJournal, "utf8"));
  } catch (e) {
    throw Object.assign(e, { path: e.path ?? cheminJournal });
  }
  const l = p.lecture ?? (await lectureComplete(p.repertoire, p.seq));
  const e = l.evenement;
  const start = debutPeriode(decoderHorodatage(e.ts));
  const m = l.manifeste ?? (await lireManifeste(path.join(p.repertoire, "manifestes"), start));
  if (!m) throw new Error(`période ${start} non close : pas de manifeste`);
  const hashes = l.hashesPeriode;
  const leaf = e.seq - m.manifeste.first_seq;
  const chemin = preuveInclusion(leaf, hashes);
  const cles = await clesDuJournal({ org_id: e.org_id, journal_id: e.journal_id, evenements: l.pourCles, creeLe: journalJson.created_at, clePublique: p.clePublique });

  const fichiers = new Map();
  const raisons = {};
  fichiers.set("evenement.json", octetsJsonLisible(e));
  fichiers.set("voisins.json", octetsJsonLisible({ version: 0, previous: l.precedent, next: l.suivant }));
  fichiers.set("chemin.json", octetsJsonLisible(chemin));
  fichiers.set("manifeste.json", m.octetsManifeste);
  fichiers.set("manifeste.sig", m.octetsSignature);
  fichiers.set("cles.json", octetsJsonLisible(cles));
  let approbations = null;
  if (e.approval) {
    const ticket = e.approval.ticket;
    const decisions = l.decisions;
    const jeu = decisions.length ? p.jeuDecision(decisions[decisions.length - 1]) : null;
    if (jeu) {
      approbations = { version: 0, ticket, request_hash: e.approval.request_hash, approver_set: jeu, events: decisions };
      fichiers.set("approbations.json", octetsJsonLisible(approbations));
    } else raisons.approbations = RAISON_JEU_INTROUVABLE;
  }
  const cheminSerie = path.join(p.repertoire, "points", nomSerie(start));
  const serie = await relireSerie(cheminSerie).catch((err) => {
    throw Object.assign(err, { path: err.path ?? cheminSerie });
  });
  return { evenement: e, evenements: l.evenements ?? null, hashes, leafIndex: leaf, manifeste: m.manifeste, signature: m.signature, cles, approbations, serie, periodStart: start, fichiers, raisons };
}

/** Raison d'absence de la partie `approbations` quand le jeu d'approbateurs de la décision est introuvable (EX-15.11). */
export const RAISON_JEU_INTROUVABLE = "jeu d'approbateurs introuvable";

/**
 * Dossier du cœur sans composant d'ancrage (aucun fichier écrit) : la
 * treizième partie porte le point couvrant sans ancre et les parties
 * réservées sont absentes (« hors périmètre CT-1 »).
 * @param {object} base rendu d'`assemblerBase`
 * @param {number} generated_at ms
 * @returns {{dossier: object, octetsIndex: Uint8Array, fichiers: Map<string, Uint8Array>, point: object|null, raisons: object}}
 */
export function construireDossierNoyau(base, generated_at) {
  const { fichiers, raisons, serie, leafIndex, hashes, evenement: e } = base;
  const point = choisirPoint(serie, leafIndex);
  if (point) {
    fichiers.set(
      "points-de-controle.json",
      octetsJsonLisible({
        version: 0,
        checkpoint: point,
        checkpoint_hash: hacherPoint(point),
        consistency: coherencePoint(point.tree_size, hashes),
        anchors: { rfc3161: null, registry: null, ots: null },
      }),
    );
  }
  const dossier = indexerDossier({
    event: { seq: e.seq, hash: e.hash },
    org_id: e.org_id,
    journal_id: e.journal_id,
    generated_at: ecrireHorodatage(generated_at),
    fichiers,
    points: true,
    raisons: Object.keys(raisons).length ? raisons : undefined,
  });
  // Un point sans ancre a le rang 4 de CT-1 §11.2 (EX-15.14, `checkpoint_rank`).
  return { dossier, octetsIndex: octetsJsonLisible(dossier), fichiers, point: point ? { rang: 4, tree_size: point.tree_size } : null, raisons };
}

/**
 * Exporte le dossier d'un événement à une destination quelconque, créée au
 * besoin (voie des essais et de `Coeur.exporterDossier`, hors de la commande
 * d'exploitation : celle-ci passe par export-dossier.mjs, EX-15.12 et
 * EX-15.13). Avec `exportateur` (branchement du composant d'ancrage,
 * `exporterDossier(base, { destination, generated_at })`), le dossier reçoit
 * ses ancres (CT-5 §10) ; sans lui, voir `construireDossierNoyau`.
 * @param {{repertoire: string, seq: number, destination: string, generated_at: number,
 *   clePublique: (keyId: string) => Promise<string>, jeuDecision: (decision: object) => object|null,
 *   exportateur?: {exporterDossier: Function}|null}} p
 * @returns {Promise<{dossier: object, octetsIndex: Uint8Array, fichiers: Map<string, Uint8Array>, point: object|null, raisons: object,
 *   resume?: object, entetes: boolean, defauts: number, composant: "ancrage"|"noyau"}>}
 */
export async function exporterDossier(p) {
  const base = await assemblerBase(p);
  if (p.exportateur) {
    const r = p.exportateur.exporterDossier(base, { destination: p.destination, generated_at: p.generated_at });
    return { dossier: r.dossier, octetsIndex: r.octetsIndex, fichiers: r.fichiers, point: r.point, raisons: r.raisons, resume: r.resume, entetes: Boolean(r.pieces?.entetes), defauts: r.defauts?.length ?? 0, composant: "ancrage" };
  }
  const r = construireDossierNoyau(base, p.generated_at);
  await fs.mkdir(p.destination, { recursive: true, mode: 0o700 });
  for (const [nom, octets] of r.fichiers) await fs.writeFile(path.join(p.destination, nom), octets);
  await fs.writeFile(path.join(p.destination, "dossier.json"), r.octetsIndex);
  return { ...r, entetes: false, defauts: 0, composant: "noyau" };
}
