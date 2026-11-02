// Export d'un dossier de preuve minimal (CT-1 §11) depuis le stockage du
// cœur (segments, manifestes, séries de points, fichiers des approbations).
// L'exportateur complet (ligne de commande de CT-6, pièces jointes, parties
// réservées de CT-4 et CT-5) est un lot suivant : ce module produit les
// douze parties v0, les cinq parties réservées absentes avec la raison
// « hors périmètre CT-1 », et la treizième partie `points-de-controle.json`
// sans ancre. Les fichiers sont écrits par `JSON.stringify(objet, null, 2)`
// suivi d'un saut de ligne (CT-1 §11.1) ; le manifeste et sa signature sont
// copiés octet pour octet depuis `manifestes/`.

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
 * Exporte le dossier d'un événement.
 * @param {{repertoire: string, seq: number, destination: string, generated_at: number,
 *   clePublique: (keyId: string) => Promise<string>, jeuDecision: (decision: object) => object|null}} p
 * @returns {Promise<{dossier: object, fichiers: Map<string, Uint8Array>}>}
 */
export async function exporterDossier(p) {
  const journalJson = JSON.parse(await fs.readFile(path.join(p.repertoire, "journal.json"), "utf8"));
  const evenements = await lireEvenements(p.repertoire);
  const e = evenements.find((x) => x.seq === p.seq);
  if (!e) throw new Error(`événement ${p.seq} absent du journal`);
  const precedent = evenements.find((x) => x.seq === p.seq - 1) ?? null;
  const suivant = evenements.find((x) => x.seq === p.seq + 1) ?? null;
  const start = debutPeriode(decoderHorodatage(e.ts));
  const m = await lireManifeste(path.join(p.repertoire, "manifestes"), start);
  if (!m) throw new Error(`période ${start} non close : pas de manifeste`);
  const hashes = evenements.filter((x) => x.seq >= m.manifeste.first_seq && x.seq <= m.manifeste.last_seq).map((x) => x.hash);
  const leaf = p.seq - m.manifeste.first_seq;
  const chemin = preuveInclusion(leaf, hashes);
  const cles = await clesDuJournal({ org_id: e.org_id, journal_id: e.journal_id, evenements, creeLe: journalJson.created_at, clePublique: p.clePublique });

  const fichiers = new Map();
  fichiers.set("evenement.json", octetsJsonLisible(e));
  fichiers.set("voisins.json", octetsJsonLisible({ version: 0, previous: precedent, next: suivant }));
  fichiers.set("chemin.json", octetsJsonLisible(chemin));
  fichiers.set("manifeste.json", m.octetsManifeste);
  fichiers.set("manifeste.sig", m.octetsSignature);
  fichiers.set("cles.json", octetsJsonLisible(cles));
  if (e.approval) {
    const ticket = e.approval.ticket;
    const decisions = evenements.filter((x) => x.execution.tool === "noortrace.approbation.decision" && x.approval?.ticket === ticket);
    const jeu = decisions.length ? p.jeuDecision(decisions[decisions.length - 1]) : null;
    if (jeu) {
      fichiers.set(
        "approbations.json",
        octetsJsonLisible({ version: 0, ticket, request_hash: e.approval.request_hash, approver_set: jeu, events: decisions }),
      );
    }
  }
  const serie = await relireSerie(path.join(p.repertoire, "points", nomSerie(start)));
  const point = choisirPoint(serie, leaf);
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
    generated_at: ecrireHorodatage(p.generated_at),
    fichiers,
    points: true,
    raisons: e.approval && !fichiers.has("approbations.json") ? { approbations: "jeu d'approbateurs introuvable" } : undefined,
  });
  await fs.mkdir(p.destination, { recursive: true, mode: 0o700 });
  for (const [nom, octets] of fichiers) await fs.writeFile(path.join(p.destination, nom), octets);
  await fs.writeFile(path.join(p.destination, "dossier.json"), octetsJsonLisible(dossier));
  return { dossier, fichiers };
}
