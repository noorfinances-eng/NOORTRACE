// Vecteurs CT-6, dossiers des décisions de refus et d'expiration
// (spec/CT-6-verificateur.md, EX-6.8, fragment F3 ; annexe A.7).
//
//   import { dossiersDecisions } from "./ct6/decisions.mjs";
//   dossiersDecisions({ repertoireCT1 }) -> { "refuse": fichiers, "expire": fichiers }
//
// Les vecteurs de CT-1 ne portent qu'une approbation (decision = approuve). Ce
// module rejoue, à partir de leur journal publié, une variante où la décision
// liée au ticket apr-2201 est un refus signé, ou une demande expirée sans
// signature : les événements 1 à 5 du journal de CT-1 sont repris tels quels
// (mêmes octets, mêmes hachages), la décision (seq 6) et l'appel relayé
// (seq 7, refusé) sont réécrits et signés, puis la période 1 est close par un
// manifeste des sept événements. Le dossier prouve la décision (seq 6) : son
// voisin précédent est l'événement de demande (A-4 vérifiée). Les cinq parties
// réservées sont absentes, raison « hors périmètre CT-1 » : ces dossiers se
// vérifient sans ancres, et leur énoncé exerce F3.
//
// Tout est déterministe : clés de CT-1 (graines publiées), comptes Hardhat 1
// et 2 (signature EIP-191 de RFC 6979), nonce dérivé d'une étiquette publiée.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet } from "ethers";
import * as J from "../../lib/journal.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

const MNEMONIQUE_HARDHAT = "test test test test test test test test test test test junk";
const CHEMIN_HARDHAT = (i) => `m/44'/60'/0'/0/${i}`;
const ETIQUETTE_GRAINE = (id) => `noortrace/vecteurs/v0/cle-enregistreur/${id}`;
const ETIQUETTE_NONCE = (decision) => `noortrace/vecteurs/v0/ct-6/nonce/decision-${decision}`;
const GENERATED_AT_MANIFESTE = "2026-11-05T10:00:00.300Z";
const GENERATED_AT_DOSSIER = "2026-11-06T08:30:00.000Z";
const SOURCE_CLES = "vecteurs CT-6, décisions de refus et d'expiration (graines de CT-1, spec/vecteurs/ct-1/cles/cles-test.json)";
const SOURCE_APPROBATEURS = "comptes Hardhat 1 à 3 (vecteurs CT-1)";
const MOTIFS = { refuse: "Refus : bénéficiaire non vérifié", expire: null };

/** Les décisions couvertes et le nom de leur dossier. */
export const DECISIONS = { refuse: "valide-decision-refusee", expire: "valide-decision-expiree" };

const sansSceau = (e) => {
  const o = { ...e };
  for (const k of ["version", "seq", "org_id", "journal_id", "prev_hash", "hash", "sig"]) delete o[k];
  return o;
};

/**
 * Construit le journal variant pour `decision` (refuse ou expire) et rend les
 * fichiers du dossier de la décision (nom -> texte), dossier.json compris.
 */
export function dossierDecision(decision, { repertoireCT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1") } = {}) {
  if (!Object.hasOwn(DECISIONS, decision)) throw new Error(`décision ${decision} : refuse ou expire attendu`);
  const evenements = J.analyserJSONStrict(fs.readFileSync(path.join(repertoireCT1, "journal-valide", "evenements.json")));
  const manifesteCT1 = J.analyserJSONStrict(fs.readFileSync(path.join(repertoireCT1, "manifestes", "periode-1.json")));
  const k1 = "rec-test-01";
  const cle = J.cleEd25519DepuisGraine(J.sha256(Buffer.from(ETIQUETTE_GRAINE(k1), "utf8")));
  const premiers = evenements.filter((e) => e.seq <= 5);
  const demande = premiers.find((e) => e.seq === 5);
  if (demande.execution.status !== "retenue" || demande.recorder_key_id !== k1) throw new Error("journal de CT-1 : seq 5 n'est pas la demande retenue signée par rec-test-01");
  const decisionCT1 = evenements.find((e) => e.seq === 6);
  const appelCT1 = evenements.find((e) => e.seq === 7);

  // La décision : A signé par les approbateurs (aucun pour expire), puis l'événement.
  const A = { decision, journal_id: demande.journal_id, org_id: demande.org_id, request_hash: demande.hash, ticket: decisionCT1.approval.ticket };
  const signataires = decision === "expire" ? [] : [1, 2].map((i) => HDNodeWallet.fromPhrase(MNEMONIQUE_HARDHAT, undefined, CHEMIN_HARDHAT(i)));
  const approval = {
    ...decisionCT1.approval,
    decision,
    request_hash: demande.hash,
    approvers: signataires.map((w) => w.address.toLowerCase()),
    signatures: signataires.map((w) => J.signerApprobation(w, A)),
    reason: MOTIFS[decision],
  };
  const suivants = [
    { ...sansSceau(decisionCT1), approval, execution: { ...decisionCT1.execution, arguments: J.referenceEnLigne(A) } },
    {
      ...sansSceau(appelCT1),
      approval,
      execution: { ...appelCT1.execution, status: "refusee", result: null, duration_ms: null, is_error: null },
      effects: [],
    },
  ];
  const tous = [...premiers, ...J.chainer(suivants, { org_id: demande.org_id, journal_id: demande.journal_id, cles: { [k1]: cle.clePrivee }, premierSeq: 6, prevHash: demande.hash })];

  // Période 1 : les sept événements, close par rec-test-01 (aucune rotation dans ce journal).
  const hashes = tous.map((e) => e.hash);
  const manifeste = J.construireManifeste({
    org_id: demande.org_id,
    journal_id: demande.journal_id,
    period_start: manifesteCT1.period_start,
    first_seq: 1,
    hashes,
    prev_period_hash: J.HASH_NUL,
    recorder_key_id: k1,
    nonce: J.sha256(Buffer.from(ETIQUETTE_NONCE(decision), "utf8")),
    generated_at: GENERATED_AT_MANIFESTE,
  });
  const manifesteSig = J.signerManifeste(manifeste, cle.clePrivee);
  const clesCT1 = J.analyserJSONStrict(fs.readFileSync(path.join(repertoireCT1, "dossiers", "valide-seq-7", "cles.json")));
  const cle01 = clesCT1.keys.find((k) => k.key_id === k1);
  const cles = { version: 0, org_id: demande.org_id, journal_id: demande.journal_id, keys: [{ ...cle01, valid_to: null, source: SOURCE_CLES }] };
  const membres = [1, 2, 3].map((i) => HDNodeWallet.fromPhrase(MNEMONIQUE_HARDHAT, undefined, CHEMIN_HARDHAT(i)).address.toLowerCase());
  const ev = tous.find((e) => e.seq === 6);
  const { fichiers } = J.assemblerDossier({
    evenement: ev,
    previous: tous.find((e) => e.seq === 5),
    next: tous.find((e) => e.seq === 7),
    hashesPeriode: hashes,
    manifeste,
    manifesteSig,
    cles,
    approbations: { approver_set: { threshold: approval.threshold, members: membres, source: SOURCE_APPROBATEURS }, events: [ev] },
    generated_at: GENERATED_AT_DOSSIER,
  });
  return fichiers;
}

/** Les dossiers des deux décisions : nom du dossier -> fichiers. */
export function dossiersDecisions(options = {}) {
  return Object.fromEntries(Object.entries(DECISIONS).map(([decision, nom]) => [nom, dossierDecision(decision, options)]));
}
