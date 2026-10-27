#!/usr/bin/env node
// Génère, de façon DÉTERMINISTE, les vecteurs de test de la spécification CT-1
// dans spec/vecteurs/ct-1/ : clés de test, cas limites de la forme canonique,
// journal fictif d'un assureur (douze événements), journaux altérés avec leur
// diagnostic, arbres de Merkle, manifestes de période, dossiers de preuve
// valides et invalides (au moins un par contrôle de CT-1 §11.4), séries de
// points de contrôle et preuves de cohérence (révision 0.3), dossiers qui
// portent la partie attestation-perimetre.json (révision 0.4, CT-7 annexe A.7),
// et l'index INDEX.md qui les décrit.
//
//   node scripts/vecteurs/generer-ct1.mjs [--sortie <répertoire>]
//
// Rejouer le générateur produit exactement les mêmes octets : aucune valeur
// aléatoire ni horloge n'intervient (graines, nonces et horodatages fixes ;
// Ed25519 et secp256k1 RFC 6979 sont déterministes). Le générateur vérifie
// lui-même chaque vecteur avec scripts/lib/journal.mjs avant d'écrire son
// attendu.json : une attente qui ne correspond pas au comportement de
// l'implémentation de référence arrête la génération.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, keccak256, toUtf8Bytes } from "ethers";
import * as J from "../lib/journal.mjs";
import * as S from "../lib/securite.mjs";
import * as A from "./ct7/attestation.mjs";
import { anchorFingerprint, parseArgs } from "../lib/noortrace.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const args = parseArgs(process.argv.slice(2));
const SORTIE = path.resolve(args.sortie ? String(args.sortie) : path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1"));

// ---------------------------------------------------------------------------
// Constantes des vecteurs (CT-1 §13) : tout est dérivé d'étiquettes documentées.
// ---------------------------------------------------------------------------

const ORG_SLUG = "assureur-demo";
const JOURNAL_NOM = "journal-sinistres";
const ORG_ID = keccak256(toUtf8Bytes(ORG_SLUG));
const JOURNAL_ID = keccak256(toUtf8Bytes(JOURNAL_NOM));

const ETIQUETTE_GRAINE = (id) => `noortrace/vecteurs/v0/cle-enregistreur/${id}`;
const ETIQUETTE_NONCE = (n) => `noortrace/vecteurs/v0/nonce/${JOURNAL_NOM}/periode-${n}`;
const ETIQUETTE_FEUILLE = (i) => `noortrace/vecteurs/v0/merkle/feuille/${i}`;
const graine = (id) => J.sha256(Buffer.from(ETIQUETTE_GRAINE(id), "utf8"));
const nonce = (n) => J.sha256(Buffer.from(ETIQUETTE_NONCE(n), "utf8"));

const CLES = {
  "rec-test-01": J.cleEd25519DepuisGraine(graine("rec-test-01")),
  "rec-test-02": J.cleEd25519DepuisGraine(graine("rec-test-02")),
};
// Une troisième paire, hors des journaux : elle ne sert qu'à forger un cles.json à identifiant en double.
const CLE_TIERCE = J.cleEd25519DepuisGraine(graine("rec-test-03"));
const CLES_PRIVEES = Object.fromEntries(Object.entries(CLES).map(([id, k]) => [id, k.clePrivee]));

const MNEMONIQUE_HARDHAT = "test test test test test test test test test test test junk";
const CHEMIN_HARDHAT = (i) => `m/44'/60'/0'/0/${i}`;
const HARDHAT = [1, 2, 3].map((i) => HDNodeWallet.fromPhrase(MNEMONIQUE_HARDHAT, undefined, CHEMIN_HARDHAT(i)));
const ADRESSES_HARDHAT = HARDHAT.map((w) => w.address.toLowerCase());
const ADRESSES_ATTENDUES = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"];
if (JSON.stringify(ADRESSES_HARDHAT) !== JSON.stringify(ADRESSES_ATTENDUES)) throw new Error("comptes Hardhat 1 à 3 : adresses inattendues");

const JOUR = [2026, 10, 5]; // 5 novembre 2026, UTC
const T = (h, m, s, ms) => J.horodatage(Date.UTC(JOUR[0], JOUR[1], JOUR[2], h, m, s, ms));
const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** Forme non canonique d'une signature EIP-191 (s dans la moitié haute, v complémenté) : même point, refusée par E-9. */
const formeHaute = (sig) => {
  const s = BigInt("0x" + sig.slice(66, 130));
  const v = sig.slice(130) === "1b" ? "1c" : "1b";
  return sig.slice(0, 66) + (N_SECP256K1 - s).toString(16).padStart(64, "0") + v;
};
const DEBUT_P1 = Date.UTC(JOUR[0], JOUR[1], JOUR[2], 9) / 1000;
const DEBUT_P2 = DEBUT_P1 + 3600;
const DEBUT_P3 = DEBUT_P2 + 3600;
const TS_ROTATION = T(9, 59, 58, 0);
const VALID_FROM_01 = "2026-11-01T00:00:00.000Z";
const GENERATED_AT_DOSSIER = "2026-11-06T08:30:00.000Z";
const SOURCE_CLES = "vecteurs CT-1 (graines documentées dans cles/cles-test.json)";
const SOURCE_APPROBATEURS = "comptes Hardhat 1 à 3 (vecteurs CT-1)";

// Les pièces (contenu fictif, octets UTF-8) et leurs références.
const PIECES = {
  prompt_systeme: "prompt systeme fictif v4 : agent sinistres",
  requete_1: '{"model":"fournisseur/modele@2026-09","messages":[{"role":"system","content":"[REDIGE:prompt-systeme]"},{"role":"user","content":"Instruis le sinistre 2026-81044."}]}',
  reponse_1: '{"content":[{"type":"text","text":"Instruire le sinistre 2026-81044 : vérifier le contrat, les pièces, puis régler"},{"type":"tool_use","name":"crm.claims.get","input":{"claim_id":"2026-81044"}}],"stop_reason":"tool_use"}',
  resultat_crm: '{"content":[{"type":"text","text":"Sinistre 2026-81044 : contrat AUTO-55-7781, assuré [REDIGE:nom], garage partenaire, statut ouvert"}],"isError":false}',
  resultat_ged: '{"content":[{"type":"text","text":"2 documents : constat du 2026-11-02 (DOC-31), facture du garage (DOC-32)"}],"isError":false}',
  constat: "piece 1 (contenu fictif) : constat amiable du 2026-11-02",
  facture: "piece 2 (contenu fictif) : facture du garage, 12500.00 CHF",
  requete_2: '{"model":"fournisseur/modele@2026-09","messages":[{"role":"system","content":"[REDIGE:prompt-systeme]"},{"role":"user","content":"Instruis le sinistre 2026-81044."},{"role":"assistant","content":"[contexte : constat DOC-31, facture DOC-32]"}]}',
  reponse_2: '{"content":[{"type":"text","text":"Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat"},{"type":"tool_use","name":"sap.payments.create","input":{"claim_id":"2026-81044","amount":"12500.00","currency":"CHF","beneficiary_iban":"CH5604835012345678009"}}],"stop_reason":"tool_use"}',
  arguments_paiement: '{"claim_id":"2026-81044","amount":"12500.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}',
  resultat_paiement: '{"content":[{"type":"text","text":"Paiement PAY-2026-61877 créé"}],"isError":false}',
  arguments_courriel: '{"to":"[REDIGE:courriel]","subject":"Sinistre 2026-81044 : règlement","body":"Votre sinistre est réglé (12500.00 CHF)."}',
  resultat_courriel: '{"content":[{"type":"text","text":"Message MSG-2026-00921 envoyé"}],"isError":false}',
  requete_3: '{"model":"fournisseur/modele@2026-09","messages":[{"role":"system","content":"[REDIGE:prompt-systeme]"},{"role":"user","content":"Clos le dossier 2026-81044."}]}',
  reponse_3: '{"content":[{"type":"text","text":"Clore le dossier 2026-81044 après un complément de 900.00 CHF"},{"type":"tool_use","name":"sap.payments.create","input":{"claim_id":"2026-81044","amount":"900.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}}],"stop_reason":"tool_use"}',
  arguments_complement: '{"claim_id":"2026-81044","amount":"900.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}',
  politique: "politique fictive de l'assureur, version 2026-11-05",
};
const ref = (nom, redacted = false) => J.reference(PIECES[nom], { redacted });
const REDACTION = "pii-v1";

// ---------------------------------------------------------------------------
// Le journal fictif : douze événements, deux périodes non vides, une vide.
// `variante` permet aux vecteurs invalides de rejouer le journal avec une
// altération à la source (chaîne et manifestes recalculés en conséquence) :
// ts (par seq), signatairesApprobation et approbateurs, contresignataireRotation,
// echangeSansReponse (seq 1 sans result, duration_ms, is_error),
// longueurReferenceDecision (écart ajouté à la length de la référence A),
// signatureNonCanonique (indice de la signature mise en forme haute),
// demandeRefusee (seq 5 refusé par la politique au lieu d'être retenu) ;
// révision 0.4 (journal rejoué de CT-7 §7.5) : politique12 (valeur en ligne
// { policy_version, policy_sha256 } de l'événement de politique seq 12) et
// politique13 ({ ts, policy_version, policy_sha256 } : un seq 13 de politique).
// ---------------------------------------------------------------------------

const DELEGATION = { launched_by: "u.martin@assureur-demo.example", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement,courriel", run_id: "run-2026-11-05-0007" };
const CODE = (model = "fournisseur/modele@2026-09", policy_version = "2026-11-01") => ({ model, prompt_version: ref("prompt_systeme").sha256, policy_version, recorder: "0.1.0" });
const CODE_JOURNAL = (policy_version = "2026-11-01") => ({ model: null, prompt_version: null, policy_version, recorder: "0.1.0" });
const POLICY = (decision, { rule = null, ticket = null, redaction = null } = {}) => ({ rule, decision, ticket, redaction });
const EXEC = (tool, { args, status = "executee", result = null, duration_ms = null, is_error = null }) => ({ tool, arguments: args, status, result, duration_ms, is_error });
const DOC = (nom) => ({ ...J.reference(PIECES[nom]), kind: "document" });
const EFFET = (system, action, object, amount = null, currency = null) => ({ system, action, object, amount, currency });

function construireJournal(variante = {}) {
  const ts = (seq, defaut) => variante.ts?.[seq] ?? defaut;
  const signataires = variante.signatairesApprobation ?? [HARDHAT[0], HARDHAT[1]];
  const approbateurs = variante.approbateurs ?? [ADRESSES_HARDHAT[0], ADRESSES_HARDHAT[1]];
  const commun = { org_id: ORG_ID, journal_id: JOURNAL_ID, cles: CLES_PRIVEES };
  const k1 = "rec-test-01";
  const k2 = "rec-test-02";

  const premiers = [
    {
      ts: ts(1, T(9, 12, 3, 417)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Instruire le sinistre 2026-81044 : vérifier le contrat, les pièces, puis régler",
      policy: POLICY("sans_objet", { redaction: REDACTION }), approval: null,
      execution: variante.echangeSansReponse ? EXEC(J.OUTIL_MODELE, { args: ref("requete_1", true) }) : EXEC(J.OUTIL_MODELE, { args: ref("requete_1", true), result: ref("reponse_1"), duration_ms: 2210, is_error: false }),
      effects: [], context: [],
    },
    {
      ts: ts(2, T(9, 12, 4, 102)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Lire le dossier du sinistre 2026-81044",
      policy: POLICY("autorise", { rule: "outil crm.claims.get : lecture autorisee" }), approval: null,
      execution: EXEC("crm.claims.get", { args: J.referenceEnLigne({ claim_id: "2026-81044" }), result: ref("resultat_crm"), duration_ms: 184, is_error: false }),
      effects: [EFFET("CRM", "lecture", "CLM-2026-81044")], context: [],
    },
    {
      ts: ts(3, T(9, 12, 5, 880)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Rechercher le constat et la facture du sinistre 2026-81044",
      policy: POLICY("autorise", { rule: "outil documents.search : lecture autorisee" }), approval: null,
      execution: EXEC("documents.search", { args: J.referenceEnLigne({ query: "sinistre 2026-81044 constat facture" }), result: ref("resultat_ged"), duration_ms: 341, is_error: false }),
      effects: [EFFET("GED", "lecture", "DOC-31"), EFFET("GED", "lecture", "DOC-32")], context: [DOC("constat"), DOC("facture")],
    },
    {
      ts: ts(4, T(9, 12, 9, 311)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat",
      policy: POLICY("sans_objet", { redaction: REDACTION }), approval: null,
      execution: EXEC(J.OUTIL_MODELE, { args: ref("requete_2", true), result: ref("reponse_2"), duration_ms: 1975, is_error: false }),
      effects: [], context: [DOC("constat"), DOC("facture")],
    },
    {
      ts: ts(5, T(9, 12, 9, 904)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat",
      policy: variante.demandeRefusee ? POLICY("refuse", { rule: "paiement > 5000 CHF", redaction: REDACTION }) : POLICY("a_approuver", { rule: "paiement > 5000 CHF", ticket: "apr-2201", redaction: REDACTION }),
      approval: null,
      execution: EXEC("sap.payments.create", { args: ref("arguments_paiement", true), status: variante.demandeRefusee ? "refusee" : "retenue" }),
      effects: [], context: [DOC("constat"), DOC("facture")],
    },
  ];
  const evenements = J.chainer(premiers, commun);
  const demande = evenements[4];

  // La décision d'approbation : A signé par les approbateurs, puis l'événement.
  const A = { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: demande.hash, ticket: "apr-2201" };
  const approval = {
    decision: "approuve",
    ticket: "apr-2201",
    request_hash: demande.hash,
    threshold: { required: 2, size: 3 },
    approvers: approbateurs,
    signatures: signataires.map((w, i) => (i === variante.signatureNonCanonique ? formeHaute(J.signerApprobation(w, A)) : J.signerApprobation(w, A))),
    at: T(9, 31, 47, 250), // instant où le seuil est atteint : fixe, distinct du ts de l'enregistrement de la décision (variante ts)
    reason: "Constat et facture concordants",
  };
  const annonce = J.annonceRotation({
    org_id: ORG_ID, journal_id: JOURNAL_ID, old_key_id: k1, new_key_id: k2, new_public_key: CLES[k2].clePublique,
    valid_from: ts(9, TS_ROTATION), cleNouvelle: variante.contresignataireRotation ?? CLES[k2].clePrivee,
  });
  const suivants = [
    {
      ts: ts(6, T(9, 31, 47, 250)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(), intent: null,
      policy: POLICY("sans_objet", { ticket: "apr-2201" }), approval,
      execution: EXEC(J.OUTIL_APPROBATION, { args: { ...J.referenceEnLigne(A), length: J.referenceEnLigne(A).length + (variante.longueurReferenceDecision ?? 0) } }), effects: [], context: [],
    },
    {
      ts: ts(7, T(9, 31, 48, 6)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Régler le sinistre 2026-81044 : 12500.00 CHF au bénéficiaire du contrat",
      policy: POLICY("a_approuver", { rule: "paiement > 5000 CHF", ticket: "apr-2201", redaction: REDACTION }), approval,
      execution: EXEC("sap.payments.create", { args: ref("arguments_paiement", true), result: ref("resultat_paiement"), duration_ms: 530, is_error: false }),
      effects: [EFFET("SAP", "ecriture", "PAY-2026-61877", "12500.00", "CHF")], context: [DOC("constat"), DOC("facture")],
    },
    {
      ts: ts(8, T(9, 31, 49, 120)), recorder_key_id: k1, delegation: DELEGATION, code: CODE(),
      intent: "Informer l'assuré du règlement",
      policy: POLICY("autorise", { rule: "outil mail.send : envoi autorise vers l'assure", redaction: REDACTION }), approval: null,
      execution: EXEC("mail.send", { args: ref("arguments_courriel", true), result: ref("resultat_courriel"), duration_ms: 902, is_error: false }),
      effects: [EFFET("Messagerie", "envoi", "MSG-2026-00921")], context: [],
    },
    {
      ts: ts(9, TS_ROTATION), recorder_key_id: k1,
      delegation: { launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null },
      code: CODE_JOURNAL(), intent: null, policy: POLICY("sans_objet"), approval: null,
      execution: EXEC(J.OUTIL_ROTATION, { args: J.referenceEnLigne(annonce) }),
      effects: [EFFET("noortrace", "ecriture", `cle:${k2}`)], context: [],
    },
    {
      ts: ts(10, T(10, 4, 12, 555)), recorder_key_id: k2, delegation: DELEGATION, code: CODE(),
      intent: "Clore le dossier 2026-81044 après un complément de 900.00 CHF",
      policy: POLICY("sans_objet", { redaction: REDACTION }), approval: null,
      execution: EXEC(J.OUTIL_MODELE, { args: ref("requete_3", true), result: ref("reponse_3"), duration_ms: 1640, is_error: false }),
      effects: [], context: [],
    },
    {
      ts: ts(11, T(10, 4, 13, 40)), recorder_key_id: k2, delegation: DELEGATION, code: CODE(),
      intent: "Verser un complément de 900.00 CHF",
      policy: POLICY("refuse", { rule: "beneficiaire hors liste blanche", redaction: REDACTION }), approval: null,
      execution: EXEC("sap.payments.create", { args: ref("arguments_complement", true), status: "refusee" }),
      effects: [], context: [],
    },
    {
      ts: ts(12, T(10, 5, 0, 0)), recorder_key_id: k2,
      delegation: { launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null },
      code: CODE_JOURNAL("2026-11-05"), intent: null, policy: POLICY("sans_objet"), approval: null,
      execution: EXEC(J.OUTIL_POLITIQUE, { args: J.referenceEnLigne(variante.politique12 ?? { policy_version: "2026-11-05", policy_sha256: J.sha256(Buffer.from(PIECES.politique, "utf8")) }) }),
      effects: [], context: [],
    },
  ];
  if (variante.politique13) {
    const { ts: ts13, policy_version, policy_sha256 } = variante.politique13;
    suivants.push({
      ts: ts13, recorder_key_id: k2,
      delegation: { launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null },
      code: CODE_JOURNAL(policy_version), intent: null, policy: POLICY("sans_objet"), approval: null,
      execution: EXEC(J.OUTIL_POLITIQUE, { args: J.referenceEnLigne({ policy_version, policy_sha256 }) }),
      effects: [], context: [],
    });
  }
  evenements.push(...J.chainer(suivants, { ...commun, premierSeq: 6, prevHash: demande.hash }));

  // Manifestes des trois périodes, signés par la clé en vigueur à la clôture (rec-test-02 dès la rotation).
  const periodes = [];
  let prev = J.HASH_NUL;
  let first_seq = 1;
  [[DEBUT_P1, "2026-11-05T10:00:00.300Z"], [DEBUT_P2, "2026-11-05T11:00:00.212Z"], [DEBUT_P3, "2026-11-05T12:00:00.105Z"]].forEach(([period_start, generated_at], i) => {
    const events = J.evenementsDePeriode(evenements, period_start);
    const hashes = events.map((e) => e.hash);
    const manifeste = J.construireManifeste({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start, first_seq, hashes, prev_period_hash: prev, recorder_key_id: k2, nonce: nonce(i + 1), generated_at });
    const sig = J.signerManifeste(manifeste, CLES[k2].clePrivee);
    periodes.push({ numero: i + 1, period_start, events, hashes, manifeste, sig });
    prev = sig.period_hash;
    first_seq = manifeste.last_seq + 1;
  });

  const cles = {
    version: 0,
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    keys: [
      { key_id: k1, algorithm: "ed25519", public_key: CLES[k1].clePublique, valid_from: VALID_FROM_01, valid_to: ts(9, TS_ROTATION), source: SOURCE_CLES },
      { key_id: k2, algorithm: "ed25519", public_key: CLES[k2].clePublique, valid_from: ts(9, TS_ROTATION), valid_to: null, source: SOURCE_CLES },
    ],
  };
  return { evenements, periodes, cles, A };
}

/**
 * Le dossier de l'événement `seq` d'un journal construit ; `point` (facultatif) :
 * un point signé qui le couvre, pour la treizième partie (CT-1 révision 0.3) ;
 * `attestation` (facultatif) : la quatorzième partie (révision 0.4), objet ou texte.
 */
function dossierPour(jeu, seq, { point = null, anchors = {}, raisons = {}, attestation = null } = {}) {
  const ev = jeu.evenements.find((e) => e.seq === seq);
  const periode = jeu.periodes.find((p) => p.manifeste.first_seq <= seq && seq <= p.manifeste.last_seq);
  const approbations =
    ev.approval === null
      ? null
      : {
          approver_set: { threshold: ev.approval.threshold, members: ADRESSES_HARDHAT, source: SOURCE_APPROBATEURS },
          events: jeu.evenements.filter((e) => e.execution.tool === J.OUTIL_APPROBATION && e.approval?.ticket === ev.approval.ticket),
        };
  return J.assemblerDossier({
    evenement: ev,
    previous: jeu.evenements.find((e) => e.seq === seq - 1) ?? null,
    next: jeu.evenements.find((e) => e.seq === seq + 1) ?? null,
    hashesPeriode: periode.hashes,
    manifeste: periode.manifeste,
    manifesteSig: periode.sig,
    cles: jeu.cles,
    approbations,
    pointsDeControle: point ? J.construirePartiePointsDeControle({ point, feuillesPeriode: periode.hashes, anchors }) : null,
    attestationPerimetre: attestation,
    generated_at: GENERATED_AT_DOSSIER,
    raisons,
  });
}

// ---------------------------------------------------------------------------
// Écriture
// ---------------------------------------------------------------------------

const ecrits = [];
function ecrire(relatif, contenu) {
  const fichier = path.join(SORTIE, relatif);
  fs.mkdirSync(path.dirname(fichier), { recursive: true });
  fs.writeFileSync(fichier, contenu);
  ecrits.push(relatif);
}
const ecrireJSON = (relatif, valeur) => ecrire(relatif, J.texteJSON(valeur));

const SCHEMAS = J.registreSchemas(["evenement", "manifeste", "dossier", "point-de-controle", "attestation-perimetre"].map((n) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", `${n}-v0.schema.json`), "utf8"))));

function exiger(condition, message) {
  if (!condition) throw new Error(`génération interrompue : ${message}`);
}

// Le générateur ne possède que ses propres entrées : il les efface avant de les
// réécrire (aucun fichier périmé ne survit) et laisse intact tout ce que
// d'autres déposent dans le répertoire des vecteurs (par exemple un
// vérificateur indépendant).
export const ENTREES_GENEREES = ["INDEX.md", "cles", "jcs", "journal-valide", "journal-supprime", "journal-modifie", "journal-insere", "journal-insere-sans-cle", "journal-reordonne", "merkle", "manifestes", "points-de-controle", "dossiers"];
for (const entree of ENTREES_GENEREES) fs.rmSync(path.join(SORTIE, entree), { recursive: true, force: true });
fs.mkdirSync(SORTIE, { recursive: true });

// 1. Clés de test ------------------------------------------------------------
const jeu = construireJournal();
ecrireJSON("cles/cles-test.json", {
  version: 0,
  description: "Clés de test des vecteurs CT-1. Jetables et publiques : elles ne doivent jamais porter de valeur. Graine Ed25519 = SHA-256(UTF-8(étiquette)) ; clé publique RFC 8032 §5.1.5 ; en PKCS#8 DER, la clé privée est le préfixe 302e020100300506032b657004220420 suivi de la graine.",
  org: { slug: ORG_SLUG, org_id: ORG_ID, derivation: "keccak256(UTF-8(slug))" },
  journal: { nom: JOURNAL_NOM, journal_id: JOURNAL_ID, derivation: "keccak256(UTF-8(nom))" },
  keys: Object.entries(CLES).map(([key_id, k]) => ({
    key_id,
    algorithm: "ed25519",
    seed_label: ETIQUETTE_GRAINE(key_id),
    seed: k.graine,
    private_key_pkcs8_der: "0x302e020100300506032b657004220420" + k.graine.slice(2),
    public_key: k.clePublique,
    valid_from: jeu.cles.keys.find((c) => c.key_id === key_id).valid_from,
    valid_to: jeu.cles.keys.find((c) => c.key_id === key_id).valid_to,
  })),
  approbateurs: {
    mnemonique: MNEMONIQUE_HARDHAT,
    chemin: "m/44'/60'/0'/0/<i>",
    seuil: { required: 2, size: 3 },
    comptes: HARDHAT.map((w, i) => ({ compte: i + 1, chemin: CHEMIN_HARDHAT(i + 1), adresse: w.address.toLowerCase(), cle_privee: w.privateKey })),
  },
  nonces: [1, 2, 3].map((n) => ({ periode: n, etiquette: ETIQUETTE_NONCE(n), nonce: nonce(n) })),
});
ecrireJSON("cles/cles.json", jeu.cles);
const erreursCles = J.validerSchema(jeu.cles, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/cles" });
exiger(erreursCles.length === 0, `cles.json non conforme : ${JSON.stringify(erreursCles)}`);

// 2. Journal valide ------------------------------------------------------------
const clesPubliques = jeu.cles;
{
  const chaine = J.verifierChaine(jeu.evenements, { clesPubliques });
  exiger(chaine.valide, `journal valide refusé : ${JSON.stringify(chaine.diagnostics)}`);
  for (const ev of jeu.evenements) {
    const res = J.controlesEvenement(ev, { schemas: SCHEMAS, cles: clesPubliques });
    const echecs = Object.entries(res).filter(([, x]) => x.ok === false);
    exiger(echecs.length === 0, `événement seq ${ev.seq} : ${JSON.stringify(echecs)}`);
  }
  ecrireJSON("journal-valide/evenements.json", jeu.evenements);
  ecrireJSON("journal-valide/cles.json", jeu.cles);
  ecrireJSON("journal-valide/attendu.json", {
    valide: true,
    diagnostics: [],
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    first_seq: 1,
    last_seq: jeu.evenements.length,
    hashes: jeu.evenements.map((e) => ({ seq: e.seq, tool: e.execution.tool, recorder_key_id: e.recorder_key_id, prev_hash: e.prev_hash, hash: e.hash, sig: e.sig, canonical_length: J.octetsJCS(J.corpsEvenement(e)).length })),
    approbation: { ticket: "apr-2201", A: jeu.A, D_A: J.condenseApprobation(jeu.A), approvers: ADRESSES_HARDHAT.slice(0, 2) },
  });
  ecrireJSON("journal-valide/pieces.json", {
    description: "Les pièces référencées par les événements : octets UTF-8 du texte (sans saut de ligne final), sha256 et length tels qu'ils figurent dans les références. Les pièces rédigées (pii-v1) sont données telles que stockées, après rédaction.",
    pieces: Object.entries(PIECES).map(([nom, texte]) => ({ nom, texte, ...J.reference(texte) })).map(({ redacted, ...p }) => p),
  });
}

// 3. Journaux altérés ------------------------------------------------------------
// Les contrôles en échec d'un journal altéré, dans l'ordre de la table 11.4 (table 7.2 : tous les symptômes sont rapportés).
const controlesDesDiagnostics = (diagnostics) => J.CONTROLES_DOSSIER.map((c) => c.id).filter((id) => diagnostics.some((d) => d.controle === id));
function vecteurChaine(nom, evenements, attendus, controles, description) {
  const r = J.verifierChaine(evenements, { clesPubliques });
  const obtenus = r.diagnostics.map(({ type, controle, seq }) => ({ type, controle, seq }));
  exiger(!r.valide && JSON.stringify(obtenus) === JSON.stringify(attendus), `${nom} : diagnostics ${JSON.stringify(obtenus)} différents des attendus ${JSON.stringify(attendus)}`);
  exiger(JSON.stringify(controlesDesDiagnostics(obtenus)) === JSON.stringify(controles), `${nom} : contrôles ${JSON.stringify(controlesDesDiagnostics(obtenus))} différents des attendus ${JSON.stringify(controles)}`);
  ecrireJSON(`${nom}/evenements.json`, evenements);
  ecrireJSON(`${nom}/attendu.json`, { valide: false, description, controles_en_echec: controles, diagnostics: obtenus, messages: r.diagnostics.map((d) => d.message) });
}
{
  const E = jeu.evenements;
  vecteurChaine("journal-supprime", E.filter((e) => e.seq !== 4), [{ type: "suppression", controle: "C-1", seq: 5 }, { type: "rupture", controle: "C-2", seq: 5 }], ["C-1", "C-2"], "L'événement seq 4 a été retiré du journal : trou entre seq 3 et seq 5 (C-1), et prev_hash de seq 5 différent du hash de seq 3 qui le précède dans le fichier (C-2).");

  const modifie = E.map((e) => (e.seq === 7 ? { ...e, intent: "Régler le sinistre 2026-81044 : 1250.00 CHF au bénéficiaire du contrat" } : e));
  vecteurChaine("journal-modifie", modifie, [{ type: "modification", controle: "E-7", seq: 7 }, { type: "signature", controle: "E-8", seq: 7 }, { type: "rupture", controle: "C-2", seq: 8 }], ["E-7", "E-8", "C-2"], "Le champ intent de seq 7 a été modifié après scellement (12500.00 devient 1250.00), hash et sig inchangés : le hash recalculé diffère (E-7), la signature ne couvre plus le contenu (E-8) et prev_hash de seq 8 ne correspond plus au hash recalculé de seq 7 (C-2).");

  const forge = { ...E[4], ts: T(9, 12, 9, 950), intent: "Lire le solde du compte technique", policy: POLICY("autorise", { rule: "outil crm.accounts.get : lecture autorisee" }), execution: EXEC("crm.accounts.get", { args: J.referenceEnLigne({ account: "TECH-01" }), result: ref("resultat_crm"), duration_ms: 90, is_error: false }), effects: [EFFET("CRM", "lecture", "TECH-01")], context: [] };
  const [insere] = J.chainer([forge], { org_id: ORG_ID, journal_id: JOURNAL_ID, cles: CLES_PRIVEES, premierSeq: 5, prevHash: E[3].hash });
  vecteurChaine("journal-insere", [...E.slice(0, 4), insere, ...E.slice(4)], [{ type: "insertion", controle: "C-1", seq: 5 }, { type: "rupture", controle: "C-2", seq: 5 }, { type: "horodatage", controle: "C-1", seq: 5 }], ["C-1", "C-2"], "Un événement forgé (signé avec la clé de l'enregistreur, chaîné à seq 4) a été inséré entre seq 4 et seq 5 : seq 5 est en double (C-1), le vrai seq 5 n'est plus chaîné à l'événement qui le précède dans le fichier (C-2) et son ts est antérieur (C-1). L'attaquant détient la clé : E-8 passe.");

  // Même insertion par un attaquant qui n'a pas la clé de l'enregistreur : l'événement forgé annonce rec-test-01 mais est signé par une autre clé.
  const [insereSansCle] = J.chainer([forge], { org_id: ORG_ID, journal_id: JOURNAL_ID, cles: { "rec-test-01": CLES["rec-test-02"].clePrivee }, premierSeq: 5, prevHash: E[3].hash });
  vecteurChaine("journal-insere-sans-cle", [...E.slice(0, 4), insereSansCle, ...E.slice(4)], [{ type: "signature", controle: "E-8", seq: 5 }, { type: "insertion", controle: "C-1", seq: 5 }, { type: "rupture", controle: "C-2", seq: 5 }, { type: "horodatage", controle: "C-1", seq: 5 }], ["E-8", "C-1", "C-2"], "Même insertion, mais l'attaquant n'a pas la clé de l'enregistreur : l'événement forgé annonce rec-test-01 et porte une signature produite par une autre clé (E-8), en plus des symptômes de chaîne (C-1, C-2).");

  const reordonne = [...E.slice(0, 4), E[5], E[4], ...E.slice(6)];
  vecteurChaine("journal-reordonne", reordonne, [{ type: "reordonnancement", controle: "C-1", seq: 5 }, { type: "rupture", controle: "C-2", seq: 6 }, { type: "rupture", controle: "C-2", seq: 5 }, { type: "horodatage", controle: "C-1", seq: 5 }, { type: "rupture", controle: "C-2", seq: 7 }], ["C-1", "C-2"], "Les événements seq 5 et seq 6 ont été échangés de place dans le fichier (contenus intacts) : l'ordre des seq n'est plus croissant (C-1) et aucun des trois liens autour d'eux ne tient (C-2).");
}

// 3 bis. Cas limites de la forme canonique (CT-1 §4) ------------------------------
{
  const cas = [
    ["tri des clés", '{"b":1,"a":2}'],
    ["unités UTF-16 : Z < z < é", '{"é":1,"z":2,"Z":3}'],
    ["clé décodée avant le tri, écrite en clair", '{"\\u00e9":1}'],
    ["paire de substituts : un caractère, quatre octets UTF-8", '{"a\\ud83d\\ude00":1}'],
    ["caractère de contrôle échappé en minuscules", '{"a":"x\\u0001y"}'],
    ["U+007F en clair", '{"a":"\\u007f"}'],
    ["barre oblique en clair", '{"a":"/"}'],
    ["U+2028 et U+2029 en clair", '{"a":"\\u2028\\u2029"}'],
    ["échappements courts", '{"a":"\\b\\t\\n\\f\\r\\"\\\\"}'],
    ["entiers de l'intervalle sûr", '[9007199254740991,-9007199254740991,0]'],
    ["zéro négatif", '{"a":-0}'],
    ["conteneurs vides", '{"a":[],"b":{}}'],
    ["aucune normalisation Unicode : é précomposé et e + U+0301 diffèrent", '{"a":"\\u00e9","b":"e\\u0301"}'],
    ["exemple de structure de la RFC 8785 §3.2.3", '{"1":{"f":{"f":"hi","F":5},"\\n":56},"10":{},"":"empty","a":{},"111":[{"e":"yes","E":"no"}],"A":{}}'],
    ["non entier (forme fractionnaire d'une valeur entière)", '{"a":1.0}'],
    ["exposant", '{"a":1e3}'],
    ["hors de l'intervalle sûr", '{"a":9007199254740993}'],
    ["substitut isolé", '{"a":"\\ud800"}'],
    ["clé en double", '{"a":1,"a":2}'],
    ["clé en double après décodage", '{"a":1,"\\u0061":2}'],
  ];
  const liste = cas.map(([name, input]) => {
    let canonical = null;
    try {
      canonical = J.canonicaliserJCS(J.analyserJSONStrict(input));
    } catch (err) {
      exiger(err instanceof J.ErreurFormat, `${name} : erreur inattendue ${err.message}`);
    }
    return { name, input, canonical };
  });
  exiger(liste.filter((c) => c.canonical === null).length === 6, "six cas invalides attendus");
  exiger(liste[0].canonical === '{"a":2,"b":1}' && liste[1].canonical === '{"Z":3,"z":2,"é":1}' && liste[10].canonical === '{"a":0}', "cas limites de §4 non reproduits");
  ecrireJSON("jcs/cas-limites.json", {
    version: 0,
    description: "Cas limites de la forme canonique JCS v0 (CT-1 §4). input : un texte JSON ; canonical : sa forme canonique (chaîne, à encoder en UTF-8 pour hacher), ou null si le document est invalide (nombre non entier ou hors de l'intervalle sûr, substitut isolé, clé en double : contrôle E-2).",
    cas: liste,
  });
}

// 4. Arbres de Merkle ------------------------------------------------------------
{
  const hashes = jeu.evenements.map((e) => e.hash);
  const feuilles1000 = Array.from({ length: 1000 }, (_, i) => J.sha256(Buffer.from(ETIQUETTE_FEUILLE(i), "utf8")));
  const arbre = (n, leaves, indices, description) => {
    const root = J.racineMerkle(leaves);
    const proofs = indices.map((m) => {
      const p = J.preuveInclusion(leaves, m);
      exiger(J.verifierInclusion(p), `preuve ${m}/${n} refusée`);
      exiger(p.root === root, "racine de la preuve différente");
      return p;
    });
    return { n, description, leaves, root, proofs };
  };
  ecrireJSON("merkle/arbres.json", {
    version: 0,
    description: "Arbres RFC 6962 (feuille = SHA-256(0x00 || D[i]), nœud = SHA-256(0x01 || g || d), découpage à la plus grande puissance de deux strictement inférieure à n). Les feuilles de n = 1, 2, 3, 5, 8 et 12 sont les hash des événements de journal-valide ; celles de n = 1000 valent SHA-256(UTF-8(\"noortrace/vecteurs/v0/merkle/feuille/<i>\")). Chaque preuve est le contenu d'un chemin.json (RFC 6962 §2.1.1), vérifiable par l'algorithme de CT-1 §9.3.",
    periode_vide: { n: 0, root: J.HASH_NUL, remarque: "Convention NOORTRACE imposée par PeriodRegistry (root == bytes32(0) quand lastSeq + 1 == firstSeq), et non MTH({}) = SHA-256(\"\") = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 de la RFC 6962." },
    arbres: [
      arbre(0, [], [], "période vide : racine nulle, aucune preuve possible"),
      arbre(1, hashes.slice(0, 1), [0], "une feuille : racine = L(0), chemin vide"),
      arbre(2, hashes.slice(0, 2), [0, 1], "deux feuilles"),
      arbre(3, hashes.slice(0, 3), [0, 1, 2], "trois feuilles : k = 2, la troisième est seule à droite"),
      arbre(5, hashes.slice(0, 5), [0, 1, 2, 3, 4], "cinq feuilles : k = 4, la cinquième est seule à droite (forme de l'exemple de CT-1 §9.4)"),
      arbre(8, hashes.slice(0, 8), [0, 3, 7], "huit feuilles : arbre complet, chemins de longueur 3"),
      arbre(12, hashes, [0, 5, 11], "les douze événements de journal-valide"),
      arbre(1000, feuilles1000, [0, 1, 499, 500, 998, 999], "mille feuilles synthétiques"),
    ],
  });

  // 4 bis. Preuves de cohérence (CT-1 §10.7, révision 0.3) entre les arbres publiés ci-dessus.
  const coherence = (m, n, description) => {
    const cas = { name: `(${m}, ${n})`, description, first_size: m, second_size: n, first_root: J.racineMerkle(hashes.slice(0, m)), second_root: J.racineMerkle(hashes.slice(0, n)), path: J.preuveCoherence(hashes.slice(0, n), m), valid: true, reason: null };
    exiger(J.verifierCoherence(cas), `preuve de cohérence ${cas.name} refusée`);
    return cas;
  };
  const refuse = (name, description, modif, reason) => {
    const base = coherence(3, 5, "");
    const cas = { ...base, ...modif, name, description, valid: false, reason };
    exiger(!J.verifierCoherence(cas), `cas refusé ${name} accepté`);
    return cas;
  };
  const acceptes = [
    coherence(1, 2, "une feuille vers deux : k = 1, la preuve est L(1)"),
    coherence(2, 3, "deux feuilles vers trois : m = k = 2, préfixe entier, la preuve est L(2)"),
    coherence(3, 5, "trois feuilles vers cinq : m > k = 2, descente à droite avec racine à fournir (quatre nœuds)"),
    coherence(5, 8, "PROOF(5, D[8]) : m > k = 4, quatre nœuds"),
    coherence(8, 12, "PROOF(8, D[12]) : m = k = 8, un seul nœud (racine des feuilles 8 à 11)"),
    coherence(4, 8, "m = 4 puissance de deux vers un arbre complet : un nœud, first_root préposé à la vérification"),
    coherence(4, 12, "m = 4 puissance de deux vers douze feuilles : deux nœuds"),
    coherence(1, 12, "une feuille vers douze : quatre nœuds, le maximum pour n = 12 (⌈log2 12⌉ = 4, sans préposition de L(0) puisque m = 1 est une puissance de deux)"),
    coherence(12, 12, "m = n : preuve vide, racines égales"),
  ];
  const refuses = [
    refuse("(0, 5)", "m = 0 n'est pas défini : rejet avant tout calcul", { first_size: 0, first_root: J.HASH_NUL, path: [] }, "m = 0"),
    refuse("(5, 3)", "m > n : rejet avant tout calcul (racines et chemin de (3, 5), tailles échangées)", { first_size: 5, second_size: 3 }, "n < m"),
    refuse("(3, 5) chemin tronqué", "dernier nœud de PROOF(3, D[5]) retiré : sn ne retombe pas à 0", { path: acceptes[2].path.slice(0, -1) }, "chemin trop court"),
    refuse("(3, 5) nœud en trop", "un nœud ajouté à la fin de PROOF(3, D[5]) : sn vaut déjà 0", { path: [...acceptes[2].path, acceptes[2].path[0]] }, "chemin trop long"),
    refuse("(3, 5) racines échangées", "first_root et second_root permutés", { first_root: acceptes[2].second_root, second_root: acceptes[2].first_root }, "racines échangées"),
    refuse("(3, 5) chemin vide", "chemin vide alors que m < n", { path: [] }, "chemin vide"),
    refuse("(3, 3) chemin non vide", "m = n avec un chemin non vide : la preuve de m = n est vide", { first_size: 3, second_size: 3, second_root: acceptes[2].first_root }, "m = n avec chemin"),
  ];
  ecrireJSON("merkle/coherence.json", {
    version: 0,
    description: "Preuves de cohérence RFC 9162 §2.1.4 (CT-1 §10.7, révision 0.3) entre les arbres de arbres.json (feuilles : hash des événements de journal-valide). Chaque cas donne first_size, second_size, first_root, second_root, path ; valid dit si l'algorithme de vérification de CT-1 §10.7 doit accepter, reason nomme le refus. Les preuves acceptées sont PROOF(first_size, D[0..second_size-1]) recalculées nœud pour nœud ; les refusées sont des sondes dérivées de (3, 5).",
    leaves: hashes,
    cases: [...acceptes, ...refuses],
  });
}

// 5. Manifestes ------------------------------------------------------------
{
  const attendu = { version: 0, periodes: [], continuite: [], discontinu: null };
  for (const p of jeu.periodes) {
    exiger(J.verifierManifeste(p.manifeste).length === 0, `manifeste ${p.numero} non conforme`);
    exiger(J.validerSchema(p.manifeste, SCHEMAS[J.ID_SCHEMA_MANIFESTE], { registre: SCHEMAS }).length === 0, `manifeste ${p.numero} hors schéma`);
    exiger(J.verifierSignatureManifeste(p.manifeste, p.sig, CLES["rec-test-02"].clePublique), `signature du manifeste ${p.numero} refusée`);
    ecrireJSON(`manifestes/periode-${p.numero}.json`, p.manifeste);
    ecrireJSON(`manifestes/periode-${p.numero}.sig`, p.sig);
    attendu.periodes.push({
      fichier: `periode-${p.numero}.json`,
      count: p.manifeste.count,
      seq: p.events.map((e) => e.seq),
      root: p.manifeste.root,
      canonical: J.canonicaliserJCS(p.manifeste),
      period_hash: p.sig.period_hash,
      sig: p.sig.sig,
      recorder_key_id: p.sig.recorder_key_id,
      anchor_fingerprint: anchorFingerprint({ orgId: ORG_ID, journalId: JOURNAL_ID, periodHash: p.sig.period_hash }),
      period_meta: { orgId: ORG_ID, journalId: JOURNAL_ID, periodHash: p.sig.period_hash, root: p.manifeste.root, periodStart: p.manifeste.period_start, periodEnd: p.manifeste.period_end, firstSeq: p.manifeste.first_seq, lastSeq: p.manifeste.last_seq, version: 0 },
    });
  }
  for (let i = 1; i < jeu.periodes.length; i++) {
    const c = J.verifierContinuiteManifestes(jeu.periodes[i - 1].manifeste, jeu.periodes[i].manifeste);
    exiger(c.valide, `continuité ${i} -> ${i + 1} : ${c.erreurs}`);
    attendu.continuite.push({ de: `periode-${i}.json`, a: `periode-${i + 1}.json`, valide: true, erreurs: [] });
  }
  const p1 = jeu.periodes[0].manifeste;
  const discontinu = { ...jeu.periodes[1].manifeste, first_seq: 11, last_seq: 13, prev_period_hash: nonce(2) };
  const c = J.verifierContinuiteManifestes(p1, discontinu);
  exiger(!c.valide && c.erreurs.length === 2, `manifeste discontinu : ${JSON.stringify(c.erreurs)}`);
  ecrireJSON("manifestes/discontinu.json", discontinu);
  ecrireJSON("manifestes/discontinu.sig", J.signerManifeste(discontinu, CLES["rec-test-02"].clePrivee));
  attendu.discontinu = {
    fichier: "discontinu.json",
    description: "Variante de periode-2.json qui prétend suivre periode-1.json : first_seq 11 au lieu de 10 (un événement sauté) et prev_period_hash qui n'est pas le periodHash de la période 1. Sa signature est valide : la discontinuité ne se voit qu'en tenant les deux manifestes (contrôle P-5, et PeriodRegistry « discontinuité de sequence »).",
    precedent: "periode-1.json",
    valide: false,
    erreurs: c.erreurs,
  };
  ecrireJSON("manifestes/attendu.json", attendu);
}

// 5 bis. Points de contrôle (CT-1 révision 0.3, §10.5 à §10.8) ------------------
// Pour chaque période : un point par minute à partir de period_start (à :00.000,
// cadence par défaut de 60 s), puis le point de clôture à generated_at du
// manifeste (tree_size = count). tree_size est le nombre d'événements de la
// période horodatés au plus tard à checkpoint_ts ; la clé est celle en vigueur
// (règle 5 : clé du dernier événement de seq <= last_seq, new_key_id après une
// rotation ; avant tout événement du journal, la première clé de cles.json).
const CLE_PAR_ID = Object.fromEntries(Object.entries(CLES).map(([id, k]) => [id, k.clePrivee]));
function corpsSerie(jeu, periode) {
  const precedents = jeu.evenements.filter((e) => e.seq < periode.manifeste.first_seq);
  const lastHashJournal = precedents.length ? precedents[precedents.length - 1].hash : J.HASH_NUL;
  const instants = [];
  for (let t = periode.period_start * 1000; t < (periode.period_start + 3600) * 1000; t += 60000) instants.push(J.horodatage(t));
  instants.push(periode.manifeste.generated_at);
  return instants.map((checkpoint_ts) => {
    const tK = J.msHorodatage(checkpoint_ts);
    const tree_size = checkpoint_ts === periode.manifeste.generated_at ? periode.manifeste.count : periode.events.filter((e) => J.msHorodatage(e.ts) <= tK).length;
    const last_seq = periode.manifeste.first_seq + tree_size - 1;
    const key_id = J.cleEnVigueurPoint(jeu.evenements, last_seq) ?? jeu.cles.keys[0].key_id;
    return J.construirePointDeControle({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: periode.period_start, first_seq: periode.manifeste.first_seq, hashes: periode.hashes, tree_size, checkpoint_ts, key_id, last_hash_journal: lastHashJournal });
  });
}
/** Chaîne et signe une liste de corps de points (prev_checkpoint_hash recalculé, signature par la clé key_id). */
function chainerPoints(corps, { signataires = {} } = {}) {
  const points = [];
  let prev = J.HASH_NUL;
  corps.forEach((c, i) => {
    const signe = J.signerPointDeControle({ ...c, prev_checkpoint_hash: prev }, signataires[i] ?? CLE_PAR_ID[c.key_id]);
    points.push(signe);
    prev = J.hachagePointDeControle(signe);
  });
  return points;
}
const SERIES = {};
{
  const attendu = { version: 0, description: "Séries complètes des points de contrôle des trois périodes de journal-valide (CT-1 §10.5 à §10.8) : un point par minute depuis period_start (cadence par défaut, points sans nouvel événement compris) puis le point de clôture à generated_at du manifeste. Pour chaque point : checkpoint_hash, forme canonique C_K, prev_checkpoint_hash attendu, clé en vigueur, preuve de cohérence vers la racine du manifeste (null pour tree_size = 0 : aucune preuve ne part d'une racine nulle). Les séries invalides (invalides/) violent chacune une règle de la série ; rules_failed les nomme.", periodes: [], invalides: [] };
  for (const periode of jeu.periodes) {
    const points = chainerPoints(corpsSerie(jeu, periode));
    SERIES[periode.numero] = points;
    const serie = J.verifierSeriePointsDeControle(points, periode.manifeste, { evenements: jeu.evenements, cles: jeu.cles });
    exiger(serie.valide, `série de la période ${periode.numero} refusée : ${JSON.stringify(serie.erreurs)}`);
    for (const pt of points) exiger(J.validerSchema(pt, SCHEMAS[J.ID_SCHEMA_POINT_DE_CONTROLE], { registre: SCHEMAS }).length === 0, `point hors schéma (période ${periode.numero}, ${pt.checkpoint_ts})`);
    ecrireJSON(`points-de-controle/periode-${periode.numero}.json`, points);
    attendu.periodes.push({
      file: `periode-${periode.numero}.json`,
      manifest: `../manifestes/periode-${periode.numero}.json`,
      period_start: periode.period_start,
      count: points.length,
      last: { tree_size: periode.manifeste.count, root: periode.manifeste.root, last_seq: periode.manifeste.last_seq },
      points: points.map((pt, i) => {
        const consistency = pt.tree_size > 0 ? J.preuveCoherenceDossier(periode.hashes, pt.tree_size) : null;
        if (consistency) exiger(J.verifierCoherence(consistency), "preuve de cohérence du point refusée");
        return { index: i, checkpoint_ts: pt.checkpoint_ts, tree_size: pt.tree_size, last_seq: pt.last_seq, key_id: pt.key_id, prev_checkpoint_hash: i === 0 ? J.HASH_NUL : J.hachagePointDeControle(points[i - 1]), canonical: J.canonicaliserJCS(J.corpsPointDeControle(pt)), checkpoint_hash: J.hachagePointDeControle(pt), sig: pt.sig, consistency };
      }),
    });
  }
  // Séries invalides, dérivées de la période 1 (61 points : minutes 09:00 à 09:59, clôture à 10:00:00.300).
  const REGLES = [
    [/prev_checkpoint_hash/, "chainage"], [/tree_size .* décroît/, "tree_size_decroissant"], [/checkpoint_ts .* antérieur au précédent/, "checkpoint_ts_decroissant"],
    [/^dernier point/, "dernier_point"], [/clé en vigueur attendue/, "cle_en_vigueur"], [/signature invalide/, "signature"], [/hors de la validité/, "validite_cle"],
    [/racine recalculée/, "root"], [/last_hash/, "last_hash"], [/last_seq .* différent de first_seq/, "last_seq"], [/period_start/, "period_start"],
  ];
  const reglesDe = (erreurs) => [...new Set(erreurs.map((e) => REGLES.find(([re]) => re.test(e))?.[1] ?? "autre"))];
  const periode1 = jeu.periodes[0];
  const corps1 = corpsSerie(jeu, periode1);
  const indicePoint = (tree_size) => corps1.findIndex((c) => c.tree_size === tree_size);
  const serieInvalide = (nom, points, rules, description) => {
    const r = J.verifierSeriePointsDeControle(points, periode1.manifeste, { evenements: jeu.evenements, cles: jeu.cles });
    exiger(!r.valide && JSON.stringify(reglesDe(r.erreurs)) === JSON.stringify(rules), `${nom} : règles ${JSON.stringify(reglesDe(r.erreurs))}, attendues ${JSON.stringify(rules)} ; ${JSON.stringify(r.erreurs)}`);
    ecrireJSON(`points-de-controle/invalides/${nom}.json`, points);
    attendu.invalides.push({ file: `invalides/${nom}.json`, manifest: "../manifestes/periode-1.json", description, rules_failed: rules, errors: r.erreurs });
  };
  {
    const c = corps1.map((x) => ({ ...x }));
    const i = indicePoint(8) + 1;
    c[i].checkpoint_ts = J.horodatage(J.msHorodatage(c[i - 1].checkpoint_ts) - 60000);
    serieInvalide("periode-1-antidate", chainerPoints(c), ["checkpoint_ts_decroissant"], `Le point d'indice ${i} est antidaté d'une minute par rapport au précédent (série rechaînée et re-signée) : checkpoint_ts décroît le long de la chaîne.`);
  }
  {
    const c = corps1.map((x) => ({ ...x }));
    const i = indicePoint(8) + 1;
    c[i] = { ...J.construirePointDeControle({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: periode1.period_start, first_seq: 1, hashes: periode1.hashes, tree_size: 7, checkpoint_ts: c[i].checkpoint_ts, key_id: c[i].key_id }) };
    serieInvalide("periode-1-tree-size-decroissant", chainerPoints(c), ["tree_size_decroissant"], `Le point d'indice ${i} n'engage que sept événements alors que le précédent en engage huit (root, last_seq et last_hash recalculés pour sept, série rechaînée) : tree_size décroît.`);
  }
  {
    const points = chainerPoints(corps1);
    const i = 20;
    const faux = J.signerPointDeControle({ ...J.corpsPointDeControle(points[i]), prev_checkpoint_hash: J.sha256(Buffer.from("prev_checkpoint_hash faux", "utf8")) }, CLE_PAR_ID[points[i].key_id]);
    let prev = J.hachagePointDeControle(faux);
    const rechaines = corps1.slice(i + 1).map((c) => {
      const signe = J.signerPointDeControle({ ...c, prev_checkpoint_hash: prev }, CLE_PAR_ID[c.key_id]);
      prev = J.hachagePointDeControle(signe);
      return signe;
    });
    serieInvalide("periode-1-chainage-faux", [...points.slice(0, i), faux, ...rechaines], ["chainage"], `Le point d'indice ${i} porte un prev_checkpoint_hash qui n'est pas le checkpointHash du point précédent (re-signé ; les points suivants sont chaînés à lui) : la chaîne est rompue en un seul endroit.`);
  }
  {
    const points = chainerPoints(corps1);
    serieInvalide("periode-1-sans-cloture", points.slice(0, -1), ["dernier_point"], "Le point de clôture (10:00:00.300Z, tree_size 9) est retiré : le dernier point (09:59:00.000Z) n'engage que huit événements et ne rejoint pas le manifeste (règle 4).");
  }
  {
    const points = chainerPoints(corps1, { signataires: { 10: CLES["rec-test-02"].clePrivee } });
    serieInvalide("periode-1-signature", points, ["signature"], "Le point d'indice 10 (09:10:00.000Z) annonce key_id rec-test-01 mais est signé par rec-test-02 : signature invalide sous la clé annoncée.");
  }
  {
    const c = corps1.map((x) => ({ ...x }));
    c[c.length - 1].key_id = "rec-test-01";
    serieInvalide("periode-1-cle-perimee", chainerPoints(c), ["cle_en_vigueur", "validite_cle"], "Le point de clôture est signé par rec-test-01 (key_id et signature cohérents) alors que la rotation de seq 9 (09:59:58.000Z) a mis rec-test-02 en vigueur et clos la validité de rec-test-01 avant 10:00:00.300Z.");
  }
  {
    const c = corps1.map((x) => ({ ...x }));
    const i = indicePoint(8);
    c[i].last_hash = J.sha256(Buffer.from("last_hash faux", "utf8"));
    serieInvalide("periode-1-last-hash", chainerPoints(c), ["last_hash"], `Le point d'indice ${i} (premier point à engager seq 8) porte un last_hash qui n'est pas le hash de seq 8 (re-signé, série rechaînée) : la tête de chaîne annoncée n'est pas celle du journal.`);
  }
  ecrireJSON("points-de-controle/attendu.json", attendu);
}

// 6. Dossiers ------------------------------------------------------------
function ecrireDossier(nom, fichiers, attendu) {
  const rapport = J.verifierDossier(fichiers, { schemas: SCHEMAS });
  const echecs = J.controlesEnEchec(rapport);
  exiger(rapport.valide === attendu.valide && JSON.stringify(echecs) === JSON.stringify(attendu.controles_en_echec ?? []), `${nom} : contrôles en échec ${JSON.stringify(echecs)} (valide ${rapport.valide}), attendus ${JSON.stringify(attendu.controles_en_echec ?? [])} ; détails : ${JSON.stringify(rapport.controles.filter((c) => c.ok === false))}`);
  for (const [fichier, contenu] of Object.entries(fichiers)) ecrire(`dossiers/${nom}/${fichier}`, contenu);
  ecrireJSON(`dossiers/${nom}/attendu.json`, attendu);
}
const lireF = (fichiers, nom) => J.analyserJSONStrict(fichiers[nom]);
const remplacer = (fichiers, nom, valeur) => ({ ...fichiers, [nom]: J.texteJSON(valeur) });
const resceller = (ev) => J.scellerEvenement(J.corpsEvenement(ev), CLES_PRIVEES[ev.recorder_key_id]);
const invalide = (controle, controles_en_echec, description) => ({ valide: false, controle, controles_en_echec, description });

{
  const valide = dossierPour(jeu, 7);
  ecrireDossier("valide-seq-7", valide.fichiers, { valide: true, controle: null, controles_en_echec: [], description: "Dossier de l'appel relayé après approbation (seq 7) : voisins seq 6 et seq 8, période 1 (neuf événements, clôturée par rec-test-02 après la rotation de seq 9), approbation apr-2201 des comptes Hardhat 1 et 2. Les cinq parties réservées à CT-4 et CT-5 sont absentes avec la raison « hors périmètre CT-1 ». Le contrôle A-4 est non exécuté : l'événement de demande (seq 5) n'est pas un voisin." });
  const F = valide.fichiers;
  const k2 = CLES["rec-test-02"].clePrivee;
  const reindexer = (fichiers) => J.reindexerDossier(fichiers).fichiers;
  // Second dossier valide : la décision d'approbation elle-même (seq 6), dont approbations.json contient l'événement prouvé et dont la demande (seq 5, retenue) est le voisin précédent.
  ecrireDossier("valide-seq-6", dossierPour(jeu, 6).fichiers, { valide: true, controle: null, controles_en_echec: [], description: "Dossier de la décision d'approbation (seq 6) : voisins seq 5 (la demande, retenue) et seq 7 (l'appel relayé) ; approbations.json contient l'événement prouvé lui-même (A-2) ; A-4 est exécuté, le hash recalculé de seq 5 égale request_hash et son status vaut retenue." });

  // D-1 : event.seq de l'index décalé (fichiers intacts : D-2 passe).
  {
    const idx = lireF(F, "dossier.json");
    idx.event.seq += 1;
    ecrireDossier("invalide-index-seq", remplacer(F, "dossier.json", idx), invalide("D-1", ["D-1"], "dossier.json annonce event.seq 8 alors que evenement.json porte seq 7 : l'index ne décrit pas l'événement du dossier."));
  }
  // E-1 : evenement.json réduit au littéral JSON null, index recalculé (partie présente, SHA-256 exact, contenu inexploitable).
  {
    const nul = "null\n";
    const idx = lireF(F, "dossier.json");
    idx.parts.find((p) => p.name === "evenement").sha256 = J.sha256(Buffer.from(nul, "utf8"));
    ecrireDossier("invalide-partie-nulle", remplacer({ ...F, "evenement.json": nul }, "dossier.json", idx), invalide("E-1", ["E-1"], "evenement.json contient le littéral JSON null ; l'index le déclare présent avec son SHA-256 exact (D-2 passe). La partie est inexploitable : E-1 échoue, les contrôles qui en dépendent sont non exécutés sans raison admise, le dossier est invalide et le rapport ne reprend rien de l'index à la place de l'événement."));
  }
  // E-1 et E-3 : échange avec le modèle sans réponse (journal rejoué), dossier de seq 1.
  {
    const variante = construireJournal({ echangeSansReponse: true });
    ecrireDossier("invalide-echange-sans-reponse", dossierPour(variante, 1).fichiers, invalide("E-3", ["E-1", "E-3"], "Journal rejoué où l'échange avec le modèle (seq 1) porte result, duration_ms et is_error à null : la table 5.3 exige la référence à la réponse, la durée et le drapeau d'erreur pour noortrace.modele.echange (E-3), et le schéma la porte (E-1)."));
  }
  // E-3 : policy.decision sans_objet sur l'appel d'outil du voisin suivant (seq 8), rescellé.
  {
    const v = lireF(F, "voisins.json");
    v.next = resceller({ ...v.next, policy: { ...v.next.policy, decision: "sans_objet", rule: null } });
    ecrireDossier("invalide-sans-objet-appel", reindexer(remplacer(F, "voisins.json", v)), invalide("E-3", ["E-3"], "voisins.next (seq 8, appel d'outil mail.send) porte policy.decision = sans_objet, valeur réservée aux événements qui ne sont pas des appels d'outil ; rescellé, donc hash et signature valides : seul E-3 le refuse."));
  }
  // E-4 : policy.redaction null sur le voisin suivant dont les arguments sont rédigés, rescellé.
  {
    const v = lireF(F, "voisins.json");
    v.next = resceller({ ...v.next, policy: { ...v.next.policy, redaction: null } });
    ecrireDossier("invalide-redaction-absente", reindexer(remplacer(F, "voisins.json", v)), invalide("E-4", ["E-4"], "voisins.next (seq 8) porte une référence rédigée (execution.arguments, redacted: true) mais policy.redaction est null : la règle de rédaction appliquée doit être nommée."));
  }
  // E-5 : deux approbateurs, une seule signature (journal rejoué).
  {
    const variante = construireJournal({ signatairesApprobation: [HARDHAT[0]], approbateurs: [ADRESSES_HARDHAT[0], ADRESSES_HARDHAT[1]] });
    ecrireDossier("invalide-signature-manquante", dossierPour(variante, 7).fichiers, invalide("E-5", ["E-5"], "Journal rejoué où approval.approvers compte deux adresses et approval.signatures une seule signature (valide, du compte Hardhat 1) : les deux tableaux doivent avoir la même longueur."));
  }
  // E-6 : length de la référence en ligne A de la décision augmentée de 1 (journal rejoué).
  {
    const variante = construireJournal({ longueurReferenceDecision: 1 });
    ecrireDossier("invalide-reference-en-ligne", dossierPour(variante, 7).fichiers, invalide("E-6", ["E-6"], "Journal rejoué où la référence en ligne de la décision (execution.arguments, value = A) déclare une length supérieure de 1 à celle de JCS(value) : le sha256 est juste, la length ne l'est pas (voisin précédent et approbations.json)."));
  }
  // C-2 : prev_hash du voisin suivant réécrit, rescellé.
  {
    const v = lireF(F, "voisins.json");
    v.next = resceller({ ...v.next, prev_hash: J.sha256(Buffer.from("autre prev_hash", "utf8")) });
    ecrireDossier("invalide-prev-hash-voisin", reindexer(remplacer(F, "voisins.json", v)), invalide("C-2", ["C-2"], "voisins.next (seq 8) porte un prev_hash qui n'est pas le hash recalculé de l'événement prouvé ; rescellé, donc hash et signature valides : la chaîne est rompue entre seq 7 et seq 8."));
  }
  // C-3 : journal rejoué (seq 10 à l'instant de la rotation) ; dossier de la rotation (seq 9), voisin suivant signé par l'ancienne clé, rescellé.
  {
    const variante = construireJournal({ ts: { 10: TS_ROTATION } });
    const d = dossierPour(variante, 9);
    const v = lireF(d.fichiers, "voisins.json");
    v.next = resceller({ ...v.next, recorder_key_id: "rec-test-01" });
    ecrireDossier("invalide-cle-voisin", reindexer(remplacer(d.fichiers, "voisins.json", v)), invalide("C-3", ["C-3"], "Journal rejoué où seq 10 est horodaté à l'instant exact de la rotation (seul instant où les deux clés valent, E-11) ; dossier de la rotation (seq 9) dont le voisin suivant est signé par rec-test-01, rescellé : la clé attendue après la rotation est rec-test-02."));
  }
  // M-1 : arbre et manifeste (re-signé) bâtis sur une autre feuille à la position de seq 7.
  {
    const hashes = [...jeu.periodes[0].hashes];
    hashes[6] = J.sha256(Buffer.from("feuille etrangere", "utf8"));
    const m = { ...lireF(F, "manifeste.json"), root: J.racineMerkle(hashes) };
    ecrireDossier("invalide-feuille-etrangere", reindexer(remplacer(remplacer(remplacer(F, "manifeste.json", m), "manifeste.sig", J.signerManifeste(m, k2)), "chemin.json", J.preuveInclusion(hashes, 6))), invalide("M-1", ["M-1"], "chemin.json et le manifeste (re-signé) sont bâtis sur un arbre où la feuille d'indice 6 n'est pas SHA-256(0x00 || hash de seq 7) : le chemin mène à la racine (M-2), la racine est celle du manifeste (M-3), mais la feuille ne prouve pas l'événement."));
  }
  // P-2 : dossier de seq 1 horodaté avant period_start ; voisin suivant, arbre et manifeste recalculés et re-signés.
  {
    const E = jeu.evenements;
    const ev1 = resceller({ ...E[0], ts: T(8, 59, 59, 999) });
    const ev2 = resceller({ ...E[1], prev_hash: ev1.hash });
    const hashes = [ev1.hash, ev2.hash, ...jeu.periodes[0].hashes.slice(2)];
    const m = { ...jeu.periodes[0].manifeste, root: J.racineMerkle(hashes) };
    const d = J.assemblerDossier({ evenement: ev1, previous: null, next: ev2, hashesPeriode: hashes, manifeste: m, manifesteSig: J.signerManifeste(m, k2), cles: jeu.cles, generated_at: GENERATED_AT_DOSSIER });
    ecrireDossier("invalide-ts-hors-periode", d.fichiers, invalide("P-2", ["P-2"], "Dossier de seq 1 horodaté 08:59:59.999Z, avant period_start de la période 1 (09:00:00Z) ; seq 2 est rechaîné et rescellé, l'arbre et le manifeste sont recalculés et re-signés : tout est cohérent sauf l'appartenance de l'événement à la période."));
  }
  // P-3 : manifeste à huit feuilles (last_seq 8) re-signé ; dossier de seq 8 dont le voisin suivant (seq 9) est horodaté dans la période.
  {
    const E = jeu.evenements;
    const hashes = jeu.periodes[0].hashes.slice(0, 8);
    const m = { ...jeu.periodes[0].manifeste, last_seq: 8, count: 8, root: J.racineMerkle(hashes) };
    const d = J.assemblerDossier({ evenement: E[7], previous: E[6], next: E[8], hashesPeriode: hashes, manifeste: m, manifesteSig: J.signerManifeste(m, k2), cles: jeu.cles, generated_at: GENERATED_AT_DOSSIER });
    ecrireDossier("invalide-periode-tronquee", d.fichiers, invalide("P-3", ["P-3"], "Le manifeste de la période 1 est refait sur huit feuilles (seq 1 à 8, last_seq = 8) et re-signé par rec-test-02 ; dossier de seq 8 dont le voisin suivant (seq 9, la rotation, 09:59:58.000Z) est hors de l'intervalle de seq mais horodaté dans la période : le manifeste a tronqué sa période."));
  }
  // P-1 : manifeste dont la période dure deux heures, re-signé.
  {
    const m = lireF(F, "manifeste.json");
    m.period_end = m.period_start + 7200;
    ecrireDossier("invalide-periode-deux-heures", reindexer(remplacer(remplacer(F, "manifeste.json", m), "manifeste.sig", J.signerManifeste(m, k2))), invalide("P-1", ["P-1"], "manifeste.json porte period_end = period_start + 7200 (deux heures), re-signé : une période est une heure UTC pleine, period_end = period_start + 3600 ; l'événement et ses voisins restent dans la fenêtre élargie (P-2, P-3 passent)."));
  }
  // P-5 : manifeste re-signé par rec-test-01, dont la validité s'arrête avant generated_at.
  {
    const m = { ...lireF(F, "manifeste.json"), recorder_key_id: "rec-test-01" };
    ecrireDossier("invalide-manifeste-cle-perimee", reindexer(remplacer(remplacer(F, "manifeste.json", m), "manifeste.sig", J.signerManifeste(m, CLES["rec-test-01"].clePrivee))), invalide("P-5", ["P-5"], "Le manifeste est signé par rec-test-01 (periodHash et signature cohérents) alors que cles.json arrête sa validité à l'instant de la rotation (09:59:58.000Z), avant generated_at (10:00:00.300Z) : la clé en vigueur à la clôture était rec-test-02."));
  }
  // A-1 : ticket de approbations.json différent de approval.ticket.
  {
    const a = lireF(F, "approbations.json");
    a.ticket = "apr-9999";
    ecrireDossier("invalide-ticket-approbations", reindexer(remplacer(F, "approbations.json", a)), invalide("A-1", ["A-1"], "approbations.json porte le ticket apr-9999 alors que approval.ticket de l'événement vaut apr-2201."));
  }
  // A-2 : approval.reason de la décision jointe modifié, décision rescellée.
  {
    const a = lireF(F, "approbations.json");
    a.events[0] = resceller({ ...a.events[0], approval: { ...a.events[0].approval, reason: "Motif différent" } });
    ecrireDossier("invalide-decision-etrangere", reindexer(remplacer(F, "approbations.json", a)), invalide("A-2", ["A-2"], "La décision jointe dans approbations.json porte un approval.reason différent (champ non signé par les approbateurs, rescellé par l'enregistreur) : approval n'est plus égal, clé pour clé, à celui de l'événement prouvé."));
  }
  // A-4 : journal rejoué où la demande (seq 5) est refusée par la politique ; dossier de la décision (seq 6) qui l'approuve pourtant.
  {
    const variante = construireJournal({ demandeRefusee: true });
    ecrireDossier("invalide-demande-refusee", dossierPour(variante, 6).fichiers, invalide("A-4", ["A-4"], "Journal rejoué où seq 5 est refusé par la politique (status refusee) au lieu d'être retenu ; dossier de la décision seq 6 dont request_hash désigne bien ce voisin : son status n'est pas retenue."));
  }
  // E-1 et A-3 : le même approbateur deux fois (journal rejoué).
  {
    const variante = construireJournal({ signatairesApprobation: [HARDHAT[0], HARDHAT[0]], approbateurs: [ADRESSES_HARDHAT[0], ADRESSES_HARDHAT[0]] });
    ecrireDossier("invalide-approbateur-double", dossierPour(variante, 7).fichiers, invalide("A-3", ["E-1", "A-3"], "Journal rejoué où le compte Hardhat 1 figure deux fois dans approvers avec deux signatures valides : le schéma impose des approbateurs distincts (uniqueItems, E-1) et A-3 compte les approbateurs distincts."));
  }
  // E-9 : signature d'approbation en forme non canonique, s haut (journal rejoué).
  {
    const variante = construireJournal({ signatureNonCanonique: 1 });
    ecrireDossier("invalide-signature-s-haut", dossierPour(variante, 7).fichiers, invalide("E-9", ["E-9"], "Journal rejoué où signatures[1] est mise en forme haute (s remplacé par n - s, v complémenté) : même point, même adresse pour un vérificateur laxiste, refusée comme non canonique (E-9), comme par le contrat ThresholdSignatures."));
  }
  // E-8 : cles.json avec un key_id en double.
  {
    const c = lireF(F, "cles.json");
    c.keys.push({ ...c.keys[0], public_key: CLE_TIERCE.clePublique });
    ecrireDossier("invalide-cles-key-id-double", reindexer(remplacer(F, "cles.json", c)), invalide("E-8", ["E-8"], "cles.json porte deux entrées rec-test-01 (la seconde avec une autre clé publique) : l'identifiant doit être unique, sinon le verdict dépendrait de l'ordre de lecture."));
  }
  // E-8 : cles.json d'un autre journal.
  {
    const c = lireF(F, "cles.json");
    c.journal_id = keccak256(toUtf8Bytes("journal-principal"));
    ecrireDossier("invalide-cles-autre-journal", reindexer(remplacer(F, "cles.json", c)), invalide("E-8", ["E-8"], "cles.json porte le journal_id d'un autre journal (journal-principal, celui de l'exemple de la spécification) : les clés doivent être rattachées au journal de l'événement prouvé."));
  }
  // E-10 : cles.json annonce la nouvelle clé valide avant le ts de la rotation (dossier de seq 9).
  {
    const d = dossierPour(jeu, 9);
    const c = lireF(d.fichiers, "cles.json");
    c.keys.find((k) => k.key_id === "rec-test-02").valid_from = T(9, 0, 0, 0);
    ecrireDossier("invalide-rotation-validite-annoncee", reindexer(remplacer(d.fichiers, "cles.json", c)), invalide("E-10", ["E-10"], "Dossier de la rotation (seq 9) dont cles.json annonce rec-test-02 valide à partir de 09:00:00Z alors que la rotation est horodatée 09:59:58.000Z : la validité d'une clé issue d'une rotation est celle que le journal annonce (CT-1 §8, règle 3)."));
  }

  // E-7 : hash réécrit, contenu et signature intacts.
  {
    const ev = lireF(F, "evenement.json");
    ev.hash = J.sha256(Buffer.from("hash faux", "utf8"));
    ecrireDossier("invalide-hash-faux", J.reindexerDossier(remplacer(F, "evenement.json", ev)).fichiers, invalide("E-7", ["E-7"], "Le champ hash de evenement.json est réécrit (contenu et signature intacts) : le hash recalculé ne correspond plus. L'index est recalculé pour que D-1 et D-2 passent ; les contrôles qui recalculent le hash (C-2, M-1) passent aussi."));
  }
  // E-8 : signature produite par une autre clé.
  {
    const ev = lireF(F, "evenement.json");
    ev.sig = J.signerEvenement(ev, CLES["rec-test-02"].clePrivee);
    ecrireDossier("invalide-signature-fausse", J.reindexerDossier(remplacer(F, "evenement.json", ev)).fichiers, invalide("E-8", ["E-8"], "La signature de evenement.json est une signature Ed25519 valide, mais produite par rec-test-02 alors que recorder_key_id vaut rec-test-01."));
  }
  // M-2 : chemin permuté, chemin tronqué.
  {
    const ch = lireF(F, "chemin.json");
    [ch.path[0], ch.path[1]] = [ch.path[1], ch.path[0]];
    ecrireDossier("invalide-chemin-permute", J.reindexerDossier(remplacer(F, "chemin.json", ch)).fichiers, invalide("M-2", ["M-2"], "Les deux premiers nœuds de chemin.json sont échangés : l'algorithme d'inclusion ne retombe pas sur la racine."));
    const ch2 = lireF(F, "chemin.json");
    ch2.path.pop();
    ecrireDossier("invalide-chemin-tronque", J.reindexerDossier(remplacer(F, "chemin.json", ch2)).fichiers, invalide("M-2", ["M-2"], "Le dernier nœud de chemin.json est retiré : le chemin n'a pas la longueur attendue pour (leaf_index, tree_size) et sn ne retombe pas à 0."));
  }
  // M-3 (et M-2) : leaf_index décalé.
  {
    const ch = lireF(F, "chemin.json");
    ch.leaf_index += 1;
    ecrireDossier("invalide-leaf-index-decale", J.reindexerDossier(remplacer(F, "chemin.json", ch)).fichiers, invalide("M-3", ["M-2", "M-3"], "leaf_index de chemin.json vaut 7 au lieu de 6 : il ne vaut plus seq - first_seq (M-3) et le chemin, interprété à cette position, ne mène plus à la racine (M-2)."));
  }
  // C-1 : voisin suivant dont le seq n'est pas seq + 1 (rescellé : hash et signature valides).
  {
    const v = lireF(F, "voisins.json");
    v.next = resceller({ ...v.next, seq: v.next.seq + 1 });
    ecrireDossier("invalide-voisin-incoherent", J.reindexerDossier(remplacer(F, "voisins.json", v)).fichiers, invalide("C-1", ["C-1"], "voisins.next porte seq 9 au lieu de 8 et a été rescellé avec la clé de l'enregistreur : hash, signature et prev_hash sont valides, mais il n'est pas le voisin immédiat."));
  }
  // M-3 : racine du manifeste différente de celle du chemin (manifeste rescellé).
  {
    const m = lireF(F, "manifeste.json");
    m.root = J.racineMerkle(jeu.periodes[0].hashes.slice(0, 8));
    const sig = J.signerManifeste(m, CLES["rec-test-02"].clePrivee);
    ecrireDossier("invalide-racine-manifeste", J.reindexerDossier(remplacer(remplacer(F, "manifeste.json", m), "manifeste.sig", sig)).fichiers, invalide("M-3", ["M-3"], "La racine de manifeste.json est celle d'un arbre à huit feuilles (seq 1 à 8) et le manifeste a été re-signé : periodHash et signature sont cohérents entre eux (P-5), mais la racine ne correspond pas à celle du chemin."));
  }
  // P-4 : racine nulle pour une période non vide.
  {
    const m = lireF(F, "manifeste.json");
    m.root = J.HASH_NUL;
    const sig = J.signerManifeste(m, CLES["rec-test-02"].clePrivee);
    ecrireDossier("invalide-racine-nulle", J.reindexerDossier(remplacer(remplacer(F, "manifeste.json", m), "manifeste.sig", sig)).fichiers, invalide("P-4", ["M-3", "P-1", "P-4"], "Racine nulle avec count = 9, manifeste re-signé : la convention de la période vide est violée (P-4), le schéma du manifeste l'interdit (P-1) et le chemin ne mène pas à cette racine (M-3)."));
  }
  // D-2 : index dont un sha256 ne correspond pas.
  {
    const idx = lireF(F, "dossier.json");
    idx.parts.find((p) => p.name === "chemin").sha256 = J.sha256(Buffer.from("autre contenu", "utf8"));
    ecrireDossier("invalide-index-sha256", remplacer(F, "dossier.json", idx), invalide("D-2", ["D-2"], "dossier.json déclare pour chemin.json un SHA-256 qui n'est pas celui du fichier : le dossier a été modifié après l'écriture de l'index."));
  }
  // E-2 : nombre non entier dans evenement.json (texte modifié, pas l'objet). Le
  // fichier n'étant plus analysable, l'index est repris du dossier valide avec
  // le SHA-256 du nouveau texte : D-1 et D-2 passent, E-2 seul échoue.
  {
    const texte = F["evenement.json"];
    exiger(texte.includes('"duration_ms": 530,'), "duration_ms de seq 7 introuvable");
    const modifie = texte.replace('"duration_ms": 530,', '"duration_ms": 530.0,');
    const idx = lireF(F, "dossier.json");
    idx.parts.find((p) => p.name === "evenement").sha256 = J.sha256(Buffer.from(modifie, "utf8"));
    ecrireDossier("invalide-nombre-non-entier", remplacer({ ...F, "evenement.json": modifie }, "dossier.json", idx), invalide("E-2", ["E-2"], "evenement.json porte duration_ms = 530.0 : même valeur entière, forme fractionnaire, interdite par JCS v0. Un analyseur strict refuse le fichier ; les contrôles qui dépendent de l'événement ne sont pas exécutés."));
  }
  // E-1 : hexadécimal en majuscules (dans le voisin suivant, rescellé, pour n'atteindre que le schéma).
  {
    const v = lireF(F, "voisins.json");
    v.next = resceller({ ...v.next, code: { ...v.next.code, prompt_version: v.next.code.prompt_version.toUpperCase().replace("0X", "0x") } });
    ecrireDossier("invalide-hex-majuscules", J.reindexerDossier(remplacer(F, "voisins.json", v)).fichiers, invalide("E-1", ["E-1"], "code.prompt_version de voisins.next est en hexadécimal majuscule ; l'événement a été rescellé (hash et signature valides sur cette forme) : seul le schéma le refuse."));
  }
  // E-9 : signature d'approbation du compte Hardhat 3 à la place du 2, approvers inchangés (journal rejoué).
  {
    const variante = construireJournal({ signatairesApprobation: [HARDHAT[0], HARDHAT[2]] });
    ecrireDossier("invalide-approbateur-substitue", dossierPour(variante, 7).fichiers, invalide("E-9", ["E-9"], "Journal rejoué où signatures[1] est produite par le compte Hardhat 3 alors que approvers[1] reste le compte 2 : l'adresse recouvrée ne correspond pas (dans l'événement prouvé, dans le voisin précédent qui est la décision, et dans approbations.json)."));
  }
  // A-3 : un seul approbateur pour un seuil de 2.
  {
    const variante = construireJournal({ signatairesApprobation: [HARDHAT[0]], approbateurs: [ADRESSES_HARDHAT[0]] });
    ecrireDossier("invalide-seuil-non-atteint", dossierPour(variante, 7).fichiers, invalide("A-3", ["A-3"], "Journal rejoué avec une seule signature d'approbateur (compte Hardhat 1) pour un seuil déclaré de 2 sur 3 : la signature est valide, le seuil n'est pas atteint."));
  }
  // E-11 : clé employée hors de sa période de validité annoncée.
  {
    const c = lireF(F, "cles.json");
    c.keys.find((k) => k.key_id === "rec-test-01").valid_from = T(9, 31, 48, 500);
    ecrireDossier("invalide-cle-hors-validite", J.reindexerDossier(remplacer(F, "cles.json", c)).fichiers, invalide("E-11", ["E-11"], "cles.json annonce rec-test-01 valide à partir de 09:31:48.500Z : l'événement prouvé (09:31:48.006Z) et son voisin précédent sont signés avant la validité annoncée."));
  }
  // E-10 : rotation dont la contresignature n'est pas celle de la nouvelle clé (journal rejoué, dossier de seq 9).
  {
    const variante = construireJournal({ contresignataireRotation: CLES["rec-test-01"].clePrivee });
    ecrireDossier("invalide-rotation-contresignature", dossierPour(variante, 9).fichiers, invalide("E-10", ["E-10"], "Dossier de l'événement de rotation (seq 9) d'un journal rejoué où counter_sig a été produite par l'ancienne clé : la contresignature ne vérifie pas sous new_public_key."));
  }
  // C-1 : ts du voisin précédent postérieur à celui de l'événement (journal rejoué).
  {
    const variante = construireJournal({ ts: { 6: T(9, 31, 48, 500) } });
    ecrireDossier("invalide-ts-voisin", dossierPour(variante, 7).fichiers, invalide("C-1", ["C-1"], "Journal rejoué où seq 6 porte ts 09:31:48.500Z, postérieur au ts de seq 7 (09:31:48.006Z) : les horodatages décroissent le long de la chaîne."));
  }
}

// 6 bis. Dossiers avec la partie points-de-controle.json (CT-1 révision 0.3, §11.2, K-1 à K-6).
// Les quarante dossiers ci-dessus ne changent pas ; ceux-ci s'y ajoutent.
{
  const point = J.choisirPointCouvrant(SERIES[1], 6); // seq 7 : leaf_index 6 ; premier point qui le couvre : 09:32:00.000Z, tree_size 8 (seq 8 est horodaté 09:31:49.120Z)
  exiger(point.tree_size === 8 && point.checkpoint_ts === T(9, 32, 0, 0), "point couvrant seq 7 inattendu");
  const valide = dossierPour(jeu, 7, { point });
  const attenduK = (k) => ({ valide: true, controle: null, controles_en_echec: [], ...k });
  ecrireDossier("valide-seq-7-point-de-controle", valide.fichiers, attenduK({ description: "Dossier de seq 7 avec la treizième partie (révision 0.3) : point de contrôle de 09:32:00.000Z, premier point de la série de la période 1 qui couvre la feuille 6 (tree_size 8, last_seq 8, signé par rec-test-01), preuve de cohérence de huit feuilles vers neuf, aucune ancre (les trois à null). K-1 à K-6 réussies (K-6 exécutée : l'événement last_seq, seq 8, est le voisin suivant) ; K-7 à K-9 non exécutées, ancre absente ; A-4 non exécuté comme dans valide-seq-7." }));
  const F = valide.fichiers;
  const lirePoints = (fichiers) => lireF(fichiers, "points-de-controle.json");
  const reindexer = (fichiers) => J.reindexerDossier(fichiers).fichiers;
  const resignerPoint = (pt, id = pt.key_id) => J.signerPointDeControle(J.corpsPointDeControle(pt), CLE_PAR_ID[id]);
  const partieAvec = (pk, { recalculerHash = true } = {}) => ({ ...pk, checkpoint_hash: recalculerHash ? J.hachagePointDeControle(pk.checkpoint) : pk.checkpoint_hash });

  ecrireDossier("valide-seq-7-partie-declaree-absente", dossierPour(jeu, 7, { raisons: { points_de_controle: J.RAISON_AUCUN_POINT } }).fichiers, attenduK({ description: `Dossier de seq 7 dont l'index déclare treize parties, la treizième absente avec la raison « ${J.RAISON_AUCUN_POINT} » : verdict identique à valide-seq-7, K-1 à K-9 non exécutées pour une raison admise (partie absente).` }));
  // K-1 : period_start d'une autre période, point re-signé.
  {
    const pk = lirePoints(F);
    pk.checkpoint = resignerPoint({ ...pk.checkpoint, period_start: DEBUT_P2 });
    ecrireDossier("invalide-k1-point-autre-periode", reindexer(remplacer(F, "points-de-controle.json", partieAvec(pk))), invalide("K-1", ["K-1"], "Le point porte le period_start de la période 2 (re-signé, checkpoint_hash recalculé) : il ne décrit pas la période du manifeste, et son checkpoint_ts (09:32:00.000Z) précède ce period_start."));
  }
  // K-2 : checkpoint_hash réécrit.
  {
    const pk = lirePoints(F);
    pk.checkpoint_hash = J.sha256(Buffer.from("checkpoint_hash faux", "utf8"));
    ecrireDossier("invalide-k2-checkpoint-hash", reindexer(remplacer(F, "points-de-controle.json", pk)), invalide("K-2", ["K-2"], "checkpoint_hash déclaré n'est pas SHA-256(P_K || C_K) du point : l'empreinte que les ancres porteraient n'est pas celle de ce point."));
  }
  // K-3 : point signé par rec-test-02 avec key_id rec-test-01.
  {
    const pk = lirePoints(F);
    pk.checkpoint = resignerPoint(pk.checkpoint, "rec-test-02");
    ecrireDossier("invalide-k3-signature-point", reindexer(remplacer(F, "points-de-controle.json", partieAvec(pk))), invalide("K-3", ["K-3"], "Le point annonce key_id rec-test-01 mais sa signature est produite par rec-test-02 (corps inchangé : checkpoint_hash juste, K-2 passe) : signature invalide sous la clé annoncée."));
  }
  // K-4 : point trop court (tree_size 6 <= leaf_index 6), preuve de cohérence correcte. La série
  // par minute passe de cinq à huit événements entre 09:31 et 09:32 : le point est produit à part,
  // entre seq 6 (09:31:47.250Z) et seq 7 (09:31:48.006Z), chaîné au point de 09:31:00.000Z.
  {
    const precedent = SERIES[1].find((pt) => pt.checkpoint_ts === T(9, 31, 0, 0));
    exiger(precedent && precedent.tree_size === 5, "point de 09:31:00.000Z inattendu");
    const court = J.signerPointDeControle(J.construirePointDeControle({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_start: DEBUT_P1, first_seq: 1, hashes: jeu.periodes[0].hashes, tree_size: 6, checkpoint_ts: T(9, 31, 48, 0), prev_checkpoint_hash: J.hachagePointDeControle(precedent), key_id: "rec-test-01" }), CLE_PAR_ID["rec-test-01"]);
    ecrireDossier("invalide-k4-point-trop-court", dossierPour(jeu, 7, { point: court }).fichiers, invalide("K-4", ["K-4"], `Le point joint (${court.checkpoint_ts}, tree_size 6, last_seq 6, chaîné au point de 09:31:00.000Z) ne couvre pas la feuille 6 de l'événement prouvé (seq 7, 09:31:48.006Z) : preuve de cohérence correcte de six feuilles vers neuf (K-5), last_hash vérifié sur le voisin précédent (K-6), mais leaf_index n'est pas strictement inférieur à tree_size et ts est postérieur à checkpoint_ts.`));
  }
  // K-5 : dernier nœud du chemin de cohérence retiré.
  {
    const pk = lirePoints(F);
    exiger(pk.consistency.path.length >= 1, "chemin de cohérence vide");
    pk.consistency.path = pk.consistency.path.slice(0, -1);
    ecrireDossier("invalide-k5-coherence-tronquee", reindexer(remplacer(F, "points-de-controle.json", pk)), invalide("K-5", ["K-5"], "Le dernier nœud de consistency.path est retiré : l'algorithme de CT-1 §10.7 ne retombe pas sur les deux racines (chemin trop court pour (8, 9))."));
  }
  // K-6 : last_hash réécrit, point re-signé, checkpoint_hash recalculé ; l'événement last_seq (seq 8) est le voisin suivant.
  {
    const pk = lirePoints(F);
    pk.checkpoint = resignerPoint({ ...pk.checkpoint, last_hash: J.sha256(Buffer.from("last_hash faux", "utf8")) });
    ecrireDossier("invalide-k6-last-hash", reindexer(remplacer(F, "points-de-controle.json", partieAvec(pk))), invalide("K-6", ["K-6"], "last_hash du point réécrit (point re-signé, checkpoint_hash recalculé : K-2 et K-3 passent) : l'événement last_seq (seq 8) est le voisin suivant et son hash recalculé n'est pas celui que le point annonce."));
  }
  // n = N : le point de clôture (tree_size = count = 9) ; preuve de cohérence vide, racines égales (CT-1 §10.7) ;
  // l'événement last_seq (seq 9) n'est pas dans le dossier de seq 7 : K-6 non exécutée, pièce hors dossier (raison admise).
  {
    const cloture = SERIES[1][SERIES[1].length - 1];
    exiger(cloture.tree_size === jeu.periodes[0].hashes.length && cloture.last_seq === 9, "point de clôture de la période 1 inattendu");
    const d = dossierPour(jeu, 7, { point: cloture });
    const pk = lirePoints(d.fichiers);
    exiger(pk.consistency.path.length === 0 && pk.consistency.first_root === pk.consistency.second_root, "preuve de cohérence du point de clôture : chemin vide et racines égales attendus");
    ecrireDossier("valide-seq-7-point-de-cloture", d.fichiers, attenduK({ description: `Dossier de seq 7 dont la treizième partie porte le point de clôture de la période 1 (${cloture.checkpoint_ts}, tree_size 9 = count) : preuve de cohérence de neuf feuilles vers neuf, chemin vide et racines égales (CT-1 §10.7, m = n) ; K-1 à K-5 réussies ; K-6 non exécutée pour une raison admise (l'événement last_seq, seq 9, est hors du dossier) ; K-7 à K-9 non exécutées, ancres nulles.` }));
  }
  // K-1 en échec (membre hors schéma à la racine de la partie) avec un second défaut (chemin de cohérence tronqué) :
  // K-2 à K-9 ne sont pas exécutées, sans raison admise (CT-1 §11.4, CT-6 EX-5.9) ; seule K-1 est en échec.
  {
    const pk = lirePoints(F);
    pk.extra = "membre hors du schéma dossier-v0 ($defs/points_de_controle)";
    pk.consistency.path = pk.consistency.path.slice(0, -1);
    ecrireDossier("invalide-k1-double-defaut", reindexer(remplacer(F, "points-de-controle.json", pk)), invalide("K-1", ["K-1"], "La partie porte un membre « extra » hors du schéma et un chemin de cohérence tronqué : K-1 échoue sur le schéma ; K-2 à K-9 ne sont pas exécutées (prérequis K-1 en échec), si bien que le chemin tronqué n'est pas examiné et K-5 n'est pas en échec."));
  }
}

// 6 ter. Dossiers avec la partie attestation-perimetre.json (CT-1 révision 0.4,
// §11.2, AT-1 à AT-7 ; CT-7 §7 et annexe A.7). Les cinquante dossiers ci-dessus
// ne changent pas ; ceux-ci s'y ajoutent. AT-1 à AT-7 ne changent jamais la
// validité du dossier : leur attendu est donné à part (perimeter_checks).
{
  /** Écrit un dossier qui porte (ou déclare) la quatorzième partie, après avoir vérifié verdict, contrôles en échec, AT- et avertissements. */
  const ecrireDossierAT = (nom, fichiers, attendu) => {
    const rapport = J.verifierDossier(fichiers, { schemas: SCHEMAS });
    const at = rapport.attestation;
    const obtenu = {
      perimeter_checks: at ? at.checks.map((c) => ({ id: c.id, status: c.status, reason: c.reason })) : [],
      perimeter_retained: at ? at.retenue : null,
      warnings: at ? at.avertissements.map((w) => w.id) : [],
    };
    const attenduAT = { perimeter_checks: attendu.perimeter_checks, perimeter_retained: attendu.perimeter_retained, warnings: attendu.warnings };
    exiger(JSON.stringify(obtenu) === JSON.stringify(attenduAT), `${nom} : vérifications AT- ${JSON.stringify(obtenu)}, attendues ${JSON.stringify(attenduAT)} ; détails : ${JSON.stringify(at?.checks.map((c) => [c.id, c.detail?.fr]))}`);
    ecrireDossier(nom, fichiers, attendu);
  };
  // Statuts attendus de AT-1 à AT-7 : « r » réussi, « e » en échec, sinon la raison de non-exécution.
  const statuts = (...codes) => codes.map((c, i) => ({ id: `AT-${i + 1}`, status: c === "r" ? "reussi" : c === "e" ? "echoue" : "non_execute", reason: c === "r" || c === "e" ? null : c }));
  const PA = "partie_absente";
  const PR = "prerequis_en_echec";
  const HD = "piece_hors_dossier";
  const attenduAT = ({ valide = true, controle = null, controles_en_echec = [], cible = null, checks, retenue, warnings = [], description }) => ({ valide, controle, controles_en_echec, perimeter_target: cible, perimeter_checks: checks, perimeter_retained: retenue, warnings, description });
  const SANS_POINT = { points_de_controle: J.RAISON_AUCUN_POINT };
  const reindexer = (fichiers) => J.reindexerDossier(fichiers).fichiers;
  const FICHIER = J.PARTIE_ATTESTATION_PERIMETRE.file;

  const P = A.attestationExemple();
  const signee = A.signer(P);
  exiger(signee.digest === "0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd", `D_P de l'exemple de CT-7 §7.2 inattendu : ${signee.digest}`);
  const JEU = A.jeuExemple();
  exiger(JSON.stringify(JEU.members) === JSON.stringify(ADRESSES_HARDHAT) && JEU.source === SOURCE_APPROBATEURS, "jeu de l'attestation différent de celui des approbations des vecteurs");
  const partie = (sig = signee, jeuDeclare = JEU, inscription = null) => S.construirePartieAttestation({ signee: sig, approver_set: jeuDeclare, inscription });

  // Journal rejoué de CT-7 §7.5 : seq 12 annonce l'ensemble de politique réduit qui porte D_P.
  const doc = A.documentPolitique(signee.digest);
  const politique12 = { policy_version: "2026-11-05", policy_sha256: J.sha256(doc) };
  exiger(politique12.policy_sha256 === "0x5016ffc47d07a5ec0dae8c464a0a5cf466cd4f425fadbf293dafbd36617f63d9", "policy_sha256 du journal rejoué inattendu");
  const rejoue = construireJournal({ politique12 });
  const seq12 = rejoue.evenements.find((e) => e.seq === 12);
  exiger(seq12.hash === "0x5aac251a7fa898317e6fd40eae4594234960cf682e4a182cf2de0a9f65b0ef90", `hash du seq 12 rejoué inattendu : ${seq12.hash}`);
  exiger(J.verifierChaine(rejoue.evenements, { clesPubliques: rejoue.cles }).valide, "journal rejoué refusé");
  const partie12 = partie(signee, JEU, { event: seq12, policy_document: doc });
  exiger(J.sha256(Buffer.from(J.texteJSON(partie12), "utf8")) === "0x4e3f9bd1cbf51471154dab29848742103c619518fb962fc93869c26304c8a120", "partie du dossier valide-seq-12-attestation-inscrite différente de celle de CT-1 §11.2");

  const d12 = dossierPour(rejoue, 12, { raisons: SANS_POINT, attestation: partie12 });
  ecrireDossierAT("valide-seq-12-attestation-inscrite", d12.fichiers, attenduAT({ checks: statuts("r", "r", "r", "r", "r", "r", "r"), retenue: true, description: "Journal rejoué de CT-7 §7.5 : seq 12 (rec-test-02) annonce la politique 2026-11-05 dont le document réduit porte perimeter.attestation_digest = D_P de l'attestation de CT-7 §7.1. Dossier de seq 12, quatorze parties (la treizième absente, « aucun point de contrôle ») ; la partie porte l'attestation signée par les comptes Hardhat 1 et 2, le jeu des comptes 1 à 3 au seuil de 2, et l'inscription (seq 12 et le document en base64). AT-1 à AT-7 réussissent : attestation retenue et inscrite (clé rec-test-02, celle de l'événement prouvé) ; AT-7 ne compare que le nom de la version de politique, et l'énoncé dit « sous une version de politique de même nom que celle de cet événement » (CT-6 EX-6.19)." }));

  const F7 = dossierPour(jeu, 7, { raisons: SANS_POINT, attestation: partie() }).fichiers;
  ecrireDossierAT("valide-seq-7-attestation-sans-inscription", F7, attenduAT({ checks: statuts("r", "r", "r", "r", "r", PA, PA), retenue: true, description: "Dossier valide-seq-7 avec la quatorzième partie sans inscription (inscription vaut null) et la treizième absente : AT-1 à AT-5 réussissent, AT-6 et AT-7 ne sont pas exécutées (partie absente) ; l'attestation est retenue sans place dans le journal (CT-7 EX-7.12). Le jeu déclaré est celui de approbations.json : aucun avertissement." }));

  ecrireDossierAT("valide-seq-7-attestation-declaree-absente", dossierPour(jeu, 7, { raisons: { ...SANS_POINT, attestation_perimetre: J.RAISON_AUCUNE_ATTESTATION } }).fichiers, attenduAT({ checks: [], retenue: null, description: `Dossier valide-seq-7 dont l'index déclare quatorze parties, la treizième et la quatorzième absentes (« ${J.RAISON_AUCUN_POINT} », « ${J.RAISON_AUCUNE_ATTESTATION} ») : aucune vérification AT- n'est exécutée ni rapportée ; le dossier ne dit rien du périmètre (CT-7 EX-7.15).` }));

  // AT-7 : seq 13 annonce une autre politique, sans perimeter ; l'événement prouvé (seq 13) porte cette autre version.
  {
    const doc13 = Buffer.from(J.canonicaliserJCSIntegral({ version: "2026-11-06" }), "utf8");
    const prolonge = construireJournal({ politique12, politique13: { ts: T(10, 20, 0, 0), policy_version: "2026-11-06", policy_sha256: J.sha256(doc13) } });
    const ins = prolonge.evenements.find((e) => e.seq === 12);
    exiger(ins.hash === seq12.hash, "seq 12 du journal prolongé différent du journal rejoué");
    ecrireDossierAT("valide-seq-13-at7-autre-version", dossierPour(prolonge, 13, { raisons: SANS_POINT, attestation: partie12 }).fichiers, attenduAT({ cible: "AT-7", checks: statuts("r", "r", "r", "r", "r", "r", HD), retenue: true, warnings: ["AV-AT-3"], description: "Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui annonce la politique 2026-11-06, sans membre perimeter ; dossier de seq 13 dont la partie joint l'inscription seq 12. AT-6 réussit (seq 12 précède seq 13) ; AT-7 n'est pas exécutée (pièce hors dossier : l'ensemble de politique en vigueur pour l'événement n'est pas celui de l'inscription), avertissement AV-AT-3 ; l'attestation reste retenue, et l'énoncé dit « sans preuve qu'elle était en vigueur pour cet événement (version de politique différente) » (CT-6 EX-6.19)." }));
  }

  // AT-1 : la partie réduite au littéral null.
  ecrireDossierAT("valide-at1-partie-nulle", reindexer({ ...F7, [FICHIER]: J.texteJSON(null) }), attenduAT({ cible: "AT-1", checks: statuts("e", PR, PR, PR, PR, PR, PR), retenue: false, warnings: ["AV-AT-1"], description: "La partie attestation-perimetre.json est le littéral null (index recalculé) : AT-1 échoue, AT-2 à AT-7 ne sont pas exécutées (prérequis en échec), AV-AT-1 ; le dossier reste valide (CT-1 §11.4, CT-6 EX-5.11)." }));

  // AT-1 : la partie dépasse 4 Mio d'un octet (espaces de mise en forme), conforme à son schéma.
  {
    const texte = J.texteJSON(partie());
    const grand = texte.slice(0, -1) + " ".repeat(S.LIMITE_PARTIE_ATTESTATION + 1 - Buffer.byteLength(texte, "utf8")) + "\n";
    exiger(Buffer.byteLength(grand, "utf8") === S.LIMITE_PARTIE_ATTESTATION + 1, "taille de la partie de valide-at1-taille");
    ecrireDossierAT("valide-at1-taille", reindexer({ ...F7, [FICHIER]: grand }), attenduAT({ cible: "AT-1", checks: statuts("e", PR, PR, PR, PR, PR, PR), retenue: false, warnings: ["AV-AT-1"], description: `La partie fait ${S.LIMITE_PARTIE_ATTESTATION + 1} octets (4 Mio plus un octet) : la même partie que valide-seq-7-attestation-sans-inscription, complétée par des espaces de mise en forme avant le saut de ligne final, donc conforme à son schéma. Au-delà de la limite de CT-6 EX-4.15 : AT-1 échoue, AT-2 à AT-7 ne sont pas exécutées, AV-AT-1 ; D-2 réussit (SHA-256 de l'index exact), le dossier reste valide.` }));
  }

  // AT-3 : la signature du compte 3 déclarée pour le compte 2 (CT-7 §7.2).
  {
    const sub = structuredClone(signee);
    sub.signatures[1].signature = A.signature(P, 3).signature;
    exiger(sub.signatures[1].signature === "0x3daebe7960d9870ebf2d5a03492283474286dbf28f7e53f20b51ba60f6e01cd603332971435717c899b12c9dd0a37aa7704e9500645a67732f7821eaf034648b1c", "signature du compte 3 de CT-7 §7.2 inattendue");
    ecrireDossierAT("valide-at3-signature-substituee", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(sub)) }), attenduAT({ cible: "AT-3", checks: statuts("r", "r", "e", PR, "r", PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "La signature du compte Hardhat 3 sur D_P est déclarée pour le compte 2 (cas invalide-at3-signature-substituee de CT-7 annexe A.6) : l'adresse recouvrée est 0x90f79bf6eb2c4f870365e785982e1f101e93b906, AT-3 échoue, AT-4 n'est pas exécutée, AV-AT-1 ; le dossier reste valide." }));
  }

  // AT-4 réussie avec un jeu déclaré différent de celui de approbations.json : AV-AT-2.
  {
    const jeu124 = { threshold: { required: 2, size: 3 }, members: [A.adresse(1), A.adresse(2), A.adresse(4)], source: "comptes Hardhat 1, 2 et 4 (vecteurs CT-7)" };
    ecrireDossierAT("valide-at4-jeu-different", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(signee, jeu124)) }), attenduAT({ cible: "AT-4", checks: statuts("r", "r", "r", "r", "r", PA, PA), retenue: true, warnings: ["AV-AT-2"], description: "Le jeu déclaré par la partie est celui des comptes Hardhat 1, 2 et 4 (seuil de 2 sur 3), approbations.json déclare les comptes 1 à 3 : AT-4 réussit (les comptes 1 et 2 sont membres des deux jeux), l'attestation est retenue, et AV-AT-2 signale les deux jeux différents." }));
  }

  // AT-5 : l'attestation ne couvre pas le journal de l'événement.
  {
    const P5 = A.attestationExemple();
    P5.journals = P5.journals.filter((j) => j.name === "journal-principal");
    P5.agents = P5.agents.filter((a) => a.journal_id === A.JOURNAL_PRINCIPAL);
    ecrireDossierAT("valide-at5-autre-journal", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(A.signer(P5))) }), attenduAT({ cible: "AT-5", checks: statuts("r", "r", "r", "r", "e", PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "Attestation (signée par les comptes 1 et 2) qui ne couvre que journal-principal et son agent : l'événement prouvé est de journal-sinistres, AT-5 échoue, AV-AT-1 ; le dossier reste valide." }));
  }
  {
    const P5 = A.attestationExemple();
    P5.validity = { from: "2026-11-01T00:00:00.000Z", until: "2026-11-04T23:59:59.999Z" };
    ecrireDossierAT("valide-at5-hors-validite", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(A.signer(P5))) }), attenduAT({ cible: "AT-5", checks: statuts("r", "r", "r", "r", "e", PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "Attestation valable du 1er au 4 novembre 2026 (signée par les comptes 1 et 2), événement prouvé du 5 novembre : ts hors de la validité, AT-5 échoue, AV-AT-1 ; le dossier reste valide." }));
  }

  // AT-6 : inscription postérieure à l'événement prouvé (dossier de seq 11 du journal rejoué).
  ecrireDossierAT("valide-at6-inscription-posterieure", dossierPour(rejoue, 11, { raisons: SANS_POINT, attestation: partie12 }).fichiers, attenduAT({ cible: "AT-6", checks: statuts("r", "r", "r", "r", "r", "e", PR), retenue: false, warnings: ["AV-AT-1"], description: "Dossier de seq 11 du journal rejoué, dont la partie joint l'inscription seq 12 : l'inscription suit l'événement prouvé (seq et ts), AT-6 échoue, AT-7 n'est pas exécutée (prérequis en échec), AV-AT-1 ; le dossier reste valide." }));

  // AT-6 : document de politique qui porte un autre condensé (journal rejoué en conséquence).
  {
    const autre = J.sha256(Buffer.from("noortrace/vecteurs/ct7/autre-attestation", "utf8"));
    const docAutre = A.documentPolitique(autre);
    const jeuAutre = construireJournal({ politique12: { policy_version: "2026-11-05", policy_sha256: J.sha256(docAutre) } });
    const insAutre = jeuAutre.evenements.find((e) => e.seq === 12);
    ecrireDossierAT("valide-at6-document-autre-condense", dossierPour(jeuAutre, 12, { raisons: SANS_POINT, attestation: partie(signee, JEU, { event: insAutre, policy_document: docAutre }) }).fichiers, attenduAT({ cible: "AT-6", checks: statuts("r", "r", "r", "r", "r", "e", PR), retenue: false, warnings: ["AV-AT-1"], description: "Journal rejoué dont seq 12 annonce un document de politique dont perimeter.attestation_digest est SHA-256(« noortrace/vecteurs/ct7/autre-attestation ») et non D_P (événement rescellé, dossier de seq 12) : AT-6 échoue, AV-AT-1 ; le dossier reste valide." }));
  }

  // AT-6 : événement d'inscription signé par rec-test-01 alors qu'il nomme rec-test-02 (seule la partie change).
  {
    const pk = J.analyserJSONStrict(d12.fichiers[FICHIER]);
    pk.inscription.event.sig = J.signerEvenement(pk.inscription.event, CLES_PRIVEES["rec-test-01"]);
    ecrireDossierAT("valide-at6-inscription-signature-fausse", reindexer({ ...d12.fichiers, [FICHIER]: J.texteJSON(pk) }), attenduAT({ cible: "AT-6", checks: statuts("r", "r", "r", "r", "r", "e", PR), retenue: false, warnings: ["AV-AT-1"], description: "Dossier valide-seq-12-attestation-inscrite dont l'événement d'inscription joint à la partie est signé par rec-test-01 alors qu'il nomme rec-test-02 (hash inchangé, evenement.json intact) : la signature est invalide sous la clé nommée, AT-6 échoue, AV-AT-1 ; le dossier reste valide." }));
  }

  // AT-6 : inscription forgée sous une clé que le dossier déclare lui-même (CT-7 MN-84, MN-90) :
  // une clé rec-forge-01, dérivée d'une étiquette publique, ajoutée à cles.json, signe un
  // événement noortrace.journal.politique seq 2 qui porte D_P. La clé n'est pas celle de
  // l'événement prouvé : rien ne la relie au journal, AT-6 n'est pas exécutée (ancre_absente).
  {
    const ev7 = lireF(F7, "evenement.json");
    const forge = J.cleEd25519DepuisGraine(J.sha256(Buffer.from("noortrace/vecteurs/ct7/rec-forge-01", "utf8")));
    const cles7 = lireF(F7, "cles.json");
    cles7.keys.push({ key_id: "rec-forge-01", algorithm: "ed25519", public_key: forge.clePublique, valid_from: "2026-11-01T00:00:00.000Z", valid_to: null, source: SOURCE_CLES });
    const docForge = A.documentPolitique(signee.digest, ev7.code.policy_version);
    const insForge = J.scellerEvenement({
      version: 0, seq: 2, ts: "2026-11-05T09:10:00.000Z", org_id: ev7.org_id, journal_id: ev7.journal_id,
      prev_hash: J.sha256(Buffer.from("noortrace/vecteurs/ct7/prev-hash-forge", "utf8")), recorder_key_id: "rec-forge-01",
      delegation: { launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null },
      code: CODE_JOURNAL(ev7.code.policy_version), intent: null, policy: POLICY("sans_objet"), approval: null,
      execution: EXEC(J.OUTIL_POLITIQUE, { args: J.referenceEnLigne({ policy_version: ev7.code.policy_version, policy_sha256: J.sha256(docForge) }) }),
      effects: [], context: [],
    }, forge.clePrivee);
    const fichiersForge = { ...remplacer(F7, "cles.json", cles7), [FICHIER]: J.texteJSON(partie(signee, JEU, { event: insForge, policy_document: docForge })) };
    ecrireDossierAT("valide-at6-cle-non-ancree", reindexer(fichiersForge), attenduAT({ cible: "AT-6", checks: statuts("r", "r", "r", "r", "r", "ancre_absente", PR), retenue: true, description: "Dossier valide-seq-7-attestation-sans-inscription où l'exportateur ajoute à cles.json une clé rec-forge-01 (graine = SHA-256 de « noortrace/vecteurs/ct7/rec-forge-01 ») et joint une inscription forgée : seq 2, 09:10:00.000Z, signée par rec-forge-01, document de politique portant D_P sous la version de l'événement prouvé. L'événement prouvé (seq 7) est signé par rec-test-01 : la clé de l'inscription n'est pas la sienne, rien ne la relie au journal, AT-6 n'est pas exécutée (ancre_absente) et AT-7 non plus (prérequis) ; l'attestation est retenue sans clause d'inscription (CT-6 EX-6.19), le dossier reste valide (CT-7 MN-84, MN-90)." }));
  }

  // AT-2 : condensé d'une autre attestation (issued_at différent), sans inscription : AT-6 et AT-7 non exécutées, partie absente (priorité, CT-6 EX-5.12).
  {
    const autre = A.attestationExemple();
    autre.issued_at = "2026-10-31T16:00:00.000Z";
    const faux = { ...signee, digest: S.condenseAttestation(autre) };
    ecrireDossierAT("valide-at2-condense-faux", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(faux)) }), attenduAT({ cible: "AT-2", checks: statuts("r", "e", "r", "r", "r", PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "signed.digest est le D_P d'une autre attestation (issued_at du 31 octobre) : AT-2 échoue ; AT-3 et AT-4 réussissent, les signatures portant sur le D_P recalculé ; inscription nulle, AT-6 et AT-7 ne sont pas exécutées, partie absente (la raison partie_absente l'emporte sur l'échec d'AT-2, CT-6 EX-5.12) ; AV-AT-1 ; le dossier reste valide (CT-6 EX-5.11, V-10)." }));
  }

  // AT-4 : une seule signature (compte 1) pour un seuil de 2.
  ecrireDossierAT("valide-at4-seuil-non-atteint", reindexer({ ...F7, [FICHIER]: J.texteJSON(partie(A.signer(P, [1]))) }), attenduAT({ cible: "AT-4", checks: statuts("r", "r", "r", "e", "r", PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "L'attestation n'est signée que par le compte Hardhat 1, pour un jeu déclaré au seuil de 2 sur 3 : AT-3 réussit, AT-4 échoue, AV-AT-1 ; le dossier reste valide (CT-6 EX-5.11, V-10)." }));

  // AT-5 non exécutée faute d'evenement.json exploitable : attestation non retenue sans AT- en échec (CT-6 EX-6.19, 5.5).
  {
    const ev7 = lireF(F7, "evenement.json");
    ecrireDossierAT("invalide-e1-attestation-non-executee", reindexer(remplacer(F7, "evenement.json", { ...ev7, extra: true })), attenduAT({ valide: false, controle: "E-1", controles_en_echec: ["E-1", "E-7", "E-8", "C-2", "M-1"], cible: "AT-5", checks: statuts("r", "r", "r", "r", PR, PA, PA), retenue: false, warnings: ["AV-AT-1"], description: "evenement.json de valide-seq-7-attestation-sans-inscription porte un membre hors schéma (extra) : E-1 échoue, avec E-7, E-8, C-2 et M-1 que le hash recalculé met en échec, et le dossier est invalide. AT-1 à AT-4 réussissent ; AT-5 n'est pas exécutée (evenement.json inexploitable) ; inscription nulle, AT-6 et AT-7 non exécutées (partie absente). Aucune AT- n'est en échec, et l'attestation n'est pas retenue : AV-AT-1 nomme AT-5, non exécutée (CT-6 5.5)." }));
  }

  // AT-7, nom de version réannoncé (CT-7 MN-91, PA-9) : seq 13 annonce, sous le même nom 2026-11-05,
  // un document sans perimeter ; l'événement prouvé (seq 13) porte ce nom. AT-7 réussit sur le nom.
  {
    const doc13 = Buffer.from(J.canonicaliserJCSIntegral({ version: "2026-11-05" }), "utf8");
    const reannonce = construireJournal({ politique12, politique13: { ts: T(10, 20, 0, 0), policy_version: "2026-11-05", policy_sha256: J.sha256(doc13) } });
    exiger(reannonce.evenements.find((e) => e.seq === 12).hash === seq12.hash, "seq 12 du journal réannoncé différent du journal rejoué");
    ecrireDossierAT("valide-at7-nom-reannonce", dossierPour(reannonce, 13, { raisons: SANS_POINT, attestation: partie12 }).fichiers, attenduAT({ cible: "AT-7", checks: statuts("r", "r", "r", "r", "r", "r", "r"), retenue: true, description: "Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui annonce, sous le même nom de version 2026-11-05, un autre document de politique, sans membre perimeter (ce que CT-2 0.5 n'interdit pas au démarrage tant que PA-9 n'est pas adoptée) ; dossier de seq 13 dont la partie joint l'inscription seq 12. AT-6 et AT-7 réussissent : AT-7 ne compare que des noms. L'énoncé dit seulement « sous une version de politique de même nom que celle de cet événement », jamais que l'attestation était en vigueur (CT-7 MN-91, RA-75)." }));
  }

  // AT-7, attestation remplacée : seq 13 inscrit une attestation B (une exception de plus) sous la version 2026-11-06 ;
  // l'exportateur joint l'attestation A et son inscription seq 12 au dossier de seq 13.
  {
    const PB = A.attestationExemple();
    PB.issued_at = "2026-11-05T10:15:00.000Z";
    PB.not_captured.push({ channel: "agent-principal, appels directs", description: "Un agent découvert après l'attestation précédente appelle un service sans passer par le mandataire.", compensating_control: null });
    const docB = A.documentPolitique(S.condenseAttestation(PB), "2026-11-06");
    const remplace = construireJournal({ politique12, politique13: { ts: T(10, 20, 0, 0), policy_version: "2026-11-06", policy_sha256: J.sha256(docB) } });
    exiger(remplace.evenements.find((e) => e.seq === 12).hash === seq12.hash, "seq 12 du journal remplacé différent du journal rejoué");
    ecrireDossierAT("valide-at7-attestation-remplacee", dossierPour(remplace, 13, { raisons: SANS_POINT, attestation: partie12 }).fichiers, attenduAT({ cible: "AT-7", checks: statuts("r", "r", "r", "r", "r", "r", HD), retenue: true, warnings: ["AV-AT-3"], description: "Journal rejoué prolongé d'un seq 13 (10:20:00.000Z) qui inscrit une attestation B (issued_at 10:15, une exception de capture de plus) sous la version 2026-11-06 ; l'exportateur joint au dossier de seq 13 l'attestation A et son inscription seq 12. AT-6 réussit ; AT-7 n'est pas exécutée (pièce hors dossier), AV-AT-3 ; l'attestation A est retenue, et l'énoncé dit « sans preuve qu'elle était en vigueur pour cet événement » (CT-6 EX-6.19, CT-7 EX-7.11)." }));
  }

  // D-2 : SHA-256 de la partie remplacé dans l'index ; l'attestation elle-même est intacte.
  {
    const idx = lireF(F7, "dossier.json");
    idx.parts.find((p) => p.name === J.PARTIE_ATTESTATION_PERIMETRE.name).sha256 = J.sha256(Buffer.from("noortrace/vecteurs/ct7/autre-partie", "utf8"));
    ecrireDossierAT("invalide-d2-attestation-sha256", remplacer(F7, "dossier.json", idx), attenduAT({ valide: false, controle: "D-2", controles_en_echec: ["D-2"], checks: statuts("r", "r", "r", "r", "r", PA, PA), retenue: true, description: "Dossier valide-seq-7-attestation-sans-inscription dont l'index déclare pour attestation-perimetre.json un autre SHA-256 : D-2 échoue et le dossier est invalide, parce que l'index n'est plus celui que l'exportateur a scellé (CT-1 §11.4) ; l'attestation elle-même est vérifiée et retenue, sans effet sur ce verdict." }));
  }
}

// 7. INDEX.md ------------------------------------------------------------
const dossiersEcrits = [...new Set(ecrits.filter((f) => f.startsWith("dossiers/")).map((f) => f.split("/")[1]))];
const lignesDossiers = dossiersEcrits.map((d) => {
  const a = JSON.parse(fs.readFileSync(path.join(SORTIE, "dossiers", d, "attendu.json"), "utf8"));
  const verdict = a.valide ? "valide" : `**${a.controle}**${a.controles_en_echec.length > 1 ? ` (en échec : ${a.controles_en_echec.join(", ")})` : ""}`;
  // Révision 0.4 : la vérification AT- visée (sans effet sur le verdict) et l'attestation retenue ou non.
  const at = a.perimeter_checks === undefined ? "" : a.perimeter_checks.length === 0 ? " ; aucune AT-" : ` ; ${a.perimeter_target ? `${a.perimeter_target} visée, ` : ""}attestation ${a.perimeter_retained ? "retenue" : "non retenue"}${a.warnings.length ? ` (${a.warnings.join(", ")})` : ""}`;
  return `| \`${d}/\` | ${verdict}${at} | ${a.description} |`;
});
ecrire(
  "INDEX.md",
  `# Vecteurs de test CT-1

Produits par \`scripts/vecteurs/generer-ct1.mjs\` (\`node scripts/vecteurs/generer-ct1.mjs\`),
rejoués par \`test/journal.test.js\`. Tout est déterministe : rejouer le générateur
produit exactement les mêmes octets. Les clés JSON sont en anglais (formats de
CT-1) ; les descriptions, en français. Chaque répertoire porte un \`attendu.json\`
qui dit ce qu'un vérificateur conforme doit obtenir.

Le générateur n'écrit que les entrées décrites ici (\`${ENTREES_GENEREES.join("`, `")}\`),
qu'il efface et réécrit à chaque exécution ; toute autre entrée du répertoire
est laissée telle quelle (le vérificateur indépendant Go de
\`verificateur-independant/\`, par exemple, qui confronte tous ces vecteurs).

Les constantes des vecteurs (journal \`journal-sinistres\`, étiquettes de nonce
\`noortrace/vecteurs/v0/nonce/journal-sinistres/periode-N\`) sont celles de la
seconde table de CT-1 §13 ; elles diffèrent de celles de l'exemple de référence
de la spécification (journal \`journal-principal\`, annexe A).

Journal fictif : organisation \`${ORG_SLUG}\` (\`org_id\` = keccak256 du slug),
journal \`${JOURNAL_NOM}\` (\`journal_id\` = keccak256 du nom), un agent qui instruit
et règle un sinistre automobile le 5 novembre 2026 entre 09:12 et 10:05 UTC.
Clés d'enregistreur \`rec-test-01\` puis \`rec-test-02\` (rotation en seq 9) ;
approbateurs : comptes 1 à 3 du mnémonique Hardhat, seuil 2 sur 3.

## \`cles/\`

| Fichier | Contenu |
|---|---|
| \`cles-test.json\` | Les deux paires Ed25519 de test (étiquette de graine, graine, clé privée PKCS#8, clé publique, validité), les trois comptes d'approbateur (mnémonique, chemin, adresse, clé privée) et les nonces des périodes, avec leur dérivation. Clés jetables et publiques. |
| \`cles.json\` | Les mêmes clés publiques au format \`cles.json\` d'un dossier (CT-1 §11.2), avec la validité annoncée : \`rec-test-01\` de ${VALID_FROM_01} à ${TS_ROTATION} (instant de la rotation, inclus), \`rec-test-02\` à partir de ${TS_ROTATION}. |

## \`jcs/\`

\`cas-limites.json\` : les cas limites de la forme canonique JCS v0 de CT-1 §4,
chacun avec \`name\`, \`input\` (un texte JSON) et \`canonical\` (la forme canonique,
ou \`null\` si le document est invalide : nombre non entier ou hors de
l'intervalle sûr, substitut isolé, clé en double).

## \`journal-valide/\`

Douze événements (\`evenements.json\`) : échange avec le modèle (seq 1, 4, 10),
appels d'outil autorisés (seq 2, 3, 8 ; seq 2 et 3 portent des arguments en ligne),
appel retenu pour approbation (seq 5, ticket \`apr-2201\`, arguments rédigés
\`pii-v1\`), décision d'approbation signée EIP-191 par les comptes Hardhat 1 et 2
(seq 6), appel relayé après approbation (seq 7), rotation de clé contresignée
(seq 9, dernier événement de la période 1), appel refusé par la politique
(seq 11), changement de politique (seq 12). \`attendu.json\` : chaîne valide,
hash, signature, \`prev_hash\` et longueur canonique de chaque événement, objet
d'approbation \`A\` et son condensé \`D_A\`. \`pieces.json\` : les pièces référencées
(octets UTF-8, \`sha256\`, \`length\`). \`cles.json\` : les clés publiques nécessaires.

## \`journal-supprime/\`, \`journal-modifie/\`, \`journal-insere/\`, \`journal-insere-sans-cle/\`, \`journal-reordonne/\`

Le même journal altéré ; \`attendu.json\` donne la liste exacte des contrôles en
échec (\`controles_en_echec\`, table 7.2 de CT-1 : tous les symptômes sont
rapportés, chaque événement pour lui-même puis chaque couple consécutif dans
l'ordre du fichier), les diagnostics nommés de l'implémentation de référence
(\`type\`, \`controle\`, \`seq\`) et les messages produits.

| Répertoire | Altération | Contrôles en échec | Diagnostics |
|---|---|---|---|
| \`journal-supprime/\` | seq 4 retiré | C-1, C-2 | \`suppression\` (C-1) et \`rupture\` (C-2) en seq 5 |
| \`journal-modifie/\` | \`intent\` de seq 7 modifié, \`hash\` et \`sig\` inchangés | E-7, E-8, C-2 | \`modification\` (E-7) et \`signature\` (E-8) en seq 7, \`rupture\` (C-2) en seq 8 |
| \`journal-insere/\` | événement forgé, signé avec la clé de l'enregistreur, inséré entre seq 4 et seq 5 avec seq 5 | C-1, C-2 | \`insertion\` (C-1), \`rupture\` (C-2) et \`horodatage\` (C-1) en seq 5 |
| \`journal-insere-sans-cle/\` | même insertion, signée par une autre clé que celle annoncée | E-8, C-1, C-2 | \`signature\` (E-8) en plus des trois précédents |
| \`journal-reordonne/\` | seq 5 et seq 6 échangés de place | C-1, C-2 | \`reordonnancement\` (C-1) en seq 5, \`rupture\` (C-2) en seq 6, 5 et 7, \`horodatage\` (C-1) en seq 5 |

La troncature de la fin du journal n'est pas détectable par la chaîne seule
(CT-1 §7.2) : elle relève du manifeste (P-3, P-4) ; le dossier
\`dossiers/invalide-periode-tronquee/\` en donne le cas.

## \`merkle/\`

\`arbres.json\` : arbres RFC 6962 de 0, 1, 2, 3, 5, 8, 12 et 1000 feuilles
(feuilles, racine, preuves d'inclusion pour des indices choisis, dont le premier
et le dernier ; toutes les feuilles pour n = 5, la forme de l'exemple de
CT-1 §9.4). La période vide a la racine nulle (convention NOORTRACE de
\`PeriodRegistry\`), distinguée de SHA-256("") de la RFC 6962.

\`coherence.json\` (révision 0.3) : preuves de cohérence RFC 9162 §2.1.4 (CT-1
§10.7) entre les arbres de \`arbres.json\`, paires \`(1, 2)\`, \`(2, 3)\`, \`(3, 5)\`,
\`(5, 8)\`, \`(8, 12)\`, \`(4, 8)\`, \`(4, 12)\`, \`(1, 12)\`, \`(12, 12)\` (preuve vide), et
sondes refusées (\`m = 0\`, \`m > n\`, chemin tronqué, nœud en trop, racines
échangées, chemin vide, \`m = n\` avec chemin). Chaque cas donne \`first_size\`,
\`second_size\`, \`first_root\`, \`second_root\`, \`path\`, \`valid\` et \`reason\`.

## \`manifestes/\`

Trois périodes consécutives du journal : \`periode-1.json\` (seq 1 à 9, signé par
\`rec-test-02\`, clé en vigueur à la clôture puisque seq 9 est la rotation),
\`periode-2.json\` (seq 10 à 12), \`periode-3.json\` (vide : \`last_seq = first_seq - 1\`,
racine nulle), chacun avec sa signature \`.sig\`. \`discontinu.json\` prétend suivre
la période 1 avec \`first_seq\` 11 et un \`prev_period_hash\` faux. \`attendu.json\` :
forme canonique, \`periodHash\`, signature, \`anchorFingerprint\` et \`PeriodMeta\` de
chaque période, continuité attendue, erreurs du manifeste discontinu.

## \`points-de-controle/\` (révision 0.3)

Séries complètes des points de contrôle (CT-1 §10.5 à §10.8) des trois
périodes : \`periode-N.json\` est le tableau des points, un par minute depuis
\`period_start\` (cadence par défaut de 60 s, à \`:00.000\`, points sans nouvel
événement compris) puis le point de clôture à \`generated_at\` du manifeste
(\`tree_size = count\`) ; 61 points par période. \`tree_size\` compte les
événements de la période horodatés au plus tard à \`checkpoint_ts\` ; la clé est
celle en vigueur (règle 5 : la rotation de seq 9 à ${TS_ROTATION} fait signer le
point de clôture de la période 1 par \`rec-test-02\`) ; la période 3, vide, ne
porte que des points \`tree_size = 0\` dont \`last_hash\` est le hash de seq 12.
\`attendu.json\` donne, pour chaque point, \`checkpoint_hash\`, la forme canonique
\`C_K\`, le \`prev_checkpoint_hash\` attendu, la clé et la preuve de cohérence vers
la racine du manifeste (\`null\` pour \`tree_size = 0\`), et pour chaque série
invalide de \`invalides/\` (dérivée de la période 1) les règles violées
(\`rules_failed\` : \`chainage\`, \`tree_size_decroissant\`,
\`checkpoint_ts_decroissant\`, \`dernier_point\`, \`cle_en_vigueur\`,
\`validite_cle\`, \`signature\`, \`last_hash\`) et les erreurs de l'implémentation
de référence.

## \`dossiers/\`

Chaque sous-répertoire est un dossier de preuve v0 complet (les douze parties
déclarées dans \`dossier.json\`, les cinq parties réservées à CT-4 et CT-5
absentes avec la raison « ${J.RAISON_HORS_PERIMETRE} » ; révision 0.3 : les
dossiers \`*-point-de-controle\`, \`*-partie-declaree-absente\` et \`invalide-k*\`
déclarent une treizième partie \`points-de-controle.json\`, vérifications K-1 à
K-6, ancres à \`null\` ; révision 0.4 : les dossiers \`*attestation*\`,
\`valide-at*\` et \`valide-seq-13-at7-autre-version\` déclarent quatorze
parties, la quatorzième \`attestation-perimetre.json\`, vérifications AT-1 à
AT-7, sans effet sur le verdict, CT-7 annexe A.7) plus un fichier
\`attendu.json\`, étranger au dossier et ignoré par le vérificateur, qui donne le
verdict attendu : \`valide\`, \`controle\` (le contrôle visé), \`controles_en_echec\`
(la liste **exacte** des contrôles en échec, dans l'ordre de CT-1 §11.4) et une
description. Chaque contrôle de la table 11.4 a au moins un dossier qui le fait
échouer (CT-1 §11.5). Sauf mention contraire, les dossiers invalides sont dérivés
de \`valide-seq-7\` et leur index est recalculé après l'altération, pour que seul
le contrôle visé échoue ; quand une cascade est inévitable, elle est listée.
« Journal rejoué » : l'altération est faite à la source et la chaîne, les
manifestes et le dossier sont recalculés.

Révision 0.4 (CT-1 §11.5, CT-7 annexe A.7) : l'\`attendu.json\` d'un dossier
qui déclare la quatorzième partie donne en plus \`perimeter_target\` (la
vérification AT- que le dossier exerce : en échec, non exécutée avec sa raison,
ou réussie quand le cas vise un avertissement, AV-AT-2 pour
\`valide-at4-jeu-different\` ; \`null\` pour les dossiers de référence et
pour \`invalide-d2-attestation-sha256\`), \`perimeter_checks\` (statut et raison de
AT-1 à AT-7, dans l'ordre ; vide quand la partie est déclarée absente),
\`perimeter_retained\` (attestation retenue, CT-6 EX-6.19 ; \`null\` sans la
partie) et \`warnings\` (avertissements AV-AT-). L'attestation est celle de
CT-7 §7.1, signée par les comptes Hardhat 1 et 2 (D_P
\`0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd\`) ; le
« journal rejoué de CT-7 §7.5 » est \`journal-valide\` dont seq 12 annonce le
document de politique réduit
\`{"perimeter":{"attestation_digest":D_P},"version":"2026-11-05"}\` (hash
\`0x5aac251a7fa898317e6fd40eae4594234960cf682e4a182cf2de0a9f65b0ef90\`). Une
vérification AT- en échec ne rend jamais le dossier invalide ; seule D-2 porte
sur le fichier de la partie.

| Répertoire | Verdict attendu | Altération |
|---|---|---|
${lignesDossiers.join("\n")}

Vérification d'un dossier : \`node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7\`
(code 0), \`node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux --json\`
(code 1, \`controles[].ok === false\` pour E-7).
`,
);

console.log(`${ecrits.length} fichiers écrits dans ${SORTIE}`);
