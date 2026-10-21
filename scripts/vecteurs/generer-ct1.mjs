#!/usr/bin/env node
// Génère, de façon DÉTERMINISTE, les vecteurs de test de la spécification CT-1
// dans spec/vecteurs/ct-1/ : clés de test, cas limites de la forme canonique,
// journal fictif d'un assureur (douze événements), journaux altérés avec leur
// diagnostic, arbres de Merkle, manifestes de période, dossiers de preuve
// valides et invalides (au moins un par contrôle de CT-1 §11.4), et l'index
// INDEX.md qui les décrit.
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
// demandeRefusee (seq 5 refusé par la politique au lieu d'être retenu).
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
      execution: EXEC(J.OUTIL_POLITIQUE, { args: J.referenceEnLigne({ policy_version: "2026-11-05", policy_sha256: J.sha256(Buffer.from(PIECES.politique, "utf8")) }) }),
      effects: [], context: [],
    },
  ];
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

/** Le dossier de l'événement `seq` d'un journal construit. */
function dossierPour(jeu, seq) {
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
    generated_at: GENERATED_AT_DOSSIER,
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

const SCHEMAS = J.registreSchemas(["evenement", "manifeste", "dossier"].map((n) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", `${n}-v0.schema.json`), "utf8"))));

function exiger(condition, message) {
  if (!condition) throw new Error(`génération interrompue : ${message}`);
}

// Le générateur ne possède que ses propres entrées : il les efface avant de les
// réécrire (aucun fichier périmé ne survit) et laisse intact tout ce que
// d'autres déposent dans le répertoire des vecteurs (par exemple un
// vérificateur indépendant).
export const ENTREES_GENEREES = ["INDEX.md", "cles", "jcs", "journal-valide", "journal-supprime", "journal-modifie", "journal-insere", "journal-insere-sans-cle", "journal-reordonne", "merkle", "manifestes", "dossiers"];
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

// 7. INDEX.md ------------------------------------------------------------
const dossiersEcrits = [...new Set(ecrits.filter((f) => f.startsWith("dossiers/")).map((f) => f.split("/")[1]))];
const lignesDossiers = dossiersEcrits.map((d) => {
  const a = JSON.parse(fs.readFileSync(path.join(SORTIE, "dossiers", d, "attendu.json"), "utf8"));
  return `| \`${d}/\` | ${a.valide ? "valide" : `**${a.controle}**${a.controles_en_echec.length > 1 ? ` (en échec : ${a.controles_en_echec.join(", ")})` : ""}`} | ${a.description} |`;
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

## \`manifestes/\`

Trois périodes consécutives du journal : \`periode-1.json\` (seq 1 à 9, signé par
\`rec-test-02\`, clé en vigueur à la clôture puisque seq 9 est la rotation),
\`periode-2.json\` (seq 10 à 12), \`periode-3.json\` (vide : \`last_seq = first_seq - 1\`,
racine nulle), chacun avec sa signature \`.sig\`. \`discontinu.json\` prétend suivre
la période 1 avec \`first_seq\` 11 et un \`prev_period_hash\` faux. \`attendu.json\` :
forme canonique, \`periodHash\`, signature, \`anchorFingerprint\` et \`PeriodMeta\` de
chaque période, continuité attendue, erreurs du manifeste discontinu.

## \`dossiers/\`

Chaque sous-répertoire est un dossier de preuve v0 complet (les douze parties
déclarées dans \`dossier.json\`, les cinq parties réservées à CT-4 et CT-5
absentes avec la raison « ${J.RAISON_HORS_PERIMETRE} ») plus un fichier
\`attendu.json\`, étranger au dossier et ignoré par le vérificateur, qui donne le
verdict attendu : \`valide\`, \`controle\` (le contrôle visé), \`controles_en_echec\`
(la liste **exacte** des contrôles en échec, dans l'ordre de CT-1 §11.4) et une
description. Chaque contrôle de la table 11.4 a au moins un dossier qui le fait
échouer (CT-1 §11.5). Sauf mention contraire, les dossiers invalides sont dérivés
de \`valide-seq-7\` et leur index est recalculé après l'altération, pour que seul
le contrôle visé échoue ; quand une cascade est inévitable, elle est listée.
« Journal rejoué » : l'altération est faite à la source et la chaîne, les
manifestes et le dossier sont recalculés.

| Répertoire | Verdict attendu | Altération |
|---|---|---|
${lignesDossiers.join("\n")}

Vérification d'un dossier : \`node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7\`
(code 0), \`node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux --json\`
(code 1, \`controles[].ok === false\` pour E-7).
`,
);

console.log(`${ecrits.length} fichiers écrits dans ${SORTIE}`);
