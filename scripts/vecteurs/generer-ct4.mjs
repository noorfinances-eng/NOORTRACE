#!/usr/bin/env node
// Générateur des vecteurs de CT-4 (spec/CT-4-registre.md, annexe A) :
// spec/vecteurs/ct-4/.
//
//   node scripts/vecteurs/generer-ct4.mjs [--sortie <répertoire ct-4>]
//   npm run vecteurs:ct4
//
// --sortie doit nommer un répertoire inexistant, vide, ou dont chaque entrée
// de premier niveau est l'une de celles que le générateur écrit
// (ENTREES_GENEREES) ou verificateur-independant/ ; sinon le générateur
// refuse sans rien effacer (EX-A.1). Il n'efface jamais que ses propres
// entrées, jamais verificateur-independant/.
//
// Familles (A.3, A.4) : constantes.json, identifiants.json, doctypes.json,
// empreintes.json, condenses.json, appels.json, transactions.json,
// manifestes/, demandes/, inscription/, capture/ et INDEX.md.
//
// Entrées lues, jamais réécrites (EX-A.2) : spec/vecteurs/ct-1/manifestes/,
// spec/vecteurs/ct-1/cles/, la capture de CT-6
// (spec/vecteurs/ct-6/registre/capture/), test/fixtures/certificat-commit/
// validators.json, chain/config/alloc-dev.json et l'exemple de manifeste
// d'instance de CT-4 §4.8 (lu dans la spécification). Aucun réseau, aucun
// artefact de compilation (hh-artifacts/) : les signatures de fonctions et
// d'événements sont celles de 5.7 et 6.7.1.
//
// Tout est déterministe : clés de graines publiées (A.2), horodatages fixes,
// signatures secp256k1 RFC 6979. Chaque attendu est posé par conception
// (verdict et code de chaque cas) puis confronté à l'implémentation de
// référence scripts/lib/conventions-registre.mjs : un écart arrête la
// génération. Les exemples de 7.7, 7.10 et 9.4 de la spécification sont
// recalculés et doivent être égaux, valeur pour valeur, aux blocs imprimés.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDNodeWallet, SigningKey, computeAddress } from "ethers";
import * as C from "../lib/conventions-registre.mjs";
import * as J from "../lib/journal.mjs";
import { analyserEnveloppe, clePubliqueDe, hachageJeuValidateurs, signerProposition, signerVote, VOTE_PRECOMMIT } from "../lib/certificat-commit.mjs";
import { hachageBlocBFT, octetsEntier, racineRecus, rlp } from "../lib/registre.mjs";

const RACINE = fileURLToPath(new URL("../../", import.meta.url));
export const REPERTOIRE_CT4 = path.join(RACINE, "spec", "vecteurs", "ct-4");
const REP_CT1 = path.join(RACINE, "spec", "vecteurs", "ct-1");
const REP_CAPTURE = path.join(RACINE, "spec", "vecteurs", "ct-6", "registre", "capture");
const REP_SCHEMAS = path.join(RACINE, "spec", "schemas");
const SPEC = path.join(RACINE, "spec", "CT-4-registre.md");

/** Les seules entrées de premier niveau que le générateur écrit, donc les seules qu'il efface (EX-A.1). */
export const ENTREES_GENEREES = ["INDEX.md", "constantes.json", "identifiants.json", "doctypes.json", "empreintes.json", "condenses.json", "appels.json", "transactions.json", "manifestes", "demandes", "inscription", "capture"];
/** Troisième ligne d'INDEX.md : la marque d'un répertoire produit par ce générateur. */
const MARQUE_INDEX = "Produit par `scripts/vecteurs/generer-ct4.mjs`";

const texteJSON = (v) => JSON.stringify(v, null, 2) + "\n";
const copie = (v) => JSON.parse(JSON.stringify(v));
const sha = (texte) => "0x" + createHash("sha256").update(Buffer.from(texte, "utf8")).digest("hex");
const shaOctets = (o) => "0x" + createHash("sha256").update(o).digest("hex");
function exiger(condition, message) {
  if (!condition) throw new Error(`génération interrompue : ${message}`);
}
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

// ---------------------------------------------------------------------------
// Constantes (A.2)
// ---------------------------------------------------------------------------

const EVM = 2124;
const BFT = "noortrace-2124-dev";
const CONTRATS = {
  curator_set_registry: "0x172076e0166d1f9cc711c77adf8488051744980c",
  recorder_registry: "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
  period_registry: "0x4ee6ecad1c2dae9f525404de8555724e3c35d07b",
  attestation_registry: "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8",
};
const JEU_ASSUREUR = "0xc0f115a19107322cfbf1cdbc7ea011c19ebdb4f8";
const MNEMONIQUE = "test test test test test test test test test test test junk";
const CHEMIN = (i) => `m/44'/60'/0'/0/${i}`;
const COMPTES = [0, 1, 2, 3, 4].map((i) => HDNodeWallet.fromPhrase(MNEMONIQUE, undefined, CHEMIN(i)));
const ADR = (i) => COMPTES[i].address.toLowerCase();
const PRIV = (i) => COMPTES[i].privateKey;
const SLUG = "assureur-demo";
const JOURNAL = "journal-sinistres";
const ORG_ID = C.orgIdDuSlug(SLUG);
const JOURNAL_ID = C.journalIdDuNom(JOURNAL);
const ETIQ_CLE_CHAINE = (k) => `noortrace/vecteurs/v0/cle-chaine/${k}`;
const ETIQ_CLE_ED = (k) => `noortrace/vecteurs/v0/cle-enregistreur/${k}`;
const ETIQ_VALIDATEUR = (i) => `noortrace/vecteurs/ct4/validateur/v${i}`;
const ETIQ_COMPTE = (r) => `noortrace/vecteurs/ct4/compte/${r}`;
const ENREGISTREURS = ["rec-test-01", "rec-test-02", "rec-test-03"].map((key_id) => {
  const prive = sha(ETIQ_CLE_CHAINE(key_id));
  return { key_id, chain_key_seed: ETIQ_CLE_CHAINE(key_id), chain_key_private: prive, chain_key: C.adresseDe(prive), ed25519_seed: ETIQ_CLE_ED(key_id), public_key: J.clePubliqueEd25519(sha(ETIQ_CLE_ED(key_id))) };
});
const ENR = Object.fromEntries(ENREGISTREURS.map((e) => [e.key_id, e]));
const VALIDATEURS_ESSAI = [1, 2, 3, 4].map((i) => ({ id: `v${i}`, seed: ETIQ_VALIDATEUR(i), private_key: sha(ETIQ_VALIDATEUR(i)), pubKeyHex: clePubliqueDe(sha(ETIQ_VALIDATEUR(i))) }));
const JEU_ESSAI = VALIDATEURS_ESSAI.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex }));
const COMPTES_PROD = Object.fromEntries(["tresorerie", "deployeur", "administrateur-registre", "relayeur"].map((r) => [r, { seed: ETIQ_COMPTE(r), private_key: sha(ETIQ_COMPTE(r)), address: C.adresseDe(sha(ETIQ_COMPTE(r))) }]));
/** Instance synthétique de production des manifestes (identifiant fictif, A.4). */
const PROD = { evm: 1912124, bft: "noortrace-1912124-vecteur" };
/** Code de création synthétique : dépose un code d'exécution de 10 octets qui rend 42 (pas celui de la compilation, EX-A.2). */
const CODE_CREATION_SYNTHETIQUE = "0x600a600c600039600a6000f3602a60005260206000f3";

// Exemples de 7.7 et 7.10.
const EX_SLUG = "relecteur-exemple";
const EX_ORG = C.orgIdDuSlug(EX_SLUG);
const EX_JOURNAL_ID = C.journalIdDuNom("journal-principal");
const EX_APPROBATEURS = [1, 2, 3].map((i) => ({ seed: `noortrace/exemple/ct4/approbateur/${i}`, private_key: sha(`noortrace/exemple/ct4/approbateur/${i}`) }));
const EX_ADMIN = { seed: "noortrace/exemple/ct4/admin-jeu", private_key: sha("noortrace/exemple/ct4/admin-jeu") };
const EX_CHAINE = { seed: "noortrace/exemple/ct4/cle-chaine/rec-exemple-01", private_key: sha("noortrace/exemple/ct4/cle-chaine/rec-exemple-01") };
const EX_ED = { seed: "noortrace/exemple/ct4/cle-enregistreur/rec-exemple-01", public_key: J.clePubliqueEd25519(sha("noortrace/exemple/ct4/cle-enregistreur/rec-exemple-01")) };
const EX_SET = "0x" + sha("noortrace/exemple/ct4/curator-set").slice(2, 42);
const EX_TX = (n) => sha(`noortrace/exemple/ct4/transaction/${n}`);
const EX_BLOC = (h) => sha(`noortrace/exemple/ct4/bloc/${h}`);
const EX_MANIFESTE = J.construireManifeste({ org_id: EX_ORG, journal_id: EX_JOURNAL_ID, period_start: 1793520000, first_seq: 1, hashes: [1, 2, 3].map((i) => sha(`noortrace/exemple/ct4/evenement/${i}`)), recorder_key_id: "rec-exemple-01", nonce: sha("noortrace/exemple/ct4/nonce/1"), generated_at: "2026-11-01T09:00:01.000Z" });
const EX_PERIOD_HASH = J.hachageManifeste(EX_MANIFESTE);

// ---------------------------------------------------------------------------
// Entrées
// ---------------------------------------------------------------------------

function chargerSchemas() {
  const docs = ["instance-registre-v0", "inscription-client-v0", "operations-registre-v0", "registre-v0", "validateurs-v0"].map((n) => lireJSON(path.join(REP_SCHEMAS, `${n}.schema.json`)));
  return C.registreSchemasCt4(docs);
}

/** Blocs JSON annotés « <!-- schema: … --> » de la spécification, dans l'ordre. */
export function exemplesAnnotes(texte = fs.readFileSync(SPEC, "utf8")) {
  const out = [];
  const re = /<!-- schema: ([a-z0-9_/-]+) -->\n```json\n([\s\S]*?)\n```/g;
  let m;
  while ((m = re.exec(texte))) out.push({ schema: m[1], valeur: JSON.parse(m[2]) });
  return out;
}

function lireCapture() {
  const description = lireJSON(path.join(REP_CAPTURE, "capture.json"));
  const fichier = (n) => fs.readFileSync(path.join(REP_CAPTURE, n));
  const res = (n) => JSON.parse(fichier(n).toString("utf8")).result;
  return { description, fichier, res };
}

function manifesteCT1(n) {
  return lireJSON(path.join(REP_CT1, "manifestes", `periode-${n}.json`));
}

// ---------------------------------------------------------------------------
// Cas
// ---------------------------------------------------------------------------

function cas(id, description, checks, input, expected, refusal = null) {
  exiger(/^[a-z0-9][a-z0-9-]{0,79}$/.test(id), `identifiant de cas ${id}`);
  return { id, description, checks, input, expected, refusal };
}

/** Exécute une vérification de la bibliothèque et confronte son verdict à la conception. */
function confronter(id, r, conception) {
  if (conception === null) {
    exiger(r.status === "reussi", `${id} : ${r.check} ${r.status} (${r.code} ${r.detail}), réussite attendue`);
    return r.valeurs;
  }
  exiger(r.status === "echoue" && r.check === conception.check && r.code === conception.code, `${id} : ${r.check} ${r.status} ${r.code} (${r.detail}), conception ${conception.check} ${conception.code}`);
  return null;
}

const refus = (check, code) => ({ check, code });

// ---------------------------------------------------------------------------
// identifiants.json (RG-1, RG-2)
// ---------------------------------------------------------------------------

function familleIdentifiants() {
  const prod = "o-" + sha("noortrace/vecteurs/ct4/slug-production").slice(2, 34);
  const conception = [
    ["slug-assureur-demo", "slug des vecteurs de CT-1 §13", "slug", SLUG, false, null],
    ["slug-canton-demo", "slug d'essai de deployments/noorcore-orgs.json", "slug", "canton-demo", false, null],
    ["slug-relecteur-exemple", "slug de l'exemple de 7.10", "slug", EX_SLUG, false, null],
    ["slug-un-caractere", "un seul caractère", "slug", "a", false, null],
    ["slug-chiffres", "chiffres seuls", "slug", "2124", false, null],
    ["slug-64-caracteres", "64 caractères, la longueur maximale", "slug", "a" + "b".repeat(62) + "c", false, null],
    ["slug-e2e", "slug d'essai e2e-<millisecondes>", "slug", "e2e-1793520000000", false, null],
    ["slug-production", "slug de production : « o- » et 32 chiffres hexadécimaux (EX-6.2)", "slug", prod, true, null],
    ["slug-vide", "chaîne vide", "slug", "", false, refus("RG-1", "slug_invalide")],
    ["slug-65-caracteres", "65 caractères", "slug", "a".repeat(65), false, refus("RG-1", "slug_invalide")],
    ["slug-majuscule", "majuscule", "slug", "Assureur-demo", false, refus("RG-1", "slug_invalide")],
    ["slug-tiret-en-tete", "trait d'union au début", "slug", "-assureur", false, refus("RG-1", "slug_invalide")],
    ["slug-tiret-en-fin", "trait d'union à la fin", "slug", "assureur-", false, refus("RG-1", "slug_invalide")],
    ["slug-espace", "espace", "slug", "assureur demo", false, refus("RG-1", "slug_invalide")],
    ["slug-unicode", "lettre accentuée (aucune normalisation Unicode)", "slug", "assureur-démo", false, refus("RG-1", "slug_invalide")],
    ["slug-souligne", "trait de soulignement", "slug", "assureur_demo", false, refus("RG-1", "slug_invalide")],
    ["slug-point", "point", "slug", "assureur.demo", false, refus("RG-1", "slug_invalide")],
    ["slug-production-forme", "slug lisible refusé pour une organisation de production (EX-6.2)", "slug", SLUG, true, refus("RG-1", "slug_invalide")],
    ["journal-principal", "journal des exemples de CT-1 et de 7.10", "journal", "journal-principal", false, null],
    ["journal-sinistres", "journal des vecteurs de CT-1 §13", "journal", JOURNAL, false, null],
    ["journal-01", "nom neutre de production (EX-6.4)", "journal", "journal-01", false, null],
    ["journal-majuscule", "majuscule", "journal", "Journal-principal", false, refus("RG-2", "nom_journal_invalide")],
    ["journal-souligne", "trait de soulignement", "journal", "journal_principal", false, refus("RG-2", "nom_journal_invalide")],
    ["journal-espace", "espace", "journal", "journal principal", false, refus("RG-2", "nom_journal_invalide")],
    ["journal-vide", "chaîne vide", "journal", "", false, refus("RG-2", "nom_journal_invalide")],
    ["journal-tiret-en-tete", "trait d'union au début", "journal", "-journal", false, refus("RG-2", "nom_journal_invalide")],
    ["journal-65-caracteres", "65 caractères", "journal", "j".repeat(65), false, refus("RG-2", "nom_journal_invalide")],
  ];
  return conception.map(([id, description, kind, value, production, ref]) => {
    const check = kind === "slug" ? "RG-1" : "RG-2";
    const r = C.verifier(check, () => (kind === "slug" ? C.orgIdDuSlug(value, { production }) : C.journalIdDuNom(value)));
    const v = confronter(id, r, ref);
    return cas(id, description, [check], kind === "slug" ? { kind, value, production } : { kind, value }, v === null ? null : kind === "slug" ? { org_id: v } : { journal_id: v }, ref);
  });
}

// ---------------------------------------------------------------------------
// doctypes.json (RG-3)
// ---------------------------------------------------------------------------

function familleDoctypes() {
  const conception = [
    ["libelle-periode", "le libellé de la table de EX-6.5", { label: "noortrace/periode/v0" }, null],
    ["valeur-periode", "la valeur de la table, rendue à son libellé", { doc_type: C.DOC_TYPE_PERIODE }, null],
    ["libelle-hors-table", "libellé conforme à la grammaire mais absent de la table", { label: "noortrace/autre/v0" }, refus("RG-3", "libelle_hors_table")],
    ["libelle-version-suivante", "version suivante, absente de la table (un sens nouveau est une version nouvelle, EX-6.6)", { label: "noortrace/periode/v1" }, refus("RG-3", "libelle_hors_table")],
    ["libelle-majuscule", "majuscule", { label: "noortrace/Periode/v0" }, refus("RG-3", "libelle_invalide")],
    ["libelle-prefixe-majuscule", "préfixe en majuscules", { label: "NOORTRACE/periode/v0" }, refus("RG-3", "libelle_invalide")],
    ["libelle-version-zero-de-tete", "version à zéro de tête", { label: "noortrace/periode/v00" }, refus("RG-3", "libelle_invalide")],
    ["libelle-version-quatre-chiffres", "version de quatre chiffres", { label: "noortrace/periode/v1000" }, refus("RG-3", "libelle_invalide")],
    ["libelle-sans-version", "version absente", { label: "noortrace/periode" }, refus("RG-3", "libelle_invalide")],
    ["libelle-accent", "lettre accentuée (EX-6.5 : ASCII seulement)", { label: "noortrace/période/v0" }, refus("RG-3", "libelle_invalide")],
    ["libelle-espace-final", "espace final", { label: "noortrace/periode/v0 " }, refus("RG-3", "libelle_invalide")],
    ["libelle-tiret-en-tete", "segment commençant par un trait d'union", { label: "noortrace/-periode/v0" }, refus("RG-3", "libelle_invalide")],
    ["libelle-segment-33", "segment de 33 caractères (48 au total)", { label: `noortrace/${"a".repeat(33)}/v0` }, refus("RG-3", "libelle_invalide")],
    ["valeur-nulle", "la valeur nulle n'est jamais un docType (EX-6.6)", { doc_type: C.HACHAGE_NUL }, refus("RG-3", "doctype_nul")],
    ["valeur-hors-table", "keccak256 d'un libellé absent de la table", { doc_type: C.keccakTexte("noortrace/autre/v0") }, refus("RG-3", "doctype_hors_table")],
  ];
  return conception.map(([id, description, input, ref]) => {
    const r = C.verifier("RG-3", () => (input.label !== undefined ? C.docTypeDuLibelle(input.label) : C.libelleDuDocType(input.doc_type)));
    const v = confronter(id, r, ref);
    return cas(id, description, ["RG-3"], input, v === null ? null : input.label !== undefined ? { doc_type: v } : { label: v }, ref);
  });
}

// ---------------------------------------------------------------------------
// empreintes.json (RG-4)
// ---------------------------------------------------------------------------

function familleEmpreintes() {
  const attendu = lireJSON(path.join(REP_CT1, "manifestes", "attendu.json"));
  const out = [];
  for (const n of [1, 2, 3]) {
    const m = manifesteCT1(n);
    const ph = J.hachageManifeste(m);
    const ref = attendu.periodes[n - 1];
    exiger(ref.period_hash === ph, `periodHash de periode-${n}`);
    const r = C.verifier("RG-4", () => C.empreinteAncre({ org_id: m.org_id, journal_id: m.journal_id, period_hash: ph }));
    const v = confronter(`ct1-periode-${n}`, r, null);
    exiger(v.fingerprint === ref.anchor_fingerprint, `empreinte de periode-${n} différente de anchor_fingerprint de CT-1`);
    out.push(cas(`ct1-periode-${n}`, `manifeste spec/vecteurs/ct-1/manifestes/periode-${n}.json${m.count === 0 ? " (période vide)" : ""} ; égale à anchor_fingerprint de attendu.json`, ["RG-4"], { org_id: m.org_id, journal_id: m.journal_id, period_hash: ph, manifest: `spec/vecteurs/ct-1/manifestes/periode-${n}.json` }, v));
  }
  const ex = C.empreinteAncre({ org_id: EX_ORG, journal_id: EX_JOURNAL_ID, period_hash: EX_PERIOD_HASH });
  exiger(ex.fingerprint === "0xe9d0f7920aa2156e93aab68d210ea95738d9631d9911b544063ecda33034c18c", "empreinte du manifeste d'exemple de A.2");
  out.push(cas("exemple-relecteur", "manifeste d'exemple de A.2 (relecteur-exemple, journal-principal)", ["RG-4"], { org_id: EX_ORG, journal_id: EX_JOURNAL_ID, period_hash: EX_PERIOD_HASH }, ex));
  const ph1 = J.hachageManifeste(manifesteCT1(1));
  const autreOrg = C.empreinteAncre({ org_id: C.orgIdDuSlug("canton-demo"), journal_id: JOURNAL_ID, period_hash: ph1 });
  out.push(cas("autre-organisation", "même periodHash sous une autre organisation : autre empreinte", ["RG-4"], { org_id: C.orgIdDuSlug("canton-demo"), journal_id: JOURNAL_ID, period_hash: ph1 }, autreOrg));
  const declares = [
    ["declaree-racine", "empreinte déclarée : keccak256 de la racine (on n'ancre pas la racine, 6.5)", C.hex(C.keccak(C.b32(manifesteCT1(1).root)))],
    ["declaree-ordre-inverse", "empreinte déclarée : préimage journal_id ‖ org_id ‖ periodHash", C.hex(C.keccak(Buffer.concat([C.b32(JOURNAL_ID), C.b32(ORG_ID), C.b32(ph1)])))],
    ["declaree-sha256", "empreinte déclarée : SHA-256 de la préimage au lieu de keccak256", shaOctets(Buffer.concat([C.b32(ORG_ID), C.b32(JOURNAL_ID), C.b32(ph1)]))],
  ];
  for (const [id, d, decl] of declares) {
    const r = C.verifier("RG-4", () => C.empreinteAncre({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_hash: ph1, declaree: decl }));
    confronter(id, r, refus("RG-4", "empreinte_differente"));
    out.push(cas(id, d, ["RG-4"], { org_id: ORG_ID, journal_id: JOURNAL_ID, period_hash: ph1, fingerprint: decl }, null, refus("RG-4", "empreinte_differente")));
  }
  for (const [id, champ] of [["org-id-nul", "org_id"], ["journal-id-nul", "journal_id"], ["period-hash-nul", "period_hash"]]) {
    const input = { org_id: ORG_ID, journal_id: JOURNAL_ID, period_hash: ph1, [champ]: C.HACHAGE_NUL };
    confronter(id, C.verifier("RG-4", () => C.empreinteAncre(input)), refus("RG-4", "entree_nulle"));
    out.push(cas(id, `${champ} nul`, ["RG-4"], input, null, refus("RG-4", "entree_nulle")));
  }
  return out;
}

// ---------------------------------------------------------------------------
// condenses.json (RG-5 à RG-13)
// ---------------------------------------------------------------------------

/** Transactions de la capture, décodées depuis le corps signé des propositions (EX-A.4). */
function transactionsCapture(capture) {
  return capture.description.transactions.map((t) => {
    const cert = capture.res(t.fichiers.certificat);
    const brut = C.hex(C.transactionsBrutesDuCertificat(cert)[t.indice]);
    const tx = C.decoderTransaction(brut);
    exiger(tx.transaction_hash === t.hash, `transaction ${t.hash} de la capture`);
    return { ...t, brut, tx, recu: capture.res(t.fichiers.recus[0]), bloc: capture.res(t.fichiers.bloc) };
  });
}

/** Arguments d'appel décodés d'une transaction de la capture (6.7.2, lecture inverse). */
function argumentsDeCapture(t) {
  const d = C.octets(t.tx.data);
  const mot = (i) => d.subarray(4 + 32 * i, 4 + 32 * i + 32);
  const sigs = (debut) => {
    const k = Number(BigInt(C.hex(d.subarray(debut, debut + 32))));
    return Array.from({ length: k }, (_, i) => {
      const b = d.subarray(debut + 32 + 96 * i, debut + 32 + 96 * (i + 1));
      return { v: Number(BigInt(C.hex(b.subarray(0, 32)))), r: C.hex(b.subarray(32, 64)), s: C.hex(b.subarray(64, 96)) };
    });
  };
  if (t.role === "inscription") return { fonction: "registerRecorder", args: { org_id: C.hex(mot(0)), journal_id: C.hex(mot(1)), chain_key: C.hex(mot(2).subarray(12)), ed25519_public_key: C.hex(mot(3)), signatures: sigs(4 + 0xa0) } };
  if (t.role === "ancre") return { fonction: "anchor", args: { fingerprint: C.hex(mot(0)), doc_type: C.hex(mot(1)), issuer: C.hex(mot(2).subarray(12)), signature: { v: Number(BigInt(C.hex(mot(3)))), r: C.hex(mot(4)), s: C.hex(mot(5)) } } };
  // submitPeriod : tête (0x40, 0x40 + L), T(meta) à partir du mot 2.
  const T = (i) => mot(2 + i);
  const lgUri = Number(BigInt(C.hex(T(10))));
  const uri = d.subarray(4 + 64 + 352, 4 + 64 + 352 + lgUri).toString("utf8");
  const L = 352 + 32 * Math.ceil(lgUri / 32);
  const meta = { org_id: C.hex(T(0)), journal_id: C.hex(T(1)), period_hash: C.hex(T(2)), root: C.hex(T(3)), period_start: BigInt(C.hex(T(4))).toString(), period_end: BigInt(C.hex(T(5))).toString(), first_seq: BigInt(C.hex(T(6))).toString(), last_seq: BigInt(C.hex(T(7))).toString(), version: Number(BigInt(C.hex(T(8)))), uri };
  return { fonction: "submitPeriod", args: { period_meta: meta, signatures: sigs(4 + 64 + L) } };
}

function signatureH(i, digest) {
  return C.signerCondense(PRIV(i), digest);
}

function familleCondenses(capture, txs) {
  const out = [];
  const M = [1, 2, 3].map(manifesteCT1);
  const metas = M.map((m) => C.metaDuManifeste(m, ""));
  const prec = (meta) => ({ period_end: meta.period_end, last_seq: meta.last_seq });
  // RG-5
  const r5 = [
    ["cloture-periode-1", "PeriodMeta de la période 1 de CT-1 (première du journal)", { period_meta: metas[0] }, null],
    ["cloture-periode-2", "période 2, à la suite de la période 1", { period_meta: metas[1], previous: prec(metas[0]) }, null],
    ["cloture-periode-3-vide", "période 3, vide : lastSeq + 1 = firstSeq et racine nulle", { period_meta: metas[2], previous: prec(metas[1]) }, null],
    ["cloture-uri-64", "uri de 64 caractères ASCII imprimables", { period_meta: { ...metas[0], uri: "urn:noortrace:periode:" + "0".repeat(42) } }, null],
    ["cloture-org-id-nul", "orgId nul", { period_meta: { ...metas[0], org_id: C.HACHAGE_NUL } }, refus("RG-5", "periode_invalide")],
    ["cloture-journal-id-nul", "journalId nul", { period_meta: { ...metas[0], journal_id: C.HACHAGE_NUL } }, refus("RG-5", "periode_invalide")],
    ["cloture-period-hash-nul", "periodHash nul", { period_meta: { ...metas[0], period_hash: C.HACHAGE_NUL } }, refus("RG-5", "periode_invalide")],
    ["cloture-bornes-inversees", "periodStart ≥ periodEnd", { period_meta: { ...metas[0], period_end: metas[0].period_start } }, refus("RG-5", "periode_invalide")],
    ["cloture-period-end-max", "periodEnd = 2^64 − 1", { period_meta: { ...metas[0], period_end: C.U64_MAX.toString() } }, refus("RG-5", "periode_invalide")],
    ["cloture-last-seq-max", "lastSeq = 2^64 − 1", { period_meta: { ...metas[0], last_seq: C.U64_MAX.toString() } }, refus("RG-5", "periode_invalide")],
    ["cloture-vide-racine", "période vide à racine non nulle", { period_meta: { ...metas[2], root: metas[0].root } }, refus("RG-5", "periode_invalide")],
    ["cloture-racine-nulle", "période non vide à racine nulle", { period_meta: { ...metas[0], root: C.HACHAGE_NUL } }, refus("RG-5", "periode_invalide")],
    ["cloture-sequence-invalide", "firstSeq > lastSeq + 1", { period_meta: { ...metas[0], first_seq: "11" } }, refus("RG-5", "periode_invalide")],
    ["cloture-discontinuite-temporelle", "periodStart différent du periodEnd précédent", { period_meta: metas[1], previous: { ...prec(metas[0]), period_end: String(Number(metas[0].period_end) - 3600) } }, refus("RG-5", "discontinuite_temporelle")],
    ["cloture-discontinuite-sequence", "firstSeq différent du lastSeq + 1 précédent", { period_meta: metas[1], previous: { ...prec(metas[0]), last_seq: "8" } }, refus("RG-5", "discontinuite_sequence")],
    ["cloture-uri-65", "uri de 65 caractères", { period_meta: { ...metas[0], uri: "u".repeat(65) } }, refus("RG-5", "periode_invalide")],
    ["cloture-uri-non-imprimable", "uri avec un saut de ligne", { period_meta: { ...metas[0], uri: "ligne\nsuivante" } }, refus("RG-5", "periode_invalide")],
    ["cloture-uri-slug", "uri qui contient le slug de l'organisation", { period_meta: { ...metas[0], uri: `noortrace://${SLUG}/1` }, slug: SLUG }, refus("RG-5", "periode_invalide")],
    ["cloture-uri-journal", "uri qui contient le nom du journal", { period_meta: { ...metas[0], uri: `noortrace://${JOURNAL}/1` }, journal_name: JOURNAL }, refus("RG-5", "periode_invalide")],
  ];
  for (const [id, d, input, ref] of r5) {
    const r = C.verifier("RG-5", () => C.verifierChampsCloture(input.period_meta, { precedente: input.previous ?? null, slug: input.slug ?? null, nom_journal: input.journal_name ?? null }));
    const v = confronter(id, r, ref);
    out.push(cas(id, d, ["RG-5"], input, v, ref));
  }
  // RG-6 periodDigest
  const ajouterCondense = (check, id, d, f, input, ref = null) => {
    const r = C.verifier(check, () => f(input));
    const v = confronter(id, r, ref);
    out.push(cas(id, d, [check], input, v, ref));
    return v;
  };
  const base = { chain_id: EVM };
  metas.forEach((meta, i) => {
    const v = ajouterCondense("RG-6", `period-digest-periode-${i + 1}`, `periodDigest de la période ${i + 1} de CT-1${i === 0 ? " (exemple de 6.6.4, bloc 16668)" : ""}`, C.condenseCloture, { ...base, contract: CONTRATS.period_registry, period_meta: meta });
    if (i === 0) exiger(v.digest === "0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674" && v.eip191_digest === "0x89072ae7b6c13cf3d65d0215ee3dce6e1c533a393877e33314574e3cf9b1936e", "periodDigest de 6.6.4");
  });
  ajouterCondense("RG-6", "period-digest-uri", "periodDigest avec une uri non vide (T(meta) de 384 octets)", C.condenseCloture, { ...base, contract: CONTRATS.period_registry, period_meta: { ...metas[0], uri: "urn:noortrace:periode:0001" } });
  ajouterCondense("RG-6", "period-digest-exemple", "periodDigest du manifeste d'exemple de A.2", C.condenseCloture, { ...base, contract: CONTRATS.period_registry, period_meta: C.metaDuManifeste(EX_MANIFESTE, "") });
  ajouterCondense("RG-6", "period-digest-autre-chaine", "condensé déclaré calculé pour l'identifiant EVM 2121", C.condenseCloture, { ...base, contract: CONTRATS.period_registry, period_meta: metas[0], digest: C.condenseCloture({ chain_id: 2121, contract: CONTRATS.period_registry, period_meta: metas[0] }).digest }, refus("RG-6", "condense_different"));
  // RG-7 registerDigest
  for (const e of ENREGISTREURS) {
    const v = ajouterCondense("RG-7", `register-digest-${e.key_id}`, `registerDigest de ${e.key_id} sous sa clé de chaîne (capture de CT-6)`, C.condenseInscription, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: e.chain_key, ed25519_public_key: e.public_key });
    if (e.key_id === "rec-test-01") exiger(v.digest === "0x90362e40306221d7f95b803857dab38f80d1ddb9b59c51441f464cb0334d1108", "registerDigest de 6.6.4");
  }
  const vEx = ajouterCondense("RG-7", "register-digest-rec-exemple-01", "registerDigest de l'exemple de 7.7", C.condenseInscription, { ...base, contract: CONTRATS.recorder_registry, org_id: EX_ORG, journal_id: EX_JOURNAL_ID, chain_key: C.adresseDe(EX_CHAINE.private_key), ed25519_public_key: EX_ED.public_key });
  exiger(vEx.digest === "0xd0b3adc4a42e8b3d9efea626a0dcd526d88fce25c7ad9f1abc3f3577d49d00fa", "registerDigest de 7.7");
  ajouterCondense("RG-7", "register-digest-cle-chaine-nulle", "clé de chaîne nulle (contracts/RecorderRegistry.sol:137)", C.condenseInscription, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: C.ADRESSE_NULLE, ed25519_public_key: ENR["rec-test-01"].public_key }, refus("RG-7", "entree_invalide"));
  ajouterCondense("RG-7", "register-digest-autre-contrat", "condensé déclaré calculé pour PeriodRegistry", C.condenseInscription, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key, digest: C.condenseInscription({ ...base, contract: CONTRATS.period_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key }).digest }, refus("RG-7", "condense_different"));
  // RG-8 revokeDigest d'enregistreur
  const tInscr = (k) => Number(BigInt(txs.find((t) => t.role === "inscription" && t.key_id === k).bloc.timestamp));
  for (const k of ["rec-test-01", "rec-test-02"]) {
    const v = ajouterCondense("RG-8", `revoke-digest-${k}`, `revokeDigest de ${k}, registeredAt = horodatage du bloc de son RecorderRegistered`, C.condenseRevocation, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, chain_key: ENR[k].chain_key, registered_at: String(tInscr(k)) });
    if (k === "rec-test-01") exiger(v.digest === "0x63e4dfd071d6f365a39772d9ca34e9791f6426e9dfc654178d280c9a1152b9df" && tInscr(k) === 0x6ada8c36, "revokeDigest de 6.6.4");
  }
  ajouterCondense("RG-8", "revoke-digest-avant-inscription", "registeredAt nul : révocation signée avant l'inscription (EX-6.11)", C.condenseRevocation, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, registered_at: "0" }, refus("RG-8", "entree_invalide"));
  ajouterCondense("RG-8", "revoke-digest-autre-inscription", "condensé déclaré pour une autre inscription (registeredAt + 1)", C.condenseRevocation, { ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, registered_at: String(tInscr("rec-test-01")), digest: C.condenseRevocation({ ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, registered_at: String(tInscr("rec-test-01") + 1) }).digest }, refus("RG-8", "condense_different"));
  // RG-9 anchorDigest et RG-10
  const empreintes = M.map((m) => C.empreinteAncre({ org_id: m.org_id, journal_id: m.journal_id, period_hash: J.hachageManifeste(m) }).fingerprint);
  empreintes.forEach((f, i) => {
    const v = ajouterCondense("RG-9", `anchor-digest-periode-${i + 1}`, `anchorDigest de l'empreinte de la période ${i + 1}${i === 0 ? " (exemple de 6.6.4, bloc 16660)" : ""}`, C.condenseAncre, { ...base, contract: CONTRATS.attestation_registry, fingerprint: f, doc_type: C.DOC_TYPE_PERIODE });
    if (i === 0) exiger(v.digest === "0xb1eb8a317f588d9484ebf839effd88727b92525bdb487402c57a7f5a1fc8cbe9", "anchorDigest de 6.6.4");
  });
  ajouterCondense("RG-9", "anchor-digest-autre-contrat", "condensé déclaré calculé pour une autre adresse d'AttestationRegistry", C.condenseAncre, { ...base, contract: CONTRATS.attestation_registry, fingerprint: empreintes[0], doc_type: C.DOC_TYPE_PERIODE, digest: C.condenseAncre({ ...base, contract: CONTRATS.recorder_registry, fingerprint: empreintes[0], doc_type: C.DOC_TYPE_PERIODE }).digest }, refus("RG-9", "condense_different"));
  ajouterCondense("RG-10", "revoke-ancre-periode-1", "revokeDigest d'attestation de l'empreinte de la période 1 (aucun outil ne l'envoie en version 0)", C.condenseRevocationAncre, { ...base, contract: CONTRATS.attestation_registry, fingerprint: empreintes[0] });
  ajouterCondense("RG-10", "revoke-ancre-etiquette-ancre", "condensé déclaré : celui de l'ancre, autre étiquette", C.condenseRevocationAncre, { ...base, contract: CONTRATS.attestation_registry, fingerprint: empreintes[0], digest: C.condenseAncre({ ...base, contract: CONTRATS.attestation_registry, fingerprint: empreintes[0], doc_type: C.DOC_TYPE_PERIODE }).digest }, refus("RG-10", "condense_different"));
  // RG-11 adminOpDigest
  const ops = [
    ["add-curator", "CuratorSet.addCurator", ADR(4)],
    ["remove-curator", "CuratorSet.removeCurator", ADR(3)],
    ["set-threshold", "CuratorSet.setThreshold", "3"],
    ["propose-admin", "CuratorSet.proposeAdmin", ADR(3)],
    ["accept-admin", "CuratorSet.acceptAdmin", null],
  ];
  for (const [id, op, valeur] of ops) {
    const v = ajouterCondense("RG-11", `admin-op-${id}`, `adminOpDigest de ${op} sur le CuratorSet de assureur-demo, nonce 0`, C.condenseOperationJeu, { ...base, contract: JEU_ASSUREUR, op, arg: C.argumentOperationJeu(op, valeur), nonce: "0" });
    if (id === "propose-admin") exiger(v.digest === "0xd0840fa693828406974358cd14061f33c59a826cc51f954f39972f615b816be2", "adminOpDigest de 6.6.4");
  }
  ajouterCondense("RG-11", "admin-op-inconnue", "opération sans étiquette du contrat", C.condenseOperationJeu, { ...base, contract: JEU_ASSUREUR, op: "CuratorSet.setAdmin", arg: C.argumentOperationJeu("CuratorSet.proposeAdmin", ADR(3)), nonce: "0" }, refus("RG-11", "entree_invalide"));
  ajouterCondense("RG-11", "admin-op-autre-nonce", "condensé déclaré au nonce 1", C.condenseOperationJeu, { ...base, contract: JEU_ASSUREUR, op: "CuratorSet.proposeAdmin", arg: C.argumentOperationJeu("CuratorSet.proposeAdmin", ADR(3)), nonce: "0", digest: C.condenseOperationJeu({ ...base, contract: JEU_ASSUREUR, op: "CuratorSet.proposeAdmin", arg: C.argumentOperationJeu("CuratorSet.proposeAdmin", ADR(3)), nonce: "1" }).digest }, refus("RG-11", "condense_different"));
  // RG-12 signatures
  const dReg = C.condenseInscription({ ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key }).digest;
  const s1 = signatureH(1, dReg);
  const s2 = signatureH(2, dReg);
  const sigCas = (id, d, digest, signature, ref, extra = {}) => {
    const input = { digest, signature, ...extra };
    const r = C.verifier("RG-12", () => C.verifierSignature(input));
    const v = confronter(id, r, ref);
    out.push(cas(id, d, ["RG-12"], input, v, ref));
  };
  sigCas("signature-h1-inscription", "Hardhat 1 signe le registerDigest de rec-test-01 (RFC 6979, s bas)", dReg, s1, null);
  sigCas("signature-h2-inscription", "Hardhat 2 signe le registerDigest de rec-test-01", dReg, s2, null, { eip191_digest: C.hachageSigne(dReg) });
  const t16668 = txs.find((t) => t.bloc && Number(BigInt(t.bloc.number)) === 16668);
  const sCap = argumentsDeCapture(t16668).args.signatures;
  const dCap = C.condenseCloture({ ...base, contract: CONTRATS.period_registry, period_meta: metas[0] }).digest;
  sigCas("signature-capture-16668", "première signature de la clôture du bloc 16668 (Hardhat 1), telle que la transaction la porte", dCap, { signer: ADR(1), ...sCap[0] }, null);
  const dAnc = C.condenseAncre({ ...base, contract: CONTRATS.attestation_registry, fingerprint: empreintes[0], doc_type: C.DOC_TYPE_PERIODE }).digest;
  sigCas("signature-ancre-rec-test-02", "la clé de chaîne de rec-test-02 signe l'anchorDigest de la période 1 (signature de 6.6.4)", dAnc, C.signerCondense(ENR["rec-test-02"].chain_key_private, dAnc), null);
  const sHaut = { ...s1, s: C.hex(C.u256(C.N_SECP256K1 - BigInt(s1.s))), v: s1.v === 27 ? 28 : 27 };
  sigCas("signature-s-haut", "forme malléable : s remplacé par n − s et v inversé (même signataire recouvré)", dReg, sHaut, refus("RG-12", "signature_non_canonique"));
  sigCas("signature-v-29", "v = 29", dReg, { ...s1, v: 29 }, refus("RG-12", "signature_non_canonique"));
  sigCas("signature-v-0", "v = 0 (identifiant de récupération sans le décalage 27)", dReg, { ...s1, v: s1.v - 27 }, refus("RG-12", "signature_non_canonique"));
  sigCas("signature-r-nul", "r = 0", dReg, { ...s1, r: C.HACHAGE_NUL }, refus("RG-12", "signature_non_canonique"));
  sigCas("signature-s-nul", "s = 0", dReg, { ...s1, s: C.HACHAGE_NUL }, refus("RG-12", "signature_non_canonique"));
  sigCas("signature-r-hors-ordre", "r = n", dReg, { ...s1, r: C.hex(C.u256(C.N_SECP256K1)) }, refus("RG-12", "signature_non_canonique"));
  const brute = new SigningKey(PRIV(1)).sign(dReg);
  sigCas("signature-sans-prefixe", "signature du condensé nu, sans préfixe EIP-191 : recouvre une autre adresse", dReg, { signer: ADR(1), v: 27 + brute.yParity, r: brute.r, s: brute.s }, refus("RG-12", "signataire_different"));
  sigCas("signature-signataire-declare-faux", "signataire déclaré Hardhat 3 pour une signature de Hardhat 1", dReg, { ...s1, signer: ADR(3) }, refus("RG-12", "signataire_different"));
  sigCas("signature-hachage-signe-faux", "hachage signé déclaré : le condensé nu", dReg, s1, refus("RG-12", "hachage_signe_different"), { eip191_digest: dReg });
  // RG-13 jeux de signatures
  const membres = [ADR(1), ADR(2), ADR(3)];
  const s3 = signatureH(3, dReg);
  const s4 = signatureH(4, dReg);
  const jeuCas = (id, d, digest, signatures, ref, { seuil = 2, exact = true, mbr = membres, extra = {} } = {}) => {
    const input = { digest, signatures, members: mbr, threshold: seuil, ...extra };
    const r = C.verifier("RG-13", () => C.verifierJeuSignatures({ digest, signatures, membres: mbr, seuil, exact }));
    const v = confronter(id, r, ref);
    out.push(cas(id, d, ["RG-12", "RG-13"], input, v, ref));
  };
  const range = C.rangerSignatures([s1, s2]);
  exiger(range[0].signer === ADR(2), "ordre des adresses Hardhat 2 < Hardhat 1");
  jeuCas("seuil-h1-h2-ranges", "Hardhat 1 et 2 au seuil 2, rangées par adresse croissante (Hardhat 2 puis Hardhat 1)", dReg, range, null);
  jeuCas("seuil-h2-h3-ranges", "Hardhat 2 et 3 au seuil 2", dReg, C.rangerSignatures([s2, s3]), null);
  jeuCas("seuil-ordre-inverse", "Hardhat 1 puis Hardhat 2 : autre ordre (le contrat l'accepte, RG-13 non)", dReg, [s1, s2], refus("RG-13", "ordre_signatures"));
  jeuCas("seuil-hors-jeu", "Hardhat 4, non membre", dReg, C.rangerSignatures([s1, s4]), refus("RG-13", "signataire_hors_jeu"));
  jeuCas("seuil-doublon", "deux fois Hardhat 1", dReg, [s1, s1], refus("RG-13", "signataire_double"));
  jeuCas("seuil-une-signature", "une signature pour un seuil de 2", dReg, [s1], refus("RG-13", "nombre_signatures"));
  jeuCas("seuil-trois-signatures", "trois signatures pour un seuil de 2 : exactement t exigées", dReg, C.rangerSignatures([s1, s2, s3]), refus("RG-13", "nombre_signatures"));
  jeuCas("seuil-s-haut", "une signature à s haut dans le jeu", dReg, C.rangerSignatures([s2, sHaut]), refus("RG-12", "signature_non_canonique"));
  // EX-A.4 : les cinq opérations au seuil de la capture, dans l'ordre de la transaction.
  for (const t of txs.filter((x) => x.role === "inscription" || x.role === "cloture")) {
    const a = argumentsDeCapture(t).args;
    const digest = t.role === "inscription" ? C.condenseInscription({ ...base, contract: CONTRATS.recorder_registry, org_id: a.org_id, journal_id: a.journal_id, chain_key: a.chain_key, ed25519_public_key: a.ed25519_public_key }).digest : C.condenseCloture({ ...base, contract: CONTRATS.period_registry, period_meta: a.period_meta }).digest;
    const sigs = a.signatures.map((s) => ({ signer: C.verifierSignature({ digest, signature: s }).recovered, ...s }));
    exiger(sigs[0].signer === ADR(1) && sigs[1].signer === ADR(2), `signataires de la transaction du bloc ${t.bloc.number}`);
    jeuCas(`capture-${Number(BigInt(t.bloc.number))}-ordre`, `signatures de la transaction du bloc ${Number(BigInt(t.bloc.number))} (${t.role}), dans l'ordre de la transaction : Hardhat 1 puis Hardhat 2 (EX-A.4)`, digest, sigs, refus("RG-13", "ordre_signatures"), { extra: { transaction_hash: t.hash } });
  }
  return out;
}

// ---------------------------------------------------------------------------
// appels.json (RG-14)
// ---------------------------------------------------------------------------

function familleAppels(txs) {
  const out = [];
  const base = { chain_id: EVM };
  const ajouter = (id, d, fonction, args, ref = null, declarees = null, extra = {}) => {
    const r = C.verifier("RG-14", () => C.verifierDonneesAppel(fonction, args, declarees));
    const v = confronter(id, r, ref);
    const input = { function: fonction, args, ...(declarees !== null ? { calldata: declarees } : {}), ...extra };
    out.push(cas(id, d, ["RG-14"], input, v, ref));
    return v;
  };
  for (const t of txs) {
    const { fonction, args } = argumentsDeCapture(t);
    const h = Number(BigInt(t.bloc.number));
    const v = ajouter(`capture-${h}`, `${fonction} de la transaction du bloc ${h} (capture de CT-6) : l'encodage de 6.7.2 redonne la donnée de la transaction réelle (EX-A.4)`, fonction, args, null, null, { transaction_hash: t.hash, block_number: h });
    exiger(v.calldata === t.tx.data, `données d'appel du bloc ${h}`);
  }
  const dReg = C.condenseInscription({ ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key }).digest;
  const sigsReg = C.rangerSignatures([signatureH(1, dReg), signatureH(2, dReg)]).map(({ v, r, s }) => ({ v, r, s }));
  ajouter("register-recorder-ranges", "registerRecorder de rec-test-01, signatures rangées (196 + 96k octets)", "registerRecorder", { org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key, signatures: sigsReg });
  const dRev = C.condenseRevocation({ ...base, contract: CONTRATS.recorder_registry, org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, registered_at: "1792707638" }).digest;
  ajouter("revoke-recorder", "revokeRecorder de rec-test-01 (132 + 96k octets)", "revokeRecorder", { org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, signatures: C.rangerSignatures([signatureH(1, dRev), signatureH(2, dRev)]).map(({ v, r, s }) => ({ v, r, s })) });
  const meta1 = C.metaDuManifeste(manifesteCT1(1), "urn:noortrace:periode:0001");
  const dPer = C.condenseCloture({ ...base, contract: CONTRATS.period_registry, period_meta: meta1 }).digest;
  const v = ajouter("submit-period-uri", "submitPeriod avec une uri de 26 octets : L = 384, 100 + L + 96k octets", "submitPeriod", { period_meta: meta1, signatures: C.rangerSignatures([signatureH(1, dPer), signatureH(2, dPer)]).map(({ v: vv, r, s }) => ({ v: vv, r, s })) });
  exiger(v.length === 100 + 384 + 192, "longueur de submitPeriod avec uri");
  ajouter("set-curator-set", "setCuratorSet(assureur-demo, son CuratorSet) (68 octets)", "setCuratorSet", { org_id: ORG_ID, curator_set: JEU_ASSUREUR });
  const opArgs = { "CuratorSet.addCurator": ADR(4), "CuratorSet.removeCurator": ADR(3), "CuratorSet.setThreshold": "3", "CuratorSet.proposeAdmin": ADR(3), "CuratorSet.acceptAdmin": null };
  for (const [op, valeur] of Object.entries(opArgs)) {
    const d = C.condenseOperationJeu({ ...base, contract: JEU_ASSUREUR, op, arg: C.argumentOperationJeu(op, valeur), nonce: "0" }).digest;
    const sig = signatureH(op === "CuratorSet.acceptAdmin" ? 3 : 0, d);
    const { fonction, args } = C.appelOperationJeu(op, valeur, "0", { v: sig.v, r: sig.r, s: sig.s });
    ajouter(`${fonction.replace(/[A-Z]/g, (x) => "-" + x.toLowerCase())}`, `${fonction} signé ${op === "CuratorSet.acceptAdmin" ? "par l'administrateur proposé (Hardhat 3)" : "par l'administrateur du jeu (Hardhat 0)"}, nonce 0`, fonction, args);
  }
  // Arguments de constructeur (sans code de création, 6.7.2).
  const ctor = [
    ["constructeur-curator-set", "CuratorSet(Hardhat 0, [Hardhat 1, 2, 3], 2)", "CuratorSet", { initial_admin: ADR(0), members: [ADR(1), ADR(2), ADR(3)], threshold: 2 }],
    ["constructeur-curator-set-registry", "CuratorSetRegistry(Hardhat 0)", "CuratorSetRegistry", { initial_admin: ADR(0) }],
    ["constructeur-period-registry", "PeriodRegistry(CuratorSetRegistry du réseau de développement)", "PeriodRegistry", { curator_set_registry: CONTRATS.curator_set_registry }],
    ["constructeur-recorder-registry", "RecorderRegistry(CuratorSetRegistry du réseau de développement)", "RecorderRegistry", { curator_set_registry: CONTRATS.curator_set_registry }],
    ["constructeur-attestation-registry", "AttestationRegistry() : aucun argument", "AttestationRegistry", {}],
  ];
  for (const [id, d, contrat, args] of ctor) out.push(cas(id, `arguments du constructeur de ${d}, sans le code de création`, ["RG-14"], { contract: contrat, args }, { constructor_args: C.argumentsConstructeur(contrat, args) }));
  // Refus.
  const anc = argumentsDeCapture(txs.find((t) => t.role === "ancre")).args;
  const juste = C.donneesAppel("anchor", anc);
  ajouter("anchor-donnees-alterees", "données déclarées dont l'émetteur est remplacé par un autre", "anchor", anc, refus("RG-14", "donnees_differentes"), juste.replace(anc.issuer.slice(2), ADR(0).slice(2)));
  const sub = argumentsDeCapture(txs.find((t) => t.role === "cloture")).args;
  const justeSub = C.donneesAppel("submitPeriod", sub);
  ajouter("submit-period-position-uri", "données déclarées où la position de uri dans T(meta) vaut 0x120 au lieu de 0x140", "submitPeriod", sub, refus("RG-14", "donnees_differentes"), justeSub.replace("0000000000000000000000000000000000000000000000000000000000000140", "0000000000000000000000000000000000000000000000000000000000000120"));
  ajouter("anchor-v-hors-uint8", "v = 300 ne tient pas dans un uint8", "anchor", { ...anc, signature: { ...anc.signature, v: 300 } }, refus("RG-14", "entree_invalide"));
  return out;
}

// ---------------------------------------------------------------------------
// transactions.json (RG-15)
// ---------------------------------------------------------------------------

/** Transaction de type 0 non protégée (EIP-155 absent), signée par `cle`. */
function transactionType0(champs, cle) {
  const L = [octetsEntier(champs.nonce), octetsEntier(champs.gas_price), octetsEntier(champs.gas_limit), C.a20(champs.to), octetsEntier(0n), C.octets(champs.data)];
  const h = C.hex(C.keccak(rlp(L)));
  const s = new SigningKey(cle).sign(h);
  const brut = rlp([...L, octetsEntier(27 + s.yParity), octetsEntier(BigInt(s.r)), octetsEntier(BigInt(s.s))]);
  return C.hex(brut);
}

/** Transaction de type 2 avec une liste d'accès non vide. */
function transactionListeAcces(champs, cle) {
  const acces = [[C.a20(champs.to), [C.u256(0)]]];
  const L = [octetsEntier(champs.chain_id), octetsEntier(champs.nonce), octetsEntier(1n), octetsEntier(1n), octetsEntier(champs.gas_limit), C.a20(champs.to), octetsEntier(0n), C.octets(champs.data), acces];
  const charge = Buffer.concat([Buffer.from([2]), rlp(L)]);
  const s = new SigningKey(cle).sign(C.hex(C.keccak(charge)));
  return C.hex(Buffer.concat([Buffer.from([2]), rlp([...L, octetsEntier(s.yParity), octetsEntier(BigInt(s.r)), octetsEntier(BigInt(s.s))])]));
}

/** Réécrit s en n − s et inverse yParity d'une transaction de type 2 (forme malléable). */
function transactionSHaut(brutHex) {
  const b = C.octets(brutHex);
  const L = C.decoderRLP(b, 1).valeur;
  const s = BigInt(C.hex(L[11]));
  const y = L[9].length === 0 ? 0 : L[9][0];
  const n = [...L.slice(0, 9), octetsEntier(1 - y), L[10], octetsEntier(C.N_SECP256K1 - s)];
  return C.hex(Buffer.concat([Buffer.from([2]), rlp(n)]));
}

function familleTransactions(txs) {
  const out = [];
  const frais = { ...C.FRAIS_DEFAUT };
  const ajouter = (id, d, champs, cle, contexte, ref = null, { brut = null, reel = null } = {}) => {
    const signee = brut ? null : C.signerTransaction(champs, cle.private_key);
    const raw = brut ?? signee.raw_transaction;
    const r = C.verifier("RG-15", () => C.verifierTransaction(raw, contexte));
    if (ref === null) confronter(id, r, null);
    else confronter(id, r, ref);
    const input = { ...(champs ? { fields: champs } : {}), ...(cle ? { signer_key: cle.label } : {}), raw_transaction: raw, context: contexte };
    const expected = signee ? { signing_payload: signee.signing_payload, signing_hash: signee.signing_hash, y_parity: signee.y_parity, r: signee.r, s: signee.s, raw_transaction: signee.raw_transaction, transaction_hash: signee.transaction_hash, from: signee.from } : null;
    if (reel) exiger(expected.raw_transaction === reel.brut && expected.transaction_hash === reel.hash, `${id} : octets recalculés différents de la transaction réelle`);
    out.push(cas(id, d, ["RG-15"], input, expected, ref));
    return expected;
  };
  const champsTx = (tx) => ({ chain_id: Number(tx.chain_id), nonce: Number(tx.nonce), max_priority_fee_per_gas: tx.max_priority_fee_per_gas.toString(), max_fee_per_gas: tx.max_fee_per_gas.toString(), gas_limit: tx.gas_limit.toString(), to: tx.to, value: tx.value.toString(), data: tx.data });
  // Transactions de la capture (EX-A.4).
  for (const t of txs) {
    const h = Number(BigInt(t.bloc.number));
    ajouter(`capture-${h}`, `transaction du bloc ${h} (${t.role}) recalculée avec le compte Hardhat 0 au nonce ${t.tx.nonce} : mêmes octets et même hachage que la transaction réelle ; RG-15 échoue sur les seuls frais (3 et 1 wei, EX-A.4)`, champsTx(t.tx), { label: "hardhat:0", private_key: PRIV(0) }, { evm_chain_id: EVM, fees: frais, objet: "appel", to: t.tx.to }, refus("RG-15", "frais_non_conformes"), { reel: { brut: t.brut, hash: t.hash } });
  }
  // Exemple de 6.7.3.
  const anc = argumentsDeCapture(txs.find((t) => t.role === "ancre" && t.periode === 1)).args;
  const dataAnc = C.donneesAppel("anchor", anc);
  const cleChaine02 = { label: `sha256:${ETIQ_CLE_CHAINE("rec-test-02")}`, private_key: ENR["rec-test-02"].chain_key_private };
  const base = { chain_id: EVM, max_priority_fee_per_gas: "1", max_fee_per_gas: "1", gas_limit: "3000000", value: "0" };
  const ex = ajouter("exemple-6-7-3", "l'anchor de 6.6.4 envoyé par la clé de chaîne de rec-test-02 elle-même, au nonce 0 (exemple de 6.7.3)", { ...base, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry, data: dataAnc });
  exiger(ex.transaction_hash === "0xf78912922ae35ecc19994b2c3ed8d5d7c53cd3702bb5f03ce5455c6b54eb486b" && ex.signing_hash === "0xedc5604b7cf7f755d1ba4237b5b1747f80b30ae6888848dcdbd9daa0630e9285", "exemple de 6.7.3");
  // Transactions de A.2.
  const sub = argumentsDeCapture(txs.find((t) => t.role === "cloture" && t.periode === 1)).args;
  const sigSub = C.rangerSignatures(sub.signatures.map((s) => ({ signer: C.verifierSignature({ digest: C.condenseCloture({ chain_id: EVM, contract: CONTRATS.period_registry, period_meta: sub.period_meta }).digest, signature: s }).recovered, ...s }))).map(({ v, r, s }) => ({ v, r, s }));
  const dataSub = C.donneesAppel("submitPeriod", { period_meta: sub.period_meta, signatures: sigSub });
  ajouter("cloture-cle-chaine", "submitPeriod de la période 1, signatures rangées, envoyé par la clé de chaîne de rec-test-02 au nonce 1 (CT-2 EX-11.19)", { ...base, nonce: 1, to: CONTRATS.period_registry, data: dataSub }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.period_registry, data: dataSub });
  const reg = argumentsDeCapture(txs.find((t) => t.role === "inscription" && t.key_id === "rec-test-01")).args;
  const dReg = C.condenseInscription({ chain_id: EVM, contract: CONTRATS.recorder_registry, org_id: reg.org_id, journal_id: reg.journal_id, chain_key: reg.chain_key, ed25519_public_key: reg.ed25519_public_key }).digest;
  const dataReg = C.donneesAppel("registerRecorder", { ...reg, signatures: C.rangerSignatures(reg.signatures.map((s) => ({ signer: C.verifierSignature({ digest: dReg, signature: s }).recovered, ...s }))).map(({ v, r, s }) => ({ v, r, s })) });
  const h0 = { label: "hardhat:0", private_key: PRIV(0) };
  ajouter("inscription-relayeur", "registerRecorder de rec-test-01, signatures rangées, relayé par le compte Hardhat 0 au nonce 200", { ...base, nonce: 200, to: CONTRATS.recorder_registry, data: dataReg }, h0, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.recorder_registry, data: dataReg });
  const dataSet = C.donneesAppel("setCuratorSet", { org_id: ORG_ID, curator_set: JEU_ASSUREUR });
  ajouter("assignation", "setCuratorSet par l'administrateur du registre (Hardhat 0) au nonce 201", { ...base, nonce: 201, to: CONTRATS.curator_set_registry, data: dataSet }, h0, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.curator_set_registry, data: dataSet });
  const P = C.provision(frais, C.BUDGET_JOUR_DEFAUT).provision_wei.toString();
  ajouter("approvisionnement", `virement de la provision P_k = ${P} wei à la clé de chaîne de rec-test-01, nonce 202 (EX-4.19)`, { ...base, nonce: 202, to: ENR["rec-test-01"].chain_key, value: P, data: "0x" }, h0, { evm_chain_id: EVM, fees: frais, objet: "approvisionnement", to: ENR["rec-test-01"].chain_key, provision: P });
  const dataDep = CODE_CREATION_SYNTHETIQUE + C.argumentsConstructeur("CuratorSet", { initial_admin: ADR(0), members: [ADR(1), ADR(2), ADR(3)], threshold: 2 }).slice(2);
  ajouter("deploiement", "déploiement d'un CuratorSet au nonce 203 : sans destinataire, code de création synthétique de A.4 suivi des arguments du constructeur", { ...base, nonce: 203, to: null, data: dataDep }, h0, { evm_chain_id: EVM, fees: frais, objet: "deploiement", data: dataDep });
  // Remplacements à 2 et 3 wei (EX-4.15).
  const rem2 = { ...base, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc, max_priority_fee_per_gas: "2", max_fee_per_gas: "2" };
  ajouter("remplacement-2-wei", "remplacement de l'exemple de 6.7.3 au même nonce : p' = ⌈1,1 × 1⌉ = 2 wei", rem2, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry, data: dataAnc, remplace: "1" });
  ajouter("remplacement-3-wei", "second remplacement au même nonce : p' = ⌈1,1 × 2⌉ = 3 wei", { ...rem2, max_priority_fee_per_gas: "3", max_fee_per_gas: "3" }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry, data: dataAnc, remplace: "2" });
  ajouter("remplacement-insuffisant", "remplacement d'une transaction à 2 wei par une autre à 2 wei (3 exigés)", rem2, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry, data: dataAnc, remplace: "2" }, refus("RG-15", "frais_non_conformes"));
  // Refus.
  ajouter("non-protegee", "transaction de type 0 sans identifiant de chaîne (EX-4.8)", null, null, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "type_non_admis"), { brut: transactionType0({ nonce: 0n, gas_price: 1n, gas_limit: 3000000n, to: CONTRATS.attestation_registry, data: dataAnc }, cleChaine02.private_key) });
  ajouter("autre-chaine", "transaction signée pour l'identifiant EVM 2121", { ...base, chain_id: 2121, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "chaine_differente"));
  ajouter("frais-nuls", "maxFeePerGas = maxPriorityFeePerGas = 0", { ...base, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc, max_fee_per_gas: "0", max_priority_fee_per_gas: "0" }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "frais_non_conformes"));
  ajouter("frais-inegaux", "maxFeePerGas = 2, maxPriorityFeePerGas = 1", { ...base, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc, max_fee_per_gas: "2" }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "frais_non_conformes"));
  ajouter("limite-au-dela-2-24", "gasLimit = 2^24 + 1", { ...base, nonce: 0, to: CONTRATS.attestation_registry, data: dataAnc, gas_limit: String(2 ** 24 + 1) }, cleChaine02, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "limite_gaz"));
  ajouter("liste-acces", "liste d'accès non vide", null, null, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "liste_acces"), { brut: transactionListeAcces({ chain_id: EVM, nonce: 0n, gas_limit: 3000000n, to: CONTRATS.attestation_registry, data: dataAnc }, cleChaine02.private_key) });
  ajouter("signature-s-haut", "l'exemple de 6.7.3 sous sa forme malléable (s haut)", null, null, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "signature_non_canonique"), { brut: transactionSHaut(ex.raw_transaction) });
  ajouter("illisible", "enveloppe de type 2 dont la liste RLP est vide : douze champs attendus", null, null, { evm_chain_id: EVM, fees: frais, objet: "appel", to: CONTRATS.attestation_registry }, refus("RG-15", "transaction_illisible"), { brut: "0x02c0" });
  ajouter("approvisionnement-excessif", "virement au-delà de la provision P_k", { ...base, nonce: 202, to: ENR["rec-test-01"].chain_key, value: (BigInt(P) + 1n).toString(), data: "0x" }, h0, { evm_chain_id: EVM, fees: frais, objet: "approvisionnement", to: ENR["rec-test-01"].chain_key, provision: P }, refus("RG-15", "objet_non_conforme"));
  ajouter("deploiement-avec-destinataire", "« déploiement » adressé à un contrat", { ...base, nonce: 203, to: CONTRATS.attestation_registry, data: dataDep }, h0, { evm_chain_id: EVM, fees: frais, objet: "deploiement", data: dataDep }, refus("RG-15", "objet_non_conforme"));
  return out;
}

// ---------------------------------------------------------------------------
// Blocs synthétiques (manifestes de production)
// ---------------------------------------------------------------------------

/** Réponse JSON-RPC brute d'un résultat, comme un nœud la sert. */
function reponseRPC(result) {
  return Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
}

/**
 * En-tête et certificat synthétiques d'un bloc de hauteur `h` : `txsRaw`
 * (octets signés de ses transactions, dans l'ordre), `recus` (au moins type,
 * status, cumulativeGasUsed et logs de chaque transaction), `entete` (champs
 * de l'en-tête à conserver : parentHash, stateRoot, timestamp, gasUsed,
 * gasLimit, baseFeePerGas, logsBloom, miner, extraData, size, mixHash ; les
 * autres reçoivent une valeur par défaut). `transactionsRoot` et
 * `receiptsRoot` sont recalculés, `hash` est le BFTBlockHash de l'en-tête
 * (CT-6 EX-11.4), et le certificat est signé par le jeu `validateurs`
 * ({ id, pubKeyHex, private_key }) sous `bftChainId` : proposant
 * jeu[h mod n], précommits de tous sauf jeu[(h + 1) mod n]. Sert aux vecteurs
 * de A.4 et au pont JSON-RPC des tests (EX-A.6). Rend { entete, certificat,
 * valsetHash, proposant }.
 */
export function certifierBloc({ h, txsRaw, recus, bftChainId, validateurs, entete: champs = {} }) {
  const hashes = txsRaw.map((t) => C.hex(C.keccak(C.octets(t))));
  const dernier = recus.length ? BigInt(recus[recus.length - 1].cumulativeGasUsed) : 0n;
  const entete = {
    number: C.quantiteRPC(h),
    hash: null,
    parentHash: champs.parentHash ?? sha(`noortrace/vecteurs/ct4/production/parent/${h}`),
    nonce: "0x0000000000000000",
    sha3Uncles: C.HACHAGE_NUL,
    logsBloom: champs.logsBloom ?? "0x" + "00".repeat(256),
    transactionsRoot: C.racineTransactions(txsRaw.map((t) => C.octets(t))),
    stateRoot: champs.stateRoot ?? sha(`noortrace/vecteurs/ct4/production/etat/${h}`),
    receiptsRoot: racineRecus(recus.map((r) => ({ type: r.type ?? "0x0", status: r.status, cumulativeGasUsed: r.cumulativeGasUsed, logs: r.logs }))),
    miner: champs.miner ?? C.ADRESSE_NULLE,
    difficulty: "0x0",
    totalDifficulty: "0x0",
    extraData: champs.extraData ?? "0x",
    size: champs.size ?? "0x0",
    gasLimit: champs.gasLimit ?? C.quantiteRPC(30000000),
    gasUsed: champs.gasUsed ?? C.quantiteRPC(dernier),
    timestamp: champs.timestamp ?? C.quantiteRPC(1793520000 + h),
    mixHash: champs.mixHash ?? C.HACHAGE_NUL,
    baseFeePerGas: champs.baseFeePerGas ?? "0x1",
    transactions: hashes,
    uncles: [],
  };
  entete.hash = hachageBlocBFT(entete);
  const jeu = validateurs;
  const valsetHash = hachageJeuValidateurs(jeu.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })));
  const proposant = jeu[h % jeu.length];
  const proposition = { height: h, round: 0, proposer: proposant.id, blockHash: entete.hash, parentHash: entete.parentHash, timestamp: Number(BigInt(entete.timestamp)), stateRoot: entete.stateRoot, receiptsRoot: entete.receiptsRoot, txRoot: entete.transactionsRoot, gasUsed: Number(BigInt(entete.gasUsed)), gasLimit: Number(BigInt(entete.gasLimit)), baseFeeHex: entete.baseFeePerGas, txsRaw };
  const ligneP = signerProposition(proposition, { chainId: bftChainId, valsetHash, validatorId: proposant.id }, proposant.private_key);
  const votants = jeu.filter((_, i) => i !== (h + 1) % jeu.length);
  const lignes = votants.map((v) => ({ v, ligne: signerVote({ height: h, round: 0, voter: v.id, type: VOTE_PRECOMMIT, blockHash: entete.hash }, { chainId: bftChainId, valsetHash, validatorId: v.id }, v.private_key) }));
  const decode = (ligne) => {
    const e = analyserEnveloppe(ligne);
    return { bodyHash: C.hex(e.bodyHash), sig: C.hex(e.sig) };
  };
  const certificat = {
    height: C.quantiteRPC(h),
    round: "0x0",
    chainId: bftChainId,
    valsetHash,
    blockHash: entete.hash,
    canonical: { blockHash: entete.hash, matchesCertificate: true },
    proposal: { line: ligneP, validatorId: proposant.id, ...decode(ligneP) },
    precommits: lignes.map(({ v, ligne }) => ({ line: ligne, validatorId: v.id, height: C.quantiteRPC(h), round: "0x0", blockHash: entete.hash, ...decode(ligne) })),
    quorum: { validators: jeu.length, required: Math.floor((2 * jeu.length) / 3) + 1, precommits: lignes.length },
    validatorSet: jeu.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })),
    validatorSetHash: valsetHash,
    validatorSetMatchesCertificate: true,
    signing: { domain: "noor/v1/bft", digestPrefix: "noor/v1/bft-sign|", scheme: "vecteur synthétique de CT-4 (annexe A.4)" },
    retention: { heights: 3000000, pruned: false },
  };
  return { entete, certificat, valsetHash, proposant };
}

/**
 * Bloc synthétique de déploiement : la transaction `brut` seule dans le bloc
 * `h`, son reçu, l'en-tête dont le hachage est le BFTBlockHash, le certificat
 * signé par le jeu d'essai de A.2 (certifierBloc). Rend les octets des trois
 * réponses et l'index de capture (rôle deploiement).
 */
function blocSynthetique({ h, brut, contrat, chainId, bftChainId, validateurs, gaz = 200000 }) {
  const tx = C.decoderTransaction(brut);
  const hash = tx.transaction_hash;
  const recuBase = { type: "0x2", status: "0x1", cumulativeGasUsed: C.quantiteRPC(gaz), logs: [] };
  const { entete, certificat, valsetHash, proposant } = certifierBloc({ h, txsRaw: [brut], recus: [recuBase], bftChainId, validateurs: validateurs.jeu, entete: { gasUsed: C.quantiteRPC(gaz) } });
  const recu = { blockHash: entete.hash, blockNumber: entete.number, contractAddress: contrat, cumulativeGasUsed: recuBase.cumulativeGasUsed, effectiveGasPrice: "0x1", from: C.adresseDe(validateurs.deployeur), gasPrice: "0x1", gasUsed: recuBase.cumulativeGasUsed, logs: [], status: "0x1", to: tx.to, transactionHash: hash, transactionIndex: "0x0", type: "0x2" };
  const fichiers = { [`bloc-${h}.json`]: reponseRPC(entete), [`recu-${hash}.json`]: reponseRPC(recu), [`certificat-${h}.json`]: reponseRPC(certificat) };
  const index = {
    version: 0,
    role: "deploiement",
    evm_chain_id: chainId,
    bft_chain_id: bftChainId,
    contract: contrat,
    transaction_hash: hash,
    block_number: h,
    block_hash: entete.hash,
    transaction_index: 0,
    log_index: null,
    files: { block: { name: `bloc-${h}.json`, sha256: shaOctets(fichiers[`bloc-${h}.json`]) }, receipts: [{ name: `recu-${hash}.json`, sha256: shaOctets(fichiers[`recu-${hash}.json`]) }], certificate: { name: `certificat-${h}.json`, sha256: shaOctets(fichiers[`certificat-${h}.json`]) } },
    node: { rpc: "vecteur synthétique (aucun nœud)", validator_id: proposant.id },
    validator_set_hash: valsetHash,
    captured_at: "2026-11-01T08:00:00.000Z",
    attempts: 1,
    checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })),
    sending: null,
  };
  return { fichiers, index, hash, entete };
}

// ---------------------------------------------------------------------------
// manifestes/ (RG-16 à RG-20)
// ---------------------------------------------------------------------------

function manifestesInstances(schemas, ecrire, exemples) {
  const out = [];
  const lire = (rep) => (n) => {
    const f = path.join(rep, n);
    return fs.existsSync(f) ? fs.readFileSync(f) : null;
  };
  // Cas : { id, description, repertoire (relatif à la racine des vecteurs), manifest, previous, genesis, registry?, conception (null ou {check, code}) }
  const evaluer = (racine, c) => {
    const rep = path.join(racine, "manifestes", c.directory);
    const r = C.verifierManifesteInstance({ octets: fs.readFileSync(path.join(rep, c.manifest)), precedent: c.previous ? fs.readFileSync(path.join(rep, c.previous)) : null, genese: fs.readFileSync(path.join(rep, c.genesis)), lireCapture: lire(rep), ancre: c.registry ?? null, schemas });
    const premier = r.checks.find((x) => x.status !== "reussi");
    if (c.conception === null) exiger(!premier, `manifeste ${c.id} : ${premier?.check} ${premier?.code} ${premier?.detail}`);
    else exiger(premier && premier.check === c.conception.check && premier.code === c.conception.code, `manifeste ${c.id} : ${premier ? `${premier.check} ${premier.code} (${premier.detail})` : "aucun échec"}, conception ${c.conception.check} ${c.conception.code}`);
    return cas(c.id, c.description, ["RG-16", "RG-17", "RG-18", "RG-19", "RG-20"], { directory: `manifestes/${c.directory}`, manifest: c.manifest, previous: c.previous ?? null, genesis: c.genesis, ...(c.registry ? { registry: c.registry } : {}) }, { verdicts: r.verdicts, registry: r.registry }, c.conception);
  };
  const ecrireBrut = (rel, octets) => ecrire(rel, octets);

  // 1. Exemple de 4.8 (réseau de développement), lu dans la spécification.
  const dev = exemples.find((e) => e.schema === "instance-registre").valeur;
  const genDev = fs.readFileSync(path.join(RACINE, "chain", "config", "alloc-dev.json"));
  ecrireBrut("manifestes/valides/developpement/instance-r1.json", texteJSON(dev));
  ecrireBrut(`manifestes/valides/developpement/${dev.genesis.file}`, genDev);
  const conceptions = [{ id: "developpement-exemple", description: "exemple de 4.8 : réseau de développement, evidence nulle, hachages des blocs 8320 à 8328 non relevés", directory: "valides/developpement", manifest: "instance-r1.json", genesis: dev.genesis.file, conception: null }];

  // 2. Instance synthétique de production.
  const jeu = VALIDATEURS_ESSAI;
  const genese = { chainId: PROD.evm, alloc: [{ address: COMPTES_PROD.tresorerie.address, balanceWei: "1000000000000000000" }], rules: { chainId: PROD.bft, ...C.REGLES_SANS_EMISSION } };
  const genProd = Buffer.from(JSON.stringify(genese, null, 2) + "\n");
  const deployeur = COMPTES_PROD.deployeur;
  const admin = COMPTES_PROD["administrateur-registre"].address;
  const noms = ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"];
  const csr = C.adresseCreation(deployeur.address, 1);
  const args = { AttestationRegistry: [], CuratorSetRegistry: [admin], PeriodRegistry: [csr], RecorderRegistry: [csr] };
  const blocs = noms.map((nom, i) => {
    const ctor = nom === "AttestationRegistry" ? "0x" : C.argumentsConstructeur(nom, nom === "CuratorSetRegistry" ? { initial_admin: admin } : { curator_set_registry: csr });
    const data = CODE_CREATION_SYNTHETIQUE + ctor.slice(2);
    const brut = C.signerTransaction({ chain_id: PROD.evm, nonce: i, max_priority_fee_per_gas: 1, max_fee_per_gas: 1, gas_limit: 3000000, to: null, value: 0, data }, deployeur.private_key).raw_transaction;
    const adresse = C.adresseCreation(deployeur.address, i);
    const b = blocSynthetique({ h: 101 + 4 * i, brut, contrat: adresse, chainId: PROD.evm, bftChainId: PROD.bft, validateurs: { jeu, deployeur: deployeur.private_key } });
    return { nom, adresse, ...b };
  });
  const prodR1 = {
    version: 0,
    revision: 1,
    previous_sha256: null,
    published_at: "2026-11-01T09:00:00.000Z",
    nature: "production",
    bft_chain_id: PROD.bft,
    evm_chain_id: PROD.evm,
    evm_chain_id_registration: { status: "inscrit", checked_at: "2026-11-01T08:00:00.000Z", source: "vecteur synthétique de CT-4 (annexe A.4) : identifiant fictif, aucune consultation ni inscription réelle" },
    genesis: { file: "genese.json", sha256: shaOctets(genProd), rules_line: C.ligneRegles(genese), alloc_total_wei: "1000000000000000000" },
    noorcore: {
      repository: "https://github.com/noorfinances-eng/noorchain-core",
      commit: "618fcef8805ef5b4cb9291a3dd97be710e489297",
      go_version: "1.26.9",
      patches: [{ name: "0001-noor_getCommitCertificate.patch", sha256: "0x04d4a48b28568bb6859abdfb1778985841fc547ea47649742b3b2763dd83ae82", effect: "ajoute la méthode JSON-RPC noor_getCommitCertificate ; consensus et format sur disque inchangés" }],
      artifacts: [{ kind: "image", name: "noortrace/noorcore", sha256: sha("noortrace/vecteurs/ct4/production/image"), build: "vecteur synthétique : condensé fictif d'une image construite selon EX-10.1" }],
    },
    validator_sets: [
      {
        from_height: 1,
        to_height: null,
        validators: JEU_ESSAI,
        source: "jeu d'essai de CT-4 A.2 : clés de graines SHA-256(UTF-8(\"noortrace/vecteurs/ct4/validateur/v<i>\")), publiques",
        valset_hash: hachageJeuValidateurs(JEU_ESSAI),
        operators: ["a", "b", "c", "d"].map((x, i) => ({ validator: `v${i + 1}`, operator: `operateur-${x}`, site: `site-${x}`, retention_heights: 3000000 })),
      },
    ],
    fees: { ...C.FRAIS_DEFAUT },
    contracts: blocs.map((b, i) => ({ name: b.nom, address: b.adresse, deployer: deployeur.address, nonce: i, constructor_args: args[b.nom], transaction_hash: b.hash, block_number: 101 + 4 * i, block_hash: b.entete.hash, evidence: { capture: { file: `preuves/${C.nomIndex(101 + 4 * i, 0, "deploiement")}`, sha256: shaOctets(Buffer.from(texteJSON(b.index))) } }, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: [
      { role: "tresorerie", address: COMPTES_PROD.tresorerie.address, from_height: 0, to_height: null },
      { role: "deployeur", address: deployeur.address, from_height: 0, to_height: null },
      { role: "administrateur_registre", address: admin, from_height: 105, to_height: null },
      { role: "relayeur", address: COMPTES_PROD.relayeur.address, from_height: 0, to_height: null },
    ],
    source: "vecteur synthétique de CT-4 (annexe A.4) : instance de production fictive, blocs de déploiement signés par le jeu d'essai de A.2",
  };
  const ecrireProd = (dir, manifestes, { blocsDe = blocs, genese: g = genProd } = {}) => {
    for (const [nom, m] of Object.entries(manifestes)) ecrireBrut(`manifestes/${dir}/${nom}`, typeof m === "string" ? m : texteJSON(m));
    ecrireBrut(`manifestes/${dir}/genese.json`, g);
    ecrireBrut(`manifestes/${dir}/validators.json`, texteJSON({ validators: JEU_ESSAI }));
    for (const b of blocsDe) {
      for (const [n, o] of Object.entries(b.fichiers)) ecrireBrut(`manifestes/${dir}/preuves/${n}`, o);
      ecrireBrut(`manifestes/${dir}/preuves/${C.nomIndex(b.index.block_number, 0, "deploiement")}`, texteJSON(b.index));
    }
  };
  const r1Texte = texteJSON(prodR1);
  const prodR2 = { ...copie(prodR1), revision: 2, previous_sha256: shaOctets(Buffer.from(r1Texte)), published_at: "2026-11-15T09:00:00.000Z", fees: { ...prodR1.fees, refill_below_days: 10 }, source: "vecteur synthétique de CT-4 (annexe A.4) : révision 2, seuil de recomplément porté à 10 jours (EX-4.25)" };
  ecrireProd("valides/production", { "instance-r1.json": r1Texte, "instance-r2.json": prodR2 });
  conceptions.push({ id: "production-r1", description: "instance synthétique de production : quatre opérateurs et quatre sites, preuves de déploiement capturées et signées par le jeu d'essai de A.2", directory: "valides/production", manifest: "instance-r1.json", genesis: "genese.json", conception: null });
  conceptions.push({ id: "production-r2", description: "révision 2 chaînée par le SHA-256 de la révision 1", directory: "valides/production", manifest: "instance-r2.json", previous: "instance-r1.json", genesis: "genese.json", conception: null });

  // 3. Invalides.
  const variante = (id, description, modifier, conception, opts = {}) => {
    const m = modifier(copie(prodR1));
    ecrireProd(`invalides/${id}`, { "instance.json": m, ...(opts.precedent ? { "instance-r1.json": r1Texte } : {}) }, opts);
    conceptions.push({ id, description, directory: `invalides/${id}`, manifest: "instance.json", previous: opts.precedent ? "instance-r1.json" : null, genesis: "genese.json", conception });
  };
  variante("schema", "membre obligatoire absent (fees)", (m) => {
    delete m.fees;
    return m;
  }, refus("RG-16", "schema"));
  variante("revision-mal-chainee", "révision 2 dont previous_sha256 n'est pas le SHA-256 de la révision 1", (m) => ({ ...m, revision: 2, previous_sha256: sha("autre revision"), published_at: "2026-11-15T09:00:00.000Z" }), refus("RG-16", "revision_mal_chainee"), { precedent: true });
  variante("genese-sha256", "genesis.sha256 différent du SHA-256 du document publié", (m) => ({ ...m, genesis: { ...m.genesis, sha256: sha("autre genese") } }), refus("RG-17", "genese_differente"));
  variante("ligne-regles", "ligne de règles altérée (possEnabled=true)", (m) => ({ ...m, genesis: { ...m.genesis, rules_line: m.genesis.rules_line.replace("possEnabled=false", "possEnabled=true") } }), refus("RG-17", "ligne_regles_differente"));
  variante("valset-hash", "valset_hash différent du hachage recalculé", (m) => {
    m.validator_sets[0].valset_hash = sha("autre jeu");
    return m;
  }, refus("RG-18", "valset_hash_different"));
  variante("domaine-de-panne", "un opérateur porte deux validateurs d'un jeu de quatre (f = 1) en production", (m) => {
    m.validator_sets[0].operators[1].operator = "operateur-a";
    return m;
  }, refus("RG-18", "domaine_de_panne"));
  variante("arguments-constructeur", "PeriodRegistry construit avec l'adresse de l'administrateur au lieu de celle du CuratorSetRegistry (EX-5.2)", (m) => {
    m.contracts[2].constructor_args = [admin];
    return m;
  }, refus("RG-19", "arguments_constructeur"));
  variante("adresse-creation", "adresse d'AttestationRegistry autre que CREATE(deployer, nonce)", (m) => {
    m.contracts[0].address = C.adresseCreation(m.contracts[0].deployer, 9);
    return m;
  }, refus("RG-19", "adresse_creation"));
  // Autres motifs de RG-17 à RG-19 (6.9).
  const avecGenese = (g) => {
    const octets = Buffer.from(JSON.stringify(g, null, 2) + "\n");
    return { genese: octets, sha256: shaOctets(octets) };
  };
  {
    const g = avecGenese({ ...genese, alloc: [genese.alloc[0], genese.alloc[0]] });
    variante("genese-invalide", "document de genèse dont alloc porte deux fois la même adresse (4.2)", (m) => ({ ...m, genesis: { ...m.genesis, sha256: g.sha256 } }), refus("RG-17", "genese_invalide"), { genese: g.genese });
  }
  {
    const { rules: _r, ...sansRegles } = genese;
    const g = avecGenese(sansRegles);
    variante("regles-absentes", "document de genèse sans section rules : le nœud ne vérifierait rien (EX-4.2)", (m) => ({ ...m, genesis: { ...m.genesis, sha256: g.sha256 } }), refus("RG-17", "regles_invalides"), { genese: g.genese });
  }
  variante("identifiants-incoherents", "bft_chain_id du manifeste différent de rules.chainId de la genèse", (m) => ({ ...m, bft_chain_id: `${PROD.bft}2` }), refus("RG-17", "identifiants_incoherents"));
  variante("offre-differente", "alloc_total_wei différent de la somme des balanceWei", (m) => ({ ...m, genesis: { ...m.genesis, alloc_total_wei: "1" } }), refus("RG-17", "offre_differente"));
  variante("jeu-invalide", "clé publique d'un validateur qui n'est pas un point de secp256k1", (m) => {
    m.validator_sets[0].validators[3].pubKeyHex = "0x04" + "00".repeat(64);
    return m;
  }, refus("RG-18", "jeu_invalide"));
  variante("operateurs-incoherents", "operators nomme un validateur absent du jeu", (m) => {
    m.validator_sets[0].operators[0].validator = "v9";
    return m;
  }, refus("RG-18", "operateurs_incoherents"));
  variante("intervalles-incoherents", "deux jeux dont les intervalles de validité se recouvrent", (m) => {
    const j = copie(m.validator_sets[0]);
    m.validator_sets[0].to_height = 200;
    m.validator_sets.push({ ...j, from_height: 150, to_height: null });
    return m;
  }, refus("RG-18", "intervalles_incoherents"));
  variante("contrats-en-service", "deux RecorderRegistry de to_height nul : RG-19 exige exactement un contrat en service par nom, et RG-20 ne peut plus dériver l'ancre (derivation_impossible)", (m) => {
    m.contracts.push({ ...copie(m.contracts[3]), address: C.adresseCreation(m.contracts[3].deployer, 4), nonce: 4, transaction_hash: sha("autre deploiement"), block_number: 121, block_hash: sha("autre bloc"), evidence: null });
    return m;
  }, refus("RG-19", "contrats_en_service"));
  variante("preuve-absente", "index de capture désigné par evidence absent du répertoire des preuves", (m) => {
    m.contracts[0].evidence.capture.file = "preuves/absente.json";
    return m;
  }, refus("RG-19", "preuve_absente"));
  // Index d'un autre rôle : l'inscription du bloc 16648 de la capture de CT-6.
  {
    const capture = lireCapture();
    const t = capture.description.transactions[0];
    const indexInscription = indexCaptureCT6(capture, t);
    const m = copie(dev);
    m.contracts[0].evidence = { capture: { file: `preuves/${C.nomIndex(t.bloc, 0, "inscription")}`, sha256: shaOctets(Buffer.from(texteJSON(indexInscription))) } };
    ecrireBrut("manifestes/invalides/preuve-autre-role/instance.json", texteJSON(m));
    ecrireBrut(`manifestes/invalides/preuve-autre-role/${dev.genesis.file}`, genDev);
    ecrireBrut(`manifestes/invalides/preuve-autre-role/preuves/${C.nomIndex(t.bloc, 0, "inscription")}`, texteJSON(indexInscription));
    for (const f of [t.fichiers.bloc, ...t.fichiers.recus, t.fichiers.certificat]) ecrireBrut(`manifestes/invalides/preuve-autre-role/preuves/${f}`, capture.fichier(f));
    conceptions.push({ id: "preuve-autre-role", description: "exemple de 4.8 dont la preuve d'AttestationRegistry est l'index de l'inscription du bloc 16648 (rôle inscription)", directory: "invalides/preuve-autre-role", manifest: "instance.json", genesis: dev.genesis.file, conception: refus("RG-19", "preuve_invalide") });
  }
  // Transaction de « déploiement » avec destinataire.
  {
    const data = CODE_CREATION_SYNTHETIQUE;
    const brut = C.signerTransaction({ chain_id: PROD.evm, nonce: 0, max_priority_fee_per_gas: 1, max_fee_per_gas: 1, gas_limit: 3000000, to: blocs[0].adresse, value: 0, data }, deployeur.private_key).raw_transaction;
    const b = blocSynthetique({ h: 101, brut, contrat: blocs[0].adresse, chainId: PROD.evm, bftChainId: PROD.bft, validateurs: { jeu, deployeur: deployeur.private_key } });
    const blocs2 = [{ ...blocs[0], ...b }, ...blocs.slice(1)];
    variante(
      "deploiement-avec-destinataire",
      "la transaction prouvée du bloc de déploiement d'AttestationRegistry a un destinataire",
      (m) => {
        m.contracts[0].transaction_hash = b.hash;
        m.contracts[0].block_hash = b.entete.hash;
        m.contracts[0].evidence.capture.sha256 = shaOctets(Buffer.from(texteJSON(b.index)));
        return m;
      },
      refus("RG-19", "preuve_invalide"),
      { blocsDe: blocs2 },
    );
  }
  // RG-20 : ancre fournie différente.
  const ancreProd = C.ancreRegistreDuManifeste(prodR1, "ancre du réviseur, recoupée (vecteur)");
  conceptions.push({ id: "ancre-conforme", description: "ancre registry du réviseur égale, hors source, à celle que le manifeste donne", directory: "valides/production", manifest: "instance-r1.json", genesis: "genese.json", registry: ancreProd, conception: null });
  conceptions.push({ id: "ancre-differente", description: "ancre registry du réviseur dont period_registry diffère du manifeste", directory: "valides/production", manifest: "instance-r1.json", genesis: "genese.json", registry: { ...ancreProd, contracts: { ...ancreProd.contracts, period_registry: ancreProd.contracts.recorder_registry } }, conception: refus("RG-20", "ancre_differente") });
  return { conceptions, evaluer };
}

/** Index de capture d'une transaction de la capture de CT-6 (9.4). */
function indexCaptureCT6(capture, t) {
  const bloc = capture.res(t.fichiers.bloc);
  const contrat = { inscription: CONTRATS.recorder_registry, ancre: CONTRATS.attestation_registry, cloture: CONTRATS.period_registry }[t.role];
  return {
    version: 0,
    role: t.role,
    evm_chain_id: EVM,
    bft_chain_id: BFT,
    contract: contrat,
    transaction_hash: t.hash,
    block_number: t.bloc,
    block_hash: String(bloc.hash).toLowerCase(),
    transaction_index: t.indice,
    log_index: 0,
    files: {
      block: { name: t.fichiers.bloc, sha256: shaOctets(capture.fichier(t.fichiers.bloc)) },
      receipts: t.fichiers.recus.map((n) => ({ name: n, sha256: shaOctets(capture.fichier(n)) })),
      certificate: { name: t.fichiers.certificat, sha256: shaOctets(capture.fichier(t.fichiers.certificat)) },
    },
    node: { rpc: "http://127.0.0.1:8645", validator_id: "v1" },
    validator_set_hash: hachageJeuValidateurs(lireJSON(path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json"))),
    captured_at: capture.description.date,
    attempts: 1,
    checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })),
    sending: null,
  };
}

// ---------------------------------------------------------------------------
// demandes/ (schéma, OP-6, OP-7)
// ---------------------------------------------------------------------------

function demandeSignee(base, cles) {
  const d = { ...base, signatures: [] };
  const calc = C.condenseDeDemande(d);
  d.digest = calc.digest;
  d.eip191_digest = calc.eip191_digest;
  d.signatures = C.rangerSignatures(cles.map((k) => C.signerCondense(k, d.digest)));
  return d;
}

function familleDemandes(exemples) {
  const valides = {};
  const membresAssureur = [ADR(1), ADR(2), ADR(3)];
  const signerSet = (h) => ({ curator_set: JEU_ASSUREUR, threshold: 2, height: h, block_hash: sha(`noortrace/vecteurs/ct4/bloc/${h}`) });
  // 7.7
  const ex = demandeSignee(
    { version: 0, operation: "inscription", evm_chain_id: EVM, contract: CONTRATS.recorder_registry, fields: { org_id: EX_ORG, journal_id: EX_JOURNAL_ID, chain_key: C.adresseDe(EX_CHAINE.private_key), ed25519_public_key: EX_ED.public_key }, digest: null, eip191_digest: null, signer_set: { curator_set: EX_SET, threshold: 2, height: 20009, block_hash: EX_BLOC(20009) }, prepared_at: "2026-11-01T08:46:00.000Z" },
    EX_APPROBATEURS.map((a) => a.private_key),
  );
  ex.signatures = ex.signatures.slice(0, 2);
  const imprime = exemples.find((e) => e.schema === "operations-registre/demande_signature").valeur;
  exiger(J.egalJSON(ex, imprime), "demande de 7.7 recalculée différente de l'exemple imprimé");
  valides["inscription-rec-exemple-01.json"] = { doc: ex, members: null, description: "exemple de 7.7 : inscription de rec-exemple-01, deux signatures sur trois approbateurs" };
  valides["inscription-rec-test-01.json"] = { doc: demandeSignee({ version: 0, operation: "inscription", evm_chain_id: EVM, contract: CONTRATS.recorder_registry, fields: { org_id: ORG_ID, journal_id: JOURNAL_ID, chain_key: ENR["rec-test-01"].chain_key, ed25519_public_key: ENR["rec-test-01"].public_key }, digest: null, eip191_digest: null, signer_set: signerSet(16644), prepared_at: "2026-10-22T22:20:00.000Z" }, [PRIV(1), PRIV(2)]), members: membresAssureur, description: "inscription de rec-test-01 (A.2), Hardhat 1 et 2 rangés" };
  valides["cloture-periode-1.json"] = { doc: demandeSignee({ version: 0, operation: "cloture", evm_chain_id: EVM, contract: CONTRATS.period_registry, fields: { period_meta: C.metaDuManifeste(manifesteCT1(1), "") }, digest: null, eip191_digest: null, signer_set: signerSet(16664), prepared_at: "2026-11-05T10:00:01.000Z" }, [PRIV(1), PRIV(3)]), members: membresAssureur, description: "clôture de la période 1 de CT-1, Hardhat 1 et 3 rangés" };
  valides["revocation-rec-test-01.json"] = { doc: demandeSignee({ version: 0, operation: "revocation", evm_chain_id: EVM, contract: CONTRATS.recorder_registry, fields: { org_id: ORG_ID, chain_key: ENR["rec-test-01"].chain_key, registered_at: "1792707638" }, digest: null, eip191_digest: null, signer_set: signerSet(16680), prepared_at: "2026-11-05T12:00:00.000Z" }, [PRIV(2), PRIV(3)]), members: membresAssureur, description: "révocation de rec-test-01, registeredAt du bloc 16648" };
  const f1 = C.empreinteAncre({ org_id: ORG_ID, journal_id: JOURNAL_ID, period_hash: J.hachageManifeste(manifesteCT1(1)) }).fingerprint;
  valides["ancre-periode-1.json"] = { doc: demandeSignee({ version: 0, operation: "ancre", evm_chain_id: EVM, contract: CONTRATS.attestation_registry, fields: { fingerprint: f1, doc_type: C.DOC_TYPE_PERIODE, issuer: ENR["rec-test-02"].chain_key }, digest: null, eip191_digest: null, signer_set: null, prepared_at: "2026-11-05T10:00:01.000Z" }, [ENR["rec-test-02"].chain_key_private]), members: null, description: "ancre de la période 1, signée par son émetteur (clé de chaîne de rec-test-02)" };
  valides["administration-jeu-propose-admin.json"] = { doc: demandeSignee({ version: 0, operation: "administration_jeu", evm_chain_id: EVM, contract: JEU_ASSUREUR, fields: { op: "CuratorSet.proposeAdmin", arg: C.argumentOperationJeu("CuratorSet.proposeAdmin", ADR(3)), nonce: "0" }, digest: null, eip191_digest: null, signer_set: null, prepared_at: "2026-11-05T12:00:00.000Z" }, [PRIV(0)]), members: null, signataire: ADR(0), description: "proposeAdminSigned vers Hardhat 3, nonce 0, signé par l'administrateur du jeu (Hardhat 0)" };
  const base = valides["inscription-rec-test-01.json"].doc;
  const invalides = {
    "schema-champ-en-trop.json": [{ ...copie(base), fields: { ...base.fields, uri: "" } }, membresAssureur, "membre en trop dans fields", refus("OP-6", "entree_illisible")],
    "schema-signature-v-0.json": [{ ...copie(base), signatures: [{ ...base.signatures[0], v: 0 }, base.signatures[1]] }, membresAssureur, "v = 0 hors de {27, 28} (schéma)", refus("OP-6", "entree_illisible")],
    "condense-altere.json": [{ ...copie(base), digest: sha("autre condense") }, membresAssureur, "digest différent du recalcul", refus("OP-6", "condense_different")],
    "champs-alteres.json": [{ ...copie(base), fields: { ...base.fields, journal_id: C.journalIdDuNom("journal-principal") } }, membresAssureur, "journal_id remplacé, digest gardé", refus("OP-6", "condense_different")],
    "autre-contrat.json": [{ ...copie(base), contract: CONTRATS.period_registry }, membresAssureur, "contract d'un autre registre", refus("OP-6", "condense_different")],
    "autre-chaine.json": [{ ...copie(base), evm_chain_id: 2121 }, membresAssureur, "identifiant EVM 2121", refus("OP-6", "condense_different")],
    "eip191-faux.json": [{ ...copie(base), eip191_digest: base.digest }, membresAssureur, "eip191_digest égal au condensé nu", refus("OP-6", "condense_different")],
    "signature-s-haut.json": [{ ...copie(base), signatures: C.rangerSignatures([base.signatures[0], { ...base.signatures[1], s: C.hex(C.u256(C.N_SECP256K1 - BigInt(base.signatures[1].s))), v: base.signatures[1].v === 27 ? 28 : 27 }]) }, membresAssureur, "une signature à s haut", refus("OP-7", "signature_non_canonique")],
    "signataire-hors-jeu.json": [{ ...copie(base), signatures: C.rangerSignatures([base.signatures[0], C.signerCondense(PRIV(4), base.digest)]) }, membresAssureur, "Hardhat 4, non membre", refus("OP-7", "signataire_hors_jeu")],
    "signatures-insuffisantes.json": [{ ...copie(base), signatures: [base.signatures[0]] }, membresAssureur, "une signature pour un seuil de 2", refus("OP-7", "signatures_insuffisantes")],
    "ordre-inverse.json": [{ ...copie(base), signatures: [base.signatures[1], base.signatures[0]] }, membresAssureur, "signatures non rangées", refus("OP-7", "signature_non_canonique")],
    "signataire-double.json": [{ ...copie(base), signatures: [base.signatures[0], base.signatures[0]] }, membresAssureur, "même signataire deux fois", refus("OP-7", "signature_non_canonique")],
    "signataire-declare-faux.json": [{ ...copie(base), signatures: [{ ...base.signatures[0], signer: ADR(3) }, base.signatures[1]] }, membresAssureur, "signer déclaré autre que l'adresse recouvrée", refus("OP-7", "signataire_hors_jeu")],
    "ancre-autre-emetteur.json": [{ ...copie(valides["ancre-periode-1.json"].doc), signatures: [C.signerCondense(ENR["rec-test-01"].chain_key_private, valides["ancre-periode-1.json"].doc.digest)] }, null, "ancre signée par la clé de chaîne de rec-test-01, émetteur rec-test-02", refus("OP-7", "signataire_hors_jeu")],
  };
  return { valides, invalides };
}

// ---------------------------------------------------------------------------
// inscription/ (schéma, OP-4)
// ---------------------------------------------------------------------------

function dossierExemple() {
  const appro = EX_APPROBATEURS.map((a) => C.adresseDe(a.private_key));
  const membres = [...appro].sort();
  const chainKey = C.adresseDe(EX_CHAINE.private_key);
  const ref = (n, h, c) => ({ transaction_hash: EX_TX(n), block_number: h, block_hash: EX_BLOC(h), capture: c });
  const etape = (step, subject, state, n, h, c, t) => ({ step, subject, state, transaction_hash: n ? EX_TX(n) : null, block_number: h ?? null, block_hash: h ? EX_BLOC(h) : null, capture: c ?? null, error: null, updated_at: t });
  return {
    version: 0,
    instance: { evm_chain_id: EVM, bft_chain_id: BFT, genesis_sha256: shaOctets(fs.readFileSync(path.join(RACINE, "chain", "config", "alloc-dev.json"))), contracts: { ...CONTRATS }, manifest_sha256: null, validator_set_hash: hachageJeuValidateurs(lireJSON(path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json"))) },
    organisation: { slug: EX_SLUG, org_id: EX_ORG },
    approvers: { members: membres, threshold: 2, set_admin: C.adresseDe(EX_ADMIN.private_key) },
    journals: [{ name: "journal-principal", journal_id: EX_JOURNAL_ID }],
    recorders: [{ key_id: "rec-exemple-01", journal_id: EX_JOURNAL_ID, algorithm: "ed25519", public_key: EX_ED.public_key, custody_class: "D", backend_type: "fichier", created_at: "2026-11-01T08:40:00.000Z", chain_key: chainKey, chain_key_class: "D", origin_proof: null }],
    funding: { funder: ADR(0), daily_budget_gas: C.BUDGET_JOUR_DEFAUT, amount_wei: C.provision(C.FRAIS_DEFAUT, C.BUDGET_JOUR_DEFAUT).provision_wei.toString() },
    // 7.10 : les hachages de transaction sont SHA-256(UTF-8("noortrace/exemple/ct4/transaction/<étape>")), <étape> étant le step de l'étape.
    steps: [
      etape("jeu_approbateurs", EX_SLUG, "capturee", "jeu_approbateurs", 20000, "capture-20000-0-jeu_approbateurs.json", "2026-11-01T08:45:04.000Z"),
      etape("assignation", EX_SLUG, "capturee", "assignation", 20004, "capture-20004-0-assignation.json", "2026-11-01T08:45:08.000Z"),
      etape("lecture_jeu", EX_SLUG, "faite", null, 20005, null, "2026-11-01T08:45:09.000Z"),
      etape("approvisionnement", chainKey, "capturee", "approvisionnement", 20008, "capture-20008-0-approvisionnement.json", "2026-11-01T08:45:12.000Z"),
      etape("inscription", "rec-exemple-01", "capturee", "inscription", 20012, "capture-20012-0-inscription.json", "2026-11-01T08:52:30.000Z"),
      etape("premiere_ancre", EX_PERIOD_HASH, "capturee", "premiere_ancre", 20016, "capture-20016-0-ancre.json", "2026-11-01T09:00:20.000Z"),
      etape("premiere_cloture", EX_PERIOD_HASH, "capturee", "premiere_cloture", 20020, "capture-20020-0-cloture.json", "2026-11-01T09:06:41.000Z"),
    ],
    result: {
      curator_set: EX_SET,
      set_deployment: ref("jeu_approbateurs", 20000, "capture-20000-0-jeu_approbateurs.json"),
      assignment: ref("assignation", 20004, "capture-20004-0-assignation.json"),
      approver_set: { source: "registre", chain_id: EVM, registry: CONTRATS.curator_set_registry, set: EX_SET, members: null, threshold: null },
      set_read: { height: 20005, block_hash: EX_BLOC(20005), threshold: 2, size: 3, members: membres },
      recorders: [{ key_id: "rec-exemple-01", chain_key: chainKey, funding: ref("approvisionnement", 20008, "capture-20008-0-approvisionnement.json"), registration: ref("inscription", 20012, "capture-20012-0-inscription.json") }],
      completed_at: "2026-11-01T09:06:41.000Z",
    },
    prepared_by: "relecteur de l'épreuve d'acceptation (exemple)",
    prepared_at: "2026-11-01T08:41:00.000Z",
    source: "exemple de CT-4 §7.10 : valeurs de transaction et de bloc synthétiques, SHA-256(UTF-8(\"noortrace/exemple/ct4/…\"))",
  };
}

/** Le dossier fini ramené à l'état après `n` étapes (0 : préparé). */
function dossierAEtape(fini, n, subjects) {
  const d = copie(fini);
  d.result = null;
  d.steps = d.steps.map((s, i) => (i < n ? s : { ...s, state: "a_faire", subject: subjects[i] ?? s.subject, transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null, updated_at: null }));
  return d;
}

function familleInscription(exemples) {
  const fini = dossierExemple();
  exiger(J.egalJSON(fini, exemples.find((e) => e.schema === "inscription-client").valeur), "dossier de 7.10 recalculé différent de l'exemple imprimé");
  const subjects = fini.steps.map((s) => (s.step.startsWith("premiere_") ? "journal-principal" : s.subject));
  const valides = { "relecteur-exemple-fini.json": [fini, "developpement", [], "exemple de 7.10 : dossier fini"] };
  const noms = ["prepare", "jeu-approbateurs", "assignation", "lecture-jeu", "approvisionnement", "inscription", "premiere-ancre"];
  noms.forEach((nom, n) => {
    valides[`relecteur-exemple-${n}-${nom}.json`] = [dossierAEtape(fini, n, subjects), "developpement", [], n === 0 ? "dossier préparé : toutes les étapes à faire, result nul" : `dossier après l'étape ${fini.steps[n - 1].step}`];
  });
  // Dossier de A.2 : assureur-demo, préparé.
  const assureur = {
    ...dossierAEtape(fini, 0, subjects),
    organisation: { slug: SLUG, org_id: ORG_ID },
    approvers: { members: [ADR(1), ADR(2), ADR(3)].sort(), threshold: 2, set_admin: ADR(0) },
    journals: [{ name: JOURNAL, journal_id: JOURNAL_ID }],
    recorders: ENREGISTREURS.map((e) => ({ key_id: e.key_id, journal_id: JOURNAL_ID, algorithm: "ed25519", public_key: e.public_key, custody_class: "D", backend_type: "fichier", created_at: "2026-10-22T22:00:00.000Z", chain_key: e.chain_key, chain_key_class: "D", origin_proof: null })),
    prepared_by: "générateur des vecteurs de CT-4 (A.2)",
    prepared_at: "2026-10-22T22:00:00.000Z",
    source: "dossier de A.2 : organisation assureur-demo des vecteurs de CT-1 et de la capture de CT-6, préparé",
  };
  assureur.steps = [
    ...["jeu_approbateurs", "assignation", "lecture_jeu"].map((step) => ({ step, subject: SLUG })),
    ...ENREGISTREURS.map((e) => ({ step: "approvisionnement", subject: e.chain_key })),
    ...ENREGISTREURS.map((e) => ({ step: "inscription", subject: e.key_id })),
    { step: "premiere_ancre", subject: JOURNAL },
    { step: "premiere_cloture", subject: JOURNAL },
  ].map((s) => ({ ...s, state: "a_faire", transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null, updated_at: null }));
  valides["assureur-demo-prepare.json"] = [assureur, "developpement", [], "dossier de A.2 (assureur-demo, trois clés de la capture de CT-6), préparé"];
  const invalides = {
    "schema-seuil-nul.json": [{ ...copie(fini), approvers: { ...fini.approvers, threshold: 0 } }, "developpement", [], "seuil 0 (schéma)", refus("OP-4", "entree_illisible")],
    "schema-slug.json": [{ ...copie(fini), organisation: { ...fini.organisation, slug: "Relecteur-Exemple" } }, "developpement", [], "slug hors de la grammaire (schéma)", refus("OP-4", "entree_illisible")],
    "org-id-faux.json": [{ ...copie(fini), organisation: { ...fini.organisation, org_id: ORG_ID } }, "developpement", [], "org_id d'un autre slug", refus("OP-4", "jeu_invalide")],
    "journal-id-faux.json": [{ ...copie(fini), journals: [{ name: "journal-principal", journal_id: JOURNAL_ID }] }, "developpement", [], "journal_id d'un autre nom", refus("OP-4", "jeu_invalide")],
    "membres-non-tries.json": [{ ...copie(fini), approvers: { ...fini.approvers, members: [...fini.approvers.members].reverse() } }, "developpement", [], "membres non triés", refus("OP-4", "jeu_invalide")],
    "membre-nul.json": [{ ...copie(fini), approvers: { ...fini.approvers, members: [C.ADRESSE_NULLE, ...fini.approvers.members.slice(1)] } }, "developpement", [], "adresse nulle parmi les membres", refus("OP-4", "jeu_invalide")],
    "seuil-superieur.json": [{ ...copie(fini), approvers: { ...fini.approvers, threshold: 4 } }, "developpement", [], "seuil 4 pour trois membres", refus("OP-4", "jeu_invalide")],
    "administrateur-nul.json": [{ ...copie(fini), approvers: { ...fini.approvers, set_admin: C.ADRESSE_NULLE } }, "developpement", [], "clé de gouvernance nulle", refus("OP-4", "jeu_invalide")],
    "administrateur-exploitant.json": [{ ...copie(fini), organisation: { slug: "o-" + sha("noortrace/vecteurs/ct4/slug-production").slice(2, 34), org_id: C.orgIdDuSlug("o-" + sha("noortrace/vecteurs/ct4/slug-production").slice(2, 34)) }, approvers: { ...fini.approvers, set_admin: ADR(0) } }, "production", [ADR(0)], "instance de production : la clé de gouvernance est un compte de l'exploitant (EX-5.6)", refus("OP-4", "jeu_invalide")],
    "slug-lisible-production.json": [copie(fini), "production", [ADR(0)], "instance de production : slug lisible au lieu de « o- » et 32 chiffres hexadécimaux (EX-6.2)", refus("OP-4", "jeu_invalide")],
    "classe-d-production.json": [{ ...copie(fini), organisation: { slug: "o-" + sha("noortrace/vecteurs/ct4/slug-production").slice(2, 34), org_id: C.orgIdDuSlug("o-" + sha("noortrace/vecteurs/ct4/slug-production").slice(2, 34)) } }, "production", [ADR(0)], "instance de production : clé d'enregistreur et clé de chaîne de classe de garde D (CT-2 §11.2, EX-11.19)", refus("OP-4", "cle_invalide")],
  };
  return { valides, invalides };
}

// ---------------------------------------------------------------------------
// capture/ (CP-2 à CP-6, export)
// ---------------------------------------------------------------------------

function familleCapture(capture, schemas, ecrire, racine) {
  const valJeu = lireJSON(path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json"));
  const transactions = [capture.description.transactions.find((t) => t.key_id === "rec-test-01"), capture.description.transactions.find((t) => t.key_id === "rec-test-02"), capture.description.transactions.find((t) => t.role === "ancre" && t.periode === 1), capture.description.transactions.find((t) => t.role === "cloture" && t.periode === 1)];
  const indexes = transactions.map((t) => indexCaptureCT6(capture, t));
  for (const t of transactions) for (const f of [t.fichiers.bloc, ...t.fichiers.recus, t.fichiers.certificat]) ecrire(`capture/periode-1/${f}`, capture.fichier(f));
  const nomsIndex = indexes.map((i) => C.nomIndex(i.block_number, i.transaction_index, i.role));
  indexes.forEach((i, k) => ecrire(`capture/periode-1/${nomsIndex[k]}`, texteJSON(i)));
  const conceptions = [];
  const lireDans = (dir) => (n) => {
    const f = path.join(racine, dir, n);
    return fs.existsSync(f) ? fs.readFileSync(f) : null;
  };
  indexes.forEach((i, k) => conceptions.push({ id: `periode-1-${i.role}-${i.block_number}`, description: `capture de la transaction du bloc ${i.block_number} (${i.role}) ; certificat vérifié contre le jeu de A.2`, directory: "capture/periode-1", index: nomsIndex[k], validators: "jeu", conception: null }));
  // Variantes.
  const v16648 = indexes[0];
  const t16648 = transactions[0];
  const fichiers16648 = { [t16648.fichiers.bloc]: capture.fichier(t16648.fichiers.bloc), [t16648.fichiers.recus[0]]: capture.fichier(t16648.fichiers.recus[0]), [t16648.fichiers.certificat]: capture.fichier(t16648.fichiers.certificat) };
  const variante = (id, description, modifier, conception, validators = "jeu") => {
    const fichiers = Object.fromEntries(Object.entries(fichiers16648).map(([n, o]) => [n, Buffer.from(o)]));
    const index = copie(v16648);
    modifier({ index, fichiers });
    for (const f of [index.files.block, ...index.files.receipts, index.files.certificate]) if (fichiers[f.name] && f.sha256 !== "garder") f.sha256 = f.sha256 === "faux" ? sha("faux") : shaOctets(fichiers[f.name]);
    for (const [n, o] of Object.entries(fichiers)) ecrire(`capture/variantes/${id}/${n}`, o);
    const nom = C.nomIndex(index.block_number, index.transaction_index, index.role);
    ecrire(`capture/variantes/${id}/${nom}`, texteJSON(index));
    conceptions.push({ id, description, directory: `capture/variantes/${id}`, index: nom, validators, conception });
  };
  const modifierJSON = (fichiers, nom, f) => {
    const v = JSON.parse(fichiers[nom].toString("utf8"));
    f(v.result);
    fichiers[nom] = Buffer.from(JSON.stringify(v));
  };
  variante("cp2-entete-modifie", "stateRoot de l'en-tête modifié : le BFTBlockHash recalculé n'est plus hash", ({ fichiers }) => modifierJSON(fichiers, t16648.fichiers.bloc, (b) => (b.stateRoot = sha("autre etat"))), refus("CP-2", "capture_incomplete"));
  variante("cp2-hash-index", "block_hash de l'index différent du hash de l'en-tête", ({ index }) => (index.block_hash = sha("autre bloc")), refus("CP-2", "capture_incomplete"));
  variante("cp2-recu-autre-bloc", "blockHash du reçu de la transaction capturée différent du hash de l'en-tête (9.4, CP-2)", ({ fichiers }) => modifierJSON(fichiers, t16648.fichiers.recus[0], (r) => (r.blockHash = sha("autre bloc du recu"))), refus("CP-2", "capture_incomplete"));
  variante("cp3-recu-falsifie", "cumulativeGasUsed du reçu modifié : receiptsRoot recalculée différente", ({ fichiers }) => modifierJSON(fichiers, t16648.fichiers.recus[0], (r) => (r.cumulativeGasUsed = "0x1")), refus("CP-3", "capture_incomplete"));
  variante("cp3-recu-autre-transaction", "transactionHash du reçu de rang 0 différent du hachage de rang 0 de l'en-tête : le reçu désigné est celui d'une autre transaction (CP-3) ; nom et SHA-256 conformes (CP-6)", ({ fichiers }) => modifierJSON(fichiers, t16648.fichiers.recus[0], (r) => (r.transactionHash = sha("autre transaction"))), refus("CP-3", "capture_incomplete"));
  variante("cp3-recu-autre-nom", "reçu identique octet pour octet, désigné sous recu-autre.json au lieu de recu-<hachage>.json : le contenu passe CP-3, le nom relève de CP-6 (9.4)", ({ index, fichiers }) => {
    fichiers["recu-autre.json"] = fichiers[t16648.fichiers.recus[0]];
    delete fichiers[t16648.fichiers.recus[0]];
    index.files.receipts[0].name = "recu-autre.json";
  }, refus("CP-6", "capture_incomplete"));
  variante("cp4-autre-jeu", "certificat vérifié contre le jeu d'essai de A.2 au lieu du jeu du réseau de développement", () => {}, refus("CP-4", "certificat_invalide"), "jeu_essai");
  variante("cp4-valset-hash-index", "validator_set_hash de l'index différent du hachage du jeu employé (9.4, CP-4)", ({ index }) => (index.validator_set_hash = sha("autre hachage de jeu")), refus("CP-4", "certificat_invalide"));
  variante("cp4-certificat-autre-bloc", "certificat du bloc 16652 sous le nom certificat-16648.json", ({ fichiers }) => (fichiers[t16648.fichiers.certificat] = capture.fichier("certificat-16652.json")), refus("CP-4", "certificat_invalide"));
  variante("cp5-autre-role", "index de rôle ancre pour une transaction d'inscription", ({ index }) => {
    index.role = "ancre";
    index.contract = CONTRATS.attestation_registry;
  }, refus("CP-5", "capture_incomplete"));
  variante("cp5-journal-absent", "log_index 1 : le reçu n'a qu'un journal", ({ index }) => (index.log_index = 1), refus("CP-5", "capture_incomplete"));
  variante("cp6-sha256-faux", "SHA-256 déclaré du reçu différent de ses octets", ({ index }) => (index.files.receipts[0].sha256 = "faux"), refus("CP-6", "capture_incomplete"));
  variante("cp6-nom-hors-convention", "en-tête écrit sous bloc-16648-copie.json au lieu de bloc-16648.json", ({ index, fichiers }) => {
    fichiers["bloc-16648-copie.json"] = fichiers[t16648.fichiers.bloc];
    delete fichiers[t16648.fichiers.bloc];
    index.files.block.name = "bloc-16648-copie.json";
  }, refus("CP-6", "capture_incomplete"));
  const evaluer = (c) => {
    const index = JSON.parse(fs.readFileSync(path.join(racine, c.directory, c.index), "utf8"));
    const validators = c.validators === "jeu" ? valJeu : { validators: JEU_ESSAI };
    const r = C.verifierCapture({ index, lireFichier: lireDans(c.directory), validators, bft_chain_id: BFT, schemas });
    const premier = r.checks.find((x) => x.status !== "reussi");
    if (c.conception === null) exiger(!premier, `capture ${c.id} : ${premier?.check} ${premier?.detail}`);
    else exiger(premier && premier.check === c.conception.check && premier.code === c.conception.code, `capture ${c.id} : ${premier ? `${premier.check} ${premier.code} (${premier.detail})` : "aucun échec"}, conception ${c.conception.check} ${c.conception.code}`);
    const verdicts = Object.fromEntries(r.checks.map((x) => [x.check, x.status]));
    return cas(c.id, c.description, ["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"], { directory: c.directory, index: c.index, validators: c.validators === "jeu" ? "test/fixtures/certificat-commit/validators.json" : "constantes.json#/test_validators", bft_chain_id: BFT }, { verdicts }, c.conception);
  };
  // Export de la période 1 (EX-9.8 à EX-9.10).
  const exportCas = () => {
    const parties = C.exporterParties({ captures: indexes.map((index) => ({ index, lireFichier: lireDans("capture/periode-1") })), jeux: [{ from_height: 1, to_height: null, validators: valJeu.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex.toLowerCase() })), source: "validators.json du réseau de développement, clés publiques seulement" }], source: "réseau de développement noortrace-2124-dev, nœud v1, capture unique du 2026-10-22 (spec/vecteurs/ct-6/registre/capture, capture.json)" });
    const ref = (n) => lireJSON(path.join(RACINE, "spec", "vecteurs", "ct-6", "registre", "periode-1", n));
    const sansSource = (v) => JSON.parse(JSON.stringify(v, (k, x) => (k === "source" ? undefined : x)));
    exiger(J.egalJSON(sansSource(parties.registre), sansSource(ref("registre.json"))), "registre.json exporté différent de ct-6/registre/periode-1");
    exiger(J.egalJSON(sansSource(parties.certificat_commit), sansSource(ref("certificat-commit.json"))), "certificat-commit.json exporté différent");
    exiger(J.egalJSON(sansSource(parties.validateurs), sansSource(ref("validateurs.json"))), "validateurs.json exporté différent");
    return cas(
      "export-periode-1",
      "parties exportées des quatre captures de la période 1 : égales, en valeurs JSON et hors source, à spec/vecteurs/ct-6/registre/periode-1/ (EX-9.8 à EX-9.10)",
      ["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"],
      { directory: "capture/periode-1", indexes: nomsIndex, validators: "test/fixtures/certificat-commit/validators.json", manifest: "spec/vecteurs/ct-1/manifestes/periode-1.json" },
      { reference: "spec/vecteurs/ct-6/registre/periode-1", entries: parties.registre.entries.map((e) => ({ role: e.role, block_number: Number(BigInt(e.block.number)), transaction_index: e.transaction_index })), certificates: parties.certificat_commit.certificates.map((c) => Number(BigInt(c.height))), sets: parties.validateurs.sets.length },
    );
  };
  return { conceptions, evaluer, exportCas, index16648: indexes[0] };
}

// ---------------------------------------------------------------------------
// INDEX.md
// ---------------------------------------------------------------------------

function attenduUneLigne(c) {
  if (c.refusal) return `\`echoue\` : ${c.refusal.check} \`${c.refusal.code}\``;
  const e = c.expected ?? {};
  if (e.verdicts) return Object.entries(e.verdicts).map(([k, v]) => `${k} ${v}`).join(", ");
  const cle = ["org_id", "journal_id", "doc_type", "label", "fingerprint", "digest", "recovered", "calldata", "constructor_args", "transaction_hash", "signers", "result", "period_meta"].find((k) => e[k] !== undefined);
  if (!cle) return "`reussi`";
  const v = e[cle];
  if (typeof v === "string") return `\`${cle}\` \`${v.length > 70 ? v.slice(0, 34) + "…" + v.slice(-8) : v}\``;
  if (Array.isArray(v)) return `\`${cle}\` ${v.length} élément(s)`;
  return `\`${cle}\` conforme`;
}

function index(familles, constantes) {
  const L = [];
  L.push("# Vecteurs de CT-4 — Registre");
  L.push("");
  L.push(MARQUE_INDEX + " (`npm run vecteurs:ct4`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-4-registre.md`](../../CT-4-registre.md), annexe A. Rejoués par `test/registreCt4.test.js` avec l'implémentation de référence `scripts/lib/conventions-registre.mjs` ; confrontés par le vérificateur Go indépendant de `verificateur-independant/` (A.5).");
  L.push("");
  L.push("## Format");
  L.push("");
  L.push("Chaque fichier de famille est conforme à `operations-registre-v0.schema.json#/$defs/fichier_vecteurs` (EX-A.3) : `cases[]` porte `id`, `description`, `checks` (vérifications exercées), `input`, `expected` et `refusal` (première vérification en échec et son code, ou `null`).");
  L.push("");
  L.push("- Pour une vérification RG-, `refusal.code` est un motif stable (table `MOTIFS_RG` de `scripts/lib/conventions-registre.mjs`) ; le verdict comparé est `echoue` sur cette vérification. Pour une OP- ou une CP-, c'est le code d'erreur de la spécification (7.11, 9.3) ; un document non conforme à son schéma est refusé en tête d'OP-6 (demandes) ou d'OP-4 (dossiers) avec `entree_illisible`.");
  L.push("- `expected` est `null` pour un refus, sauf : (a) famille `transactions`, tout cas dont `input.fields` est donné : `expected` porte la transaction recalculée et signée depuis `fields` (`signing_payload`, `signing_hash`, `y_parity`, `r`, `s`, `raw_transaction`, `transaction_hash`, `from`) même quand RG-15 échoue sur les frais, la chaîne, la limite de gaz ou l'objet (transactions de la capture de CT-6, EX-A.4, et cas `remplacement-insuffisant`, `autre-chaine`, `frais-nuls`, `frais-inegaux`, `limite-au-dela-2-24`, `approvisionnement-excessif`, `deploiement-avec-destinataire`) ; un cas donné par `raw_transaction` seule (`non-protegee`, `liste-acces`, `signature-s-haut`, `illisible`) a `expected` nul ; (b) familles `manifestes` et `capture` : `expected.verdicts` donne le verdict de chaque vérification et `refusal` la première en échec (et, pour `manifestes`, `expected.registry` l'ancre dérivée, nulle quand RG-20 échoue).");
  L.push("- Octets en hexadécimal minuscule préfixé `0x` ; entiers de 64 bits en chaînes décimales ; signatures `{ signer, v, r, s }` (`v` dans {27, 28}) ; `PeriodMeta` au format `#/$defs/meta_periode`.");
  L.push("- `transactions.json` : `input.fields` sont les champs signés (6.7.3), `input.signer_key` la clé (constantes), `input.raw_transaction` la transaction vérifiée, `input.context` le contexte de RG-15 (`objet` : `appel`, `deploiement`, `approvisionnement` ; `remplace` : frais de la transaction remplacée).");
  L.push("- `manifestes.json` : `input.directory` est le répertoire du cas ; `manifest`, `previous`, `genesis` et les fichiers de preuve désignés par `contracts[].evidence` y sont des chemins relatifs ; `input.registry`, quand il figure, est l'ancre à comparer (RG-20).");
  L.push("- `capture.json` : `input.directory` contient l'index et les réponses brutes ; `input.validators` désigne le jeu contre lequel CP-4 vérifie le certificat (`test/fixtures/certificat-commit/validators.json`, ou le jeu d'essai de `constantes.json`).");
  L.push("");
  L.push("## Constantes (A.2)");
  L.push("");
  L.push("Clés de test publiques, sans valeur : elles ne doivent jamais porter de NUR ni servir hors des tests. `constantes.json` les porte toutes.");
  L.push("");
  L.push("| Grandeur | Valeur |");
  L.push("|---|---|");
  L.push(`| Chaîne | identifiant EVM ${constantes.chain.evm_chain_id}, identifiant BFT \`${constantes.chain.bft_chain_id}\` |`);
  for (const [k, v] of Object.entries(constantes.contracts)) L.push(`| \`${k}\` | \`${v}\` |`);
  L.push(`| CuratorSet de \`assureur-demo\` | \`${constantes.curator_set}\` |`);
  L.push(`| Jeu de validateurs | \`${constantes.validator_set.file}\`, hachage \`${constantes.validator_set.valset_hash}\` |`);
  L.push(`| Genèse | \`${constantes.genesis.file}\`, SHA-256 \`${constantes.genesis.sha256}\` |`);
  L.push(`| Organisation, journal | \`${constantes.organisation.slug}\` (\`${constantes.organisation.org_id}\`), \`${constantes.journal.name}\` (\`${constantes.journal.journal_id}\`) |`);
  for (const a of constantes.accounts) L.push(`| Compte Hardhat ${a.index} (\`${a.derivation_path}\`) | adresse \`${a.address}\`, clé \`${a.private_key}\` |`);
  for (const e of constantes.recorders) L.push(`| \`${e.key_id}\` | clé de chaîne \`${e.chain_key}\` (graine SHA-256(UTF-8(\`${e.chain_key_seed}\`)) = \`${e.chain_key_private}\`) ; clé Ed25519 \`${e.public_key}\` (graine SHA-256(UTF-8(\`${e.ed25519_seed}\`))) |`);
  for (const v of constantes.test_validators.validators) L.push(`| Validateur d'essai \`${v.id}\` | graine SHA-256(UTF-8(\`${v.seed}\`)) = \`${v.private_key}\` ; clé publique \`${v.pubKeyHex.slice(0, 20)}…\` |`);
  L.push(`| Jeu d'essai | hachage \`${constantes.test_validators.valset_hash}\` |`);
  for (const [r, a] of Object.entries(constantes.production.accounts)) L.push(`| Instance synthétique de production, \`${r}\` | graine SHA-256(UTF-8(\`${a.seed}\`)), adresse \`${a.address}\` |`);
  L.push(`| Instance synthétique de production | identifiant EVM ${constantes.production.evm_chain_id} (fictif), \`${constantes.production.bft_chain_id}\` ; code de création synthétique \`${constantes.production.creation_code}\` |`);
  L.push(`| Exemples de 7.7 et 7.10 | \`${constantes.example.slug}\`, \`${constantes.example.journal}\`, periodHash du manifeste d'exemple \`${constantes.example.period_hash}\`, empreinte \`${constantes.example.fingerprint}\` |`);
  L.push("");
  for (const [fichier, doc] of familles) {
    L.push(`## ${fichier} — famille \`${doc.family}\``);
    L.push("");
    L.push(doc.description);
    L.push("");
    L.push("| Cas | Vérifications | Attendu |");
    L.push("|---|---|---|");
    for (const c of doc.cases) L.push(`| \`${c.id}\` | ${c.checks.join(", ")} | ${attenduUneLigne(c)} |`);
    L.push("");
  }
  return L.join("\n");
}

// ---------------------------------------------------------------------------
// Génération
// ---------------------------------------------------------------------------

/**
 * Refuse, sans rien effacer, une racine qui n'est pas un répertoire ou qui
 * porte une entrée de premier niveau que le générateur n'écrit pas (EX-A.1).
 */
export function racineAdmise(racine) {
  if (!fs.existsSync(racine)) return;
  exiger(fs.statSync(racine).isDirectory(), `${racine} n'est pas un répertoire`);
  const etrangeres = fs.readdirSync(racine).filter((e) => !ENTREES_GENEREES.includes(e) && e !== "verificateur-independant").sort();
  exiger(etrangeres.length === 0, `${racine} porte des entrées que le générateur n'écrit pas (${etrangeres.slice(0, 3).join(", ")}) : nommer un répertoire vide ou déjà produit par lui`);
}

/** Génère spec/vecteurs/ct-4 (ou `racine`). Rend des compteurs pour les tests. */
export function genererCt4({ racine = REPERTOIRE_CT4 } = {}) {
  const schemas = chargerSchemas();
  racineAdmise(racine);
  fs.mkdirSync(racine, { recursive: true });
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(racine, e), { recursive: true, force: true });
  const ecrire = (rel, valeur) => {
    const f = path.join(racine, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, typeof valeur === "string" || Buffer.isBuffer(valeur) ? valeur : texteJSON(valeur));
  };
  const exemples = exemplesAnnotes();
  const capture = lireCapture();
  const txs = transactionsCapture(capture);

  // Constantes.
  const valJeu = lireJSON(path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json"));
  const constantes = {
    version: 0,
    chain: { evm_chain_id: EVM, bft_chain_id: BFT },
    contracts: CONTRATS,
    curator_set: JEU_ASSUREUR,
    validator_set: { file: "test/fixtures/certificat-commit/validators.json", valset_hash: hachageJeuValidateurs(valJeu) },
    genesis: { file: "chain/config/alloc-dev.json", sha256: shaOctets(fs.readFileSync(path.join(RACINE, "chain", "config", "alloc-dev.json"))) },
    test_validators: { validators: VALIDATEURS_ESSAI.map((v) => ({ id: v.id, seed: v.seed, private_key: v.private_key, pubKeyHex: v.pubKeyHex })), valset_hash: hachageJeuValidateurs(JEU_ESSAI) },
    organisation: { slug: SLUG, org_id: ORG_ID },
    journal: { name: JOURNAL, journal_id: JOURNAL_ID },
    mnemonic: MNEMONIQUE,
    accounts: [0, 1, 2, 3, 4].map((i) => ({ index: i, derivation_path: CHEMIN(i), address: ADR(i), private_key: PRIV(i) })),
    approvers: { accounts: [1, 2, 3], threshold: 2 },
    relayer: { account: 0 },
    recorders: ENREGISTREURS,
    manifests: [1, 2, 3].map((n) => ({ file: `spec/vecteurs/ct-1/manifestes/periode-${n}.json`, period_hash: J.hachageManifeste(manifesteCT1(n)) })),
    production: { evm_chain_id: PROD.evm, bft_chain_id: PROD.bft, accounts: COMPTES_PROD, creation_code: CODE_CREATION_SYNTHETIQUE },
    example: {
      slug: EX_SLUG,
      org_id: EX_ORG,
      journal: "journal-principal",
      journal_id: EX_JOURNAL_ID,
      approvers: EX_APPROBATEURS.map((a) => ({ ...a, address: C.adresseDe(a.private_key) })),
      set_admin: { ...EX_ADMIN, address: C.adresseDe(EX_ADMIN.private_key) },
      chain_key: { ...EX_CHAINE, address: C.adresseDe(EX_CHAINE.private_key) },
      ed25519: EX_ED,
      curator_set: EX_SET,
      labels: { transaction: "noortrace/exemple/ct4/transaction/<étape>", block: "noortrace/exemple/ct4/bloc/<h>", event: "noortrace/exemple/ct4/evenement/<i>", nonce: "noortrace/exemple/ct4/nonce/1" },
      manifest: EX_MANIFESTE,
      period_hash: EX_PERIOD_HASH,
      fingerprint: C.empreinteAncre({ org_id: EX_ORG, journal_id: EX_JOURNAL_ID, period_hash: EX_PERIOD_HASH }).fingerprint,
    },
    fees: C.FRAIS_DEFAUT,
    capture_transactions: txs.map((t) => ({ role: t.role, block_number: t.bloc ? Number(BigInt(t.bloc.number)) : null, transaction_hash: t.hash, nonce: Number(t.tx.nonce), max_fee_per_gas: t.tx.max_fee_per_gas.toString(), max_priority_fee_per_gas: t.tx.max_priority_fee_per_gas.toString(), gas_limit: t.tx.gas_limit.toString() })),
  };
  ecrire("constantes.json", constantes);

  const fichierFamille = (family, description, cases) => {
    const doc = { version: 0, family, description, cases };
    const e = J.validerSchema(doc, schemas[C.ID_SCHEMA_OPERATIONS], { registre: schemas, fragment: "#/$defs/fichier_vecteurs" });
    exiger(e.length === 0, `famille ${family} non conforme : ${JSON.stringify(e.slice(0, 2))}`);
    return doc;
  };
  const familles = [];
  const poser = (fichier, doc) => {
    ecrire(fichier, doc);
    familles.push([fichier, doc]);
  };
  poser("identifiants.json", fichierFamille("identifiants", "Slugs et noms de journal admis et refusés ; org_id et journal_id (RG-1, RG-2, 6.2, 6.3).", familleIdentifiants()));
  poser("doctypes.json", fichierFamille("doctypes", "Libellés et valeurs de docType admis et refusés (RG-3, 6.4).", familleDoctypes()));
  poser("empreintes.json", fichierFamille("empreintes", "Empreintes d'ancre keccak256(org_id ‖ journal_id ‖ periodHash) (RG-4, 6.5) ; égales à anchor_fingerprint de CT-1 pour ses trois manifestes.", familleEmpreintes()));
  poser("condenses.json", fichierFamille("condenses", "Champs de clôture (RG-5), six condensés internes et leurs préimages (RG-6 à RG-11), hachage signé et signatures (RG-12), jeux de signatures au seuil (RG-13), dont les cinq opérations au seuil de la capture de CT-6 (EX-A.4).", familleCondenses(capture, txs)));
  poser("appels.json", fichierFamille("appels", "Données d'appel des fonctions écrites par les outils et arguments de constructeur (RG-14, 6.7.2) ; pour chaque transaction de la capture de CT-6, la donnée de la transaction réelle (EX-A.4).", familleAppels(txs)));
  poser("transactions.json", fichierFamille("transactions", "Transactions de type 2 signées et transactions à refuser (RG-15, 6.7.3) ; transactions de la capture de CT-6 recalculées octet pour octet (EX-A.4).", familleTransactions(txs)));

  // Manifestes.
  const man = manifestesInstances(schemas, ecrire, exemples);
  poser("manifestes/manifestes.json", fichierFamille("manifestes", "Manifestes d'instance valides et refusés : verdict de RG-16 à RG-20 et ancre registry dérivée (6.8, 4.8).", man.conceptions.map((c) => man.evaluer(racine, c))));

  // Demandes.
  const dem = familleDemandes(exemples);
  const casDem = [];
  for (const [f, v] of Object.entries(dem.valides)) {
    ecrire(`demandes/valides/${f}`, v.doc);
    const r = C.verifierDemande(v.doc, { schemas, membres: v.members, signataireAttendu: v.signataire ?? null });
    exiger(r.refusal === null, `demande valide ${f} : ${r.refusal?.check} ${r.refusal?.code} ${r.detail}`);
    casDem.push(cas(f.replace(/\.json$/, ""), v.description, ["OP-6", "OP-7"], { file: `demandes/valides/${f}`, members: v.members, administrator: v.signataire ?? null, complete: true }, { result: "valide", digest: v.doc.digest, signers: v.doc.signatures.map((s) => s.signer) }));
  }
  for (const [f, [doc, membres, description, ref]] of Object.entries(dem.invalides)) {
    ecrire(`demandes/invalides/${f}`, doc);
    const r = C.verifierDemande(doc, { schemas, membres });
    exiger(r.refusal && r.refusal.check === ref.check && r.refusal.code === ref.code, `demande invalide ${f} : ${JSON.stringify(r.refusal)} (${r.detail}), conception ${ref.check} ${ref.code}`);
    casDem.push(cas(f.replace(/\.json$/, ""), description, ["OP-6", "OP-7"], { file: `demandes/invalides/${f}`, members: membres, administrator: null, complete: true }, null, ref));
  }
  poser("demandes/demandes.json", fichierFamille("demandes", "Demandes de signature (operations-registre-v0#/$defs/demande_signature) : schéma, OP-6 (condensé recalculé), OP-7 (signatures canoniques, recouvrées, distinctes, rangées, membres et seuil).", casDem));

  // Inscription.
  const ins = familleInscription(exemples);
  const casIns = [];
  for (const [f, [doc, nature, comptes, description]] of Object.entries(ins.valides)) {
    ecrire(`inscription/valides/${f}`, doc);
    const r = C.verifierDossierInscription(doc, { schemas, nature, comptes });
    exiger(r.status === "reussi", `dossier valide ${f} : ${r.code} ${r.detail}`);
    casIns.push(cas(f.replace(/\.json$/, ""), description, ["OP-4"], { file: `inscription/valides/${f}`, nature, operator_accounts: comptes }, { result: "valide", org_id: doc.organisation.org_id }));
  }
  for (const [f, [doc, nature, comptes, description, ref]] of Object.entries(ins.invalides)) {
    ecrire(`inscription/invalides/${f}`, doc);
    const r = C.verifierDossierInscription(doc, { schemas, nature, comptes });
    exiger(r.status === "echoue" && r.check === ref.check && r.code === ref.code, `dossier invalide ${f} : ${r.status} ${r.code} (${r.detail}), conception ${ref.code}`);
    casIns.push(cas(f.replace(/\.json$/, ""), description, ["OP-4"], { file: `inscription/invalides/${f}`, nature, operator_accounts: comptes }, null, ref));
  }
  poser("inscription/inscription.json", fichierFamille("inscription", "Dossiers d'inscription (inscription-client-v0) à toutes les étapes, valides et refusés : schéma et OP-4.", casIns));

  // Capture.
  const cap = familleCapture(capture, schemas, ecrire, racine);
  const imprime = exemples.find((e) => e.schema === "operations-registre").valeur;
  exiger(J.egalJSON(cap.index16648, imprime), "index de capture de 9.4 recalculé différent de l'exemple imprimé");
  poser("capture/capture.json", fichierFamille("capture", "Captures des quatre transactions de la période 1 de la capture de CT-6 et variantes altérées : verdicts CP-2 à CP-6 (CP-4 hors ligne) ; export des parties (EX-9.8 à EX-9.10).", [...cap.conceptions.map((c) => cap.evaluer(c)), cap.exportCas()]));

  ecrire("INDEX.md", index(familles, constantes) + "\n");
  return Object.fromEntries(familles.map(([f, d]) => [d.family, d.cases.length]));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && !process.argv[i + 1]) {
    process.stderr.write("generer-ct4 : --sortie demande un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT4;
  try {
    const r = genererCt4({ racine });
    process.stdout.write(`ct-4 : ${Object.entries(r).map(([f, n]) => `${n} cas ${f}`).join(", ")} sous ${racine}\n`);
  } catch (err) {
    process.stderr.write(`${err.stack ?? err.message}\n`);
    process.exit(1);
  }
}
