#!/usr/bin/env node
// Générateur des vecteurs de CT-3 (spec/CT-3-approbations.md, annexe A) :
// spec/vecteurs/ct-3/.
//
//   node scripts/vecteurs/generer-ct3.mjs [--sortie <répertoire ct-3>]
//   npm run vecteurs:ct3
//
// --sortie doit nommer un répertoire inexistant, vide, ou dont chaque entrée de
// premier niveau est l'une de celles que le générateur écrit (ENTREES_GENEREES)
// ou verificateur-independant/ ; sinon le générateur refuse sans rien effacer.
// Il n'efface jamais que ses propres entrées.
//
// Familles (annexe A.3) :
//
//   constantes.json            constantes de A.2 (clés de test publiques) ;
//   politiques/                politiques valides (A.4) ;
//   politiques-invalides/      politiques refusées et attendu.json (A.4) ;
//   evaluation/                demandes évaluées par politique (A.4) ;
//   candidats/                 outils susceptibles d'approbation (A.4) ;
//   acceptation/               l'épreuve des trois relecteurs (A.5) ;
//   acceptation-attendu.json   ses décisions attendues, hors du répertoire ;
//   tickets/                   traces de cycle de vie (A.6) ;
//   decisions/                 remises valides et invalides (A.7) ;
//   signatures/                normalisation d'EX-9.3 (A.8) ;
//   INDEX.md                   chaque cas et son attendu.
//
// Tout est déterministe (EX-A.1) : comptes 1 à 4 du mnémonique public de
// Hardhat, adresses de registre, de jeu, de bloc, de demande et d'événement
// dérivées par SHA-256 d'étiquettes fixes, horodatages fixes, signatures
// secp256k1 RFC 6979. Le générateur efface et réécrit ses entrées
// (ENTREES_GENEREES), jamais verificateur-independant/.
//
// Une partie des attendus est posée par conception (règle, décision et
// ouverture de chaque demande ; état de chaque ticket après chaque pas, sort et
// raison de chaque entrée, membres choisis de chaque réponse ; décision,
// signataires, motif et source de chaque remise ; tickets des fenêtres), puis
// confrontée à l'implémentation de référence scripts/lib/approbation.mjs : un
// écart arrête la génération. Le reste des attendus (seuil et membres d'une
// remise, objet approval rendu à une ré-émission, bornes et restant des
// fenêtres, jeu des réponses nouveau) sort de l'implémentation sans contrôle de
// conception : le vérificateur Go indépendant le recalcule.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDNodeWallet, Signature, hashMessage, keccak256, toUtf8Bytes } from "ethers";
import * as J from "../lib/journal.mjs";
import * as A from "../lib/approbation.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const REPERTOIRE_CT3 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3");
const REPERTOIRE_SCHEMAS = path.join(PROJECT_ROOT, "spec", "schemas");
const REPERTOIRE_CT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1");
/** Les seules entrées de premier niveau que le générateur écrit, et donc les seules qu'il efface (EX-A.1) ; verificateur-independant/ n'en est pas. */
export const ENTREES_GENEREES = ["INDEX.md", "acceptation", "acceptation-attendu.json", "candidats", "constantes.json", "decisions", "evaluation", "politiques", "politiques-invalides", "signatures", "tickets"];
/** Troisième ligne d'INDEX.md : la marque d'un répertoire produit par ce générateur. */
const MARQUE_INDEX = "Produit par `scripts/vecteurs/generer-ct3.mjs`";

const texteJSON = (v) => JSON.stringify(v, null, 2) + "\n";
const exiger = (condition, message) => {
  if (!condition) throw new Error(`generer-ct3 : ${message}`);
};
const copie = (v) => JSON.parse(JSON.stringify(v));
const sha = (etiquette) => J.sha256(Buffer.from(etiquette, "utf8"));

/** Les trois schémas de CT-3, chargés depuis spec/schemas. */
export function chargerSchemas(repertoire = REPERTOIRE_SCHEMAS) {
  return A.registreSchemas(A.FICHIERS_SCHEMAS.map((f) => JSON.parse(fs.readFileSync(path.join(repertoire, f), "utf8"))));
}

// ---------------------------------------------------------------------------
// Constantes (annexe A.2)
// ---------------------------------------------------------------------------

export const ORG = "assureur-demo";
export const ORG_ID = keccak256(toUtf8Bytes(ORG));
export const JOURNAL = "journal-approbations";
export const JOURNAL_ID = keccak256(toUtf8Bytes(JOURNAL));
export const V1 = "vecteurs-ct3-1";
export const V2 = "vecteurs-ct3-2";
export const CHAIN_ID = 2124;
export const REGISTRE = sha("noortrace/vecteurs/ct3/registre").slice(0, 42);
export const JEU = (n) => sha(`noortrace/vecteurs/ct3/jeu/${n}`).slice(0, 42);
export const BLOC = (h) => sha(`noortrace/vecteurs/ct3/bloc/${h}`);
export const DEMANDE = (k) => sha(`noortrace/vecteurs/ct3/demande/${k}`);
/** Hachage synthétique d'un événement scellé (décision, appel relayé) des traces : étiquette ajoutée par ce générateur. */
export const EVENEMENT = (seq) => sha(`noortrace/vecteurs/ct3/evenement/${seq}`);
const MNEMONIQUE = "test test test test test test test test test test test junk";
const CHEMIN = (i) => `m/44'/60'/0'/0/${i}`;
export const COMPTES = Object.fromEntries([1, 2, 3, 4].map((i) => [i, HDNodeWallet.fromPhrase(MNEMONIQUE, undefined, CHEMIN(i))]));
export const ADR = (i) => COMPTES[i].address.toLowerCase();
const ATTENDUES = { 1: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", 2: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", 3: "0x90f79bf6eb2c4f870365e785982e1f101e93b906", 4: "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65" };
for (const i of [1, 2, 3, 4]) exiger(ADR(i) === ATTENDUES[i], `compte Hardhat ${i} : adresse inattendue`);
exiger(ORG_ID === "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab", "org_id de A.2");
exiger(JOURNAL_ID === "0x3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1", "journal_id de A.2");
export const DEMANDEUR = "u.martin@assureur-demo.example";
const AUTRE_DEMANDEUR = "a.keller@assureur-demo.example";
const TIERS = "u.dupont@assureur-demo.example";
export const INSTANT_BASE = "2026-11-12T09:00:00.000Z";
const T = (hms) => `2026-11-12T${hms}Z`;
const E = 3600000;
const SESSION = (i) => (i === 3 ? DEMANDEUR : `approbateur-${i}@assureur-demo.example`);
const IBAN_A = "CH9300762011623852957";
const IBAN_B = "CH5604835012345678009";

const APPROVER_SET_REGISTRE = { source: "registre", chain_id: CHAIN_ID, registry: REGISTRE, set: JEU(1), members: null, threshold: null };
const APPROVER_SET_STATIQUE = { source: "statique", chain_id: null, registry: null, set: null, members: [ADR(1), ADR(2), ADR(3)], threshold: { required: 2, size: 3 } };
const SEPARATION = { self_approval: "interdite", identities: [{ launched_by: DEMANDEUR, addresses: [ADR(3)] }] };

/** Jeu lu au registre (objet jeu de ticket-v0) : jeu `n`, hauteur `h`, comptes membres, seuil. */
const jeuLu = (n, h, comptes, required) => ({ chain_id: CHAIN_ID, registry: REGISTRE, set: JEU(n), height: h, block_hash: BLOC(h), threshold: { required, size: comptes.length }, members: A.trierAdresses(comptes.map(ADR)) });
const J1 = (h) => jeuLu(1, h, [1, 2, 3], 2);

/** Requête evaluer de 12.3 (CT-2 EX-7.4). */
function requete({ outil = "sap.payments.create", origine = outil, alias = "sap", classe = "ecriture", args = {}, demandeur = DEMANDEUR, version = V1, run = "run-2026-11-12-0001", intent = null }) {
  return {
    tool_announced: outil,
    tool_original: origine,
    server_alias: alias,
    arguments: args,
    class: classe,
    delegation: { launched_by: demandeur, on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: run },
    intent,
    code: { model: "fournisseur/modele@2026-09", prompt_version: null, policy_version: version, recorder: "0.1.0" },
    context: [],
  };
}

// ---------------------------------------------------------------------------
// Politiques (A.4)
// ---------------------------------------------------------------------------

const pred = (p, op, value) => ({ path: p, op, value });
function regle(name, tools, when, level, { decision = null, window = null, contest_ms = 0, description = null } = {}) {
  return { name, description, tools, when, level, decision: level === "automatique" ? decision : null, window: level === "fenetre" ? window : null, contest_ms: level === "automatique" ? null : contest_ms };
}
const auto = (name, tools, when, decision, description = null) => regle(name, tools, when, "automatique", { decision, description });
const defautRevue = (contest_ms = 0) => ({ name: "defaut : revue", description: "Tout appel qu'aucune règle ne couvre est soumis aux approbateurs.", level: "revue", decision: null, contest_ms });
const DEFAUT_AUTORISE = { name: "defaut : autorisation", description: "Politique de test : ce qu'aucune règle ne refuse est autorisé.", level: "automatique", decision: "autorise", contest_ms: null };
const DEFAUT_REFUS = { name: "defaut : refus", description: null, level: "automatique", decision: "refuse", contest_ms: null };
const politique = (defaut, rules, { approver_set = APPROVER_SET_REGISTRE, separation = SEPARATION } = {}) => ({ version: 0, default: defaut, rules, approver_set: copie(approver_set), separation: copie(separation) });

/** La politique de l'exemple complet de CT-3 §4.3, à l'identique (le test la compare au bloc de la spécification). */
export const POLITIQUE_ASSUREUR = {
  version: 0,
  default: { name: "defaut : revue", description: "Tout appel qu'aucune règle ne couvre est soumis aux approbateurs.", level: "revue", decision: null, contest_ms: 0 },
  rules: [
    auto("outil crm.claims.get : lecture autorisee", ["crm.claims.get"], null, "autorise"),
    auto("outil documents.search : lecture autorisee", ["documents.search"], null, "autorise"),
    auto("outil mail.send : envoi autorise vers l'assure", ["mail.send"], pred("/arguments/recipient_role", "egal", "assure"), "autorise", "Courriel à l'assuré du dossier ; tout autre destinataire relève de la règle par défaut."),
    auto("paiement hors CHF", ["sap.payments.create"], { none: [pred("/arguments/currency", "egal", "CHF")] }, "refuse", "Les paiements de sinistre se font en francs suisses."),
    auto("beneficiaire hors liste blanche", ["sap.payments.create"], { none: [pred("/arguments/beneficiary_iban", "dans", [IBAN_A, IBAN_B])] }, "refuse"),
    auto("paiement <= 1000 CHF", ["sap.payments.create"], { all: [pred("/arguments/currency", "egal", "CHF"), pred("/arguments/amount", "strictement_superieur", "0"), pred("/arguments/amount", "inferieur_ou_egal", "1000")] }, "autorise"),
    regle("paiement de 1000 a 5000 CHF", ["sap.payments.create"], { all: [pred("/arguments/currency", "egal", "CHF"), pred("/arguments/amount", "strictement_superieur", "1000"), pred("/arguments/amount", "inferieur_ou_egal", "5000")] }, "fenetre", {
      description: "Une approbation ouvre, pour le même demandeur et le même bénéficiaire, une fenêtre de 8 heures et 20 paiements.",
      window: { duration_ms: 28800000, max_calls: 20, same_arguments: ["/arguments/beneficiary_iban"] },
    }),
    regle("paiement > 5000 CHF", ["sap.payments.create"], { all: [pred("/arguments/currency", "egal", "CHF"), pred("/arguments/amount", "strictement_superieur", "5000")] }, "revue", { description: "Chaque paiement est approuvé au seuil du jeu d'approbateurs." }),
    regle("suppression de sinistre", ["crm.claims.delete"], null, "revue", { description: "Toute suppression attend 15 minutes après le seuil : un autre approbateur peut s'y opposer.", contest_ms: 900000 }),
  ],
  approver_set: { source: "registre", chain_id: 2124, registry: "0x172076e0166d1f9cc711c77adf8488051744980c", set: JEU(1), members: null, threshold: null },
  separation: { self_approval: "interdite", identities: [{ launched_by: DEMANDEUR, addresses: ["0x90f79bf6eb2c4f870365e785982e1f101e93b906"] }] },
};

/** Copie d'une valeur JSON dont chaque objet a ses membres dans l'ordre inverse (AP-17). */
export function permuter(v) {
  if (Array.isArray(v)) return v.map(permuter);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.keys(v).reverse().map((k) => [k, permuter(v[k])]));
  return v;
}

const POLITIQUE_SELECTION = politique(DEFAUT_REFUS, [
  auto("lecture crm autorisee", ["crm__claims.get", "crm__claims.search"], null, "autorise"),
  regle("ecritures sap en revue", ["sap__*"], null, "revue"),
  auto("suppressions refusees", ["*"], { all: [pred("/arguments/action", "existe", null), pred("/arguments/action", "egal", "supprimer")] }, "refuse", "Tout outil, quand l'argument action vaut supprimer."),
]);

const POLITIQUE_POINTEURS = politique(DEFAUT_AUTORISE, [
  auto("echappement ~1", ["ptr__barre"], pred("/arguments/a~1b", "egal", "ok"), "refuse"),
  auto("echappement ~0", ["ptr__tilde"], pred("/arguments/m~0n", "egal", "ok"), "refuse"),
  auto("ordre de decodage", ["ptr__ordre"], pred("/arguments/~01", "egal", "ok"), "refuse"),
  auto("indice de tableau", ["ptr__indice"], pred("/arguments/items/1/id", "egal", "x2"), "refuse"),
  auto("membre nul", ["ptr__nul"], pred("/arguments/n", "existe", null), "refuse"),
  auto("jeton tiret", ["ptr__tiret"], pred("/arguments/items/-", "egal", "x"), "refuse"),
  auto("zero de tete", ["ptr__zero"], pred("/arguments/items/01", "egal", "x"), "refuse"),
  auto("jeton de dix chiffres", ["ptr__long"], pred("/arguments/t/1000000000", "egal", "x"), "refuse"),
  auto("indice hors limites", ["ptr__hors"], pred("/arguments/items/5", "egal", "x"), "refuse"),
  auto("pas a travers une chaine", ["ptr__chaine"], pred("/arguments/s/0", "egal", "a"), "refuse"),
  auto("membre de nom vide", ["ptr__vide"], pred("/arguments/", "egal", "ok"), "refuse"),
  auto("membre de nom numerique", ["ptr__objet"], pred("/arguments/o/0", "egal", "ok"), "refuse"),
]);

const POLITIQUE_NOMBRES = politique(DEFAUT_AUTORISE, [
  auto("egal a 5000", ["num__egal"], pred("/arguments/v", "egal_numerique", "5000"), "refuse"),
  auto("egal a zero", ["num__zero"], pred("/arguments/v", "egal_numerique", "0"), "refuse"),
  auto("superieur a 5000", ["num__sup"], pred("/arguments/v", "strictement_superieur", "5000"), "refuse"),
  auto("superieur a 9.00", ["num__neuf"], pred("/arguments/v", "strictement_superieur", "9.00"), "refuse"),
  auto("superieur ou egal a -0.5", ["num__supeg"], pred("/arguments/v", "superieur_ou_egal", "-0.5"), "refuse"),
  auto("inferieur a zero", ["num__inf"], pred("/arguments/v", "strictement_inferieur", "0"), "refuse"),
  auto("inferieur ou egal au plus petit pas", ["num__infeg"], pred("/arguments/v", "inferieur_ou_egal", "0.000000000000000001"), "refuse"),
  auto("superieur a trente chiffres", ["num__grand"], pred("/arguments/v", "strictement_superieur", "999999999999999999999999999999"), "refuse"),
]);

const POLITIQUE_CHAINES = politique(DEFAUT_AUTORISE, [
  auto("devise CHF", ["str__devise"], pred("/arguments/currency", "egal", "CHF"), "refuse"),
  auto("accent precompose", ["str__accent"], pred("/arguments/nom", "egal", "é"), "refuse"),
  auto("liste blanche", ["str__liste"], pred("/arguments/iban", "dans", [IBAN_A, IBAN_B]), "refuse"),
  auto("prefixe de compte", ["str__prefixe"], pred("/arguments/compte", "commence_par", "CH93"), "refuse"),
  auto("domaine du courriel", ["str__domaine"], pred("/arguments/courriel", "finit_par", "@assureur-demo.example"), "refuse"),
  auto("drapeau urgent", ["str__drapeau"], pred("/arguments/urgent", "egal", true), "refuse"),
  auto("symbole hors du plan de base", ["str__symbole"], pred("/arguments/note", "finit_par", "\u{1D11E}"), "refuse"),
]);

const A1 = pred("/arguments/a", "egal", "1");
const B1 = pred("/arguments/b", "egal", "1");
const POLITIQUE_LOGIQUE = politique(DEFAUT_AUTORISE, [
  auto("toutes", ["log__tout"], { all: [A1, B1] }, "refuse"),
  auto("l'une", ["log__un"], { any: [A1, B1] }, "refuse"),
  auto("l'une, ordre inverse", ["log__un_inverse"], { any: [B1, A1] }, "refuse"),
  auto("aucune", ["log__aucun"], { none: [A1, B1] }, "refuse"),
  auto("imbriquee", ["log__imbrique"], { none: [{ any: [A1, B1] }, { all: [pred("/arguments/c", "egal", "1"), pred("/arguments/d", "existe", null)] }] }, "refuse"),
  auto("garde existe", ["log__garde"], { all: [pred("/arguments/priority", "existe", null), pred("/arguments/priority", "egal", "haute")] }, "refuse", "Exemple de CT-3 §4.10 : priority absent rend la condition FAUX, pas INDETERMINE."),
]);

const MONTANT = (op, v) => pred("/arguments/amount", op, v);
const POLITIQUE_NIVEAUX = politique(defautRevue(0), [
  auto("petit montant", ["pay__virement"], MONTANT("inferieur_ou_egal", "100"), "autorise"),
  auto("petit montant bis", ["pay__virement"], MONTANT("inferieur_ou_egal", "200"), "autorise"),
  regle("fenetre moyenne", ["pay__virement"], { all: [MONTANT("strictement_superieur", "100"), MONTANT("inferieur_ou_egal", "1000")] }, "fenetre", { window: { duration_ms: 3600000, max_calls: 2, same_arguments: ["/arguments/beneficiary"] } }),
  regle("revue elevee", ["pay__virement"], MONTANT("strictement_superieur", "1000"), "revue", { contest_ms: 60000 }),
  regle("revue elevee bis", ["pay__virement"], MONTANT("strictement_superieur", "5000"), "revue"),
  auto("blocage pays", ["pay__virement"], { all: [pred("/arguments/pays", "existe", null), pred("/arguments/pays", "egal", "KP")] }, "refuse"),
  auto("consultation autorisee", ["pay__consultation"], pred("/arguments/mode", "egal", "lecture"), "autorise"),
  regle("fenetre sans portee", ["pay__releve", "pay__releve_detail"], null, "fenetre", { window: { duration_ms: 600000, max_calls: 1, same_arguments: [] } }),
]);

/** AP-12 : parmi les issues de même rang, l'ordre du document désigne la règle retenue (EX-4.9) ; la même politique en ordre inverse. */
const REGLES_ORDRE = [
  regle("revue sans contestation", ["ord__revue"], null, "revue", { contest_ms: 0 }),
  regle("revue avec contestation", ["ord__revue"], null, "revue", { contest_ms: 900000 }),
  regle("fenetre indeterminee", ["ord__fenetre"], null, "fenetre", { window: { duration_ms: 3600000, max_calls: 5, same_arguments: ["/arguments/absent"] } }),
  regle("fenetre determinee", ["ord__fenetre"], null, "fenetre", { window: { duration_ms: 600000, max_calls: 2, same_arguments: ["/arguments/beneficiary"] } }),
  regle("fenetre longue", ["ord__couverte"], null, "fenetre", { window: { duration_ms: 3600000, max_calls: 10, same_arguments: [] } }),
  regle("fenetre courte", ["ord__couverte"], null, "fenetre", { window: { duration_ms: 600000, max_calls: 1, same_arguments: [] } }),
];
const POLITIQUE_ORDRE = politique(defautRevue(0), REGLES_ORDRE);
const POLITIQUE_ORDRE_INVERSE = politique(defautRevue(0), [...REGLES_ORDRE].reverse());

/** Pointeur de n jetons : /arguments/k/k/… */
const pointeurJetons = (n) => "/arguments" + "/k".repeat(n - 1);
/** Condition de profondeur p (un prédicat est au niveau 1). */
const conditionProfonde = (p, feuille) => (p === 1 ? feuille : { all: [conditionProfonde(p - 1, feuille)] });
/** n prédicats en au plus deux niveaux de combinaison (64 au plus par combinaison, schéma). */
const predicats = (n) => Array.from({ length: n }, (_, i) => pred(`/arguments/p${i}`, "existe", null));
const conditionNPredicats = (n) => (n <= 64 ? { all: predicats(n) } : { all: [{ all: predicats(64) }, ...predicats(n - 64).map((p, i) => ({ ...p, path: `/arguments/q${i}` }))] });

const POLITIQUE_BORNES = politique(defautRevue(3599999), [
  auto("pointeur de 32 jetons", ["borne__pointeur"], pred(pointeurJetons(32), "egal", "fond"), "refuse"),
  auto("condition de 8 niveaux", ["borne__profondeur"], conditionProfonde(8, pred("/arguments/x", "egal", "1")), "refuse"),
  auto("64 predicats", ["borne__predicats"], conditionNPredicats(64), "refuse"),
  regle("contestation juste sous l'echeance", ["borne__contestation"], null, "revue", { contest_ms: 3599999 }),
]);

/** Les politiques valides : nom de fichier → { doc, description }. */
export function politiquesValides() {
  return {
    "assureur.json": { doc: POLITIQUE_ASSUREUR, description: "Exemple complet de CT-3 §4.3, même valeur JSON (scénario de l'assureur de CT-1 et CT-2)." },
    "assureur-permute.json": { doc: permuter(POLITIQUE_ASSUREUR), description: "La même politique, chaque objet avec ses membres en ordre inverse (AP-17)." },
    "selection.json": { doc: POLITIQUE_SELECTION, description: "Sélecteurs : noms exacts, préfixe sap__*, * seul ; règle par défaut automatique refuse." },
    "pointeurs.json": { doc: POLITIQUE_POINTEURS, description: "Pointeurs RFC 6901 : un outil par cas, règles automatique refuse (VRAI : refus, INDETERMINE : refus marqué, FAUX : défaut autorise)." },
    "nombres.json": { doc: POLITIQUE_NOMBRES, description: "Comparaisons décimales exactes et typage numérique, un outil par opérateur." },
    "chaines.json": { doc: POLITIQUE_CHAINES, description: "Égalité, appartenance, préfixe, suffixe, booléen, sans normalisation Unicode." },
    "logique.json": { doc: POLITIQUE_LOGIQUE, description: "Combinaisons all, any, none en logique de Kleene ; garde existe." },
    "niveaux.json": { doc: POLITIQUE_NIVEAUX, description: "Les trois niveaux, les rangs, l'égalité de rang, la règle par défaut, les fenêtres." },
    "bornes.json": { doc: POLITIQUE_BORNES, description: "Bornes admises d'EX-4.2 : pointeur de 32 jetons, condition de 8 niveaux, 64 prédicats, contest_ms = expire_after_ms − 1." },
    "ordre.json": { doc: POLITIQUE_ORDRE, description: "Issues de même rang : la première règle du document est retenue, et d'elle viennent contest_ms, la fenêtre ouverte ou consommée (EX-4.9)." },
    "ordre-inverse.json": { doc: POLITIQUE_ORDRE_INVERSE, description: "La politique ordre.json, règles en ordre inverse : même décision, autre règle retenue (EX-4.9)." },
  };
}

// ---------------------------------------------------------------------------
// Évaluation (A.4) : conception des cas
// ---------------------------------------------------------------------------

const T_67 = "2026-11-05T10:00:00.000Z";
const W_APR_3001 = { scope: { policy_version: V1, rule: "paiement de 1000 a 5000 CHF", tool: "sap.payments.create", launched_by: DEMANDEUR, values: [IBAN_A] }, start: "2026-11-05T08:00:00.000Z", end: "2026-11-05T16:00:00.000Z", remaining: 20, ticket: "apr-3001" };
const PAIEMENT = { claim_id: "2026-77812", amount: "7400.00", currency: "CHF", beneficiary_iban: IBAN_A };
const sans = (o, ...cles) => Object.fromEntries(Object.entries(o).filter(([k]) => !cles.includes(k)));

/**
 * Un cas : [id, description, checks, outil, arguments, règle attendue,
 * décision attendue, options { windows, t, demandeur, ouvrant, alias,
 * origine, consomme }].
 */
function casAssureur() {
  const P = (args) => ({ ...PAIEMENT, ...args });
  const c = (id, d, outil, args, rule, decision, o = {}) => [id, d, ["AP-11", "AP-12", "AP-13", ...(o.checks ?? [])], outil, args, rule, decision, { t: T_67, alias: outil.split(".")[0].toLowerCase(), ...o }];
  return [
    c("lecture-inconditionnelle", "crm.claims.get : règle inconditionnelle, rang 1 (CT-3 §6.7).", "crm.claims.get", { claim_id: "2026-77812" }, "outil crm.claims.get : lecture autorisee", "autorise"),
    c("paiement-7400", "7400.00 CHF : paiement > 5000 CHF VRAI, rang 4.", "sap.payments.create", P({}), "paiement > 5000 CHF", "a_approuver"),
    c("beneficiaire-hors-liste", "IBAN hors liste blanche : refus VRAI, rang 5, l'emporte sur la revue.", "sap.payments.create", P({ beneficiary_iban: "CH4431999123000889012" }), "beneficiaire hors liste blanche", "refuse"),
    c("paiement-800", "800 CHF : rang 1.", "sap.payments.create", P({ amount: "800" }), "paiement <= 1000 CHF", "autorise"),
    c("paiement-2500-sans-fenetre", "2500.00 CHF sans fenêtre : fenetre VRAI, rang 3, ticket ouvrant.", "sap.payments.create", P({ amount: "2500.00" }), "paiement de 1000 a 5000 CHF", "a_approuver", { ouvrant: true, checks: ["AP-14"] }),
    c("paiement-2500-fenetre-ouverte", "2500.00 CHF sous la fenêtre apr-3001 : rang 2, 19 appels restants.", "sap.payments.create", P({ amount: "2500.00" }), "paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]", "autorise", { windows: [W_APR_3001], consomme: true, checks: ["AP-14"] }),
    c("paiement-2500-autre-beneficiaire", "Fenêtre ouverte pour un autre bénéficiaire : autre portée, rang 3.", "sap.payments.create", P({ amount: "2500.00", beneficiary_iban: IBAN_B }), "paiement de 1000 a 5000 CHF", "a_approuver", { windows: [W_APR_3001], ouvrant: true, checks: ["AP-14"] }),
    c("paiement-5000-borne", "5000.00 : ≤ 5000 VRAI, > 5000 FAUX, rang 3.", "sap.payments.create", P({ amount: "5000.00" }), "paiement de 1000 a 5000 CHF", "a_approuver", { ouvrant: true, checks: ["AP-8"] }),
    c("paiement-5000-dix-huit-decimales", "5000.000000000000000001 : > 5000 VRAI, rang 4.", "sap.payments.create", P({ amount: "5000.000000000000000001" }), "paiement > 5000 CHF", "a_approuver", { checks: ["AP-8"] }),
    c("paiement-nombre-entier", "7400 en nombre JSON entier : numérique, rang 4.", "sap.payments.create", P({ amount: 7400 }), "paiement > 5000 CHF", "a_approuver", { checks: ["AP-7"] }),
    c("paiement-nombre-non-entier", "7400.5 en nombre JSON : non numérique, les trois règles de montant INDETERMINE ; l'autorisation ne s'applique pas ; rang 4.", "sap.payments.create", P({ amount: 7400.5 }), "paiement > 5000 CHF [indetermine]", "a_approuver", { checks: ["AP-7"] }),
    c("paiement-hors-grammaire", "\"7,400.00\" : hors grammaire, même cas.", "sap.payments.create", P({ amount: "7,400.00" }), "paiement > 5000 CHF [indetermine]", "a_approuver", { checks: ["AP-7"] }),
    c("paiement-montant-absent", "amount absent : même cas.", "sap.payments.create", sans(PAIEMENT, "amount"), "paiement > 5000 CHF [indetermine]", "a_approuver"),
    c("paiement-devise-absente", "currency absent : none d'un INDETERMINE, refus INDETERMINE, rang 5.", "sap.payments.create", sans(PAIEMENT, "currency"), "paiement hors CHF [indetermine]", "refuse"),
    c("paiement-devise-minuscules", "currency \"chf\" : la casse compte, egal FAUX, none VRAI.", "sap.payments.create", P({ currency: "chf" }), "paiement hors CHF", "refuse", { checks: ["AP-9"] }),
    c("paiement-iban-absent-fenetre", "2500.00 CHF, beneficiary_iban absent, fenêtre ouverte : liste blanche INDETERMINE, rang 5 ; la fenêtre n'est pas consommée.", "sap.payments.create", sans(P({ amount: "2500.00" }), "beneficiary_iban"), "beneficiaire hors liste blanche [indetermine]", "refuse", { windows: [W_APR_3001], checks: ["AP-14"] }),
    c("paiement-zero", "\"0\" : > 0 FAUX, > 1000 FAUX ; aucune règle ne s'applique.", "sap.payments.create", P({ amount: "0" }), "defaut : revue", "a_approuver"),
    c("paiement-moins-zero", "\"-0\" vaut zéro : même cas.", "sap.payments.create", P({ amount: "-0" }), "defaut : revue", "a_approuver", { checks: ["AP-8"] }),
    c("courriel-assure", "mail.send à l'assuré : rang 1.", "mail.send", { recipient_role: "assure" }, "outil mail.send : envoi autorise vers l'assure", "autorise"),
    c("courriel-garage", "mail.send au garage : FAUX, la règle par défaut décide.", "mail.send", { recipient_role: "garage" }, "defaut : revue", "a_approuver"),
    c("courriel-sans-role", "mail.send sans recipient_role : INDETERMINE, l'autorisation ne s'applique pas.", "mail.send", {}, "defaut : revue", "a_approuver"),
    c("outil-sans-regle", "sap.payments.list : aucune règle ne le sélectionne.", "sap.payments.list", {}, "defaut : revue", "a_approuver"),
    c("outil-casse", "SAP.payments.create : la casse du nom compte, aucune règle.", "SAP.payments.create", PAIEMENT, "defaut : revue", "a_approuver", { alias: "sap", checks: ["AP-5"] }),
    c("suppression", "crm.claims.delete : revue inconditionnelle, contest_ms 900 000.", "crm.claims.delete", { claim_id: "2026-77812" }, "suppression de sinistre", "a_approuver"),
  ];
}

function casSelection() {
  const c = (id, d, outil, args, rule, decision) => [id, d, ["AP-5", "AP-12"], outil, args, rule, decision, {}];
  return [
    c("nom-exact", "crm__claims.get : nom exact.", "crm__claims.get", {}, "lecture crm autorisee", "autorise"),
    c("nom-exact-casse", "CRM__claims.get : la casse compte ; seule la règle * conditionnelle sélectionne, FAUX ; défaut.", "CRM__claims.get", {}, "defaut : refus", "refuse"),
    c("prefixe", "sap__payments.create : préfixe sap__*.", "sap__payments.create", {}, "ecritures sap en revue", "a_approuver"),
    c("prefixe-seul", "sap__ : le préfixe lui-même est sélectionné.", "sap__", {}, "ecritures sap en revue", "a_approuver"),
    c("prefixe-autre-alias", "sapx__payments.create : sap__ n'en est pas un préfixe.", "sapx__payments.create", {}, "defaut : refus", "refuse"),
    c("prefixe-un-seul-trait-bas", "sap_payments.create : sap__ n'en est pas un préfixe.", "sap_payments.create", {}, "defaut : refus", "refuse"),
    c("etoile", "mail__send avec action supprimer : * seul.", "mail__send", { action: "supprimer" }, "suppressions refusees", "refuse"),
    c("etoile-rang", "crm__claims.get avec action supprimer : le refus (rang 5) l'emporte sur l'autorisation (rang 1).", "crm__claims.get", { action: "supprimer" }, "suppressions refusees", "refuse"),
    c("etoile-garde", "mail__send sans action : existe FAUX, la condition vaut FAUX ; défaut.", "mail__send", {}, "defaut : refus", "refuse"),
    c("etoile-autre-action", "mail__send avec action lire : FAUX ; défaut.", "mail__send", { action: "lire" }, "defaut : refus", "refuse"),
  ];
}

/** Cas d'une politique de test à règles automatique refuse et défaut autorise : `issue` = VRAI, FAUX ou INDETERMINE. */
const casRefus = (P, checks) => (id, d, outil, args, issue) => {
  const r = P.rules.find((x) => x.tools.includes(outil));
  exiger(r, `aucune règle pour ${outil}`);
  const attendu = issue === "VRAI" ? [r.name, "refuse"] : issue === "INDETERMINE" ? [`${r.name} [indetermine]`, "refuse"] : ["defaut : autorisation", "autorise"];
  return [id, d, checks, outil, args, attendu[0], attendu[1], {}];
};

function casPointeurs() {
  const c = casRefus(POLITIQUE_POINTEURS, ["AP-6"]);
  return [
    c("barre-membre", "/arguments/a~1b désigne le membre « a/b ».", "ptr__barre", { "a/b": "ok" }, "VRAI"),
    c("barre-imbrique", "« a/b » n'est pas a puis b : non résolu, INDETERMINE.", "ptr__barre", { a: { b: "ok" } }, "INDETERMINE"),
    c("tilde-membre", "/arguments/m~0n désigne le membre « m~n ».", "ptr__tilde", { "m~n": "ok" }, "VRAI"),
    c("ordre-de-decodage", "~01 se décode en « ~1 » (~1 d'abord, puis ~0).", "ptr__ordre", { "~1": "ok" }, "VRAI"),
    c("ordre-de-decodage-inverse", "Le décodage dans l'autre ordre donnerait « / » : non résolu ici.", "ptr__ordre", { "/": "ok" }, "INDETERMINE"),
    c("indice", "items/1/id : deuxième élément.", "ptr__indice", { items: [{ id: "x1" }, { id: "x2" }] }, "VRAI"),
    c("indice-autre-valeur", "items/1/id résolu, autre valeur : FAUX.", "ptr__indice", { items: [{ id: "x1" }, { id: "x3" }] }, "FAUX"),
    c("membre-nul", "existe sur un membre null : résolu, VRAI.", "ptr__nul", { n: null }, "VRAI"),
    c("membre-absent", "existe sur un membre absent : FAUX (jamais INDETERMINE).", "ptr__nul", {}, "FAUX"),
    c("jeton-tiret", "Le jeton - ne résout pas.", "ptr__tiret", { items: ["x"] }, "INDETERMINE"),
    c("zero-de-tete-tableau", "01 n'est pas un indice de tableau.", "ptr__zero", { items: ["a", "x"] }, "INDETERMINE"),
    c("zero-de-tete-objet", "01 est un nom de membre d'objet : résolu.", "ptr__zero", { items: { "01": "x" } }, "VRAI"),
    c("dix-chiffres-objet", "1000000000 est un nom de membre d'objet : résolu.", "ptr__long", { t: { 1000000000: "x" } }, "VRAI"),
    c("dix-chiffres-tableau", "1000000000 a plus de 9 chiffres : pas un indice de tableau.", "ptr__long", { t: ["x"] }, "INDETERMINE"),
    c("indice-hors-limites", "items/5 d'un tableau de deux éléments.", "ptr__hors", { items: ["a", "b"] }, "INDETERMINE"),
    c("pas-a-travers-une-chaine", "s/0 d'une chaîne : non résolu.", "ptr__chaine", { s: "abc" }, "INDETERMINE"),
    c("membre-de-nom-vide", "/arguments/ désigne le membre de nom vide.", "ptr__vide", { "": "ok" }, "VRAI"),
    c("membre-numerique-objet", "o/0 d'un objet : membre « 0 ».", "ptr__objet", { o: { 0: "ok" } }, "VRAI"),
    c("membre-numerique-tableau", "o/0 d'un tableau : premier élément.", "ptr__objet", { o: ["ok"] }, "VRAI"),
  ];
}

function casNombres() {
  const c = casRefus(POLITIQUE_NOMBRES, ["AP-7", "AP-8"]);
  return [
    c("egal-chaine", "\"5000\" = 5000.", "num__egal", { v: "5000" }, "VRAI"),
    c("egal-echelle", "\"5000.00\" = 5000 : échelles différentes.", "num__egal", { v: "5000.00" }, "VRAI"),
    c("egal-nombre", "5000 en nombre JSON = \"5000\".", "num__egal", { v: 5000 }, "VRAI"),
    c("egal-dix-huit-decimales", "\"5000.000000000000000001\" ≠ 5000.", "num__egal", { v: "5000.000000000000000001" }, "FAUX"),
    c("zero-negatif", "\"-0\" vaut zéro.", "num__zero", { v: "-0" }, "VRAI"),
    c("zero-negatif-decimales", "\"-0.00\" vaut zéro.", "num__zero", { v: "-0.00" }, "VRAI"),
    c("zero-nombre", "0 en nombre JSON.", "num__zero", { v: 0 }, "VRAI"),
    c("superieur-d-un-pas", "\"5000.000000000000000001\" > 5000.", "num__sup", { v: "5000.000000000000000001" }, "VRAI"),
    c("superieur-egalite", "\"5000\" n'est pas > 5000.", "num__sup", { v: "5000" }, "FAUX"),
    c("superieur-ordre-des-chaines", "\"10.00\" > 9.00 numériquement (l'ordre des chaînes dirait le contraire).", "num__neuf", { v: "10.00" }, "VRAI"),
    c("superieur-ou-egal-borne", "\"-0.50\" ≥ -0.5 (égalité, échelles différentes).", "num__supeg", { v: "-0.50" }, "VRAI"),
    c("superieur-ou-egal-sous-la-borne", "\"-0.51\" < -0.5.", "num__supeg", { v: "-0.51" }, "FAUX"),
    c("superieur-ou-egal-negatif-entier", "-1 en nombre JSON < -0.5.", "num__supeg", { v: -1 }, "FAUX"),
    c("inferieur-negatif", "-1 < 0.", "num__inf", { v: -1 }, "VRAI"),
    c("inferieur-plus-petit-pas", "\"-0.000000000000000001\" < 0.", "num__inf", { v: "-0.000000000000000001" }, "VRAI"),
    c("inferieur-moins-zero", "\"-0\" n'est pas < 0.", "num__inf", { v: "-0" }, "FAUX"),
    c("inferieur-ou-egal-pas", "\"0.000000000000000001\" ≤ lui-même.", "num__infeg", { v: "0.000000000000000001" }, "VRAI"),
    c("inferieur-ou-egal-deux-pas", "\"0.000000000000000002\" > 0.000000000000000001.", "num__infeg", { v: "0.000000000000000002" }, "FAUX"),
    c("quarante-huit-chiffres", "30 chiffres et 18 décimales : dans la grammaire, > 999…9 (30 neuf).", "num__grand", { v: "999999999999999999999999999999.000000000000000001" }, "VRAI"),
    c("trente-et-un-chiffres", "31 chiffres avant le point : hors grammaire.", "num__grand", { v: "1000000000000000000000000000000" }, "INDETERMINE"),
    c("dix-neuf-decimales", "19 décimales : hors grammaire.", "num__sup", { v: "0.0000000000000000001" }, "INDETERMINE"),
    c("entier-sur-maximal", "2^53-1 en nombre JSON : numérique.", "num__sup", { v: 9007199254740991 }, "VRAI"),
    c("entier-hors-intervalle", "2^53 en nombre JSON : hors de l'intervalle, non numérique.", "num__sup", { v: 9007199254740992 }, "INDETERMINE"),
    c("nombre-non-entier", "7400.5 en nombre JSON : non numérique.", "num__sup", { v: 7400.5 }, "INDETERMINE"),
    c("separateur-de-milliers", "\"7,400.00\" : hors grammaire.", "num__sup", { v: "7,400.00" }, "INDETERMINE"),
    c("exposant", "\"1e3\" : hors grammaire.", "num__sup", { v: "1e3" }, "INDETERMINE"),
    c("espace-de-tete", "\" 12\" : hors grammaire.", "num__sup", { v: " 12" }, "INDETERMINE"),
    c("signe-plus", "\"+6000\" : hors grammaire.", "num__sup", { v: "+6000" }, "INDETERMINE"),
    c("zero-de-tete", "\"06000\" : hors grammaire.", "num__sup", { v: "06000" }, "INDETERMINE"),
    c("point-de-tete", "\".5\" : hors grammaire.", "num__supeg", { v: ".5" }, "INDETERMINE"),
    c("point-final", "\"6000.\" : hors grammaire.", "num__sup", { v: "6000." }, "INDETERMINE"),
    c("booleen", "true : non numérique.", "num__sup", { v: true }, "INDETERMINE"),
    c("nul", "null : résolu, non numérique.", "num__sup", { v: null }, "INDETERMINE"),
    c("objet", "Un objet : non numérique.", "num__sup", { v: { montant: "6000" } }, "INDETERMINE"),
    c("absent", "v absent : non résolu.", "num__sup", {}, "INDETERMINE"),
  ];
}

function casChaines() {
  const c = casRefus(POLITIQUE_CHAINES, ["AP-9"]);
  return [
    c("egal", "\"CHF\" = \"CHF\".", "str__devise", { currency: "CHF" }, "VRAI"),
    c("egal-casse", "\"chf\" ≠ \"CHF\" : la casse compte.", "str__devise", { currency: "chf" }, "FAUX"),
    c("egal-nombre", "756 (nombre) comparé à une chaîne : autre type, INDETERMINE.", "str__devise", { currency: 756 }, "INDETERMINE"),
    c("egal-booleen", "true comparé à une chaîne : INDETERMINE.", "str__devise", { currency: true }, "INDETERMINE"),
    c("egal-nul", "null comparé à une chaîne : INDETERMINE.", "str__devise", { currency: null }, "INDETERMINE"),
    c("egal-absent", "currency absent : INDETERMINE.", "str__devise", {}, "INDETERMINE"),
    c("sans-normalisation", "é précomposé (U+00E9) égal à lui-même.", "str__accent", { nom: "é" }, "VRAI"),
    c("sans-normalisation-decompose", "e suivi de U+0301 n'est pas égal à é précomposé.", "str__accent", { nom: "é" }, "FAUX"),
    c("dans", "IBAN de la liste.", "str__liste", { iban: IBAN_B }, "VRAI"),
    c("dans-hors-liste", "IBAN hors de la liste.", "str__liste", { iban: "CH4431999123000889012" }, "FAUX"),
    c("dans-autre-type", "42 (nombre) : INDETERMINE.", "str__liste", { iban: 42 }, "INDETERMINE"),
    c("commence-par", "\"CH93…\" commence par CH93.", "str__prefixe", { compte: IBAN_A }, "VRAI"),
    c("commence-par-casse", "\"ch93…\" ne commence pas par CH93.", "str__prefixe", { compte: IBAN_A.toLowerCase() }, "FAUX"),
    c("commence-par-tableau", "Un tableau : INDETERMINE.", "str__prefixe", { compte: ["CH93"] }, "INDETERMINE"),
    c("finit-par", "Adresse du domaine.", "str__domaine", { courriel: "u.martin@assureur-demo.example" }, "VRAI"),
    c("finit-par-autre-domaine", "Le domaine est suivi d'autre chose.", "str__domaine", { courriel: "x@assureur-demo.example.net" }, "FAUX"),
    c("booleen-vrai", "true = true.", "str__drapeau", { urgent: true }, "VRAI"),
    c("booleen-faux", "false ≠ true.", "str__drapeau", { urgent: false }, "FAUX"),
    c("booleen-chaine", "\"true\" (chaîne) comparé à un booléen : INDETERMINE.", "str__drapeau", { urgent: "true" }, "INDETERMINE"),
    c("suffixe-hors-plan-de-base", "Finit par U+1D11E (deux unités UTF-16, quatre octets UTF-8).", "str__symbole", { note: "clé \u{1D11E}" }, "VRAI"),
    c("suffixe-hors-plan-de-base-en-tete", "U+1D11E en tête seulement.", "str__symbole", { note: "\u{1D11E} clé" }, "FAUX"),
  ];
}

function casLogique() {
  const c = casRefus(POLITIQUE_LOGIQUE, ["AP-10"]);
  return [
    c("tout-vrai", "all : VRAI, VRAI.", "log__tout", { a: "1", b: "1" }, "VRAI"),
    c("tout-faux", "all : VRAI, FAUX.", "log__tout", { a: "1", b: "0" }, "FAUX"),
    c("tout-indetermine", "all : VRAI, INDETERMINE.", "log__tout", { a: "1" }, "INDETERMINE"),
    c("tout-indetermine-inverse", "all : INDETERMINE, VRAI.", "log__tout", { b: "1" }, "INDETERMINE"),
    c("tout-faux-absorbe", "all : FAUX, INDETERMINE donne FAUX.", "log__tout", { a: "0" }, "FAUX"),
    c("tout-faux-absorbe-inverse", "all : INDETERMINE, FAUX donne FAUX.", "log__tout", { b: "0" }, "FAUX"),
    c("un-vrai-absorbe", "any : VRAI, INDETERMINE donne VRAI.", "log__un", { a: "1" }, "VRAI"),
    c("un-vrai-absorbe-inverse", "any : INDETERMINE, VRAI donne VRAI.", "log__un", { b: "1" }, "VRAI"),
    c("un-faux", "any : FAUX, FAUX.", "log__un", { a: "0", b: "0" }, "FAUX"),
    c("un-indetermine", "any : FAUX, INDETERMINE.", "log__un", { a: "0" }, "INDETERMINE"),
    c("un-inverse-vrai", "any en ordre inverse : même valeur.", "log__un_inverse", { a: "1" }, "VRAI"),
    c("un-inverse-indetermine", "any en ordre inverse : même valeur.", "log__un_inverse", { a: "0" }, "INDETERMINE"),
    c("aucun-vrai", "none : FAUX, FAUX donne VRAI.", "log__aucun", { a: "0", b: "0" }, "VRAI"),
    c("aucun-faux", "none : VRAI, INDETERMINE donne FAUX.", "log__aucun", { a: "1" }, "FAUX"),
    c("aucun-faux-inverse", "none : INDETERMINE, VRAI donne FAUX.", "log__aucun", { b: "1" }, "FAUX"),
    c("aucun-indetermine", "none : FAUX, INDETERMINE donne INDETERMINE.", "log__aucun", { a: "0" }, "INDETERMINE"),
    c("imbriquee-vrai", "none[any FAUX, all FAUX] : VRAI.", "log__imbrique", { a: "0", b: "0", c: "0" }, "VRAI"),
    c("imbriquee-faux", "none[any VRAI, …] : FAUX.", "log__imbrique", { b: "1" }, "FAUX"),
    c("imbriquee-existe", "none[any FAUX, all[VRAI, existe FAUX]] : VRAI.", "log__imbrique", { a: "0", b: "0", c: "1" }, "VRAI"),
    c("imbriquee-indetermine", "none[any INDETERMINE, all FAUX] : INDETERMINE.", "log__imbrique", { a: "0", c: "0" }, "INDETERMINE"),
    c("garde-absent", "priority absent : existe FAUX, all FAUX.", "log__garde", {}, "FAUX"),
    c("garde-haute", "priority haute : VRAI.", "log__garde", { priority: "haute" }, "VRAI"),
    c("garde-basse", "priority basse : FAUX.", "log__garde", { priority: "basse" }, "FAUX"),
    c("garde-autre-type", "priority 3 : existe VRAI, egal INDETERMINE.", "log__garde", { priority: 3 }, "INDETERMINE"),
  ];
}

const T_NIV = "2026-11-12T10:00:00.000Z";
const W_RELEVE = { scope: { policy_version: V1, rule: "fenetre sans portee", tool: "pay__releve", launched_by: DEMANDEUR, values: [] }, start: "2026-11-12T09:55:00.000Z", end: "2026-11-12T10:05:00.000Z", remaining: 1, ticket: "apr-0043" };
const W_NIV = (o = {}) => ({ scope: { policy_version: V1, rule: "fenetre moyenne", tool: "pay__virement", launched_by: DEMANDEUR, values: [IBAN_A], ...(o.scope ?? {}) }, start: "2026-11-12T09:30:00.000Z", end: "2026-11-12T10:30:00.000Z", remaining: 2, ticket: "apr-0042", ...sans(o, "scope") });
function casNiveaux() {
  const c = (id, d, checks, outil, args, rule, decision, o = {}) => [id, d, checks, outil, args, rule, decision, { t: T_NIV, ...o }];
  const V = (args) => ({ beneficiary: IBAN_A, ...args });
  return [
    c("automatique-autorise-egalite-de-rang", "50 : petit montant et petit montant bis VRAI au rang 1 ; la première du document est nommée.", ["AP-11", "AP-12", "AP-13"], "pay__virement", { amount: "50" }, "petit montant", "autorise"),
    c("fenetre-portee-indeterminee", "150 sans beneficiary : condition VRAI, portée indéterminée : rang 3 marqué, ticket non ouvrant.", ["AP-11", "AP-13", "AP-15"], "pay__virement", { amount: "150" }, "fenetre moyenne [indetermine]", "a_approuver"),
    c("fenetre-ouvrante", "150 avec beneficiary, aucune fenêtre : rang 3 (l'emporte sur petit montant bis, rang 1), ticket ouvrant.", ["AP-11", "AP-12", "AP-14"], "pay__virement", V({ amount: "150" }), "fenetre moyenne", "a_approuver", { ouvrant: true }),
    c("fenetre-couverte", "Fenêtre apr-0042 ouverte, même portée : rang 2, une unité consommée.", ["AP-11", "AP-13", "AP-14"], "pay__virement", V({ amount: "150" }), "fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]", "autorise", { windows: [W_NIV()], consomme: true }),
    c("fenetre-dernier-appel", "Dernière unité : restant passe à 0, la fenêtre reste dans l'état.", ["AP-14"], "pay__virement", V({ amount: "999.99" }), "fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]", "autorise", { windows: [W_NIV({ remaining: 1 })], consomme: true }),
    c("fenetre-epuisee", "restant = 0 : la fenêtre ne couvre plus ; rang 3, ticket ouvrant.", ["AP-15"], "pay__virement", V({ amount: "150" }), "fenetre moyenne", "a_approuver", { windows: [W_NIV({ remaining: 0 })], ouvrant: true }),
    c("fenetre-debut-inclus", "t = debut : couvert.", ["AP-14"], "pay__virement", V({ amount: "150" }), "fenetre moyenne [fenetre apr-0042 2026-11-12T10:30:00.000Z]", "autorise", { windows: [W_NIV()], consomme: true, t: "2026-11-12T09:30:00.000Z" }),
    c("fenetre-fin-exclue", "t = fin : fermée ; rang 3.", ["AP-15"], "pay__virement", V({ amount: "150" }), "fenetre moyenne", "a_approuver", { windows: [W_NIV()], ouvrant: true, t: "2026-11-12T10:30:00.000Z" }),
    c("fenetre-autre-demandeur", "Même bénéficiaire, autre demandeur : autre portée.", ["AP-14"], "pay__virement", V({ amount: "150" }), "fenetre moyenne", "a_approuver", { windows: [W_NIV()], ouvrant: true, demandeur: AUTRE_DEMANDEUR }),
    c("fenetre-autre-beneficiaire", "Autre bénéficiaire : autre portée.", ["AP-14"], "pay__virement", V({ amount: "150", beneficiary: IBAN_B }), "fenetre moyenne", "a_approuver", { windows: [W_NIV()], ouvrant: true }),
    c("fenetre-autre-version", "Fenêtre d'une autre policy_version : ne couvre pas (EX-4.12).", ["AP-15"], "pay__virement", V({ amount: "150" }), "fenetre moyenne", "a_approuver", { windows: [W_NIV({ scope: { policy_version: "vecteurs-ct3-0" } })], ouvrant: true }),
    c("fenetre-non-consommee", "Fenêtre qui couvre, mais blocage pays (rang 5) l'emporte : rien n'est consommé.", ["AP-12", "AP-14"], "pay__virement", V({ amount: "150", pays: "KP" }), "blocage pays", "refuse", { windows: [W_NIV()] }),
    c("revue", "2000 : revue elevee, rang 4.", ["AP-11"], "pay__virement", V({ amount: "2000" }), "revue elevee", "a_approuver"),
    c("revue-egalite-de-rang", "6000 : deux revues VRAI au rang 4 ; la première du document.", ["AP-12"], "pay__virement", V({ amount: "6000" }), "revue elevee", "a_approuver"),
    c("refus", "pays KP : refus, rang 5.", ["AP-11", "AP-12"], "pay__virement", V({ amount: "6000", pays: "KP" }), "blocage pays", "refuse"),
    c("refus-indetermine", "pays 1 (nombre) : existe VRAI, egal INDETERMINE : refus marqué.", ["AP-11", "AP-13"], "pay__virement", V({ amount: "6000", pays: 1 }), "blocage pays [indetermine]", "refuse"),
    c("montant-absent", "amount absent : autorisations sans effet, fenêtre et revues INDETERMINE ; revue elevee marquée.", ["AP-11", "AP-12", "AP-13"], "pay__virement", V({}), "revue elevee [indetermine]", "a_approuver"),
    c("defaut-autre-outil", "pay__inconnu : aucune règle ne le sélectionne.", ["AP-12"], "pay__inconnu", {}, "defaut : revue", "a_approuver"),
    c("consultation", "mode lecture : rang 1.", ["AP-11"], "pay__consultation", { mode: "lecture" }, "consultation autorisee", "autorise"),
    c("consultation-faux", "mode ecriture : FAUX, défaut.", ["AP-12"], "pay__consultation", { mode: "ecriture" }, "defaut : revue", "a_approuver"),
    c("consultation-indeterminee", "mode absent : l'autorisation INDETERMINE ne s'applique pas ; la règle par défaut décide.", ["AP-11", "AP-12"], "pay__consultation", {}, "defaut : revue", "a_approuver"),
    c("fenetre-sans-portee-ouvrante", "same_arguments vide : la portée est (version, règle, demandeur) ; ticket ouvrant.", ["AP-14"], "pay__releve", {}, "fenetre sans portee", "a_approuver", { ouvrant: true }),
    c("fenetre-sans-portee-couverte", "Fenêtre sans valeurs, une unité : consommée.", ["AP-14"], "pay__releve", { periode: "2026-10" }, "fenetre sans portee [fenetre apr-0043 2026-11-12T10:05:00.000Z]", "autorise", { windows: [W_RELEVE], consomme: true }),
    c("fenetre-autre-outil", "Règle fenetre à deux outils : la fenêtre ouverte pour pay__releve ne couvre pas pay__releve_detail, autre portée (EX-5.2) ; rang 3, ticket ouvrant.", ["AP-14"], "pay__releve_detail", { periode: "2026-10" }, "fenetre sans portee", "a_approuver", { windows: [W_RELEVE], ouvrant: true }),
  ];
}

/** AP-12 : la même demande sous ordre.json et ordre-inverse.json ; `inverse` choisit l'attendu. */
const W_LONGUE = { scope: { policy_version: V1, rule: "fenetre longue", tool: "ord__couverte", launched_by: DEMANDEUR, values: [] }, start: "2026-11-12T09:30:00.000Z", end: "2026-11-12T10:30:00.000Z", remaining: 10, ticket: "apr-0051" };
const W_COURTE = { scope: { policy_version: V1, rule: "fenetre courte", tool: "ord__couverte", launched_by: DEMANDEUR, values: [] }, start: "2026-11-12T09:55:00.000Z", end: "2026-11-12T10:05:00.000Z", remaining: 1, ticket: "apr-0052" };
function casOrdre(inverse) {
  const c = (id, d, checks, outil, args, [rule, decision, o], [ruleI, decisionI, oI]) => (inverse ? [id, d, checks, outil, args, ruleI, decisionI, { t: T_NIV, ...oI }] : [id, d, checks, outil, args, rule, decision, { t: T_NIV, ...o }]);
  return [
    c("revue-meme-rang", "Deux règles revue VRAI au rang 4 : la première du document est retenue, avec son contest_ms (0 dans ordre.json, 900 000 dans ordre-inverse.json) ; la décision ne change pas.", ["AP-12"], "ord__revue", {}, ["revue sans contestation", "a_approuver", { contest: 0 }], ["revue avec contestation", "a_approuver", { contest: 900000 }]),
    c("fenetre-meme-rang", "Deux règles fenetre au rang 3, l'une de portée indéterminée (marquée, non ouvrante), l'autre VRAI (ouvrante) : la première du document décide si le ticket ouvrira une fenêtre.", ["AP-12", "AP-14"], "ord__fenetre", { beneficiary: IBAN_A }, ["fenetre indeterminee [indetermine]", "a_approuver", { contest: 0 }], ["fenetre determinee", "a_approuver", { contest: 0, ouvrant: true }]),
    c("fenetres-couvrantes", "Deux fenêtres de deux règles couvrent la demande au rang 2 : seule celle de la première règle du document est consommée.", ["AP-12", "AP-14"], "ord__couverte", {}, ["fenetre longue [fenetre apr-0051 2026-11-12T10:30:00.000Z]", "autorise", { windows: [W_LONGUE, W_COURTE], consomme: true }], ["fenetre courte [fenetre apr-0052 2026-11-12T10:05:00.000Z]", "autorise", { windows: [W_LONGUE, W_COURTE], consomme: true }]),
  ];
}

function casBornes() {
  const fond = (n) => {
    let v = "fond";
    for (let i = 0; i < n - 1; i++) v = { k: v };
    return v;
  };
  return [
    ["pointeur-32-jetons", "Pointeur de 32 jetons sur un objet de 31 niveaux : résolu.", ["AP-3", "AP-6"], "borne__pointeur", fond(32), "pointeur de 32 jetons", "refuse", {}],
    ["condition-8-niveaux", "Condition de 8 niveaux.", ["AP-3", "AP-10"], "borne__profondeur", { x: "1" }, "condition de 8 niveaux", "refuse", {}],
    ["64-predicats", "64 prédicats existe, tous VRAI.", ["AP-3"], "borne__predicats", Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`p${i}`, i])), "64 predicats", "refuse", {}],
    ["64-predicats-un-absent", "63 prédicats VRAI, un FAUX : la règle ne s'applique pas ; défaut revue.", ["AP-3"], "borne__predicats", Object.fromEntries(Array.from({ length: 63 }, (_, i) => [`p${i}`, i])), "defaut : revue", "a_approuver", {}],
  ];
}

/** Les fichiers d'évaluation : politique → cas. */
function conceptionEvaluation() {
  const assureur = casAssureur();
  // AP-17 : la même politique et les mêmes arguments, membres en ordre inverse, mêmes sorties.
  const permute = assureur.map(([id, d, checks, outil, args, rule, decision, o]) => [id, `${d} Membres des arguments en ordre inverse.`, [...new Set([...checks, "AP-17"])], outil, permuter(args), rule, decision, o]);
  return {
    "assureur.json": { policy: "assureur.json", cas: assureur },
    "assureur-permute.json": { policy: "assureur-permute.json", cas: permute },
    "selection.json": { policy: "selection.json", cas: casSelection() },
    "pointeurs.json": { policy: "pointeurs.json", cas: casPointeurs() },
    "nombres.json": { policy: "nombres.json", cas: casNombres() },
    "chaines.json": { policy: "chaines.json", cas: casChaines() },
    "logique.json": { policy: "logique.json", cas: casLogique() },
    "niveaux.json": { policy: "niveaux.json", cas: casNiveaux() },
    "bornes.json": { policy: "bornes.json", cas: casBornes() },
    "ordre.json": { policy: "ordre.json", cas: casOrdre(false) },
    "ordre-inverse.json": { policy: "ordre-inverse.json", cas: casOrdre(true) },
  };
}

/** Alias de serveur (CT-2 EX-4.9) et nom d'origine (EX-4.10) d'un nom annoncé des vecteurs : <alias>__<origine>, sinon préfixe désactivé. */
const aliasDe = (outil) => (outil.includes("__") ? outil.split("__")[0] : outil.split(".")[0]).toLowerCase().replace(/[^a-z0-9-]/g, "-");
const origineDe = (outil) => (outil.includes("__") && outil.split("__")[1] !== "" ? outil.slice(outil.indexOf("__") + 2) : outil);

/** Écrit un fichier d'évaluation après confrontation de chaque cas à la conception. */
function fichierEvaluation(nomPolitique, doc, cas) {
  const cases = cas.map(([id, description, checks, outil, args, rule, decision, o]) => {
    const t = o.t ?? T_NIV;
    const windows = copie(o.windows ?? []);
    const request = requete({ outil, origine: origineDe(outil), alias: o.alias ?? aliasDe(outil), classe: "ecriture", args, demandeur: o.demandeur ?? DEMANDEUR, version: V1 });
    const r = A.evaluer(doc, request, { fenetres: windows, t, policy_version: V1 });
    exiger(r.rule === rule && r.decision === decision, `évaluation ${nomPolitique}/${id} : attendu ${decision} « ${rule} », obtenu ${r.decision} « ${r.rule} »`);
    exiger((r.opening !== null) === Boolean(o.ouvrant), `évaluation ${nomPolitique}/${id} : ouverture ${r.opening !== null}, conception ${Boolean(o.ouvrant)}`);
    exiger((r.fenetreConsommee !== null) === Boolean(o.consomme), `évaluation ${nomPolitique}/${id} : consommation ${r.fenetreConsommee}, conception ${Boolean(o.consomme)}`);
    if (o.consomme) exiger(r.fenetres[r.fenetreConsommee].remaining === windows[r.fenetreConsommee].remaining - 1, `évaluation ${nomPolitique}/${id} : une unité consommée`);
    else exiger(J.egalJSON(r.fenetres, windows), `évaluation ${nomPolitique}/${id} : fenêtres inchangées`);
    if (o.contest !== undefined) exiger(r.contest_ms === o.contest, `évaluation ${nomPolitique}/${id} : contest_ms ${r.contest_ms}, conception ${o.contest}`);
    if (o.consomme && o.windows) exiger(r.fenetres[r.fenetreConsommee].ticket === r.rule.split(" [fenetre ")[1].split(" ")[0], `évaluation ${nomPolitique}/${id} : fenêtre consommée`);
    return { id, description, checks, t, windows, request, expected: { rule: r.rule, decision: r.decision, contest_ms: r.contest_ms, opening: r.opening, windows: r.fenetres } };
  });
  return { version: 0, policy: `politiques/${nomPolitique}`, policy_version: V1, cases };
}

// ---------------------------------------------------------------------------
// Candidats (A.4, EX-4.11)
// ---------------------------------------------------------------------------

function conceptionCandidats() {
  const L412 = ["crm.claims.get", "crm.claims.delete", "documents.search", "mail.send", "sap.payments.create", "sap.payments.list"];
  return {
    "assureur.json": [
      ["exemple-4-12", ["AP-16"], L412, ["crm.claims.delete", "mail.send", "sap.payments.create", "sap.payments.list"]],
      ["ordre-et-doublons", ["AP-16"], ["sap.payments.list", "crm.claims.get", "sap.payments.list", "mail.send", "documents.search", "crm.claims.delete", "mail.send"], ["sap.payments.list", "mail.send", "crm.claims.delete"]],
      ["liste-vide", ["AP-16"], [], []],
      ["outil-inconnu", ["AP-16"], ["erp.invoices.cancel"], ["erp.invoices.cancel"]],
    ],
    "pointeurs.json": [
      ["defaut-autorise", ["AP-16"], ["ptr__barre", "ptr__autre", "ptr__nul", "ptr__barre"], ["ptr__barre", "ptr__nul"]],
    ],
    "selection.json": [
      ["regle-etoile-refus", ["AP-16"], ["crm__claims.get", "mail__send", "CRM__claims.get"], ["crm__claims.get", "mail__send", "CRM__claims.get"]],
    ],
    "niveaux.json": [
      ["defaut-revue", ["AP-16"], ["pay__virement", "pay__consultation", "pay__releve", "pay__inconnu"], ["pay__virement", "pay__consultation", "pay__releve", "pay__inconnu"]],
    ],
    "nombres.json": [
      ["regles-de-refus", ["AP-16"], ["num__egal", "num__autre", "num__grand"], ["num__egal", "num__grand"]],
    ],
  };
}

// ---------------------------------------------------------------------------
// Politiques invalides (A.4)
// ---------------------------------------------------------------------------

const BASE_INVALIDE = () => politique(defautRevue(0), [
  auto("lecture autorisee", ["crm__claims.get"], null, "autorise"),
  regle("paiement en revue", ["sap__payments.create"], MONTANT("strictement_superieur", "5000"), "revue"),
  regle("paiement moyen", ["sap__payments.create"], { all: [MONTANT("strictement_superieur", "1000"), MONTANT("inferieur_ou_egal", "5000")] }, "fenetre", { window: { duration_ms: 3600000, max_calls: 5, same_arguments: ["/arguments/beneficiary_iban"] } }),
]);
const modifier = (f) => {
  const p = BASE_INVALIDE();
  f(p);
  return p;
};

/** Politiques refusées : [fichier, checks, environment, expire_after_ms, document, erreurs attendues, description]. */
function conceptionInvalides() {
  const schema = [{ code: "schema", pointer: null }];
  const S = (fichier, checks, f, description) => [fichier, checks, "developpement", E, modifier(f), schema, description];
  const ident = (n) => ({ launched_by: n, addresses: [ADR(3)] });
  return [
    S("schema-version.json", ["AP-1"], (p) => (p.version = 1), "version 1 : la constante du format est 0."),
    S("schema-membre-inconnu.json", ["AP-1"], (p) => (p.comment = "membre hors du schéma"), "Membre de premier niveau non admis."),
    S("schema-decision-manquante.json", ["AP-1"], (p) => (p.rules[0].decision = null), "Règle automatique sans décision."),
    S("schema-fenetre-sans-window.json", ["AP-1"], (p) => (p.rules[2].window = null), "Règle fenetre sans window."),
    S("schema-defaut-fenetre.json", ["AP-1"], (p) => (p.default.level = "fenetre"), "La règle par défaut ne peut pas être de niveau fenetre."),
    S("schema-litteral-nombre.json", ["AP-1", "AP-7"], (p) => (p.rules[1].when.value = 5000), "Littéral numérique écrit en nombre JSON : toujours une chaîne D."),
    S("schema-litteral-exposant.json", ["AP-1", "AP-7"], (p) => (p.rules[1].when.value = "5e3"), "Littéral \"5e3\" hors de la grammaire D."),
    S("schema-joker-interne.json", ["AP-1", "AP-5"], (p) => (p.rules[1].tools = ["sap*create"]), "Joker ailleurs qu'en fin de sélecteur : aucun autre joker n'existe."),
    S("schema-double-joker.json", ["AP-1", "AP-5"], (p) => (p.rules[1].tools = ["sap**"]), "Deux jokers finaux."),
    S("schema-pointeur-hors-arguments.json", ["AP-1"], (p) => (p.rules[1].when.path = "/amount"), "Pointeur qui ne commence pas par /arguments."),
    S("schema-pointeur-echappement.json", ["AP-1", "AP-6"], (p) => (p.rules[1].when.path = "/arguments/a~2b"), "Échappement ~2 invalide (RFC 6901)."),
    S("schema-nom-crochet.json", ["AP-1", "AP-13"], (p) => (p.rules[1].name = "paiement [urgent]"), "Crochet dans un nom de règle."),
    S("schema-nom-espace-final.json", ["AP-1", "AP-13"], (p) => (p.rules[1].name = "paiement en revue "), "Espace en fin de nom."),
    S("schema-expression-reguliere.json", ["AP-1"], (p) => (p.rules[1].when = { path: "/arguments/amount", op: "correspond", value: "^[0-9]+$" }), "Opérateur d'expression régulière : le langage n'en a pas (EX-4.13)."),
    S("schema-statique-avec-chaine.json", ["AP-1"], (p) => (p.approver_set = { ...APPROVER_SET_STATIQUE, chain_id: CHAIN_ID }), "Jeu statique qui porte un chain_id (nul exigé pour statique)."),
    S("schema-erreurs-multiples.json", ["AP-1"], (p) => {
      p.version = 2;
      p.rules[0].level = "manuel";
      p.rules[1].when.value = 5000;
      p.separation.self_approval = "souvent";
    }, "Quatre non-conformités au schéma : une seule entrée schema."),
    S("schema-et-nom-double.json", ["AP-1", "AP-2"], (p) => {
      p.version = 1;
      p.rules[2].name = "lecture autorisee";
    }, "Non conforme au schéma (version 1) et nom en double : exactement l'entrée schema, aucune autre règle n'est vérifiée (EX-4.2)."),
    ["nom-double.json", ["AP-2"], "developpement", E, modifier((p) => (p.rules[2].name = "lecture autorisee")), [{ code: "nom_double", pointer: "/rules/2/name" }], "La troisième règle reprend le nom de la première (exemple de CT-3 annexe A.4)."],
    ["nom-de-la-regle-par-defaut.json", ["AP-2"], "developpement", E, modifier((p) => (p.rules[1].name = "defaut : revue")), [{ code: "nom_double", pointer: "/rules/1/name" }], "Une règle porte le nom de la règle par défaut."],
    ["pointeur-trop-long.json", ["AP-3"], "developpement", E, modifier((p) => {
      p.rules[1].when.path = pointeurJetons(33);
      p.rules[2].window.same_arguments = [pointeurJetons(33)];
    }), [{ code: "pointeur_trop_long", pointer: "/rules/1/when/path" }, { code: "pointeur_trop_long", pointer: "/rules/2/window/same_arguments/0" }], "Pointeurs de 33 jetons, dans un prédicat et dans same_arguments."],
    ["condition-trop-profonde.json", ["AP-3"], "developpement", E, modifier((p) => (p.rules[1].when = conditionProfonde(9, MONTANT("strictement_superieur", "5000")))), [{ code: "condition_trop_profonde", pointer: "/rules/1/when" }], "Condition de 9 niveaux."],
    ["trop-de-predicats.json", ["AP-3"], "developpement", E, modifier((p) => (p.rules[1].when = conditionNPredicats(65))), [{ code: "trop_de_predicats", pointer: "/rules/1/when" }], "65 prédicats dans une règle."],
    ["substitut-isole.json", ["AP-4"], "developpement", E, modifier((p) => (p.rules[1].description = "paiement \ud800 en revue")), [{ code: "substitut_isole", pointer: "/rules/1/description" }], "Substitut isolé U+D800 dans une description (écrit \\ud800 dans le fichier)."],
    ["launched-by-double.json", ["AP-4"], "developpement", E, modifier((p) => (p.separation.identities = [ident(DEMANDEUR), ident(AUTRE_DEMANDEUR), ident(DEMANDEUR)])), [{ code: "launched_by_double", pointer: "/separation/identities/2/launched_by" }], "Le même launched_by deux fois dans separation.identities."],
    ["contest-ms-egal-echeance.json", ["AP-4"], "developpement", E, modifier((p) => (p.rules[1].contest_ms = E)), [{ code: "contest_ms_trop_long", pointer: "/rules/1/contest_ms" }], "contest_ms égal à expire_after_ms (3 600 000)."],
    ["contest-ms-defaut.json", ["AP-4"], "developpement", 600000, modifier((p) => (p.default.contest_ms = 900000)), [{ code: "contest_ms_trop_long", pointer: "/default/contest_ms" }], "Règle par défaut à contest_ms 900 000 sous expire_after_ms 600 000."],
    ["statique-seuil-incoherent.json", ["AP-4"], "developpement", E, modifier((p) => (p.approver_set = { ...APPROVER_SET_STATIQUE, threshold: { required: 2, size: 4 } })), [{ code: "seuil_statique_incoherent", pointer: "/approver_set/threshold" }], "Jeu statique de trois membres déclaré de taille 4 (EX-8.2, point 1)."],
    ["statique-en-production.json", ["AP-4"], "production", E, modifier((p) => (p.approver_set = copie(APPROVER_SET_STATIQUE))), [{ code: "jeu_statique_en_production", pointer: "/approver_set/source" }], "Jeu statique chargé en production (EX-8.2, point 2)."],
    ["erreurs-multiples.json", ["AP-2", "AP-4"], "production", E, modifier((p) => {
      p.rules[2].name = "paiement en revue";
      p.rules[2].contest_ms = 4000000;
      p.separation.identities = [ident(DEMANDEUR), ident(DEMANDEUR)];
      p.approver_set = { ...APPROVER_SET_STATIQUE, threshold: { required: 4, size: 3 } };
    }), [
      { code: "jeu_statique_en_production", pointer: "/approver_set/source" },
      { code: "seuil_statique_incoherent", pointer: "/approver_set/threshold" },
      { code: "contest_ms_trop_long", pointer: "/rules/2/contest_ms" },
      { code: "nom_double", pointer: "/rules/2/name" },
      { code: "launched_by_double", pointer: "/separation/identities/1/launched_by" },
    ], "Cinq erreurs au-delà du schéma : la liste complète, triée par pointeur puis par code."],
    ["ordre-des-pointeurs.json", ["AP-2"], "developpement", E, modifier((p) => {
      for (let i = 3; i <= 10; i++) p.rules.push(auto(`lecture ${i}`, [`crm__lecture_${i}`], null, "autorise"));
      p.rules[2].name = "lecture autorisee";
      p.rules[10].name = "lecture 4";
    }), [{ code: "nom_double", pointer: "/rules/10/name" }, { code: "nom_double", pointer: "/rules/2/name" }], "Onze règles, noms en double aux indices 2 et 10 : les pointeurs se trient comme des chaînes (« /rules/10 » avant « /rules/2 »), sans ordre numérique des indices (A.4)."],
  ];
}

// ---------------------------------------------------------------------------
// Épreuve d'acceptation (A.5)
// ---------------------------------------------------------------------------

export const POLITIQUE_ACCEPTATION = politique({ name: "defaut : revue", description: "Tout appel qu'aucune règle ne couvre est soumis aux approbateurs.", level: "revue", decision: null, contest_ms: 0 }, [
  auto("virement hors CHF", ["sap__payments.create"], { none: [pred("/arguments/currency", "egal", "CHF")] }, "refuse", "Tout virement dont la devise n'est pas exactement la chaîne CHF est refusé."),
  auto("virement <= 1000 CHF", ["sap__payments.create"], { all: [pred("/arguments/currency", "egal", "CHF"), pred("/arguments/amount", "strictement_superieur", "0"), pred("/arguments/amount", "inferieur_ou_egal", "1000")] }, "autorise", "Virement en CHF de plus de 0 et d'au plus 1000 : autorisé sans approbation."),
  regle("virement > 1000 CHF", ["sap__payments.create"], { all: [pred("/arguments/currency", "egal", "CHF"), pred("/arguments/amount", "strictement_superieur", "1000")] }, "revue", { description: "Virement en CHF de plus de 1000 : soumis aux approbateurs." }),
]);

/** Les dix cas : [id, outil, arguments, règle attendue, décision attendue, ce qu'il exerce]. */
function conceptionAcceptation() {
  const V = (amount, currency = "CHF") => ({ claim_id: "2026-90417", amount, currency, beneficiary_iban: IBAN_A });
  return [
    ["cas-01", "sap__payments.create", V("800.00"), "virement <= 1000 CHF", "autorise", "montant ordinaire sous la borne"],
    ["cas-02", "sap__payments.create", V("1000"), "virement <= 1000 CHF", "autorise", "égalité exacte à la borne (≤ 1000)"],
    ["cas-03", "sap__payments.create", V("1000.01"), "virement > 1000 CHF", "a_approuver", "juste au-dessus de la borne"],
    ["cas-04", "sap__payments.create", V("2500", "EUR"), "virement hors CHF", "refuse", "autre devise"],
    ["cas-05", "sap__payments.create", sans(V("500"), "currency"), "virement hors CHF [indetermine]", "refuse", "argument absent : la règle restrictive s'applique"],
    ["cas-06", "sap__payments.create", V(1500.5), "virement > 1000 CHF [indetermine]", "a_approuver", "montant en nombre JSON non entier : non numérique"],
    ["cas-07", "sap__payments.list", { claim_id: "2026-90417" }, "defaut : revue", "a_approuver", "outil qu'aucune règle ne couvre : règle par défaut"],
    ["cas-08", "sap__payments.create", V("0"), "defaut : revue", "a_approuver", "aucune règle ne s'applique (> 0 FAUX)"],
    ["cas-09", "sap__payments.create", V(750), "virement <= 1000 CHF", "autorise", "montant en nombre JSON entier : numérique"],
    ["cas-10", "sap__payments.create", { ...V("300"), currency: 756 }, "virement hors CHF [indetermine]", "refuse", "devise d'un autre type (nombre 756) : INDETERMINE"],
  ];
}

const CONSIGNE = `# Épreuve d'acceptation de CT-3 : trois relecteurs, une politique, dix cas

Ce répertoire, avec la partie A de la spécification CT-3, est tout ce que
reçoit un relecteur. Il sert le critère d'acceptation du lot CT-3 : trois
relecteurs, dans les rôles d'approbateur, d'auditeur et de développeur,
lisent la même politique à l'aveugle et en tirent la même décision sur dix
cas (CT-3, annexe A.5, EX-A.4 et EX-A.5).

## Ce que vous recevez

- \`politique.json\` : une politique d'approbation (document
  \`politique-approbation-v0\`), ses règles sur un même outil et sa règle
  par défaut ;
- \`cas/cas-01.json\` à \`cas/cas-10.json\` : dix demandes, chacune la
  requête \`evaluer\` que le noyau de l'enregistreur envoie au service
  d'approbation (\`tool_announced\` est le nom de l'outil, \`arguments\` ses
  arguments, \`delegation.launched_by\` le demandeur) ;
- \`gabarit-reponse.json\` : le fichier à remplir et à rendre ;
- la partie A de la spécification CT-3 (sections 0 à 6), à part.

Pour lire la politique, chaque relecteur lit, dans la partie A : la
section 5 pour les niveaux ; 4.2 pour la forme d'une règle (\`description\`
est sans effet sur la décision) ; 4.4 à 4.11 pour la sélection de l'outil,
les pointeurs, les types (un montant est numérique s'il est une chaîne
décimale ou un nombre JSON entier, EX-4.5), les comparaisons, les
combinaisons \`all\`, \`any\`, \`none\`, la valeur INDETERMINE d'un argument
absent ou d'un autre type, et la règle par défaut ; 6.2 à 6.4 pour l'issue de
chaque règle et le rang qui l'emporte. Le rôle de développeur lit en plus le
reste des sections 4 et 6.

## Ce que vous faites

1. Travaillez seul. Ne consultez ni les réponses des autres relecteurs, ni
   aucun fichier de décisions attendues : il n'est pas dans ce répertoire et
   vous ne devez pas le demander avant d'avoir rendu votre réponse.
2. Pour chaque cas, décidez ce que la politique rend : \`autorise\`,
   \`a_approuver\` ou \`refuse\`. Aucune fenêtre n'est ouverte et aucun ticket
   n'existe : seule la politique décide.
3. Les rôles d'approbateur et d'auditeur n'exécutent aucun code. Le rôle de
   développeur peut écrire son propre code, sans reprendre
   \`scripts/lib/approbation.mjs\` ni le vérificateur Go du dépôt.
4. Copiez \`gabarit-reponse.json\`, inscrivez votre rôle (\`approbateur\`,
   \`auditeur\` ou \`developpeur\`), votre nom ou un pseudonyme, et une
   décision par cas, puis rendez le fichier.

## Résultat

L'épreuve est réussie si les trois réponses sont égales entre elles et
égales, cas par cas, aux décisions attendues que tient l'organisateur
(\`acceptation-attendu.json\`, hors de ce répertoire). L'implémentation de
référence et le vérificateur Go indépendant doivent, eux, rendre exactement
ces décisions attendues. Les réponses des relecteurs ne sont pas des
vecteurs et ne sont pas publiées par le générateur.
`;

// ---------------------------------------------------------------------------
// Traces de tickets (A.6)
// ---------------------------------------------------------------------------

const PAIEMENT_T = (amount, iban = IBAN_A) => ({ claim_id: "2026-90417", amount, currency: "CHF", beneficiary_iban: iban });
const R_PAIEMENT = (amount, o = {}) => requete({ args: PAIEMENT_T(amount, o.iban), demandeur: o.demandeur, version: o.version, run: o.run, intent: o.intent ?? "Régler le sinistre 2026-90417" });
const R_SUPPRESSION = (demandeur = AUTRE_DEMANDEUR) => requete({ outil: "crm.claims.delete", alias: "crm", args: { claim_id: "2026-90417" }, demandeur, intent: "Supprimer le sinistre en double 2026-90417" });
const EV_REVUE = { rule: "paiement > 5000 CHF", decision: "a_approuver", contest_ms: 0, opening: null };
const EV_CONTEST = { rule: "suppression de sinistre", decision: "a_approuver", contest_ms: 900000, opening: null };
const EV_AUTORISE = { rule: "paiement <= 1000 CHF", decision: "autorise", contest_ms: null, opening: null };
const EV_REFUSE = { rule: "beneficiaire hors liste blanche", decision: "refuse", contest_ms: null, opening: null };
const EV_OUVRANT = (iban, { demandeur = DEMANDEUR, version = V1, duration_ms = 600000, max_calls = 3 } = {}) => ({ rule: "paiement de 1000 a 5000 CHF", decision: "a_approuver", contest_ms: 0, opening: { scope: { policy_version: version, rule: "paiement de 1000 a 5000 CHF", tool: "sap.payments.create", launched_by: demandeur, values: [iban] }, duration_ms, max_calls } });
/** Sortie autorise de rang 2 d'une demande couverte par la fenêtre du ticket `ticket`, de fin `fin` (EX-5.5). */
const EV_COUVERT = (ticket, fin) => ({ rule: `paiement de 1000 a 5000 CHF [fenetre ${ticket} ${T(fin)}]`, decision: "autorise", contest_ms: null, opening: null });

/** Objet approval qu'un noyau scelle seul à l'échéance (EX-12.11). */
const approvalNoyau = (ticket, k, at, threshold = { required: 2, size: 3 }) => ({ decision: "expire", ticket, request_hash: DEMANDE(k), threshold, approvers: [], signatures: [], at, reason: A.RAISON_EXPIRATION_NOYAU });
/** Objet approval scellé d'une décision signée par `comptes` (approuve ou refuse) sur la demande `k`. */
const approvalSigne = (ticket, k, decision, comptes, at, reason) => ({ decision, ticket, request_hash: DEMANDE(k), threshold: { required: 2, size: 3 }, approvers: comptes.map(ADR), signatures: comptes.map((c) => A.signerVote(COMPTES[c], { decision, journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: DEMANDE(k), ticket })), at, reason });

/**
 * Entrées de 7.4 ($defs/entree). `k` : numéro de la demande (request_hash =
 * DEMANDE(k)). Un acquittement scelle ou ticket_deja_decide porte l'objet
 * approval scellé ; { "$remise": id } le désigne comme l'approval de cette
 * remise augmenté de at, résolu au moment où le pas est joué.
 */
const X = {
  ev: (at, request, evaluation) => ({ kind: "evaluer", at: T(at), data: { request, evaluation } }),
  ouv: (at, ticket, k, seq, ts) => ({ kind: "ouvrir", at: T(at), data: { ticket, request_hash: DEMANDE(k), request_seq: seq, request_ts: T(ts) } }),
  lu: (at, jeu) => ({ kind: "jeu_lu", at: T(at), data: { status: "lu", jeu, cause: null } }),
  ill: (at, cause) => ({ kind: "jeu_lu", at: T(at), data: { status: "illisible", jeu: null, cause } }),
  vote: (at, ticket, k, compte, decision, reason = null, { signature = null } = {}) => ({
    kind: "voter",
    at: T(at),
    data: { ticket, approver: ADR(compte), decision, signature: signature ?? A.signerVote(COMPTES[compte], { decision, journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: DEMANDE(k), ticket }), reason, session_identity: SESSION(compte) },
  }),
  rec: (at, ticket, compte) => ({ kind: "recuser", at: T(at), data: { ticket, approver: ADR(compte), session_identity: SESSION(compte) } }),
  ret: (at, ticket, by, reason = null) => ({ kind: "retirer", at: T(at), data: { ticket, by, reason } }),
  hor: (at) => ({ kind: "horloge", at: T(at), data: {} }),
  acq: (at, remise_id, result, { reason = null, seq = null, scelle = null, decision = null, held = false, approval = undefined } = {}) => {
    const scellement = result === "scelle" || reason === "ticket_deja_decide";
    return { kind: "acquitter", at: T(at), data: { remise_id, ticket: remise_id.split("/")[0], result, reason, seq, hash: seq === null ? null : EVENEMENT(seq), at: scelle === null ? null : T(scelle), decision, held: result === "scelle" ? held : null, approval: scellement ? (approval ?? { $remise: remise_id }) : null } };
  },
  con: (at, ticket, seq) => ({ kind: "consommer", at: T(at), data: { ticket, seq, hash: EVENEMENT(seq) } }),
  exp: (at, ticket, k, seq, scelle, { threshold } = {}) => ({ kind: "expiration", at: T(at), data: { ticket, seq, hash: EVENEMENT(seq), at: T(scelle), approval: approvalNoyau(ticket, k, T(scelle), threshold) } }),
  ch: (at, version) => ({ kind: "charger", at: T(at), data: { policy_version: version } }),
};
/** Signature d'un vote sur A d'un autre ticket ou d'une autre décision (pour les refus de signature). */
const sigSur = (compte, champs) => A.signerVote(COMPTES[compte], { journal_id: JOURNAL_ID, org_id: ORG_ID, ...champs });
const N_SECP = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** Forme à s haut d'une signature canonique (v inversé). */
export const formeHaute = (sig) => sig.slice(0, 66) + (N_SECP - BigInt("0x" + sig.slice(66, 130))).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
/** Forme v ∈ {0, 1} d'une signature canonique. */
export const formeV01 = (sig) => sig.slice(0, 130) + (sig.slice(130) === "1b" ? "00" : "01");
/** Signature EIP-191 des 66 caractères ASCII de "0x…" au lieu des 32 octets de D_A (EX-9.7) : hashMessage d'une chaîne la prend en UTF-8. */
export const signatureSurChaine = (compte, champs) => Signature.from(COMPTES[compte].signingKey.sign(hashMessage(J.condenseApprobation(A.objetA({ journal_id: JOURNAL_ID, org_id: ORG_ID, ...champs }))))).serialized;

/** Source attendue d'un jeu lu (EX-8.8). */
const SRC = (n, h1, h2, repli = false) => `CuratorSet c=${CHAIN_ID} r=${REGISTRE} s=${JEU(n)} h=${h1}..${h2} b=${BLOC(h2)}${repli ? " repli" : ""}`;
const SRC_STATIQUE = `jeu statique de la politique ${V1}`;
const SERVICE = (o = {}) => ({ max_open_tickets: 20, escalation: [], set_poll_interval_ms: 10000, administrators: [], ...o });

/**
 * Conception d'un pas : [entrée, attendu de conception]. L'attendu de
 * conception : `e` (états de tous les tickets, « apr-0001:ouvert … »), `r`
 * (raison de refus, absente si l'entrée est acceptée), `rep` (membres de la
 * réponse à vérifier), `rem` (remises calculées : [décision, comptes, motif,
 * source, seuil facultatif]), `w` (tickets des fenêtres ouvertes).
 */
function traces() {
  const P1 = () => [X.lu("08:59:00.000", J1(1190)), { e: "" }];
  const ouverture = (k = 1, ticket = `apr-000${k}`, seqDemande = 5) => [
    [X.ouv("09:00:00.250", ticket, k, seqDemande, "09:00:00.200"), { e: `${ticket}:ouvert`, rep: { ticket, state: "ouvert", deadline: T("10:00:00.200") } }],
    [X.lu("09:00:01.000", J1(1200)), { e: `${ticket}:ouvert` }],
  ];
  const prelude = (request = R_PAIEMENT("7400.00"), evaluation = EV_REVUE) => [P1(), [X.ev("09:00:00.000", request, evaluation), { e: "apr-0001:reserve", rep: { decision: "a_approuver", ticket: "apr-0001", ticket_state: "nouveau", approval: null, approver_set: { threshold: { required: 2, size: 3 }, members: A.trierAdresses([1, 2, 3].map(ADR)), source: SRC(1, 1190, 1190, true) } } }], ...ouverture()];
  const t = [];
  const trace = (id, description, checks, pas, o = {}) => t.push({ id, description, checks, pas, ...o });
  const R1 = R_PAIEMENT("7400.00");

  trace("approuve-sans-contestation", "Cycle nominal : réservation (la réponse nouveau porte le jeu de repli), ouverture, gel du jeu 1 à la hauteur 1200, votes approuve des comptes 1 et 2, confirmation à 1214, remise, scellement, ré-émission servie une fois (approuve), consommation, puis nouvel appel identique : nouveau ticket.", ["TK-1", "TK-2", "TK-3", "TK-5", "TK-7", "TK-8", "TK-9", "TK-10", "TK-12"], [
    ...prelude(),
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve", "Pièces vérifiées"), { e: "apr-0001:ouvert" }],
    [X.vote("09:15:00.000", "apr-0001", 1, 2, "approuve", "Constat et facture concordants"), { e: "apr-0001:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Constat et facture concordants", SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:15:01.900", decision: "approuve" }), { e: "apr-0001:approuve", rep: { ticket: "apr-0001", state: "approuve" } }],
    [X.ev("09:16:00.000", R1, EV_REVUE), { e: "apr-0001:approuve", rep: { decision: "autorise", ticket: "apr-0001", ticket_state: "approuve", approver_set: null } }],
    [X.ev("09:16:00.500", R1, EV_REVUE), { e: "apr-0001:approuve", rep: { decision: "a_approuver", ticket: "apr-0001", ticket_state: "en_attente", approval: null } }],
    [X.con("09:16:01.000", "apr-0001", 7), { e: "apr-0001:consomme", rep: { ticket: "apr-0001", state: "consomme" } }],
    [X.ev("09:20:00.000", R1, EV_REVUE), { e: "apr-0001:consomme apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
  ]);

  trace("refuse-seuil", "Deux votes refuse des comptes 1 et 2 : décision refuse au seuil ; la ré-émission reçoit le refus scellé ; au terme du délai de reconnaissance, clos, et la même demande ouvre un nouveau ticket.", ["TK-3", "TK-6", "TK-9"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "refuse", "Bénéficiaire inconnu"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "refuse", "IBAN non conforme"), { e: "apr-0001:verification" }],
    [X.lu("09:06:01.000", J1(1210)), { e: "apr-0001:a_remettre", rem: [["refuse", [1, 2], "IBAN non conforme", SRC(1, 1200, 1210)]] }],
    [X.acq("09:06:02.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:06:01.900", decision: "refuse" }), { e: "apr-0001:refuse" }],
    [X.ev("09:07:00.000", R1, EV_REVUE), { e: "apr-0001:refuse", rep: { decision: "refuse", ticket: "apr-0001", ticket_state: "refuse" } }],
    [X.hor("10:06:01.900"), { e: "apr-0001:clos" }],
    [X.ev("10:06:02.000", R1, EV_REVUE), { e: "apr-0001:clos apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
  ]);

  trace("expire-sans-vote", "Aucun vote : à l'échéance (ts de la demande + 1 h), expire ; un vote reçu à l'instant de l'échéance arrive après elle (minuteur d'abord) ; les deux escalades configurées ne changent rien.", ["TK-3", "TK-4"], [
    ...prelude(),
    [X.hor("09:30:00.200"), { e: "apr-0001:ouvert" }],
    [X.hor("09:50:00.200"), { e: "apr-0001:ouvert" }],
    [X.vote("10:00:00.200", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:a_remettre", r: "ticket_clos_aux_votes", rem: [["expire", [], "echeance atteinte sans decision", SRC(1, 1200, 1200)]] }],
    [X.acq("10:00:01.000", "apr-0001/1", "scelle", { seq: 6, scelle: "10:00:00.900", decision: "expire" }), { e: "apr-0001:expire" }],
  ], { service: SERVICE({ escalation: [{ after_ms: 1800000, notify: "jeu" }, { after_ms: 3000000, notify: "administrateur" }] }) });

  trace("vote-remplace", "Le compte 1 approuve, puis refuse (remplacement), puis refuse de nouveau avec un autre motif (vote_identique, sans effet : seule la décision compte) ; le compte 2 approuve, le compte 1 revient à approuve : la remise nomme les votes courants dans l'ordre de leur acceptation (2 puis 1) et le motif du second.", ["TK-3", "TK-5", "TK-8"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 1, "refuse", "Pièce manquante"), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 1, "refuse", "Pièce toujours manquante"), { e: "apr-0001:ouvert", r: "vote_identique" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 2, "approuve", "Conforme"), { e: "apr-0001:ouvert" }],
    [X.vote("09:09:00.000", "apr-0001", 1, 1, "approuve", "Pièce reçue"), { e: "apr-0001:verification" }],
    [X.lu("09:09:01.000", J1(1205)), { e: "apr-0001:a_remettre", rem: [["approuve", [2, 1], "Pièce reçue", SRC(1, 1200, 1205)]] }],
  ]);

  const PS = () => prelude(R_SUPPRESSION(), EV_CONTEST);
  const sepSuppr = { separation: SEPARATION };
  trace("contestation-sans-objection", "contest_ms 900 000 (suppression de sinistre, demandeur sans adresse déclarée) : le seuil est atteint à 09:06, la fenêtre court jusqu'à 09:21 ; une approbation de plus ne la recommence pas ; à sa fin, verification, puis remise après confirmation.", ["TK-3", "TK-6", "TK-8"], [
    ...PS(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve", "Doublon confirmé"), { e: "apr-0001:seuil_atteint" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 3, "approuve"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:20:59.999"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:21:00.000"), { e: "apr-0001:verification" }],
    [X.lu("09:21:01.000", J1(1220)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Doublon confirmé", SRC(1, 1200, 1220)]] }],
  ], sepSuppr);

  trace("contestation-objection-levee", "Objection du compte 3 pendant la fenêtre : retour en ouvert ; il la lève par un vote approuve : une nouvelle fenêtre complète s'ouvre (09:12 à 09:27), la première ne compte plus.", ["TK-3", "TK-6"], [
    ...PS(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve", "Doublon confirmé"), { e: "apr-0001:seuil_atteint" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 3, "refuse", "Sinistre encore ouvert"), { e: "apr-0001:ouvert" }],
    [X.vote("09:12:00.000", "apr-0001", 1, 3, "approuve", "Vérifié, objection retirée"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:21:00.000"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:27:00.000"), { e: "apr-0001:verification" }],
    [X.lu("09:27:01.000", J1(1230)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Doublon confirmé", SRC(1, 1200, 1230)]] }],
  ], sepSuppr);

  trace("contestation-objection-maintenue", "Objection du compte 3 ; il se récuse ensuite : son vote refuse reste compté et l'objection demeure, et il ne peut plus la lever ; à l'échéance, expire, raison « objection non levee ».", ["TK-3", "TK-6", "TK-11"], [
    ...PS(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:seuil_atteint" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 3, "refuse", "Sinistre encore ouvert"), { e: "apr-0001:ouvert" }],
    [X.rec("09:11:00.000", "apr-0001", 3), { e: "apr-0001:ouvert" }],
    [X.vote("09:12:00.000", "apr-0001", 1, 3, "approuve"), { e: "apr-0001:ouvert", r: "recuse" }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte, objection non levee", SRC(1, 1200, 1200)]] }],
  ], sepSuppr);

  trace("contestation-refus-anterieur", "contest_ms > 0 : un refus du compte 3 avant que le seuil soit atteint est une objection (EX-10.7) ; les approbations des comptes 1 et 2 n'ouvrent pas de fenêtre tant qu'elle n'est pas levée ; levée par son auteur (vote approuve), une fenêtre complète s'ouvre à cet instant.", ["TK-3", "TK-6"], [
    ...PS(),
    [X.vote("09:05:00.000", "apr-0001", 1, 3, "refuse", "Doute"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 2, "approuve", "Doublon confirmé"), { e: "apr-0001:ouvert" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 3, "approuve", "Doute levé"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:24:59.999"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:25:00.000"), { e: "apr-0001:verification" }],
    [X.lu("09:25:01.000", J1(1226)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Doublon confirmé", SRC(1, 1200, 1226)]] }],
  ], sepSuppr);

  trace("contestation-apres-echeance", "Seuil atteint exactement contest_ms avant l'échéance : la fenêtre finirait à l'échéance ; à instant égal, l'échéance passe d'abord : expire, raison « pendant la fenetre de contestation ».", ["TK-3", "TK-4", "TK-6"], [
    ...PS(),
    [X.vote("09:40:00.200", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:45:00.200", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte pendant la fenetre de contestation", SRC(1, 1200, 1200)]] }],
  ], sepSuppr);

  const J1b = (h) => jeuLu(1, h, [1, 2, 3, 4], 2);
  trace("jeu-change-pendant-contestation", "Pendant la fenêtre de contestation (09:06 à 09:21), le compte 4 est ajouté au jeu épinglé (seuil inchangé, 2 sur 4) : nouveau gel, la fenêtre en cours est annulée et, le seuil restant atteint, une fenêtre complète s'ouvre à l'instant de la lecture (09:12 à 09:27) (EX-8.6).", ["TK-6", "TK-7"], [
    ...PS(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve", "Doublon confirmé"), { e: "apr-0001:seuil_atteint" }],
    [X.lu("09:12:00.000", J1b(1210)), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:21:00.000"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:26:59.999"), { e: "apr-0001:seuil_atteint" }],
    [X.hor("09:27:00.000"), { e: "apr-0001:verification" }],
    [X.lu("09:27:01.000", J1b(1230)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Doublon confirmé", SRC(1, 1210, 1230), { required: 2, size: 4 }]] }],
  ], sepSuppr);

  trace("separation-auto-approbation", "self_approval interdite : le vote du compte 3, adresse du demandeur, est refusé (auto_approbation) ; les comptes 1 et 2 décident.", ["TK-3", "TK-11"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 3, "approuve"), { e: "apr-0001:ouvert", r: "auto_approbation" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.lu("09:07:01.000", J1(1206)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1206)]] }],
  ]);

  trace("separation-auto-permise", "self_approval permise : le compte 3, adresse du demandeur, vote comme un autre membre ; la remise le nomme dans approvers.", ["TK-3", "TK-11"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 3, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 1, "approuve", "Conforme"), { e: "apr-0001:verification" }],
    [X.lu("09:06:01.000", J1(1206)), { e: "apr-0001:a_remettre", rem: [["approuve", [3, 1], "Conforme", SRC(1, 1200, 1206)]] }],
  ], { separation: { ...SEPARATION, self_approval: "permise" } });

  trace("seuil-inatteignable", "Compte 3 inéligible (demandeur), compte 1 récusé : un seul éligible pour un seuil de 2 ; à l'échéance, expire, raison « seuil inatteignable ».", ["TK-3", "TK-6", "TK-11"], [
    ...prelude(),
    [X.rec("09:05:00.000", "apr-0001", 1), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:ouvert" }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte, seuil inatteignable", SRC(1, 1200, 1200)]] }],
  ]);

  trace("recusation", "Récusation du compte 1 après son vote approuve : vote retiré ; récusation répétée et nouveau vote refusés (recuse) ; récusation d'un non-membre (hors_jeu) et du demandeur (auto_approbation) refusées.", ["TK-3", "TK-5", "TK-11"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.rec("09:06:00.000", "apr-0001", 1), { e: "apr-0001:ouvert" }],
    [X.rec("09:07:00.000", "apr-0001", 1), { e: "apr-0001:ouvert", r: "recuse" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert", r: "recuse" }],
    [X.rec("09:09:00.000", "apr-0001", 4), { e: "apr-0001:ouvert", r: "hors_jeu" }],
    [X.rec("09:10:00.000", "apr-0001", 3), { e: "apr-0001:ouvert", r: "auto_approbation" }],
    [X.vote("09:11:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:ouvert" }],
  ]);

  trace("recusation-refus-maintenu", "Demandeur sans adresse déclarée : les trois comptes sont éligibles. Le compte 1 refuse puis se récuse : son vote refuse reste compté (EX-10.4) et un nouveau vote lui est refusé (recuse) ; le refus du compte 3 complète le seuil : la remise refuse porte les signatures des comptes 1 et 3.", ["TK-6", "TK-11"], [
    ...prelude(R_PAIEMENT("7400.00", { demandeur: AUTRE_DEMANDEUR })),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "refuse", "Bénéficiaire inconnu"), { e: "apr-0001:ouvert" }],
    [X.rec("09:06:00.000", "apr-0001", 1), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert", r: "recuse" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 3, "refuse", "IBAN non conforme"), { e: "apr-0001:verification" }],
    [X.lu("09:08:01.000", J1(1209)), { e: "apr-0001:a_remettre", rem: [["refuse", [1, 3], "IBAN non conforme", SRC(1, 1200, 1209)]] }],
  ]);

  const J1prime = (h) => jeuLu(1, h, [1, 3, 4], 2);
  trace("jeu-change-membre-retire", "Pendant verification, le compte 2 est retiré du jeu 1 et le compte 4 ajouté (hauteur 1208) : nouveau gel, vote du compte 2 écarté (hors_jeu), retour en ouvert ; le compte 4 approuve ; confirmation à 1212.", ["TK-3", "TK-7", "TK-8"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.lu("09:06:30.000", J1prime(1208)), { e: "apr-0001:ouvert" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:ouvert", r: "hors_jeu" }],
    [X.vote("09:09:00.000", "apr-0001", 1, 4, "approuve", "Contrôlé"), { e: "apr-0001:verification" }],
    [X.lu("09:09:01.000", J1prime(1212)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 4], "Contrôlé", SRC(1, 1208, 1212)]] }],
  ]);

  const J1bas = (h) => jeuLu(1, h, [1, 2, 3], 1);
  trace("jeu-seuil-abaisse", "Pendant l'attente, l'administrateur du jeu épinglé ramène son seuil à 1 sur 3 : nouveau gel, mais le nombre de signatures exigé ne baisse pas (2, le plus grand seuil figé, EX-8.6) ; la remise porte deux signatures et le seuil lu à la confirmation, 1 sur 3 (A-3 : au moins required).", ["TK-6", "TK-7", "TK-8"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.lu("09:06:00.000", J1bas(1205)), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 2, "approuve", "Second contrôle"), { e: "apr-0001:verification" }],
    [X.lu("09:07:01.000", J1bas(1207)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Second contrôle", SRC(1, 1205, 1207), { required: 1, size: 3 }]] }],
  ]);

  const J2 = (h) => jeuLu(2, h, [1, 2, 4], 1);
  trace("jeu-reassigne", "Pendant verification, le registre désigne le jeu 2 pour l'organisation : la lecture est illisible (jeu_non_attendu : le jeu 1 est épinglé par la politique, EX-8.1), sans nouveau gel ; une lecture lu du jeu 2 est traitée de même ; le compte 4, membre du seul jeu 2, est hors_jeu ; aucune confirmation, donc aucune remise approuve ; à l'échéance, expire, raison « jeu reassigne ».", ["TK-3", "TK-7"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.ill("09:06:30.000", "jeu_non_attendu"), { e: "apr-0001:verification" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 4, "approuve"), { e: "apr-0001:verification", r: "hors_jeu" }],
    [X.lu("09:08:00.000", J2(1214)), { e: "apr-0001:verification" }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte, jeu reassigne", SRC(1, 1200, 1200)]] }],
  ]);

  trace("jeu-illisible", "Le jeu n'est jamais figé (lectures illisibles) : votes refusés (jeu_non_fige) ; à l'échéance, expire sur le jeu de repli, lu à 1190 avant la demande, source terminée par « repli ».", ["TK-3", "TK-7"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert" }],
    [X.ill("09:00:01.000", "etat_indisponible"), { e: "apr-0001:ouvert" }],
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert", r: "jeu_non_fige" }],
    [X.ill("09:30:00.000", "membres_non_reconstitues"), { e: "apr-0001:ouvert" }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte, jeu d'approbateurs illisible", SRC(1, 1190, 1190, true)]] }],
  ]);

  trace("non-pret", "Jeu registre jamais lu : evaluer reçoit non_pret, même après une lecture illisible ; après une lecture réussie, la demande est servie ; une version de politique non chargée : politique_inconnue.", ["TK-3"], [
    [X.ev("08:58:00.000", R1, EV_REVUE), { e: "", r: "non_pret", rep: null }],
    [X.ill("08:58:30.000", "chaine_differente"), { e: "" }],
    [X.ev("08:59:00.000", R1, EV_REVUE), { e: "", r: "non_pret", rep: null }],
    [X.lu("08:59:30.000", J1(1190)), { e: "" }],
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ev("09:00:01.000", R_PAIEMENT("7400.00", { version: "vecteurs-ct3-9" }), EV_REVUE), { e: "apr-0001:reserve", r: "politique_inconnue", rep: null }],
  ]);

  trace("jeu-statique", "approver_set statique (comptes 1 à 3, seuil 2) : aucun jeu_lu ; la réponse nouveau porte le jeu statique ; gel à l'ouverture, confirmation acquise : la remise suit l'entrée en verification au même pas ; source « jeu statique de la politique vecteurs-ct3-1 ».", ["TK-3", "TK-7", "TK-8"], [
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve", rep: { approver_set: { threshold: { required: 2, size: 3 }, members: A.trierAdresses([1, 2, 3].map(ADR)), source: SRC_STATIQUE } } }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert" }],
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "approuve", "Conforme"), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], "Conforme", SRC_STATIQUE]] }],
    [X.acq("09:06:01.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:06:00.900", decision: "approuve" }), { e: "apr-0001:approuve" }],
  ], { approver_set: copie(APPROVER_SET_STATIQUE) });

  const champs1 = (decision = "approuve") => ({ decision, request_hash: DEMANDE(1), ticket: "apr-0001" });
  trace("signature-hors-jeu", "Votes refusés : compte 4 non membre (hors_jeu) ; signature d'un autre ticket, signature des 66 caractères « 0x… » de D_A, signature de 64 octets, v = 29 (signature_invalide). Votes acceptés après normalisation : s haut (compte 1), v ∈ {0, 1} (compte 2) ; la remise porte les formes canoniques.", ["TK-3", "TK-5", "TK-8"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 4, "approuve"), { e: "apr-0001:ouvert", r: "hors_jeu" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 1, "approuve", null, { signature: sigSur(1, { decision: "approuve", request_hash: DEMANDE(1), ticket: "apr-0099" }) }), { e: "apr-0001:ouvert", r: "signature_invalide" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 2, "approuve", null, { signature: signatureSurChaine(2, champs1()) }), { e: "apr-0001:ouvert", r: "signature_invalide" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 2, "approuve", null, { signature: sigSur(2, champs1()).slice(0, 130) }), { e: "apr-0001:ouvert", r: "signature_invalide" }],
    [X.vote("09:09:00.000", "apr-0001", 1, 2, "approuve", null, { signature: sigSur(2, champs1()).slice(0, 130) + "1d" }), { e: "apr-0001:ouvert", r: "signature_invalide" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve", null, { signature: formeHaute(sigSur(1, champs1())) }), { e: "apr-0001:ouvert" }],
    [X.vote("09:11:00.000", "apr-0001", 1, 2, "approuve", null, { signature: formeV01(sigSur(2, champs1())) }), { e: "apr-0001:verification" }],
    [X.lu("09:11:01.000", J1(1207)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1207)]] }],
  ]);

  const MOTIF_LONG = "x".repeat(1025);
  trace("ordre-des-raisons-de-vote", "Votes à deux défauts : la première raison d'EX-9.10 l'emporte. Jeu non figé et signature invalide : jeu_non_fige ; non-membre et signature invalide : signature_invalide ; adresse déclarée du demandeur hors du jeu (compte 4) : hors_jeu ; demandeur et motif trop long : auto_approbation ; récusé et motif trop long : recuse ; motif trop long et même décision que le vote courant : motif_trop_long ; puis vote identique.", ["TK-5", "TK-11"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert" }],
    [X.vote("09:01:00.000", "apr-0001", 1, 1, "approuve", null, { signature: sigSur(1, { decision: "approuve", request_hash: DEMANDE(1), ticket: "apr-0099" }) }), { e: "apr-0001:ouvert", r: "jeu_non_fige" }],
    [X.lu("09:02:00.000", J1(1200)), { e: "apr-0001:ouvert" }],
    [X.vote("09:03:00.000", "apr-0001", 1, 4, "approuve", null, { signature: sigSur(4, { decision: "approuve", request_hash: DEMANDE(1), ticket: "apr-0099" }) }), { e: "apr-0001:ouvert", r: "signature_invalide" }],
    [X.vote("09:04:00.000", "apr-0001", 1, 4, "approuve"), { e: "apr-0001:ouvert", r: "hors_jeu" }],
    [X.vote("09:05:00.000", "apr-0001", 1, 3, "approuve", MOTIF_LONG), { e: "apr-0001:ouvert", r: "auto_approbation" }],
    [X.rec("09:06:00.000", "apr-0001", 2), { e: "apr-0001:ouvert" }],
    [X.vote("09:07:00.000", "apr-0001", 1, 2, "approuve", MOTIF_LONG), { e: "apr-0001:ouvert", r: "recuse" }],
    [X.vote("09:08:00.000", "apr-0001", 1, 1, "approuve", "Conforme"), { e: "apr-0001:ouvert" }],
    [X.vote("09:09:00.000", "apr-0001", 1, 1, "approuve", MOTIF_LONG), { e: "apr-0001:ouvert", r: "motif_trop_long" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve", "Toujours conforme"), { e: "apr-0001:ouvert", r: "vote_identique" }],
  ], { separation: { self_approval: "interdite", identities: [{ launched_by: DEMANDEUR, addresses: [ADR(3), ADR(4)] }] } });

  trace("reemission-en-attente", "Ré-émissions : sur reserve, même ticket et nouveau ; run_id et intent hors de la clé ; un argument différent fait une autre demande ; pendant l'attente, en_attente sans événement ; ouvrir répété : l'état courant ; ouvrir d'un autre request_hash : ticket_deja_ouvert ; ticket inconnu.", ["TK-1", "TK-2", "TK-3", "TK-9"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve", rep: { ticket: "apr-0001", ticket_state: "nouveau" } }],
    [X.ev("09:00:00.100", R1, EV_REVUE), { e: "apr-0001:reserve", rep: { decision: "a_approuver", ticket: "apr-0001", ticket_state: "nouveau" } }],
    [X.ev("09:00:00.150", R_PAIEMENT("7400.01"), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
    [X.ev("09:00:00.180", R_PAIEMENT("7400.00", { run: "run-2026-11-12-0002", intent: "Nouvelle tentative" }), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve", rep: { ticket: "apr-0001", ticket_state: "nouveau" } }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve" }],
    [X.ev("09:00:01.000", R1, EV_REVUE), { e: "apr-0001:ouvert apr-0002:reserve", rep: { decision: "a_approuver", ticket: "apr-0001", ticket_state: "en_attente", approval: null, approver_set: null } }],
    [X.ouv("09:00:02.000", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve", rep: { ticket: "apr-0001", state: "ouvert", deadline: T("10:00:00.200") } }],
    [X.ouv("09:00:03.000", "apr-0001", 9, 8, "09:00:02.900"), { e: "apr-0001:ouvert apr-0002:reserve", r: "ticket_deja_ouvert", rep: null }],
    [X.ouv("09:00:04.000", "apr-0099", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve", r: "ticket_inconnu", rep: null }],
  ]);

  trace("retrait", "Retrait par un tiers refusé (retrait_non_autorise) ; retrait par le demandeur : échéance avancée, expire, raison « echeance avancee par retrait » ; la ré-émission reçoit le refus scellé.", ["TK-3", "TK-9"], [
    ...prelude(),
    [X.ret("09:05:00.000", "apr-0001", TIERS, "Je n'en veux pas"), { e: "apr-0001:ouvert", r: "retrait_non_autorise" }],
    [X.ret("09:06:00.000", "apr-0001", DEMANDEUR, "Demande saisie par erreur"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance avancee par retrait", SRC(1, 1200, 1200)]] }],
    [X.acq("09:06:01.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:06:00.900", decision: "expire" }), { e: "apr-0001:expire" }],
    [X.ev("09:07:00.000", R1, EV_REVUE), { e: "apr-0001:expire", rep: { decision: "refuse", ticket: "apr-0001", ticket_state: "expire" } }],
  ]);

  const ADMIN = "admin@assureur-demo.example";
  trace("retrait-administrateur", "Le contact administrateur de la configuration du service retire le ticket (EX-7.15) : expire, raison « echeance avancee par retrait » ; un tiers, ni demandeur ni administrateur, est refusé.", ["TK-3"], [
    ...prelude(),
    [X.ret("09:05:00.000", "apr-0001", TIERS, "Je n'en veux pas"), { e: "apr-0001:ouvert", r: "retrait_non_autorise" }],
    [X.ret("09:06:00.000", "apr-0001", ADMIN, "Doublon de saisie"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance avancee par retrait", SRC(1, 1200, 1200)]] }],
  ], { service: SERVICE({ administrators: [ADMIN] }) });

  trace("acquittement-temporaire", "Refus temporaire du noyau (mode dégradé) puis échéance : la décision approuve, non scellée, devient caduque et une remise expire la remplace (apr-0001/2) ; un acquittement de l'ancienne remise est sans effet ; la nouvelle est scellée.", ["TK-3", "TK-4", "TK-8"], [
    ...prelude(),
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:15:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "temporaire", { reason: "mode_degrade" }), { e: "apr-0001:a_remettre", rep: { ticket: "apr-0001", state: "a_remettre" } }],
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "decision non scellee avant l'echeance", SRC(1, 1200, 1214)]] }],
    [X.acq("10:00:01.000", "apr-0001/1", "temporaire", { reason: "mode_degrade" }), { e: "apr-0001:a_remettre" }],
    [X.acq("10:00:02.000", "apr-0001/2", "scelle", { seq: 6, scelle: "10:00:01.900", decision: "expire" }), { e: "apr-0001:expire" }],
  ]);

  const R2 = R_PAIEMENT("8100.00");
  const SCELLE_AILLEURS = approvalSigne("apr-0001", 1, "approuve", [2, 1], T("09:15:01.500"), "Constat confirmé");
  trace("deja-decide", "Le noyau refuse une remise parce qu'une décision est déjà scellée pour cette demande (ticket_deja_decide) : le service s'aligne et garde l'objet approval scellé reçu, même s'il diffère de sa remise (ordre des signataires, motif) ; un second ticket est expiré par le noyau seul, à l'échéance plus timeout_ms (expiration) : le service s'aligne, après sa propre remise expire, et rend à la ré-émission l'objet du noyau.", ["TK-3", "TK-9"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ev("09:00:00.050", R2, EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve" }],
    [X.ouv("09:00:00.300", "apr-0002", 2, 6, "09:00:00.280"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.lu("09:00:01.000", J1(1200)), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:15:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification apr-0002:ouvert" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre apr-0002:ouvert", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "refuse", { reason: "ticket_deja_decide", seq: 8, scelle: "09:15:01.500", decision: "approuve", approval: SCELLE_AILLEURS }), { e: "apr-0001:approuve apr-0002:ouvert", rep: { ticket: "apr-0001", state: "approuve" } }],
    [X.ev("09:16:00.000", R1, EV_REVUE), { e: "apr-0001:approuve apr-0002:ouvert", rep: { decision: "autorise", ticket_state: "approuve", approval: SCELLE_AILLEURS } }],
    [X.exp("10:00:02.300", "apr-0002", 2, 9, "10:00:02.280"), { e: "apr-0001:approuve apr-0002:expire", rem: [["expire", [], "echeance atteinte sans decision", SRC(1, 1200, 1214)]], rep: { ticket: "apr-0002", state: "expire" } }],
    [X.exp("10:00:03.000", "apr-0002", 2, 9, "10:00:02.280"), { e: "apr-0001:approuve apr-0002:expire", rep: { ticket: "apr-0002", state: "expire" } }],
    [X.ev("10:00:04.000", R2, EV_REVUE), { e: "apr-0001:approuve apr-0002:expire", rep: { decision: "refuse", ticket_state: "expire", approval: approvalNoyau("apr-0002", 2, T("10:00:02.280")) } }],
  ]);

  const AUTRE_DEMANDE = approvalSigne("apr-0001", 7, "approuve", [1, 2], T("08:40:00.000"), "Autre paiement");
  trace("deja-decide-autre-demande", "Un service qui aurait réattribué l'identifiant apr-0001 : le noyau refuse la remise refuse par ticket_deja_decide, avec la décision scellée d'une autre demande (autre request_hash) ; le service ne s'aligne pas (T20) : ticket clos, alerte identifiant_en_collision ; la ré-émission de la demande est une nouvelle demande ; l'acquittement répété est sans effet.", ["TK-1", "TK-3", "TK-9"], [
    ...prelude(),
    [X.vote("09:05:00.000", "apr-0001", 1, 1, "refuse", "Bénéficiaire inconnu"), { e: "apr-0001:ouvert" }],
    [X.vote("09:06:00.000", "apr-0001", 1, 2, "refuse", "IBAN non conforme"), { e: "apr-0001:verification" }],
    [X.lu("09:06:01.000", J1(1210)), { e: "apr-0001:a_remettre", rem: [["refuse", [1, 2], "IBAN non conforme", SRC(1, 1200, 1210)]] }],
    [X.acq("09:06:02.000", "apr-0001/1", "refuse", { reason: "ticket_deja_decide", seq: 3, scelle: "08:40:00.000", decision: "approuve", approval: AUTRE_DEMANDE }), { e: "apr-0001:clos", rep: { ticket: "apr-0001", state: "clos" } }],
    [X.ev("09:07:00.000", R1, EV_REVUE), { e: "apr-0001:clos apr-0002:reserve", rep: { decision: "a_approuver", ticket: "apr-0002", ticket_state: "nouveau" } }],
    [X.acq("09:07:30.000", "apr-0001/1", "refuse", { reason: "ticket_deja_decide", seq: 3, scelle: "08:40:00.000", decision: "approuve", approval: AUTRE_DEMANDE }), { e: "apr-0001:clos apr-0002:reserve", rep: { ticket: "apr-0001", state: "clos" } }],
  ]);

  const REFUS_AILLEURS = approvalSigne("apr-0001", 1, "refuse", [1, 2], T("09:21:01.500"), "Refus scellé par une autre instance");
  trace("acquittements-noyau", "Acquittements du noyau : remise approuve refusée pour signature_invalide (T16 : votes écartés, retour en ouvert), acquittement répété sans effet ; seconde remise refusée par ticket_deja_decide avec une décision refuse (T14 : alignement sur une décision différente de la remise) ; scellement contraire refusé ; sur un second ticket, refus echeance_depassee avant l'échéance du service (T15), puis décision caduque, ancienne remise sans effet, scellement de l'expiration.", ["TK-3", "TK-8", "TK-9"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ev("09:00:00.050", R2, EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve" }],
    [X.ouv("09:00:00.300", "apr-0002", 2, 6, "09:00:00.280"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.lu("09:00:01.000", J1(1200)), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:11:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification apr-0002:ouvert" }],
    [X.lu("09:11:01.000", J1(1206)), { e: "apr-0001:a_remettre apr-0002:ouvert", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1206)]] }],
    [X.acq("09:11:02.000", "apr-0001/1", "refuse", { reason: "signature_invalide" }), { e: "apr-0001:ouvert apr-0002:ouvert", rep: { ticket: "apr-0001", state: "ouvert" } }],
    [X.acq("09:11:03.000", "apr-0001/1", "refuse", { reason: "signature_invalide" }), { e: "apr-0001:ouvert apr-0002:ouvert", rep: { ticket: "apr-0001", state: "ouvert" } }],
    [X.vote("09:20:00.000", "apr-0001", 1, 1, "approuve", "Nouvelle signature"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:21:00.000", "apr-0001", 1, 2, "approuve", "Nouvelle signature"), { e: "apr-0001:verification apr-0002:ouvert" }],
    [X.lu("09:21:01.000", J1(1220)), { e: "apr-0001:a_remettre apr-0002:ouvert", rem: [["approuve", [1, 2], "Nouvelle signature", SRC(1, 1200, 1220)]] }],
    [X.acq("09:21:02.000", "apr-0001/2", "refuse", { reason: "ticket_deja_decide", seq: 7, scelle: "09:21:01.500", decision: "refuse", approval: REFUS_AILLEURS }), { e: "apr-0001:refuse apr-0002:ouvert", rep: { ticket: "apr-0001", state: "refuse" } }],
    [X.ev("09:22:00.000", R1, EV_REVUE), { e: "apr-0001:refuse apr-0002:ouvert", rep: { decision: "refuse", ticket_state: "refuse", approval: REFUS_AILLEURS } }],
    [X.acq("09:22:30.000", "apr-0001/2", "scelle", { seq: 9, scelle: "09:22:29.900", decision: "approuve" }), { e: "apr-0001:refuse apr-0002:ouvert", r: "requete_invalide", rep: null }],
    [X.vote("09:58:00.000", "apr-0002", 2, 1, "approuve"), { e: "apr-0001:refuse apr-0002:ouvert" }],
    [X.vote("09:59:00.000", "apr-0002", 2, 2, "approuve"), { e: "apr-0001:refuse apr-0002:verification" }],
    [X.lu("09:59:30.000", J1(1300)), { e: "apr-0001:refuse apr-0002:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1300)]] }],
    [X.acq("09:59:59.000", "apr-0002/1", "refuse", { reason: "echeance_depassee" }), { e: "apr-0001:refuse apr-0002:a_remettre", rep: { ticket: "apr-0002", state: "a_remettre" } }],
    [X.hor("10:00:00.280"), { e: "apr-0001:refuse apr-0002:a_remettre", rem: [["expire", [], "decision non scellee avant l'echeance", SRC(1, 1200, 1300)]] }],
    [X.acq("10:00:01.000", "apr-0002/1", "temporaire", { reason: "mode_degrade" }), { e: "apr-0001:refuse apr-0002:a_remettre" }],
    [X.acq("10:00:02.000", "apr-0002/2", "scelle", { seq: 10, scelle: "10:00:01.900", decision: "expire" }), { e: "apr-0001:refuse apr-0002:expire" }],
  ]);

  const R3 = R_PAIEMENT("8200.00");
  trace("expiration-noyau", "Expirations scellées par le noyau seul (T17). Remise expire refusée par le noyau (T16) : pas de nouvelle remise ; le noyau scelle expire et l'annonce ; l'acquittement répété est sans effet. Expiration d'un ticket encore en reserve (horloges décalées) : request_hash inscrit, ouvrir tardif sans effet. Expiration d'un ticket abandonné : la clé n'est pas reprise.", ["TK-3", "TK-9"], [
    ...prelude(),
    [X.hor("10:00:00.200"), { e: "apr-0001:a_remettre", rem: [["expire", [], "echeance atteinte sans decision", SRC(1, 1200, 1200)]] }],
    [X.acq("10:00:01.000", "apr-0001/1", "refuse", { reason: "seuil_different_du_jeu" }), { e: "apr-0001:a_remettre", rep: { ticket: "apr-0001", state: "a_remettre" } }],
    [X.hor("10:00:02.000"), { e: "apr-0001:a_remettre" }],
    [X.exp("10:00:02.300", "apr-0001", 1, 6, "10:00:02.200"), { e: "apr-0001:expire", rep: { ticket: "apr-0001", state: "expire" } }],
    [X.acq("10:00:03.000", "apr-0001/1", "refuse", { reason: "seuil_different_du_jeu" }), { e: "apr-0001:expire", rep: { ticket: "apr-0001", state: "expire" } }],
    [X.ev("10:00:04.000", R1, EV_REVUE), { e: "apr-0001:expire", rep: { decision: "refuse", ticket_state: "expire", approval: approvalNoyau("apr-0001", 1, T("10:00:02.200")) } }],
    [X.ev("10:01:00.000", R2, EV_REVUE), { e: "apr-0001:expire apr-0002:reserve" }],
    [X.exp("10:01:01.000", "apr-0002", 2, 8, "10:01:00.900"), { e: "apr-0001:expire apr-0002:expire", rep: { ticket: "apr-0002", state: "expire" } }],
    [X.ev("10:01:02.000", R2, EV_REVUE), { e: "apr-0001:expire apr-0002:expire", rep: { decision: "refuse", ticket_state: "expire" } }],
    [X.ouv("10:01:03.000", "apr-0002", 2, 7, "10:01:00.500"), { e: "apr-0001:expire apr-0002:expire", rep: { ticket: "apr-0002", state: "expire", deadline: null } }],
    [X.ev("10:02:00.000", R3, EV_REVUE), { e: "apr-0001:expire apr-0002:expire apr-0003:reserve" }],
    [X.hor("11:02:00.000"), { e: "apr-0001:clos apr-0002:clos apr-0003:abandonne" }],
    [X.exp("11:02:02.300", "apr-0003", 3, 10, "11:02:02.200"), { e: "apr-0001:clos apr-0002:clos apr-0003:expire", rep: { ticket: "apr-0003", state: "expire" } }],
    [X.ev("11:02:03.000", R3, EV_REVUE), { e: "apr-0001:clos apr-0002:clos apr-0003:expire apr-0004:reserve", rep: { ticket: "apr-0004", ticket_state: "nouveau" } }],
  ]);

  trace("retenir-double-reemission", "Mode retenir : le noyau scelle la décision approuve et relaie la requête qu'il retient (acquitter scelle, held) : l'approbation est servie dès le scellement ; une ré-émission de même clé avant consommer reçoit en_attente, jamais un second autorise ; après consommer, la même demande est nouvelle (EX-7.17, EX-11.5).", ["TK-9", "TK-10"], [
    ...prelude(),
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:15:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:15:01.900", decision: "approuve", held: true }), { e: "apr-0001:approuve", rep: { ticket: "apr-0001", state: "approuve" } }],
    [X.ev("09:15:30.000", R1, EV_REVUE), { e: "apr-0001:approuve", rep: { decision: "a_approuver", ticket: "apr-0001", ticket_state: "en_attente", approval: null } }],
    [X.con("09:16:00.000", "apr-0001", 7), { e: "apr-0001:consomme", rep: { ticket: "apr-0001", state: "consomme" } }],
    [X.ev("09:17:00.000", R1, EV_REVUE), { e: "apr-0001:consomme apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
  ]);

  trace("reservation-abandonnee", "Réservation sans ouvrir : abandonne à reserved_at + 1 h, clé libérée (la même demande ouvre apr-0002) ; ouvrir tardif d'apr-0001 : a_remettre, expire sur le jeu de repli, raison « reservation abandonnee avant l'ouverture » ; la clé n'est pas reprise.", ["TK-3", "TK-4"], [
    P1(),
    [X.ev("09:00:00.000", R1, EV_REVUE), { e: "apr-0001:reserve" }],
    [X.hor("10:00:00.000"), { e: "apr-0001:abandonne" }],
    [X.ev("10:00:05.000", R1, EV_REVUE), { e: "apr-0001:abandonne apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
    [X.ouv("10:00:10.000", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:a_remettre apr-0002:reserve", rep: { ticket: "apr-0001", state: "a_remettre", deadline: T("10:00:00.200") }, rem: [["expire", [], "reservation abandonnee avant l'ouverture", SRC(1, 1190, 1190, true)]] }],
    [X.acq("10:00:11.000", "apr-0001/1", "scelle", { seq: 7, scelle: "10:00:10.900", decision: "expire" }), { e: "apr-0001:expire apr-0002:reserve" }],
    [X.ev("10:00:12.000", R1, EV_REVUE), { e: "apr-0001:expire apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
  ]);

  trace("plafond", "max_open_tickets = 2 : une troisième demande à approuver du même demandeur reçoit plafond_atteint, sans ticket ; une ré-émission reconnue reste servie ; un autre demandeur n'est pas concerné ; une sortie autorise ou refuse non plus.", ["TK-3"], [
    P1(),
    [X.ev("09:00:00.000", R_PAIEMENT("6000.00"), EV_REVUE), { e: "apr-0001:reserve" }],
    [X.ev("09:00:01.000", R_PAIEMENT("7000.00"), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve" }],
    [X.ev("09:00:02.000", R_PAIEMENT("8000.00"), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve", r: "plafond_atteint", rep: null }],
    [X.ev("09:00:03.000", R_PAIEMENT("6000.00"), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve", rep: { ticket: "apr-0001", ticket_state: "nouveau" } }],
    [X.ev("09:00:04.000", R_PAIEMENT("8000.00", { demandeur: AUTRE_DEMANDEUR }), EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve apr-0003:reserve" }],
    [X.ev("09:00:05.000", R_PAIEMENT("900.00"), EV_AUTORISE), { e: "apr-0001:reserve apr-0002:reserve apr-0003:reserve", rep: { rule: "paiement <= 1000 CHF", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null } }],
    [X.ev("09:00:06.000", R_PAIEMENT("900.00", { iban: "CH4431999123000889012" }), EV_REFUSE), { e: "apr-0001:reserve apr-0002:reserve apr-0003:reserve", rep: { rule: EV_REFUSE.rule, decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null } }],
  ], { service: SERVICE({ max_open_tickets: 2 }) });

  trace("fenetre-ouvrante", "Deux tickets ouvrants de même portée (u.martin, sap.payments.create, IBAN A ; 10 min, 3 appels) et un ticket non ouvrant, approuvés : le non ouvrant n'ouvre rien ; le premier ouvrant ouvre une fenêtre à l'acquittement de son scellement, debut = approval.at ; le second la remplace. Trois appels couverts l'épuisent : elle est retirée (EX-5.6). Une nouvelle demande ouvre apr-0004, dont la fenêtre est retirée à sa fin.", ["TK-3", "TK-13"], [
    P1(),
    [X.ev("09:00:00.000", R_PAIEMENT("2500.00"), EV_OUVRANT(IBAN_A)), { e: "apr-0001:reserve" }],
    [X.ev("09:00:00.050", R1, EV_REVUE), { e: "apr-0001:reserve apr-0002:reserve" }],
    [X.ev("09:00:00.100", R_PAIEMENT("3000.00"), EV_OUVRANT(IBAN_A)), { e: "apr-0001:reserve apr-0002:reserve apr-0003:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve apr-0003:reserve" }],
    [X.ouv("09:00:00.300", "apr-0002", 2, 6, "09:00:00.280"), { e: "apr-0001:ouvert apr-0002:ouvert apr-0003:reserve" }],
    [X.ouv("09:00:00.350", "apr-0003", 3, 7, "09:00:00.330"), { e: "apr-0001:ouvert apr-0002:ouvert apr-0003:ouvert" }],
    [X.lu("09:00:01.000", J1(1200)), { e: "apr-0001:ouvert apr-0002:ouvert apr-0003:ouvert" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert apr-0002:ouvert apr-0003:ouvert" }],
    [X.vote("09:10:01.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification apr-0002:ouvert apr-0003:ouvert" }],
    [X.vote("09:10:02.000", "apr-0002", 2, 1, "approuve"), { e: "apr-0001:verification apr-0002:ouvert apr-0003:ouvert" }],
    [X.vote("09:10:03.000", "apr-0002", 2, 2, "approuve"), { e: "apr-0001:verification apr-0002:verification apr-0003:ouvert" }],
    [X.vote("09:10:04.000", "apr-0003", 3, 1, "approuve"), { e: "apr-0001:verification apr-0002:verification apr-0003:ouvert" }],
    [X.vote("09:10:05.000", "apr-0003", 3, 2, "approuve"), { e: "apr-0001:verification apr-0002:verification apr-0003:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre apr-0002:a_remettre apr-0003:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)], ["approuve", [1, 2], null, SRC(1, 1200, 1214)], ["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0002/1", "scelle", { seq: 8, scelle: "09:15:01.900", decision: "approuve" }), { e: "apr-0001:a_remettre apr-0002:approuve apr-0003:a_remettre", w: [] }],
    [X.acq("09:15:03.000", "apr-0001/1", "scelle", { seq: 9, scelle: "09:15:02.950", decision: "approuve" }), { e: "apr-0001:approuve apr-0002:approuve apr-0003:a_remettre", w: ["apr-0001"] }],
    [X.acq("09:15:04.000", "apr-0003/1", "scelle", { seq: 10, scelle: "09:15:03.950", decision: "approuve" }), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve", w: ["apr-0003"] }],
    [X.ev("09:16:00.000", R_PAIEMENT("2600.00"), EV_COUVERT("apr-0003", "09:25:03.950")), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve", rep: { decision: "autorise", ticket: null }, w: ["apr-0003"] }],
    [X.ev("09:17:00.000", R_PAIEMENT("2700.00"), EV_COUVERT("apr-0003", "09:25:03.950")), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve", w: ["apr-0003"] }],
    [X.ev("09:18:00.000", R_PAIEMENT("2800.00"), EV_COUVERT("apr-0003", "09:25:03.950")), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve", w: [] }],
    [X.ev("09:19:00.000", R_PAIEMENT("2900.00"), EV_OUVRANT(IBAN_A)), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:reserve", w: [] }],
    [X.ouv("09:19:00.250", "apr-0004", 4, 14, "09:19:00.200"), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:ouvert" }],
    [X.lu("09:19:01.000", J1(1240)), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:ouvert" }],
    [X.vote("09:20:00.000", "apr-0004", 4, 1, "approuve"), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:ouvert" }],
    [X.vote("09:21:00.000", "apr-0004", 4, 2, "approuve"), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:verification" }],
    [X.lu("09:21:01.000", J1(1244)), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1240, 1244)]] }],
    [X.acq("09:21:02.000", "apr-0004/1", "scelle", { seq: 15, scelle: "09:21:01.900", decision: "approuve" }), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:approuve", w: ["apr-0004"] }],
    [X.hor("09:31:01.899"), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:approuve", w: ["apr-0004"] }],
    [X.hor("09:31:01.900"), { e: "apr-0001:approuve apr-0002:approuve apr-0003:approuve apr-0004:approuve", w: [] }],
  ]);

  trace("fenetre-politique-changee", "Deux tickets ouvrants (IBAN A et IBAN B) : le premier ouvre sa fenêtre ; un charger de la version vecteurs-ct3-2 ferme toutes les fenêtres ; le second, scellé après le changement, n'en ouvre aucune.", ["TK-3", "TK-13"], [
    P1(),
    [X.ev("09:00:00.000", R_PAIEMENT("2500.00"), EV_OUVRANT(IBAN_A)), { e: "apr-0001:reserve" }],
    [X.ev("09:00:00.050", R_PAIEMENT("2500.00", { iban: IBAN_B }), EV_OUVRANT(IBAN_B)), { e: "apr-0001:reserve apr-0002:reserve" }],
    [X.ouv("09:00:00.250", "apr-0001", 1, 5, "09:00:00.200"), { e: "apr-0001:ouvert apr-0002:reserve" }],
    [X.ouv("09:00:00.300", "apr-0002", 2, 6, "09:00:00.280"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.lu("09:00:01.000", J1(1200)), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert apr-0002:ouvert" }],
    [X.vote("09:10:01.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification apr-0002:ouvert" }],
    [X.vote("09:10:02.000", "apr-0002", 2, 1, "approuve"), { e: "apr-0001:verification apr-0002:ouvert" }],
    [X.vote("09:10:03.000", "apr-0002", 2, 2, "approuve"), { e: "apr-0001:verification apr-0002:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre apr-0002:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)], ["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "scelle", { seq: 7, scelle: "09:15:01.900", decision: "approuve" }), { e: "apr-0001:approuve apr-0002:a_remettre", w: ["apr-0001"] }],
    [X.ch("09:16:00.000", V2), { e: "apr-0001:approuve apr-0002:a_remettre", rep: { policy_version: V2 }, w: [] }],
    [X.acq("09:16:01.000", "apr-0002/1", "scelle", { seq: 9, scelle: "09:16:00.900", decision: "approuve" }), { e: "apr-0001:approuve apr-0002:approuve", w: [] }],
  ]);

  trace("politique-changee", "Après le chargement de vecteurs-ct3-2, la même demande portant code.policy_version = vecteurs-ct3-2 a une autre clé : nouvelle évaluation, nouveau ticket ; le ticket approuve de la version 1 n'est pas consommé et finit clos.", ["TK-2", "TK-3"], [
    ...prelude(),
    [X.vote("09:10:00.000", "apr-0001", 1, 1, "approuve"), { e: "apr-0001:ouvert" }],
    [X.vote("09:15:00.000", "apr-0001", 1, 2, "approuve"), { e: "apr-0001:verification" }],
    [X.lu("09:15:01.000", J1(1214)), { e: "apr-0001:a_remettre", rem: [["approuve", [1, 2], null, SRC(1, 1200, 1214)]] }],
    [X.acq("09:15:02.000", "apr-0001/1", "scelle", { seq: 6, scelle: "09:15:01.900", decision: "approuve" }), { e: "apr-0001:approuve" }],
    [X.ch("09:20:00.000", V2), { e: "apr-0001:approuve", rep: { policy_version: V2 } }],
    [X.ev("09:21:00.000", R_PAIEMENT("7400.00", { version: V2 }), EV_REVUE), { e: "apr-0001:approuve apr-0002:reserve", rep: { ticket: "apr-0002", ticket_state: "nouveau" } }],
    [X.hor("10:15:01.900"), { e: "apr-0001:clos apr-0002:reserve" }],
  ]);

  return t;
}

/** Résout les marques d'une entrée de trace : { $remise } d'un acquittement devient l'approval de cette remise augmenté de at (A.6). */
function resoudreEntree(input, service) {
  const e = copie(input);
  if (e.kind === "acquitter" && e.data.approval && e.data.approval.$remise) {
    const id = e.data.approval.$remise;
    const tk = service.tickets.get(id.split("/")[0]);
    const r = tk && tk.remises.find((x) => x.remise.remise_id === id);
    exiger(r, `remise ${id} inconnue au moment de son acquittement`);
    e.data.approval = A.approvalScelle(r.remise.approval, e.data.at);
  }
  return e;
}

/** Joue une trace conçue pas à pas, confronte chaque pas à sa conception, et rend le fichier ($defs/trace). */
function fichierTrace(c, schemas) {
  const trace = {
    version: 0,
    id: c.id,
    description: c.description,
    checks: c.checks,
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    environment: c.environment ?? "developpement",
    policy_version: V1,
    expire_after_ms: E,
    approver_set: copie(c.approver_set ?? APPROVER_SET_REGISTRE),
    separation: copie(c.separation ?? SEPARATION),
    service: copie(c.service ?? SERVICE()),
    steps: [],
  };
  const service = new A.ServiceApprobation({ org_id: trace.org_id, journal_id: trace.journal_id, environment: trace.environment, policy_version: trace.policy_version, parametres: { expire_after_ms: trace.expire_after_ms, approver_set: trace.approver_set, separation: trace.separation }, service: trace.service, schemas });
  c.pas.forEach(([brute, k], i) => {
    const input = resoudreEntree(brute, service);
    const r = service.traiter(input);
    delete r.errors;
    delete r.data;
    const ou = `trace ${c.id}, pas ${i + 1} (${input.kind} ${input.at})`;
    const etats = Object.fromEntries((k.e ? k.e.split(" ") : []).map((x) => x.split(":")));
    exiger(J.egalJSON(r.tickets, etats), `${ou} : états ${JSON.stringify(r.tickets)}, conception ${JSON.stringify(etats)}`);
    exiger(r.accepted === !k.r && r.reason === (k.r ?? null), `${ou} : accepted ${r.accepted} reason ${r.reason}, conception ${k.r ?? "acceptée"}`);
    if (k.rep === null) exiger(r.response === null, `${ou} : réponse attendue nulle`);
    else if (k.rep) for (const [cle, v] of Object.entries(k.rep)) exiger(J.egalJSON(r.response?.[cle], v), `${ou} : response.${cle} = ${JSON.stringify(r.response?.[cle])}, conception ${JSON.stringify(v)}`);
    if (input.kind === "evaluer" && r.response) exiger(A.combinaisonAdmise(r.response), `${ou} : réponse hors des sept combinaisons d'EX-12.6`);
    const rem = k.rem ?? [];
    exiger(r.remises.length === rem.length, `${ou} : ${r.remises.length} remise(s), conception ${rem.length}`);
    rem.forEach(([decision, comptes, motif, source, seuil], j) => {
      const x = r.remises[j];
      exiger(x.approval.decision === decision && J.egalJSON(x.approval.approvers, comptes.map(ADR)) && x.approval.reason === motif && x.approver_set.source === source, `${ou} : remise ${JSON.stringify(x)}, conception ${JSON.stringify(rem[j])}`);
      if (seuil) exiger(J.egalJSON(x.approval.threshold, seuil), `${ou} : seuil ${JSON.stringify(x.approval.threshold)}, conception ${JSON.stringify(seuil)}`);
      exiger(A.erreursSchema(x, schemas, "remise").length === 0, `${ou} : remise non conforme à $defs/remise`);
    });
    if (k.w) exiger(J.egalJSON(r.windows.map((w) => w.ticket), k.w), `${ou} : fenêtres ${JSON.stringify(r.windows.map((w) => w.ticket))}, conception ${JSON.stringify(k.w)}`);
    trace.steps.push({ input, expected: r });
  });
  return trace;
}

// ---------------------------------------------------------------------------
// Décisions (A.7)
// ---------------------------------------------------------------------------

const TS_DEMANDE = T("09:00:00.200");
const CONTEXTE = (o = {}) => ({ org_id: ORG_ID, journal_id: JOURNAL_ID, retained: [{ seq: 5, ticket: "apr-0001", hash: DEMANDE(1), ts: TS_DEMANDE }], decided: [], expire_after_ms: E, write_at: T("09:15:01.900"), ...o });
const JEU_DECLARE = (o = {}) => ({ threshold: { required: 2, size: 3 }, members: A.trierAdresses([ADR(1), ADR(2), ADR(3)]), source: SRC(1, 1200, 1214), ...o });
const sigA = (compte, decision = "approuve", o = {}) => sigSur(compte, { decision, request_hash: DEMANDE(1), ticket: "apr-0001", ...o });
const REMISE = ({ decision = "approuve", comptes = [1, 2], signatures = null, reason = "Constat et facture concordants", threshold = { required: 2, size: 3 }, jeu = {}, ticket = "apr-0001", approvalTicket = ticket, remise_id = `${ticket}/1`, extra = {} } = {}) => ({
  remise_id,
  ticket,
  approval: { decision, ticket: approvalTicket, request_hash: DEMANDE(1), threshold, approvers: comptes.map(ADR), signatures: signatures ?? comptes.map((c) => sigA(c, decision, { ticket: approvalTicket })), reason, ...extra },
  approver_set: JEU_DECLARE(jeu),
});

/** Les cas de remise : [répertoire, id, check, description, contexte, remise, raison attendue (null : scelle)]. */
function conceptionDecisions() {
  const v = (id, description, contexte, remise) => ["valides", id, null, description, contexte, remise, null];
  const iv = (id, check, description, contexte, remise, raison) => ["invalides", id, check, description, contexte, remise, raison];
  const ct1 = JSON.parse(fs.readFileSync(path.join(REPERTOIRE_CT1, "journal-valide", "evenements.json"), "utf8"));
  const dec = ct1.find((e) => e.seq === 6);
  const demande = ct1.find((e) => e.seq === 5);
  const { at, ...approvalCt1 } = dec.approval;
  const remiseCt1 = { remise_id: "apr-2201/1", ticket: "apr-2201", approval: approvalCt1, approver_set: JEU_DECLARE() };
  const contexteCt1 = { org_id: dec.org_id, journal_id: dec.journal_id, retained: [{ seq: demande.seq, ticket: "apr-2201", hash: demande.hash, ts: demande.ts }], decided: [], expire_after_ms: E, write_at: at };
  const expire = (o = {}) => REMISE({ decision: "expire", comptes: [], reason: "echeance atteinte sans decision", ...o });
  return [
    v("approbation-2-sur-3", "Approbation des comptes 1 et 2 sur le jeu 1 (2 sur 3), écrite avant l'échéance.", CONTEXTE(), REMISE()),
    v("refus-2-sur-3", "Refus des comptes 1 et 2 : mêmes règles que l'approbation (A-3).", CONTEXTE(), REMISE({ decision: "refuse", reason: "IBAN non conforme" })),
    v("expiration-sans-signature", "Expiration sans signature, écrite à l'échéance : SG-4 ne vise que approuve et refuse.", CONTEXTE({ write_at: T("10:00:00.200") }), expire()),
    v("jeu-statique", "Approbation sur un jeu statique : source « jeu statique de la politique vecteurs-ct3-1 ».", CONTEXTE(), REMISE({ jeu: { source: SRC_STATIQUE } })),
    v("ct1-apr-2201", "La décision du ticket apr-2201 des vecteurs de CT-1 (journal-sinistres, seq 6) : approval augmenté de at = l'approval de l'événement, clé pour clé (exemple de CT-3 §12.5).", contexteCt1, remiseCt1),
    v("separation-non-verifiee-par-le-noyau", "Le compte 3, adresse du demandeur, signe avec le compte 1 : le noyau scelle, il ne vérifie pas la séparation des tâches (EX-9.12).", CONTEXTE(), REMISE({ comptes: [3, 1] })),
    iv("sg1-at-present", "SG-1", "approval porte at, que l'écrivain pose.", CONTEXTE(), REMISE({ extra: { at: T("09:15:01.900") } }), "remise_mal_formee"),
    iv("sg1-ticket-different", "SG-1", "approval.ticket (apr-0002) différent du ticket de la remise.", CONTEXTE(), REMISE({ approvalTicket: "apr-0002" }), "remise_mal_formee"),
    iv("sg1-source-libre", "SG-1", "source en texte libre, hors d'EX-8.8.", CONTEXTE(), REMISE({ jeu: { source: "comptes Hardhat 1 à 3 (vecteurs CT-1)" } }), "remise_mal_formee"),
    iv("sg1-signature-courte", "SG-1", "Signature de 64 octets.", CONTEXTE(), REMISE({ signatures: [sigA(1), sigA(2).slice(0, 130)] }), "remise_mal_formee"),
    iv("sg2-ticket-inconnu", "SG-2", "Aucun événement retenue ne porte ce ticket.", CONTEXTE({ retained: [{ seq: 5, ticket: "apr-0002", hash: DEMANDE(1), ts: TS_DEMANDE }] }), REMISE(), "ticket_inconnu"),
    iv("sg2-request-hash-different", "SG-2", "L'événement retenue du ticket a un autre hash.", CONTEXTE({ retained: [{ seq: 5, ticket: "apr-0001", hash: DEMANDE(2), ts: TS_DEMANDE }] }), REMISE(), "request_hash_different"),
    iv("sg3-deja-decide", "SG-3", "Une décision est déjà scellée pour ce ticket.", CONTEXTE({ decided: [{ ticket: "apr-0001", decision: "approuve", seq: 6, hash: EVENEMENT(6), at: T("09:15:00.900") }] }), REMISE(), "ticket_deja_decide"),
    iv("sg4-ecriture-a-l-echeance", "SG-4", "Écriture à l'instant exact de l'échéance (ts + 1 h) : non strictement antérieure.", CONTEXTE({ write_at: T("10:00:00.200") }), REMISE(), "echeance_depassee"),
    iv("sg4-ecriture-apres-l-echeance", "SG-4", "Refus écrit après l'échéance.", CONTEXTE({ write_at: T("10:05:00.000") }), REMISE({ decision: "refuse" }), "echeance_depassee"),
    iv("sg5-signature-sur-la-chaine", "SG-5", "Le compte 2 a signé les 66 caractères « 0x… » de D_A au lieu de ses 32 octets (EX-9.7).", CONTEXTE(), REMISE({ signatures: [sigA(1), signatureSurChaine(2, { decision: "approuve", request_hash: DEMANDE(1), ticket: "apr-0001" })] }), "signature_invalide"),
    iv("sg5-approuve-pour-refuse", "SG-5", "Signatures approuve présentées dans une remise refuse.", CONTEXTE(), REMISE({ decision: "refuse", signatures: [sigA(1, "approuve"), sigA(2, "approuve")] }), "signature_invalide"),
    iv("sg5-autre-journal", "SG-5", "Signatures sur A d'un autre journal (journal-sinistres de CT-1).", CONTEXTE(), REMISE({ signatures: [1, 2].map((c) => sigSur(c, { decision: "approuve", request_hash: DEMANDE(1), ticket: "apr-0001", journal_id: keccak256(toUtf8Bytes("journal-sinistres")) })) }), "signature_invalide"),
    iv("sg5-s-haut", "SG-5", "Signature du compte 2 à s haut : le noyau ne normalise pas.", CONTEXTE(), REMISE({ signatures: [sigA(1), formeHaute(sigA(2))] }), "signature_invalide"),
    iv("sg5-v-zero-un", "SG-5", "Signature du compte 2 avec v ∈ {0, 1} : non canonique pour le noyau.", CONTEXTE(), REMISE({ signatures: [sigA(1), formeV01(sigA(2))] }), "signature_invalide"),
    iv("sg5-longueurs-differentes", "SG-5", "Deux approbateurs, une signature (E-5).", CONTEXTE(), REMISE({ signatures: [sigA(1)] }), "signature_invalide"),
    iv("sg5-ordre-inverse", "SG-5", "signatures[i] ne correspond pas à approvers[i].", CONTEXTE(), REMISE({ signatures: [sigA(2), sigA(1)] }), "signature_invalide"),
    iv("sg6-approbateur-double", "SG-6", "Le compte 1 deux fois.", CONTEXTE(), REMISE({ comptes: [1, 1] }), "approbateur_double"),
    iv("sg6-approbateur-hors-jeu", "SG-6", "Le compte 4, non membre, signe validement.", CONTEXTE(), REMISE({ comptes: [1, 4] }), "approbateur_hors_jeu"),
    iv("sg6-seuil-different-du-jeu", "SG-6", "approval.threshold 2 sur 3, jeu déclaré 3 sur 3.", CONTEXTE(), REMISE({ jeu: { threshold: { required: 3, size: 3 } } }), "seuil_different_du_jeu"),
    iv("sg6-expire-avec-signature", "SG-6", "Expiration portant une signature valide du compte 1 sur A(expire).", CONTEXTE(), expire({ comptes: [1] }), "expire_avec_signatures"),
    iv("sg6-seuil-non-atteint", "SG-6", "Une seule approbation pour un seuil de 2.", CONTEXTE(), REMISE({ comptes: [1] }), "seuil_non_atteint"),
    iv("sg6-refus-seuil-non-atteint", "SG-6", "Un seul refus pour un seuil de 2 (EX-9.13).", CONTEXTE(), REMISE({ decision: "refuse", comptes: [1] }), "seuil_non_atteint"),
    iv("sg1-remise-id-autre-ticket", "SG-1", "remise_id apr-0002/1 pour une remise du ticket apr-0001 : remise_id doit commencer par « <ticket>/ ».", CONTEXTE(), REMISE({ remise_id: "apr-0002/1" }), "remise_mal_formee"),
    iv("sg6-taille-differente-des-membres", "SG-6", "approval.threshold et jeu déclarés 2 sur 4, mais le jeu déclaré n'a que trois membres : size doit égaler le nombre de membres.", CONTEXTE(), REMISE({ threshold: { required: 2, size: 4 }, jeu: { threshold: { required: 2, size: 4 } } }), "seuil_different_du_jeu"),
    // Ordre des vérifications (EX-9.11) : deux vérifications en échec, la première l'emporte.
    iv("ordre-sg1-sg2", "SG-1", "SG-1 (approval porte at) et SG-2 (ticket sans événement retenue) en échec : SG-1 l'emporte.", CONTEXTE({ retained: [{ seq: 5, ticket: "apr-0002", hash: DEMANDE(1), ts: TS_DEMANDE }] }), REMISE({ extra: { at: T("09:15:01.900") } }), "remise_mal_formee"),
    iv("ordre-sg2-sg3", "SG-2", "SG-2 (autre hash) et SG-3 (décision déjà scellée) en échec : SG-2 l'emporte.", CONTEXTE({ retained: [{ seq: 5, ticket: "apr-0001", hash: DEMANDE(2), ts: TS_DEMANDE }], decided: [{ ticket: "apr-0001", decision: "approuve", seq: 6, hash: EVENEMENT(6), at: T("09:15:00.900") }] }), REMISE(), "request_hash_different"),
    iv("ordre-sg3-sg4", "SG-3", "SG-3 (décision déjà scellée) et SG-4 (écriture à l'échéance) en échec : SG-3 l'emporte.", CONTEXTE({ write_at: T("10:00:00.200"), decided: [{ ticket: "apr-0001", decision: "approuve", seq: 6, hash: EVENEMENT(6), at: T("09:15:00.900") }] }), REMISE(), "ticket_deja_decide"),
    iv("ordre-sg4-sg5", "SG-4", "SG-4 (écriture après l'échéance) et SG-5 (signatures inversées) en échec : SG-4 l'emporte.", CONTEXTE({ write_at: T("10:05:00.000") }), REMISE({ signatures: [sigA(2), sigA(1)] }), "echeance_depassee"),
    iv("ordre-sg5-sg6", "SG-5", "SG-5 (signatures inversées) et SG-6 (compte 4 hors jeu) en échec : SG-5 l'emporte.", CONTEXTE(), REMISE({ comptes: [1, 4], signatures: [sigA(4), sigA(1)] }), "signature_invalide"),
    iv("ordre-sg6-double-hors-jeu", "SG-6", "Le compte 4, non membre, deux fois : approbateur_double précède approbateur_hors_jeu.", CONTEXTE(), REMISE({ comptes: [4, 4] }), "approbateur_double"),
    iv("ordre-sg6-hors-jeu-seuil", "SG-6", "Le compte 4 hors jeu, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : approbateur_hors_jeu précède seuil_different_du_jeu.", CONTEXTE(), REMISE({ comptes: [1, 4], jeu: { threshold: { required: 3, size: 3 } } }), "approbateur_hors_jeu"),
    iv("ordre-sg6-seuil-expire", "SG-6", "Expiration signée par le compte 1, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : seuil_different_du_jeu précède expire_avec_signatures.", CONTEXTE(), expire({ comptes: [1], jeu: { threshold: { required: 3, size: 3 } } }), "seuil_different_du_jeu"),
    iv("ordre-sg6-seuil-non-atteint", "SG-6", "Une seule approbation, et un jeu déclaré 3 sur 3 pour approval.threshold 2 sur 3 : seuil_different_du_jeu précède seuil_non_atteint.", CONTEXTE(), REMISE({ comptes: [1], jeu: { threshold: { required: 3, size: 3 } } }), "seuil_different_du_jeu"),
  ];
}

// ---------------------------------------------------------------------------
// Normalisation (A.8)
// ---------------------------------------------------------------------------

function conceptionNormalisation() {
  // Une signature canonique de v = 27 et une de v = 28, sur A d'apr-0001 (demande 1, approuve).
  const candidates = [1, 2, 3, 4].map((c) => sigA(c));
  const v27 = candidates.find((s) => s.endsWith("1b"));
  const v28 = candidates.find((s) => s.endsWith("1c"));
  exiger(v27 && v28, "il faut une signature de chaque parité parmi les comptes 1 à 4");
  return [
    ["canonique", v27, v27, null, "Forme canonique (s bas, v = 27) : inchangée."],
    ["canonique-v28", v28, v28, null, "Forme canonique (s bas, v = 28) : inchangée."],
    ["s-haut-v27", formeHaute(v28), v28, null, "s haut et v = 27 : n − s et v = 28."],
    ["s-haut-v28", formeHaute(v27), v27, null, "s haut et v = 28 : n − s et v = 27."],
    ["v-0", formeV01(v27), v27, null, "v = 0 devient 27."],
    ["v-1", formeV01(v28), v28, null, "v = 1 devient 28."],
    ["s-haut-v-0", formeV01(formeHaute(v28)).slice(0, 130) + "00", v28, null, "s haut et v = 0 : v devient 27, puis n − s et v = 28."],
    ["v-29", v27.slice(0, 130) + "1d", null, "signature_invalide", "v = 29 : refusée."],
    ["v-2", v27.slice(0, 130) + "02", null, "signature_invalide", "v = 2 : refusée."],
    ["longueur-64", v27.slice(0, 130), null, "signature_invalide", "64 octets : refusée."],
    ["longueur-66", v27 + "00", null, "signature_invalide", "66 octets : refusée."],
    ["r-nul", "0x" + "0".repeat(64) + v27.slice(66), null, "signature_invalide", "r = 0 : refusée (r doit être dans [1, n − 1])."],
    ["r-egal-n", "0x" + N_SECP.toString(16) + v27.slice(66), null, "signature_invalide", "r = n : refusée (r doit être dans [1, n − 1])."],
    ["s-nul", v27.slice(0, 66) + "0".repeat(64) + v27.slice(130), null, "signature_invalide", "s = 0 : refusée (s doit être dans [1, n − 1])."],
    ["s-egal-n", v27.slice(0, 66) + N_SECP.toString(16) + v27.slice(130), null, "signature_invalide", "s = n : refusée avant toute normalisation (s doit être dans [1, n − 1])."],
  ];
}

// ---------------------------------------------------------------------------
// INDEX.md
// ---------------------------------------------------------------------------

const code = (s) => "`" + s + "`";
function index({ constantes, politiques, invalides, evaluations, candidats, acceptation, tickets, decisions, normalisation }) {
  const L = [];
  L.push("# Vecteurs CT-3 — approbations");
  L.push("");
  L.push(MARQUE_INDEX + " (`npm run vecteurs:ct3`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-3-approbations.md`](../../CT-3-approbations.md), annexe A. Rejoués par `test/approbation.test.js` avec l'implémentation de référence `scripts/lib/approbation.mjs`.");
  L.push("");
  L.push("Le générateur n'efface et ne réécrit que ses propres entrées de premier niveau (`constantes.json`, `INDEX.md`, `acceptation-attendu.json` et les répertoires `acceptation/`, `candidats/`, `decisions/`, `evaluation/`, `politiques/`, `politiques-invalides/`, `signatures/`, `tickets/`), jamais `verificateur-independant/` (EX-A.1). Une partie des attendus est posée par conception dans le générateur (règle, décision et ouverture de chaque demande ; état de chaque ticket après chaque pas, sort et raison de chaque entrée ; décision, signataires, motif et source de chaque remise ; tickets des fenêtres) et confrontée à l'implémentation de référence avant d'être écrite. Le reste (seuil et membres d'une remise, objet approval rendu à une ré-émission, bornes et restant des fenêtres, jeu des réponses nouveau) sort de l'implémentation de référence sans contrôle de conception : le vérificateur Go indépendant (`verificateur-independant/`) le recalcule.");
  L.push("");
  L.push("## Constantes (A.2, `constantes.json`)");
  L.push("");
  L.push("Clés de test **publiques** (mnémonique Hardhat) : elles ne doivent jamais porter de valeur.");
  L.push("");
  L.push("| Grandeur | Valeur |");
  L.push("|---|---|");
  L.push(`| Organisation | ${code(constantes.organization.slug)}, ${code(constantes.organization.org_id)} |`);
  L.push(`| Journal | ${code(constantes.journal.name)}, ${code(constantes.journal.journal_id)} |`);
  L.push(`| Versions de politique | ${constantes.policy_versions.map(code).join(", ")} |`);
  L.push(`| Chaîne, registre | ${constantes.chain_id}, ${code(constantes.registry)} |`);
  L.push(`| Jeux | 1 : ${code(constantes.sets["1"])} ; 2 : ${code(constantes.sets["2"])} |`);
  L.push(`| Hachages synthétiques | bloc ${code(constantes.labels.block)}, demande ${code(constantes.labels.request)}, événement ${code(constantes.labels.event)} (SHA-256 de l'étiquette UTF-8) |`);
  for (const c of constantes.accounts) L.push(`| Compte ${c.index} | ${code(c.address)}, clé ${code(c.private_key)} |`);
  L.push(`| Demandeur | ${code(constantes.requester.launched_by)}, détient le compte ${constantes.requester.account} |`);
  L.push(`| Instant de base | ${code(constantes.base_instant)} |`);
  L.push("");
  L.push("## politiques/ et politiques-invalides/ (A.4, AP-1 à AP-4)");
  L.push("");
  L.push("| Politique valide | Contenu |");
  L.push("|---|---|");
  for (const [f, p] of Object.entries(politiques)) L.push(`| ${code(f)} | ${p.description} |`);
  L.push("");
  L.push("Attendus des politiques refusées : `politiques-invalides/attendu.json` (liste complète des erreurs, triée par pointeur puis par code).");
  L.push("");
  L.push("| Politique refusée | environment, expire_after_ms | Erreurs | Ce qu'elle exerce |");
  L.push("|---|---|---|---|");
  for (const c of invalides) L.push(`| ${code(c.file)} | ${c.environment}, ${c.expire_after_ms} | ${c.errors.map((e) => `${e.code}${e.pointer ? " " + code(e.pointer) : ""}`).join(" ; ")} | ${c.description} |`);
  L.push("");
  L.push("## evaluation/ (A.4, AP-5 à AP-17)");
  L.push("");
  for (const [f, doc] of Object.entries(evaluations)) {
    L.push(`### ${code(f)} — politique ${code(doc.policy)}`);
    L.push("");
    L.push("| Cas | Outil | Décision | policy.rule | Ouvrant |");
    L.push("|---|---|---|---|---|");
    for (const c of doc.cases) L.push(`| ${code(c.id)} | ${code(c.request.tool_announced)} | ${c.expected.decision} | ${code(c.expected.rule)} | ${c.expected.opening ? "oui" : "—"} |`);
    L.push("");
  }
  L.push("## candidats/ (A.4, AP-16)");
  L.push("");
  L.push("| Fichier | Cas | Liste L | approval_candidates |");
  L.push("|---|---|---|---|");
  for (const [f, doc] of Object.entries(candidats)) for (const c of doc.cases) L.push(`| ${code(f)} | ${code(c.id)} | ${c.tools.map(code).join(", ") || "—"} | ${c.approval_candidates.map(code).join(", ") || "—"} |`);
  L.push("");
  L.push("## acceptation/ et acceptation-attendu.json (A.5)");
  L.push("");
  L.push("Le répertoire `acceptation/` est ce que reçoit chaque relecteur (consigne, politique, dix cas, gabarit de réponse) ; les décisions attendues sont dans `acceptation-attendu.json`, à côté, que les relecteurs ne reçoivent pas. Pour cette raison, cet index ne les reproduit pas : il dit seulement ce que chaque cas exerce.");
  L.push("");
  L.push("| Cas | Ce qu'il exerce |");
  L.push("|---|---|");
  for (const [id, ce] of acceptation) L.push(`| ${code(id)} | ${ce} |`);
  L.push("");
  L.push("## tickets/ (A.6, TK-1 à TK-13)");
  L.push("");
  L.push("Chaque pas donne l'état de chaque ticket après l'entrée (minuteurs échus compris). Notation : entrée, instant, puis états ; « refus : » donne la raison d'une entrée refusée ; « remise : » la décision remise au noyau pendant le pas.");
  L.push("");
  for (const tr of tickets) {
    L.push(`### ${code(tr.id + ".json")} (${tr.checks.join(", ")})`);
    L.push("");
    L.push(tr.description);
    L.push("");
    tr.steps.forEach((s, i) => {
      const etats = Object.entries(s.expected.tickets).map(([k, v]) => `${k} ${v}`).join(", ") || "aucun ticket";
      const refus = s.expected.accepted ? "" : ` ; refus : ${s.expected.reason}`;
      const remises = s.expected.remises.map((r) => ` ; remise ${r.remise_id} : ${r.approval.decision}${r.approval.approvers.length ? " (" + r.approval.approvers.length + " signatures)" : ""}`).join("");
      L.push(`${i + 1}. ${s.input.kind} ${s.input.at.slice(11, 23)} → ${etats}${refus}${remises}`);
    });
    L.push("");
  }
  L.push("## decisions/ (A.7, SG-1 à SG-6)");
  L.push("");
  L.push("| Cas | Vérification visée | Résultat attendu | Ce qu'il exerce |");
  L.push("|---|---|---|---|");
  for (const d of decisions) L.push(`| ${code(d.chemin)} | ${d.cas.check ?? "—"} | ${d.cas.expected.result}${d.cas.expected.reason ? ", " + d.cas.expected.reason : ""} | ${d.cas.description} |`);
  L.push("");
  L.push("## signatures/normalisation.json (A.8, EX-9.3)");
  L.push("");
  L.push("Signatures du vote approuve d'apr-0001 (demande 1, journal-approbations) par les comptes de test ; chaque forme normalisée recouvre la même adresse que la forme d'entrée.");
  L.push("");
  L.push("| Cas | Attendu |");
  L.push("|---|---|");
  for (const c of normalisation) L.push(`| ${code(c.id)} | ${c.expected ? "forme normalisée" : "refusée (" + c.reason + ")"} |`);
  L.push("");
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

/** Génère spec/vecteurs/ct-3 (ou `racine`). Rend des compteurs pour les tests. */
export function genererCt3({ racine = REPERTOIRE_CT3 } = {}) {
  const schemas = chargerSchemas();
  racineAdmise(racine);
  fs.mkdirSync(racine, { recursive: true });
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(racine, e), { recursive: true, force: true });
  const ecrire = (rel, valeur) => {
    const f = path.join(racine, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, typeof valeur === "string" ? valeur : texteJSON(valeur));
  };

  // Constantes.
  const constantes = {
    version: 0,
    organization: { slug: ORG, org_id: ORG_ID },
    journal: { name: JOURNAL, journal_id: JOURNAL_ID },
    policy_versions: [V1, V2],
    chain_id: CHAIN_ID,
    registry: REGISTRE,
    sets: { 1: JEU(1), 2: JEU(2) },
    labels: { registry: "noortrace/vecteurs/ct3/registre", set: "noortrace/vecteurs/ct3/jeu/<n>", block: "noortrace/vecteurs/ct3/bloc/<h>", request: "noortrace/vecteurs/ct3/demande/<k>", event: "noortrace/vecteurs/ct3/evenement/<seq>" },
    accounts: [1, 2, 3, 4].map((i) => ({ index: i, derivation_path: CHEMIN(i), address: ADR(i), private_key: COMPTES[i].privateKey })),
    mnemonic: MNEMONIQUE,
    requester: { launched_by: DEMANDEUR, account: 3 },
    base_instant: INSTANT_BASE,
    expire_after_ms: E,
  };
  ecrire("constantes.json", constantes);

  // Politiques valides.
  const politiques = politiquesValides();
  for (const [f, p] of Object.entries(politiques)) {
    exiger(A.erreursPolitique(p.doc, { schemas, environment: "developpement", expire_after_ms: E }).length === 0, `politique ${f} invalide`);
    ecrire(path.join("politiques", f), p.doc);
  }

  // Politiques invalides.
  const invalides = conceptionInvalides().map(([file, checks, environment, expire_after_ms, doc, errors, description]) => {
    const obtenues = A.erreursPolitique(doc, { schemas, environment, expire_after_ms });
    exiger(J.egalJSON(obtenues, errors), `politique invalide ${file} : ${JSON.stringify(obtenues)}, conception ${JSON.stringify(errors)}`);
    // EX-4.2 : une non-conformité au schéma donne exactement l'entrée schema, et aucune autre.
    if (errors[0].code === "schema") exiger(errors.length === 1, `politique invalide ${file} : entrée schema non seule`);
    ecrire(path.join("politiques-invalides", file), doc);
    return { file, environment, expire_after_ms, checks, errors, description };
  });
  ecrire(path.join("politiques-invalides", "attendu.json"), { version: 0, cases: invalides.map(({ description, ...c }) => c) });

  // Évaluation.
  const evaluations = {};
  for (const [f, { policy, cas }] of Object.entries(conceptionEvaluation())) {
    const doc = fichierEvaluation(policy, politiques[policy].doc, cas);
    exiger(A.erreursSchema(doc, schemas, "fichier_evaluation").length === 0, `evaluation/${f} non conforme`);
    evaluations[f] = doc;
    ecrire(path.join("evaluation", f), doc);
  }
  // AP-17 : mêmes sorties pour la politique permutée.
  evaluations["assureur.json"].cases.forEach((c, i) => exiger(J.egalJSON(c.expected, evaluations["assureur-permute.json"].cases[i].expected), `AP-17 : ${c.id}`));

  // Candidats.
  const candidats = {};
  for (const [f, cas] of Object.entries(conceptionCandidats())) {
    const doc = {
      version: 0,
      policy: `politiques/${f}`,
      cases: cas.map(([id, checks, tools, attendus]) => {
        const r = A.candidats(politiques[f].doc, tools);
        exiger(J.egalJSON(r, attendus), `candidats ${f}/${id} : ${JSON.stringify(r)}, conception ${JSON.stringify(attendus)}`);
        return { id, checks, tools, approval_candidates: r };
      }),
    };
    exiger(A.erreursSchema(doc, schemas, "fichier_candidats").length === 0, `candidats/${f} non conforme`);
    candidats[f] = doc;
    ecrire(path.join("candidats", f), doc);
  }

  // Acceptation.
  exiger(A.erreursPolitique(POLITIQUE_ACCEPTATION, { schemas, environment: "developpement", expire_after_ms: E }).length === 0, "politique d'acceptation invalide");
  ecrire(path.join("acceptation", "politique.json"), POLITIQUE_ACCEPTATION);
  ecrire(path.join("acceptation", "consigne.md"), CONSIGNE);
  const accCas = conceptionAcceptation();
  const attendus = accCas.map(([id, outil, args, rule, decision]) => {
    const request = requete({ outil, origine: outil.split("__")[1], alias: "sap", args, intent: null, run: "run-2026-11-12-0042" });
    const r = A.evaluer(POLITIQUE_ACCEPTATION, request, { fenetres: [], t: INSTANT_BASE, policy_version: V1 });
    exiger(r.rule === rule && r.decision === decision, `acceptation ${id} : ${r.decision} « ${r.rule} », conception ${decision} « ${rule} »`);
    ecrire(path.join("acceptation", "cas", `${id}.json`), { id, request });
    return { id, rule, decision };
  });
  for (const d of ["autorise", "a_approuver", "refuse"]) exiger(attendus.filter((a) => a.decision === d).length >= 2, `EX-A.4 : ${d} moins de deux fois`);
  ecrire(path.join("acceptation", "gabarit-reponse.json"), { role: null, reviewer: null, answers: attendus.map(({ id }) => ({ id, decision: null })) });
  const accAttendu = { version: 0, policy: "acceptation/politique.json", expected: attendus };
  exiger(A.erreursSchema(accAttendu, schemas, "attendu_acceptation").length === 0, "acceptation-attendu.json non conforme");
  ecrire("acceptation-attendu.json", accAttendu);

  // Traces.
  const tickets = traces().map((c) => {
    const tr = fichierTrace(c, schemas);
    exiger(A.erreursSchema(tr, schemas, "trace").length === 0, `trace ${c.id} non conforme : ${JSON.stringify(A.erreursSchema(tr, schemas, "trace").slice(0, 3))}`);
    ecrire(path.join("tickets", `${c.id}.json`), tr);
    return tr;
  });

  // Décisions.
  const decisions = conceptionDecisions().map(([rep, id, check, description, context, remise, raison]) => {
    const r = A.verifierRemise(remise, context, { schemas });
    exiger(r.result === (raison ? "refuse" : "scelle") && r.reason === raison && r.check === check, `remise ${rep}/${id} : ${JSON.stringify(r)}, conception ${raison ?? "scelle"} (${check})`);
    const cas = { version: 0, id, description, check, context, remise, expected: { result: r.result, reason: r.reason } };
    exiger(A.erreursSchema(cas, schemas, "cas_remise").length === 0, `decisions/${rep}/${id} non conforme`);
    ecrire(path.join("decisions", rep, `${id}.json`), cas);
    return { chemin: `decisions/${rep}/${id}.json`, cas };
  });

  // Normalisation.
  const normalisation = conceptionNormalisation().map(([id, signature, expected, reason, description]) => {
    const r = A.normaliserSignature(signature);
    exiger(r.signature === expected && r.reason === reason, `normalisation ${id} : ${JSON.stringify(r)}`);
    return { id, description, signature, expected, reason };
  });
  ecrire(path.join("signatures", "normalisation.json"), { version: 0, cases: normalisation.map(({ id, signature, expected, reason }) => ({ id, signature, expected, reason })) });

  ecrire("INDEX.md", index({ constantes, politiques, invalides, evaluations, candidats, acceptation: accCas.map(([id, , , , , ce]) => [id, ce]), tickets, decisions, normalisation }));
  return { politiques: Object.keys(politiques).length, invalides: invalides.length, evaluation: Object.values(evaluations).reduce((n, d) => n + d.cases.length, 0), candidats: Object.values(candidats).reduce((n, d) => n + d.cases.length, 0), tickets: tickets.length, decisions: decisions.length, normalisation: normalisation.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && !process.argv[i + 1]) {
    process.stderr.write("generer-ct3 : --sortie demande un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT3;
  const r = genererCt3({ racine });
  process.stdout.write(`ct-3 : ${r.politiques} politiques valides, ${r.invalides} invalides, ${r.evaluation} cas d'évaluation, ${r.candidats} cas de candidats, 10 cas d'acceptation, ${r.tickets} traces, ${r.decisions} remises, ${r.normalisation} signatures sous ${racine}\n`);
}
