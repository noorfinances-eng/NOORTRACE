#!/usr/bin/env node
// Générateur des vecteurs de CT-6 (spec/CT-6-verificateur.md, annexe A) :
// spec/vecteurs/ct-6/.
//
//   node scripts/vecteurs/generer-ct6.mjs [--sortie <répertoire ct-6>]
//   npm run vecteurs:ct6
//
// Il appelle les trois générateurs de famille, puis écrit les fichiers
// d'ancres de test, les dossiers complets et INDEX.md :
//
//   rfc3161/   scripts/vecteurs/ct6/rfc3161.mjs (jetons, certificats, CRL) ;
//   ots/       scripts/vecteurs/ct6/ots.mjs (preuves .ots, en-têtes regtest) ;
//   registre/  scripts/vecteurs/ct6/registre.mjs (parties du contrôle 8,
//              dérivées de la capture unique registre/capture/) ;
//   ancres/    fichiers d'ancres de test (EX-A.10) ;
//   dossiers/  le dossier CT-1 valide-seq-7 complété des cinq parties
//              réservées, et ses variantes (EX-A.11), chacun avec son
//              attendu.json (EX-A.3) ; révision 0.2 : les dossiers qui portent
//              la treizième partie points-de-controle.json (EX-A.16), bâtis sur
//              le point de contrôle couvrant seq 7 de la série de CT-1
//              (spec/vecteurs/ct-1/points-de-controle/periode-1.json) ;
//   INDEX.md   chaque cas et son attendu.
//
// Entrées jamais réécrites (EX-A.1) : registre/capture/ (capture du réseau de
// développement), rfc3161/cles/*.cle.pem (clés RSA de test, dérivées de
// graines publiées) et confrontation/ (programmes et sorties des
// implémentations tierces). Tout le reste de spec/vecteurs/ct-6 est effacé et
// réécrit, à l'identique d'une exécution à l'autre.
//
// Les attendus des dossiers sont posés par construction (vérifications en
// échec, statut et raison des huit contrôles, avertissements, borne, code de
// retour), puis confrontés au vérificateur de référence
// (scripts/lib/verificateur.mjs) : un écart arrête la génération. L'énoncé et
// la liste des vérifications non exécutées sont ceux que le vérificateur
// construit selon les sections 5 et 6.5 ; test/verificateur.test.js
// reconstruit l'énoncé du dossier complet fragment par fragment,
// indépendamment.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as J from "../lib/journal.mjs";
import * as V from "../lib/verificateur.mjs";
import { dossiersDecisions } from "./ct6/decisions.mjs";
import crypto from "node:crypto";
import { construireJeton, genererRfc3161 } from "./ct6/rfc3161.mjs";
import { genererOts } from "./ct6/ots.mjs";
import { ancreRegistre, ancresEnregistreurs, appliquerModifications, genererRegistre, lireCapture, modificationsAncres, referenceAncreDePeriodeCommePoint, referencePoint, sectionIndex, transactionPoint } from "./ct6/registre.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const REPERTOIRE_CT6 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6");
const REPERTOIRE_CT1 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1");
const DOSSIER_BASE = path.join(REPERTOIRE_CT1, "dossiers", "valide-seq-7");

/** Entrées de premier niveau de ct-6 que ce générateur ne supprime pas : familles (gérées par leur générateur) et confrontation/. */
const CONSERVEES = new Set(["rfc3161", "ots", "registre", "confrontation"]);
// Entrées de premier niveau que le générateur écrit lui-même : seules elles sont
// effacées avant une génération ; une racine qui porte une autre entrée est refusée.
const ENTREES_GENEREES = ["INDEX.md", "ancres", "dossiers"];

const texteJSON = (v) => JSON.stringify(v, null, 2) + "\n";
const exiger = (condition, message) => {
  if (!condition) throw new Error(`generer-ct6 : ${message}`);
};

// ---------------------------------------------------------------------------
// Ancres de test (EX-A.10)
// ---------------------------------------------------------------------------

const PREPARE_PAR = "générateur des vecteurs CT-6 (scripts/vecteurs/generer-ct6.mjs)";
const PREPARE_LE = "2026-11-10T08:00:00.000Z";

/**
 * Les fichiers d'ancres de test (annexe A.6) : nom -> { objet, description }.
 */
export function fichiersAncres({ fragments, ancreBitcoin, capture }) {
  const base = (label, fragment) => ({
    version: 0,
    label,
    prepared_by: PREPARE_PAR,
    prepared_at: PREPARE_LE,
    tsa_authorities: fragment.tsa_authorities,
    revocation: fragment.revocation,
    bitcoin: ancreBitcoin,
    registry: ancreRegistre(capture),
    recorders: ancresEnregistreurs(capture),
  });
  const test = base("Ancres de test CT-6 (ancres-test.json)", fragments.test);
  const mods = modificationsAncres(capture);
  const variante = (nom, modifications) => ({ ...appliquerModifications(test, modifications), label: `Ancres de test CT-6 (${nom})` });
  const out = {
    "ancres-test.json": { objet: test, description: "autorité ac-test.pem (politique d'essai admise, qualified = null), crl-vide.pem ; bitcoin regtest, point de contrôle 1000, profondeur 6 ; registry de capture.json et validators.json ; recorders rec-test-01 et rec-test-02 avec leurs clés de chaîne" },
    "ancres-qualification-declaree.json": { objet: base("Ancres de test CT-6 (ancres-qualification-declaree.json)", fragments.qualification_declaree), description: "idem, qualified = {eidas, 2026-01-01, sans fin, « déclaration de test, sans valeur »}" },
    "ancres-tsa-revoquee.json": { objet: base("Ancres de test CT-6 (ancres-tsa-revoquee.json)", fragments.tsa_revoquee), description: "idem, crl-tsa-revoquee.pem à la place de crl-vide.pem (tsa-test.pem révoqué le 2026-11-05T12:00:00Z, keyCompromise)" },
    "ancres-autre-chaine.json": { objet: variante("ancres-autre-chaine.json", mods["ancres-autre-chaine.json"]), description: "idem, registry.chain_id = noortrace-9999-test" },
    "ancres-autre-registre.json": { objet: variante("ancres-autre-registre.json", mods["ancres-autre-registre.json"]), description: "idem, period_registry = adresse d'AttestationRegistry" },
    "ancres-cle-enregistreur-autre.json": { objet: variante("ancres-cle-enregistreur-autre.json", [{ pointer: "/recorders/0/public_key", value: test.recorders[1].public_key }]), description: "idem, public_key de rec-test-01 remplacée par celle de rec-test-02" },
    "ancres-cle-chaine-autre.json": { objet: variante("ancres-cle-chaine-autre.json", mods["ancres-cle-chaine-autre.json"]), description: "idem, chain_key de rec-test-02 remplacée par celle de rec-test-01" },
    "ancres-sans-enregistreurs.json": { objet: variante("ancres-sans-enregistreurs.json", mods["ancres-sans-enregistreurs.json"]), description: "idem, recorders vide : aucune clé d'enregistreur ne vient du fichier d'ancres (N-3 et N-4 absentes) ; les clés sont confirmées par les inscriptions que R-10 prouve" },
    "ancres-enregistreur-01-seul.json": { objet: variante("ancres-enregistreur-01-seul.json", mods["ancres-enregistreur-01-seul.json"]), description: "idem, recorders réduit à rec-test-01 (provenance mixte des clés, EX-6.8 ; N-4 absente)" },
    "ancres-deux-jeux.json": { objet: variante("ancres-deux-jeux.json", mods["ancres-deux-jeux.json"]), description: "idem, registry.validator_sets coupé en deux jeux de mêmes clés, l'un jusqu'au bloc de l'ancre de la période 1, l'autre au-delà (EX-11.22)" },
    "ancres-unite-epinglee-revoquee.json": { objet: base("Ancres de test CT-6 (ancres-unite-epinglee-revoquee.json)", fragments.unite_epinglee_revoquee), description: "idem, autorité = l'unité tsa-test.pem elle-même (« Unité TSA épinglée de test CT-6 ») et crl-tsa-revoquee.pem, qui la révoque pour keyCompromise : T-10 échoue (EX-9.16)" },
    "ancres-deux-autorites.json": { objet: base("Ancres de test CT-6 (ancres-deux-autorites.json)", fragments.deux_autorites), description: "idem, deux autorités : l'unité tsa-test.pem épinglée (qualified eidas déclaré), puis ac-test.pem ; crl-vide.pem. T-7 retient la première (EX-9.13)" },
  };
  return out;
}

// ---------------------------------------------------------------------------
// Dossiers (EX-A.11)
// ---------------------------------------------------------------------------

const TOUS_REUSSIS = { 1: "reussi", 2: "reussi", 3: "reussi", 4: "reussi", 5: "reussi", 6: "reussi", 7: "reussi", 8: "reussi" };
/** Contrôle servi par les vérifications K- (CT-6 EX-5.7). */
const CONTROLE_K = { "K-1": 3, "K-2": 3, "K-3": 6, "K-4": 3, "K-5": 3, "K-6": 2, "K-7": 4, "K-8": 8, "K-9": 5 };
const CONTROLE_DE = (id) => CONTROLE_K[id] ?? ({ T: 4, O: 5, R: 8, P: 3 })[id[0]] ?? (id === "N-3" ? 6 : 8);
const HORS_CT1 = { 4: "hors_perimetre_version", 5: "hors_perimetre_version", 8: "hors_perimetre_version" };

/**
 * Conception des dossiers : changement par rapport à valide-seq-7-complet,
 * ancres et en-têtes employés, et attendus posés par construction : statut
 * des huit contrôles et raison de chaque contrôle non exécuté (d'où la borne,
 * EX-6.12), vérifications en échec, avertissements dans l'ordre de EX-6.15.
 * `base` : « complet » (valide-seq-7 complété des cinq parties) ou le nom d'un
 * dossier de décision de scripts/vecteurs/ct6/decisions.mjs (parties
 * réservées absentes, hors périmètre CT-1).
 */
export function conceptionDossiers() {
  const d = [];
  const ajouter = (nom, { base = "complet", jeton = "periode-1", preuve = "periode-1", registre = null, partiesRegistre = null, manifeste = null, point = null, ancres = "ancres-test.json", entetes = "chaine.json", cible = null, echecs = null, statuts = {}, raisons = {}, avertissements = ["AV-O-3"], description }) => {
    const control_statuses = { ...TOUS_REUSSIS, ...statuts };
    if (cible && !statuts[CONTROLE_DE(cible)]) control_statuses[CONTROLE_DE(cible)] = "echoue";
    for (const n of Object.keys(raisons)) if (control_statuses[n] !== "non_execute") throw new Error(`conception ${nom} : raison pour le contrôle ${n}, qui n'est pas non exécuté`);
    for (const [n, st] of Object.entries(control_statuses)) if (st === "non_execute" && !raisons[n]) throw new Error(`conception ${nom} : contrôle ${n} non exécuté sans raison posée`);
    d.push({ nom, base, jeton, preuve, registre, partiesRegistre: partiesRegistre ?? (registre ? `variantes/${registre}` : "periode-1"), manifeste, point, ancres, entetes, cible, failed_checks: echecs ?? (cible ? [cible] : []), control_statuses, control_reasons: raisons, warnings: avertissements, description });
  };
  ajouter("valide-seq-7-complet", { description: "Dossier valide-seq-7 de CT-1, ses sept parties inchangées, complété du jeton de la période 1 (rfc3161/jetons/periode-1.der), de sa preuve OpenTimestamps (ots/preuves/periode-1.ots) et des trois parties du registre de la période 1 (registre/periode-1/ : inscriptions de rec-test-01 et rec-test-02, ancre et clôture). Les huit contrôles réussissent ; T-11 n'est pas exécutée (aucun statut qualifié déclaré), l'énoncé ne dit pas « qualifié »." });
  ajouter("valide-seq-7-complet-sans-ancres", { ancres: null, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: { 4: "ancre_absente", 5: "ancre_absente", 8: "ancre_absente" }, avertissements: [], description: "Le même dossier, vérifié sans fichier d'ancres (avec chaine.json) : les contrôles 4, 5 et 8 ne sont pas exécutés (ancre_absente) ; N-3 et N-4 ne figurent pas au rapport ; aucun avertissement (AV-O-3 exige O-5 exécutée)." });
  ajouter("valide-seq-7-complet-sans-entetes", { entetes: null, statuts: { 5: "non_execute" }, raisons: { 5: "partie_absente" }, avertissements: [], description: "Le même dossier, vérifié avec ancres-test.json et sans fichier d'en-têtes : contrôle 5 non exécuté (partie_absente, EX-4.5)." });
  ajouter("valide-t11-qualification-declaree", { ancres: "ancres-qualification-declaree.json", description: "Le même dossier, vérifié avec ancres-qualification-declaree.json : T-11 réussie ; l'énoncé dit « horodatage qualifié eIDAS selon le réviseur (déclaration de test, sans valeur) »." });
  ajouter("valide-t7-deux-autorites", { ancres: "ancres-deux-autorites.json", description: "Le même dossier, vérifié avec ancres-deux-autorites.json (l'unité tsa-test.pem épinglée, statut qualifié déclaré, puis ac-test.pem) : T-7 retient la première autorité du fichier pour laquelle un chemin existe, par l'identité (EX-9.13) ; T-10 n'a rien à prouver ; T-11 réussie ; l'énoncé nomme « Unité TSA épinglée de test CT-6 »." });
  ajouter("valide-unite-sans-cn", { jeton: "periode-1-unite-sans-cn", description: "jeton-rfc3161.der = rfc3161/jetons/periode-1-unite-sans-cn.der : le sujet de l'unité tsa-sans-cn.pem n'a pas de commonName ; tsu_subject_cn est nul, et l'énoncé nomme l'unité par le SHA-256 de son certificat (EX-9.19, EX-9.20)." });
  for (const [t, jeton, desc] of [
    ["T-1", "t1-octet-en-trop", "un octet 00 après le ContentInfo"],
    ["T-1", "t1-default-explicite", "certificat de l'unité dont une extension encode critical à FALSE, valeur DEFAULT (EX-9.21)"],
    ["T-1", "t1-cn-utf8-invalide", "certificat de l'unité dont le CN est une UTF8String d'octets ff fe, UTF-8 invalide (EX-9.4)"],
    ["T-2", "periode-2", "jeton de la période 2 dans un dossier de la période 1 (rejeu sur un autre manifeste)"],
    ["T-3", "t3-message-digest", "genTime avancé d'une seconde dans TSTInfo, message-digest inchangé"],
    ["T-4", "t4-ess-autre-certificat", "certHash de ESSCertIDv2 = SHA-256 de ac-test.pem"],
    ["T-5", "t5-sha1", "digestAlgorithm et signature en SHA-1"],
    ["T-6", "t6-signature", "dernier octet de la signature inversé"],
    ["T-7", "t7-tsa-expiree", "certificat de la TSA expiré à genTime"],
    ["T-8", "t8-eku-non-critique", "extKeyUsage non critique"],
    ["T-9", "t9-extension-critique", "extension critique inconnue dans TSTInfo"],
  ]) {
    const nom = jeton === "periode-2" ? "invalide-t2-jeton-autre-manifeste" : `invalide-${jeton}`;
    ajouter(nom, { jeton, cible: t, description: `jeton-rfc3161.der = rfc3161/jetons/${jeton}.der : ${desc}.` });
  }
  ajouter("invalide-t10-tsa-revoquee", { ancres: "ancres-tsa-revoquee.json", cible: "T-10", description: "Le dossier complet, vérifié avec ancres-tsa-revoquee.json : le certificat de la TSA est révoqué pour keyCompromise ; T-10 échoue." });
  ajouter("invalide-t10-unite-epinglee-revoquee", { ancres: "ancres-unite-epinglee-revoquee.json", cible: "T-10", description: "Le dossier complet, vérifié avec ancres-unite-epinglee-revoquee.json : le réviseur épingle l'unité elle-même, et la CRL de son fichier d'ancres la révoque pour keyCompromise avant genTime ; T-10 échoue sur le certificat de l'autorité (EX-9.16)." });
  ajouter("invalide-o1-octet-en-trop", { preuve: "o1-octet-en-trop", cible: "O-1", avertissements: [], description: "preuve.ots = ots/preuves/o1-octet-en-trop.ots : un octet après l'arbre. O-5 n'est pas exécutée : pas d'AV-O-3." });
  ajouter("invalide-o2-preuve-autre-manifeste", { preuve: "periode-2", cible: "O-2", description: "preuve.ots = ots/preuves/periode-2.ots : preuve de la période 2 dans un dossier de la période 1." });
  ajouter("invalide-o3-resultat-trop-long", { preuve: "o3-resultat-trop-long", cible: "O-3", avertissements: ["AV-O-3", "AV-O-2"], description: "preuve.ots = ots/preuves/o3-resultat-trop-long.ots : branche f0 d'un argument de 4096 octets, message de plus de 4096 octets." });
  ajouter("invalide-o4-mauvaise-hauteur", { preuve: "o4-mauvaise-hauteur", cible: "O-4", description: "preuve.ots = ots/preuves/o4-mauvaise-hauteur.ots : attestation à la hauteur 1002." });
  ajouter("invalide-o5-chaine-sans-travail", { entetes: "chaine-sans-travail.json", cible: "O-5", description: "Le dossier complet, vérifié avec ots/entetes/chaine-sans-travail.json : l'en-tête 1010 n'a pas de preuve de travail." });
  ajouter("non-execute-o5-point-de-controle-hors-entetes", { entetes: "chaine-depuis-1001.json", statuts: { 5: "non_execute" }, raisons: { 5: "ancre_absente" }, avertissements: [], description: "Le dossier complet, vérifié avec ots/entetes/chaine-depuis-1001.json (1001 à 1020) : le point de contrôle 1000 du réviseur n'est pas dans le fichier ; O-5 non exécutée (ancre_absente, EX-10.9), contrôle 5 non exécuté ; dossier valide. O-5 n'est pas exécutée : pas d'AV-O-3." });
  ajouter("non-execute-o6-profondeur", { entetes: "chaine-courte.json", statuts: { 5: "non_execute" }, raisons: { 5: "ancre_absente" }, description: "Le dossier complet, vérifié avec ots/entetes/chaine-courte.json (990 à 1003) : 3 confirmations pour 6 exigées ; contrôle 5 non exécuté (ancre_absente) ; dossier valide." });
  ajouter("non-execute-o7-en-attente", { preuve: "o7-en-attente", statuts: { 5: "non_execute" }, raisons: { 5: "partie_absente" }, avertissements: ["AV-O-2"], description: "preuve.ots = ots/preuves/o7-en-attente.ots : une seule attestation en attente ; contrôle 5 non exécuté (partie_absente) ; dossier valide. O-5 n'est pas exécutée : pas d'AV-O-3." });
  ajouter("valide-deux-attestations", { preuve: "deux-attestations", avertissements: ["AV-O-1", "AV-O-3"], description: "preuve.ots = ots/preuves/deux-attestations.ots : attestations à 1001 (concordante) et 1002 (discordante) ; AV-O-1." });
  ajouter("valide-attente-uri-vide", { preuve: "attente-uri-vide", avertissements: ["AV-O-3", "AV-O-2"], description: "preuve.ots = ots/preuves/attente-uri-vide.ots : à côté de la branche Bitcoin attestée à 1001, une attestation en attente d'URI vide, que la bibliothèque de référence admet (EX-10.2) ; O-1 réussie ; AV-O-2." });
  ajouter("valide-o3-branche-hors-profil", { preuve: "branche-hors-profil", avertissements: ["AV-O-2", "AV-O-3"], description: "preuve.ots = ots/preuves/branche-hors-profil.ots : une seconde branche 03 (ripemd160, hors profil) finie par une attestation Bitcoin, non exécutée ; O-3 réussie, les opérations hors profil ne changeant pas son statut (EX-10.7) ; AV-O-2." });
  for (const [r, nom, quoi, desc] of [
    ["R-1", "invalide-r1-sans-ancre", { registre: "invalide-r1-sans-ancre" }, "entrée ancre retirée de registre.json"],
    ["R-2", "invalide-r2-jeu-substitue", { registre: "invalide-r2-jeu-substitue" }, "certificats re-signés par un jeu substitué, déclaré par validateurs.json"],
    ["R-3", "invalide-r3-validateurs-declares", { registre: "invalide-r3-validateurs-declares" }, "validateurs.json déclare un autre jeu que celui qui a signé"],
    ["R-4", "invalide-r4-autre-chaine", { ancres: "ancres-autre-chaine.json" }, "chain_id noortrace-9999-test dans l'ancre"],
    ["R-5", "invalide-r5-quorum", { registre: "invalide-r5-quorum" }, "une ligne de precommit retirée du certificat de la clôture, qui portait le quorum exact"],
    ["R-6", "invalide-r6-entete-modifie", { registre: "invalide-r6-entete-modifie" }, "timestamp + 1 dans block de l'entrée cloture"],
    ["R-7", "invalide-r7-recu-falsifie", { registre: "invalide-r7-recu-falsifie" }, "topics[2] du journal de la clôture remplacé par 0x11…11"],
    ["R-8", "invalide-r8-autre-contrat", { ancres: "ancres-autre-registre.json" }, "period_registry = adresse d'AttestationRegistry dans l'ancre"],
    ["R-9", "invalide-r9-cloture-autre-periode", { registre: "invalide-r9-cloture-autre-periode" }, "entrées cloture et ancre et leurs certificats pris dans registre/periode-2/"],
    ["R-10", "invalide-r10-inscription-cle-inconnue", { registre: "invalide-r10-inscription-cle-inconnue" }, "inscription de rec-test-03, clé absente de cles.json, et certificat de son bloc ajoutés"],
  ]) {
    const source = quoi.registre ? `parties du registre de registre/variantes/${quoi.registre}/` : `le dossier complet, vérifié avec ${quoi.ancres}`;
    ajouter(nom, { ...quoi, cible: r, description: `${source} : ${desc}.` });
  }
  ajouter("invalide-n3-cle-enregistreur", { ancres: "ancres-cle-enregistreur-autre.json", cible: "N-3", description: "Le dossier complet, vérifié avec ancres-cle-enregistreur-autre.json : la clé publique de rec-test-01 dans l'ancre est celle de rec-test-02 ; N-3 échoue, contrôle 6 en échec." });
  ajouter("invalide-n4-cle-chaine", { ancres: "ancres-cle-chaine-autre.json", cible: "N-4", description: "Le dossier complet, vérifié avec ancres-cle-chaine-autre.json : la chain_key de rec-test-02 dans l'ancre est celle de rec-test-01 ; N-4 échoue, contrôle 8 en échec." });
  ajouter("valide-sans-inscription", { registre: "valide-sans-inscription", avertissements: ["AV-O-3", "AV-R-1"], description: "parties du registre de registre/variantes/valide-sans-inscription/ : inscriptions retirées ; R-10 non exécutée (partie_absente), sans effet sur le contrôle 8 ; AV-R-1." });
  ajouter("valide-ligne-non-canonique", { registre: "valide-ligne-non-canonique", avertissements: ["AV-O-3", "AV-R-2"], description: "parties du registre de registre/variantes/valide-ligne-non-canonique/ : membre « Domain » dans une ligne de precommit, accepté par le décodeur du nœud ; AV-R-2." });
  ajouter("valide-provenance-registre", { ancres: "ancres-sans-enregistreurs.json", description: "Le dossier complet, vérifié avec ancres-sans-enregistreurs.json : N-3 et N-4 ne figurent pas ; les deux clés de l'énoncé sont confirmées par les inscriptions que R-10 prouve, provenance « registre » (EX-6.8)." });
  ajouter("valide-provenance-mixte", { registre: "valide-provenance-mixte", ancres: "ancres-enregistreur-01-seul.json", description: "parties du registre de registre/variantes/valide-provenance-mixte/ (inscription de rec-test-01 retirée), vérifiées avec ancres-enregistreur-01-seul.json : rec-test-01 est confirmée par N-3 seulement, rec-test-02 par l'inscription que R-10 prouve ; l'énoncé écrit la provenance clé par clé (EX-6.8) ; N-4 ne figure pas." });
  ajouter("valide-deux-jeux-validateurs", { ancres: "ancres-deux-jeux.json", description: "Le dossier complet, vérifié avec ancres-deux-jeux.json : les blocs des inscriptions et de l'ancre relèvent du premier jeu, celui de la clôture du second ; la proposition de l'énoncé nomme les deux groupes (EX-11.22)." });
  ajouter("invalide-p1-manifeste-membre-en-trop", { manifeste: "membre-en-trop", cible: "P-1", echecs: ["P-1", "P-5"], statuts: { 3: "echoue", 4: "non_execute", 5: "non_execute", 6: "echoue", 8: "non_execute" }, raisons: { 4: "prerequis_en_echec", 5: "prerequis_en_echec", 8: "prerequis_en_echec" }, description: "manifeste.json porte un membre « extra » de plus (dossier.json réindexé) : P-1 échoue, et P-5 aussi, la forme canonique du manifeste modifié n'étant plus celle que manifeste.sig signe ; periodHash n'est pas recalculé pour les ancres ; T-2, O-2, R-9 et R-10 sont non exécutées (prerequis_en_echec), toutes les autres vérifications T-, O- et R- s'exécutent (EX-5.4) ; le contrôle 5 n'est pas réussi sans O-2 (EX-10.12)." });
  for (const [nom, desc] of [
    ["valide-decision-refusee", "décision du ticket apr-2201 refusée (decision = refuse), signée par les comptes Hardhat 1 et 2 ; l'énoncé dit « porte un refus signé par » (EX-6.8, F3)"],
    ["valide-decision-expiree", "décision du ticket apr-2201 expirée (decision = expire), sans approbateur ni signature ; l'énoncé dit « porte une demande d'approbation expirée sans signature » et facts.approval.approvers est vide (EX-6.8, F3)"],
  ]) {
    ajouter(nom, { base: nom, ancres: null, entetes: null, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: HORS_CT1, avertissements: [], description: `Dossier de la décision (seq 6) d'une variante du journal de CT-1 produite par scripts/vecteurs/ct6/decisions.mjs : ${desc}. Les cinq parties réservées sont absentes (hors périmètre CT-1) ; vérifié sans ancres.` });
  }

  // Révision 0.2 (EX-A.16) : dossiers avec la treizième partie points-de-controle.json, tous dérivés
  // de valide-seq-7-complet (index à treize parties, generated_at inchangé), point couvrant seq 7
  // (09:32:00.000Z, tree_size 8) de la série de CT-1, preuve PROOF(8, D[9]), en-têtes chaine-points.json.
  // `point` : { jeton, preuve, registre (référence au registre), modif, absent }.
  const POINT_COMPLET = { jeton: "point-periode-1", preuve: "point-periode-1", registre: true, modif: null, absent: false };
  const DEUX_AV_O3 = ["AV-O-3", "AV-O-3"];
  const avecPoint = (nom, point, autres) => ajouter(nom, { entetes: "chaine-points.json", partiesRegistre: "periode-1-point", point: { ...POINT_COMPLET, ...point }, ...autres });
  avecPoint("valide-point-de-controle-complet", {}, { avertissements: DEUX_AV_O3, description: "valide-seq-7-complet dont l'index passe à treize parties : points-de-controle.json porte le point de contrôle couvrant seq 7 (série de CT-1, 09:32:00.000Z, tree_size 8, signé par rec-test-01), la preuve de cohérence de huit feuilles vers neuf, le jeton rfc3161/jetons/point-periode-1.der, la preuve ots/preuves/point-periode-1.ots (attestation à 1004, en-têtes chaine-points.json) et la référence à l'ancre du point au registre ; parties du registre de registre/periode-1-point/ (entrée ancre_point_de_controle). K-1 à K-9 et R-11 réussies ; FK avec ses trois clauses ; facts.checkpoint complet (inclusion prouvee) ; AV-O-3 deux fois (K-9 et O-5)." });
  avecPoint("valide-point-de-controle-jeton-seul", { preuve: null, registre: false }, { partiesRegistre: "periode-1", description: "Même partie avec le seul jeton du point (registry et ots nuls), parties du registre de periode-1/ : K-8 et K-9 non exécutées (partie_absente), R-11 non exécutée (partie_absente, aucune entrée) ; FK avec la seule clause jeton ; F7 absent (les huit contrôles réussissent)." });
  avecPoint("valide-point-de-controle-sans-ancre", { jeton: null, preuve: null, registre: false }, { partiesRegistre: "periode-1", description: "Même partie avec les trois ancres nulles : K-7 à K-9 non exécutées (partie_absente) ; pas de FK ; facts.checkpoint non nul à timestamp, bitcoin et registry nuls ; énoncé égal à celui de valide-seq-7-complet." });
  avecPoint("valide-point-de-controle-declare-absent", { absent: true }, { partiesRegistre: "periode-1", description: "Treize parties déclarées, la treizième absente avec la raison « aucun point de contrôle » : aucune vérification K- au rapport, absent_parts la porte ; énoncé, statuts et borne égaux à ceux de valide-seq-7-complet (EX-6.18)." });
  avecPoint("valide-point-de-controle-sans-ancres-reviseur", {}, { ancres: null, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: { 4: "ancre_absente", 5: "ancre_absente", 8: "ancre_absente" }, avertissements: [], description: "Comme valide-point-de-controle-complet, vérifié sans fichier d'ancres (avec chaine-points.json) : K-7, K-8 et K-9 non exécutées (ancre_absente) comme les contrôles 4, 5 et 8 ; pas de FK ; les K- ne changent aucun statut (EX-5.8) ; aucun avertissement (O-5 non exécutée)." });
  avecPoint("valide-point-de-controle-reference-declarative", {}, { partiesRegistre: "periode-1", avertissements: ["AV-K-1", "AV-O-3", "AV-O-3"], description: "Comme valide-point-de-controle-complet, parties du registre de periode-1/ (sans l'entrée ancre_point_de_controle) : K-8 réussie, inclusion declarative, AV-K-1 ; R-11 non exécutée (partie_absente) ; FK sans clause registre." });
  // Choix du point couvrant (CT-5 EX-10.2, AN-51 ; CT-1 §11.2 ; CT-6 EX-13.18) : un point plus tardif
  // de la série, porteur d'un jeton construit par le générateur avec la TSA de test (rfc3161/cles).
  avecPoint("valide-point-de-controle-point-contresigne", { autre: "contresigne", jeton: null, preuve: null, registre: false }, { partiesRegistre: "periode-1", description: "Partie bâtie sur le point de 09:35:00.000Z (tree_size 8), celui que le planificateur de CT-5 contresigne à l'échéance D_7 (c_T = 300 s), porteur d'un jeton de la TSA de test sur son checkpoint_hash (genTime 09:35:02Z, numéro de série 1002) ; registry et ots nuls : le point de 09:32 de même tree_size est ancré au registre seul, et la règle d'EX-10.2 (CT-5), de CT-1 §11.2 et d'EX-13.18 (CT-6) retient le point qui porte un jeton promu. K-1 à K-7 réussies ; K-8 et K-9 non exécutées (partie_absente) ; FK avec la seule clause jeton. Le jeton est construit par le générateur et ne figure pas dans rfc3161/jetons." });
  avecPoint("valide-point-de-controle-point-de-cloture", { autre: "cloture", jeton: null, preuve: null, registre: false }, { partiesRegistre: "periode-1", description: "Partie bâtie sur le point de clôture de la période 1 (10:00:00.300Z, tree_size 9 = count), porteur d'un jeton de la TSA de test sur son checkpoint_hash (genTime 10:00:02Z, numéro de série 1003) ; preuve de cohérence de neuf feuilles vers neuf, chemin vide (CT-1 §10.7) ; K-6 non exécutée pour une raison admise (l'événement last_seq, seq 9, est hors du dossier) ; K-8 et K-9 non exécutées (partie_absente) ; FK avec la seule clause jeton. Le jeton est construit par le générateur et ne figure pas dans rfc3161/jetons." });
  avecPoint("valide-point-de-controle-ots-en-attente", { preuve: "point-periode-1-en-attente" }, { avertissements: ["AV-O-2", "AV-O-3"], description: "Comme valide-point-de-controle-complet avec ots/preuves/point-periode-1-en-attente.ots (une attestation en attente) : K-9 non exécutée (partie_absente, O-7), AV-O-2 (K-9) ; FK sans clause Bitcoin." });
  avecPoint("invalide-k1-partie-inexploitable", { modif: "k1-null" }, { partiesRegistre: "periode-1", cible: "K-1", description: "points-de-controle.json réduit au littéral JSON null (index recalculé) : K-1 échoue, K-2 à K-9 non exécutées (prerequis_en_echec, dans blocking_unexecuted), contrôle 3 en échec ; R-11 non exécutée (partie_absente) ; les contrôles 4, 5 et 8 réussissent sur le manifeste (EX-5.8)." });
  avecPoint("invalide-k1-double-defaut", { modif: "k1-double-defaut" }, { cible: "K-1", avertissements: ["AV-O-3"], description: "Partie de valide-point-de-controle-complet portant un membre « extra » hors du schéma et un chemin de cohérence tronqué (dernier nœud retiré), index recalculé : K-1 échoue sur le schéma ; K-2 à K-9 non exécutées (prerequis_en_echec, dans blocking_unexecuted), si bien que le chemin tronqué n'est pas examiné et K-5 n'est pas en échec (CT-6 EX-5.9, CT-1 §11.4) ; failed_checks = [K-1] ; contrôle 3 en échec." });
  avecPoint("invalide-k7-jeton-autre-empreinte", { jeton: "periode-1" }, { cible: "K-7", avertissements: DEUX_AV_O3, description: "Le jeton de la clôture (rfc3161/jetons/periode-1.der) embarqué comme jeton du point : T-2 du point en échec, K-7 échoue, contrôle 4 en échec ; les T- de la clôture restent réussies." });
  avecPoint("invalide-k7-jeton-signature", { jeton: "k7-point-signature" }, { cible: "K-7", avertissements: DEUX_AV_O3, description: "Jeton du point rfc3161/jetons/k7-point-signature.der (dernier octet de la signature inversé) : T-6 du point en échec, K-7 échoue, contrôle 4 en échec." });
  avecPoint("invalide-k7-base64-non-canonique", { modif: "k7-base64" }, { cible: "K-7", avertissements: DEUX_AV_O3, description: "token dont le dernier caractère utile porte des bits de bourrage non nuls (même longueur, même remplissage : le motif du schéma passe, K-1 réussie) : le décodage n'est pas canonique, K-7 échoue (jeton inexploitable, EX-4.14), contrôle 4 en échec." });
  avecPoint("invalide-k8-empreinte", { modif: "k8-empreinte" }, { cible: "K-8", avertissements: DEUX_AV_O3, description: "anchors.registry.fingerprint remplacée par 0x11…11 : K-8 échoue, contrôle 8 en échec ; R-11 réussie (l'entrée est authentique et son topics[1] égale le recalcul : seule la référence de la partie est fausse)." });
  avecPoint("invalide-k8-contrat", { modif: "k8-contrat" }, { cible: "K-8", avertissements: DEUX_AV_O3, description: "anchors.registry.contract = adresse de PeriodRegistry : K-8 échoue, contrôle 8 en échec ; R-11 réussie (l'entrée, elle, est émise par AttestationRegistry)." });
  avecPoint("invalide-k9-preuve-autre-empreinte", { preuve: "periode-1" }, { cible: "K-9", avertissements: DEUX_AV_O3, description: "La preuve de la clôture (ots/preuves/periode-1.ots) embarquée comme preuve du point : O-2 du point en échec, K-9 échoue, contrôle 5 en échec." });
  avecPoint("invalide-r11-ancre-de-periode", { registre: "ancre-de-periode" }, { partiesRegistre: "variantes/invalide-r11-ancre-de-periode", cible: "R-11", avertissements: DEUX_AV_O3, description: "Parties du registre de registre/variantes/invalide-r11-ancre-de-periode/ (entrée ancre de la période 1, bloc 16660, dupliquée sous le rôle ancre_point_de_controle) ; anchors.registry de la partie porte l'empreinte et le docType du point mais désigne ce bloc et cette transaction : R-11 échoue (règle 1 : docType de période), R-6 et R-7 réussies (bloc authentique), K-8 réussie, contrôle 8 en échec." });
  return d;
}

/** Modifications de manifeste.json des dossiers qui visent P-1 (EX-5.4). */
const MODIFICATIONS_MANIFESTE = {
  "membre-en-trop": (texte) => {
    const m = J.analyserJSONStrict(texte);
    return Buffer.from(JSON.stringify({ ...m, extra: "membre hors du schéma manifeste-v0" }, null, 2) + "\n");
  },
};

/**
 * Base64 non canonique (EX-4.14, dossier invalide-k7-base64-non-canonique) :
 * le bit de bourrage le plus bas du dernier caractère utile est mis à 1 ; même
 * longueur, même remplissage, motif du schéma respecté, décodage non canonique.
 */
function base64NonCanonique(b64) {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const remplissage = b64.length - b64.replace(/=+$/, "").length;
  exiger(remplissage === 1 || remplissage === 2, "le base64 du jeton du point doit porter un remplissage pour cette altération");
  const i = b64.length - remplissage - 1;
  const v = ALPHABET.indexOf(b64[i]);
  const bitBourrage = remplissage === 2 ? 0b000001 : 0b000001;
  exiger((v & bitBourrage) === 0, "bit de bourrage déjà non nul");
  const altere = b64.slice(0, i) + ALPHABET[v | bitBourrage] + b64.slice(i + 1);
  exiger(Buffer.from(altere, "base64").toString("base64") !== altere && Buffer.from(altere, "base64").equals(Buffer.from(b64, "base64")), "altération base64 sans effet");
  return altere;
}

/**
 * Fichiers d'un dossier : les sept parties de valide-seq-7 inchangées (sauf
 * manifeste.json modifié), les cinq parties réservées, dossier.json recalculé ;
 * ou les fichiers d'un dossier de décision. `contextePoint` (révision 0.2) :
 * { point, feuilles, referenceRegistre, referenceAncreDePeriode } pour la
 * treizième partie des dossiers qui la déclarent (EX-A.16).
 */
function fichiersDossier(base, { base: origine, jeton, preuve, partiesRegistre, manifeste, point }, racine, decisions, contextePoint) {
  if (origine !== "complet") return decisions[origine];
  const fichiers = { ...base };
  delete fichiers["dossier.json"];
  if (manifeste) fichiers["manifeste.json"] = MODIFICATIONS_MANIFESTE[manifeste](fichiers["manifeste.json"]);
  fichiers["jeton-rfc3161.der"] = fs.readFileSync(path.join(racine, "rfc3161", "jetons", `${jeton}.der`));
  fichiers["preuve.ots"] = fs.readFileSync(path.join(racine, "ots", "preuves", `${preuve}.ots`));
  for (const f of ["registre.json", "certificat-commit.json", "validateurs.json"]) fichiers[f] = fs.readFileSync(path.join(racine, "registre", partiesRegistre, f));
  if (point && point.absent) {
    // Treize parties déclarées, la treizième absente avec sa raison (CT-1 §11.1).
    const ancien = J.analyserJSONStrict(base["dossier.json"]);
    const evenement = J.analyserJSONStrict(fichiers["evenement.json"]);
    const index = J.indexDossier({ evenement, generated_at: ancien.generated_at, fichiers, raisons: { points_de_controle: J.RAISON_AUCUN_POINT } });
    return { "dossier.json": Buffer.from(texteJSON(index)), ...fichiers };
  }
  if (point && point.autre) {
    // Point plus tardif de la série (EX-10.2) : jeton construit, registry et ots nuls.
    const autre = contextePoint.autres[point.autre];
    const partie = J.construirePartiePointsDeControle({ point: autre.point, feuillesPeriode: contextePoint.feuilles, anchors: { rfc3161: autre.jeton, registry: null, ots: null } });
    fichiers[J.PARTIE_POINTS_DE_CONTROLE.file] = Buffer.from(texteJSON(partie));
  } else if (point) {
    const anchors = {
      rfc3161: point.jeton ? fs.readFileSync(path.join(racine, "rfc3161", "jetons", `${point.jeton}.der`)) : null,
      registry: point.registre === "ancre-de-periode" ? contextePoint.referenceAncreDePeriode : point.registre ? contextePoint.referenceRegistre : null,
      ots: point.preuve ? fs.readFileSync(path.join(racine, "ots", "preuves", `${point.preuve}.ots`)) : null,
    };
    const partie = J.construirePartiePointsDeControle({ point: contextePoint.point, feuillesPeriode: contextePoint.feuilles, anchors });
    if (point.modif === "k7-base64") partie.anchors.rfc3161.token = base64NonCanonique(partie.anchors.rfc3161.token);
    if (point.modif === "k8-empreinte") partie.anchors.registry = { ...partie.anchors.registry, fingerprint: "0x" + "11".repeat(32) };
    if (point.modif === "k1-double-defaut") {
      partie.extra = true;
      partie.consistency = { ...partie.consistency, path: partie.consistency.path.slice(0, -1) };
    }
    if (point.modif === "k8-contrat") partie.anchors.registry = { ...partie.anchors.registry, contract: contextePoint.adressePeriodRegistry };
    fichiers[J.PARTIE_POINTS_DE_CONTROLE.file] = point.modif === "k1-null" ? Buffer.from("null\n") : Buffer.from(texteJSON(partie));
  }
  const avecIndex = { "dossier.json": base["dossier.json"], ...fichiers };
  const { fichiers: reindexes } = J.reindexerDossier(avecIndex);
  return reindexes;
}

/**
 * Le point de contrôle couvrant seq 7 (EX-A.13) : lu dans la série de CT-1,
 * avec les feuilles de la période 1 et son checkpointHash, confronté à la
 * transaction de la capture (EX-A.15 : la série est figée avant la capture).
 */
function pointCouvrant(capture) {
  const points = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT1, "points-de-controle", "periode-1.json")));
  const point = J.choisirPointCouvrant(points, 6);
  exiger(point, "aucun point de la série de la période 1 ne couvre la feuille 6 (seq 7)");
  const checkpointHash = J.hachagePointDeControle(point);
  const t = transactionPoint(capture);
  exiger(t.checkpoint_hash === checkpointHash, `le checkpointHash du point couvrant (${checkpointHash}) n'est pas celui que la capture a ancré (${t.checkpoint_hash}) : la série de CT-1 a changé depuis la capture (EX-A.15)`);
  const evenements = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT1, "journal-valide", "evenements.json")));
  const manifeste = J.analyserJSONStrict(fs.readFileSync(path.join(DOSSIER_BASE, "manifeste.json")));
  const feuilles = evenements.filter((e) => e.seq >= manifeste.first_seq && e.seq <= manifeste.last_seq).sort((a, b) => a.seq - b.seq).map((e) => e.hash);
  exiger(J.racineMerkle(feuilles) === manifeste.root && feuilles.length === manifeste.count, "feuilles de la période 1 incohérentes avec le manifeste");
  exiger(J.racineMerkle(feuilles.slice(0, point.tree_size)) === point.root, "racine du point couvrant incohérente avec les feuilles");
  return { point, checkpointHash, checkpoint_ts: point.checkpoint_ts, feuilles, referenceRegistre: referencePoint(capture), referenceAncreDePeriode: referenceAncreDePeriodeCommePoint(capture), adressePeriodRegistry: capture.description.contrats.period_registry };
}

/**
 * Points plus tardifs de la série de la période 1 (CT-5 EX-10.2, AN-51), avec
 * un jeton de la TSA de test sur leur checkpoint_hash : le point de 09:35:00.000Z,
 * contresigné à D_7, et le point de clôture. genTime = checkpoint_ts tronqué à la
 * seconde plus 2 s (comme EX-A.13) ; numéros de série 1002 et 1003 ; nonce dérivé
 * d'une étiquette propre à chaque point.
 */
function autresPoints(contexte, materiel) {
  const points = J.analyserJSONStrict(fs.readFileSync(path.join(REPERTOIRE_CT1, "points-de-controle", "periode-1.json")));
  const genTime = (ts) => new Date(Math.floor(Date.parse(ts) / 1000) * 1000 + 2000).toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
  const nonce = (etiquette) => BigInt("0x" + crypto.createHash("sha256").update(etiquette, "utf8").digest().subarray(0, 8).toString("hex"));
  const avecJeton = (point, serie, etiquette) => {
    const h = J.hachagePointDeControle(point);
    const jeton = construireJeton({ empreinte: Buffer.from(h.slice(2), "hex"), genTime: genTime(point.checkpoint_ts), serie, nonce: nonce(etiquette), tsaNom: materiel.nomTsa, certificats: [materiel.certs["tsa-test"]], signataire: materiel.certs["tsa-test"], cle: materiel.cles["tsa-test"] });
    return { point, checkpointHash: h, jeton };
  };
  const contresigne = points.find((p) => p.checkpoint_ts === "2026-11-05T09:35:00.000Z");
  const cloture = points[points.length - 1];
  exiger(contresigne && contresigne.tree_size === contexte.point.tree_size, "le point de 09:35 de la série de la période 1 n'a pas la tree_size du point couvrant");
  exiger(cloture.tree_size === contexte.feuilles.length, "le dernier point de la série n'est pas le point de clôture");
  // Le choix d'EX-10.2 retient le point qui porte un jeton plutôt que le point de 09:32 ancré au registre seul.
  const ancres = { [contexte.checkpointHash]: { registry: true }, [J.hachagePointDeControle(contresigne)]: { rfc3161: true } };
  exiger(J.choisirPointCouvrant(points, 6, ancres) === contresigne, "EX-10.2 ne retient pas le point contresigné de 09:35");
  return {
    contresigne: avecJeton(contresigne, 1002, "noortrace/vecteurs/v0/ct-6/nonce-tsa/point-de-controle/periode-1/0935"),
    cloture: avecJeton(cloture, 1003, "noortrace/vecteurs/v0/ct-6/nonce-tsa/point-de-controle/periode-1/cloture"),
  };
}

/** Contexte du point couvrant seq 7 lu depuis la capture du dépôt (pour les tests des générateurs rfc3161 et ots, EX-A.13 et EX-A.14). */
export function contextePointDeControle() {
  return pointCouvrant(lireCapture(path.join(REPERTOIRE_CT6, "registre", "capture")));
}

/** Borne attendue (EX-6.12), construite depuis la conception : contrôles non exécutés et leur raison. */
export function borneConception(c) {
  const non = [1, 2, 3, 4, 5, 6, 7, 8].filter((n) => c.control_statuses[n] === "non_execute");
  if (!non.length) return null;
  return {
    fr: `verdict borné : ${non.map((n) => `contrôle ${n} non exécuté (${c.control_reasons[n]})`).join(", ")}`,
    en: `bounded verdict: ${non.map((n) => `control ${n} not run (${c.control_reasons[n]})`).join(", ")}`,
  };
}

/** Registre des schémas de spec/schemas employés par le vérificateur. */
export function chargerSchemas() {
  return J.registreSchemas(V.FICHIERS_SCHEMAS.map(({ fichier }) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", fichier), "utf8"))));
}

/**
 * Vérifie un dossier du répertoire `repertoire` comme la ligne de commande le
 * ferait, sans --pieces ni --second-manifeste : rend le corps du rapport.
 */
export function verifierRepertoire(repertoire, { ancres = null, entetes = null, schemas = chargerSchemas(), langue = "fr" } = {}) {
  const fichiers = {};
  for (const f of fs.readdirSync(repertoire)) if (V.FICHIERS_DOSSIER.includes(f)) fichiers[f] = fs.readFileSync(path.join(repertoire, f));
  const a = ancres ? V.controlerAncres(fs.readFileSync(ancres), schemas) : null;
  const e = entetes ? V.controlerEntetes(fs.readFileSync(entetes), schemas) : null;
  return V.verifierDossierComplet({ fichiers, schemas, ancres: a, entetes: e, langue });
}

/** Confronte les attendus posés par construction au vérificateur de référence. */
function confronter(nom, attendu, corps) {
  const obtenu = {
    failed_checks: corps.failed_checks,
    control_statuses: Object.fromEntries(corps.controls.map((c) => [String(c.number), c.status])),
    control_reasons: Object.fromEntries(corps.controls.filter((c) => c.status === "non_execute").map((c) => [String(c.number), c.reason])),
    warnings: corps.warnings.map((w) => w.id),
    exit_code: corps.exit_code,
  };
  const a = JSON.stringify(attendu);
  const o = JSON.stringify(obtenu);
  exiger(a === o, `dossier ${nom} : attendu ${a}, obtenu ${o}`);
}

// ---------------------------------------------------------------------------
// INDEX.md
// ---------------------------------------------------------------------------

function index({ rfc, ots, attenduRegistre, ancres, dossiers }) {
  const L = [];
  L.push("# Vecteurs CT-6 — vérificateur");
  L.push("");
  L.push("Produit par `scripts/vecteurs/generer-ct6.mjs` (`npm run vecteurs:ct6`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-6-verificateur.md`](../../CT-6-verificateur.md), annexe A.");
  L.push("");
  L.push("Le générateur rejoue tout à l'identique, sauf trois entrées qu'il lit et ne réécrit jamais : `registre/capture/` (capture unique du réseau de développement, procédure dans `registre/capture/CAPTURE.md`), `rfc3161/cles/*.cle.pem` (clés RSA de test, publiques, dérivées de graines publiées, pour les tests seulement) et `confrontation/` (implémentations tierces).");
  L.push("");
  L.push("Données de base : le journal `journal-sinistres` de CT-1, ses trois manifestes (`spec/vecteurs/ct-1/manifestes/periode-{1,2,3}.json`) et le dossier `spec/vecteurs/ct-1/dossiers/valide-seq-7/` (période 1). Les heures des blocs du registre sont celles de la capture (octobre 2026), antérieures aux dates fictives des manifestes (novembre 2026) : aucune vérification ne les compare (EX-A.9).");
  L.push("");
  L.push("## Vérifier un dossier");
  L.push("");
  L.push("```bash");
  L.push("node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet \\");
  L.push("  --ancres spec/vecteurs/ct-6/ancres/ancres-test.json \\");
  L.push("  --entetes-bitcoin spec/vecteurs/ct-6/ots/entetes/chaine.json            # code 0");
  L.push("node scripts/verify/dossier.mjs spec/vecteurs/ct-6/dossiers/valide-seq-7-complet --json   # sans ancres : 4, 5, 8 non exécutés");
  L.push("```");
  L.push("");
  L.push("Chaque dossier porte un `attendu.json` (EX-A.3) : `anchors` et `bitcoin_headers` donnent, relativement au répertoire du dossier, le fichier d'ancres et le fichier d'en-têtes à passer au vérificateur (`null` : option omise).");
  L.push("");
  L.push("Révision 0.2 : les dossiers `valide-point-de-controle-*`, `invalide-k*` et `invalide-r11-*` portent la treizième partie `points-de-controle.json` (CT-1 révision 0.3) bâtie sur le point de contrôle couvrant seq 7 de `spec/vecteurs/ct-1/points-de-controle/periode-1.json` (09:32:00.000Z, `tree_size` 8) ; ils se vérifient avec `ots/entetes/chaine-points.json` (EX-A.14) et, quand la référence au registre est non nulle, les parties de `registre/periode-1-point/` (EX-A.15). Exceptions : `valide-point-de-controle-point-contresigne` (point de 09:35:00.000Z, contresigné à D_7) et `valide-point-de-controle-point-de-cloture` (point de clôture, `tree_size` 9) portent un point plus tardif de la série avec un jeton construit par le générateur sur son `checkpoint_hash` (TSA de test, numéros de série 1002 et 1003, absent de `rfc3161/jetons`), `registry` et `ots` nuls : ils illustrent le choix du point couvrant d'EX-10.2 de CT-5 (AN-51), qui retient le point porteur d'un jeton plutôt que le point de 09:32, ancré au registre seul. Les cinquante dossiers antérieurs ne changent pas (EX-6.18).");
  L.push("");
  L.push("## dossiers/");
  L.push("");
  L.push("| Dossier | Ancres | En-têtes | Visée | En échec | Contrôles non exécutés | Avertissements | Code |");
  L.push("|---|---|---|---|---|---|---|---|");
  for (const x of dossiers) {
    const non = Object.entries(x.attendu.control_statuses).filter(([, s]) => s === "non_execute").map(([n]) => n);
    L.push(`| \`${x.nom}/\` | ${x.ancres ?? "aucune"} | ${x.entetes ?? "aucun"} | ${x.cible ?? "—"} | ${x.attendu.failed_checks.join(", ") || "aucune"} | ${non.join(", ") || "—"} | ${x.attendu.warnings.join(", ") || "—"} | ${x.attendu.exit_code} |`);
  }
  L.push("");
  for (const x of dossiers) {
    L.push(`- \`${x.nom}/\` : ${x.description}`);
  }
  L.push("");
  L.push("## ancres/");
  L.push("");
  L.push("| Fichier | Contenu |");
  L.push("|---|---|");
  for (const [nom, a] of Object.entries(ancres)) L.push(`| \`${nom}\` | ${a.description} |`);
  L.push("");
  L.push("## rfc3161/ (contrôle 4)");
  L.push("");
  L.push("Autorité de test et TSA de test à clés RSA 3072 publiques (`rfc3161/cles/`), CRL de test (`rfc3161/crl/`), jetons (`rfc3161/jetons/`). Attendus : `rfc3161/attendu.json`.");
  L.push("");
  L.push("| Jeton | periodHash (checkpoint_hash pour le jeton du point) | genTime | Visée | SHA-256 |");
  L.push("|---|---|---|---|---|");
  for (const t of rfc.attendu.tokens) L.push(`| \`${t.file}\` | \`${t.period_hash}\` | ${t.gen_time} | ${t.target ?? "—"} | \`${t.sha256}\` |`);
  L.push("");
  L.push("## ots/ (contrôle 5)");
  L.push("");
  L.push(`Chaîne regtest synthétique (\`ots/entetes/\`), point de contrôle ${ots.ancre.checkpoint.height} (\`${ots.ancre.checkpoint.hash}\`), profondeur minimale ${ots.ancre.min_confirmations}. Attendus : \`ots/attendu.json\`. \`chaine-points.json\` (révision 0.2) : mêmes en-têtes 990 à 1003 que \`chaine.json\`, racine 1004 égale au résultat de \`preuves/point-periode-1.ots\`, en-têtes 1004 à 1020 recalculés.`);
  L.push("");
  L.push("| Preuve | Empreinte de fichier | Visée | SHA-256 |");
  L.push("|---|---|---|---|");
  for (const p of ots.attendu.proofs) L.push(`| \`${p.file}\` | \`${p.file_digest}\` | ${p.target ?? "—"} | \`${p.sha256}\` |`);
  L.push("");
  L.push(sectionIndex(attenduRegistre).trimEnd());
  L.push("");
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Génération
// ---------------------------------------------------------------------------

/** Copie les clés RSA de test (entrée) dans une sortie neuve, pour ne pas les re-dériver. */
function copierClesSiAbsentes(racine) {
  if (path.resolve(racine) === path.resolve(REPERTOIRE_CT6)) return;
  const source = path.join(REPERTOIRE_CT6, "rfc3161", "cles");
  const cible = path.join(racine, "rfc3161", "cles");
  fs.mkdirSync(cible, { recursive: true });
  for (const f of fs.readdirSync(source).filter((x) => x.endsWith(".cle.pem"))) if (!fs.existsSync(path.join(cible, f))) fs.copyFileSync(path.join(source, f), path.join(cible, f));
}

/**
 * Génère spec/vecteurs/ct-6 (ou `racine`). La capture est lue dans
 * `racine`/registre/capture si elle existe, sinon dans celle du dépôt.
 * Rend { dossiers, ancres, fichiers } pour les tests.
 */
export function genererCt6({ racine = REPERTOIRE_CT6 } = {}) {
  fs.mkdirSync(racine, { recursive: true });
  const etrangeres = fs.readdirSync(racine).filter((e) => !CONSERVEES.has(e) && !ENTREES_GENEREES.includes(e)).sort();
  exiger(etrangeres.length === 0, `${racine} porte des entrées que le générateur n'écrit pas (${etrangeres.slice(0, 3).join(", ")}) : nommer un répertoire vide ou déjà produit par lui`);
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(racine, e), { recursive: true, force: true });
  copierClesSiAbsentes(racine);

  const repCapture = fs.existsSync(path.join(racine, "registre", "capture", "capture.json")) ? path.join(racine, "registre", "capture") : path.join(REPERTOIRE_CT6, "registre", "capture");
  const capture = lireCapture(repCapture);
  const contextePoint = pointCouvrant(capture);
  const rfc = genererRfc3161({ racine, repertoireCT1: REPERTOIRE_CT1, point: contextePoint });
  contextePoint.autres = autresPoints(contextePoint, rfc.materiel);
  const ots = genererOts({ racine, repertoireCT1: REPERTOIRE_CT1, point: contextePoint });
  genererRegistre({ sortie: path.join(racine, "registre"), capture });
  const attenduRegistre = J.analyserJSONStrict(fs.readFileSync(path.join(racine, "registre", "attendu.json")));

  // Ancres.
  const ancres = fichiersAncres({ fragments: rfc.fragments, ancreBitcoin: ots.ancre, capture });
  fs.mkdirSync(path.join(racine, "ancres"));
  for (const [nom, a] of Object.entries(ancres)) fs.writeFileSync(path.join(racine, "ancres", nom), texteJSON(a.objet));
  const schemas = chargerSchemas();
  for (const nom of Object.keys(ancres)) V.controlerAncres(fs.readFileSync(path.join(racine, "ancres", nom)), schemas);

  // Dossiers.
  const base = {};
  for (const f of fs.readdirSync(DOSSIER_BASE)) if (f !== "attendu.json") base[f] = fs.readFileSync(path.join(DOSSIER_BASE, f));
  exiger(Object.keys(base).length === 8, "le dossier valide-seq-7 de CT-1 porte dossier.json et sept parties");
  const dossiers = [];
  const decisions = dossiersDecisions({ repertoireCT1: REPERTOIRE_CT1 });
  fs.mkdirSync(path.join(racine, "dossiers"));
  for (const c of conceptionDossiers()) {
    const rep = path.join(racine, "dossiers", c.nom);
    fs.mkdirSync(rep);
    const fichiers = fichiersDossier(base, c, racine, decisions, contextePoint);
    for (const [f, contenu] of Object.entries(fichiers)) fs.writeFileSync(path.join(rep, f), contenu);
    const cheminAncres = c.ancres ? path.join(racine, "ancres", c.ancres) : null;
    const cheminEntetes = c.entetes ? path.join(racine, "ots", "entetes", c.entetes) : null;
    const invalide = c.failed_checks.length > 0 || Object.values(c.control_reasons).includes("prerequis_en_echec");
    const attenduConstruction = { failed_checks: c.failed_checks, control_statuses: c.control_statuses, control_reasons: Object.fromEntries(Object.entries(c.control_reasons).map(([n, r]) => [String(n), r])), warnings: c.warnings, exit_code: invalide ? 1 : 0 };
    const corps = verifierRepertoire(rep, { ancres: cheminAncres, entetes: cheminEntetes, schemas });
    confronter(c.nom, attenduConstruction, corps);
    const corpsEn = verifierRepertoire(rep, { ancres: cheminAncres, entetes: cheminEntetes, schemas, langue: "en" });
    exiger(JSON.stringify(corpsEn.statement) === JSON.stringify(corps.statement), `dossier ${c.nom} : l'énoncé dépend de --langue`);
    // La borne est posée par la conception (EX-6.12) et confrontée au vérificateur.
    const borne = borneConception(c);
    exiger(JSON.stringify(borne) === JSON.stringify(corps.bound === null ? null : { fr: corps.bound, en: corpsEn.bound }), `dossier ${c.nom} : borne attendue ${JSON.stringify(borne)}, obtenue ${JSON.stringify([corps.bound, corpsEn.bound])}`);
    const attendu = {
      valid: !invalide,
      target: c.cible,
      failed_checks: c.failed_checks,
      control_statuses: c.control_statuses,
      not_executed: corps.checks.filter((x) => x.status === "non_execute").map((x) => ({ id: x.id, reason: x.reason })),
      warnings: c.warnings,
      anchors: c.ancres ? `../../ancres/${c.ancres}` : null,
      bitcoin_headers: c.entetes ? `../../ots/entetes/${c.entetes}` : null,
      exit_code: attenduConstruction.exit_code,
      statement: corps.statement,
      bound: borne,
      description: c.description,
    };
    fs.writeFileSync(path.join(rep, "attendu.json"), texteJSON(attendu));
    dossiers.push({ ...c, attendu });
  }

  fs.writeFileSync(path.join(racine, "INDEX.md"), index({ rfc, ots, attenduRegistre, ancres, dossiers }));
  return { dossiers, ancres };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && (!process.argv[i + 1] || process.argv[i + 1].startsWith("--"))) {
    process.stderr.write("generer-ct6 : --sortie attend un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT6;
  const r = genererCt6({ racine });
  process.stdout.write(`ct-6 : ${Object.keys(r.ancres).length} fichiers d'ancres, ${r.dossiers.length} dossiers vérifiés sous ${racine}\n`);
}
