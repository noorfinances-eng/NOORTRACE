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
//              attendu.json (EX-A.3) ;
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
import { genererRfc3161 } from "./ct6/rfc3161.mjs";
import { genererOts } from "./ct6/ots.mjs";
import { ancreRegistre, ancresEnregistreurs, appliquerModifications, genererRegistre, lireCapture, modificationsAncres, sectionIndex } from "./ct6/registre.mjs";

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
const CONTROLE_DE = (id) => ({ T: 4, O: 5, R: 8, P: 3 })[id[0]] ?? (id === "N-3" ? 6 : 8);
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
  const ajouter = (nom, { base = "complet", jeton = "periode-1", preuve = "periode-1", registre = null, manifeste = null, ancres = "ancres-test.json", entetes = "chaine.json", cible = null, echecs = null, statuts = {}, raisons = {}, avertissements = ["AV-O-3"], description }) => {
    const control_statuses = { ...TOUS_REUSSIS, ...statuts };
    if (cible && !statuts[CONTROLE_DE(cible)]) control_statuses[CONTROLE_DE(cible)] = "echoue";
    for (const n of Object.keys(raisons)) if (control_statuses[n] !== "non_execute") throw new Error(`conception ${nom} : raison pour le contrôle ${n}, qui n'est pas non exécuté`);
    for (const [n, st] of Object.entries(control_statuses)) if (st === "non_execute" && !raisons[n]) throw new Error(`conception ${nom} : contrôle ${n} non exécuté sans raison posée`);
    d.push({ nom, base, jeton, preuve, registre, manifeste, ancres, entetes, cible, failed_checks: echecs ?? (cible ? [cible] : []), control_statuses, control_reasons: raisons, warnings: avertissements, description });
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
 * Fichiers d'un dossier : les sept parties de valide-seq-7 inchangées (sauf
 * manifeste.json modifié), les cinq parties réservées, dossier.json recalculé ;
 * ou les fichiers d'un dossier de décision.
 */
function fichiersDossier(base, { base: origine, jeton, preuve, registre, manifeste }, racine, decisions) {
  if (origine !== "complet") return decisions[origine];
  const partiesRegistre = registre ? path.join(racine, "registre", "variantes", registre) : path.join(racine, "registre", "periode-1");
  const fichiers = { ...base };
  delete fichiers["dossier.json"];
  if (manifeste) fichiers["manifeste.json"] = MODIFICATIONS_MANIFESTE[manifeste](fichiers["manifeste.json"]);
  fichiers["jeton-rfc3161.der"] = fs.readFileSync(path.join(racine, "rfc3161", "jetons", `${jeton}.der`));
  fichiers["preuve.ots"] = fs.readFileSync(path.join(racine, "ots", "preuves", `${preuve}.ots`));
  for (const f of ["registre.json", "certificat-commit.json", "validateurs.json"]) fichiers[f] = fs.readFileSync(path.join(partiesRegistre, f));
  const avecIndex = { "dossier.json": base["dossier.json"], ...fichiers };
  const { fichiers: reindexes } = J.reindexerDossier(avecIndex);
  return reindexes;
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
  L.push("| Jeton | periodHash | genTime | Visée | SHA-256 |");
  L.push("|---|---|---|---|---|");
  for (const t of rfc.attendu.tokens) L.push(`| \`${t.file}\` | \`${t.period_hash}\` | ${t.gen_time} | ${t.target ?? "—"} | \`${t.sha256}\` |`);
  L.push("");
  L.push("## ots/ (contrôle 5)");
  L.push("");
  L.push(`Chaîne regtest synthétique (\`ots/entetes/\`), point de contrôle ${ots.ancre.checkpoint.height} (\`${ots.ancre.checkpoint.hash}\`), profondeur minimale ${ots.ancre.min_confirmations}. Attendus : \`ots/attendu.json\`.`);
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

  const rfc = genererRfc3161({ racine, repertoireCT1: REPERTOIRE_CT1 });
  const ots = genererOts({ racine, repertoireCT1: REPERTOIRE_CT1 });
  const repCapture = fs.existsSync(path.join(racine, "registre", "capture", "capture.json")) ? path.join(racine, "registre", "capture") : path.join(REPERTOIRE_CT6, "registre", "capture");
  const capture = lireCapture(repCapture);
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
    const fichiers = fichiersDossier(base, c, racine, decisions);
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
