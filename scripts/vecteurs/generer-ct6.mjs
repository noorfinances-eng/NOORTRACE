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
//              révision 0.3 : les dossiers qui portent la quatorzième partie
//              attestation-perimetre.json (EX-A.18 ; CT-7 annexe A.7),
//              construite par scripts/lib/securite.mjs ;
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
import { fileURLToPath } from "node:url";
import * as J from "../lib/journal.mjs";
import * as V from "../lib/verificateur.mjs";
import * as S from "../lib/securite.mjs";
import * as A from "./ct7/attestation.mjs";
import { dossiersDecisions } from "./ct6/decisions.mjs";
import crypto from "node:crypto";
import { construireJeton, genererRfc3161 } from "./ct6/rfc3161.mjs";
import { genererOts } from "./ct6/ots.mjs";
import * as OTS from "../lib/ots.mjs";
import { ancreRegistre, ancresEnregistreurs, appliquerModifications, genererRegistre, jeuReseau, jeuSubstitue, lireCapture, modificationsAncres, octetsParties, partiesPrecommitType, partiesPropositionMembreMalType, referenceAncreDePeriodeCommePoint, referencePoint, sectionIndex, transactionPoint } from "./ct6/registre.mjs";

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
    "ancres-tsa-revoquee-serie-non-minimale.json": { objet: base("Ancres de test CT-6 (ancres-tsa-revoquee-serie-non-minimale.json)", fragments.tsa_revoquee_serie_non_minimale), description: "revue de sécurité de l'étape 8 : idem ancres-tsa-revoquee.json, la CRL crl-tsa-revoquee-serie-non-minimale.pem encodant le numéro de série révoqué sur deux octets (02 02 00 02, INTEGER non minimal, EX-9.6) : le fichier d'ancres est utilisable (N-1), la CRL est lue et T-10 échoue" },
    "ancres-crl-extension-critique-inconnue.json": { objet: base("Ancres de test CT-6 (ancres-crl-extension-critique-inconnue.json)", fragments.crl_extension_critique_inconnue), description: "révision 0.9 de CT-6 (EX-9.16) : idem ancres-test.json, la CRL crl-extension-critique-inconnue.pem (complète, bien signée) portant sur la liste une extension critique d'OID 1.3.6.1.4.1.99999.2 que la version 0 ne lit pas : écartée, AV-T-3, T-10 non exécutée (ancre_absente)" },
    "ancres-crl-entree-extension-critique-inconnue.json": { objet: base("Ancres de test CT-6 (ancres-crl-entree-extension-critique-inconnue.json)", fragments.crl_entree_extension_critique_inconnue), description: "révision 0.9 de CT-6 (EX-9.16) : idem ancres-test.json, la CRL crl-entree-extension-critique-inconnue.pem dont l'entrée du numéro de série 99 (un autre certificat) porte une extension critique d'OID 1.3.6.1.4.1.99999.2 que la version 0 ne lit pas : écartée, AV-T-3, T-10 non exécutée (ancre_absente)" },
    "ancres-cle-non-ancree.json": { objet: variante("ancres-cle-non-ancree.json", [{ pointer: "/recorders/1/key_id", value: "rec-test-99" }]), description: "révision 0.9 de CT-6 (EX-12.4) : idem ancres-test.json, la ligne recorders de rec-test-02 (clé du manifeste) renommée rec-test-99 : la clé employée par le verdict n'a pas d'ancre dans recorders, N-3 non exécutée (ancre_absente) et le contrôle 6 avec elle ; N-4 non exécutée (ancre_absente)" },
    "ancres-autre-chaine.json": { objet: variante("ancres-autre-chaine.json", mods["ancres-autre-chaine.json"]), description: "idem, registry.chain_id = noortrace-9999-test" },
    "ancres-autre-registre.json": { objet: variante("ancres-autre-registre.json", mods["ancres-autre-registre.json"]), description: "idem, period_registry = adresse d'AttestationRegistry" },
    "ancres-cle-enregistreur-autre.json": { objet: variante("ancres-cle-enregistreur-autre.json", [{ pointer: "/recorders/0/public_key", value: test.recorders[1].public_key }]), description: "idem, public_key de rec-test-01 remplacée par celle de rec-test-02" },
    "ancres-cle-chaine-autre.json": { objet: variante("ancres-cle-chaine-autre.json", mods["ancres-cle-chaine-autre.json"]), description: "idem, chain_key de rec-test-02 remplacée par celle de rec-test-01" },
    "ancres-sans-enregistreurs.json": { objet: variante("ancres-sans-enregistreurs.json", mods["ancres-sans-enregistreurs.json"]), description: "idem, recorders vide : aucune clé d'enregistreur ne vient du fichier d'ancres (N-3 et N-4 absentes) ; les clés sont confirmées par les inscriptions que R-10 prouve" },
    "ancres-enregistreur-01-seul.json": { objet: variante("ancres-enregistreur-01-seul.json", mods["ancres-enregistreur-01-seul.json"]), description: "idem, recorders réduit à rec-test-01 (provenance mixte des clés, EX-6.8 ; N-4 absente)" },
    "ancres-deux-jeux.json": { objet: variante("ancres-deux-jeux.json", mods["ancres-deux-jeux.json"]), description: "idem, registry.validator_sets coupé en deux jeux de mêmes clés, l'un jusqu'au bloc de l'ancre de la période 1, l'autre au-delà (EX-11.22)" },
    "ancres-unite-epinglee-revoquee.json": { objet: base("Ancres de test CT-6 (ancres-unite-epinglee-revoquee.json)", fragments.unite_epinglee_revoquee), description: "idem, autorité = l'unité tsa-test.pem elle-même (« Unité TSA épinglée de test CT-6 ») et crl-tsa-revoquee.pem, qui la révoque pour keyCompromise : T-10 échoue (EX-9.16)" },
    "ancres-deux-autorites.json": { objet: base("Ancres de test CT-6 (ancres-deux-autorites.json)", fragments.deux_autorites), description: "idem, deux autorités : l'unité tsa-test.pem épinglée (qualified eidas déclaré), puis ac-test.pem ; crl-vide.pem. T-7 retient la première (EX-9.13)" },
    // Révision 0.4 (EX-A.22, EX-A.23).
    "ancres-unite-intermediaire.json": { objet: base("Ancres de test CT-6 (ancres-unite-intermediaire.json)", fragments.unite_intermediaire), description: "révision 0.4 (EX-A.22) : ancres-test.json dont l'autorité ac-test.pem porte tsa-test.pem dans intermediates : un jeton sans certificats y trouve le certificat de l'unité (T-4)" },
    "ancres-jeu-substitue.json": { objet: variante("ancres-jeu-substitue.json", [{ pointer: "/registry/validator_sets", value: [{ ...jeuReseau(capture, jeuSubstitue()), source: "jeu substitué des vecteurs CT-6 (graines publiées), déclaré par le réviseur pour les dossiers *-precommit-type-*" }] }]), description: "révision 0.4 (EX-A.23) : ancres-test.json dont registry.validator_sets déclare le jeu substitué v1 à v4 (clés de graines publiées, registre/variantes/invalide-r2-jeu-substitue/)" },
  };
  return out;
}

// ---------------------------------------------------------------------------
// Dossiers (EX-A.11)
// ---------------------------------------------------------------------------

const TOUS_REUSSIS = { 1: "reussi", 2: "reussi", 3: "reussi", 4: "reussi", 5: "reussi", 6: "reussi", 7: "reussi", 8: "reussi" };
/** Contrôle servi par les vérifications K- (CT-6 EX-5.7). */
const CONTROLE_K = { "K-1": 3, "K-2": 3, "K-3": 6, "K-4": 3, "K-5": 3, "K-6": 2, "K-7": 4, "K-8": 8, "K-9": 5 };
/** Contrôle principal servi par une vérification de CT-1 (table 5.1 de CT-6), pour les cibles des dossiers de la revue de l'étape 8. */
const CONTROLE_CT1 = { "E-1": 1, "E-2": 1, "E-3": 1, "E-4": 1, "E-6": 1, "E-7": 1, "E-5": 7, "E-9": 7, "A-1": 7, "A-2": 7, "A-3": 7, "A-4": 7, "E-8": 6, "E-10": 6, "E-11": 6, "C-3": 6, "C-1": 2, "C-2": 2, "M-1": 3, "M-2": 3, "M-3": 3, "P-2": 3, "P-4": 3, "P-5": 3 };
const CONTROLE_DE = (id) => CONTROLE_K[id] ?? CONTROLE_CT1[id] ?? ({ T: 4, O: 5, R: 8, P: 3 })[id[0]] ?? (id === "N-3" ? 6 : 8);
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
  const ajouter = (nom, { base = "complet", jeton = "periode-1", preuve = "periode-1", registre = null, partiesRegistre = null, manifeste = null, point = null, attestation = null, evenement = null, precommitType = null, absentes = null, mutation = null, indexTexte = null, exiger4 = false, ancres = "ancres-test.json", entetes = "chaine.json", cible = null, echecs = null, statuts = {}, raisons = {}, avertissements = ["AV-O-3"], description }) => {
    const control_statuses = { ...TOUS_REUSSIS, ...statuts };
    if (cible && !statuts[CONTROLE_DE(cible)]) control_statuses[CONTROLE_DE(cible)] = "echoue";
    for (const n of Object.keys(raisons)) if (control_statuses[n] !== "non_execute") throw new Error(`conception ${nom} : raison pour le contrôle ${n}, qui n'est pas non exécuté`);
    for (const [n, st] of Object.entries(control_statuses)) if (st === "non_execute" && !raisons[n]) throw new Error(`conception ${nom} : contrôle ${n} non exécuté sans raison posée`);
    d.push({ nom, base, jeton, preuve, registre, partiesRegistre: partiesRegistre ?? (registre ? `variantes/${registre}` : "periode-1"), manifeste, point, attestation, evenement, precommitType, absentes, mutation, indexTexte, exiger4, ancres, entetes, cible, failed_checks: echecs ?? (cible ? [cible] : []), control_statuses, control_reasons: raisons, warnings: avertissements, description });
  };
  /** Récrit le texte d'une partie (une occurrence exacte de `ancien`). */
  const recrire = (fichier, ancien, nouveau) => (fichiers) => {
    const texte = Buffer.from(fichiers[fichier]).toString("utf8");
    exiger(texte.split(ancien).length === 2, `« ${ancien.slice(0, 40)} » doit figurer une fois dans ${fichier}`);
    fichiers[fichier] = Buffer.from(texte.replace(ancien, nouveau));
  };
  /** Première ligne de precommit du premier certificat de certificat-commit.json récrite par `f(ligne)`. */
  const ligneCertificat = (f) => (fichiers) => {
    const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]);
    cc.certificates[0].precommits[0].line = f(cc.certificates[0].precommits[0].line);
    fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc, null, 2) + "\n");
  };
  ajouter("valide-seq-7-complet", { description: "Dossier valide-seq-7 de CT-1, ses sept parties inchangées, complété du jeton de la période 1 (rfc3161/jetons/periode-1.der), de sa preuve OpenTimestamps (ots/preuves/periode-1.ots) et des trois parties du registre de la période 1 (registre/periode-1/ : inscriptions de rec-test-01 et rec-test-02, ancre et clôture). Les huit contrôles réussissent ; T-11 n'est pas exécutée (aucun statut qualifié déclaré), l'énoncé ne dit pas « qualifié »." });
  ajouter("valide-seq-7-complet-sans-ancres", { ancres: null, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: { 4: "ancre_absente", 5: "ancre_absente", 8: "ancre_absente" }, avertissements: [], description: "Le même dossier, vérifié sans fichier d'ancres (avec chaine.json) : les contrôles 4, 5 et 8 ne sont pas exécutés (ancre_absente) ; N-3 et N-4 ne figurent pas au rapport ; pas d'AV-O-3 (il exige O-5 exécutée) ; complément du 2026-11-19 : AV-N-1 (clés d'essai rec-test-01 et rec-test-02) et AV-N-2 (deux approbateurs d'essai), les contrôles 6 et 7 réussissant avec des pièces d'essai (CT-6 EX-6.24)." });
  ajouter("valide-seq-7-complet-sans-entetes", { entetes: null, statuts: { 5: "non_execute" }, raisons: { 5: "partie_absente" }, avertissements: [], description: "Le même dossier, vérifié avec ancres-test.json et sans fichier d'en-têtes : contrôle 5 non exécuté (partie_absente, EX-4.5)." });
  ajouter("valide-t11-qualification-declaree", { ancres: "ancres-qualification-declaree.json", description: "Le même dossier, vérifié avec ancres-qualification-declaree.json : T-11 réussie ; l'énoncé dit « horodatage qualifié eIDAS selon le réviseur (déclaration de test, sans valeur) »." });
  ajouter("valide-t7-deux-autorites", { ancres: "ancres-deux-autorites.json", description: "Le même dossier, vérifié avec ancres-deux-autorites.json (l'unité tsa-test.pem épinglée, statut qualifié déclaré, puis ac-test.pem) : T-7 retient la première autorité du fichier pour laquelle un chemin existe, par l'identité (EX-9.13) ; T-10 n'a rien à prouver ; T-11 réussie ; l'énoncé nomme « Unité TSA épinglée de test CT-6 »." });
  ajouter("valide-unite-sans-cn", { jeton: "periode-1-unite-sans-cn", description: "jeton-rfc3161.der = rfc3161/jetons/periode-1-unite-sans-cn.der : le sujet de l'unité tsa-sans-cn.pem n'a pas de commonName ; tsu_subject_cn est nul, et l'énoncé nomme l'unité par le SHA-256 de son certificat (EX-9.19, EX-9.20)." });
  for (const [t, jeton, desc] of [
    ["T-1", "t1-octet-en-trop", "un octet 00 après le ContentInfo"],
    ["T-1", "t1-default-explicite", "certificat de l'unité dont une extension encode critical à FALSE, valeur DEFAULT (EX-9.21)"],
    ["T-1", "t1-cn-utf8-invalide", "certificat de l'unité dont le CN est une UTF8String d'octets ff fe, UTF-8 invalide (EX-9.4)"],
    // Révision 0.9 (EX-9.4) : formes DER hors de la signature, refusées par les trois implémentations.
    ["T-1", "t1-null-longueur", "NULL de longueur 1 (05 01 00) dans le champ crls [1], que la signature ne couvre pas : le profil DER d'EX-9.4 s'applique à tout le jeton (révision 0.9)"],
    ["T-1", "t1-integer-vide", "INTEGER vide (02 00) dans le champ crls [1] (EX-9.4, révision 0.9)"],
    ["T-1", "t1-bit-string-vide", "BIT STRING vide (03 00), sans octet des bits inutilisés, dans le champ crls [1] (EX-9.4, révision 0.9)"],
    ["T-1", "t1-octet-string-construite", "OCTET STRING de forme construite (24 02 04 00) dans le champ crls [1] : tout type universel autre que SEQUENCE et SET est primitif (EX-9.4, révision 0.9)"],
    ["T-1", "t1-etiquette-0", "étiquette universelle 0 (00 00) dans le champ crls [1] (EX-9.4, révision 0.9)"],
    ["T-1", "t1-unsigned-null-longueur", "NULL de longueur 1 (05 01 00) dans un attribut du champ unsignedAttrs [1] du SignerInfo (EX-9.4, révision 0.9)"],
    ["T-1", "t1-tstinfo-integer-vide", "accuracy.seconds codé en INTEGER vide (02 00) dans le TSTInfo encapsulé (EX-9.4, révision 0.9 : le profil s'applique au TSTInfo)"],
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
  ajouter("valide-integer-non-minimal", { jeton: "integer-non-minimal", description: "jeton-rfc3161.der = rfc3161/jetons/integer-non-minimal.der : SignedData.version codée 02 02 00 03 (INTEGER non minimal, hors de la signature) : lu, accepté (EX-9.6) ; témoin des six dossiers invalide-t1-* de la révision 0.9, qui refusent les formes que X.690 interdit, non la forme non minimale d'un INTEGER." });
  ajouter("invalide-t10-tsa-revoquee", { ancres: "ancres-tsa-revoquee.json", cible: "T-10", description: "Le dossier complet, vérifié avec ancres-tsa-revoquee.json : le certificat de la TSA est révoqué pour keyCompromise ; T-10 échoue." });
  // Révision 0.9 (EX-9.16) : CRL à extension critique non lue, sur la liste ou sur une entrée.
  ajouter("non-execute-t10-crl-extension-critique-inconnue", { ancres: "ancres-crl-extension-critique-inconnue.json", statuts: { 4: "non_execute" }, raisons: { 4: "ancre_absente" }, avertissements: ["AV-T-3", "AV-O-3"], description: "Le dossier complet, vérifié avec ancres-crl-extension-critique-inconnue.json : la seule CRL du fichier porte sur la liste une extension critique d'OID 1.3.6.1.4.1.99999.2 que la version 0 ne lit pas (RFC 5280 §5.2) ; elle n'est pas une preuve de non-révocation : écartée (AV-T-3), T-10 non exécutée (ancre_absente), contrôle 4 non exécuté, code 0 (3 avec --exiger 4) ; dossier valide." });
  ajouter("non-execute-t10-crl-entree-extension-critique-inconnue", { ancres: "ancres-crl-entree-extension-critique-inconnue.json", statuts: { 4: "non_execute" }, raisons: { 4: "ancre_absente" }, avertissements: ["AV-T-3", "AV-O-3"], description: "Le dossier complet, vérifié avec ancres-crl-entree-extension-critique-inconnue.json : l'entrée du numéro de série 99 de la CRL porte une extension critique d'OID 1.3.6.1.4.1.99999.2 que la version 0 ne lit pas (RFC 5280 §5.3) ; la CRL est écartée (AV-T-3), T-10 non exécutée (ancre_absente), contrôle 4 non exécuté, code 0 ; dossier valide." });
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
  ajouter("non-execute-n3-cle-non-ancree", { ancres: "ancres-cle-non-ancree.json", statuts: { 6: "non_execute" }, raisons: { 6: "ancre_absente" }, description: "Le dossier complet, vérifié avec ancres-cle-non-ancree.json : recorders porte le journal sous rec-test-01 et rec-test-99, non sous rec-test-02, clé du manifeste : N-3 est non exécutée (ancre_absente, le détail nommant rec-test-02) et le contrôle 6 avec elle, code 0 et code 3 avec --exiger 6 (EX-12.4, révision 0.9 : la version 0.8 laissait le contrôle 6 réussi dès qu'une clé signataire était comparée) ; N-4 non exécutée (ancre_absente) sans effet sur le contrôle 8 ; rec-test-01 n'a pas la provenance « ancres » (N-3 non réussie), les deux clés sont inscrites au registre." });
  ajouter("invalide-r1-hauteur-0", { mutation: (fichiers) => { const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]); cc.certificates[0].height = "0x0"; fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc, null, 2) + "\n"); }, cible: "R-1", description: "valide-seq-7-complet dont le premier certificat de certificat-commit.json porte height 0x0 (SHA-256 de l'index reporté) : la genèse n'est jamais décidée par le BFT, R-1 échoue (premier écart : « certificat 0 de hauteur 0 », puis l'appariement), R-2 à R-10 non exécutées (prerequis_en_echec), code 1 (EX-11.14, révision 0.9 : la référence le refusait en R-5 par la structure, le binaire l'admettait)." });
  ajouter("invalide-n4-cle-chaine", { ancres: "ancres-cle-chaine-autre.json", cible: "N-4", description: "Le dossier complet, vérifié avec ancres-cle-chaine-autre.json : la chain_key de rec-test-02 dans l'ancre est celle de rec-test-01 ; N-4 échoue, contrôle 8 en échec." });
  ajouter("valide-sans-inscription", { registre: "valide-sans-inscription", avertissements: ["AV-O-3", "AV-R-1"], description: "parties du registre de registre/variantes/valide-sans-inscription/ : inscriptions retirées ; R-10 non exécutée (partie_absente), sans effet sur le contrôle 8 ; AV-R-1." });
  ajouter("invalide-p1-sans-inscription", { registre: "valide-sans-inscription", manifeste: "membre-en-trop", cible: "P-1", echecs: ["P-1", "P-5"], statuts: { 3: "echoue", 4: "non_execute", 5: "non_execute", 6: "echoue", 8: "non_execute" }, raisons: { 4: "prerequis_en_echec", 5: "prerequis_en_echec", 8: "prerequis_en_echec" }, description: "parties du registre de registre/variantes/valide-sans-inscription/ (inscriptions retirées) et manifeste.json à membre hors du schéma, comme invalide-p1-manifeste-membre-en-trop (P-1 et P-5 en échec, dossier.json réindexé) : R-10 est non exécutée avec la raison admise partie_absente, l'absence d'entrée inscription étant jugée avant les prérequis (EX-11.19, révision 0.9 : le binaire rendait prerequis_en_echec, qui comptait dans blocking_unexecuted) ; R-9 non exécutée (prerequis_en_echec) rend le contrôle 8 non exécuté ; contrôles 3 et 6 en échec, 4 et 5 non exécutés, code 1 ; AV-R-1 n'est pas levé (clé du manifeste non établie)." });
  ajouter("valide-ligne-non-canonique", { registre: "valide-ligne-non-canonique", avertissements: ["AV-O-3", "AV-R-2"], description: "parties du registre de registre/variantes/valide-ligne-non-canonique/ : membre « Domain » dans une ligne de precommit, accepté par le décodeur du nœud ; AV-R-2." });
  ajouter("valide-provenance-registre", { ancres: "ancres-sans-enregistreurs.json", description: "Le dossier complet, vérifié avec ancres-sans-enregistreurs.json : N-3 et N-4 ne figurent pas ; les deux clés de l'énoncé sont confirmées par les inscriptions que R-10 prouve, provenance « registre » (EX-6.8)." });
  // Révision 0.9 (EX-12.4) : recorders ne porte pas rec-test-02, clé du manifeste, employée par le verdict : N-3 non exécutée (ancre_absente) et le
  // contrôle 6 avec elle ; rec-test-01, comparée et égale, n'a plus la provenance « ancres » (N-3 non réussie) : « déclarée par le dossier »,
  // rec-test-02 « inscrite au registre ». La table d'A.11 et l'exemple d'EX-6.8 (« rec-test-01 confirmée par N-3 ») sont à réviser avec ce vecteur.
  ajouter("valide-provenance-mixte", { registre: "valide-provenance-mixte", ancres: "ancres-enregistreur-01-seul.json", statuts: { 6: "non_execute" }, raisons: { 6: "ancre_absente" }, description: "parties du registre de registre/variantes/valide-provenance-mixte/ (inscription de rec-test-01 retirée), vérifiées avec ancres-enregistreur-01-seul.json : recorders ne porte pas rec-test-02, clé du manifeste, employée par le verdict ; N-3 est non exécutée (ancre_absente) et le contrôle 6 avec elle (EX-12.4, révision 0.9) ; rec-test-02 est confirmée par l'inscription que R-10 prouve, rec-test-01 reste « déclarée par le dossier » (son inscription est retirée et N-3 n'a pas réussi) ; l'énoncé écrit la provenance clé par clé (EX-6.8), mixte ; N-4 ne figure pas ; code 0." });
  ajouter("valide-deux-jeux-validateurs", { ancres: "ancres-deux-jeux.json", description: "Le dossier complet, vérifié avec ancres-deux-jeux.json : les blocs des inscriptions et de l'ancre relèvent du premier jeu, celui de la clôture du second ; la proposition de l'énoncé nomme les deux groupes (EX-11.22)." });
  ajouter("invalide-p1-manifeste-membre-en-trop", { manifeste: "membre-en-trop", cible: "P-1", echecs: ["P-1", "P-5"], statuts: { 3: "echoue", 4: "non_execute", 5: "non_execute", 6: "echoue", 8: "non_execute" }, raisons: { 4: "prerequis_en_echec", 5: "prerequis_en_echec", 8: "prerequis_en_echec" }, description: "manifeste.json porte un membre « extra » de plus (dossier.json réindexé) : P-1 échoue, et P-5 aussi, la forme canonique du manifeste modifié n'étant plus celle que manifeste.sig signe ; periodHash n'est pas recalculé pour les ancres ; T-2, O-2, R-9 et R-10 sont non exécutées (prerequis_en_echec), toutes les autres vérifications T-, O- et R- s'exécutent (EX-5.4) ; le contrôle 5 n'est pas réussi sans O-2 (EX-10.12)." });
  for (const [nom, desc] of [
    ["valide-decision-refusee", "décision du ticket apr-2201 refusée (decision = refuse), signée par les comptes Hardhat 1 et 2 ; l'énoncé dit « porte le refus de la demande » (EX-6.8, F3)"],
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
  avecPoint("invalide-r7-r11-non-executee", {}, { cible: "R-7", mutation: (fichiers) => { const reg = J.analyserJSONStrict(fichiers["registre.json"]); const e = reg.entries[0]; const j = e.receipts[e.transaction_index].logs[e.log_index]; j.data = j.data.slice(0, 4) + (j.data[4] === "0" ? "1" : "0") + j.data.slice(5); fichiers["registre.json"] = Buffer.from(JSON.stringify(reg, null, 2) + "\n"); }, avertissements: DEUX_AV_O3, description: "valide-point-de-controle-complet dont le journal prouvé de l'entrée 0 (inscription de rec-test-01) a un chiffre de data changé (SHA-256 de l'index reporté) : R-7 échoue pour cette entrée ; R-10 non exécutée (prerequis_en_echec) ; R-11 non exécutée (prerequis_en_echec, règle 3 : R-10 non réussie pour une autre raison que l'absence d'entrée inscription), sans AV-K-3 ; K-8 réussie, inclusion déclarative sans AV-K-1 (EX-11.25 : la raison de R-11 n'est pas admise) ; contrôle 8 en échec, code 1 (EX-11.24, révision 0.9 : la référence appliquait la règle 3 sans R-10 réussie et levait AV-K-3)." });
  avecPoint("valide-point-de-controle-sans-ancres-reviseur", {}, { ancres: null, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: { 4: "ancre_absente", 5: "ancre_absente", 8: "ancre_absente" }, avertissements: [], description: "Comme valide-point-de-controle-complet, vérifié sans fichier d'ancres (avec chaine-points.json) : K-7, K-8 et K-9 non exécutées (ancre_absente) comme les contrôles 4, 5 et 8 ; pas de FK ; les K- ne changent aucun statut (EX-5.8) ; pas d'AV-O-3 (O-5 non exécutée) ; complément du 2026-11-19 : AV-N-1 (clés d'essai rec-test-01 et rec-test-02) et AV-N-2 (deux approbateurs d'essai), les contrôles 6 et 7 réussissant avec des pièces d'essai (CT-6 EX-6.24)." });
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
  // Révision 0.3 (EX-A.18, CT-7 annexe A.7) : dossiers avec la quatorzième partie attestation-perimetre.json,
  // l'attestation de CT-7 §7.1 signée par les comptes Hardhat 1 et 2, le jeu des comptes 1 à 3, sans inscription.
  // `attestation` : { mode (« exemple » ou « substituee »), checks (statuts attendus de AT-1 à AT-7), retenue }.
  const AT_SANS_INSCRIPTION = ["reussi", "reussi", "reussi", "reussi", "reussi", "partie_absente", "partie_absente"];
  ajouter("valide-seq-7-complet-attestation", { attestation: { mode: "exemple", checks: AT_SANS_INSCRIPTION, retenue: true }, description: "valide-seq-7-complet dont l'index passe à quatorze parties : la treizième déclarée absente (« aucun point de contrôle »), la quatorzième attestation-perimetre.json porte l'attestation de CT-7 §7.1 signée par les comptes Hardhat 1 et 2, le jeu des comptes 1 à 3 au seuil de 2, sans inscription. Les huit contrôles réussissent comme dans valide-seq-7-complet ; AT-1 à AT-5 réussies, AT-6 et AT-7 non exécutées (partie_absente) ; énoncé = celui de valide-seq-7-complet avec le fragment FP sans clause d'inscription inséré avant le point final ; facts.perimeter rempli, provenance declaree." });
  ajouter("valide-seq-7-complet-attestation-non-retenue", { attestation: { mode: "substituee", checks: ["reussi", "reussi", "echoue", "prerequis_en_echec", "reussi", "partie_absente", "partie_absente"], retenue: false }, avertissements: ["AV-AT-1", "AV-O-3"], description: "Même dossier, la signature du compte 3 déclarée pour le compte 2 : AT-3 échoue, AT-4 non exécutée ; mêmes statuts des huit contrôles, même verdict valide et code 0 (EX-5.11) ; FP « l'attestation de périmètre jointe n'est pas retenue (vérification(s) en échec : AT-3) » ; AV-AT-1 ; facts.perimeter nul." });
  avecPoint("valide-point-de-controle-complet-attestation", {}, { attestation: { mode: "exemple", checks: AT_SANS_INSCRIPTION, retenue: true }, avertissements: DEUX_AV_O3, description: "valide-point-de-controle-complet dont l'index passe à quatorze parties : la treizième (points-de-controle.json) inchangée, la quatorzième porte l'attestation de valide-seq-7-complet-attestation. K-1 à K-9 et R-11 réussies, AT-1 à AT-5 réussies, AT-6 et AT-7 non exécutées (partie_absente) ; l'énoncé porte FK puis FP, avant le point final." });
  ajouter("valide-seq-7-complet-attestation-cle-non-ancree", { attestation: { mode: "cle-non-ancree", checks: ["reussi", "reussi", "reussi", "reussi", "reussi", "ancre_absente", "prerequis_en_echec"], retenue: true }, description: "valide-seq-7-complet-attestation où l'exportateur ajoute à cles.json une clé rec-forge-01 (graine = SHA-256 de « noortrace/vecteurs/ct7/rec-forge-01 ») et joint une inscription forgée (seq 2, 09:10:00.000Z, signée par rec-forge-01, document de politique portant D_P sous la version de l'événement prouvé). N-3 ne compare que les clés qui signent le dossier : il réussit comme dans valide-seq-7-complet. La clé de l'inscription n'est pas celle de l'événement prouvé (rec-test-01) : AT-6 n'est pas exécutée (ancre_absente), AT-7 non plus ; l'attestation est retenue et FP dit que l'inscription jointe n'est pas signée par la clé de l'événement prouvé, sans date ni rang (CT-6 EX-6.19 ; CT-7 MN-84, MN-90)." });
  ajouter("invalide-t6-signature-attestation", { jeton: "t6-signature", cible: "T-6", attestation: { mode: "exemple", checks: AT_SANS_INSCRIPTION, retenue: true }, description: "invalide-t6-signature (jeton-rfc3161.der = rfc3161/jetons/t6-signature.der, dernier octet de la signature inversé) avec la partie de valide-seq-7-complet-attestation : T-6 échoue, verdict invalide ; l'énoncé est celui d'EX-6.9, sans FP ; l'attestation est retenue et facts.perimeter est gardé pour le diagnostic (EX-6.13, EX-6.20)." });
  avecPoint("invalide-r11-ancre-de-periode", { registre: "ancre-de-periode" }, { partiesRegistre: "variantes/invalide-r11-ancre-de-periode", cible: "R-11", avertissements: DEUX_AV_O3, description: "Parties du registre de registre/variantes/invalide-r11-ancre-de-periode/ (entrée ancre de la période 1, bloc 16660, dupliquée sous le rôle ancre_point_de_controle) ; anchors.registry de la partie porte l'empreinte et le docType du point mais désigne ce bloc et cette transaction : R-11 échoue (règle 1 : docType de période), R-6 et R-7 réussies (bloc authentique), K-8 réussie, contrôle 8 en échec." });
  // Révision 0.4 (EX-A.23) : jetons de EX-A.22 (T-4, T-5, T-7, numéro de série), precommit de Type toléré
  // ou refusé, K-8 en échec sans les parties du contrôle 8.
  const SANS_ANCRES = { ancres: null, avertissements: [] };
  ajouter("invalide-t4-sid-introuvable", { jeton: "t4-sid-introuvable", cible: "T-4", description: "jeton-rfc3161.der = rfc3161/jetons/t4-sid-introuvable.der : le sid désigne l'AC et le numéro 0x7f, que ne porte aucun certificat du jeton ni des ancres ; le jeton porte des certificats : T-4 échoue (EX-9.10, révision 0.4), T-5 à T-11 non exécutées (prerequis_en_echec), contrôle 4 en échec. En version 0.3, T-4 était non exécutée (ancre_absente) et le dossier valide, code 0." });
  ajouter("invalide-t4-sid-introuvable-sans-ancres", { jeton: "t4-sid-introuvable", cible: "T-4", ...SANS_ANCRES, statuts: { 4: "echoue", 5: "non_execute", 8: "non_execute" }, raisons: { 5: "ancre_absente", 8: "ancre_absente" }, description: "Le même jeton, vérifié sans fichier d'ancres : le jeton porte des certificats, T-4 échoue quand même (EX-9.10) ; contrôles 5 et 8 non exécutés (ancre_absente)." });
  ajouter("invalide-t4-jeton-sans-certificat", { jeton: "t4-sans-certificat", cible: "T-4", description: "jeton-rfc3161.der = rfc3161/jetons/t4-sans-certificat.der (sans champ certificates) vérifié avec ancres-test.json, dont l'autorité ne fournit pas tsa-test.pem : T-4 échoue (EX-9.10, révision 0.4)." });
  ajouter("valide-t4-jeton-sans-certificat-sans-ancres", { jeton: "t4-sans-certificat", ...SANS_ANCRES, statuts: { 4: "non_execute", 5: "non_execute", 8: "non_execute" }, raisons: { 4: "ancre_absente", 5: "ancre_absente", 8: "ancre_absente" }, description: "Le même jeton sans certificats, vérifié sans fichier d'ancres : la seule absence légitime (EX-9.10) ; T-4 à T-11 non exécutées (ancre_absente), contrôles 4, 5 et 8 non exécutés (ancre_absente), code 0, verdict borné." });
  ajouter("valide-t4-unite-en-intermediaire", { jeton: "t4-sans-certificat", ancres: "ancres-unite-intermediaire.json", description: "Le même jeton sans certificats, vérifié avec ancres-unite-intermediaire.json, dont l'autorité porte tsa-test.pem dans intermediates : T-4 trouve le certificat de l'unité parmi les ancres ; les huit contrôles réussissent." });
  ajouter("invalide-t5-rsa-8200", { jeton: "t5-rsa-8200", cible: "T-5", description: "jeton-rfc3161.der = rfc3161/jetons/t5-rsa-8200.der (unité RSA de 8200 bits) : T-5 échoue avant tout calcul (EX-9.23), T-6, T-7, T-10 et T-11 non exécutées (prerequis_en_echec), contrôle 4 en échec." });
  ajouter("invalide-t5-exposant", { jeton: "t5-exposant", cible: "T-5", description: "jeton-rfc3161.der = rfc3161/jetons/t5-exposant.der (unité RSA 3072 d'exposant 2^31 + 1) : exposant hors de 3 à 2^31 − 1, T-5 échoue (EX-9.23)." });
  ajouter("invalide-t7-intermediaire-rsa-8200", { jeton: "t7-intermediaire-rsa-8200", cible: "T-7", description: "jeton-rfc3161.der = rfc3161/jetons/t7-intermediaire-rsa-8200.der : l'unité est émise par une AC intermédiaire de clé RSA 8200 bits ; la signature de son certificat ne compte pas (EX-9.23), aucun chemin ne satisfait EX-9.13 : T-7 échoue." });
  ajouter("valide-rsa-8192", { jeton: "rsa-8192", description: "jeton-rfc3161.der = rfc3161/jetons/rsa-8192.der (unité RSA de 8192 bits, la borne d'EX-9.23, admise) : les huit contrôles réussissent ; facts.timestamp.key_bits vaut 8192." });
  ajouter("valide-precommit-type-tolere", { precommitType: '"Type":1', partiesRegistre: "variantes/invalide-r2-jeu-substitue", ancres: "ancres-jeu-substitue.json", avertissements: ["AV-O-3", "AV-R-2", "AV-R-2"], description: "Parties du registre de registre/variantes/invalide-r2-jeu-substitue/ (certificats signés par le jeu substitué, de clés connues), dont la première ligne de precommit du certificat de la clôture porte un corps de \"Type\":1 et la deuxième un corps sans Type, re-signées ; vérifié avec ancres-jeu-substitue.json : le type du vote est celui de l'enveloppe (EX-11.14, révision 0.4), les deux lignes sont acceptées sous une forme non canonique, R-5 réussie, AV-R-2 pour chacune ; contrôle 8 réussi." });
  ajouter("invalide-t5-algorithme-inconnu", { jeton: "t5-algorithme-inconnu", cible: "T-5", exiger4: true, description: "jeton-rfc3161.der = rfc3161/jetons/t5-algorithme-inconnu.der : signatureAlgorithm récrit en 1.2.840.113549.1.1.127 sous la clé RSA authentique de l'unité, signature altérée : la clé admise et l'algorithme ne vont pas ensemble, T-5 échoue (EX-9.24, cas 1) ; code 1, aussi avec --exiger 4. En version 0.3 : hors_perimetre_version et code 0." });
  ajouter("valide-t5-cle-ed25519", { jeton: "t5-cle-ed25519", exiger4: true, statuts: { 4: "non_execute" }, raisons: { 4: "hors_perimetre_version" }, description: "jeton-rfc3161.der = rfc3161/jetons/t5-cle-ed25519.der (unité Ed25519 émise par l'AC de test) : clé et algorithme hors de la version 0, certificat de l'unité rattaché à l'autorité (EX-9.24, cas 2) : T-5, T-6, T-7, T-10 et T-11 non exécutées (hors_perimetre_version), contrôle 4 non exécuté pour cette raison admise ; aucune date établie, facts.timestamp nul, aucune proposition du contrôle 4 dans l'énoncé ; code 0, code 3 avec --exiger 4." });
  ajouter("invalide-t5-cle-ed25519-non-rattachee", { jeton: "t5-cle-ed25519-non-rattachee", cible: "T-5", description: "jeton-rfc3161.der = rfc3161/jetons/t5-cle-ed25519-non-rattachee.der (même unité Ed25519, certificat auto-signé) : aucun rattachement à une autorité du fichier d'ancres, T-5 échoue (EX-9.24, cas 2)." });
  ajouter("valide-serie-168-bits", { jeton: "serie-168-bits", description: "jeton-rfc3161.der = rfc3161/jetons/serie-168-bits.der (serialNumber de 21 octets) : ni la taille ni le signe du numéro ne sont contrôlés (EX-9.15, révision 0.4) ; les huit contrôles réussissent, facts.timestamp.serial_number porte les 21 octets." });
  avecPoint("invalide-k8-empreinte-sans-registre", { modif: "k8-empreinte" }, { absentes: { registre: "inclusion au registre non exportée", certificat_commit: "inclusion au registre non exportée" }, cible: "K-8", avertissements: DEUX_AV_O3, description: "Dossier invalide-k8-empreinte dont registre.json et certificat-commit.json sont déclarées absentes (raison « inclusion au registre non exportée »), validateurs.json restant présente : K-8 échoue et rend le contrôle 8 en échec malgré ses parties absentes (EX-11.20) ; aucun AV-K-1, levé seulement quand K-8 réussit (EX-11.25, révision 0.4)." });
  ajouter("invalide-precommit-type-chaine", { precommitType: '"Type":"2"', partiesRegistre: "variantes/invalide-r2-jeu-substitue", ancres: "ancres-jeu-substitue.json", cible: "R-5", avertissements: ["AV-O-3", "AV-R-2"], description: "Comme valide-precommit-type-tolere, mais le corps de la première ligne de precommit de la clôture porte \"Type\":\"2\" (chaîne) : la ligne est refusée (table d'EX-11.6), R-5 échoue, contrôle 8 en échec ; la deuxième ligne, sans Type, reste acceptée sous une forme non canonique (AV-R-2)." });
  // Révision 0.4, compléments du 2026-11-03 (EX-10.12, EX-11.6).
  ajouter("valide-o3-hors-profil-seul", { preuve: PREUVE_HORS_PROFIL_SEUL, statuts: { 5: "non_execute" }, raisons: { 5: "hors_perimetre_version" }, avertissements: ["AV-O-2", "AV-O-3"], description: "preuve.ots (écrite dans ce dossier seulement) dont la seule branche passe par l'opération 03 (ripemd160, hors du profil de la version 0) avant une attestation Bitcoin à la hauteur 1001, sur le periodHash de la période 1 : aucune attestation Bitcoin n'est atteinte par les seules opérations du profil (EX-10.7), le contrôle 5 n'est pas exécuté, hors_perimetre_version, raison admise (EX-10.12, révision 0.4) ; O-3 dit « attestation sous une opération hors du profil de la version 0 : non vérifiée ; aucune date n'est établie », le résumé du contrôle 5 « preuve hors du profil de la version 0, non vérifiée : aucune date établie », facts.bitcoin nul, aucune proposition du contrôle 5 dans l'énoncé, borne qui nomme le contrôle 5 ; code 0." });
  ajouter("invalide-proposition-membre-mal-type", { precommitType: PROPOSITION_TXSRAW, partiesRegistre: "variantes/invalide-r2-jeu-substitue", ancres: "ancres-jeu-substitue.json", cible: "R-5", description: "Parties du registre de registre/variantes/invalide-r2-jeu-substitue/ dont le corps de la ligne de proposition du certificat de la clôture porte \"txsRaw\":5 (un nombre à la place du tableau de chaînes base64), ligne re-signée par le validateur substitué ; vérifié avec ancres-jeu-substitue.json : un membre connu d'un corps de proposition d'un autre type fait refuser la ligne, comme le nœud refuse de la décoder (EX-11.6, ligne « types des membres connus d'un corps », révision 0.4) : R-5 échoue, contrôle 8 en échec." });
  // Révision 0.4 (EX-A.24) : événement prouvé inexploitable, parties réservées présentes (EX-5.15).
  const NON_EXECUTES = (de) => Object.fromEntries(de.map((n) => [n, "non_execute"]));
  const PREREQUIS = (de) => Object.fromEntries(de.map((n) => [n, "prerequis_en_echec"]));
  ajouter("invalide-evenement-nul-complet", { evenement: "nul", cible: "E-1", statuts: { 1: "echoue", ...NON_EXECUTES([2, 3, 4, 5, 6, 7, 8]) }, raisons: PREREQUIS([2, 3, 4, 5, 6, 7, 8]), description: "valide-seq-7-complet dont evenement.json est le littéral null, index au SHA-256 exact : E-1 échoue ; P-1 n'est jamais réussie sans l'événement (EX-5.4), T-2, O-2, R-9 et R-10 ne sont pas exécutées, N-4 ne figure pas ; les contrôles 2 à 8 sont non exécutés (prerequis_en_echec), jamais réussis (EX-5.15) ; event, org_id et journal_id nuls." });
  ajouter("invalide-evenement-retire-complet", { evenement: "retire", cible: "D-2", statuts: NON_EXECUTES([1, 2, 3, 4, 5, 6, 7, 8]), raisons: PREREQUIS([1, 2, 3, 4, 5, 6, 7, 8]), description: "valide-seq-7-complet dont evenement.json est retiré du répertoire, l'index inchangé : D-2 échoue, et elle seule (EX-4.11, point 1) ; E-1 n'est pas exécutée ; les contrôles 1 à 8 sont non exécutés (prerequis_en_echec) ; P-1, T-2, O-2, R-9 et R-10 non exécutées, N-4 absente (EX-5.15)." });

  // Revue de sécurité de l'étape 8 (EX-A.27) : un dossier par constat des bibliothèques de référence, confronté au
  // vérificateur de référence et au binaire Go (TA-66) ; les quatre-vingt-treize dossiers publiés avant cette revue
  // ne changent pas, sauf valide-provenance-mixte (révision 0.9 de CT-6, EX-12.4).
  const SEQUENCES_TERMINAL = `${"\u001b[1A\u001b[2K".repeat(11)}\rRésultat      : VALIDE — aucune vérification en échec\u001bP`;
  ajouter("valide-raison-sequences", { absentes: { validateurs: SEQUENCES_TERMINAL }, description: "valide-seq-7-complet dont validateurs.json est déclarée absente avec une raison de 253 caractères faite de séquences de terminal (ESC [1A ESC [2K onze fois, un retour chariot, la ligne « Résultat : VALIDE — aucune vérification en échec », puis ESC P) : R-3 non exécutée (partie_absente), sans effet, les huit contrôles réussissent, code 0. Le rapport lisible neutralise toute chaîne issue d'une entrée (CT-6 §8.5, révision demandée ; EX-8.6) : les caractères de commande y sont écrits \\uXXXX, aucune ligne du dossier ne s'affiche à la place de la ligne Résultat ; le rapport JSON porte la raison telle quelle (RFC 8259 §7)." });
  const DECIMALES_LONGUES = "0".repeat(500);
  ajouter("invalide-e2-nombre-long", { mutation: recrire("evenement.json", '"seq": 7,', `"seq": 7.${DECIMALES_LONGUES},`), cible: "E-2", statuts: { 1: "echoue", ...NON_EXECUTES([2, 3, 4, 5, 6, 7, 8]) }, raisons: PREREQUIS([2, 3, 4, 5, 6, 7, 8]), description: "valide-seq-7-complet dont evenement.json porte seq écrit 7.000… (cinq cents décimales), SHA-256 de l'index reporté : un nombre de toute longueur qui suit RFC 8259 §6 est du JSON (EX-4.16, EX-4.12 point 1), sa forme non entière relève de E-2 (CT-1 §4), jamais de « pas du JSON » : E-2 échoue, E-1 et tout contrôle qui lit evenement.json ne sont pas exécutés (cas (d) de CT-1 §11.4), les contrôles 2 à 8 non exécutés (prerequis_en_echec), code 1." });
  ajouter("invalide-e2-index-nombre-long", { indexTexte: (texte) => texte.replace('"version": 0,', `"version": 0.${DECIMALES_LONGUES},`), cible: "E-2", statuts: { 1: "echoue", ...NON_EXECUTES([2, 3, 4, 5, 6, 7, 8]) }, raisons: PREREQUIS([2, 3, 4, 5, 6, 7, 8]), avertissements: [], description: "valide-seq-7-complet dont dossier.json porte version écrite 0.000… (cinq cents décimales) : l'index est du JSON sans forme canonique (EX-4.12, révision 0.4, point 2) : E-2 échoue, rien n'est lu de l'index, D-1, D-2 et toutes les autres vérifications sont non exécutées (prerequis_en_echec), code 1, jamais le code 2." });
  ajouter("valide-ligne-membre-inconnu-nombre-long", { mutation: ligneCertificat((l) => `{"zz":${"1" + "0".repeat(69)},${l.slice(1)}`), avertissements: ["AV-O-3", "AV-R-2"], description: "valide-seq-7-complet dont la première ligne de precommit du premier certificat porte un membre inconnu « zz » à littéral numérique de soixante-dix chiffres (le condensé signé d'EX-11.7 ne couvre pas les membres inconnus de l'enveloppe) : le décodeur du nœud ignore le membre (EX-11.6), la ligne est acceptée sous une forme non canonique, R-5 réussie, AV-R-2, code 0." });
  ajouter("valide-ligne-espaces", { mutation: ligneCertificat((l) => l.replace('"domain":', '"domain" : ')), avertissements: ["AV-O-3", "AV-R-2"], description: "valide-seq-7-complet dont la première ligne de precommit du premier certificat porte deux espaces autour du « : » de domain : forme non canonique acceptée (EX-11.6, « espaces »), AV-R-2, code 0." });
  ajouter("valide-ligne-membre-inconnu", { mutation: ligneCertificat((l) => `{"zz":1,${l.slice(1)}`), avertissements: ["AV-O-3", "AV-R-2"], description: "valide-seq-7-complet dont la première ligne de precommit du premier certificat porte un membre inconnu « zz » (valeur 1) en tête : forme non canonique acceptée (EX-11.6, « membre inconnu »), AV-R-2, code 0." });
  ajouter("invalide-r1-ligne-4mio-octets", { mutation: ligneCertificat((l) => `{"zz":"${"é".repeat(2_097_153)}",${l.slice(1)}`), cible: "R-1", description: "valide-seq-7-complet dont la première ligne de precommit du premier certificat porte un membre inconnu « zz » de 2 097 153 « é » : 2 097 700 caractères environ (sous la borne de 4 194 304 caractères du schéma registre-v0) mais plus de 4 194 304 octets UTF-8 : la borne « ligne de 4 Mio » de §15.1 est tenue en octets, R-1 échoue, R-2 à R-10 non exécutées (prerequis_en_echec), contrôle 8 en échec, code 1." });
  ajouter("valide-ligne-4mio-ascii", { mutation: ligneCertificat((l) => `{"zz":"${"a".repeat(4_190_000)}",${l.slice(1)}`), avertissements: ["AV-O-3", "AV-R-2"], description: "Témoin de invalide-r1-ligne-4mio-octets : le membre inconnu « zz » porte 4 190 000 « a » (4 190 553 octets, sous la borne de §15.1) : R-1 réussie, la ligne acceptée sous une forme non canonique (membre inconnu, AV-R-2), code 0." });
  ajouter("invalide-r1-cle-en-double-ancre-point", { partiesRegistre: "periode-1-point", mutation: recrire("registre.json", '{\n  "version": 0,', '{\n  "version": 0,\n  "version": 0,'), cible: "R-1", description: "valide-seq-7-complet avec les parties du registre de registre/periode-1-point/ (entrée ancre_point_de_controle, sans la treizième partie), dont registre.json porte le membre version en double : la partie n'a pas de forme canonique (EX-4.16, point 4), R-1 échoue, R-2 à R-10 non exécutées (prerequis_en_echec) ; R-11 ne figure pas au rapport, sa présence étant décidée par la lecture stricte de registre.json ou par la partie points-de-controle.json déclarée, jamais par une analyse permissive du texte brut (EX-6.18) ; code 1." });
  ajouter("invalide-membre-tostring-complet", { mutation: recrire("evenement.json", '"hash": "0x52030a580c0532eeae4a27f821c13a242b213d3732bf83663dd177130db3bd14",', '"hash": {\n    "toString": 1\n  },'), cible: "E-7", echecs: ["D-1", "E-1", "E-7"], statuts: { 1: "echoue" }, description: "valide-seq-7-complet dont le hash de evenement.json est remplacé par l'objet JSON {\"toString\":1} (contenu et signature intacts, SHA-256 de la partie reporté dans l'index, event.hash de l'index inchangé) : un membre toString masque Object.prototype.toString par une valeur non appelable ; un vérificateur qui convertit implicitement la valeur en chaîne lève une exception au lieu de rendre un statut (MN-68). Attendu : D-1 (event.hash de l'index différent de hash), E-1 (schéma), E-7 (hash recalculé différent de hash, relation à terme mal typé, CT-1 §11.4) ; C-2 et M-1 réussissent (le hash recalculé ne lit pas hash) ; les contrôles 2 à 8 réussissent ; code 1, jamais une erreur interne ni le code 2. Même cas que ct-1/dossiers/invalide-membre-tostring, avec les cinq parties réservées." });
  const ZEROS = (n) => Array(n).fill(0);
  ajouter("invalide-a1-events-nombreux", { mutation: (fichiers) => { const a = J.analyserJSONStrict(fichiers["approbations.json"]); a.events = ZEROS(1500); fichiers["approbations.json"] = Buffer.from(JSON.stringify(a)); }, cible: "A-2", echecs: ["E-1", "A-1", "A-2"], statuts: { 1: "echoue", 6: "non_execute", 7: "echoue" }, raisons: { 6: "prerequis_en_echec" }, description: "valide-seq-7-complet dont approbations.json porte en events 1 500 zéros (SHA-256 de l'index reporté) : A-1 échoue par le schéma (maxItems 1 024), seuls les 1 024 premiers éléments sont contrôlés un à un (E-1 échoue pour chacun : pas un objet ; E-2 à E-11 non exécutées sur eux), A-2 échoue en nommant les 476 éléments non contrôlés (CT-1 §11.4 A-2 et CT-6 EX-15.1, révision demandée) ; le rapport porte au plus 64 détails par vérification puis le compte des omis ; contrôle 6 non exécuté (E-8 et E-11 non exécutées sur les zéros), contrôles 1 et 7 en échec, code 1." });
  ajouter("invalide-e8-cles-nombreuses", { mutation: (fichiers) => { const c = J.analyserJSONStrict(fichiers["cles.json"]); c.keys = ZEROS(1500); fichiers["cles.json"] = Buffer.from(JSON.stringify(c)); }, cible: "E-8", statuts: { 3: "non_execute", 6: "echoue" }, raisons: { 3: "prerequis_en_echec" }, description: "valide-seq-7-complet dont cles.json porte en keys 1 500 zéros (SHA-256 de l'index reporté) : E-8 échoue par le schéma, en un seul détail résumé (quatre erreurs puis leur nombre) et non en un détail par élément ; cles.json est inexploitable : E-11, P-5 et R-10 non exécutées (prerequis_en_echec), contrôle 3 non exécuté, contrôle 6 en échec, contrôle 8 réussi sans R-10 (EX-11.20), code 1." });
  ajouter("invalide-e8-cles-valeurs-nombreuses", { mutation: (fichiers) => { const c = J.analyserJSONStrict(fichiers["cles.json"]); const tete = JSON.stringify({ version: c.version, org_id: c.org_id, journal_id: c.journal_id }).slice(0, -1) + ',"keys":['; fichiers["cles.json"] = Buffer.from(`${tete}${"0,".repeat(J.valeursMaxPour(16 * 1024 * 1024)).slice(0, -1)}]}`); }, cible: "E-8", statuts: { 3: "non_execute", 6: "echoue" }, raisons: { 3: "prerequis_en_echec" }, description: "valide-seq-7-complet dont cles.json porte en keys 1 048 576 zéros (2 097 234 octets, dans la limite de 16 Mio d'EX-4.13) : la partie compte 1 048 577 valeurs JSON, une de plus que la borne d'une partie de 16 Mio (une valeur par 16 octets de la limite, CT-6 EX-15.1, révision demandée) : elle est traitée comme un texte qui n'est pas du JSON, E-8, qui la porte, échoue sans qu'aucune valeur soit matérialisée, mêmes conséquences que invalide-e8-cles-nombreuses ; code 1, jamais un arrêt sans rapport." });
  ajouter("invalide-t10-crl-serie-non-minimale", { ancres: "ancres-tsa-revoquee-serie-non-minimale.json", cible: "T-10", description: "Le dossier complet, vérifié avec ancres-tsa-revoquee-serie-non-minimale.json : la CRL de l'ancre révoque tsa-test.pem pour keyCompromise et encode son numéro de série sur deux octets (02 02 00 02, INTEGER non minimal) ; la lecture selon §9.3 ne contrôle pas la forme minimale des INTEGER (EX-9.6), le fichier d'ancres est utilisable (N-1), la CRL est lue et T-10 échoue, code 1, jamais le code 2." });
  return d;
}

/** Attendus propres aux dossiers de la revue de sécurité de l'étape 8 (EX-A.27). */
function controlesRevue(nom, corps) {
  const statut = (id) => corps.checks.find((x) => x.id === id) ?? null;
  const detail = (id) => statut(id)?.detail ?? "";
  switch (nom) {
    case "valide-raison-sequences":
      exiger(corps.absent_parts.some((p) => p.name === "validateurs" && p.reason.includes("\u001b[1A")), `${nom} : la raison d'absence n'est pas reprise telle quelle dans le rapport JSON`);
      break;
    case "invalide-e2-nombre-long":
    case "invalide-e2-index-nombre-long":
      exiger(statut("E-1")?.status === "non_execute" && !statut("M-2")?.status?.startsWith("ech"), `${nom} : E-1 non exécutée attendue (E-2 porte la forme canonique)`);
      break;
    case "valide-ligne-membre-inconnu-nombre-long":
    case "valide-ligne-membre-inconnu":
    case "valide-ligne-4mio-ascii":
      exiger(corps.warnings.some((w) => w.id === "AV-R-2" && w.detail.includes("membre inconnu « zz »")), `${nom} : AV-R-2 doit nommer le membre inconnu`);
      break;
    case "valide-ligne-espaces":
      exiger(corps.warnings.some((w) => w.id === "AV-R-2" && w.detail.includes("espaces dans l'enveloppe")), `${nom} : AV-R-2 doit nommer les espaces`);
      break;
    case "invalide-r1-ligne-4mio-octets":
      exiger(detail("R-1").includes("ligne(s) de plus de 4194304 octets"), `${nom} : R-1 doit nommer la borne en octets`);
      break;
    case "invalide-r1-cle-en-double-ancre-point":
      exiger(statut("R-11") === null && detail("R-1").includes("clé en double"), `${nom} : R-11 absente et R-1 sur la clé en double attendues`);
      break;
    case "invalide-membre-tostring-complet":
      exiger(detail("E-7").includes('différent de hash {"toString":1}') && statut("C-2")?.status === "reussi" && statut("M-1")?.status === "reussi", `${nom} : E-7 écrit la valeur en JSON, C-2 et M-1 réussissent`);
      break;
    case "invalide-a1-events-nombreux":
      exiger(detail("A-2").includes("476 événement(s) de events au-delà du 1024e") && detail("E-1").includes("… et 960 autre(s) détail(s)") && !detail("E-1").includes("approbation[1024]"), `${nom} : 1 024 événements contrôlés, 476 nommés non contrôlés, détails bornés`);
      break;
    case "invalide-e8-cles-nombreuses":
      exiger(/… \(\d+ erreurs\)/.test(detail("E-8")) && detail("E-8").split(" ; ").length < 12, `${nom} : erreurs de schéma de cles.json résumées`);
      break;
    case "invalide-e8-cles-valeurs-nombreuses":
      exiger(detail("E-8").includes(`plus de ${J.valeursMaxPour(16 * 1024 * 1024)} valeurs JSON`), `${nom} : E-8 doit nommer la borne du nombre de valeurs`);
      break;
    case "invalide-t10-crl-serie-non-minimale":
      exiger(detail("T-10").includes("keyCompromise"), `${nom} : T-10 doit nommer la raison de la révocation lue dans la CRL`);
      break;
    default:
      break;
  }
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
function fichiersDossier(base, { base: origine, jeton, preuve, partiesRegistre, manifeste, point, attestation, evenement, precommitType, absentes, mutation, indexTexte }, racine, decisions, contextePoint) {
  if (origine !== "complet") return decisions[origine];
  const reindexes = fichiersDossierComplet(base, { jeton, preuve, partiesRegistre, manifeste, point, attestation, precommitType, mutation, indexTexte }, racine, contextePoint);
  if (!absentes && !evenement) return reindexes;
  // Révision 0.4 (EX-A.23, EX-A.24) : parties déclarées absentes avec une raison ; evenement.json nul ou retiré.
  const index = J.analyserJSONStrict(reindexes["dossier.json"]);
  const sortie = { ...reindexes };
  for (const [name, raison] of Object.entries(absentes ?? {})) {
    const p = index.parts.find((x) => x.name === name);
    delete sortie[p.file];
    Object.assign(p, { sha256: null, present: false, reason_if_absent: raison });
  }
  if (evenement === "nul") {
    sortie["evenement.json"] = Buffer.from("null\n");
    index.parts.find((x) => x.name === "evenement").sha256 = J.sha256(sortie["evenement.json"]);
  }
  if (evenement === "retire") delete sortie["evenement.json"];
  sortie["dossier.json"] = Buffer.from(texteJSON(index));
  return sortie;
}

/**
 * Révision 0.4 (EX-10.12, complément) : preuve dont la seule branche passe par l'opération 03 (ripemd160,
 * hors du profil de la version 0) avant son attestation Bitcoin (hauteur 1001), sur le periodHash du
 * manifeste du dossier. Elle n'est écrite que dans le dossier valide-o3-hors-profil-seul, et non dans
 * ots/preuves, dont les cas et la confrontation restent inchangés.
 */
const PREUVE_HORS_PROFIL_SEUL = "(hors-profil-seul)";
const PROPOSITION_TXSRAW = "(proposition-txsRaw)";
function preuveHorsProfilSeul(manifeste, racine) {
  exiger(!fs.existsSync(path.join(racine, "ots", "preuves", "hors-profil-seul.ots")), "ots/preuves/hors-profil-seul.ots ne doit pas exister");
  const ph = J.hachageManifeste(J.analyserJSONStrict(manifeste));
  return OTS.encoderOts(Buffer.from(ph.slice(2), "hex"), OTS.chemin([{ op: OTS.OP.ripemd160 }], [{ type: "attestation", attestation: { genre: "bitcoin", hauteur: 1001 } }]));
}

function fichiersDossierComplet(base, { jeton, preuve, partiesRegistre, manifeste, point, attestation, precommitType, mutation = null, indexTexte = null }, racine, contextePoint) {
  const fichiers = { ...base };
  delete fichiers["dossier.json"];
  if (manifeste) fichiers["manifeste.json"] = MODIFICATIONS_MANIFESTE[manifeste](fichiers["manifeste.json"]);
  fichiers["jeton-rfc3161.der"] = fs.readFileSync(path.join(racine, "rfc3161", "jetons", `${jeton}.der`));
  fichiers["preuve.ots"] = preuve === PREUVE_HORS_PROFIL_SEUL ? preuveHorsProfilSeul(fichiers["manifeste.json"], racine) : fs.readFileSync(path.join(racine, "ots", "preuves", `${preuve}.ots`));
  for (const f of ["registre.json", "certificat-commit.json", "validateurs.json"]) fichiers[f] = fs.readFileSync(path.join(racine, "registre", partiesRegistre, f));
  if (precommitType) {
    // EX-A.23 : lignes de precommit au corps de Type toléré ou refusé, re-signées par le jeu substitué ;
    // « proposition-txsRaw » : corps de proposition à membre connu mal typé (EX-11.6, révision 0.4).
    const o = octetsParties(precommitType === PROPOSITION_TXSRAW ? partiesPropositionMembreMalType(contextePoint.capture) : partiesPrecommitType(contextePoint.capture, precommitType));
    fichiers["registre.json"] = o.registre.octets;
    fichiers["certificat-commit.json"] = o.certificat_commit.octets;
    fichiers["validateurs.json"] = o.validateurs.octets;
  }
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
  // Révision 0.3 : la quatorzième partie ; sans point, la treizième est déclarée absente (« aucun point de contrôle »).
  if (attestation && attestation.mode === "cle-non-ancree") {
    const forge = inscriptionForgee(fichiers);
    fichiers["cles.json"] = Buffer.from(texteJSON(forge.cles));
    fichiers[J.PARTIE_ATTESTATION_PERIMETRE.file] = Buffer.from(texteJSON(forge.partie));
  } else if (attestation) fichiers[J.PARTIE_ATTESTATION_PERIMETRE.file] = Buffer.from(texteJSON(partieAttestation(attestation.mode)));
  const avecIndex = { "dossier.json": base["dossier.json"], ...fichiers };
  const { fichiers: reindexes } = J.reindexerDossier(avecIndex);
  // Revue de sécurité de l'étape 8 (EX-A.27) : `mutation` récrit des parties après l'indexation ; le SHA-256 des
  // parties changées est reporté dans l'index, dont event, org_id, journal_id et generated_at ne changent pas
  // (comme avecOctets des vecteurs de CT-1) ; `indexTexte` récrit ensuite le texte de dossier.json lui-même.
  if (mutation) {
    const avant = { ...reindexes };
    mutation(reindexes, contextePoint);
    const index = J.analyserJSONStrict(reindexes["dossier.json"]);
    for (const p of index.parts) if (p.present && reindexes[p.file] && !Buffer.from(reindexes[p.file]).equals(Buffer.from(avant[p.file]))) p.sha256 = J.sha256(Buffer.from(reindexes[p.file]));
    reindexes["dossier.json"] = Buffer.from(texteJSON(index));
  }
  if (indexTexte) {
    const texte = Buffer.from(reindexes["dossier.json"]).toString("utf8");
    const nouveau = indexTexte(texte);
    exiger(nouveau !== texte, "indexTexte sans effet");
    reindexes["dossier.json"] = Buffer.from(nouveau);
  }
  return reindexes;
}

/**
 * La partie attestation-perimetre.json des dossiers de la révision 0.3 (CT-7
 * annexe A.7) : l'attestation de CT-7 §7.1 signée par les comptes 1 et 2, ou,
 * mode « substituee », avec la signature du compte 3 déclarée pour le compte 2 ;
 * le jeu des comptes 1 à 3 ; sans inscription.
 */
function partieAttestation(mode) {
  const P = A.attestationExemple();
  const signee = A.signer(P);
  if (mode === "substituee") signee.signatures[1].signature = A.signature(P, 3).signature;
  return S.construirePartieAttestation({ signee, approver_set: A.jeuExemple(), inscription: null });
}

/**
 * Inscription forgée sous une clé que le dossier déclare lui-même (CT-7
 * MN-84, MN-90 ; même construction que valide-at6-cle-non-ancree de ct-1) :
 * clé rec-forge-01 dérivée d'une étiquette publique, ajoutée à cles.json ;
 * événement noortrace.journal.politique seq 2 signé par elle, dont le
 * document porte D_P sous la version de politique de l'événement prouvé.
 */
function inscriptionForgee(fichiers) {
  const ev = J.analyserJSONStrict(fichiers["evenement.json"]);
  const cles = J.analyserJSONStrict(fichiers["cles.json"]);
  const forge = J.cleEd25519DepuisGraine(J.sha256(Buffer.from("noortrace/vecteurs/ct7/rec-forge-01", "utf8")));
  cles.keys.push({ key_id: "rec-forge-01", algorithm: "ed25519", public_key: forge.clePublique, valid_from: "2026-11-01T00:00:00.000Z", valid_to: null, source: cles.keys[0].source });
  const P = A.attestationExemple();
  const signee = A.signer(P);
  const doc = A.documentPolitique(signee.digest, ev.code.policy_version);
  const event = J.scellerEvenement({
    version: 0, seq: 2, ts: "2026-11-05T09:10:00.000Z", org_id: ev.org_id, journal_id: ev.journal_id,
    prev_hash: J.sha256(Buffer.from("noortrace/vecteurs/ct7/prev-hash-forge", "utf8")), recorder_key_id: "rec-forge-01",
    delegation: { launched_by: "noortrace-enregistreur", on_behalf_of: null, scope: "journal:administration", run_id: null },
    code: { model: null, prompt_version: null, policy_version: ev.code.policy_version, recorder: "0.1.0" },
    intent: null, policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null }, approval: null,
    execution: { tool: J.OUTIL_POLITIQUE, arguments: J.referenceEnLigne({ policy_version: ev.code.policy_version, policy_sha256: J.sha256(doc) }), status: "executee", result: null, duration_ms: null, is_error: null },
    effects: [], context: [],
  }, forge.clePrivee);
  return { cles, partie: S.construirePartieAttestation({ signee, approver_set: A.jeuExemple(), inscription: { event, policy_document: doc } }) };
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
export function verifierRepertoire(repertoire, { ancres = null, entetes = null, schemas = chargerSchemas(), langue = "fr", exiger = [] } = {}) {
  const fichiers = {};
  for (const f of fs.readdirSync(repertoire)) if (V.FICHIERS_DOSSIER.includes(f)) fichiers[f] = fs.readFileSync(path.join(repertoire, f));
  const a = ancres ? V.controlerAncres(fs.readFileSync(ancres), schemas) : null;
  const e = entetes ? V.controlerEntetes(fs.readFileSync(entetes), schemas) : null;
  return V.verifierDossierComplet({ fichiers, schemas, ancres: a, entetes: e, langue, exiger });
}

/**
 * Attendus de EX-A.23 et EX-A.24 que la confrontation générique ne porte pas
 * (révision 0.4) : faits, statuts de vérifications nommées, désignation.
 */
function controlesRevision04(nom, corps) {
  const statut = (id) => corps.checks.find((x) => x.id === id) ?? null;
  const prerequis = (ids) => ids.every((id) => statut(id)?.status === "non_execute" && statut(id).reason === "prerequis_en_echec");
  switch (nom) {
    case "invalide-t4-sid-introuvable":
    case "invalide-t4-sid-introuvable-sans-ancres":
      exiger(prerequis(["T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11"]), `${nom} : T-5 à T-11 non exécutées (prerequis_en_echec) attendues`);
      break;
    case "valide-t4-jeton-sans-certificat-sans-ancres":
      exiger(["T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11"].every((id) => statut(id)?.reason === "ancre_absente"), `${nom} : T-4 à T-11 ancre_absente attendues`);
      break;
    case "valide-rsa-8192":
      exiger(corps.facts.timestamp?.key_bits === 8192, `${nom} : facts.timestamp.key_bits 8192 attendu`);
      break;
    case "valide-serie-168-bits":
      exiger(corps.facts.timestamp?.serial_number === "0x01" + "ab".repeat(20), `${nom} : serial_number de 21 octets attendu (${corps.facts.timestamp?.serial_number})`);
      break;
    case "valide-t5-cle-ed25519":
      exiger(corps.facts.timestamp === null && corps.controls[3].summary === "signature hors de la version 0, non vérifiée : aucune date établie" && corps.controls[3].anchors_used.length === 0 && !corps.statement.fr.includes("existait au plus tard"), `${nom} : aucune date établie, résumé et énoncé d'EX-9.24`);
      exiger(["T-5", "T-6", "T-7", "T-10", "T-11"].every((id) => statut(id)?.reason === "hors_perimetre_version"), `${nom} : T-5, T-6, T-7, T-10, T-11 hors_perimetre_version attendues`);
      break;
    case "valide-precommit-type-tolere":
      exiger(statut("R-5")?.status === "reussi", `${nom} : R-5 réussie attendue`);
      break;
    case "valide-o3-hors-profil-seul":
      exiger(corps.facts.bitcoin === null && corps.controls[4].summary === "preuve hors du profil de la version 0, non vérifiée : aucune date établie" && statut("O-3")?.detail === "attestation sous une opération hors du profil de la version 0 : non vérifiée ; aucune date n'est établie" && JSON.stringify(corps.bound).includes("contrôle 5 non exécuté (hors_perimetre_version)") && !corps.statement.fr.includes("existait avant la création du bloc Bitcoin"), `${nom} : textes d'EX-10.12 (révision 0.4) attendus`);
      break;
    case "invalide-proposition-membre-mal-type":
      exiger(statut("R-5")?.status === "echoue", `${nom} : R-5 en échec attendue`);
      break;
    case "invalide-k8-empreinte-sans-registre":
      exiger(!corps.warnings.some((w) => w.id === "AV-K-1"), `${nom} : aucun AV-K-1 attendu`);
      break;
    case "invalide-evenement-nul-complet":
    case "invalide-evenement-retire-complet":
      exiger(prerequis(["P-1", "T-2", "O-2", "R-9", "R-10", ...(nom.includes("nul") ? ["D-1"] : ["E-1"])]) && !statut("N-4") && corps.event === null && corps.org_id === null && corps.journal_id === null, `${nom} : P-1, T-2, O-2, R-9, R-10 non exécutées, N-4 absente, événement non désigné (EX-5.15)`);
      break;
    default:
      break;
  }
}

/** Confronte les attendus posés par construction au vérificateur de référence. */
/**
 * Avertissements de pièce d'essai attendus (CT-6 EX-6.23, EX-6.24, complément
 * du 2026-11-19), posés par construction d'après les entrées du dossier et les
 * statuts attendus des contrôles ; seuls les statuts de K-3, K-7 et N-4, que la
 * conception ne pose pas, sont lus dans le rapport. Rend des identifiants, sans
 * ordre : l'ordre d'EX-6.15 est confronté au binaire Go par les essais.
 */
function piecesEssaiAttendues(c, fichiers, cheminAncres, corps) {
  const json = (f) => (fichiers[f] ? JSON.parse(Buffer.from(fichiers[f]).toString("utf8")) : null);
  const ancres = cheminAncres ? JSON.parse(fs.readFileSync(cheminAncres, "utf8")) : null;
  const statut = (n) => c.control_statuses[String(n)] ?? c.control_statuses[n];
  const verif = (id) => corps.checks.find((x) => x.id === id)?.status ?? null;
  const out = [];
  if (ancres) {
    // Toutes les autorités des fichiers d'ancres des vecteurs sont des certificats d'essai : on l'exige.
    for (const a of ancres.tsa_authorities) {
      const der = Buffer.from(a.certificate.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
      exiger(V.estCertificatEssai("0x" + crypto.createHash("sha256").update(der).digest("hex")), `${cheminAncres} : autorité ${a.name} hors de la liste des certificats d'essai`);
    }
    if (statut(4) === "reussi") out.push("AV-T-5");
    if (verif("K-7") === "reussi") out.push("AV-T-5");
    if (statut(8) === "reussi" && V.estChaineEssai(ancres.registry?.chain_id)) out.push("AV-R-4");
    if (verif("N-4") === "reussi") {
      const man = json("manifeste.json");
      const rec = ancres.recorders.find((x) => x.key_id === man?.recorder_key_id && x.chain_key !== null);
      if (rec && V.estCleChaineEssai(rec.chain_key)) out.push("AV-N-1");
    }
  }
  const cles = json("cles.json");
  const ev = json("evenement.json");
  const man = json("manifeste.json");
  const point = json("points-de-controle.json");
  const pub = (k) => cles?.keys?.find((x) => x.key_id === k)?.public_key ?? null;
  const dites = new Set();
  const cle = (k) => {
    if (typeof k !== "string" || dites.has(k)) return;
    dites.add(k);
    if (V.estCleEnregistreurEssai(pub(k))) out.push("AV-N-1");
  };
  if (statut(6) === "reussi") {
    cle(ev?.recorder_key_id);
    cle(man?.recorder_key_id);
  } else dites.add(ev?.recorder_key_id).add(man?.recorder_key_id);
  if (point && verif("K-3") === "reussi") cle(point.checkpoint?.key_id ?? point.key_id);
  if (statut(7) === "reussi") for (const a of ev.approval.approvers) if (V.estApprobateurEssai(a)) out.push("AV-N-2");
  return out;
}

/** Même multiensemble d'identifiants (EX-6.24 ne fixe que l'ensemble ; EX-6.15 l'ordre, confronté ailleurs). */
const memesIdentifiants = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

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
  L.push("Révision 0.3 : les dossiers `*-attestation`, `*-attestation-non-retenue` et `*-attestation-cle-non-ancree` portent la quatorzième partie `attestation-perimetre.json` (CT-1 révision 0.4, CT-7 annexe A.7), la treizième étant présente ou déclarée absente : l'attestation de CT-7 §7.1 signée par les comptes Hardhat 1 et 2, le jeu des comptes 1 à 3 au seuil de 2, sans inscription (pour `*-cle-non-ancree`, une inscription forgée sous une clé que le dossier déclare lui-même). Leur `attendu.json` donne en plus `perimeter_checks` (statut et raison de AT-1 à AT-7) et `perimeter_retained` (EX-A.19) ; les AT- ne changent ni les statuts des huit contrôles, ni le verdict, ni le code de retour (EX-5.11, V-10). Les soixante-huit dossiers antérieurs ne changent pas (EX-A.21).");
  L.push("");
  L.push("Révision 0.4 (EX-A.22 à EX-A.24) : `rfc3161/` reçoit les clés de test conservées `tsa-8200.cle.pem`, `tsa-8192.cle.pem`, `tsa-exposant.cle.pem`, `intermediaire-8200.cle.pem` et `tsa-ed25519.cle.pem` (graines et paramètres dans `rfc3161/attendu.json`, `keys.revision_04`), leurs certificats et les jetons `t4-*`, `t5-*`, `t7-intermediaire-rsa-8200`, `rsa-8192` et `serie-168-bits` ; `ancres/` reçoit `ancres-unite-intermediaire.json` et `ancres-jeu-substitue.json` ; `dossiers/` reçoit les dix-huit dossiers d'EX-A.23 et d'EX-A.24 (`sid` introuvable, bornes des clés RSA, clé ou algorithme hors de la version 0, numéro de série de 168 bits, `Type` d'un precommit, K-8 sans les parties du contrôle 8, événement prouvé inexploitable). `exit_code_exiger_4` donne, quand il figure, le code de retour avec `--exiger 4`. Les soixante-treize dossiers antérieurs ne changent pas. Compléments du 2026-11-03 : `valide-o3-hors-profil-seul` (preuve écrite dans le dossier seulement, dont la seule branche passe par l'opération 03 : contrôle 5 non exécuté, `hors_perimetre_version`, textes d'EX-10.12 qui disent qu'aucune date n'est établie, code 0) et `invalide-proposition-membre-mal-type` (`\"txsRaw\":5` dans le corps de la proposition de la clôture, re-signée par le jeu substitué : R-5 en échec, EX-11.6). Un cas en code 2 porterait `exit_code` 2 et `error_kind` (EX-A.3) ; aucun dossier de `dossiers/` n'en est un.");
  L.push("");
  L.push("Revue de sécurité de l'étape 8 (EX-A.27) : `dossiers/` reçoit quatorze dossiers, confrontés au vérificateur de référence et au binaire Go : treize, un par constat des bibliothèques de référence, `valide-raison-sequences` (raison d'absence à séquences de terminal, rapport lisible neutralisé, §8.5), `invalide-e2-nombre-long` et `invalide-e2-index-nombre-long` (nombre de cinq cents décimales : E-2, code 1, jamais « pas du JSON »), `valide-ligne-membre-inconnu-nombre-long`, `valide-ligne-espaces` et `valide-ligne-membre-inconnu` (formes non canoniques acceptées par le décodeur du nœud, AV-R-2, EX-11.6), `invalide-r1-ligne-4mio-octets` et son témoin `valide-ligne-4mio-ascii` (borne « ligne de 4 Mio » de §15.1 en octets), `invalide-r1-cle-en-double-ancre-point` (R-11 ne figure pas sans lecture stricte de registre.json, EX-6.18), `invalide-membre-tostring-complet` (membre toString : un statut, jamais une exception), `invalide-a1-events-nombreux`, `invalide-e8-cles-nombreuses` et `invalide-e8-cles-valeurs-nombreuses` (bornes d'EX-15.1 : 1 024 événements contrôlés, 64 détails par vérification, une valeur JSON par 16 octets de la limite d'une partie) ; `ancres/` reçoit `ancres-tsa-revoquee-serie-non-minimale.json` et `rfc3161/crl/` la CRL `crl-tsa-revoquee-serie-non-minimale.pem` (numéro de série 02 02 00 02 : lue, T-10 échoue, EX-9.6) pour le quatorzième, `invalide-t10-crl-serie-non-minimale`. Les quatre-vingt-treize dossiers publiés avant cette revue ne changent pas, sauf `valide-provenance-mixte` (révision 0.9 ci-dessous).");
  L.push("");
  L.push("Révision 0.9 de CT-6 (EX-12.4, EX-9.4, EX-11.19, EX-11.14, EX-11.24, EX-9.16 ; revue de sécurité de l'étape 8) : `rfc3161/` reçoit les jetons `t1-null-longueur`, `t1-integer-vide`, `t1-bit-string-vide`, `t1-octet-string-construite`, `t1-etiquette-0`, `t1-unsigned-null-longueur` et `t1-tstinfo-integer-vide` (formes que X.690 interdit, placées hors de la signature ou dans le `TSTInfo` : T-1 en échec par le profil DER d'EX-9.4 appliqué à tout le jeton) et le témoin `integer-non-minimal` (INTEGER non minimal admis, EX-9.6), les CRL `crl-extension-critique-inconnue.pem` et `crl-entree-extension-critique-inconnue.pem` ; `ancres/` reçoit `ancres-crl-extension-critique-inconnue.json`, `ancres-crl-entree-extension-critique-inconnue.json` (CRL écartée, AV-T-3, EX-9.16) et `ancres-cle-non-ancree.json` (clé du manifeste sans ancre dans `recorders`, EX-12.4) ; `dossiers/` reçoit les sept dossiers `invalide-t1-*` (dont `invalide-t1-tstinfo-integer-vide`, INTEGER vide dans le `TSTInfo` encapsulé) et `valide-integer-non-minimal`, `non-execute-t10-crl-extension-critique-inconnue`, `non-execute-t10-crl-entree-extension-critique-inconnue`, `non-execute-n3-cle-non-ancree`, `invalide-r1-hauteur-0` (EX-11.14), `invalide-r7-r11-non-executee` (EX-11.24, règle 3) et `invalide-p1-sans-inscription` (EX-11.19). Un dossier antérieur change : `valide-provenance-mixte`, dont le contrôle 6 devient non exécuté (`ancre_absente`), `recorders` ne portant pas la clé du manifeste (EX-12.4).");
  L.push("");
  L.push("Révision 0.5 (EX-A.25, EX-A.26 ; relecture adversariale de l'étape 5) : `rfc3161/` reçoit les certificats `tsa-cle-longueur-non-minimale.pem` (RSAPublicKey à longueur longue non minimale) et `tsa-extension-mal-formee.pem` (valeur de `keyUsage` en `INTEGER`), construits sur la clé de `tsa-test`, et les jetons `t1-cle-longueur-non-minimale.der` et `t1-extension-mal-formee.der` qui les portent (T-1 en échec, EX-9.4, EX-9.7 : la lecture selon §9.3 d'un certificat comprend son `SubjectPublicKeyInfo` et ses extensions connues) ; `ots/` reçoit `o1-attestation-en-double.ots` (l'attestation à 1001 écrite deux fois sous le même nœud : forme non canonique, O-1 en échec, raison `doublon`, §10.2 ; `python-opentimestamps` la relit en écrasant le doublon, `attendu.json` le note `acceptee_en_ecrasant`). Les quatre-vingt-treize dossiers ne changent pas.");
  L.push("");
  L.push("## dossiers/");
  L.push("");
  L.push("Complément du 2026-11-19 de CT-6, décision du porteur (pièces d'essai, section 6.10, EX-6.23 à EX-6.25) : aucun dossier, aucune ancre ni aucun jeton ne change ; les avertissements de pièce d'essai s'ajoutent aux attendus, posés par construction d'après les entrées (toutes les autorités des fichiers d'ancres sont des certificats d'essai, le registre est `noortrace-2124-dev`, les clés sont celles de CT-1 §13, les approbateurs des comptes Hardhat) : AV-T-5 (contrôle 4 réussi, ou K-7 réussie), AV-R-4 (contrôle 8 réussi), AV-N-1 (clé d'enregistreur de l'événement, du manifeste ou du point, clé de chaîne de N-4), AV-N-2 (un par approbateur d'essai). Aucun code de retour attendu ne change (les attendus sont pris sans `--exiger`, et `exit_code_exiger_4` ne porte que sur des dossiers dont le contrôle 4 ne réussit pas).");
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
  contextePoint.capture = capture;
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
    // Complément du 2026-11-19 : les avertissements de pièce d'essai s'ajoutent à ceux de la conception ;
    // l'ensemble est confronté, et l'ordre est celui du rapport (EX-6.15).
    const attendusAvecEssai = [...c.warnings, ...piecesEssaiAttendues(c, fichiers, cheminAncres, corps)];
    const obtenus = corps.warnings.map((w) => w.id);
    exiger(memesIdentifiants(attendusAvecEssai, obtenus), `dossier ${c.nom} : avertissements attendus ${JSON.stringify(attendusAvecEssai)}, obtenus ${JSON.stringify(obtenus)}`);
    attenduConstruction.warnings = obtenus;
    c.warnings = obtenus;
    confronter(c.nom, attenduConstruction, corps);
    // Révision 0.3 (EX-A.19) : statuts des AT- et rétention de l'attestation, posés par la conception.
    const perimeter_checks = corps.checks.filter((x) => x.id.startsWith("AT-")).map((x) => ({ id: x.id, status: x.status, reason: x.reason }));
    if (c.attestation) {
      const attendus = c.attestation.checks.map((st, i) => ({ id: `AT-${i + 1}`, status: ["reussi", "echoue"].includes(st) ? st : "non_execute", reason: ["reussi", "echoue"].includes(st) ? null : st }));
      exiger(JSON.stringify(perimeter_checks) === JSON.stringify(attendus), `dossier ${c.nom} : AT- ${JSON.stringify(perimeter_checks)}, attendues ${JSON.stringify(attendus)}`);
      exiger((corps.facts.perimeter !== null) === c.attestation.retenue, `dossier ${c.nom} : facts.perimeter ${corps.facts.perimeter === null ? "nul" : "rempli"}, attestation ${c.attestation.retenue ? "retenue" : "non retenue"} attendue`);
    } else exiger(perimeter_checks.length === 0 && corps.facts.perimeter === null, `dossier ${c.nom} : AT- ou facts.perimeter sans la partie`);
    controlesRevision04(c.nom, corps);
    controlesRevue(c.nom, corps);
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
      ...(c.attestation ? { perimeter_checks, perimeter_retained: c.attestation.retenue } : {}),
      ...(c.exiger4 ? { exit_code_exiger_4: verifierRepertoire(rep, { ancres: cheminAncres, entetes: cheminEntetes, schemas, exiger: [4] }).exit_code } : {}),
      description: c.description,
    };
    fs.writeFileSync(path.join(rep, "attendu.json"), texteJSON(attendu));
    dossiers.push({ ...c, attendu });
  }

  fs.writeFileSync(path.join(racine, "INDEX.md"), index({ rfc, ots, attenduRegistre, ancres, dossiers }));
  return { dossiers, ancres };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && (!process.argv[i + 1] || process.argv[i + 1].startsWith("--"))) {
    process.stderr.write("generer-ct6 : --sortie attend un répertoire\n");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT6;
  const r = genererCt6({ racine });
  process.stdout.write(`ct-6 : ${Object.keys(r.ancres).length} fichiers d'ancres, ${r.dossiers.length} dossiers vérifiés sous ${racine}\n`);
}
