#!/usr/bin/env node
// Configuration de l'installation rapide (CT-8 §7.2, pas IR-3, et §7.3).
//
//   node scripts/deploiement/configurer-rapide.mjs --org <nom court> --journal <nom> \
//     --serveur-outils https://<serveur>/mcp --sortie <configuration.json> \
//     [--ac-horodatage <ac.pem> --sortie-ancrage <ancrage.json>]
//
// Part de deploiement/config/rapide/configuration.json (configuration de
// référence, mode observation), recalcule recorder.org_id = orgIdOf(<org>) et
// recorder.journal_id = journalIdOf(<journal>) (CT-4 §6.2, §6.3), remplace
// policy.servers.outils.transport.url, valide le résultat contre
// configuration-enregistreur-v0 (avec politique-redaction-v0 et
// politique-approbation-v0), l'écrit en JSON indenté de deux espaces suivi
// d'un saut de ligne, et imprime org_id, journal_id, le SHA-256 du fichier et
// « configuration valide ». La configuration désigne le document d'ancrage
// de test (anchoring.ancrage = /etc/noortrace/ancrage.json, que rapide.yaml
// monte depuis deploiement/config/rapide/ancrage.json : jeton RFC 3161 de
// clôture par le serveur interne du service horodatage, preuves
// OpenTimestamps des manifestes, CT-8 EX-7.3) ; ce document est validé contre
// ancrage-v0, son prestataire unique comparé au serveur interne de
// l'installation rapide (principal non qualifié, http://127.0.0.1:2020/, sans
// authentification : admis hors production seulement, CT-5 EX-4.9, règle 4)
// et sa cadence checkpoint_interval_s comparée à celle de l'enregistreur
// (règle 1 d'AN-1) avant toute écriture. Avec --ac-horodatage (le certificat
// de l'AC que le pas IR-2 a créée, en PEM) et --sortie-ancrage, le document
// d'ancrage est écrit avec ce seul certificat dans anchor_certificates, et son
// SHA-256 imprimé (ligne « ancrage_sha256 »). Avec --org organisation-exemple
// --journal journal-rapide --serveur-outils https://outils.interne.example/mcp
// (et --ac-horodatage spec/vecteurs/ct-6/rfc3161/cles/ac-test.pem), les
// fichiers écrits sont octet pour octet les fichiers de référence.
// Codes : 0 écrite ; 2 usage ou configuration invalide (rien n'est écrit).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import * as J from "../lib/journal.mjs";
import { orgIdOf, journalIdOf } from "../lib/noortrace.mjs";
import { RACINE, messageOptions, texteJSON, chargerSchema, validerSchemaDeploiement } from "../lib/deploiement.mjs";

export const REFERENCE = path.join(RACINE, "deploiement", "config", "rapide", "configuration.json");

/** Document ancrage-v0 de l'installation rapide, monté par rapide.yaml à ANCRAGE_CONTENEUR. */
export const REFERENCE_ANCRAGE = path.join(RACINE, "deploiement", "config", "rapide", "ancrage.json");
export const ANCRAGE_CONTENEUR = "/etc/noortrace/ancrage.json";

/** Cadence des points par défaut de l'enregistreur (CT-2, checkpoint_interval_s absent). */
const CADENCE_POINTS_DEFAUT = 60;

/**
 * Prestataire RFC 3161 de l'installation rapide : le serveur interne du service
 * horodatage, joint par la boucle locale de l'espace réseau de l'enregistreur
 * (rapide.yaml), principal non qualifié admis hors production seulement (CT-5
 * EX-4.9, règle 4).
 */
export const SERVEUR_INTERNE_RAPIDE = Object.freeze({ id: "tsa-interne", role: "principal", url: "http://127.0.0.1:2020/", auth: { method: "aucune", secret: null }, qualified: null });

/** Contrôle un document ancrage-v0 pour l'installation rapide. Lève une Error décrite. */
function controlerDocumentAncrage(doc, config) {
  const erreurs = validerSchemaDeploiement(doc, chargerSchema("ancrage"));
  if (erreurs.length) throw new Error(`document d'ancrage invalide : ${erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
  if (doc.opentimestamps.enabled !== true) throw new Error("document d'ancrage : opentimestamps.enabled doit valoir true (CT-8 EX-7.3)");
  const cadence = config.checkpoint_interval_s ?? CADENCE_POINTS_DEFAUT;
  if (doc.checkpoint_interval_s !== cadence) throw new Error(`document d'ancrage : checkpoint_interval_s ${doc.checkpoint_interval_s} différent de celui de l'enregistreur (${cadence}) (AN-1, règle 1)`);
  const p = doc.rfc3161.providers;
  const s = SERVEUR_INTERNE_RAPIDE;
  if (p.length !== 1 || p[0].id !== s.id || p[0].role !== s.role || p[0].url !== s.url || p[0].auth.method !== s.auth.method || p[0].auth.secret !== null || p[0].qualified !== null) {
    throw new Error(`document d'ancrage : un seul prestataire attendu, le serveur interne du service horodatage (${JSON.stringify(s)}) (CT-8 EX-7.3, CT-5 EX-4.9 règle 4)`);
  }
  if (p[0].anchor_certificates.length !== 1) throw new Error("document d'ancrage : un seul certificat d'AC attendu dans anchor_certificates");
}

/**
 * Contrôle le document d'ancrage que désigne la configuration : chemin dans le
 * conteneur, schéma ancrage-v0, OpenTimestamps activé, même cadence des points
 * que l'enregistreur, prestataire unique = serveur interne. Lève une Error décrite.
 */
export function controlerAncrageRapide(config) {
  if (config.anchoring?.ancrage !== ANCRAGE_CONTENEUR) throw new Error(`anchoring.ancrage : ${ANCRAGE_CONTENEUR} attendu (document monté par rapide.yaml), reçu ${JSON.stringify(config.anchoring?.ancrage ?? null)}`);
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(REFERENCE_ANCRAGE, "utf8"));
  } catch (err) {
    throw new Error(`document d'ancrage illisible (${path.relative(RACINE, REFERENCE_ANCRAGE)}) : ${err.message}`);
  }
  controlerDocumentAncrage(doc, config);
}

/**
 * Lit le certificat d'une AC en PEM : un seul bloc CERTIFICATE, certificat
 * d'autorité (basicConstraints cA), lignes de base64 de 64 caractères au plus.
 * Rend le PEM normalisé (fin de ligne finale). Lève une Error décrite.
 */
export function lirePemAc(texte) {
  const m = /^-----BEGIN CERTIFICATE-----\n((?:[A-Za-z0-9+/=]{1,76}\n)+)-----END CERTIFICATE-----\n?$/.exec(String(texte));
  if (!m) throw new Error("--ac-horodatage : un seul certificat PEM attendu (bloc CERTIFICATE)");
  let x;
  try {
    x = new crypto.X509Certificate(texte);
  } catch (err) {
    throw new Error(`--ac-horodatage : certificat illisible (${err.message})`);
  }
  if (x.ca !== true) throw new Error("--ac-horodatage : certificat d'autorité (cA) attendu, celui de l'AC créée au pas IR-2");
  return `-----BEGIN CERTIFICATE-----\n${m[1]}-----END CERTIFICATE-----\n`;
}

/**
 * Document d'ancrage de l'installation rapide : le document de référence, dont
 * anchor_certificates reçoit le seul certificat de l'AC du serveur interne.
 * Lève une Error décrite.
 */
export function ancrageRapide({ acPem, configuration }) {
  const doc = JSON.parse(fs.readFileSync(REFERENCE_ANCRAGE, "utf8"));
  doc.rfc3161.providers[0].anchor_certificates = [lirePemAc(acPem)];
  controlerDocumentAncrage(doc, JSON.parse(configuration));
  return texteJSON(doc);
}

const RE_NOM = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** Configuration de l'installation rapide pour une organisation, un journal et un serveur d'outils. Lève une Error décrite. */
export function configurationRapide({ org, journal, serveurOutils }) {
  if (!RE_NOM.test(org)) throw new Error(`--org : nom court attendu (minuscules, chiffres, tirets), reçu ${JSON.stringify(org)}`);
  if (!RE_NOM.test(journal)) throw new Error(`--journal : nom attendu (minuscules, chiffres, tirets), reçu ${JSON.stringify(journal)}`);
  let url;
  try {
    url = new URL(serveurOutils);
  } catch {
    throw new Error(`--serveur-outils : URL invalide ${JSON.stringify(serveurOutils)}`);
  }
  if (url.protocol !== "https:") throw new Error("--serveur-outils : une URL https est exigée");
  const c = JSON.parse(fs.readFileSync(REFERENCE, "utf8"));
  c.recorder.org_id = orgIdOf(org);
  c.recorder.journal_id = journalIdOf(journal);
  c.policy.servers.outils.transport.url = serveurOutils;
  const schemas = ["configuration-enregistreur", "politique-redaction", "politique-approbation"].map((n) => JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", `${n}-v0.schema.json`), "utf8")));
  const erreurs = J.validerSchema(c, schemas[0], { registre: J.registreSchemas(schemas) });
  if (erreurs.length) throw new Error(`configuration invalide : ${erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ")}`);
  controlerAncrageRapide(c);
  return texteJSON(c);
}

function principal(argv) {
  let o;
  try {
    o = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { org: { type: "string" }, journal: { type: "string" }, "serveur-outils": { type: "string" }, sortie: { type: "string" }, "ac-horodatage": { type: "string" }, "sortie-ancrage": { type: "string" } } }).values;
    for (const k of ["org", "journal", "serveur-outils", "sortie"]) if (o[k] === undefined) throw new Error(`option --${k} requise`);
    if ((o["ac-horodatage"] === undefined) !== (o["sortie-ancrage"] === undefined)) throw new Error("--ac-horodatage et --sortie-ancrage vont ensemble");
  } catch (err) {
    process.stderr.write(`Erreur : ${messageOptions(err)}\nUsage : node scripts/deploiement/configurer-rapide.mjs --org <nom court> --journal <nom> --serveur-outils https://<serveur>/mcp --sortie <fichier> [--ac-horodatage <ac.pem> --sortie-ancrage <fichier>]\n`);
    return 2;
  }
  let texte;
  let ancrage = null;
  try {
    texte = configurationRapide({ org: o.org, journal: o.journal, serveurOutils: o["serveur-outils"] });
    if (o["ac-horodatage"] !== undefined) ancrage = ancrageRapide({ acPem: fs.readFileSync(o["ac-horodatage"], "utf8"), configuration: texte });
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  fs.writeFileSync(o.sortie, texte);
  if (ancrage !== null) fs.writeFileSync(o["sortie-ancrage"], ancrage);
  const c = JSON.parse(texte);
  const sha = (x) => crypto.createHash("sha256").update(x).digest("hex");
  process.stdout.write(`org_id ${c.recorder.org_id}\njournal_id ${c.recorder.journal_id}\nsha256 ${sha(texte)}\n${ancrage === null ? "" : `ancrage_sha256 ${sha(ancrage)}\n`}configuration valide\n`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
