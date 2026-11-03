// Requêtes exactes du support WORM (CT-2 EX-12.39), sans réseau : cible
// relative au service (sans hôte), en-têtes que fixe NOORTRACE triés par nom
// en minuscules, corps. `Host`, `Date`, `x-amz-date`, `x-ms-date`,
// `Authorization` et les en-têtes de signature sont ajoutés par la couche
// d'accès du support (s3.mjs, azure.mjs, gcs.mjs) et n'en font pas partie.
// La famille de vecteurs `worm/requetes.json` (annexe B.9) les fixe octet pour
// octet.

import { createHash } from "node:crypto";
import { sha256Hex } from "@noortrace/noyau";
import { jcsIntegralOctets } from "../jcs-integral.mjs";

/** Version d'API Azure de toutes les requêtes (EX-12.39). */
export const VERSION_AZURE = "2020-06-12";

const ESPACE_S3 = "http://s3.amazonaws.com/doc/2006-03-01/";
const DECLARATION_XML = '<?xml version="1.0" encoding="UTF-8"?>';
const NON_RESERVES = /^[A-Za-z0-9\-._~]$/;

/**
 * Encode une clé ou une valeur de paramètre octet par octet (EX-12.39) :
 * chaque octet UTF-8 hors des non réservés de la RFC 3986 devient `%XX`
 * (hexadécimal majuscule) ; `/` est gardé si `garderBarre`.
 * @param {string} texte
 * @param {boolean} [garderBarre]
 * @returns {string}
 */
export function encoderComposant(texte, garderBarre = false) {
  let r = "";
  for (const o of Buffer.from(texte, "utf8")) {
    const c = String.fromCharCode(o);
    if (o < 0x80 && (NON_RESERVES.test(c) || (garderBarre && c === "/"))) r += c;
    else r += `%${o.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return r;
}

/**
 * `Content-MD5` de la RFC 1864 : base64 des 16 octets du MD5 du corps.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function contentMd5(octets) {
  return createHash("md5").update(octets).digest("base64");
}

function trier(entetes) {
  return [...entetes].sort((a, b) => {
    const x = a[0].toLowerCase();
    const y = b[0].toLowerCase();
    return x < y ? -1 : x > y ? 1 : 0;
  });
}

function requete(method, target, entetes, corps) {
  return { method, target, headers: trier(entetes), body: corps };
}

function avecCorpsMd5(entetes, corps) {
  return [["Content-Length", String(corps.length)], ["Content-MD5", contentMd5(corps)], ...entetes];
}

const cibleS3 = (cle) => `/${encoderComposant(cle, true)}`;

/** Corps XML de `PutObjectLegalHold` (128 octets pour ON, 129 pour OFF). */
export function corpsGelS3(pose) {
  return Buffer.from(`${DECLARATION_XML}<LegalHold xmlns="${ESPACE_S3}"><Status>${pose ? "ON" : "OFF"}</Status></LegalHold>`, "utf8");
}

/** Corps XML de `PutObjectLockConfiguration` (EX-12.30) : COMPLIANCE, `Days`. */
export function corpsConfigurationVerrou(jours, mode = "COMPLIANCE") {
  return Buffer.from(
    `${DECLARATION_XML}<ObjectLockConfiguration xmlns="${ESPACE_S3}"><ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
      `<Rule><DefaultRetention><Days>${jours}</Days><Mode>${mode}</Mode></DefaultRetention></Rule></ObjectLockConfiguration>`,
    "utf8",
  );
}

/** S3, poser ou lever un gel : `PUT /<clé>?legal-hold&versionId=<version>`. */
export function requeteS3Gel(cle, versionId, pose) {
  const corps = corpsGelS3(pose);
  return requete("PUT", `${cibleS3(cle)}?legal-hold&versionId=${encoderComposant(versionId)}`, avecCorpsMd5([], corps), corps);
}

/** S3, lire le gel : `GET /<clé>?legal-hold&versionId=<version>`. */
export function requeteS3LireGel(cle, versionId) {
  return requete("GET", `${cibleS3(cle)}?legal-hold&versionId=${encoderComposant(versionId)}`, [], null);
}

/**
 * S3, lire l'état d'une version : `HEAD /<clé>?versionId=<version>` ; sans
 * identifiant de version (support qui n'en rend pas, EX-12.29 : `null`), la
 * version courante.
 */
export function requeteS3Etat(cle, versionId) {
  return requete("HEAD", versionId === null ? cibleS3(cle) : `${cibleS3(cle)}?versionId=${encoderComposant(versionId)}`, [], null);
}

/**
 * S3, lister les versions : paramètres dans l'ordre de la syntaxe de la page
 * (`versions`, `key-marker`, `max-keys`, `prefix`, `version-id-marker`).
 * @param {{prefix: string, keyMarker?: string|null, versionIdMarker?: string|null}} p
 */
export function requeteS3Liste(p) {
  let t = "/?versions";
  if (p.keyMarker) t += `&key-marker=${encoderComposant(p.keyMarker)}`;
  t += "&max-keys=1000";
  t += `&prefix=${encoderComposant(p.prefix ?? "")}`;
  if (p.versionIdMarker) t += `&version-id-marker=${encoderComposant(p.versionIdMarker)}`;
  return requete("GET", t, [], null);
}

/** S3, rétention par défaut posée par l'exploitant (EX-12.30) : `PUT /?object-lock`. */
export function requeteS3ConfigurationVerrou(jours, mode = "COMPLIANCE") {
  const corps = corpsConfigurationVerrou(jours, mode);
  return requete("PUT", "/?object-lock", avecCorpsMd5([], corps), corps);
}

/** S3, lire la rétention par défaut (EX-17.5) : `GET /?object-lock`. */
export function requeteS3LireConfiguration() {
  return requete("GET", "/?object-lock", [], null);
}

/**
 * S3, copier (EX-12.16) : `PUT /<clé>`, conditionnelle à l'absence, avec
 * `x-amz-object-lock-legal-hold: ON` sous `legal_hold_on_write` (EX-12.31) ;
 * ni mode ni échéance de rétention (EX-12.30).
 * @param {string} cle
 * @param {Uint8Array} octets
 * @param {boolean} [gelAEcriture]
 */
export function requeteS3Copie(cle, octets, gelAEcriture = false) {
  const corps = Buffer.from(octets);
  const entetes = [["If-None-Match", "*"]];
  if (gelAEcriture) entetes.push(["x-amz-object-lock-legal-hold", "ON"]);
  return requete("PUT", cibleS3(cle), avecCorpsMd5(entetes, corps), corps);
}

/**
 * S3, écriture conditionnelle d'un objet du registre des gels (EX-12.37) :
 * même forme que la copie, sans gel à l'écriture.
 */
export function requeteS3EcritureConditionnelle(cle, octets) {
  return requeteS3Copie(cle, octets, false);
}

/** S3, lire un objet (version donnée ou courante) : `GET /<clé>[?versionId=<version>]`. */
export function requeteS3Lire(cle, versionId = null) {
  return requete("GET", versionId ? `${cibleS3(cle)}?versionId=${encoderComposant(versionId)}` : cibleS3(cle), [], null);
}

const cibleAzure = (conteneur, cle) => `/${encoderComposant(conteneur, true)}/${encoderComposant(cle, true)}`;

/** Azure, poser ou lever un gel de niveau version (`Set Blob Legal Hold`). */
export function requeteAzureGel(conteneur, cle, versionId, pose) {
  return requete(
    "PUT",
    `${cibleAzure(conteneur, cle)}?comp=legalhold&versionid=${encoderComposant(versionId)}`,
    [["Content-Length", "0"], ["x-ms-legal-hold", pose ? "true" : "false"], ["x-ms-version", VERSION_AZURE]],
    null,
  );
}

/** Azure, lire l'état d'une version (`Get Blob Properties`). */
export function requeteAzureEtat(conteneur, cle, versionId) {
  return requete("HEAD", `${cibleAzure(conteneur, cle)}?versionid=${encoderComposant(versionId)}`, [["x-ms-version", VERSION_AZURE]], null);
}

const cibleGcs = (bucket, cle) => `/storage/v1/b/${encoderComposant(bucket)}/o/${encoderComposant(cle)}`;

/** GCS, poser ou lever un gel (`temporaryHold`) par `PATCH` de l'API JSON. */
export function requeteGcsGel(bucket, cle, generation, pose) {
  const corps = Buffer.from(jcsIntegralOctets({ temporaryHold: pose }));
  return requete(
    "PATCH",
    `${cibleGcs(bucket, cle)}?generation=${encoderComposant(generation)}`,
    [["Content-Length", String(corps.length)], ["Content-Type", "application/json"]],
    corps,
  );
}

/** GCS, lire l'état d'une génération (ressource objet de l'API JSON). */
export function requeteGcsEtat(bucket, cle, generation) {
  return requete("GET", `${cibleGcs(bucket, cle)}?generation=${encoderComposant(generation)}`, [], null);
}

/**
 * Requête d'une opération de la famille `worm/requetes` (entrées du cas).
 * @param {object} e entrées (`operation`, `bucket`, `key`, `version_id`, `hold`, `prefix`,
 *   `key_marker`, `version_id_marker`, `retain_days`, `body_utf8`, `legal_hold_on_write`)
 */
export function requeteOperation(e) {
  switch (e.operation) {
    case "s3_gel": return requeteS3Gel(e.key, e.version_id, e.hold);
    case "s3_lire_gel": return requeteS3LireGel(e.key, e.version_id);
    case "s3_etat": return requeteS3Etat(e.key, e.version_id);
    case "s3_liste": return requeteS3Liste({ prefix: e.prefix, keyMarker: e.key_marker, versionIdMarker: e.version_id_marker });
    case "s3_configuration_verrou": return requeteS3ConfigurationVerrou(e.retain_days);
    case "s3_lire_configuration": return requeteS3LireConfiguration();
    case "s3_copie": return requeteS3Copie(e.key, Buffer.from(e.body_utf8 ?? "", "utf8"), e.legal_hold_on_write === true);
    case "azure_gel": return requeteAzureGel(e.bucket, e.key, e.version_id, e.hold);
    case "azure_etat": return requeteAzureEtat(e.bucket, e.key, e.version_id);
    case "gcs_gel": return requeteGcsGel(e.bucket, e.key, e.version_id, e.hold);
    case "gcs_etat": return requeteGcsEtat(e.bucket, e.key, e.version_id);
    default: throw new Error(`opération inconnue : ${e.operation}`);
  }
}

/**
 * Forme publiée d'une requête (`expected` des vecteurs) : corps en UTF-8,
 * longueur et SHA-256 en hexadécimal `0x`, `null` sans corps.
 * @param {{method: string, target: string, headers: string[][], body: Uint8Array|null}} r
 */
export function formeRequete(r) {
  return {
    method: r.method,
    target: r.target,
    headers: r.headers.map(([n, v]) => [n, v]),
    body_utf8: r.body ? Buffer.from(r.body).toString("utf8") : null,
    body_length: r.body ? r.body.length : 0,
    body_sha256: r.body ? sha256Hex(r.body) : null,
  };
}
