// Configuration du serveur de console (CT-3 EX-10.13, contrat 2.3) :
// document `configuration-console-v0` analysé en JSON strict, validé contre
// les copies embarquées des schémas (répertoire `schemas/` du paquet), puis
// les règles d'EX-10.13 (révision 0.6 : `origine_port_par_defaut`,
// `url_illisible`) ; défauts des membres facultatifs ; résolution des
// références de secrets au démarrage, dont le refus est le rapport
// d'EX-10.14 (`reference_illisible`), qui nomme le pointeur, jamais la valeur.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import { RegistreSchemas, lireJsonStrict } from "@noortrace/approbation";
import { ErreurDemarrage, blocsPem, retirerBlancs } from "./outils.mjs";

/** Répertoire des copies des schémas (comparées à spec/schemas par les essais). */
export const REPERTOIRE_SCHEMAS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "schemas");

/** Fichiers des schémas embarqués (contrat 2.3) : sept copies, dont
 * `console-approbation-v0`, auquel `console-service-v0` fait référence. */
export const FICHIERS_SCHEMAS = Object.freeze([
  "configuration-console-v0.schema.json",
  "configuration-approbation-v0.schema.json",
  "annuaire-approbateurs-v0.schema.json",
  "evenement-v0.schema.json",
  "ticket-v0.schema.json",
  "console-service-v0.schema.json",
  "console-approbation-v0.schema.json",
]);

/** `$id` des deux schémas que lit le serveur. */
export const IDS = Object.freeze({
  configuration: "https://noortrace.example/schemas/v0/configuration-console.schema.json",
  service: "https://noortrace.example/schemas/v0/console-service.schema.json",
  evenement: "https://noortrace.example/schemas/v0/evenement.schema.json",
});

let registre = null;

/** Registre des schémas embarqués, chargé une fois. */
export function registreSchemas() {
  if (registre) return registre;
  const r = new RegistreSchemas();
  for (const f of FICHIERS_SCHEMAS) r.ajouter(JSON.parse(fs.readFileSync(path.join(REPERTOIRE_SCHEMAS, f), "utf8")));
  registre = r;
  return r;
}

/** Vrai si `valeur` est conforme à `$defs/<nom>` de `console-service-v0`. */
export const conformeService = (nom, valeur) => registreSchemas().estValide(`${IDS.service}#/$defs/${nom}`, valeur);

/** Défauts des membres facultatifs (descriptions du schéma, 10.3). */
export const DEFAUTS = Object.freeze({
  reauth_max_age_s: 900,
  service_timeout_ms: 10000,
  delai_signature_ms: 300000,
  session_max_age_s: 28800,
  id_token_signing_alg_values: Object.freeze(["RS256"]),
  cache_s: 3600,
  walletconnect: null,
});

const comparer = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Tri des erreurs : par pointeur puis par code, en unités UTF-16 (EX-10.12). */
const trier = (errors) => errors.sort((x, y) => comparer(x.pointer, y.pointer) || comparer(x.code, y.code));

/**
 * Hôte d'une URL `http://` du schéma est une adresse de boucle locale
 * (`127.0.0.1`, `::1` ou `localhost`, EX-10.12), écrite telle quelle.
 * @param {string} url
 */
export function versBoucleLocale(url) {
  const m = /^http:\/\/(\[[^\]]*\]|[^:]*)(?::[0-9]*)?$/.exec(url);
  return m !== null && ["127.0.0.1", "[::1]", "localhost"].includes(m[1]);
}

/**
 * Vrai si `url` (déjà conforme au motif du schéma) s'analyse comme une URL
 * absolue (RFC 3986) dont le port, s'il est écrit, est un entier de 1 à
 * 65 535 (règle `url_illisible`, EX-10.13, révision 0.6).
 * @param {string} url
 */
export function urlLisible(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.hostname === "") return false;
  const autorite = url.slice(url.indexOf("//") + 2);
  const m = /^(\[[^\]]*\]|[^:\[\]]*)(?::(.*))?$/.exec(autorite);
  if (m === null) return false;
  if (m[2] === undefined) return true;
  if (!/^[0-9]{1,5}$/.test(m[2])) return false;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535;
}

/**
 * Erreurs d'un document déjà analysé : `schema` au pointeur de chaque membre
 * fautif, ou, document conforme, les règles d'EX-10.13.
 * @param {unknown} doc
 * @returns {{code: string, pointer: string}[]}
 */
export function erreursDocument(doc) {
  const v = registreSchemas().valider(IDS.configuration, doc);
  if (!v.valide) return trier([...new Set(v.erreurs.map((e) => e.pointeur))].map((pointer) => ({ code: "schema", pointer })));
  const errors = [];
  if (doc.environment === "production" && doc.identity.kind !== "oidc") errors.push({ code: "identite_locale_en_production", pointer: "/identity/kind" });
  const url = doc.service.url ?? null;
  if (url !== null && !url.startsWith("https://") && !versBoucleLocale(url)) errors.push({ code: "tls_exige", pointer: "/service/url" });
  const nonNul = (k) => doc.service[k] !== undefined && doc.service[k] !== null;
  if (!nonNul("token") && !nonNul("client_cert")) errors.push({ code: "authentification_exigee", pointer: "/service" });
  if (nonNul("client_cert") !== nonNul("client_key")) errors.push({ code: "certificat_client_incomplet", pointer: "/service" });
  // Révision 0.6 : le navigateur omet le port par défaut dans `Host` et
  // `Origin` ; une origine qui l'écrit ferait refuser chaque requête.
  if (doc.console_origin.endsWith(":443")) errors.push({ code: "origine_port_par_defaut", pointer: "/console_origin" });
  if (url !== null && !urlLisible(url)) errors.push({ code: "url_illisible", pointer: "/service/url" });
  return trier(errors);
}

/**
 * Rapport d'EX-10.13 (`$defs/rapport_validation`) sur les octets d'un
 * document, sans lire de secret.
 * @param {string|Uint8Array} octets
 * @returns {{valide: boolean, errors: {code: string, pointer: string}[]}}
 */
export function validerConfiguration(octets) {
  let doc;
  try {
    doc = lireJsonStrict(octets);
  } catch {
    return { valide: false, errors: [{ code: "json", pointer: "" }] };
  }
  const errors = erreursDocument(doc);
  return { valide: errors.length === 0, errors };
}

/**
 * Document complété de ses défauts (copie).
 * @param {object} doc document conforme
 */
export function completer(doc) {
  const c = structuredClone(doc);
  for (const k of ["reauth_max_age_s", "service_timeout_ms", "delai_signature_ms", "session_max_age_s", "walletconnect"]) {
    if (c[k] === undefined) c[k] = DEFAUTS[k];
  }
  for (const k of ["token", "ca", "client_cert", "client_key"]) if (c.service[k] === undefined) c.service[k] = null;
  if (c.service.url === undefined) c.service.url = null;
  if (c.service.socket === undefined) c.service.socket = null;
  if (c.identity.kind === "oidc") {
    if (c.identity.id_token_signing_alg_values === undefined) c.identity.id_token_signing_alg_values = [...DEFAUTS.id_token_signing_alg_values];
    if (c.identity.cache_s === undefined) c.identity.cache_s = DEFAUTS.cache_s;
  }
  return c;
}

/**
 * Refus au démarrage d'EX-10.14 : ligne `$defs/rapport_validation` d'une
 * erreur, sans valeur secrète.
 * @param {"reference_illisible"|"ecoute_impossible"|"parcours_non_offert"} code
 * @param {string} pointeur
 * @param {string} message texte du journal, sans valeur secrète
 */
export const refusDemarrage = (code, pointeur, message) =>
  new ErreurDemarrage(message, { pointeur, rapport: { valide: false, errors: [{ code, pointer: pointeur }] } });

const refus = (pointeur, quoi) => refusDemarrage("reference_illisible", pointeur, `référence ${quoi} : ${pointeur}`);

/**
 * Lit une référence de secret (`{ file }`, relatif au répertoire de la
 * configuration s'il n'est pas absolu, ou `{ env }`).
 * @param {{file?: string, env?: string}} ref
 * @param {string} base
 * @param {string} pointeur
 * @returns {Buffer}
 */
export function lireReference(ref, base, pointeur) {
  if (ref.env !== undefined) {
    const v = process.env[ref.env];
    if (v === undefined) throw refus(pointeur, "illisible");
    return Buffer.from(v, "utf8");
  }
  try {
    return fs.readFileSync(path.resolve(base, ref.file));
  } catch {
    throw refus(pointeur, "illisible");
  }
}

/** Texte UTF-8 valide d'octets, ou `null`. */
function utf8(octets) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(octets);
  } catch {
    return null;
  }
}

/** Certificats PEM (au moins un, chacun lisible), dans l'ordre. */
function certificats(octets, pointeur) {
  const t = utf8(octets);
  const blocs = t === null ? [] : blocsPem(t, "CERTIFICATE");
  if (blocs.length === 0) throw refus(pointeur, "mal formée");
  try {
    for (const b of blocs) new crypto.X509Certificate(b);
  } catch {
    throw refus(pointeur, "mal formée");
  }
  return blocs;
}

/** Clé privée PEM. */
function clePrivee(octets, pointeur) {
  const t = utf8(octets);
  const bloc = t === null ? null : /-----BEGIN ([A-Z ]*)PRIVATE KEY-----\r?\n[\s\S]*?-----END \1PRIVATE KEY-----/.exec(t);
  if (!bloc) throw refus(pointeur, "mal formée");
  try {
    return crypto.createPrivateKey(bloc[0]).export({ type: "pkcs8", format: "pem" });
  } catch {
    throw refus(pointeur, "mal formée");
  }
}

/**
 * Résout les références de la configuration complétée (contrat 2.3) ;
 * lève `ErreurDemarrage` en nommant le pointeur.
 * @param {object} c configuration complétée
 * @param {string} base répertoire du fichier de configuration
 */
export function resoudreReferences(c, base) {
  const lire = (ref, p) => lireReference(ref, base, p);
  const tlsCert = certificats(lire(c.tls.cert, "/tls/cert"), "/tls/cert");
  const tlsCle = clePrivee(lire(c.tls.key, "/tls/key"), "/tls/key");
  try {
    tls.createSecureContext({ cert: tlsCert.join(""), key: tlsCle });
  } catch {
    throw refus("/tls/key", "mal formée");
  }
  const s = c.service;
  let jeton = null;
  if (s.token !== null) {
    const t = utf8(lire(s.token, "/service/token"));
    jeton = t === null ? null : retirerBlancs(t);
    if (jeton === null || !/^[\x21-\x7e]{16,1024}$/.test(jeton)) throw refus("/service/token", "mal formée");
  }
  const ca = s.ca === null ? null : certificats(lire(s.ca, "/service/ca"), "/service/ca").join("");
  const certClient = s.client_cert === null ? null : certificats(lire(s.client_cert, "/service/client_cert"), "/service/client_cert").join("");
  const cleClient = s.client_key === null ? null : clePrivee(lire(s.client_key, "/service/client_key"), "/service/client_key");
  if (certClient !== null) {
    try {
      tls.createSecureContext({ cert: certClient, key: cleClient });
    } catch {
      throw refus("/service/client_key", "mal formée");
    }
  }
  const resolu = { tls: { cert: tlsCert.join(""), key: tlsCle }, service: { jeton, ca, certClient, cleClient }, identity: {} };
  if (c.identity.kind === "oidc") {
    const t = utf8(lire(c.identity.client_secret, "/identity/client_secret"));
    const secret = t === null ? "" : retirerBlancs(t);
    if (secret === "") throw refus("/identity/client_secret", "mal formée");
    resolu.identity.secret = secret;
  } else {
    let doc;
    try {
      doc = lireJsonStrict(lire(c.identity.accounts, "/identity/accounts"));
    } catch (e) {
      if (e instanceof ErreurDemarrage) throw e;
      throw refus("/identity/accounts", "mal formée");
    }
    if (!registreSchemas().estValide(`${IDS.configuration}#/$defs/fichier_comptes`, doc)) throw refus("/identity/accounts", "mal formée");
    const comptes = new Map();
    for (const a of doc.accounts) {
      if (comptes.has(a.name)) throw refus("/identity/accounts", "mal formée");
      comptes.set(a.name, { salt: Buffer.from(a.salt, "hex"), key: Buffer.from(a.key, "hex") });
    }
    resolu.identity.comptes = comptes;
  }
  return resolu;
}
