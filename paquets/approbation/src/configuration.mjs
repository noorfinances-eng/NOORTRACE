// Configuration du service d'approbation (CT-3 10.3, EX-10.12 ; CT-7
// EX-3.10) : document `configuration-approbation-v0`, analysé en JSON strict,
// contrôlé par son schéma puis par les règles d'EX-10.12 que le schéma
// n'exprime pas ; ses références de secrets (fichier ou variable
// d'environnement) ne sont résolues qu'au démarrage.
//
// `validerConfiguration` est la validation hors secrets de la commande
// `noortrace-approbation valider-configuration` : rapport
// `$defs/rapport_validation`, erreurs `{ code, pointer }` triées par pointeur
// puis par code (unités UTF-16). Un document non conforme au schéma ne donne
// que des erreurs `schema` ; les règles ne sont alors pas évaluées.
//
// `resoudreSecrets` lit chaque référence au démarrage et refuse, en nommant
// le pointeur et jamais la valeur (code `reference_illisible`, EX-10.14), un
// secret illisible ou mal formé : clé de stockage brute de 32 octets prise
// telle quelle, sinon 64 chiffres hexadécimaux (préfixe 0x facultatif) après
// retrait des espaces de tête et de fin ; jetons des canaux et `rpc.token` de
// 16 à 1 024 caractères, `notifications.key` de 32 à 1 024, ASCII imprimables
// au sens de la révision 0.6 d'EX-10.12, de U+0021 à U+007E, sans espace
// intérieure, pour ces quatre secrets, la clé du webhook comprise ;
// certificats et clés TLS en PEM, le certificat du serveur en tête.
//
// Boucle locale (EX-10.12, révision 0.6) : `127.0.0.1`, `::1` (`[::1]` dans
// une URL) ou `localhost`, écrits exactement ainsi, en minuscules, comparés
// au texte de l'hôte tel qu'il est écrit dans le document, avant toute
// normalisation (`127.1` ou `LOCALHOST` n'en sont pas).

import fs from "node:fs";
import path from "node:path";
import { X509Certificate, createPrivateKey } from "node:crypto";
import { lireJsonStrict, comparerChaines } from "./json.mjs";
import { IDS, registreSchemas } from "./schema.mjs";

/** Adresses de boucle locale d'EX-10.12. */
export const BOUCLE_LOCALE = Object.freeze(["127.0.0.1", "::1", "localhost"]);

/** Valeurs par défaut des membres facultatifs (descriptions du schéma). */
export const DEFAUTS = Object.freeze({
  max_open_tickets: 20,
  set_poll_interval_ms: 10000,
  registration_ttl_ms: 600000,
  remise_representation_ms: 30000,
  body_max_bytes: 16 * 1024 * 1024,
  rpc_timeout_ms: 5000,
  notifications_timeout_ms: 10000,
  socket_mode: "0660",
});

/** Codes des règles d'EX-10.12. */
export const CODES_CONFIGURATION = Object.freeze([
  "json", "schema", "rpc_non_declare", "rpc_tls", "tls_exige", "authentification_exigee", "jeton_exige_production",
  "jetons_egaux", "escalade_non_croissante", "webhook_http", "origine_port_par_defaut",
]);

/** Codes que seul le démarrage décèle (EX-10.14), jamais rendus par la validation. */
export const CODES_DEMARRAGE = Object.freeze(["reference_illisible", "jetons_egaux", "ecoute_impossible"]);

const objet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Hôte de boucle locale (`[::1]` d'une URL compris), comparé au texte écrit,
 * sans normalisation ni changement de casse (EX-10.12, révision 0.6).
 */
export function estBoucleLocale(hote) {
  const h = String(hote);
  return BOUCLE_LOCALE.includes(h) || h === "[::1]";
}

/**
 * Hôte d'une URL tel qu'il est écrit (sans normalisation), ou null : texte
 * entre `//` (après d'éventuelles informations d'utilisateur) et le port, le
 * chemin, la requête ou le fragment.
 * @param {string} url
 */
export function hoteEcrit(url) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/.exec(String(url));
  return m ? m[1] : null;
}

/** `console_origin` porte-t-elle le port par défaut (443) écrit en clair (règle origine_port_par_defaut) ? */
export function originePortParDefaut(origine) {
  return /^https:\/\/(?:\[[^\]]*\]|[^:/?#]*):443$/i.test(String(origine));
}

/** Erreur de configuration : liste d'erreurs `{ code, pointer }`, jamais une valeur de secret. */
export class ErreurConfiguration extends Error {
  /** @param {{code: string, pointer: string}[]} erreurs */
  constructor(erreurs) {
    super(`configuration refusée : ${erreurs.map((e) => `${e.code} ${e.pointer}`).join(", ")}`);
    this.name = "ErreurConfiguration";
    this.erreurs = erreurs;
  }
}

/** Trie des erreurs par pointeur puis par code (unités UTF-16), sans doublon. */
export function trierErreurs(erreurs) {
  const vues = new Set();
  const r = [];
  for (const e of erreurs) {
    const k = `${e.pointer}\u0000${e.code}`;
    if (vues.has(k)) continue;
    vues.add(k);
    r.push({ code: e.code, pointer: e.pointer });
  }
  return r.sort((a, b) => comparerChaines(a.pointer, b.pointer) || comparerChaines(a.code, b.code));
}

/** URL `https`, ou `http` vers la boucle locale hors production (règles rpc_tls, webhook_http). */
function urlAdmise(url, environment) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && environment !== "production" && estBoucleLocale(hoteEcrit(url));
}

/** Forme normale d'une référence de secret, pour la règle jetons_egaux (par référence). */
function cleReference(ref, base) {
  if (!objet(ref)) return null;
  if (typeof ref.file === "string") return `file:${base ? path.resolve(base, ref.file) : ref.file}`;
  if (typeof ref.env === "string") return `env:${ref.env}`;
  return null;
}

/**
 * Règles d'EX-10.12 sur un document conforme au schéma.
 * @param {object} c
 * @param {{base?: string}} [o] répertoire du fichier, pour comparer les références `file`
 * @returns {{code: string, pointer: string}[]}
 */
export function reglesConfiguration(c, o = {}) {
  const e = [];
  const prod = c.environment === "production";
  // rpc_non_declare (CT-7 EX-3.10, MN-51)
  if (prod) {
    if (c.rpc === undefined || c.rpc === null) e.push({ code: "rpc_non_declare", pointer: "/rpc" });
    else if (c.rpc.validator !== "client" && c.rpc.validator !== "partenaire") e.push({ code: "rpc_non_declare", pointer: "/rpc/validator" });
  }
  // rpc_tls
  if (objet(c.rpc) && !urlAdmise(c.rpc.url, c.environment)) e.push({ code: "rpc_tls", pointer: "/rpc/url" });
  for (const canal of ["noyau", "console"]) {
    const l = c[canal];
    if (!objet(l)) continue;
    const ici = `/${canal}`;
    const tcp = objet(l.tcp) ? l.tcp : null;
    const tls = objet(l.tls) ? l.tls : null;
    const jeton = l.token !== undefined && l.token !== null;
    const mtls = tls !== null && tls.client_ca !== undefined && tls.client_ca !== null;
    if (tcp && !estBoucleLocale(tcp.host) && tls === null) e.push({ code: "tls_exige", pointer: ici });
    if ((canal === "console" || tcp) && !jeton && !mtls) e.push({ code: "authentification_exigee", pointer: ici });
    if (prod && typeof l.socket === "string" && !jeton) e.push({ code: "jeton_exige_production", pointer: ici });
  }
  if (objet(c.noyau) && objet(c.console)) {
    const a = cleReference(c.noyau.token, o.base);
    const b = cleReference(c.console.token, o.base);
    if (a !== null && a === b) e.push({ code: "jetons_egaux", pointer: "/console/token" });
  }
  if (Array.isArray(c.escalation)) {
    for (let k = 1; k < c.escalation.length; k++) {
      if (!(c.escalation[k].after_ms > c.escalation[k - 1].after_ms)) {
        e.push({ code: "escalade_non_croissante", pointer: `/escalation/${k}/after_ms` });
        break;
      }
    }
  }
  if (objet(c.notifications) && !urlAdmise(c.notifications.url, c.environment)) e.push({ code: "webhook_http", pointer: "/notifications/url" });
  // origine_port_par_defaut (révision 0.6) : le navigateur omet le port 443 de l'origine
  if (typeof c.console_origin === "string" && originePortParDefaut(c.console_origin)) e.push({ code: "origine_port_par_defaut", pointer: "/console_origin" });
  return e;
}

/**
 * Valide un document de configuration sans lire de secret (EX-10.12).
 * @param {unknown} doc
 * @param {{base?: string}} [o]
 * @returns {{valide: boolean, errors: {code: string, pointer: string}[]}}
 */
export function validerConfiguration(doc, o = {}) {
  const r = registreSchemas().valider(IDS.configuration, doc, { detailler: true });
  let errors;
  if (!r.valide) errors = r.erreurs.map((x) => ({ code: "schema", pointer: x.pointeur }));
  else errors = reglesConfiguration(doc, o);
  errors = trierErreurs(errors);
  return { valide: errors.length === 0, errors };
}

/**
 * Lit et valide un fichier de configuration, sans secret.
 * @param {string} chemin
 * @returns {{document: unknown, rapport: {valide: boolean, errors: object[]}}}
 */
export function lireEtValiderConfiguration(chemin) {
  let doc;
  try {
    doc = lireJsonStrict(fs.readFileSync(chemin));
  } catch {
    return { document: null, rapport: { valide: false, errors: [{ code: "json", pointer: "" }] } };
  }
  return { document: doc, rapport: validerConfiguration(doc, { base: path.dirname(path.resolve(chemin)) }) };
}

// ---------------------------------------------------------------- secrets

/**
 * Lit une référence de secret (fichier relatif au répertoire de la
 * configuration, ou variable d'environnement non vide).
 * @param {{file?: string, env?: string}} ref
 * @param {string} base
 * @returns {Buffer}
 */
export function lireSecret(ref, base) {
  if (ref.env !== undefined) {
    const v = process.env[ref.env];
    if (v === undefined || v === "") throw new Error("variable absente");
    return Buffer.from(v, "utf8");
  }
  return fs.readFileSync(path.resolve(base, ref.file));
}

const ESPACES = /^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g;

/** Clé de stockage (EX-10.12) : 32 octets bruts tels quels, sinon 64 chiffres hexadécimaux. */
export function decoderCle(octets) {
  if (octets.length === 32) return new Uint8Array(octets);
  const t = octets.toString("latin1").replace(ESPACES, "").replace(/^0x/, "");
  if (/^[0-9a-fA-F]{64}$/.test(t)) return new Uint8Array(Buffer.from(t, "hex"));
  throw new Error("clé de stockage mal formée");
}

function decoderTexte(octets, min, max) {
  const t = octets.toString("latin1").replace(ESPACES, "");
  if (t.length < min || t.length > max || !/^[\x21-\x7e]*$/.test(t)) throw new Error("secret mal formé");
  return t;
}

/** Jeton d'un canal ou du point RPC : 16 à 1 024 caractères ASCII imprimables. */
export function decoderJeton(octets) {
  return decoderTexte(octets, 16, 1024);
}

/**
 * Clé HMAC du webhook (EX-13.41) : 32 à 1 024 caractères ASCII imprimables,
 * sans espace intérieure (EX-10.12, révision 0.6, qui vaut pour les quatre
 * secrets textuels, `notifications.key` compris).
 */
export function decoderCleWebhook(octets) {
  return decoderTexte(octets, 32, 1024);
}

const BLOC_CERTIFICAT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Chaîne de certificats PEM, le premier étant le certificat du serveur ; rend le texte PEM. */
export function decoderCertificats(octets) {
  const blocs = octets.toString("utf8").match(BLOC_CERTIFICAT) ?? [];
  if (blocs.length === 0) throw new Error("certificat PEM attendu");
  for (const b of blocs) new X509Certificate(b);
  return blocs.join("\n") + "\n";
}

const BLOC_CLE = /-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]+?-----END \1PRIVATE KEY-----/;

/** Clé privée PEM (le fichier peut porter aussi la chaîne de certificats) ; rend le bloc de la clé. */
export function decoderClePrivee(octets) {
  const m = BLOC_CLE.exec(octets.toString("utf8"));
  if (!m) throw new Error("clé PEM attendue");
  createPrivateKey(m[0]);
  return m[0] + "\n";
}

/**
 * Résout les secrets d'une configuration validée (EX-10.12). Lève
 * ErreurConfiguration : code `reference_illisible` (EX-10.14) au pointeur de
 * chaque référence illisible ou mal formée, puis `jetons_egaux` entre deux
 * valeurs.
 * @param {object} c configuration complétée
 * @param {string} base répertoire du fichier de configuration
 */
export function resoudreSecrets(c, base) {
  const erreurs = [];
  const lire = (ref, pointeur, decoder) => {
    if (ref === undefined || ref === null) return null;
    try {
      return decoder(lireSecret(ref, base));
    } catch {
      erreurs.push({ code: "reference_illisible", pointer: pointeur });
      return null;
    }
  };
  const ecoute = (l, ici) => {
    if (!l || !l.tls) return null;
    return {
      cert: lire(l.tls.cert, `${ici}/tls/cert`, decoderCertificats),
      key: lire(l.tls.key, `${ici}/tls/key`, decoderClePrivee),
      ca: lire(l.tls.client_ca, `${ici}/tls/client_ca`, decoderCertificats),
    };
  };
  const s = {
    cle: lire(c.storage_key, "/storage_key", decoderCle),
    jetonNoyau: lire(c.noyau.token, "/noyau/token", decoderJeton),
    jetonConsole: c.console ? lire(c.console.token, "/console/token", decoderJeton) : null,
    jetonRpc: c.rpc ? lire(c.rpc.token, "/rpc/token", decoderJeton) : null,
    cleWebhook: c.notifications ? lire(c.notifications.key, "/notifications/key", decoderCleWebhook) : null,
    caWebhook: c.notifications ? lire(c.notifications.ca, "/notifications/ca", decoderCertificats) : null,
    tls: { noyau: ecoute(c.noyau, "/noyau"), console: ecoute(c.console, "/console") },
  };
  if (erreurs.length) throw new ErreurConfiguration(trierErreurs(erreurs));
  if (!jetonsDistincts(s)) throw new ErreurConfiguration([{ code: "jetons_egaux", pointer: "/console/token" }]);
  return s;
}

/**
 * Les jetons résolus du noyau et de la console sont-ils distincts (EX-12.4,
 * règle jetons_egaux par valeur) ?
 * @param {{jetonNoyau: string|null, jetonConsole: string|null}} s
 */
export function jetonsDistincts(s) {
  return s.jetonNoyau === null || s.jetonConsole === null || s.jetonNoyau !== s.jetonConsole;
}

// ---------------------------------------------------------------- défauts

function completerEcoute(l) {
  if (!objet(l)) return l ?? null;
  const r = { socket: null, socket_mode: DEFAUTS.socket_mode, tcp: null, tls: null, token: null, ...l };
  if (objet(r.tls)) r.tls = { client_ca: null, ...r.tls };
  return r;
}

/**
 * Complète les membres facultatifs absents par leur défaut (descriptions du
 * schéma) ; le document n'est pas modifié.
 * @param {object} c document validé
 */
export function completer(c) {
  const r = {
    console: null,
    etat: null,
    tickets: { epoch: null },
    max_open_tickets: DEFAUTS.max_open_tickets,
    escalation: [],
    set_poll_interval_ms: DEFAUTS.set_poll_interval_ms,
    registration_ttl_ms: DEFAUTS.registration_ttl_ms,
    rpc: null,
    notifications: null,
    remise_representation_ms: DEFAUTS.remise_representation_ms,
    body_max_bytes: DEFAUTS.body_max_bytes,
    ...c,
  };
  r.tickets = { epoch: null, ...(r.tickets ?? {}) };
  r.noyau = completerEcoute(r.noyau);
  r.console = completerEcoute(r.console);
  if (objet(r.console)) r.console = { annuaire: null, ...r.console };
  if (objet(r.rpc)) r.rpc = { token: null, timeout_ms: DEFAUTS.rpc_timeout_ms, logs_from_block: 0, ...r.rpc };
  if (objet(r.notifications)) r.notifications = { ca: null, timeout_ms: DEFAUTS.notifications_timeout_ms, ...r.notifications };
  return r;
}

/**
 * Lit, valide et complète un fichier de configuration ; résout ses secrets.
 * @param {string} chemin
 * @returns {{config: object, secrets: object, base: string}}
 * @throws {ErreurConfiguration}
 */
export function chargerConfiguration(chemin) {
  const { document, rapport } = lireEtValiderConfiguration(chemin);
  if (!rapport.valide) throw new ErreurConfiguration(rapport.errors);
  const base = path.dirname(path.resolve(chemin));
  const config = completer(document);
  return { config, secrets: resoudreSecrets(config, base), base };
}
