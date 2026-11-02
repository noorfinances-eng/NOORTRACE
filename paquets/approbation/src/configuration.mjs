// Configuration du service d'approbation (CT-3 10.3, 12.1, 12.2 ; CT-7
// EX-3.10) : document JSON lu au démarrage, contrôlé ici, avec ses
// références de secrets (fichier ou variable d'environnement).
//
// {
//   "version": 0,
//   "environment": "production" | "developpement",
//   "org_id": "0x…", "journal_id": "0x…",          // le journal que sert le service
//   "state_dir": "<répertoire d'état>",
//   "storage_key": { "file": "<chemin>" } | { "env": "<VARIABLE>" },   // 32 octets (EX-7.24)
//   "noyau":   { "socket": "<chemin>"|null, "socket_mode": "0660", "tcp": { "host", "port" }|null,
//                "tls": { "cert", "key", "client_ca" }|null, "token": <secret>|null },
//   "console": null | { mêmes membres d'écoute, "token": <secret>, "annuaire": "<fichier annuaire-approbateurs-v0>" },
//   "tickets": { "epoch": null | "<époque>" },      // EX-7.1 : null = 65 bits aléatoires
//   "max_open_tickets": 20, "escalation": [], "set_poll_interval_ms": 10000, "administrators": [],
//   "console_origin": null | "https://…",
//   "rpc": null | { "url", "validator": "client"|"partenaire", "timeout_ms": 5000, "logs_from_block": 0 },
//   "remise_representation_ms": 30000,
//   "body_max_bytes": 16777216
// }

import fs from "node:fs";
import path from "node:path";
import { identiteCanonique } from "./annuaire.mjs";
import { lireJsonStrict } from "./json.mjs";

const HEX32 = /^0x[0-9a-f]{64}$/;
const BOUCLE = new Set(["127.0.0.1", "localhost"]);

/** Valeurs par défaut (10.3). */
export const DEFAUTS = Object.freeze({
  max_open_tickets: 20,
  set_poll_interval_ms: 10000,
  remise_representation_ms: 30000,
  body_max_bytes: 16 * 1024 * 1024,
});

const objet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function controlerEcoute(e, ici, erreurs, env) {
  if (!objet(e)) return erreurs.push(`${ici} : objet attendu`);
  const permis = ["socket", "socket_mode", "tcp", "tls", "token", "annuaire"];
  for (const k of Object.keys(e)) if (!permis.includes(k)) erreurs.push(`${ici}/${k} : membre inconnu`);
  const socket = e.socket ?? null;
  const tcp = e.tcp ?? null;
  if ((socket === null) === (tcp === null)) erreurs.push(`${ici} : exactement un de socket et tcp`);
  if (socket !== null && (typeof socket !== "string" || !path.isAbsolute(socket))) erreurs.push(`${ici}/socket : chemin absolu attendu`);
  if (e.socket_mode !== undefined && !/^0[0-7]{3}$/.test(e.socket_mode)) erreurs.push(`${ici}/socket_mode : mode octal attendu (0660)`);
  if (e.socket_mode !== undefined && (parseInt(e.socket_mode, 8) & 0o007) !== 0) erreurs.push(`${ici}/socket_mode : aucun droit pour les autres`);
  if (tcp !== null) {
    if (!objet(tcp) || typeof tcp.host !== "string" || !Number.isInteger(tcp.port) || tcp.port < 0 || tcp.port > 65535) {
      erreurs.push(`${ici}/tcp : { host, port } attendu`);
    } else if (!BOUCLE.has(tcp.host) && !e.tls) {
      // EX-12.2 : TLS hors de la boucle locale
      erreurs.push(`${ici}/tcp : TLS exigé hors de la boucle locale`);
    }
    if (!e.token && !e.tls?.client_ca) erreurs.push(`${ici} : jeton ou mTLS exigé en TCP (EX-12.2)`);
  }
  if (e.tls) {
    if (!objet(e.tls) || typeof e.tls.cert !== "string" || typeof e.tls.key !== "string") erreurs.push(`${ici}/tls : { cert, key, client_ca } attendu`);
  }
  if (env === "production" && socket !== null && !e.token) {
    // en production, la seule permission de la prise ne suffit pas sans pair vérifié (lecture 2)
    erreurs.push(`${ici} : jeton exigé en production`);
  }
  if (e.token !== undefined && e.token !== null && !refSecret(e.token)) erreurs.push(`${ici}/token : référence de secret attendue`);
}

function refSecret(r) {
  return objet(r) && Object.keys(r).length === 1 && (typeof r.file === "string" || typeof r.env === "string");
}

/**
 * Contrôle une configuration ; rend la liste de toutes les erreurs.
 * @param {unknown} c
 * @returns {string[]}
 */
export function controlerConfiguration(c) {
  const erreurs = [];
  if (!objet(c)) return ["configuration : objet attendu"];
  const permis = [
    "version", "environment", "org_id", "journal_id", "state_dir", "storage_key", "noyau", "console", "tickets",
    "max_open_tickets", "escalation", "set_poll_interval_ms", "administrators", "console_origin", "rpc",
    "remise_representation_ms", "body_max_bytes",
  ];
  for (const k of Object.keys(c)) if (!permis.includes(k)) erreurs.push(`/${k} : membre inconnu`);
  if (c.version !== 0) erreurs.push("/version : 0 attendu");
  if (c.environment !== "production" && c.environment !== "developpement") erreurs.push("/environment : production ou developpement");
  if (!HEX32.test(c.org_id ?? "")) erreurs.push("/org_id : hexadécimal de 32 octets");
  if (!HEX32.test(c.journal_id ?? "")) erreurs.push("/journal_id : hexadécimal de 32 octets");
  if (typeof c.state_dir !== "string" || !path.isAbsolute(c.state_dir)) erreurs.push("/state_dir : chemin absolu attendu");
  if (!refSecret(c.storage_key)) erreurs.push("/storage_key : référence de secret attendue (EX-7.24)");
  controlerEcoute(c.noyau, "/noyau", erreurs, c.environment);
  if (c.console !== undefined && c.console !== null) {
    controlerEcoute(c.console, "/console", erreurs, c.environment);
    if (!c.console.token && !c.console.tls?.client_ca) erreurs.push("/console : jeton ou mTLS exigé (EX-12.4)");
    if (typeof c.console.annuaire !== "string") erreurs.push("/console/annuaire : fichier d'annuaire attendu");
    if (c.noyau?.token && c.console.token && JSON.stringify(c.noyau.token) === JSON.stringify(c.console.token)) {
      erreurs.push("/console/token : distinct du jeton du noyau (EX-12.4)");
    }
  }
  if (c.tickets !== undefined) {
    const ep = c.tickets?.epoch ?? null;
    if (!objet(c.tickets) || (ep !== null && !/^[0-9a-z]+(-[0-9a-z]+)*$/.test(ep)) || (ep !== null && ep.length > 100)) {
      erreurs.push("/tickets/epoch : null ou époque [0-9a-z-] (EX-7.1)");
    }
  }
  if (c.max_open_tickets !== undefined && !(Number.isInteger(c.max_open_tickets) && c.max_open_tickets >= 1 && c.max_open_tickets <= 10000)) {
    erreurs.push("/max_open_tickets : entier de 1 à 10 000");
  }
  if (c.set_poll_interval_ms !== undefined && !(Number.isInteger(c.set_poll_interval_ms) && c.set_poll_interval_ms >= 1000 && c.set_poll_interval_ms <= 86400000)) {
    erreurs.push("/set_poll_interval_ms : entier de 1 000 à 86 400 000");
  }
  if (c.escalation !== undefined) {
    if (!Array.isArray(c.escalation) || c.escalation.length > 8) erreurs.push("/escalation : au plus 8 étapes");
    else {
      let avant = 0;
      c.escalation.forEach((e, k) => {
        if (!objet(e) || !Number.isInteger(e.after_ms) || e.after_ms <= avant || !["jeu", "administrateur", "demandeur"].includes(e.notify)) {
          erreurs.push(`/escalation/${k} : { after_ms strictement croissant, notify jeu|administrateur|demandeur }`);
        } else avant = e.after_ms;
      });
    }
  }
  if (c.administrators !== undefined) {
    if (!Array.isArray(c.administrators) || c.administrators.length > 16 || !c.administrators.every(identiteCanonique)) {
      erreurs.push("/administrators : au plus 16 identités de session canoniques (EX-13.7)");
    }
  }
  if (c.console_origin !== undefined && c.console_origin !== null && !/^https:\/\/[^/?#\s]+$/.test(c.console_origin)) {
    erreurs.push("/console_origin : origine https");
  }
  if (c.rpc !== undefined && c.rpc !== null) {
    if (!objet(c.rpc) || typeof c.rpc.url !== "string" || !/^https?:\/\//.test(c.rpc.url)) erreurs.push("/rpc/url : URL http(s)");
    if (c.rpc && !["client", "partenaire", "developpement"].includes(c.rpc.validator)) erreurs.push("/rpc/validator : client, partenaire ou developpement");
    // CT-7 EX-3.10, MN-51 : en production, un validateur que le client opère ou un validateur partenaire
    if (c.environment === "production" && c.rpc?.validator === "developpement") erreurs.push("/rpc/validator : client ou partenaire exigé en production");
  }
  for (const k of ["remise_representation_ms", "body_max_bytes"]) {
    if (c[k] !== undefined && !(Number.isInteger(c[k]) && c[k] >= 1)) erreurs.push(`/${k} : entier positif`);
  }
  return erreurs;
}

/**
 * Lit une référence de secret.
 * @param {{file?: string, env?: string}} ref
 * @param {string} base répertoire du fichier de configuration
 * @returns {Buffer}
 */
export function lireSecret(ref, base) {
  if (ref.env !== undefined) {
    const v = process.env[ref.env];
    if (v === undefined || v === "") throw new Error(`secret : variable ${ref.env} absente`);
    return Buffer.from(v, "utf8");
  }
  return fs.readFileSync(path.resolve(base, ref.file));
}

/** Clé de stockage : 32 octets bruts, ou 64 chiffres hexadécimaux (préfixe 0x facultatif). */
export function decoderCle(octets) {
  if (octets.length === 32) return new Uint8Array(octets);
  const t = octets.toString("utf8").trim().replace(/^0x/, "");
  if (/^[0-9a-fA-F]{64}$/.test(t)) return new Uint8Array(Buffer.from(t, "hex"));
  throw new Error("clé de stockage : 32 octets ou 64 chiffres hexadécimaux attendus");
}

/** Jeton : texte d'au moins 16 caractères imprimables. */
export function decoderJeton(octets) {
  const t = octets.toString("utf8").trim();
  if (!/^[\x21-\x7e]{16,1024}$/.test(t)) throw new Error("jeton : 16 à 1 024 caractères ASCII imprimables");
  return t;
}

/**
 * Lit et contrôle un fichier de configuration ; résout ses secrets.
 * @param {string} chemin
 * @returns {{config: object, secrets: {cle: Uint8Array, jetonNoyau: string|null, jetonConsole: string|null}}}
 */
export function chargerConfiguration(chemin) {
  const config = lireJsonStrict(fs.readFileSync(chemin));
  const erreurs = controlerConfiguration(config);
  if (erreurs.length) throw new Error(`configuration refusée :\n  ${erreurs.join("\n  ")}`);
  const base = path.dirname(path.resolve(chemin));
  return { config: completer(config), secrets: resoudreSecrets(config, base) };
}

/** Complète les valeurs par défaut. */
export function completer(c) {
  return {
    tickets: { epoch: null },
    max_open_tickets: DEFAUTS.max_open_tickets,
    escalation: [],
    set_poll_interval_ms: DEFAUTS.set_poll_interval_ms,
    administrators: [],
    console_origin: null,
    rpc: null,
    console: null,
    remise_representation_ms: DEFAUTS.remise_representation_ms,
    body_max_bytes: DEFAUTS.body_max_bytes,
    ...c,
  };
}

/** Résout les secrets d'une configuration contrôlée. */
export function resoudreSecrets(c, base) {
  return {
    cle: decoderCle(lireSecret(c.storage_key, base)),
    jetonNoyau: c.noyau.token ? decoderJeton(lireSecret(c.noyau.token, base)) : null,
    jetonConsole: c.console?.token ? decoderJeton(lireSecret(c.console.token, base)) : null,
  };
}
