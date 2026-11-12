// Modules serveur de l'interface d'exploitant (INTERFACES.md 1, 2) :
// configuration, comptes de l'exploitant (scrypt, verrou progressif comme
// CT-3 EX-13.47), sessions en mémoire (cookie `__Host-noortrace-inscription`,
// MAC HMAC-SHA256 sous une clé tirée au démarrage, durée 8 h), contrôle de
// l'origine. Ces modules ne s'exécutent que sur le serveur : rien de ce qu'ils
// tiennent (chemin de la prise, clé de session, comptes) n'est envoyé à la
// page.
//
// Next compile chaque route et le mandataire en modules distincts : l'état
// partagé (sessions, compteurs d'échecs, clé de MAC) est tenu sur
// `globalThis`, sous un symbole propre, une fois par processus.

import crypto from "node:crypto";
import fs from "node:fs";
import { lireJsonStrict } from "../../commun/json.mjs";
import { lireReference } from "../../commun/references.mjs";

/** Nom du cookie de session (INTERFACES.md 1). */
export const COOKIE = "__Host-noortrace-inscription";
/** Durée d'une session : 8 h. */
export const DUREE_SESSION_MS = 8 * 3600 * 1000;
/** Paramètres scrypt du fichier des comptes (`configuration-console-v0#/$defs/fichier_comptes`). */
export const SCRYPT = Object.freeze({ N: 131072, r: 8, p: 1, longueur: 32, maxmem: 256 * 1024 * 1024 });

const ETAT = Symbol.for("noortrace.inscription.interface");

/** État du processus (créé au premier appel). */
export function etat() {
  if (!globalThis[ETAT]) {
    globalThis[ETAT] = {
      configuration: null,
      comptes: null,
      cleMac: crypto.randomBytes(32),
      sessions: new Map(),
      echecs: new Map(),
      calculs: 0,
    };
  }
  return globalThis[ETAT];
}

/** Erreur de configuration de l'interface. */
export class ErreurConfigurationInterface extends Error {}

/**
 * Configuration de l'interface (`NOORTRACE_INSCRIPTION_CONFIG`, posée par
 * `bin/noortrace-inscription-web --config`) : `{ version: 0, ecoute: { hote,
 * port }, origine, prise, donnees, comptes: "fichier:<chemin>", nature }`.
 */
export function configuration() {
  const e = etat();
  if (e.configuration) return e.configuration;
  const chemin = process.env.NOORTRACE_INSCRIPTION_CONFIG;
  if (!chemin) throw new ErreurConfigurationInterface("NOORTRACE_INSCRIPTION_CONFIG absente");
  e.configuration = lireConfigurationInterface(chemin);
  return e.configuration;
}

/** Lit et contrôle une configuration de l'interface. */
export function lireConfigurationInterface(chemin) {
  let c;
  try {
    c = lireJsonStrict(fs.readFileSync(chemin));
  } catch (e) {
    throw new ErreurConfigurationInterface(`configuration de l'interface illisible : ${e.message}`);
  }
  const refus = (m) => new ErreurConfigurationInterface(`configuration de l'interface : ${m}`);
  const membres = ["version", "ecoute", "origine", "prise", "donnees", "comptes", "nature"];
  if (!c || typeof c !== "object" || Array.isArray(c)) throw refus("objet attendu");
  for (const k of Object.keys(c)) if (!membres.includes(k)) throw refus(`membre inconnu ${k}`);
  if (c.version !== 0) throw refus("version 0 attendue");
  if (!c.ecoute || typeof c.ecoute.hote !== "string" || !Number.isSafeInteger(c.ecoute.port) || c.ecoute.port < 1 || c.ecoute.port > 65535) throw refus("ecoute : { hote, port } attendu");
  if (typeof c.origine !== "string" || !/^https?:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?$/.test(c.origine)) throw refus("origine : origine http(s) sans chemin attendue");
  for (const k of ["prise", "donnees"]) if (typeof c[k] !== "string" || !c[k].startsWith("/")) throw refus(`${k} : chemin absolu attendu`);
  try {
    lireReference("comptes", c.comptes, { formes: ["fichier"] });
  } catch (e) {
    throw refus(e.message);
  }
  if (c.nature !== "developpement" && c.nature !== "production") throw refus("nature : developpement ou production");
  if (c.nature === "production" && !c.origine.startsWith("https://")) throw refus("origine https:// exigée en production");
  return { ...c };
}

/** Comptes de l'exploitant (`fichier:` de la configuration), lus une fois : `Map(name → { salt, key })`. */
export function comptes() {
  const e = etat();
  if (e.comptes) return e.comptes;
  const chemin = configuration().comptes.slice("fichier:".length);
  const doc = lireJsonStrict(fs.readFileSync(chemin));
  if (!doc || doc.version !== 0 || !Array.isArray(doc.accounts) || doc.accounts.length < 1) throw new ErreurConfigurationInterface("fichier des comptes : { version: 0, accounts: [...] } attendu");
  const m = new Map();
  for (const a of doc.accounts) {
    if (typeof a.name !== "string" || !/^[!-~]{1,255}$/.test(a.name) || !/^[0-9a-f]{32}$/.test(a.salt) || !/^[0-9a-f]{64}$/.test(a.key) || Object.keys(a).length !== 3) throw new ErreurConfigurationInterface("fichier des comptes : compte hors de la forme { name, salt, key }");
    if (m.has(a.name)) throw new ErreurConfigurationInterface("fichier des comptes : noms en double");
    m.set(a.name, { salt: Buffer.from(a.salt, "hex"), key: Buffer.from(a.key, "hex") });
  }
  e.comptes = m;
  return m;
}

/** scrypt du mot de passe (octets UTF-8, sans normalisation). */
export function scrypt(motDePasse, sel) {
  return new Promise((ok, ko) => crypto.scrypt(Buffer.from(motDePasse, "utf8"), sel, SCRYPT.longueur, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem }, (err, cle) => (err ? ko(err) : ok(cle))));
}

const SEL_FIXE = Buffer.alloc(16, 0x5a);

/**
 * Connexion (INTERFACES.md 1 ; verrou comme CT-3 EX-13.47) : deux calculs à
 * la fois au plus ; pour chaque nom, connu ou non, `f` échecs consécutifs ;
 * à partir de cinq, une requête reçue avant le dernier échec + min(2^(f − 5),
 * 900) s est refusée sans calcul ; un nom inconnu fait le même calcul. Rend
 * `{ statut: 204, session }`, `{ statut: 401, code }` ou `{ statut: 429,
 * code, retry_after_s }`.
 */
export async function connecter(nom, motDePasse, maintenant = Date.now()) {
  const e = etat();
  const suivi = e.echecs.get(nom);
  if (suivi && suivi.f >= 5) {
    const attente = Math.min(2 ** (suivi.f - 5), 900) * 1000;
    const reste = suivi.dernier + attente - maintenant;
    if (reste > 0) return { statut: 429, code: "essai_trop_tot", retry_after_s: Math.ceil(reste / 1000) };
  }
  if (e.calculs >= 2) return { statut: 429, code: "essai_trop_tot", retry_after_s: 1 };
  e.calculs++;
  let ok = false;
  try {
    const compte = comptes().get(nom);
    const cle = await scrypt(motDePasse, compte ? compte.salt : SEL_FIXE);
    ok = Boolean(compte) && crypto.timingSafeEqual(cle, compte.key);
  } finally {
    e.calculs--;
  }
  if (!ok) {
    const s = e.echecs.get(nom) ?? { f: 0, dernier: 0 };
    s.f++;
    s.dernier = Date.now();
    e.echecs.delete(nom);
    e.echecs.set(nom, s);
    // Au plus 10 000 noms suivis : on oublie d'abord le plus ancien des noms non verrouillés.
    if (e.echecs.size > 10000) {
      const ancien = [...e.echecs.entries()].find(([, v]) => v.f < 5) ?? e.echecs.entries().next().value;
      e.echecs.delete(ancien[0]);
    }
    return { statut: 401, code: "identifiants_refuses" };
  }
  e.echecs.delete(nom);
  return { statut: 204, session: ouvrirSession(nom) };
}

const b64 = (o) => Buffer.from(o).toString("base64url");

/** Ouvre une session : identifiant de 32 octets tiré au hasard ; rend la valeur du cookie (identifiant et MAC). */
export function ouvrirSession(nom) {
  const e = etat();
  const id = crypto.randomBytes(32);
  e.sessions.set(id.toString("hex"), { nom, expire: Date.now() + DUREE_SESSION_MS });
  const mac = crypto.createHmac("sha256", e.cleMac).update(id).digest();
  return `${b64(id)}.${b64(mac)}`;
}

/** Session d'une valeur de cookie : `{ nom, identite }` ou null (MAC faux, inconnue ou expirée). */
export function session(valeur) {
  if (typeof valeur !== "string" || valeur.length > 200) return null;
  const [i, m] = valeur.split(".");
  if (!i || !m) return null;
  const id = Buffer.from(i, "base64url");
  const mac = Buffer.from(m, "base64url");
  if (id.length !== 32 || mac.length !== 32) return null;
  const e = etat();
  const attendu = crypto.createHmac("sha256", e.cleMac).update(id).digest();
  if (!crypto.timingSafeEqual(attendu, mac)) return null;
  const s = e.sessions.get(id.toString("hex"));
  if (!s) return null;
  if (s.expire <= Date.now()) {
    e.sessions.delete(id.toString("hex"));
    return null;
  }
  return { nom: s.nom, identite: `exploitant ${s.nom}` };
}

/** Ferme une session. */
export function fermerSession(valeur) {
  if (typeof valeur !== "string") return;
  const [i] = valeur.split(".");
  if (!i) return;
  etat().sessions.delete(Buffer.from(i, "base64url").toString("hex"));
}

/** En-tête `Set-Cookie` de session (INTERFACES.md 1). */
export function enteteCookie(valeur, { effacer = false } = {}) {
  return `${COOKIE}=${effacer ? "" : valeur}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${effacer ? 0 : DUREE_SESSION_MS / 1000}`;
}

/** Valeur du cookie de session dans un en-tête `Cookie`. */
export function cookieDe(entete) {
  if (typeof entete !== "string") return null;
  for (const morceau of entete.split(";")) {
    const [k, ...v] = morceau.trim().split("=");
    if (k === COOKIE) return v.join("=");
  }
  return null;
}
