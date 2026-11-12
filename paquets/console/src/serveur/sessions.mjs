// Sessions et cookies du serveur de console (CT-3 EX-13.48, contrat 2.7) :
// sessions en mémoire seulement (au plus 10 000, la plus ancienne détruite
// au-delà), cookie de session `__Host-noortrace-session` signé par
// HMAC-SHA256 sous `K_s`, cookie de transaction `__Host-noortrace-connexion`
// chiffré par AES-256-GCM sous `K_t`, `tid` des transactions présentées
// (au plus 100 000, gardés 600 s). `K_s` et `K_t` sont tirées au démarrage,
// distinctes, et jamais écrites.

import crypto from "node:crypto";
import { b64u, deB64u, egauxTempsConstant } from "./outils.mjs";

export const COOKIE_SESSION = "__Host-noortrace-session";
export const COOKIE_CONNEXION = "__Host-noortrace-connexion";
export const MAX_SESSIONS = 10000;
export const MAX_TIDS = 100000;
export const DUREE_TRANSACTION_MS = 600000;

const ETIQUETTE_SESSION = Buffer.from("noortrace/console/session/v0\n", "utf8");
const DONNEES_ASSOCIEES = Buffer.from("noortrace/console/connexion/v0", "utf8");

/**
 * Valeur d'un cookie de l'en-tête `Cookie` (la première occurrence du nom).
 * @param {string|undefined} entete
 * @param {string} nom
 * @returns {string|null}
 */
export function lireCookie(entete, nom) {
  if (typeof entete !== "string") return null;
  for (const morceau of entete.split(";")) {
    const k = morceau.indexOf("=");
    if (k < 0) continue;
    if (morceau.slice(0, k).trim() === nom) return morceau.slice(k + 1).trim();
  }
  return null;
}

/** En-tête `Set-Cookie` du cookie de session. */
export const cookieSession = (valeur) => `${COOKIE_SESSION}=${valeur}; Secure; HttpOnly; SameSite=Strict; Path=/`;
/** En-tête `Set-Cookie` qui efface le cookie de session. */
export const effacerSession = () => `${COOKIE_SESSION}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
/** En-tête `Set-Cookie` du cookie de transaction. */
export const cookieConnexion = (valeur) => `${COOKIE_CONNEXION}=${valeur}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`;
/** En-tête `Set-Cookie` qui efface le cookie de transaction. */
export const effacerConnexion = () => `${COOKIE_CONNEXION}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;

/** Sessions en mémoire (EX-13.48, points 1 et 2). */
export class Sessions {
  /**
   * @param {{horloge: () => number, dureeS: number, journal: Function}} o
   */
  constructor({ horloge, dureeS, journal }) {
    this.horloge = horloge;
    this.dureeMs = dureeS * 1000;
    this.journal = journal;
    this.cle = crypto.randomBytes(32);
    /** @type {Map<string, object>} sid (hexadécimal) → session, dans l'ordre de création */
    this.table = new Map();
  }

  #mac(sid) {
    return crypto.createHmac("sha256", this.cle).update(ETIQUETTE_SESSION).update(sid).digest();
  }

  /**
   * Ouvre une session nouvelle ; rend la valeur du cookie.
   * @param {{identite: string, authTimeMs: number, systeme: string}} o
   */
  creer({ identite, authTimeMs, systeme }) {
    while (this.table.size >= MAX_SESSIONS) {
      const [plusAncienne] = this.table.keys();
      this.detruire(plusAncienne, "eviction");
    }
    const sid = crypto.randomBytes(32);
    const maintenant = this.horloge();
    const session = {
      sid: sid.toString("hex"),
      identite,
      authTimeMs,
      creeeMs: maintenant,
      echeanceMs: maintenant + this.dureeMs,
      administrator: false,
      reauthEmployee: false,
      inscriptionCouverte: false,
      systeme,
    };
    this.table.set(session.sid, session);
    return { session, cookie: `${b64u(sid)}.${b64u(this.#mac(sid))}` };
  }

  /**
   * Session que désigne la valeur d'un cookie : MAC vérifié en temps
   * constant avant la recherche ; cookie invalide, inconnu ou échu : `null`.
   * @param {string|null} valeur
   */
  lire(valeur) {
    if (typeof valeur !== "string") return null;
    const k = valeur.indexOf(".");
    if (k < 0) return null;
    const sid = deB64u(valeur.slice(0, k));
    const mac = deB64u(valeur.slice(k + 1));
    if (sid === null || mac === null || sid.length !== 32 || mac.length !== 32) return null;
    if (!egauxTempsConstant(mac, this.#mac(sid))) return null;
    const session = this.table.get(sid.toString("hex")) ?? null;
    if (session === null) return null;
    if (this.horloge() >= session.echeanceMs) {
      this.detruire(session.sid, "echeance");
      return null;
    }
    return session;
  }

  /** Détruit une session (sans effet si elle n'existe plus). */
  detruire(sid, cause) {
    const s = this.table.get(sid);
    if (!s) return;
    this.table.delete(sid);
    this.journal("session_fermee", { cause });
  }

  /** Détruit les sessions échues (entretien). */
  purger() {
    const maintenant = this.horloge();
    for (const s of [...this.table.values()]) if (maintenant >= s.echeanceMs) this.detruire(s.sid, "echeance");
  }
}

/** Transactions OIDC portées par le cookie chiffré (EX-13.45, points 2 et 3 ; EX-13.48, point 3). */
export class Transactions {
  /** @param {{horloge: () => number}} o */
  constructor({ horloge }) {
    this.horloge = horloge;
    this.cle = crypto.randomBytes(32);
    /** @type {Map<string, number>} tid → instant de création, dans l'ordre de présentation */
    this.presentees = new Map();
  }

  /**
   * Chiffre une transaction : `base64url(iv ‖ c ‖ t)`.
   * @param {object} transaction `{ tid, state, nonce, code_verifier, created_at, retour, sid }`
   */
  sceller(transaction) {
    const iv = crypto.randomBytes(12);
    const chiffreur = crypto.createCipheriv("aes-256-gcm", this.cle, iv);
    chiffreur.setAAD(DONNEES_ASSOCIEES);
    const c = Buffer.concat([chiffreur.update(JSON.stringify(transaction), "utf8"), chiffreur.final()]);
    return b64u(Buffer.concat([iv, c, chiffreur.getAuthTag()]));
  }

  /**
   * Ouvre et consomme la transaction du cookie : déchiffrée et authentifiée
   * sous la clé en cours, créée depuis moins de 600 s, `tid` jamais présenté.
   * Le `tid` est retenu dès cette présentation, quelle qu'en soit l'issue.
   * @param {string|null} valeur
   * @returns {object|null}
   */
  consommer(valeur) {
    this.purger();
    const o = typeof valeur === "string" ? deB64u(valeur) : null;
    if (o === null || o.length < 12 + 16 + 2) return null;
    let t;
    try {
      const dechiffreur = crypto.createDecipheriv("aes-256-gcm", this.cle, o.subarray(0, 12));
      dechiffreur.setAAD(DONNEES_ASSOCIEES);
      dechiffreur.setAuthTag(o.subarray(o.length - 16));
      t = JSON.parse(Buffer.concat([dechiffreur.update(o.subarray(12, o.length - 16)), dechiffreur.final()]).toString("utf8"));
    } catch {
      return null;
    }
    const maintenant = this.horloge();
    if (!(maintenant - t.created_at < DUREE_TRANSACTION_MS) || maintenant < t.created_at) return null;
    if (this.presentees.has(t.tid)) return null;
    while (this.presentees.size >= MAX_TIDS) {
      const [plusAncien] = this.presentees.keys();
      this.presentees.delete(plusAncien);
    }
    this.presentees.set(t.tid, t.created_at);
    return t;
  }

  /** Oublie les `tid` des transactions créées depuis 600 s ou plus. */
  purger() {
    const maintenant = this.horloge();
    for (const [tid, cree] of this.presentees) if (maintenant - cree >= DUREE_TRANSACTION_MS) this.presentees.delete(tid);
  }
}
