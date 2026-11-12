// Client du serveur de console (contrat de l'étape 6, 2.4 et 3.4 ; CT-3 12.9,
// EX-13.33 point 3, EX-13.43, EX-13.48, EX-13.49) : `POST /v0/<méthode>` en
// `fetch` de même origine, `credentials: "same-origin"`, corps JSON ; réponse
// lue en JSON strict (`analyserJsonStrict` de la bibliothèque), octets gardés
// (l'export de l'annuaire rend les octets reçus). La page met dans chaque
// corps la `session_identity` lue par `session` ; le serveur l'impose de toute
// façon. `session_absente` et `reauthentification_requise` font naviguer vers
// `/connexion?retour=<chemin de l'écran>`.

import { analyserJsonStrict, analyserIdentite, estInstant, METHODES_REAUTHENTIFICATION } from "noortrace-console/index.mjs";

/** Erreur d'un appel : code de la réponse (12.8, `$defs/code_serveur_console`) ou code propre à la page. */
export class ErreurAppel extends Error {
  /**
   * @param {string} code
   * @param {{statut?: number|null, data?: object, message?: string, sansReponse?: boolean}} [details]
   */
  constructor(code, details = {}) {
    super(code);
    this.code = code;
    this.statut = details.statut ?? null;
    this.data = details.data ?? {};
    this.messageServeur = details.message ?? "";
    this.sansReponse = details.sansReponse === true;
  }
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Méthodes de la liste d'EX-13.8 envoyées par la page, avec leur instant :
// sert à la règle de 3.5 pour `reauth_max_age_s` = 0.
const envoisReauth = [];

/** Instant courant, au format de CT-1 §3. */
export function maintenant() {
  return new Date().toISOString();
}

/** Vrai si la page a envoyé une méthode de la liste d'EX-13.8 à `auth_time` ou après. */
export function envoiDepuis(authTime) {
  return envoisReauth.some((e) => e.instant >= authTime);
}

/**
 * Méthodes de la liste d'EX-13.8 envoyées par la page à `auth_time` ou après,
 * dans l'ordre d'envoi.
 * @param {string} authTime
 * @returns {string[]}
 */
export function methodesDepuis(authTime) {
  return envoisReauth.filter((e) => e.instant >= authTime).map((e) => e.methode);
}

async function lireReponse(reponse) {
  let octets;
  try {
    octets = new Uint8Array(await reponse.arrayBuffer());
  } catch {
    throw new ErreurAppel("service_indisponible", { sansReponse: true });
  }
  let valeur;
  try {
    valeur = analyserJsonStrict(octets);
  } catch {
    throw new ErreurAppel("reponse_service_invalide", { statut: reponse.status });
  }
  return { octets, valeur };
}

/**
 * Envoie une requête JSON de même origine et rend la réponse lue ; lève
 * `ErreurAppel` pour une erreur du serveur ou du service.
 * @param {string} chemin
 * @param {object} corps
 * @param {number} attendu statut attendu (200 ou 204)
 */
async function envoyer(chemin, corps, attendu) {
  let reponse;
  try {
    reponse = await fetch(chemin, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(corps),
    });
  } catch {
    throw new ErreurAppel("service_indisponible", { sansReponse: true });
  }
  if (reponse.status === attendu) {
    if (attendu === 204) return { octets: new Uint8Array(0), valeur: null };
    return lireReponse(reponse);
  }
  const { valeur } = await lireReponse(reponse);
  const e = estObjet(valeur) && estObjet(valeur.error) ? valeur.error : null;
  if (e === null || typeof e.code !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(e.code)) {
    throw new ErreurAppel("reponse_service_invalide", { statut: reponse.status });
  }
  throw new ErreurAppel(e.code, {
    statut: reponse.status,
    data: estObjet(e.data) ? e.data : {},
    message: typeof e.message === "string" ? e.message : "",
    sansReponse: e.code === "service_indisponible",
  });
}

/**
 * Appelle une méthode de `/v0/` et rend `{ valeur, octets }`.
 * @param {string} methode
 * @param {object} corps
 */
export async function appeler(methode, corps) {
  if (METHODES_REAUTHENTIFICATION.includes(methode)) envoisReauth.push({ methode, instant: maintenant() });
  return envoyer(`/v0/${methode}`, corps, 200);
}

/** `POST /connexion/locale` (EX-13.47) : 204 attendu. */
export async function connexionLocale(nom, motDePasse) {
  return envoyer("/connexion/locale", { name: nom, password: motDePasse }, 204);
}

/** `POST /deconnexion` (EX-13.48, point 6) : 204 attendu. */
export async function deconnexion() {
  return envoyer("/deconnexion", {}, 204);
}

/** Navigue vers l'écran de connexion, `retour` étant le chemin de l'écran courant. */
export function allerConnexion() {
  window.location.assign(`/connexion?retour=${encodeURIComponent(window.location.pathname)}`);
}

/** Vrai si l'erreur fait naviguer vers la connexion (3.4) ; navigue alors. */
export function erreurDeSession(e) {
  if (e instanceof ErreurAppel && (e.code === "session_absente" || e.code === "reauthentification_requise")) {
    allerConnexion();
    return true;
  }
  return false;
}

/**
 * Lit la session (`POST /v0/session`, EX-13.33 point 3). Rend
 * `{ etat: "session", session }`, `{ etat: "navigation" }` (session absente :
 * la page part vers la connexion), `{ etat: "identite_invalide" }` (identité
 * que `analyserIdentite` refuse, EX-13.7) ou `{ etat: "erreur", erreur }`.
 */
export async function lireSession() {
  let r;
  try {
    r = await appeler("session", {});
  } catch (e) {
    if (erreurDeSession(e)) return { etat: "navigation" };
    return { etat: "erreur", erreur: e };
  }
  const s = r.valeur;
  if (!estObjet(s)) return { etat: "erreur", erreur: new ErreurAppel("reponse_service_invalide") };
  try {
    analyserIdentite(s.session_identity);
  } catch {
    return { etat: "identite_invalide" };
  }
  const entierDans = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;
  if (
    typeof s.auth_time !== "string" ||
    !estInstant(s.auth_time) ||
    typeof s.administrator !== "boolean" ||
    !entierDans(s.reauth_max_age_s, 0, 3600) ||
    (s.delai_signature_ms !== undefined && !entierDans(s.delai_signature_ms, 30000, 1800000))
  ) {
    return { etat: "erreur", erreur: new ErreurAppel("reponse_service_invalide") };
  }
  return {
    etat: "session",
    session: {
      session_identity: s.session_identity,
      auth_time: s.auth_time,
      administrator: s.administrator,
      reauth_max_age_s: s.reauth_max_age_s,
      // EX-13.48, point 4 : sans `delai_signature_ms`, 300 000 ms.
      delai_signature_ms: s.delai_signature_ms === undefined ? 300000 : s.delai_signature_ms,
    },
  };
}
