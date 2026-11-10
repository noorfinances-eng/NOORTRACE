// Classement des erreurs d'une tentative (CT-5 EX-5.12, AN-11) et attente de
// reprise (EX-8.9, AN-37). La gigue uniforme de `[0, jitter_ms]` est tirée
// par l'appelant (le planificateur), qui l'ajoute à `attenteMs`.

/** Valeurs par défaut de `rfc3161.retry` (CT-5 §4.4). */
export const RETRY_DEFAUT = Object.freeze({ initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 });

/** `PKIFailureInfo` qui mettent la requête en cause (permanentes, alerte nominative). */
export const ECHECS_PERMANENTS = Object.freeze(["badAlg", "badRequest", "badDataFormat", "unacceptedPolicy", "unacceptedExtension", "addInfoNotAvailable"]);
/** `PKIFailureInfo` transitoires. */
export const ECHECS_TRANSITOIRES = Object.freeze(["timeNotAvailable", "systemFailure"]);
/** Statuts HTTP transitoires rejoués avec attente (EX-5.12). */
export const HTTP_TRANSITOIRES = Object.freeze([429, 500, 502, 503, 504]);
/** Statuts HTTP dont le `Retry-After` est respecté (EX-8.9). */
export const HTTP_RETRY_AFTER = Object.freeze([429, 503]);
/** Plafond de la valeur consignée `retry_after_s` (schéma `planificateur-ancrage-v0`, `$defs/tentative`). */
export const RETRY_AFTER_MAX_S = 604800;

/**
 * Lit un en-tête `Retry-After` : secondes entières, ou date RFC 1123 convertie
 * en secondes depuis `maintenantMs` (jamais négatif). Rend un entier plafonné
 * à `RETRY_AFTER_MAX_S` (borne du schéma, correction R-C-1) ou `null`.
 */
export function lireRetryAfter(valeur, maintenantMs) {
  if (valeur === null || valeur === undefined) return null;
  const s = String(valeur).trim();
  if (/^\d{1,15}$/.test(s)) return Math.min(RETRY_AFTER_MAX_S, Number(s));
  if (!/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(s)) return null;
  const t = Date.parse(s);
  if (!Number.isFinite(t)) return null;
  return Math.min(RETRY_AFTER_MAX_S, Math.max(0, Math.ceil((t - maintenantMs) / 1000)));
}

/** Plafonne une valeur `retry_after_s` déjà lue (entier non négatif) à la borne du schéma ; `null` sinon. */
export function bornerRetryAfter(retryAfterS) {
  if (typeof retryAfterS !== "number" || !Number.isFinite(retryAfterS) || retryAfterS < 0) return null;
  return Math.min(RETRY_AFTER_MAX_S, Math.floor(retryAfterS));
}

/** Attente de la règle générale d'EX-8.9 : `min(max_ms, initial_ms × factor^(k−1))`, sans gigue. */
export function attenteReprise(retry, k) {
  const r = { ...RETRY_DEFAUT, ...(retry ?? {}) };
  const n = Math.max(1, Math.floor(k ?? 1));
  let d = r.initial_ms;
  for (let i = 1; i < n && d < r.max_ms; i++) d *= r.factor;
  return Math.min(r.max_ms, d);
}

/**
 * Attente après une erreur transitoire d'une réponse HTTP (EX-8.9, règle
 * révisée après la relecture, R-C-1 à R-C-3) : l'unique table, partagée par le
 * client (`classerErreur`) et le planificateur (`attenteReprise` du lot C).
 * `d = Retry-After` quand la réponse 429 ou 503 en porte un, **borné** à
 * `[retry.initial_ms, retry.max_ms]` ; `d = 0` sur le premier 408 de la demande
 * chez ce prestataire ; sinon la règle générale `min(max_ms, initial_ms ×
 * factor^(k−1))`. Sur 408, 500, 502 et 504, `Retry-After` n'est pas suivi.
 * La gigue est ajoutée par l'appelant à la seule raison `backoff`.
 * Rend `{ attenteMs, raison: "retry_after"|"immediat"|"backoff" }`.
 */
export function attenteTransitoire({ httpStatus = null, retryAfterS = null, retry = RETRY_DEFAUT, k = 1, premier408 = null } = {}) {
  const r = { ...RETRY_DEFAUT, ...(retry ?? {}) };
  const statut = typeof httpStatus === "number" ? httpStatus : null;
  if (statut !== null && HTTP_RETRY_AFTER.includes(statut) && typeof retryAfterS === "number" && Number.isFinite(retryAfterS) && retryAfterS >= 0) {
    const d = Math.min(r.max_ms, Math.max(r.initial_ms, Math.floor(retryAfterS) * 1000));
    return { attenteMs: d, raison: "retry_after" };
  }
  if (statut === 408) {
    const premier = premier408 === null ? k === 1 : premier408;
    if (premier) return { attenteMs: 0, raison: "immediat" };
  }
  return { attenteMs: attenteReprise(r, k), raison: "backoff" };
}

/**
 * Classe l'issue d'une tentative. Entrées : `code` d'EX-5.10 (`http_503`,
 * `type_contenu`, `taille`, `reponse_illisible`, `statut_3`, `echec_badAlg`,
 * `empreinte_differente`, `nonce_different`, `politique_refusee`,
 * `verification_T-6`, `reponse_tardive`, `ecriture`, `erreur_transport`,
 * `delai`…), ou à défaut `httpStatus`, `pkiStatus`, `failureInfo` ; `retryAfter`
 * (secondes, ou en-tête brut avec `maintenantMs`) ; `retry` ; `k` (nombre
 * d'échecs transitoires consécutifs de la demande chez ce prestataire, celui-ci
 * compris) ; `premier408` (premier 408 de la demande chez ce prestataire ;
 * défaut : `k === 1`).
 *
 * Rend `{ classe: "transitoire"|"permanente"|null, attenteMs, raisonAttente:
 * "retry_after"|"immediat"|"backoff"|null, alerte: "aucune"|"alerte"|"critique", immediat }`.
 */
export function classerErreur({ etape = null, httpStatus = null, retryAfter = null, maintenantMs = 0, pkiStatus = null, failureInfo = null, code = null, retry = RETRY_DEFAUT, k = 1, premier408 = null } = {}) {
  void etape;
  let c = code;
  if (c === null) {
    if (httpStatus !== null && httpStatus !== 200) c = `http_${httpStatus}`;
    else if (pkiStatus !== null && pkiStatus >= 2) c = pkiStatus === 2 && failureInfo && failureInfo !== "autre" ? `echec_${failureInfo}` : `statut_${pkiStatus}`;
  }
  if (c === null) return { classe: null, attenteMs: null, raisonAttente: null, alerte: "aucune", immediat: false, code: null };

  const retryAfterS = typeof retryAfter === "number" ? retryAfter : lireRetryAfter(retryAfter, maintenantMs);
  const transitoire = (raison, attente) => ({ classe: "transitoire", attenteMs: attente, raisonAttente: raison, alerte: "aucune", immediat: raison === "immediat", code: c });
  const permanente = (alerte) => ({ classe: "permanente", attenteMs: null, raisonAttente: null, alerte, immediat: false, code: c });
  const backoff = () => transitoire("backoff", attenteReprise(retry, k));

  const http = /^http_(\d{3})$/.exec(c);
  if (http) {
    const statut = Number(http[1]);
    if (statut === 408 || HTTP_TRANSITOIRES.includes(statut)) {
      const a = attenteTransitoire({ httpStatus: statut, retryAfterS, retry, k, premier408 });
      return transitoire(a.raison, a.attenteMs);
    }
    return permanente("alerte");
  }
  if (c === "type_contenu" || c === "taille" || c === "reponse_illisible") return permanente("alerte");
  const statut = /^statut_(\d+)$/.exec(c);
  if (statut) {
    const n = Number(statut[1]);
    if (n === 3) return backoff();
    if (n === 4 || n === 5) return permanente("critique");
    return permanente("alerte");
  }
  const echec = /^echec_(.+)$/.exec(c);
  if (echec) {
    if (ECHECS_TRANSITOIRES.includes(echec[1])) return backoff();
    return permanente("alerte");
  }
  if (c === "empreinte_differente" || c === "nonce_absent" || c === "nonce_different" || c === "politique_differente" || c === "politique_refusee" || /^verification_T-\d+$/.test(c)) return permanente("alerte");
  if (c === "reponse_tardive" || c === "ecriture" || c === "erreur_transport" || c === "delai") return backoff();
  return permanente("alerte");
}

/** Issue d'EX-5.13 déduite d'une classe (`null` : `obtenue`). */
export function issueDepuisClasse(classe, code) {
  if (classe === null) return "obtenue";
  if (code === "reponse_tardive") return "reponse_tardive";
  return classe === "transitoire" ? "echec_transitoire" : "echec_permanente";
}
