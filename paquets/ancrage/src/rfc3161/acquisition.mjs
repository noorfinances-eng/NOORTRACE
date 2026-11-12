// Une tentative complète d'acquisition d'un jeton (CT-5 EX-5.5, EX-5.10
// étapes 1 à 9, EX-5.11, EX-5.13 ; AN-7 à AN-11, AN-14) : requête d'EX-5.1,
// envoi, lecture de la réponse, égalités, T-1 à T-9, fraîcheur, horloge,
// écriture des pièces et de l'enregistrement d'acquisition. Rend le `data`
// d'une entrée `reponse_rfc3161` du schéma `planificateur-ancrage-v0`.
//
// Horloge et aléa sont injectés ; aucun fichier ni variable d'environnement
// n'est lu : `prestataire.auth.secret` est déjà résolu en octets par l'appelant.

import { ecrireHorodatage } from "@noortrace/noyau";
import { octetsVersHex } from "./der.mjs";
import { sha256Hex } from "./x509.mjs";
import { construireRequete, tirerNonce, nonceVersBigint, nonceVersHex8, ErreurRequete, NONCE_MAX } from "./requete.mjs";
import { lireReponse, lireJeton, ErreurReponse } from "./reponse.mjs";
import { ErreurDer } from "./der.mjs";
import { verifierJeton, ancresDepuisPrestataire, normaliserAncres, VERIFICATIONS_ACQUISITION } from "./verification.mjs";
import { classerErreur, issueDepuisClasse, lireRetryAfter, RETRY_DEFAUT } from "./classement.mjs";
import { CORPS_MAX, TYPES_REPONSE, ErreurTransport, entetesRequete } from "./transport.mjs";
import { ErreurDepot, nomObjet } from "./depot.mjs";

/** Valeurs par défaut de `rfc3161.freshness` (CT-5 §4.4). */
export const FRAICHEUR_DEFAUT = Object.freeze({ max_response_delay_s: 60, clock_tolerance_s: 120 });

const ROLES = new Set(["principal", "secours", "second_rang", "interne"]);

/** Contrôle minimal d'un prestataire résolu (la validation complète, AN-1, est celle du planificateur). */
export function controlerPrestataire(p) {
  if (!p || typeof p !== "object") throw new TypeError("prestataire attendu");
  if (typeof p.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(p.id)) throw new TypeError("prestataire.id invalide");
  if (!ROLES.has(p.role)) throw new TypeError("prestataire.role hors énumération");
  if (typeof p.url !== "string") throw new TypeError("prestataire.url attendu");
  if (p.hash !== "sha256") throw new TypeError("prestataire.hash : sha256 seulement (EX-5.2)");
  if (!Array.isArray(p.anchor_certificates) || p.anchor_certificates.length < 1 || p.anchor_certificates.length > 8) throw new TypeError("anchor_certificates : 1 à 8 certificats PEM");
  if (p.accepted_policies !== null && p.accepted_policies !== undefined && (!Array.isArray(p.accepted_policies) || p.accepted_policies.length === 0)) throw new TypeError("accepted_policies : null ou liste non vide");
  if (p.auth && p.auth.method !== "aucune" && p.auth.secret !== null && p.auth.secret !== undefined && !(p.auth.secret instanceof Uint8Array)) throw new TypeError("auth.secret doit être résolu en octets par l'appelant (CT-2 §15.2)");
  return p;
}

/** Type de média d'un en-tête `Content-Type` (sans paramètres, en minuscules). */
export function typeMedia(valeur) {
  if (valeur === null || valeur === undefined) return null;
  return String(valeur).split(";")[0].trim().toLowerCase();
}

/** Identifiant de tentative par défaut (CT-5 annexe A.2 : `<kind>:<16 premiers hex de l'empreinte>:<n>`). */
export function identifiantTentative(objet, imprint, attempt) {
  return `${objet === "manifeste" ? "periode" : "point"}:${imprint.slice(2, 18)}:${attempt}`;
}

/** `request_id` du schéma : `jeton_periode:<hash>` ou `jeton_point:<hash>`. */
export function identifiantDemande(objet, imprint) {
  return `${objet === "manifeste" ? "jeton_periode" : "jeton_point"}:${imprint}`;
}

/** `gen_time` du schéma : RFC 3339, fraction d'au plus trois chiffres sans zéro final. */
function genTimePourSchema(texte) {
  if (!texte) return null;
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/.exec(texte);
  if (!m) return null;
  const f = (m[2] ?? "").slice(0, 3).replace(/0+$/, "");
  return `${m[1]}${f ? "." + f : ""}Z`;
}

/**
 * Exécute une tentative. Voir INTERFACES.md (rubrique A) ; paramètres ajoutés
 * (LISEZMOI-A.md, « Écarts au contrat ») : `attempt`, `periodStart`,
 * `deadlineIndex`, `fraicheur`, `retry`, `tardivesAvant`, `k`, `premier408`.
 */
export async function acquerir({
  prestataire,
  imprint,
  objet,
  nonce = null,
  attemptId = null,
  attempt = 1,
  periodStart,
  deadlineIndex = null,
  horloge,
  aleatoire,
  depot = null,
  transport,
  fraicheur = FRAICHEUR_DEFAUT,
  retry = RETRY_DEFAUT,
  tardivesAvant = 0,
  k = 1,
  premier408 = null,
}) {
  controlerPrestataire(prestataire);
  if (!/^0x[0-9a-f]{64}$/.test(imprint)) throw new TypeError("imprint hex32 attendu");
  if (objet !== "manifeste" && objet !== "point") throw new TypeError("objet : manifeste ou point");
  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > 100000) throw new TypeError("attempt : entier de 1 à 100000");
  if (!horloge || typeof horloge.murale !== "function" || typeof horloge.monotone !== "function") throw new TypeError("horloge injectée attendue");
  if (!transport || typeof transport.envoyer !== "function") throw new TypeError("transport injecté attendu");
  if (depot !== null && !Number.isSafeInteger(periodStart)) throw new TypeError("periodStart requis avec un dépôt");
  const ancres = normaliserAncres(ancresDepuisPrestataire(prestataire)); // N-1 d'avance (EX-4.9, règle 8)

  // Nonce frais (EX-5.3, AN-6).
  let n;
  if (nonce === null || nonce === undefined) {
    if (typeof aleatoire !== "function") throw new TypeError("aleatoire injecté attendu");
    let essais = 0;
    do {
      n = tirerNonce(aleatoire);
      if (++essais > 64) throw new ErreurRequete("AN-6", "nonce_reemploye : aucun nonce frais après 64 tirages");
    } while (depot && depot.nonceConnu(n));
  } else {
    n = nonceVersBigint(nonce);
    if (n < 1n || n > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${n} hors de [1, 2^64 - 1]`);
    if (depot && depot.nonceConnu(n)) throw new ErreurRequete("AN-6", `nonce_reemploye : ${nonceVersHex8(n)} figure déjà dans le journal d'acquisition`);
  }
  const requete = construireRequete({ imprint, hash: "sha256", nonce: n, policy_oid: prestataire.policy_oid ?? null });
  const idTentative = attemptId ?? identifiantTentative(objet, imprint, attempt);
  const entetes = entetesRequete({ taille: requete.octets.length, correlationHeader: prestataire.correlation_header ?? null, attemptId: idTentative });

  // Envoi (EX-5.5) ; instants lus sur l'horloge monotone, convertis à l'envoi (EX-5.11).
  const sentAtMs = Math.round(horloge.murale());
  const m0 = horloge.monotone();
  let reponseHttp = null;
  let transportIssue = "reponse";
  let codeTransport = null;
  try {
    reponseHttp = await transport.envoyer({
      url: prestataire.url,
      octets: requete.octets,
      entetes,
      delaiMs: prestataire.request_timeout_ms ?? 10000,
      auth: prestataire.auth ?? null,
      tls: prestataire.tls ?? null,
      role: prestataire.role,
      serveurInterne: prestataire.serveur_interne === true,
    });
  } catch (err) {
    if (!(err instanceof ErreurTransport) || err.code === "url") throw err; // url refusée : configuration (EX-5.5, AN-1), jamais une tentative
    transportIssue = err.code === "delai" ? "delai" : "erreur_transport";
    codeTransport = err.code === "delai" ? "delai" : "erreur_transport";
  }
  const receivedAtMs = sentAtMs + Math.max(0, Math.round(horloge.monotone() - m0));

  // Étapes 1 à 8 d'EX-5.10.
  let code = codeTransport;
  const avertissements = [];
  let httpStatus = null;
  let contentType = null;
  let bodySize = null;
  let retryAfterS = null;
  let corps = null;
  let lecture = null;
  let verification = null;
  let imprintMatches = null;
  let nonceInResponse = null;
  let policyCheck = null;
  let token = null;
  let tokenSha256 = null;

  if (reponseHttp) {
    const statutBrut = reponseHttp.status ?? null;
    const h = reponseHttp.entetes ?? {};
    const typeBrut = h["content-type"] ?? h["Content-Type"] ?? null;
    // R-F-1 : un `Content-Type` vide vaut absent (le schéma exige `minLength 1`) ; un statut hors de [100, 599] n'est pas
    // une réponse HTTP (`transport: erreur_transport`, code `http_hors_bornes`, permanente) : rien ne reste hors schéma.
    contentType = typeof typeBrut === "string" && typeBrut.trim().length > 0 ? typeBrut : null;
    retryAfterS = lireRetryAfter(h["retry-after"] ?? h["Retry-After"] ?? null, receivedAtMs);
    corps = reponseHttp.corps instanceof Uint8Array ? reponseHttp.corps : new Uint8Array(0);
    bodySize = reponseHttp.tronque ? CORPS_MAX + 1 : corps.length;
    if (!Number.isSafeInteger(statutBrut) || statutBrut < 100 || statutBrut > 599) {
      httpStatus = null;
      transportIssue = "erreur_transport";
      code = "http_hors_bornes";
      retryAfterS = null;
    } else httpStatus = statutBrut;
    // Étape 1.
    if (code !== null) {
      // statut hors bornes : rien d'autre n'est lu
    } else if (httpStatus !== 200) code = `http_${httpStatus}`;
    else if (!TYPES_REPONSE.includes(typeMedia(contentType))) code = "type_contenu";
    else if (reponseHttp.tronque || corps.length > CORPS_MAX) code = "taille";
    // Étape 2 : TimeStampResp lisible selon CT-6 §9.3, jeton compris (lecture H1-e : un TimeStampToken qui ne se lit pas
    // par le lecteur borné rend `reponse_illisible`, non `verification_T-1` ; le `.tsr` est écrit tel que reçu, pas de `.der`).
    if (code === null) {
      try {
        lecture = lireReponse(corps);
        if (lecture.token !== null) lireJeton(lecture.token);
      } catch (err) {
        if (!(err instanceof ErreurReponse) && !(err instanceof ErreurDer)) throw err;
        code = "reponse_illisible";
      }
    }
    if (code === null && lecture.status >= 2) {
      code = lecture.status === 2 && lecture.failureInfo && lecture.failureInfo !== "autre" ? `echec_${lecture.failureInfo}` : `statut_${lecture.status}`;
    }
    if (code === null) {
      token = lecture.token;
      tokenSha256 = sha256Hex(token);
      // Étape 6 exécutée en entier pour `checks_passed` ; les étapes 3 à 5 s'appuient sur sa lecture.
      verification = verifierJeton({ octets: token, imprintAttendue: imprint, ancres, aGenTime: true });
      const t = verification.tstInfo;
      if (verification.checks["T-1"] !== "reussi") {
        code = "verification_T-1";
      } else {
        // Étape 3.
        imprintMatches = verification.checks["T-2"] === "reussi";
        if (!imprintMatches) code = "empreinte_differente";
        // Étape 4.
        if (t.nonce !== null && t.nonce >= 0n && t.nonce <= NONCE_MAX) nonceInResponse = nonceVersHex8(t.nonce);
        if (code === null) {
          if (t.nonce === null) code = "nonce_absent";
          else if (t.nonce !== n) code = "nonce_different";
        }
        // Étape 5.
        if (prestataire.policy_oid && t.policy !== prestataire.policy_oid) policyCheck = "politique_differente";
        else if (prestataire.accepted_policies && !prestataire.accepted_policies.includes(t.policy)) policyCheck = "politique_refusee";
        else policyCheck = "conforme";
        if (code === null && policyCheck !== "conforme") code = policyCheck;
        // Étape 6.
        if (code === null) {
          const premiere = VERIFICATIONS_ACQUISITION.find((id) => verification.checks[id] !== "reussi");
          if (premiere) code = `verification_${premiere}`;
        }
        // Étape 7 : fraîcheur.
        if (code === null && receivedAtMs - sentAtMs > fraicheur.max_response_delay_s * 1000) {
          if (tardivesAvant >= 2) avertissements.push("reponse_tardive");
          else code = "reponse_tardive";
        }
        // Étape 8 : horloge.
        if (code === null && t.genTime !== null && Math.abs(t.genTime - sentAtMs) > fraicheur.clock_tolerance_s * 1000) avertissements.push("horloge_suspecte");
      }
    }
  }

  const classement = classerErreur({ code, httpStatus, retryAfter: retryAfterS, pkiStatus: lecture?.status ?? null, failureInfo: lecture?.failureInfo ?? null, retry, k, premier408 });
  let outcome = issueDepuisClasse(classement.classe, code);
  const t = verification?.tstInfo ?? null;
  const S = verification?.certificatSignataire ?? null;
  const checks = {};
  for (const id of VERIFICATIONS_ACQUISITION) checks[id] = verification ? verification.checks[id] : "non_execute";
  checks["T-10"] = "non_execute";
  const checksPassed = verification ? VERIFICATIONS_ACQUISITION.filter((id) => verification.checks[id] === "reussi") : [];

  // Étape 9 : écriture des pièces, puis de l'enregistrement.
  const fichiers = { request: null, response: null, token: null, crls: [], acquisitions: null };
  let erreurEcriture = null;
  const nomBase = depot ? depot.nomPiece({ objet, imprint, providerId: prestataire.id, attemptId: idTentative }) : null;
  if (depot) {
    try {
      fichiers.request = depot.ecrirePiece(periodStart, "rfc3161", `${nomBase}.tsq`, requete.octets);
      if (corps && httpStatus === 200 && TYPES_REPONSE.includes(typeMedia(contentType)) && corps.length > 0 && code !== "taille") {
        fichiers.response = depot.ecrirePiece(periodStart, "rfc3161", `${nomBase}.tsr`, corps);
      }
      if (token) fichiers.token = depot.ecrirePiece(periodStart, "rfc3161", `${nomBase}.der`, token);
    } catch (err) {
      if (!(err instanceof ErreurDepot)) throw err;
      erreurEcriture = err;
    }
  }
  if (erreurEcriture) {
    code = "ecriture";
    outcome = "echec_transitoire";
  }
  const promoted = outcome === "obtenue" && (depot ? !depot.dejaPromu(objet, imprint, periodStart) : true);

  const enregistrement = {
    attempt_id: idTentative,
    attempt,
    org_id: depot ? depot.orgId : null,
    journal_id: depot ? depot.journalId : null,
    period_start: Number.isSafeInteger(periodStart) ? periodStart : null,
    object: objet,
    object_name: nomObjet(objet, imprint),
    imprint,
    hash_algorithm: "sha256",
    deadline_index: deadlineIndex,
    provider_id: prestataire.id,
    provider_role: prestataire.role,
    qualified: prestataire.qualified ?? null,
    nonce: nonceVersHex8(n),
    request_sha256: requete.sha256,
    request_size: requete.octets.length,
    sent_at: ecrireHorodatage(sentAtMs),
    received_at: ecrireHorodatage(receivedAtMs),
    transport: transportIssue,
    http_status: httpStatus,
    content_type: contentType === null ? null : String(contentType),
    body_size: bodySize,
    retry_after_s: retryAfterS,
    pki_status: lecture ? lecture.status : null,
    pki_failure_info: lecture ? lecture.failureInfo : null,
    outcome,
    error_code: outcome === "obtenue" ? null : code,
    error_class: classement.classe,
    alert: classement.alerte,
    retry_delay_ms: classement.attenteMs,
    response_sha256: corps && fichiers.response !== null ? sha256Hex(corps) : corps && httpStatus === 200 && code !== "taille" && TYPES_REPONSE.includes(typeMedia(contentType)) ? sha256Hex(corps) : null,
    token_sha256: tokenSha256,
    token_size: token ? token.length : null,
    gen_time: t ? t.genTimeTexte : null,
    accuracy: t ? t.accuracy : null,
    upper_bound: t && t.upperBoundMs !== null ? ecrireHorodatage(t.upperBoundMs) : null,
    serial_number: t ? t.serialNumber : null,
    policy: t ? t.policy : null,
    policy_check: policyCheck,
    nonce_in_response: nonceInResponse,
    imprint_matches: imprintMatches,
    tsu_subject: S ? octetsVersHex(S.sujet.octets) : null,
    tsu_subject_cn: S ? S.sujet.cn : null,
    tsu_certificate_sha256: S ? S.sha256 : null,
    authority: verification?.autorite ? verification.autorite.nom : null,
    freshness: outcome === "obtenue" ? (avertissements.includes("reponse_tardive") ? "reponse_tardive" : "nonce") : code === "reponse_tardive" ? "reponse_tardive" : null,
    warnings: avertissements,
    checks,
    checks_passed: checksPassed,
    promoted,
    revoked: false,
    files: { request: fichiers.request, response: fichiers.response, token: fichiers.token, crls: [] },
  };
  if (depot && !erreurEcriture) {
    try {
      fichiers.acquisitions = depot.ajouterAcquisition(periodStart, enregistrement);
    } catch (err) {
      if (!(err instanceof ErreurDepot)) throw err;
      erreurEcriture = err;
      enregistrement.outcome = "echec_transitoire";
      enregistrement.error_code = "ecriture";
    }
  }

  const data = {
    request_id: identifiantDemande(objet, imprint),
    attempt,
    transport: transportIssue,
    http_status: httpStatus,
    pki_status: lecture ? lecture.status : null,
    failure_info: lecture ? lecture.failureInfo : null,
    retry_after_s: retryAfterS,
    nonce_in_response: nonceInResponse,
    imprint_matches: imprintMatches,
    checks_passed: checksPassed,
    gen_time: t ? genTimePourSchema(t.genTimeTexte) : null,
    accuracy_s: t ? (t.accuracyUs === null ? null : Math.ceil(t.accuracyUs / 1e6)) : null,
    token_sha256: tokenSha256,
    token_size: token ? token.length : null,
    content_type: contentType === null ? null : String(contentType).slice(0, 256),
    body_size: bodySize,
    policy_check: policyCheck,
  };

  return {
    data,
    enregistrement,
    fichiers,
    verification,
    classement,
    outcome: enregistrement.outcome,
    code: enregistrement.error_code,
    warnings: avertissements,
    requete: requete.octets,
    reponse: corps,
    jeton: token,
    erreurEcriture,
  };
}
