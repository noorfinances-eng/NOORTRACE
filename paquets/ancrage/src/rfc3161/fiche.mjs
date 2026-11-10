// Fiche de prestataire (CT-5 EX-10.6, AN-54) et épreuve d'acceptation
// (EX-11.4, AN-57) : l'élément `providers[]` d'`ancrage-v0` privé de `auth`,
// complété des SHA-256 des certificats, de l'instantané `qualified`, des
// sources de révocation et du résultat daté de l'épreuve. Ni identifiant de
// compte, ni secret, ni prix.

import { createHash } from "node:crypto";
import { ecrireHorodatage, utf8 } from "@noortrace/noyau";
import { octetsVersHex } from "./der.mjs";
import { lireCertificatPem, pointsDistributionCrl, urisOcsp } from "./x509.mjs";
import { acquerir } from "./acquisition.mjs";
import { transportHttps } from "./transport.mjs";

/** Clés interdites dans une fiche, à tout niveau (AN-54). */
export const CLES_INTERDITES = Object.freeze(["auth", "secret", "price", "account", "password"]);

/** Mention portée quand le prestataire des points n'est pas qualifié (EX-10.6, EX-4.10, EX-7.3). */
export const MENTION_NON_QUALIFIE = "non qualifie : la cible W_date de CT-5 3.3 n'est pas tenue face à l'opérateur (EX-4.10, EX-7.3)";

/** Étiquette de l'empreinte de test de l'épreuve d'acceptation. */
export const ETIQUETTE_EPREUVE = "noortrace/ancrage/epreuve-acceptation/v0";

/** Empreinte de test : SHA-256 de l'étiquette et de l'instant de l'épreuve. */
export function empreinteEpreuve(testedAt) {
  return octetsVersHex(new Uint8Array(createHash("sha256").update(utf8(`${ETIQUETTE_EPREUVE}/${testedAt}`)).digest()));
}

/**
 * Construit le document `prestataire-<id>.json`. `epreuve` : résultat
 * d'`epreuveAcceptation`, ou `null`.
 */
export function construireFiche(prestataire, { epreuve = null } = {}) {
  if (!prestataire || typeof prestataire !== "object") throw new TypeError("prestataire attendu");
  const certificats = (prestataire.anchor_certificates ?? []).map((pem) => lireCertificatPem(pem));
  const crl = [];
  const ocsp = [];
  for (const c of certificats) {
    for (const u of pointsDistributionCrl(c)) if (!crl.includes(u)) crl.push(u);
    for (const u of urisOcsp(c)) if (!ocsp.includes(u)) ocsp.push(u);
  }
  const qualified = prestataire.qualified ?? null;
  const nonQualifie = qualified === null;
  const fiche = {
    version: 0,
    id: prestataire.id,
    role: prestataire.role,
    url: prestataire.url,
    hash: prestataire.hash,
    policy_oid: prestataire.policy_oid ?? null,
    accepted_policies: prestataire.accepted_policies ?? null,
    anchor_certificates: [...(prestataire.anchor_certificates ?? [])],
    anchor_certificates_sha256: certificats.map((c) => c.sha256),
    anchor_certificates_subjects: certificats.map((c) => c.sujet.cn),
    qualified,
    qualified_notice: nonQualifie ? MENTION_NON_QUALIFIE : null,
    revocation_sources: { crl, ocsp },
    min_interval_ms: prestataire.min_interval_ms,
    request_timeout_ms: prestataire.request_timeout_ms,
    correlation_header: prestataire.correlation_header ?? null,
    source: prestataire.source,
    acceptance_test: epreuve,
  };
  return fiche;
}

/** Nom du fichier d'une fiche. */
export function nomFiche(fiche) {
  return `prestataire-${fiche.id}.json`;
}

const RFC3339 = /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/;
const ISSUES = new Set(["obtenue", "echec_transitoire", "echec_permanente", "reponse_tardive"]);

/** Clés interdites présentes à n'importe quel niveau (noms comparés sans la casse). */
export function clesInterdites(valeur, chemin = "") {
  const trouvees = [];
  if (Array.isArray(valeur)) {
    valeur.forEach((v, i) => trouvees.push(...clesInterdites(v, `${chemin}[${i}]`)));
  } else if (valeur && typeof valeur === "object") {
    for (const [k, v] of Object.entries(valeur)) {
      if (CLES_INTERDITES.includes(k.toLowerCase())) trouvees.push(`${chemin}.${k}`.replace(/^\./, ""));
      trouvees.push(...clesInterdites(v, chemin ? `${chemin}.${k}` : k));
    }
  }
  return trouvees;
}

/** AN-54 : `{ conforme, ecarts }`. */
export function verifierFiche(fiche) {
  const ecarts = [];
  if (!fiche || typeof fiche !== "object" || Array.isArray(fiche)) return { conforme: false, ecarts: ["fiche : objet attendu"] };
  for (const k of ["id", "role", "url", "hash", "policy_oid", "accepted_policies", "anchor_certificates", "anchor_certificates_sha256", "qualified", "min_interval_ms", "request_timeout_ms", "correlation_header", "source", "acceptance_test"]) {
    if (!(k in fiche)) ecarts.push(`clé ${k} absente`);
  }
  for (const k of clesInterdites(fiche)) ecarts.push(`clé interdite ${k}`);
  if (!["principal", "secours", "second_rang", "interne"].includes(fiche.role)) ecarts.push("role hors énumération");
  if (typeof fiche.url !== "string" || !/^https?:\/\/[^\s]+$/.test(fiche.url)) ecarts.push("url mal formée");
  if (fiche.hash !== "sha256") ecarts.push("hash autre que sha256");
  if (fiche.role === "interne" && fiche.qualified !== null) ecarts.push("un prestataire interne n'est jamais qualifié (EX-7.1, EX-5.6)");
  if (fiche.qualified === null && fiche.qualified_notice !== MENTION_NON_QUALIFIE) ecarts.push("mention « non qualifié » absente (EX-10.6)");
  if (Array.isArray(fiche.anchor_certificates)) {
    if (!Array.isArray(fiche.anchor_certificates_sha256) || fiche.anchor_certificates_sha256.length !== fiche.anchor_certificates.length) {
      ecarts.push("anchor_certificates_sha256 : une valeur par certificat");
    } else {
      fiche.anchor_certificates.forEach((pem, i) => {
        try {
          const c = lireCertificatPem(pem);
          if (c.sha256 !== fiche.anchor_certificates_sha256[i]) ecarts.push(`anchor_certificates[${i}] : SHA-256 différent de celui déclaré`);
        } catch (err) {
          ecarts.push(`anchor_certificates[${i}] illisible : ${err.message}`);
        }
      });
    }
  } else ecarts.push("anchor_certificates : liste attendue");
  const e = fiche.acceptance_test;
  if (e !== null && e !== undefined) {
    if (typeof e !== "object") ecarts.push("acceptance_test : objet ou null");
    else {
      if (typeof e.tested_at !== "string" || !RFC3339.test(e.tested_at)) ecarts.push("acceptance_test.tested_at : horodatage RFC 3339 attendu");
      if (!ISSUES.has(e.outcome)) ecarts.push("acceptance_test.outcome hors énumération");
      if (e.outcome === "obtenue" && !/^0x[0-9a-f]{64}$/.test(e.tsu_certificate_sha256 ?? "")) ecarts.push("acceptance_test.tsu_certificate_sha256 attendu pour une épreuve réussie (AN-57)");
    }
  }
  return { conforme: ecarts.length === 0, ecarts };
}

/**
 * Épreuve d'acceptation (EX-11.4) : une requête d'EX-5.1 sur une empreinte de
 * test, la réponse vérifiée par EX-5.10 (nonce repris, T-1 à T-9 avec les
 * `anchor_certificates` et `accepted_policies` du prestataire ; T-10 reste
 * différée), résultat daté. Aucun fichier n'est écrit.
 */
export async function epreuveAcceptation({ prestataire, transport = null, horloge, aleatoire, fraicheur, imprint = null }) {
  const testedAt = ecrireHorodatage(horloge.murale());
  const empreinte = imprint ?? empreinteEpreuve(testedAt);
  const r = await acquerir({
    prestataire,
    imprint: empreinte,
    objet: "point",
    attemptId: `epreuve:${empreinte.slice(2, 18)}:1`,
    attempt: 1,
    periodStart: Math.floor(horloge.murale() / 3600000) * 3600,
    horloge,
    aleatoire,
    depot: null,
    transport: transport ?? transportHttps(),
    ...(fraicheur ? { fraicheur } : {}),
  });
  const e = r.enregistrement;
  return {
    tested_at: testedAt,
    imprint: empreinte,
    nonce: e.nonce,
    outcome: e.outcome,
    error_code: e.error_code,
    error_class: e.error_class,
    http_status: e.http_status,
    pki_status: e.pki_status,
    pki_failure_info: e.pki_failure_info,
    nonce_in_response: e.nonce_in_response,
    imprint_matches: e.imprint_matches,
    policy_check: e.policy_check,
    checks: e.checks,
    checks_passed: e.checks_passed,
    warnings: e.warnings,
    gen_time: e.gen_time,
    upper_bound: e.upper_bound,
    policy: e.policy,
    serial_number: e.serial_number,
    tsu_subject_cn: e.tsu_subject_cn,
    tsu_certificate_sha256: e.tsu_certificate_sha256,
    authority: e.authority,
    token_sha256: e.token_sha256,
    token_size: e.token_size,
    qualified_snapshot: prestataire.qualified ?? null,
    note: "T-10 différée (capture des CRL après genTime) ; la qualification se recoupe sur la liste de confiance (EX-5.9), jamais sur cette épreuve",
  };
}
