// Configuration `ancrage-v0` (CT-5 §4.4) : validation AN-1 (schéma puis les
// huit règles d'EX-4.9, rapport nominatif complet) et projection d'EX-8.2 sur
// les clés que le planificateur lit (`$defs/configuration` du schéma
// `planificateur-ancrage-v0`). Le module ne lit aucun fichier : les schémas
// sont embarqués (schemas-ancrage.mjs).

import { RegistreSchemas } from "@noortrace/noyau";
import { SCHEMA_ANCRAGE, SCHEMA_PLANIFICATEUR } from "./schemas-ancrage.mjs";

/** Registre des deux schémas de CT-5. */
export const REGISTRE_ANCRAGE = new RegistreSchemas([SCHEMA_ANCRAGE, SCHEMA_PLANIFICATEUR]);

/** Référence du schéma de la configuration et de ses définitions. */
export const ID_SCHEMA_ANCRAGE = SCHEMA_ANCRAGE.$id;
/** Référence du schéma des traces, des demandes et des familles de vecteurs. */
export const ID_SCHEMA_PLANIFICATEUR = SCHEMA_PLANIFICATEUR.$id;

/** Profils de CT-2 §15 : la même notion que l'enregistreur. */
export const PROFILS = Object.freeze(["developpement", "test", "production"]);

/** Hôtes locaux admis pour un prestataire `interne` en `http://` (EX-4.9, règle 4). */
const HOTES_LOCAUX = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);

/**
 * Le prestataire suit-il les règles d'adresse et d'authentification du serveur
 * RFC 3161 interne (CT-5 §7, EX-4.9 règle 4) ? Oui pour le rôle `interne` ; et,
 * hors production seulement (révision 0.9 de CT-5), pour le `principal` non
 * qualifié (`qualified: null`) : le serveur interne tient alors lieu de
 * prestataire principal, jeton de clôture compris, sans jamais être qualifié.
 * @param {{role: string, qualified: object|null}} p
 * @param {boolean} production
 */
export function commeServeurInterne(p, production) {
  return p.role === "interne" || (!production && p.role === "principal" && p.qualified === null);
}

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Valide une instance contre un schéma de CT-5 ou l'une de ses définitions.
 * @param {string} ref `$id` ou `$id#/$defs/…`
 * @param {unknown} instance
 * @returns {{valide: boolean, erreurs: string[]}}
 */
export function validerSchemaAncrage(ref, instance) {
  return REGISTRE_ANCRAGE.valider(ref, instance);
}

/**
 * Hôte d'une URL, ou null si l'URL ne se lit pas.
 * @param {string} url
 */
function hoteDe(url) {
  try {
    const u = new URL(url);
    return { protocole: u.protocol, hote: u.hostname };
  } catch {
    return null;
  }
}

/**
 * Lecture bornée d'un certificat PEM : un seul bloc `CERTIFICATE`, base64
 * canonique, DER d'une `SEQUENCE` de trois éléments (`tbsCertificate`
 * `SEQUENCE`, `signatureAlgorithm` `SEQUENCE`, `signatureValue` `BIT STRING`)
 * dont les longueurs se recoupent exactement (CT-6 §9.3, règle 8 d'EX-4.9).
 * La lecture complète des champs est celle du lecteur DER du lot A.
 * @param {string} pem
 * @returns {string|null} motif du refus, ou null
 */
export function motifCertificatPemIllisible(pem) {
  if (typeof pem !== "string") return "PEM attendu";
  const m = /^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$/.exec(pem);
  if (!m) return "un seul bloc CERTIFICATE attendu";
  const b64 = m[1].replace(/\n/g, "");
  if (b64.length % 4 !== 0 || /=[^=]/.test(b64) || /={3,}/.test(b64)) return "base64 non canonique";
  const der = Buffer.from(b64, "base64");
  if (der.length < 8 || der.length > 65536) return `DER de ${der.length} octets hors bornes`;
  if (Buffer.from(der).toString("base64") !== b64) return "base64 non canonique";
  const lireTlv = (pos, fin) => {
    if (pos + 2 > fin) return null;
    const etiquette = der[pos];
    let l = der[pos + 1];
    let debut = pos + 2;
    if (l & 0x80) {
      const nb = l & 0x7f;
      if (nb === 0 || nb > 4 || debut + nb > fin) return null;
      l = 0;
      for (let i = 0; i < nb; i++) l = l * 256 + der[debut + i];
      if ((nb === 1 && l < 0x80) || (nb > 1 && l < 256 ** (nb - 1))) return null;
      debut += nb;
    }
    if (debut + l > fin) return null;
    return { etiquette, debut, fin: debut + l };
  };
  const racine = lireTlv(0, der.length);
  if (!racine || racine.etiquette !== 0x30 || racine.fin !== der.length) return "la racine n'est pas une SEQUENCE qui couvre tout le DER";
  const tbs = lireTlv(racine.debut, racine.fin);
  if (!tbs || tbs.etiquette !== 0x30) return "tbsCertificate : SEQUENCE attendue";
  const alg = lireTlv(tbs.fin, racine.fin);
  if (!alg || alg.etiquette !== 0x30) return "signatureAlgorithm : SEQUENCE attendue";
  const sig = lireTlv(alg.fin, racine.fin);
  if (!sig || sig.etiquette !== 0x03 || sig.fin !== racine.fin) return "signatureValue : BIT STRING final attendu";
  if (sig.fin - sig.debut < 2 || der[sig.debut] !== 0) return "signatureValue : bits inutilisés non nuls";
  return null;
}

/**
 * AN-1 : valide un document `ancrage-v0` contre son schéma puis applique les
 * huit règles d'EX-4.9 ; rend la liste complète des règles violées.
 * @param {unknown} document
 * @param {{profil?: string, checkpointIntervalEnregistreur?: number|null}} [options]
 *   `profil` : profil de CT-2 §15 (`production` déclenche la règle 4 et la
 *   partie production de la règle 1) ; `checkpointIntervalEnregistreur` :
 *   `checkpoint_interval_s` de `configuration-enregistreur-v0`, ou null s'il
 *   n'est pas connu
 * @returns {{valide: boolean, erreurs: {regle: string, message: string}[], projection: object|null}}
 */
export function validerConfiguration(document, options = {}) {
  const profil = options.profil ?? "developpement";
  if (!PROFILS.includes(profil)) throw new RangeError(`profil inconnu : ${String(profil)}`);
  const cKEnregistreur = options.checkpointIntervalEnregistreur ?? null;
  const production = profil === "production";
  const erreurs = [];
  const violer = (regle, message) => erreurs.push({ regle, message });

  const schema = REGISTRE_ANCRAGE.valider(ID_SCHEMA_ANCRAGE, document);
  if (!schema.valide) {
    for (const e of schema.erreurs) violer("schema", e);
    return { valide: false, erreurs, projection: null };
  }
  const d = document;
  const cK = d.checkpoint_interval_s;

  // Règle 1 : cadence des points égale à celle de l'enregistreur, diviseur de 3600.
  if (3600 % cK !== 0) violer("1", `checkpoint_interval_s ${cK} ne divise pas 3600`);
  if (cKEnregistreur === null) {
    if (production) violer("1", "checkpoint_interval_s de l'enregistreur inconnu : refusé en production");
  } else if (!Number.isSafeInteger(cKEnregistreur)) {
    violer("1", "checkpoint_interval_s de l'enregistreur : entier attendu");
  } else if (cKEnregistreur !== cK) {
    violer("1", `checkpoint_interval_s ${cK} différent de celui de l'enregistreur (${cKEnregistreur})`);
  }

  // Règle 2 : un principal, au plus un secours, ids distincts.
  const fournisseurs = d.rfc3161.providers;
  const parRole = (role) => fournisseurs.filter((p) => p.role === role);
  if (parRole("principal").length !== 1) violer("2", `${parRole("principal").length} prestataire(s) de rôle principal : exactement un attendu`);
  if (parRole("secours").length > 1) violer("2", `${parRole("secours").length} prestataires de rôle secours : au plus un`);
  const ids = new Set();
  for (const p of fournisseurs) {
    if (ids.has(p.id)) violer("2", `id de prestataire en double : ${p.id}`);
    ids.add(p.id);
  }

  // Règle 3 : c_T multiple de c_K et diviseur de 3600.
  const cT = d.rfc3161.checkpoints.interval_s;
  if (cT % cK !== 0) violer("3", `rfc3161.checkpoints.interval_s ${cT} n'est pas un multiple de checkpoint_interval_s ${cK}`);
  if (3600 % cT !== 0) violer("3", `rfc3161.checkpoints.interval_s ${cT} ne divise pas 3600`);

  // Règle 4 : exigences de production ; adresse locale d'un interne en http ; hors production, le
  // serveur RFC 3161 interne peut être le principal (révision 0.9 de CT-5).
  const role = d.rfc3161.checkpoints.provider_role;
  if (production) {
    if (role === "aucun") violer("4", "rfc3161.checkpoints.provider_role aucun : refusé en production");
    if (d.registry.checkpoints === "aucun") violer("4", "registry.checkpoints aucun : refusé en production");
    if (d.opentimestamps.enabled !== true) violer("4", "opentimestamps.enabled faux : refusé en production");
    for (const p of parRole("principal")) if (p.qualified === null) violer("4", `principal ${p.id} sans qualified : refusé en production`);
    for (const p of parRole("secours")) if (p.qualified === null) violer("4", `secours ${p.id} sans qualified : refusé en production (EX-5.7)`);
  }
  for (const p of fournisseurs) {
    const u = hoteDe(p.url);
    if (!u) {
      violer("4", `prestataire ${p.id} : url illisible`);
      continue;
    }
    // EX-5.5 : « la requête est envoyée par HTTP sur TLS », sans profil ; `http://` n'est admis que pour le serveur
    // interne vers une adresse locale (règle 4). Le transport refuse la même chose : la configuration le dit d'avance.
    const interne = commeServeurInterne(p, production);
    const principalInterne = p.role === "principal" && p.qualified === null;
    if (!interne && u.protocole !== "https:") {
      violer(
        "4",
        production && principalInterne
          ? `principal ${p.id} : url ${u.protocole}// refusée en production ; le serveur RFC 3161 interne n'est admis comme principal que hors production (EX-4.9, règle 4)`
          : `prestataire ${p.id} (${p.role}) : url en https:// exigée hors du serveur interne, quel que soit le profil (EX-5.5, TLS obligatoire)`,
      );
    }
    if (interne && u.protocole === "http:" && !HOTES_LOCAUX.has(u.hote)) {
      violer("4", `prestataire ${p.id} (${p.role}, serveur interne) : http:// n'est admis que vers une adresse locale (127.0.0.1, ::1, localhost), sinon https:// (EX-5.5)`);
    }
    if (p.auth.method === "aucune" && (!interne || !HOTES_LOCAUX.has(u.hote))) {
      violer(
        "4",
        production && principalInterne
          ? `principal ${p.id} : auth aucune refusée en production ; le serveur RFC 3161 interne n'est admis comme principal que hors production (EX-4.9, règle 4)`
          : `prestataire ${p.id} : auth aucune n'est admise que pour le serveur interne sur une adresse locale (EX-5.5)`,
      );
    }
    if (p.auth.method !== "aucune" && p.auth.secret === null) violer("4", `prestataire ${p.id} : auth ${p.auth.method} sans secret`);
  }

  // Règle 5 : OpenTimestamps activé ⇒ deux calendriers, min_responses, liste blanche.
  const ots = d.opentimestamps;
  if (ots.enabled) {
    if (new Set(ots.calendars).size < 2) violer("5", `opentimestamps.calendars : au moins deux calendriers distincts (${ots.calendars.length})`);
    if (ots.min_responses > ots.calendars.length) violer("5", `opentimestamps.min_responses ${ots.min_responses} supérieur au nombre de calendriers ${ots.calendars.length}`);
    if (ots.upgrade.whitelist.length < 1) violer("5", "opentimestamps.upgrade.whitelist vide");
  }

  // Règle 6 : conservation, reprise, cadence de mise à niveau.
  if (d.rfc3161.retention_years < 10) violer("6", `rfc3161.retention_years ${d.rfc3161.retention_years} : au moins 10`);
  if (d.rfc3161.retry.initial_ms > d.rfc3161.retry.max_ms) violer("6", `rfc3161.retry.initial_ms ${d.rfc3161.retry.initial_ms} supérieur à max_ms ${d.rfc3161.retry.max_ms}`);
  if (ots.upgrade.interval_s < 60) violer("6", `opentimestamps.upgrade.interval_s ${ots.upgrade.interval_s} : au moins 60 s`);

  // Règle 7 : le rôle désigné pour les points existe.
  if ((role === "second_rang" || role === "interne") && parRole(role).length === 0) {
    violer("7", `rfc3161.checkpoints.provider_role ${role} sans prestataire de ce rôle`);
  }

  // Règle 8 : chaque PEM se lit comme un certificat.
  for (const p of fournisseurs) {
    p.anchor_certificates.forEach((pem, i) => {
      const motif = motifCertificatPemIllisible(pem);
      if (motif) violer("8", `prestataire ${p.id} : anchor_certificates[${i}] illisible (${motif})`);
    });
  }

  return { valide: erreurs.length === 0, erreurs, projection: erreurs.length === 0 ? projection(d) : null };
}

/**
 * Projection d'EX-8.2 : les clés que le planificateur lit, aux mêmes chemins
 * et bornes qu'`ancrage-v0`, `qualified` réduit à un booléen ; ni secret, ni
 * certificat, ni URL, ni source, ni chemin.
 * @param {object} document document `ancrage-v0` valide
 * @returns {object} `$defs/configuration` de `planificateur-ancrage-v0`
 */
export function projection(document) {
  if (!estObjet(document)) throw new TypeError("document ancrage-v0 attendu");
  const r = document.rfc3161;
  const o = document.opentimestamps;
  return {
    checkpoint_interval_s: document.checkpoint_interval_s,
    rfc3161: {
      providers: r.providers.map((p) => ({
        id: p.id,
        role: p.role,
        policy_oid: p.policy_oid,
        qualified: p.qualified !== null && p.qualified !== undefined,
        min_interval_ms: p.min_interval_ms,
        request_timeout_ms: p.request_timeout_ms,
      })),
      manifest: { fallback_after_s: r.manifest.fallback_after_s },
      checkpoints: {
        interval_s: r.checkpoints.interval_s,
        provider_role: r.checkpoints.provider_role,
        fallback_after_s: r.checkpoints.fallback_after_s,
        countersign_idle: r.checkpoints.countersign_idle,
      },
      freshness: { max_response_delay_s: r.freshness.max_response_delay_s, clock_tolerance_s: r.freshness.clock_tolerance_s },
      retry: { initial_ms: r.retry.initial_ms, factor: r.retry.factor, max_ms: r.retry.max_ms, jitter_ms: r.retry.jitter_ms },
    },
    registry: { checkpoints: document.registry.checkpoints, squat_wait_s: document.registry.squat_wait_s, inclusion_alert_s: document.registry.inclusion_alert_s },
    opentimestamps: {
      enabled: o.enabled,
      calendars: [...o.calendars],
      min_responses: o.min_responses,
      timeout_ms: o.timeout_ms,
      checkpoint: o.checkpoint,
      upgrade: { first_after_s: o.upgrade.first_after_s, interval_s: o.upgrade.interval_s, give_up_after_s: o.upgrade.give_up_after_s },
    },
    queue: { max_pending: document.queue.max_pending, anchor_pending_alert_s: document.queue.anchor_pending_alert_s },
  };
}

/**
 * Valide une projection contre `$defs/configuration` (traces, planificateur).
 * @param {unknown} projection
 * @returns {{valide: boolean, erreurs: string[]}}
 */
export function validerProjection(projection) {
  return REGISTRE_ANCRAGE.valider(`${ID_SCHEMA_PLANIFICATEUR}#/$defs/configuration`, projection);
}
