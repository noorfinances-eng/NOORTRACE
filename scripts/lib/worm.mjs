// Copies WORM et gel juridique (CT-2 révision 0.5, §12.6 et §12.11) : briques
// SANS RÉSEAU de l'enregistreur (copie, contrôle du verrou, relevé) et de
// l'outil `noortrace-ctl worm gel`. Ce module construit les requêtes exactes
// (EX-12.39), juge l'état de verrouillage lu d'une version (EX-12.33), calcule
// le périmètre d'un gel (EX-12.35), les empreintes des enregistrements du
// registre des gels (EX-12.37) et la règle de garde de la levée (EX-12.38).
// Il n'envoie rien : l'hôte, la date et la signature sont ajoutés par la
// couche d'accès du support, hors de ce module.
//
// Les formes rendues suivent le schéma spec/schemas/worm-v0.schema.json
// (`$defs/requete`, `$defs/ligne_copie`, `$defs/ligne_objet_gel`,
// `$defs/enregistrement_gel`) ; la famille de vecteurs spec/vecteurs/ct-2/worm/
// (annexe B.9) les fixe cas par cas.

import crypto from "node:crypto";
import * as J from "./journal.mjs";

// ---------------------------------------------------------------------------
// Encodage des cibles (EX-12.39)
// ---------------------------------------------------------------------------

const NON_RESERVE = /^[A-Za-z0-9\-._~]$/;

/**
 * Encode un texte octet par octet (EX-12.39) : chaque octet UTF-8 hors des
 * caractères non réservés de la RFC 3986 (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`,
 * `_`, `~`) devient `%` suivi de deux chiffres hexadécimaux MAJUSCULES ; `/`
 * est gardé si `garderBarre`.
 */
export function encoderSegment(texte, garderBarre = false) {
  if (typeof texte !== "string") throw new TypeError("encoderSegment : chaîne attendue");
  let out = "";
  for (const o of Buffer.from(texte, "utf8")) {
    const c = String.fromCharCode(o);
    if (o < 0x80 && (NON_RESERVE.test(c) || (garderBarre && c === "/"))) out += c;
    else out += "%" + o.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** `Content-MD5` (RFC 1864) : base64 des 16 octets du MD5 du corps. */
export const contentMD5 = (octets) => crypto.createHash("md5").update(octets).digest("base64");

const DECLARATION_XML = '<?xml version="1.0" encoding="UTF-8"?>';
const ESPACE_NOMS_S3 = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"';
/** Version de l'API Azure Blob employée (EX-12.39). */
export const VERSION_AZURE = "2020-06-12";

/** Corps XML de `PutObjectLegalHold` (`ON` : 128 octets ; `OFF` : 129). */
export const corpsGelS3 = (gel) => Buffer.from(`${DECLARATION_XML}<LegalHold ${ESPACE_NOMS_S3}><Status>${gel ? "ON" : "OFF"}</Status></LegalHold>`, "utf8");

/** Corps XML de `PutObjectLockConfiguration` en mode `COMPLIANCE` (EX-12.30, 273 octets pour 4 018 jours). */
export function corpsConfigurationVerrouS3(days) {
  if (!Number.isSafeInteger(days) || days < 1) throw new RangeError("corpsConfigurationVerrouS3 : nombre de jours entier positif attendu");
  return Buffer.from(
    `${DECLARATION_XML}<ObjectLockConfiguration ${ESPACE_NOMS_S3}><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>${days}</Days><Mode>COMPLIANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>`,
    "utf8",
  );
}

const cleTri = (nom) => nom.toLowerCase();

/**
 * Forme `$defs/requete` du schéma `worm-v0` : en-têtes triés par nom en
 * minuscules (tri stable), corps en UTF-8, longueur et SHA-256 (`null` sans corps).
 */
export function requete(method, target, headers, corps = null) {
  const h = headers.map(([n, v]) => [n, String(v)]);
  h.sort((a, b) => (cleTri(a[0]) < cleTri(b[0]) ? -1 : cleTri(a[0]) > cleTri(b[0]) ? 1 : 0));
  return {
    method,
    target,
    headers: h,
    body_utf8: corps ? corps.toString("utf8") : null,
    body_length: corps ? corps.length : 0,
    body_sha256: corps ? J.sha256(corps) : null,
  };
}

const enteteCorps = (corps) => [["Content-Length", String(corps.length)], ["Content-MD5", contentMD5(corps)]];
const cibleS3 = (cle) => "/" + encoderSegment(cle, true);

/** S3, poser (`gel: true`) ou lever un gel : `PUT /<clé>?legal-hold&versionId=<version>`. */
export function requeteGelS3({ cle, versionId, gel }) {
  const corps = corpsGelS3(gel);
  return requete("PUT", `${cibleS3(cle)}?legal-hold&versionId=${encoderSegment(versionId)}`, enteteCorps(corps), corps);
}
/** S3, lire le gel : `GET /<clé>?legal-hold&versionId=<version>`. */
export const requeteLireGelS3 = ({ cle, versionId }) => requete("GET", `${cibleS3(cle)}?legal-hold&versionId=${encoderSegment(versionId)}`, []);
/** S3, lire l'état d'une version : `HEAD /<clé>?versionId=<version>`. */
export const requeteEtatS3 = ({ cle, versionId }) => requete("HEAD", `${cibleS3(cle)}?versionId=${encoderSegment(versionId)}`, []);
/** S3, lister les versions (paramètres dans l'ordre de la syntaxe de la page `ListObjectVersions`). */
export function requeteListeS3({ prefix, keyMarker = null, versionIdMarker = null }) {
  let t = "/?versions";
  if (keyMarker !== null) t += "&key-marker=" + encoderSegment(keyMarker);
  t += "&max-keys=1000&prefix=" + encoderSegment(prefix);
  if (versionIdMarker !== null) t += "&version-id-marker=" + encoderSegment(versionIdMarker);
  return requete("GET", t, []);
}
/** S3, rétention par défaut posée par l'exploitant (EX-12.30) : `PUT /?object-lock`. */
export function requeteConfigurationVerrouS3(days) {
  const corps = corpsConfigurationVerrouS3(days);
  return requete("PUT", "/?object-lock", enteteCorps(corps), corps);
}
/** S3, lire la rétention par défaut : `GET /?object-lock`. */
export const requeteLireConfigurationS3 = () => requete("GET", "/?object-lock", []);
/** S3, copie conditionnelle à l'absence (EX-12.16, EX-12.31). */
export function requeteCopieS3({ cle, octets, gelALEcriture = false }) {
  const corps = Buffer.from(octets);
  const h = [...enteteCorps(corps), ["If-None-Match", "*"]];
  if (gelALEcriture) h.push(["x-amz-object-lock-legal-hold", "ON"]);
  return requete("PUT", cibleS3(cle), h, corps);
}
/** Azure, poser ou lever le gel de niveau version : `PUT /<conteneur>/<blob>?comp=legalhold&versionid=<version>`. */
export function requeteGelAzure({ conteneur, blob, versionId, gel }) {
  return requete(
    "PUT",
    `/${encoderSegment(conteneur)}/${encoderSegment(blob, true)}?comp=legalhold&versionid=${encoderSegment(versionId)}`,
    [["Content-Length", "0"], ["x-ms-legal-hold", gel ? "true" : "false"], ["x-ms-version", VERSION_AZURE]],
  );
}
/** Azure, lire l'état d'une version : `HEAD /<conteneur>/<blob>?versionid=<version>`. */
export const requeteEtatAzure = ({ conteneur, blob, versionId }) =>
  requete("HEAD", `/${encoderSegment(conteneur)}/${encoderSegment(blob, true)}?versionid=${encoderSegment(versionId)}`, [["x-ms-version", VERSION_AZURE]]);
const cibleGcs = (bucket, nom, generation) => `/storage/v1/b/${encoderSegment(bucket)}/o/${encoderSegment(nom)}?generation=${encoderSegment(generation)}`;
/** GCS, poser ou lever `temporaryHold` : `PATCH` de la ressource objet, corps JCS intégral (22 ou 23 octets). */
export function requeteGelGcs({ bucket, nom, generation, gel }) {
  const corps = Buffer.from(J.canonicaliserJCSIntegral({ temporaryHold: gel === true }), "utf8");
  return requete("PATCH", cibleGcs(bucket, nom, generation), [["Content-Length", String(corps.length)], ["Content-Type", "application/json"]], corps);
}
/** GCS, lire l'état d'une version par l'API JSON. */
export const requeteEtatGcs = ({ bucket, nom, generation }) => requete("GET", cibleGcs(bucket, nom, generation), []);

/** Opérations de la famille `worm/requetes` (`$defs/cas_requete`), appelées depuis l'entrée d'un cas. */
export function requeteDeCas(input) {
  const { operation: op } = input;
  switch (op) {
    case "s3_gel": return requeteGelS3({ cle: input.key, versionId: input.version_id, gel: input.hold === true });
    case "s3_lire_gel": return requeteLireGelS3({ cle: input.key, versionId: input.version_id });
    case "s3_etat": return requeteEtatS3({ cle: input.key, versionId: input.version_id });
    case "s3_liste": return requeteListeS3({ prefix: input.prefix, keyMarker: input.key_marker, versionIdMarker: input.version_id_marker });
    case "s3_configuration_verrou": return requeteConfigurationVerrouS3(input.retain_days);
    case "s3_lire_configuration": return requeteLireConfigurationS3();
    case "s3_copie": return requeteCopieS3({ cle: input.key, octets: Buffer.from(input.body_utf8, "utf8"), gelALEcriture: input.legal_hold_on_write === true });
    case "azure_gel": return requeteGelAzure({ conteneur: input.bucket, blob: input.key, versionId: input.version_id, gel: input.hold === true });
    case "azure_etat": return requeteEtatAzure({ conteneur: input.bucket, blob: input.key, versionId: input.version_id });
    case "gcs_gel": return requeteGelGcs({ bucket: input.bucket, nom: input.key, generation: input.version_id, gel: input.hold === true });
    case "gcs_etat": return requeteEtatGcs({ bucket: input.bucket, nom: input.key, generation: input.version_id });
    default: throw new RangeError(`requeteDeCas : opération inconnue ${op}`);
  }
}

// ---------------------------------------------------------------------------
// Contrôle du verrou d'une version (EX-12.33)
// ---------------------------------------------------------------------------

const MOIS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const RE_RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})$/;
const RE_IMF = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/;

function msUTC(an, mois, jour, h, mi, s) {
  if (mois < 1 || mois > 12 || jour < 1 || h > 23 || mi > 59 || s > 59) return null;
  const jours = new Date(Date.UTC(an, mois, 0)).getUTCDate();
  if (jour > jours) return null;
  const d = new Date(0);
  d.setUTCFullYear(an, mois - 1, jour);
  d.setUTCHours(h, mi, s, 0);
  return d.getTime();
}

/**
 * Lit une échéance rendue par un support (EX-12.33 pas 2) : RFC 3339 (avec ou
 * sans fraction, `Z` ou décalage `±hh:mm`) ou IMF-fixdate de HTTP
 * (`Tue, 10 Nov 2037 11:00:05 GMT` ; le jour de la semaine est lu pour sa
 * forme et ignoré). Rend des millisecondes UTC (fraction au-delà de la
 * milliseconde tronquée) ou `null` si la valeur est illisible.
 */
export function lireEcheance(valeur) {
  if (typeof valeur !== "string") return null;
  let m = RE_RFC3339.exec(valeur);
  if (m) {
    const base = msUTC(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]);
    if (base === null) return null;
    const fraction = m[7] ? Number((m[7] + "00").slice(0, 3)) : 0;
    let decalage = 0;
    if (m[8] !== "Z") {
      const hh = +m[8].slice(1, 3);
      const mm = +m[8].slice(4, 6);
      if (hh > 23 || mm > 59) return null;
      decalage = (m[8][0] === "+" ? 1 : -1) * (hh * 60 + mm) * 60000;
    }
    return base + fraction - decalage;
  }
  m = RE_IMF.exec(valeur);
  if (m) return msUTC(+m[3], MOIS.indexOf(m[2]) + 1, +m[1], +m[4], +m[5], +m[6]);
  return null;
}

const CHAMPS_ETAT = {
  "s3-object-lock": { mode: "x-amz-object-lock-mode", echeance: "x-amz-object-lock-retain-until-date", gel: "x-amz-object-lock-legal-hold", attendu: { compliance: "COMPLIANCE", governance: "GOVERNANCE" }, on: "ON", off: "OFF" },
  "azure-immutable-blob": { mode: "x-ms-immutability-policy-mode", echeance: "x-ms-immutability-policy-until-date", gel: "x-ms-legal-hold", attendu: { compliance: "locked", governance: "unlocked" }, on: "true", off: "false" },
};

/**
 * Verdict du contrôle du verrou d'une version lue (EX-12.33) : mode, échéance,
 * gel, dans cet ordre. `entree` = `{ type, headers, json, expected_lock: {
 * retain_until_min, hold } }` (`$defs/cas_etat`) ; `mode` : `compliance`
 * (défaut) ou `governance`. Rend `{ mode, retain_until, legal_hold, verdict,
 * reasons, notes }`.
 */
export function etatVerrou({ type, headers = null, json = null, expected_lock }, { mode: modeAttendu = "compliance" } = {}) {
  let mode;
  let echeance;
  let gel;
  let attenduMode;
  if (type === "gcs-object-retention") {
    const ret = json && typeof json.retention === "object" && json.retention !== null && !Array.isArray(json.retention) ? json.retention : null;
    mode = ret && typeof ret.mode === "string" ? ret.mode : null;
    echeance = ret && ret.retainUntilTime !== undefined && ret.retainUntilTime !== null ? ret.retainUntilTime : null;
    const th = json ? json.temporaryHold : undefined;
    gel = th === true ? "on" : th === false ? "off" : th === undefined || th === null ? "jamais" : "illisible";
    attenduMode = modeAttendu === "governance" ? "Unlocked" : "Locked";
  } else {
    const c = CHAMPS_ETAT[type];
    if (!c) throw new RangeError(`etatVerrou : type de support inconnu ${type}`);
    const h = headers ?? {};
    mode = typeof h[c.mode] === "string" ? h[c.mode] : null;
    echeance = typeof h[c.echeance] === "string" ? h[c.echeance] : null;
    const g = h[c.gel];
    gel = g === undefined || g === null ? "jamais" : g === c.on ? "on" : g === c.off ? "off" : "illisible";
    attenduMode = c.attendu[modeAttendu];
  }
  const reasons = [];
  const notes = [];
  if (mode === null) reasons.push("mode_absent");
  else if (mode !== attenduMode) reasons.push("mode_non_conforme");
  let retain_until = null;
  if (echeance === null) reasons.push("echeance_absente");
  else {
    const ms = lireEcheance(echeance);
    if (ms === null) reasons.push("date_illisible");
    else {
      retain_until = J.horodatage(ms);
      if (ms < J.msHorodatage(expected_lock.retain_until_min)) reasons.push("echeance_courte");
    }
  }
  if (gel === "jamais") notes.push("jamais_gele");
  // Valeur de gel hors de la table (EX-12.33) : non conforme, jamais lue comme off.
  if (gel === "illisible") reasons.push("gel_illisible");
  else if (expected_lock.hold === true && gel !== "on") reasons.push("gel_absent");
  if (expected_lock.hold !== true && gel === "on") notes.push("gel_inattendu");
  return { mode, retain_until, legal_hold: gel, verdict: reasons.length === 0 ? "conforme" : "non_conforme", reasons, notes };
}

/** Échéance minimale admise d'une copie (EX-12.33 pas 2) : `copied_at + retain_days × 86 400 s − 3 600 s`. */
export const echeanceMinimale = (copied_at, retain_days) => J.horodatage(J.msHorodatage(copied_at) + retain_days * 86400000 - 3600000);

/** Ligne du registre des copies (EX-12.29, `$defs/ligne_copie`) et son texte (JCS intégral suivi de `\n`). */
export function ligneCopie({ key, version_id = null, octets, copied_at, lock }) {
  const o = Buffer.from(octets);
  const ligne = { key, version_id, sha256: J.sha256(o), length: o.length, copied_at, lock: { verdict: lock.verdict, retain_until: lock.retain_until, legal_hold: lock.legal_hold } };
  return { ligne, texte: J.canonicaliserJCSIntegral(ligne) + "\n" };
}

// ---------------------------------------------------------------------------
// Périmètre d'un gel (EX-12.35)
// ---------------------------------------------------------------------------

const RE_SEGMENT = /^segments\/seg-([0-9]{16})-([0-9]{20})\.ndjson$/;
const p10 = (P) => String(P).padStart(10, "0");
const p16 = (n) => String(n).padStart(16, "0");
const compareCles = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

/**
 * Périmètre d'un gel (EX-12.35, pas 2 à 6) à partir de la liste des versions
 * déjà lue (pas 1). `versions` : `[{ key, version_id, is_latest, delete_marker }]`
 * dans l'ordre de la liste ; `manifests` : `[{ period_start, first_seq,
 * last_seq }]` lus dans les copies (une version présente mais illisible est
 * absente de `manifests`) ; `pieces` : `null` (pièces non copiées,
 * `storage.seal.worm.copy_pieces` faux) ou les empreintes référencées par les
 * segments retenus ; `pieces_purgeable` : `storage.retention.pieces_days`
 * n'est pas null (les pièces locales peuvent être purgées).
 *
 * Ordre des anomalies (EX-12.35) : pour chaque période, dans l'ordre
 * croissant, celles du pas 2 (`manifeste_absent` ou `manifeste_illisible`,
 * puis `segments_indetermines`) et du pas 3 (`objet_absent` de la signature,
 * puis de la série des points, puis `segment_absent`) ; ensuite celles du pas
 * 4 (`pieces_non_copiees`, ou `piece_absente` dans l'ordre des empreintes
 * reçues) ; enfin celles du pas 5, clé par clé dans l'ordre des clés (octets
 * UTF-8), `versions_multiples` avant `marqueur_de_suppression`. Un marqueur
 * de suppression compte comme une version pour les pas 2 et 3 : la clé est
 * retenue et le pas 5 rend `marqueur_de_suppression`.
 *
 * Rend `{ objects, objects_sha256, count, anomalies, texte }` ; `texte` est
 * le fichier `objets-<nnnn>.ndjson` (lignes JCS intégral suivies de `\n`).
 */
export function perimetreGel({ prefix, from, to, manifests, versions, pieces = null, pieces_purgeable = false }) {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from % 3600 !== 0 || to % 3600 !== 0 || from > to) throw new RangeError("perimetreGel : plage de périodes invalide");
  const parCle = new Map();
  for (const v of versions) {
    if (!parCle.has(v.key)) parCle.set(v.key, []);
    parCle.get(v.key).push(v);
  }
  const aUneVersion = (cle) => parCle.has(cle);
  const anomalies = [];
  const retenues = new Set();
  for (let P = from; P <= to; P += 3600) {
    const cleManifeste = `${prefix}manifestes/periode-${p10(P)}.json`;
    const manifeste = manifests.find((m) => m.period_start === P) ?? null;
    if (!aUneVersion(cleManifeste)) {
      anomalies.push({ key: cleManifeste, kind: "manifeste_absent" });
      anomalies.push({ key: `${prefix}segments/`, kind: "segments_indetermines" });
    } else if (manifeste === null) {
      // Version présente mais non lue (EX-12.35) : la clé est gelée quand même ; les segments restent indéterminés.
      retenues.add(cleManifeste);
      anomalies.push({ key: cleManifeste, kind: "manifeste_illisible" });
      anomalies.push({ key: `${prefix}segments/`, kind: "segments_indetermines" });
    } else retenues.add(cleManifeste);
    for (const cle of [`${prefix}manifestes/periode-${p10(P)}.sig`, `${prefix}points/periode-${p10(P)}.ndjson`]) {
      if (aUneVersion(cle)) retenues.add(cle);
      else anomalies.push({ key: cle, kind: "objet_absent" });
    }
    const prefixeAncres = `${prefix}ancres/periode-${p10(P)}/`;
    for (const cle of parCle.keys()) if (cle.startsWith(prefixeAncres)) retenues.add(cle);
    if (manifeste !== null && aUneVersion(cleManifeste)) {
      let premierTrouve = false;
      for (const cle of parCle.keys()) {
        if (!cle.startsWith(prefix)) continue;
        const m = RE_SEGMENT.exec(cle.slice(prefix.length));
        if (!m) continue;
        const f = Number(m[1]);
        if (f >= manifeste.first_seq && f <= manifeste.last_seq) {
          retenues.add(cle);
          if (f === manifeste.first_seq) premierTrouve = true;
        }
      }
      if (manifeste.last_seq >= manifeste.first_seq && !premierTrouve) anomalies.push({ key: `${prefix}segments/seg-${p16(manifeste.first_seq)}-${"0".repeat(20)}.ndjson`, kind: "segment_absent" });
    }
  }
  if (pieces !== null) {
    for (const h of pieces) {
      const nu = h.slice(2);
      const cle = `${prefix}pieces/${nu.slice(0, 2)}/${nu}`;
      if (aUneVersion(cle)) retenues.add(cle);
      else anomalies.push({ key: cle, kind: "piece_absente" });
    }
  } else if (pieces_purgeable) anomalies.push({ key: `${prefix}pieces/`, kind: "pieces_non_copiees" });
  const cles = [...retenues].sort(compareCles);
  const objects = [];
  for (const cle of cles) {
    const vs = parCle.get(cle) ?? [];
    const pleines = vs.filter((v) => !v.delete_marker);
    if (pleines.length > 1) anomalies.push({ key: cle, kind: "versions_multiples" });
    if (vs.some((v) => v.delete_marker && v.is_latest)) anomalies.push({ key: cle, kind: "marqueur_de_suppression" });
    for (const v of pleines) objects.push({ key: v.key, version_id: v.version_id });
  }
  const texte = objects.map((o) => J.canonicaliserJCSIntegral(o) + "\n").join("");
  return { objects, objects_sha256: J.sha256(Buffer.from(texte, "utf8")), count: objects.length, anomalies, texte };
}

// ---------------------------------------------------------------------------
// Registre des gels (EX-12.37) et règle de garde (EX-12.38)
// ---------------------------------------------------------------------------

/** Octets d'un enregistrement du registre des gels : JCS intégral. */
export const octetsEnregistrement = (r) => Buffer.from(J.canonicaliserJCSIntegral(r), "utf8");
/** Empreinte d'un enregistrement : SHA-256 de son JCS intégral. */
export const empreinteEnregistrement = (r) => J.sha256(octetsEnregistrement(r));

/** Successions admises (EX-12.38, `ordre_invalide`). */
export const SUCCESSIONS = Object.freeze({
  pose: ["pose_resultat"],
  pose_resultat: ["pose_resultat", "demande_levee"],
  demande_levee: ["demande_levee", "levee"],
  levee: ["levee_resultat"],
  levee_resultat: ["levee_resultat"],
});
/** Codes de la règle de garde, dans l'ordre de la table d'EX-12.38. */
export const CODES_GARDE = Object.freeze(["chaine_rompue", "premier_non_pose", "ordre_invalide", "meme_identite", "demande_inconnue", "demande_expiree", "levee_en_double", "objets_differents", "periode_differente"]);
/** Délai maximal entre une demande de levée et la levée : sept jours. */
export const DELAI_LEVEE_MS = 604800000;

const jcs = (v) => J.canonicaliserJCSIntegral(v);

/**
 * Règle de garde de la levée par deux personnes (EX-12.38), vérifiée sur une
 * suite d'enregistrements relus. `n` d'une erreur est le rang (1, 2, …) de
 * l'enregistrement fautif dans la suite ; une erreur par enregistrement
 * fautif et par règle, dans l'ordre des rangs puis de la table.
 */
export function verifierGarde(enregistrements) {
  // Une suite vide n'a pas de pose (EX-12.38).
  if (enregistrements.length === 0) return { valid: false, record_sha256: [], errors: [{ n: 1, code: "premier_non_pose" }] };
  const record_sha256 = enregistrements.map(empreinteEnregistrement);
  const errors = [];
  // Un `at` illisible viole ordre_invalide et demande_expiree (EX-12.38).
  const ms = (at) => {
    try {
      const v = J.msHorodatage(at);
      return Number.isFinite(v) ? v : NaN;
    } catch {
      return NaN;
    }
  };
  const premier = enregistrements[0];
  const approuvees = new Set();
  enregistrements.forEach((r, i) => {
    const n = i + 1;
    const fautes = new Set();
    // chaine_rompue
    if (r.n !== n) fautes.add("chaine_rompue");
    if (i === 0 ? r.prev_sha256 !== null : r.prev_sha256 !== record_sha256[i - 1]) fautes.add("chaine_rompue");
    for (const k of ["gel_id", "org_id", "journal_id", "support"]) if (jcs(r[k]) !== jcs(premier[k])) fautes.add("chaine_rompue");
    // premier_non_pose
    if (i === 0 && r.kind !== "pose") fautes.add("premier_non_pose");
    // ordre_invalide
    if (i > 0) {
      const prec = enregistrements[i - 1];
      if (!(SUCCESSIONS[prec.kind] ?? []).includes(r.kind)) fautes.add("ordre_invalide");
      const a = ms(r.at);
      const b = ms(prec.at);
      if (Number.isNaN(a) || Number.isNaN(b) || a < b) fautes.add("ordre_invalide");
    } else if (Number.isNaN(ms(r.at))) {
      fautes.add("ordre_invalide");
    }
    if (r.kind === "levee") {
      let derniere = -1;
      for (let j = i - 1; j >= 0; j--) if (enregistrements[j].kind === "demande_levee") { derniere = j; break; }
      const approuvee = enregistrements.findIndex((d, j) => j < i && d.kind === "demande_levee" && record_sha256[j] === r.request_sha256);
      if (approuvee >= 0 && enregistrements[approuvee].actor === r.actor) fautes.add("meme_identite");
      if (derniere < 0 || r.request_sha256 !== record_sha256[derniere]) fautes.add("demande_inconnue");
      // meme_identite, demande_expiree et levee_en_double ne sont jugées que si la demande désignée existe.
      if (approuvee >= 0) {
        const ecart = ms(r.at) - ms(enregistrements[approuvee].at);
        if (!(ecart >= 0 && ecart <= DELAI_LEVEE_MS)) fautes.add("demande_expiree");
        if (approuvees.has(r.request_sha256)) fautes.add("levee_en_double");
        approuvees.add(r.request_sha256);
      }
    }
    if (i > 0 && jcs(r.objects) !== jcs(premier.objects)) fautes.add("objets_differents");
    if (i > 0 && jcs(r.periods) !== jcs(premier.periods)) fautes.add("periode_differente");
    for (const code of CODES_GARDE) if (fautes.has(code)) errors.push({ n, code });
  });
  return { valid: errors.length === 0, record_sha256, errors };
}

/**
 * Versions à lever (EX-12.40) : les couples `{ key, version_id }` du
 * gel levé qui ne sont couverts par aucun autre gel actif (EX-17.7). Sur
 * S3, Azure et GCS, le gel est un drapeau unique par version : lever une
 * version couverte par un autre gel lèverait aussi la protection de
 * celui-ci. `autresGels` : `[{ gel_id, objects: [{ key, version_id }] }]`,
 * les gels actifs du même préfixe autres que celui levé (pose en cours
 * comprise). Rend `{ lever, conserver }` ; `conserver` porte, pour chaque
 * couple exclu, le premier `gel_id` qui le couvre (ordre des gels reçu), et
 * garde l'ordre de la liste du gel.
 */
export function versionsALever(objets, autresGels) {
  const couvreur = new Map();
  for (const g of autresGels) for (const o of g.objects) {
    const k = `${o.key}\u0000${o.version_id}`;
    if (!couvreur.has(k)) couvreur.set(k, g.gel_id);
  }
  const lever = [];
  const conserver = [];
  for (const o of objets) {
    const g = couvreur.get(`${o.key}\u0000${o.version_id}`);
    if (g === undefined) lever.push({ key: o.key, version_id: o.version_id });
    else conserver.push({ key: o.key, version_id: o.version_id, gel_id: g });
  }
  return { lever, conserver };
}

/** Clé d'un enregistrement du registre des gels : `<prefix>gels/<gel_id>/<nnnn>-<kind>.json`. */
export const cleEnregistrement = (prefix, r) => `${prefix}gels/${r.gel_id}/${String(r.n).padStart(4, "0")}-${r.kind}.json`;
/** Clé de la liste des objets d'un gel : `<prefix>gels/<gel_id>/objets-<nnnn>.ndjson`. */
export const cleListeObjets = (prefix, gel_id, nnnn = 1) => `${prefix}gels/${gel_id}/objets-${String(nnnn).padStart(4, "0")}.ndjson`;
