// Contrôle du verrou et du gel d'une version copiée (CT-2 EX-12.33), sans
// réseau : à partir des en-têtes d'un `HEAD` (S3, Azure) ou de la ressource
// objet de l'API JSON (GCS), dans cet ordre : mode, échéance, gel. Le verdict
// est `conforme` sans raison, `non_conforme` sinon. La famille de vecteurs
// `worm/etats.json` (annexe B.9) fixe ces règles cas par cas.

import { ecrireHorodatage } from "@noortrace/noyau";

const MOIS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$/;
const IMF = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$/;

function bissextile(a) {
  return (a % 4 === 0 && a % 100 !== 0) || a % 400 === 0;
}

function instant(a, mo, j, h, mi, s) {
  if (mo < 1 || mo > 12) return null;
  const jours = [31, bissextile(a) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (j < 1 || j > jours || h > 23 || mi > 59 || s > 59) return null;
  return Date.UTC(a, mo - 1, j, h, mi, s);
}

/**
 * Lit une échéance rendue par le support (EX-12.33 pas 2) : horodatage RFC 3339
 * (avec ou sans fraction, `Z` ou décalage) ou `IMF-fixdate` de HTTP ; rend
 * l'instant en millisecondes UTC, fraction au-delà de la milliseconde
 * tronquée, ou `null` si la valeur est illisible.
 * @param {unknown} texte
 * @returns {number|null}
 */
export function lireEcheance(texte) {
  if (typeof texte !== "string") return null;
  let r = RFC3339.exec(texte);
  if (r) {
    const [a, mo, j, h, mi, s] = r.slice(1, 7).map(Number);
    const base = instant(a, mo, j, h, mi, s);
    if (base === null) return null;
    const ms = r[7] ? Number(r[7].slice(1, 4).padEnd(3, "0")) : 0;
    let decalage = 0;
    if (r[8] !== "Z" && r[8] !== "z") {
      const dh = Number(r[8].slice(1, 3));
      const dm = Number(r[8].slice(4, 6));
      if (dh > 23 || dm > 59) return null;
      decalage = (r[8][0] === "+" ? 1 : -1) * (dh * 60 + dm) * 60000;
    }
    return base + ms - decalage;
  }
  r = IMF.exec(texte);
  if (r) return instant(Number(r[4]), MOIS.indexOf(r[3]) + 1, Number(r[2]), Number(r[5]), Number(r[6]), Number(r[7]));
  return null;
}

/**
 * Échéance minimale attendue d'une copie (EX-12.33 pas 2) :
 * `copied_at + retain_days × 86 400 s − 3 600 s`.
 * @param {number} copieA ms
 * @param {number} retainDays
 * @returns {number} ms
 */
export function echeanceMinimale(copieA, retainDays) {
  return copieA + retainDays * 86400000 - 3600000;
}

const MODES = {
  "s3-object-lock": { compliance: "COMPLIANCE", governance: "GOVERNANCE" },
  "azure-immutable-blob": { compliance: "locked", governance: "unlocked" },
  "gcs-object-retention": { compliance: "Locked", governance: "Unlocked" },
};

function entete(entetes, nom) {
  if (!entetes) return undefined;
  for (const [k, v] of Object.entries(entetes)) if (k.toLowerCase() === nom) return v;
  return undefined;
}

/**
 * Contrôle du verrou d'une version (EX-12.33).
 * @param {object} p
 * @param {"s3-object-lock"|"azure-immutable-blob"|"gcs-object-retention"} p.type
 * @param {Record<string, string>|null} [p.entetes] en-têtes de la réponse (S3, Azure)
 * @param {object|null} [p.json] ressource objet (GCS)
 * @param {"compliance"|"governance"} [p.mode] `storage.seal.worm.mode` (défaut compliance)
 * @param {number} p.echeanceMin instant minimal de l'échéance, ms
 * @param {boolean} [p.gelAttendu] gel actif du registre ou `legal_hold_on_write`
 * @returns {{mode: string|null, retain_until: string|null, legal_hold: "on"|"off"|"jamais"|"illisible",
 *   verdict: "conforme"|"non_conforme", reasons: string[], notes: string[]}}
 */
export function controlerVerrou(p) {
  const reasons = [];
  const notes = [];
  let modeLu;
  let echeanceLue;
  let gelLu;
  if (p.type === "gcs-object-retention") {
    const j = p.json && typeof p.json === "object" ? p.json : {};
    const ret = j.retention && typeof j.retention === "object" ? j.retention : null;
    modeLu = ret ? ret.mode : undefined;
    echeanceLue = ret ? ret.retainUntilTime : undefined;
    gelLu = j.temporaryHold;
  } else if (p.type === "azure-immutable-blob") {
    modeLu = entete(p.entetes, "x-ms-immutability-policy-mode");
    echeanceLue = entete(p.entetes, "x-ms-immutability-policy-until-date");
    gelLu = entete(p.entetes, "x-ms-legal-hold");
  } else {
    modeLu = entete(p.entetes, "x-amz-object-lock-mode");
    echeanceLue = entete(p.entetes, "x-amz-object-lock-retain-until-date");
    gelLu = entete(p.entetes, "x-amz-object-lock-legal-hold");
  }

  // 1. Mode.
  const attendu = MODES[p.type][p.mode ?? "compliance"];
  let mode = null;
  if (modeLu === undefined || modeLu === null) reasons.push("mode_absent");
  else {
    mode = String(modeLu);
    if (mode !== attendu) reasons.push("mode_non_conforme");
  }

  // 2. Échéance.
  let retain_until = null;
  if (echeanceLue === undefined || echeanceLue === null) reasons.push("echeance_absente");
  else {
    const t = lireEcheance(echeanceLue);
    if (t === null) reasons.push("date_illisible");
    else {
      retain_until = ecrireHorodatage(t);
      if (t < p.echeanceMin) reasons.push("echeance_courte");
    }
  }

  // 3. Gel.
  let legal_hold;
  if (gelLu === undefined || gelLu === null) {
    legal_hold = "jamais";
    notes.push("jamais_gele");
  } else if (p.type === "gcs-object-retention") {
    legal_hold = gelLu === true ? "on" : gelLu === false ? "off" : "illisible";
  } else if (p.type === "azure-immutable-blob") {
    legal_hold = gelLu === "true" ? "on" : gelLu === "false" ? "off" : "illisible";
  } else {
    legal_hold = gelLu === "ON" ? "on" : gelLu === "OFF" ? "off" : "illisible";
  }
  if (legal_hold === "illisible") reasons.push("gel_illisible");
  else if (p.gelAttendu && legal_hold !== "on") reasons.push("gel_absent");
  else if (!p.gelAttendu && legal_hold === "on") notes.push("gel_inattendu");

  return { mode, retain_until, legal_hold, verdict: reasons.length ? "non_conforme" : "conforme", reasons, notes };
}
