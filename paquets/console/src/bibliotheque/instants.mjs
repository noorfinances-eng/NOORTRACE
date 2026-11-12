// Instants (CT-1 §3 ; CT-3 EX-13.13 et EX-13.15 pas 5 pour les instants
// d'un défi, EX-13.30 pour l'attente d'une signature, EX-9.4 pour le temps
// restant) : chaîne `AAAA-MM-JJTHH:MM:SS.mmmZ`, UTC, date du
// calendrier grégorien proleptique (un 30 février ne se décode pas, il n'est
// jamais décalé). Les comparaisons portent sur les instants décodés, à la
// milliseconde (CT-1 §3). Aucune lecture d'horloge : l'instant est toujours un
// paramètre (contrat de l'étape 6, 0.4).

const MOTIF = /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\.([0-9]{3})Z$/;

const MS_PAR_JOUR = 86400000;

function bissextile(a) {
  return (a % 4 === 0 && a % 100 !== 0) || a % 400 === 0;
}

function joursDuMois(a, m) {
  if (m === 2) return bissextile(a) ? 29 : 28;
  return m === 4 || m === 6 || m === 9 || m === 11 ? 30 : 31;
}

// Nombre de jours depuis 1970-01-01 d'une date grégorienne (algorithme
// « days_from_civil »).
function joursDepuisEpoque(a, m, j) {
  const y = m <= 2 ? a - 1 : a;
  const ere = Math.floor(y / 400);
  const ya = y - ere * 400;
  const ma = m > 2 ? m - 3 : m + 9;
  const ja = Math.floor((153 * ma + 2) / 5) + j - 1;
  const je = ya * 365 + Math.floor(ya / 4) - Math.floor(ya / 100) + ja;
  return ere * 146097 + je - 719468;
}

// Inverse de joursDepuisEpoque (« civil_from_days »).
function dateDepuisJours(z0) {
  const z = z0 + 719468;
  const ere = Math.floor(z / 146097);
  const je = z - ere * 146097;
  const ya = Math.floor((je - Math.floor(je / 1460) + Math.floor(je / 36524) - Math.floor(je / 146096)) / 365);
  const ja = je - (365 * ya + Math.floor(ya / 4) - Math.floor(ya / 100));
  const ma = Math.floor((5 * ja + 2) / 153);
  const j = ja - Math.floor((153 * ma + 2) / 5) + 1;
  const m = ma < 10 ? ma + 3 : ma - 9;
  return { a: ya + ere * 400 + (m <= 2 ? 1 : 0), m, j };
}

/**
 * Instant de CT-1 §3 → millisecondes depuis l'époque, ou `null` s'il ne se
 * décode pas (motif, ou date absente du calendrier).
 * @param {unknown} texte
 * @returns {number|null}
 */
export function decoderInstant(texte) {
  if (typeof texte !== "string") return null;
  const r = MOTIF.exec(texte);
  if (r === null) return null;
  const a = Number(r[1]);
  const m = Number(r[2]);
  const j = Number(r[3]);
  if (j > joursDuMois(a, m)) return null;
  return (
    joursDepuisEpoque(a, m, j) * MS_PAR_JOUR +
    Number(r[4]) * 3600000 +
    Number(r[5]) * 60000 +
    Number(r[6]) * 1000 +
    Number(r[7])
  );
}

/**
 * Vrai pour un instant de CT-1 §3 qui se décode.
 * @param {unknown} texte
 */
export function estInstant(texte) {
  return decoderInstant(texte) !== null;
}

/**
 * Instant attendu en paramètre : millisecondes, ou `TypeError`.
 * @param {unknown} texte
 * @param {string} nom
 * @returns {number}
 */
export function instantParametre(texte, nom) {
  const v = decoderInstant(texte);
  if (v === null) throw new TypeError(`${nom} : instant de CT-1 attendu`);
  return v;
}

const deux = (n) => String(n).padStart(2, "0");

/**
 * Millisecondes depuis l'époque → instant de CT-1 §3 (années 0000 à 9999).
 * @param {number} ms
 * @returns {string}
 */
export function encoderInstant(ms) {
  if (!Number.isSafeInteger(ms)) throw new TypeError("encoderInstant : entier attendu");
  const jours = Math.floor(ms / MS_PAR_JOUR);
  let reste = ms - jours * MS_PAR_JOUR;
  const { a, m, j } = dateDepuisJours(jours);
  if (a < 0 || a > 9999) throw new TypeError("encoderInstant : annee hors de 0000 a 9999");
  const h = Math.floor(reste / 3600000);
  reste -= h * 3600000;
  const mi = Math.floor(reste / 60000);
  reste -= mi * 60000;
  const s = Math.floor(reste / 1000);
  const mm = reste - s * 1000;
  return `${String(a).padStart(4, "0")}-${deux(m)}-${deux(j)}T${deux(h)}:${deux(mi)}:${deux(s)}.${String(mm).padStart(3, "0")}Z`;
}
