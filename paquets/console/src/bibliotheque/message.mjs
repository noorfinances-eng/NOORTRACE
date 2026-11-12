// Message d'inscription (CT-3 EX-13.12) : dix lignes séparées par LF, sans LF
// final ni CR, ASCII imprimable ; les deux premières lignes fixes ; chaque clé
// suivie de « : » et d'une espace, sa valeur jusqu'à la fin de la ligne et dans
// sa grammaire (`$defs/champs_inscription` d'annuaire-approbateurs-v0 ;
// instants de CT-1 §3, date du calendrier comprise). L'analyse reconstruit le
// texte depuis les valeurs lues et exige l'égalité octet pour octet : aucune
// variante n'est admise (`message_invalide`).

import { ErreurConsole } from "./erreurs.mjs";
import { estIdentiteCanonique } from "./identite.mjs";
import { estInstant } from "./instants.mjs";

const LIGNE_1 = "noortrace/inscription/v0";
const LIGNE_2 = "Je lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.";

/** Champs, dans l'ordre des lignes 3 à 10, avec leur clé. */
const CLES = Object.freeze([
  ["origin", "Origine: "],
  ["org", "Organisation: "],
  ["org_id", "Identifiant d'organisation: "],
  ["identity", "Identite: "],
  ["address", "Adresse: "],
  ["issued_at", "Emis le: "],
  ["expires_at", "Expire le: "],
  ["nonce", "Nonce: "],
]);

const MOTIF_ORIGINE = /^https:\/\/[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[1-9][0-9]{0,4})?$/;
const MOTIF_ORGANISATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MOTIF_HEX32 = /^0x[0-9a-f]{64}$/;
const MOTIF_ADRESSE = /^0x[0-9a-f]{40}$/;
const MOTIF_NONCE = /^[0-9a-f]{32}$/;

/** Grammaire de chaque champ (`$defs/champs_inscription`). */
const GRAMMAIRES = Object.freeze({
  origin: (v) => typeof v === "string" && v.length <= 270 && MOTIF_ORIGINE.test(v),
  org: (v) => typeof v === "string" && MOTIF_ORGANISATION.test(v),
  org_id: (v) => typeof v === "string" && MOTIF_HEX32.test(v),
  identity: (v) => estIdentiteCanonique(v),
  address: (v) => typeof v === "string" && MOTIF_ADRESSE.test(v),
  issued_at: (v) => estInstant(v),
  expires_at: (v) => estInstant(v),
  nonce: (v) => typeof v === "string" && MOTIF_NONCE.test(v),
});

/**
 * Vrai si `champs` a exactement les huit membres de `$defs/champs_inscription`,
 * chacun dans sa grammaire.
 * @param {unknown} champs
 */
export function champsInscriptionValides(champs) {
  if (champs === null || typeof champs !== "object" || Array.isArray(champs)) return false;
  const cles = Object.keys(champs);
  if (cles.length !== CLES.length) return false;
  for (const [nom] of CLES) {
    if (!Object.prototype.hasOwnProperty.call(champs, nom) || !GRAMMAIRES[nom](champs[nom])) return false;
  }
  return true;
}

function ecrire(champs) {
  const lignes = [LIGNE_1, LIGNE_2];
  for (const [nom, cle] of CLES) lignes.push(cle + champs[nom]);
  return lignes.join("\n");
}

/**
 * Texte exact du message d'inscription.
 * @param {{origin: string, org: string, org_id: string, identity: string, address: string, issued_at: string, expires_at: string, nonce: string}} champs
 * @returns {string}
 * @throws {ErreurConsole} `message_invalide` (champ hors de sa grammaire)
 */
export function messageInscription(champs) {
  if (champs === null || typeof champs !== "object" || Array.isArray(champs)) {
    throw new TypeError("messageInscription : objet attendu");
  }
  if (!champsInscriptionValides(champs)) throw new ErreurConsole("message_invalide", "champ d'inscription hors de sa grammaire (EX-13.12)");
  return ecrire(champs);
}

/**
 * Analyse un message d'inscription (EX-13.12).
 * @param {string} texte
 * @returns {{origin: string, org: string, org_id: string, identity: string, address: string, issued_at: string, expires_at: string, nonce: string}}
 * @throws {ErreurConsole} `message_invalide`
 */
export function analyserMessageInscription(texte) {
  if (typeof texte !== "string") throw new TypeError("analyserMessageInscription : chaine attendue");
  const refus = () => new ErreurConsole("message_invalide", "message d'inscription hors de la forme exacte (EX-13.12)");
  const lignes = texte.split("\n");
  if (lignes.length !== 10 || lignes[0] !== LIGNE_1 || lignes[1] !== LIGNE_2) throw refus();
  const champs = {};
  for (let k = 0; k < CLES.length; k++) {
    const [nom, cle] = CLES[k];
    const ligne = lignes[k + 2];
    if (!ligne.startsWith(cle)) throw refus();
    const valeur = ligne.slice(cle.length);
    if (!GRAMMAIRES[nom](valeur)) throw refus();
    champs[nom] = valeur;
  }
  if (ecrire(champs) !== texte) throw refus();
  return champs;
}
