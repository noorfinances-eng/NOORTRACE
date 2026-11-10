// Lecture stricte d'une requête `TimeStampReq` (RFC 3161 §2.4.1) reçue par
// le serveur interne, avec le lecteur borné de `der-lecture.mjs`. Toute
// défaillance est rendue comme un refus nommé par son bit `PKIFailureInfo`
// (RFC 3161 §2.4.2 ; CT-5 §7 : badAlg pour un condensé hors de SHA-256,
// SHA-384, SHA-512, AN-23 ; unacceptedExtension pour toute extension ;
// badDataFormat pour une requête illisible ou hors profil, badRequest pour
// une version autre que 1). Les octets recopiés dans le jeton
// (`messageImprint` entier, contenu de `nonce`) sont rendus tels que reçus.

import { ErreurDer, lireUnique, lireSuite, exiger, contenuEntier, valeurEntier, valeurBooleen, valeurOid, lireIdentifiantAlgorithme, parametresAbsentsOuNuls } from "./der-lecture.mjs";
import { CONDENSES_ADMIS, OID } from "./oids.mjs";

/** Taille maximale d'une requête lue (CT-5 : quelques dizaines d'octets ; une requête sans extension n'atteint jamais ce plafond). */
export const TAILLE_MAX_REQUETE = 2048;

/** Refus d'une requête : `echec` est un nom de bit de `PKIFailureInfo`. */
export class RefusRequete extends Error {
  constructor(echec, message) {
    super(message);
    this.name = "RefusRequete";
    this.echec = echec;
  }
}

/**
 * @typedef {object} RequeteLue
 * @property {number} version
 * @property {Uint8Array} messageImprint octets complets de `MessageImprint`, recopiés dans le jeton
 * @property {string} algorithme OID du condensé
 * @property {string} nomAlgorithme `sha256`, `sha384` ou `sha512`
 * @property {Uint8Array} condense octets de `hashedMessage`
 * @property {string|null} reqPolicy
 * @property {Uint8Array|null} nonce octets de contenu de l'INTEGER, tels que reçus (déjà minimaux)
 * @property {boolean} certReq
 */

/**
 * Relit une requête. Lève `RefusRequete` (bit nommé) pour toute forme refusée.
 * @param {Uint8Array} octets
 * @returns {RequeteLue}
 */
export function lireRequete(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("requête : Uint8Array attendu");
  if (octets.length === 0) throw new RefusRequete("badDataFormat", "requête vide");
  if (octets.length > TAILLE_MAX_REQUETE) throw new RefusRequete("badDataFormat", `requête de ${octets.length} octets, au-delà de ${TAILLE_MAX_REQUETE}`);
  let racine;
  let parties;
  try {
    racine = lireUnique(octets);
    exiger(racine, 0x30, "TimeStampReq");
    parties = lireSuite(racine.contenu, 1);
  } catch (e) {
    if (e instanceof ErreurDer) throw new RefusRequete("badDataFormat", `requête illisible : ${e.message}`);
    throw e;
  }
  try {
    return interpreter(parties);
  } catch (e) {
    if (e instanceof ErreurDer) throw new RefusRequete("badDataFormat", `requête hors profil : ${e.message}`);
    throw e;
  }
}

function interpreter(parties) {
  if (parties.length < 2) throw new ErreurDer("version et messageImprint attendus");
  let i = 0;
  const version = valeurEntier(parties[i++], "version");
  if (version !== 1n) throw new RefusRequete("badRequest", `version ${version} : seule la version 1 est servie`);

  const imprint = exiger(parties[i++], 0x30, "messageImprint");
  const champs = lireSuite(imprint.contenu, 2);
  if (champs.length !== 2) throw new ErreurDer("messageImprint : deux éléments attendus");
  const { algorithme, parametres } = lireIdentifiantAlgorithme(champs[0], "hashAlgorithm");
  if (!parametresAbsentsOuNuls(parametres)) throw new ErreurDer("hashAlgorithm : paramètres autres qu'absents ou NULL");
  const condenseElement = exiger(champs[1], 0x04, "hashedMessage");
  const admis = CONDENSES_ADMIS[algorithme];
  if (!admis) throw new RefusRequete("badAlg", `condensé ${algorithme} refusé : SHA-256, SHA-384 ou SHA-512 seulement (AN-23)`);
  if (condenseElement.contenu.length !== admis.longueur) {
    throw new ErreurDer(`hashedMessage : ${admis.longueur} octets attendus pour ${admis.nom}, ${condenseElement.contenu.length} lus`);
  }

  let reqPolicy = null;
  let nonce = null;
  let certReq = false;
  if (i < parties.length && parties[i].etiquette === 0x06) reqPolicy = valeurOid(parties[i++], "reqPolicy");
  if (i < parties.length && parties[i].etiquette === 0x02) nonce = contenuEntier(parties[i++], "nonce");
  if (i < parties.length && parties[i].etiquette === 0x01) {
    certReq = valeurBooleen(parties[i++], "certReq");
    if (!certReq) throw new ErreurDer("certReq FALSE encodé : valeur DEFAULT (X.690 §11.5)");
  }
  if (i < parties.length && parties[i].etiquette === 0xa0) {
    throw new RefusRequete("unacceptedExtension", "extensions présentes : aucune n'est reconnue");
  }
  if (i < parties.length) throw new ErreurDer(`élément inattendu d'étiquette 0x${parties[i].etiquette.toString(16)} après certReq`);
  return {
    version: 1,
    messageImprint: imprint.complet,
    algorithme,
    nomAlgorithme: admis.nom,
    condense: condenseElement.contenu,
    reqPolicy,
    nonce,
    certReq,
  };
}

export { OID };
