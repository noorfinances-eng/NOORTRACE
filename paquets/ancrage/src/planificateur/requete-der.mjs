// Requête TimeStampReq de CT-5 EX-5.1, octet pour octet : le seul encodage DER
// du planificateur, qui en calcule le SHA-256 et la taille pour l'action
// `envoyer_rfc3161` (EX-8.6, 8.10). La requête est SHA-256 seulement
// (EX-5.2), le nonce un entier non signé de 64 bits dans [1, 2^64 − 1] encodé
// minimalement (EX-5.3), `reqPolicy` présent si et seulement si `policy_oid`
// est non nul, `certReq` toujours TRUE, aucune extension (EX-5.4). Une
// relecture bornée vérifie que la requête relue est identique à l'entrée
// (AN-5).

import { estHex, hexVersOctets, octetsVersHex, sha256 } from "@noortrace/noyau";

/** AlgorithmIdentifier sha256 avec paramètres NULL explicites (EX-5.1). */
const ALGORITHME_SHA256 = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);
const NONCE_MAX = (1n << 64n) - 1n;
const MOTIF_OID = /^[0-2](\.(0|[1-9][0-9]*))+$/;

/** Erreur de construction ou de relecture d'une requête (AN-5, AN-6). */
export class ErreurRequete extends Error {
  /**
   * @param {"AN-5"|"AN-6"} regle
   * @param {string} message
   */
  constructor(regle, message) {
    super(message);
    this.name = "ErreurRequete";
    this.regle = regle;
  }
}

/**
 * Longueur DER définie minimale.
 * @param {number} n
 * @returns {number[]}
 */
function longueur(n) {
  if (n < 0x80) return [n];
  const octets = [];
  let v = n;
  while (v > 0) {
    octets.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return [0x80 | octets.length, ...octets];
}

/**
 * Élément DER : étiquette, longueur, contenu.
 * @param {number} etiquette
 * @param {Uint8Array|number[]} contenu
 * @returns {Uint8Array}
 */
function tlv(etiquette, contenu) {
  return Uint8Array.from([etiquette, ...longueur(contenu.length), ...contenu]);
}

/**
 * Encodage DER d'un OBJECT IDENTIFIER en notation pointée.
 * @param {string} oid
 * @returns {Uint8Array}
 */
export function encoderOid(oid) {
  if (typeof oid !== "string" || !MOTIF_OID.test(oid)) throw new ErreurRequete("AN-5", `policy_oid : OID mal formé (${String(oid)})`);
  const arcs = oid.split(".").map((a) => BigInt(a));
  if (arcs[0] < 2n && arcs[1] >= 40n) throw new ErreurRequete("AN-5", `policy_oid : second arc ${arcs[1]} trop grand pour l'arc ${arcs[0]}`);
  const contenu = [];
  const base128 = (valeur) => {
    const groupes = [Number(valeur & 0x7fn)];
    let v = valeur >> 7n;
    while (v > 0n) {
      groupes.unshift(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    contenu.push(...groupes);
  };
  base128(arcs[0] * 40n + arcs[1]);
  for (const a of arcs.slice(2)) base128(a);
  return tlv(0x06, contenu);
}

/**
 * Nonce d'EX-5.3 en entier : `bigint`, ou hexadécimal préfixé de 1 à 8 octets.
 * @param {bigint|string} nonce
 * @returns {bigint}
 */
export function nonceEntier(nonce) {
  let n;
  if (typeof nonce === "bigint") n = nonce;
  else if (typeof nonce === "string" && /^0x[0-9a-f]+$/.test(nonce)) n = BigInt(nonce);
  else throw new ErreurRequete("AN-6", "nonce : entier ou hexadécimal préfixé attendu");
  if (n < 1n || n > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${n} hors de [1, 2^64 - 1]`);
  return n;
}

/**
 * Nonce en hexadécimal préfixé sur 8 octets (forme `hex8` du schéma).
 * @param {bigint} n
 * @returns {string}
 */
export function nonceHex(n) {
  return "0x" + n.toString(16).padStart(16, "0");
}

/**
 * INTEGER DER minimal d'un entier non signé (octet 00 de tête si le bit de
 * poids fort du premier octet significatif vaut 1).
 * @param {bigint} n
 * @returns {Uint8Array}
 */
function entierDer(n) {
  const octets = [];
  let v = n;
  while (v > 0n) {
    octets.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  if (octets[0] & 0x80) octets.unshift(0);
  return tlv(0x02, octets);
}

/**
 * Construit la requête d'EX-5.1.
 * @param {{imprint: string, hash?: string, nonce: bigint|string, policy_oid?: string|null, cert_req?: boolean}} p
 * @returns {{octets: Uint8Array, sha256: string, taille: number, nonce: string}}
 */
export function construireRequete({ imprint, hash = "sha256", nonce, policy_oid = null, cert_req = true }) {
  if (hash !== "sha256") throw new ErreurRequete("AN-5", `algorithme ${String(hash)} refusé : SHA-256 seulement (EX-5.2)`);
  if (!estHex(imprint, 32)) throw new ErreurRequete("AN-5", "empreinte : 32 octets attendus (SHA-256)");
  if (cert_req !== true) throw new ErreurRequete("AN-5", "certReq vaut toujours TRUE (EX-5.4)");
  const n = nonceEntier(nonce);
  const messageImprint = tlv(0x30, [...ALGORITHME_SHA256, ...tlv(0x04, hexVersOctets(imprint, 32))]);
  const parties = [0x02, 0x01, 0x01, ...messageImprint];
  if (policy_oid !== null && policy_oid !== undefined) parties.push(...encoderOid(policy_oid));
  parties.push(...entierDer(n), 0x01, 0x01, 0xff);
  const octets = tlv(0x30, parties);
  const relue = relireRequete(octets);
  if (relue.imprint !== imprint || relue.nonce !== nonceHex(n) || (relue.policy_oid ?? null) !== (policy_oid ?? null)) {
    throw new ErreurRequete("AN-5", "relecture de la requête différente de l'entrée");
  }
  return { octets, sha256: octetsVersHex(sha256(octets)), taille: octets.length, nonce: nonceHex(n) };
}

/**
 * Lecteur DER borné de la seule forme d'EX-5.1 : toute autre forme est refusée.
 * @param {Uint8Array} octets
 * @returns {{imprint: string, nonce: string, policy_oid: string|null, cert_req: true}}
 */
export function relireRequete(octets) {
  if (!(octets instanceof Uint8Array)) throw new ErreurRequete("AN-5", "octets attendus");
  if (octets.length > 200) throw new ErreurRequete("AN-5", `requête de ${octets.length} octets, au plus 200`);
  let pos = 0;
  const lireTlv = (etiquetteAttendue, nom) => {
    if (pos + 2 > octets.length) throw new ErreurRequete("AN-5", `${nom} : fin de fichier prématurée`);
    const etiquette = octets[pos];
    if (etiquette !== etiquetteAttendue) throw new ErreurRequete("AN-5", `${nom} : étiquette 0x${etiquette.toString(16)} inattendue`);
    let l = octets[pos + 1];
    let debut = pos + 2;
    if (l & 0x80) {
      const nb = l & 0x7f;
      if (nb !== 1 || debut + 1 > octets.length) throw new ErreurRequete("AN-5", `${nom} : longueur non minimale`);
      l = octets[debut];
      if (l < 0x80) throw new ErreurRequete("AN-5", `${nom} : longueur non minimale`);
      debut += 1;
    }
    if (debut + l > octets.length) throw new ErreurRequete("AN-5", `${nom} : longueur ${l} au-delà des octets`);
    const contenu = octets.subarray(debut, debut + l);
    pos = debut + l;
    return contenu;
  };
  const corps = lireTlv(0x30, "TimeStampReq");
  if (pos !== octets.length) throw new ErreurRequete("AN-5", "octets au-delà de la requête");
  const sauvegarde = { octets, pos };
  // Relecture du corps dans son propre cadre.
  const lecteur = relireCorps(corps);
  void sauvegarde;
  return lecteur;
}

/** @param {Uint8Array} corps */
function relireCorps(corps) {
  let pos = 0;
  const lire = (etiquette, nom) => {
    if (pos + 2 > corps.length) throw new ErreurRequete("AN-5", `${nom} : fin prématurée`);
    if (corps[pos] !== etiquette) throw new ErreurRequete("AN-5", `${nom} : étiquette 0x${corps[pos].toString(16)} inattendue`);
    const l = corps[pos + 1];
    if (l & 0x80) throw new ErreurRequete("AN-5", `${nom} : longueur longue inattendue`);
    if (pos + 2 + l > corps.length) throw new ErreurRequete("AN-5", `${nom} : longueur ${l} au-delà du corps`);
    const contenu = corps.subarray(pos + 2, pos + 2 + l);
    pos += 2 + l;
    return contenu;
  };
  const version = lire(0x02, "version");
  if (version.length !== 1 || version[0] !== 1) throw new ErreurRequete("AN-5", "version : 1 attendu");
  const mi = lire(0x30, "messageImprint");
  if (mi.length !== 0x31 || !ALGORITHME_SHA256.every((o, i) => mi[i] === o)) throw new ErreurRequete("AN-5", "messageImprint : AlgorithmIdentifier sha256 avec NULL attendu");
  if (mi[15] !== 0x04 || mi[16] !== 0x20) throw new ErreurRequete("AN-5", "hashedMessage : 32 octets attendus");
  const imprint = octetsVersHex(mi.subarray(17, 49));
  let policy_oid = null;
  if (pos < corps.length && corps[pos] === 0x06) {
    const oid = lire(0x06, "reqPolicy");
    policy_oid = decoderOid(oid);
  }
  const nonceOctets = lire(0x02, "nonce");
  if (nonceOctets.length === 0 || nonceOctets.length > 9) throw new ErreurRequete("AN-5", "nonce : 1 à 9 octets attendus");
  if (nonceOctets[0] === 0 && (nonceOctets.length === 1 || !(nonceOctets[1] & 0x80))) {
    throw new ErreurRequete("AN-5", "nonce : zéro de tête superflu (encodage non minimal)");
  }
  if (nonceOctets[0] & 0x80) throw new ErreurRequete("AN-5", "nonce : entier négatif");
  let n = 0n;
  for (const o of nonceOctets) n = (n << 8n) | BigInt(o);
  if (n < 1n || n > NONCE_MAX) throw new ErreurRequete("AN-6", `nonce ${n} hors de [1, 2^64 - 1]`);
  const certReq = lire(0x01, "certReq");
  if (certReq.length !== 1 || certReq[0] !== 0xff) throw new ErreurRequete("AN-5", "certReq vaut toujours TRUE (EX-5.4)");
  if (pos !== corps.length) throw new ErreurRequete("AN-5", "champ supplémentaire après certReq (extensions refusées, EX-5.4)");
  return { imprint, nonce: nonceHex(n), policy_oid, cert_req: true };
}

/** @param {Uint8Array} contenu */
function decoderOid(contenu) {
  if (contenu.length === 0) throw new ErreurRequete("AN-5", "reqPolicy : OID vide");
  const arcs = [];
  let v = 0n;
  let enCours = false;
  for (let i = 0; i < contenu.length; i++) {
    const o = contenu[i];
    if (!enCours && o === 0x80) throw new ErreurRequete("AN-5", "reqPolicy : arc non minimal");
    v = (v << 7n) | BigInt(o & 0x7f);
    enCours = (o & 0x80) !== 0;
    if (!enCours) {
      arcs.push(v);
      v = 0n;
    }
  }
  if (enCours) throw new ErreurRequete("AN-5", "reqPolicy : OID tronqué");
  const premier = arcs[0] < 40n ? 0n : arcs[0] < 80n ? 1n : 2n;
  const second = arcs[0] - premier * 40n;
  return [premier, second, ...arcs.slice(1)].map(String).join(".");
}
