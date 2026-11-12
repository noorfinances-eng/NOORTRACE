// Clé de chaîne (CT-2 EX-11.19) : la clé secp256k1 qui signe les ancres et
// relaie les clôtures. Ce module fixe l'interface `SignataireChaine` que
// toute classe de garde met en œuvre, et la classe D de développement
// (`SignataireChaineFichier`), construite depuis des octets déjà résolus par
// l'appelant (CT-2 §15.2) : le module ne lit ni fichier ni variable
// d'environnement, et la clé privée ne quitte jamais le champ privé de
// l'instance (aucune sérialisation, aucun message d'erreur ne la porte).
//
// Le signataire signe un condensé de 32 octets tel quel (ECDSA secp256k1,
// RFC 6979, `s` bas) : l'appelant forme lui-même le hachage signé EIP-191 d'un
// condensé interne (CT-4 §6.6.3) ou le hachage d'une transaction (§6.7.3), et
// convertit `v` ∈ {27, 28} en `yParity = v − 27` pour une transaction.

import { createPrivateKey } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak256 } from "@noortrace/noyau";
import { estOctets, hexVersOctets, octetsVersEntier, octetsVersHex, utf8Texte } from "./octets.mjs";

const N = secp256k1.Point.CURVE().n;
const DEMI_N = N >> 1n;

/** Adresse (20 octets, hexadécimal minuscule) d'une clé publique non compressée de 65 octets. */
export function adresseDepuisClePublique(publique) {
  if (!estOctets(publique) || publique.length !== 65 || publique[0] !== 0x04) throw new TypeError("clé publique non compressée de 65 octets attendue");
  return octetsVersHex(keccak256(publique.subarray(1)).subarray(12));
}

/**
 * Interface d'un signataire de clé de chaîne (classes de garde A à D de
 * CT-2 §11.2) : `adresse()` rend l'adresse hexadécimale minuscule ;
 * `signerCondense(hash32)` rend `{ r, s, v }` (`r`, `s` hexadécimaux de 32
 * octets, `s` dans la moitié basse de l'ordre, `v` égal à 27 ou 28), de
 * façon synchrone ou par une promesse.
 * @abstract
 */
export class SignataireChaine {
  /** @returns {string} */
  adresse() {
    throw new Error("SignataireChaine.adresse non mise en œuvre");
  }

  /**
   * @param {Uint8Array} hash32
   * @returns {{r: string, s: string, v: 27|28}|Promise<{r: string, s: string, v: 27|28}>}
   */
  signerCondense(hash32) {
    void hash32;
    throw new Error("SignataireChaine.signerCondense non mise en œuvre");
  }

  /** La classe de garde (CT-2 §11.2) ; `D` pour la classe fichier. */
  get classe() {
    return null;
  }
}

/** Dit si 32 octets forment une clé privée secp256k1 admise (1 ≤ d < n). */
function clePriveeAdmise(octets) {
  if (!estOctets(octets) || octets.length !== 32) return false;
  const d = octetsVersEntier(octets);
  return d >= 1n && d < N;
}

/**
 * Clé de chaîne de classe D (clé en clair, développement seulement : CT-2
 * refuse cette classe en production). Construite depuis des octets résolus
 * par l'appelant : 32 octets bruts, hexadécimal (64 chiffres, préfixe `0x`
 * facultatif, blancs de fin tolérés), PKCS#8 en PEM ou en DER d'une clé
 * `id-ecPublicKey` sur la courbe secp256k1, ou SEC1 `EC PRIVATE KEY` en PEM.
 */
export class SignataireChaineFichier extends SignataireChaine {
  #cle;
  #adresse;

  /** @param {Uint8Array} clePrivee 32 octets */
  constructor(clePrivee) {
    super();
    if (!clePriveeAdmise(clePrivee)) throw new TypeError("clé de chaîne : 32 octets dans [1, n − 1] attendus");
    this.#cle = Uint8Array.from(clePrivee);
    this.#adresse = adresseDepuisClePublique(secp256k1.getPublicKey(this.#cle, false));
  }

  /**
   * Construit le signataire depuis des octets ou un texte résolus (forme
   * détectée : brut, hexadécimal, PEM, DER).
   * @param {Uint8Array|string} source
   */
  static depuisOctets(source) {
    if (typeof source === "string") return SignataireChaineFichier.#depuisTexte(source);
    if (!estOctets(source)) throw new TypeError("octets ou texte attendus");
    if (source.length === 32) return new SignataireChaineFichier(source);
    // Un texte hexadécimal ou PEM d'abord (« 0x… » commence par l'octet 0x30, comme une séquence DER) ; sinon DER.
    const texte = utf8Texte(source);
    if (texte !== null && /^\s*((0x)?[0-9a-fA-F]{64}|-----BEGIN)/.test(texte)) return SignataireChaineFichier.#depuisTexte(texte);
    if (source.length > 0 && source[0] === 0x30) return SignataireChaineFichier.#depuisDer(source);
    throw new TypeError("clé de chaîne : forme non reconnue");
  }

  static #depuisTexte(texte) {
    const t = texte.replace(/\s+$/, "");
    if (/^(0x)?[0-9a-fA-F]{64}$/.test(t)) {
      const h = t.startsWith("0x") ? t.slice(2) : t;
      return new SignataireChaineFichier(Uint8Array.from(Buffer.from(h, "hex")));
    }
    if (/^-----BEGIN (EC )?PRIVATE KEY-----/.test(t)) {
      let objet;
      try {
        objet = createPrivateKey({ key: t, format: "pem" });
      } catch {
        throw new TypeError("clé de chaîne : PEM illisible");
      }
      return SignataireChaineFichier.#depuisObjet(objet);
    }
    throw new TypeError("clé de chaîne : forme non reconnue");
  }

  static #depuisDer(octets) {
    let objet = null;
    for (const type of ["pkcs8", "sec1"]) {
      try {
        objet = createPrivateKey({ key: Buffer.from(octets), format: "der", type });
        break;
      } catch {
        objet = null;
      }
    }
    if (!objet) throw new TypeError("clé de chaîne : DER illisible");
    return SignataireChaineFichier.#depuisObjet(objet);
  }

  static #depuisObjet(objet) {
    if (objet.asymmetricKeyType !== "ec" || objet.asymmetricKeyDetails?.namedCurve !== "secp256k1") {
      throw new TypeError("clé de chaîne : clé EC sur secp256k1 attendue");
    }
    const jwk = objet.export({ format: "jwk" });
    const d = Uint8Array.from(Buffer.from(jwk.d, "base64url"));
    if (d.length !== 32) throw new TypeError("clé de chaîne : scalaire de 32 octets attendu");
    return new SignataireChaineFichier(d);
  }

  get classe() {
    return "D";
  }

  adresse() {
    return this.#adresse;
  }

  /**
   * Signature ECDSA du condensé tel quel (RFC 6979, `s` bas).
   * @param {Uint8Array} hash32
   * @returns {{r: string, s: string, v: 27|28}}
   */
  signerCondense(hash32) {
    if (!estOctets(hash32) || hash32.length !== 32) throw new TypeError("condensé de 32 octets attendu");
    if (this.#efface) throw new Error("clé de chaîne effacée");
    const recouvrable =secp256k1.sign(hash32, this.#cle, { prehash: false, lowS: true, format: "recovered" });
    return {
      r: octetsVersHex(recouvrable.subarray(1, 33)),
      s: octetsVersHex(recouvrable.subarray(33, 65)),
      v: 27 + recouvrable[0],
    };
  }

  /** Efface la clé privée de la mémoire de l'instance (arrêt du démon, CT-2 EX-11.9) ; toute signature est ensuite refusée. */
  effacer() {
    this.#cle.fill(0);
    this.#efface = true;
  }

  #efface = false;

  /** Ne révèle jamais la clé. */
  toJSON() {
    return { classe: "D", adresse: this.#adresse };
  }

  toString() {
    return `SignataireChaineFichier(${this.#adresse})`;
  }
}

/**
 * Lit une signature `{ r, s, v }` (hexadécimaux ou octets) et dit si elle
 * est canonique (CT-4 RG-12 : `r` et `s` dans [1, n − 1], `s ≤ n/2`, `v` 27 ou
 * 28 ; pour une transaction, `v` ∈ {0, 1} admis par `yParity`).
 * @returns {{r: bigint, s: bigint, rec: 0|1}|null}
 */
export function lireSignature(sig, { yParity = false } = {}) {
  if (!sig || typeof sig !== "object") return null;
  const lireMot = (x) => {
    if (estOctets(x)) return x.length === 32 ? octetsVersEntier(x) : null;
    if (typeof x === "string" && /^0x[0-9a-f]{64}$/.test(x)) return BigInt(x);
    return null;
  };
  const r = lireMot(sig.r);
  const s = lireMot(sig.s);
  if (r === null || s === null) return null;
  let rec;
  if (yParity) {
    if (sig.yParity === 0 || sig.yParity === 1) rec = sig.yParity;
    else if (sig.v === 27 || sig.v === 28) rec = sig.v - 27;
    else return null;
  } else if (sig.v === 27 || sig.v === 28) rec = sig.v - 27;
  else return null;
  if (r < 1n || r >= N || s < 1n || s >= N || s > DEMI_N) return null;
  return { r, s, rec };
}

/**
 * Recouvre l'adresse qui a signé un condensé de 32 octets (ECDSA tel quel,
 * sans préfixe), ou rend null si la signature n'est pas canonique ou ne se
 * recouvre pas.
 */
export function recouvrerSignataire(hash32, sig, options) {
  if (!estOctets(hash32) || hash32.length !== 32) return null;
  const lue = lireSignature(sig, options);
  if (!lue) return null;
  try {
    const point = new secp256k1.Signature(lue.r, lue.s, lue.rec).recoverPublicKey(hash32);
    return adresseDepuisClePublique(point.toBytes(false));
  } catch {
    return null;
  }
}

/**
 * Recouvre la clé publique non compressée (65 octets) d'une signature
 * `R ‖ S ‖ V` de 65 octets (`V` ∈ {0, 1}, `S` bas) sur un condensé, comme
 * les enveloppes BFT de CT-6 EX-11.7 ; null sinon.
 */
export function recouvrerClePublique65(hash32, signature65) {
  if (!estOctets(hash32) || hash32.length !== 32 || !estOctets(signature65) || signature65.length !== 65) return null;
  const r = octetsVersEntier(signature65.subarray(0, 32));
  const s = octetsVersEntier(signature65.subarray(32, 64));
  const v = signature65[64];
  if (v !== 0 && v !== 1) return null;
  if (r < 1n || r >= N || s < 1n || s >= N || s > DEMI_N) return null;
  try {
    return new secp256k1.Signature(r, s, v).recoverPublicKey(hash32).toBytes(false);
  } catch {
    return null;
  }
}

/**
 * Ramène une clé publique déclarée (65 octets `04 ‖ X ‖ Y`, 64 octets
 * `X ‖ Y`, 33 octets compressée) à la forme non compressée de 65 octets, ou
 * rend null si ce n'est pas un point de secp256k1.
 */
export function clePubliqueNonCompressee(declaree) {
  if (!estOctets(declaree)) return null;
  try {
    if (declaree.length === 64) return secp256k1.Point.fromBytes(Uint8Array.of(0x04, ...declaree)).toBytes(false);
    if (declaree.length === 65 || declaree.length === 33) return secp256k1.Point.fromBytes(declaree).toBytes(false);
  } catch {
    return null;
  }
  return null;
}

/**
 * Signature ECDSA secp256k1 rendue en DER par un service de signature
 * (séquence de deux entiers `r`, `s`, X.690 ; AWS KMS `ECDSA_SHA_256` avec
 * `MessageType: DIGEST`, PKCS#11 `CKM_ECDSA` après mise en DER) ramenée à
 * la forme de l'interface `SignataireChaine` : `s` bas (`s ← n − s` si
 * `s > n/2`, même signature au sens d'ECDSA), `v` ∈ {27, 28} trouvé en
 * recouvrant `adresse` (étape 7 : clé de chaîne de classe B). Une forme DER
 * non minimale, des octets en trop, `r` ou `s` hors de [1, n − 1], ou une
 * signature qui ne recouvre pas `adresse` lèvent une erreur.
 * @param {Uint8Array} hash32
 * @param {Uint8Array} der
 * @param {string} adresse adresse attendue (minuscules)
 * @returns {{r: string, s: string, v: 27|28}}
 */
export function signatureDepuisDer(hash32, der, adresse) {
  if (!estOctets(hash32) || hash32.length !== 32) throw new TypeError("condensé de 32 octets attendu");
  if (!estOctets(der) || der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new TypeError("signature DER : séquence attendue");
  let k = 2;
  const entier = () => {
    if (der[k] !== 0x02) throw new TypeError("signature DER : entier attendu");
    const n = der[k + 1];
    if (n < 1 || n > 33 || k + 2 + n > der.length) throw new TypeError("signature DER : longueur d'entier");
    const v = der.subarray(k + 2, k + 2 + n);
    // X.690 : forme minimale, positive.
    if (v[0] & 0x80) throw new TypeError("signature DER : entier négatif");
    if (n > 1 && v[0] === 0 && !(v[1] & 0x80)) throw new TypeError("signature DER : entier non minimal");
    k += 2 + n;
    return octetsVersEntier(v);
  };
  const r = entier();
  let s = entier();
  if (k !== der.length) throw new TypeError("signature DER : octets en trop");
  if (r < 1n || r >= N || s < 1n || s >= N) throw new TypeError("signature DER : r ou s hors de [1, n − 1]");
  if (s > DEMI_N) s = N - s;
  const mot = (x) => `0x${x.toString(16).padStart(64, "0")}`;
  for (const v of [27, 28]) {
    const sig = { r: mot(r), s: mot(s), v };
    if (recouvrerSignataire(hash32, sig) === adresse) return sig;
  }
  throw new Error("la signature ne recouvre pas l'adresse de la clé de chaîne");
}

/** Ordre de la courbe et sa moitié, pour les contrôles de forme. */
export const ORDRE_SECP256K1 = N;
export const DEMI_ORDRE_SECP256K1 = DEMI_N;

/** Lit une clé privée hexadécimale de test (publiée) en 32 octets ; pour les tests. */
export function clePriveeDepuisHex(hex) {
  return hexVersOctets(hex, 32);
}
