// Octets, hexadécimal, UTF-8 et base64 (CT-1 §3) : conversions sans
// dépendance, identiques sous Node 22 et dans Chromium. Règles tenues :
// hexadécimal minuscule préfixé `0x` (CT-1 §3) ; UTF-8 bien formé au sens de
// la RFC 3629 (CT-3 EX-9.19, CT-1 §3 révision 0.5) ; base64 de la RFC 4648 §4
// (CT-3 EX-9.15, contrôle 3).

const CHIFFRES = "0123456789abcdef";

/**
 * Octets → `0x` et hexadécimal minuscule.
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function versHex(octets) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("versHex : Uint8Array attendu");
  let s = "0x";
  for (let i = 0; i < octets.length; i++) s += CHIFFRES[octets[i] >> 4] + CHIFFRES[octets[i] & 15];
  return s;
}

/**
 * Valeur d'un chiffre hexadécimal (casse indifférente), ou -1.
 * @param {number} c unité de code
 */
function valeurChiffre(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}

/**
 * `0x` et un nombre pair de chiffres hexadécimaux (casse indifférente) →
 * octets ; `null` pour toute autre chaîne.
 * @param {string} hex
 * @returns {Uint8Array|null}
 */
export function depuisHex(hex) {
  if (typeof hex !== "string") throw new TypeError("depuisHex : chaine attendue");
  if (hex.length < 2 || hex[0] !== "0" || hex[1] !== "x" || hex.length % 2 !== 0) return null;
  const n = (hex.length - 2) / 2;
  const sortie = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const h = valeurChiffre(hex.charCodeAt(2 + 2 * i));
    const b = valeurChiffre(hex.charCodeAt(3 + 2 * i));
    if (h < 0 || b < 0) return null;
    sortie[i] = h * 16 + b;
  }
  return sortie;
}

/**
 * Chaîne → octets UTF-8. Une chaîne qui porte un substitut isolé n'a pas
 * d'encodage UTF-8 : `null`.
 * @param {string} s
 * @returns {Uint8Array|null}
 */
export function utf8(s) {
  if (typeof s !== "string") throw new TypeError("utf8 : chaine attendue");
  const sortie = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) return null;
      c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return null;
    }
    if (c < 0x80) sortie.push(c);
    else if (c < 0x800) sortie.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) sortie.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else sortie.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(sortie);
}

/**
 * Chaîne sans substitut isolé → octets UTF-8 ; lève `TypeError` sinon.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function utf8Strict(s) {
  const o = utf8(s);
  if (o === null) throw new TypeError("chaine a substitut isole");
  return o;
}

/**
 * Décode des octets UTF-8 bien formés (RFC 3629 : ni forme trop longue, ni
 * substitut U+D800 à U+DFFF, ni point de code au-delà de U+10FFFF), ou `null`.
 * @param {Uint8Array} o
 * @returns {string|null}
 */
export function decoderUtf8(o) {
  if (!(o instanceof Uint8Array)) throw new TypeError("decoderUtf8 : Uint8Array attendu");
  const unites = [];
  let i = 0;
  while (i < o.length) {
    const a = o[i];
    let c;
    let n;
    if (a < 0x80) {
      c = a;
      n = 1;
    } else if (a >= 0xc2 && a <= 0xdf) {
      c = a & 0x1f;
      n = 2;
    } else if (a >= 0xe0 && a <= 0xef) {
      c = a & 0x0f;
      n = 3;
    } else if (a >= 0xf0 && a <= 0xf4) {
      c = a & 0x07;
      n = 4;
    } else {
      return null;
    }
    if (i + n > o.length) return null;
    for (let k = 1; k < n; k++) {
      const b = o[i + k];
      if ((b & 0xc0) !== 0x80) return null;
      c = (c << 6) | (b & 0x3f);
    }
    if (n === 3 && (c < 0x800 || (c >= 0xd800 && c <= 0xdfff))) return null;
    if (n === 4 && (c < 0x10000 || c > 0x10ffff)) return null;
    if (c >= 0x10000) {
      const v = c - 0x10000;
      unites.push(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
    } else {
      unites.push(c);
    }
    i += n;
  }
  let s = "";
  for (let k = 0; k < unites.length; k += 4096) s += String.fromCharCode(...unites.slice(k, k + 4096));
  return s;
}

/**
 * Vrai si les octets sont de l'UTF-8 bien formé (RFC 3629).
 * @param {Uint8Array} o
 */
export function estUtf8(o) {
  return decoderUtf8(o) !== null;
}

/**
 * Concatène des suites d'octets.
 * @param {...Uint8Array} parties
 * @returns {Uint8Array}
 */
export function concatener(...parties) {
  let n = 0;
  for (const p of parties) {
    if (!(p instanceof Uint8Array)) throw new TypeError("concatener : Uint8Array attendu");
    n += p.length;
  }
  const sortie = new Uint8Array(n);
  let k = 0;
  for (const p of parties) {
    sortie.set(p, k);
    k += p.length;
  }
  return sortie;
}

/**
 * Octets → entier non signé gros-boutiste.
 * @param {Uint8Array} o
 * @returns {bigint}
 */
export function versEntier(o) {
  let v = 0n;
  for (let i = 0; i < o.length; i++) v = (v << 8n) | BigInt(o[i]);
  return v;
}

/**
 * Entier non signé → `longueur` octets gros-boutistes.
 * @param {bigint} v
 * @param {number} longueur
 * @returns {Uint8Array}
 */
export function depuisEntier(v, longueur) {
  const sortie = new Uint8Array(longueur);
  let x = v;
  for (let i = longueur - 1; i >= 0; i--) {
    sortie[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new TypeError("entier trop grand");
  return sortie;
}

/**
 * Nombre de points de code d'une chaîne (un substitut isolé compte pour un).
 * @param {string} s
 */
export function longueurPointsDeCode(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

const ALPHABET_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Décode le base64 de la RFC 4648 §4 (alphabet standard, remplissage `=`
 * obligatoire, sans blanc, bits de remplissage nuls : forme canonique de §3.5),
 * ou `null`.
 * @param {string} texte
 * @returns {Uint8Array|null}
 */
export function decoderBase64(texte) {
  if (typeof texte !== "string") throw new TypeError("decoderBase64 : chaine attendue");
  if (texte.length % 4 !== 0) return null;
  const sortie = [];
  for (let i = 0; i < texte.length; i += 4) {
    const derniers = i + 4 === texte.length;
    const v = [];
    let remplissage = 0;
    for (let k = 0; k < 4; k++) {
      const c = texte[i + k];
      if (c === "=") {
        if (!derniers || k < 2) return null;
        remplissage++;
        v.push(0);
        continue;
      }
      if (remplissage > 0) return null;
      const x = ALPHABET_B64.indexOf(c);
      if (x < 0) return null;
      v.push(x);
    }
    const bloc = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    if (remplissage === 2 && (bloc & 0xffff) !== 0) return null;
    if (remplissage === 1 && (bloc & 0xff) !== 0) return null;
    sortie.push((bloc >> 16) & 0xff);
    if (remplissage < 2) sortie.push((bloc >> 8) & 0xff);
    if (remplissage < 1) sortie.push(bloc & 0xff);
  }
  return Uint8Array.from(sortie);
}
