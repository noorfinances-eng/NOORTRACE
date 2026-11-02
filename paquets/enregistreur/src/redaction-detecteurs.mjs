// Détecteurs exacts de la rédaction (CT-2 §10.3) : `iban`, `avs`, `carte`,
// `email`, `telephone` au caractère près, et `regex` (motif nommé, EX-10.10).
// Chaque détecteur opère sur un segment `[a, b)` d'une chaîne, situé entre
// deux jetons (EX-10.9) : chaque bord de segment vaut début ou fin de chaîne
// pour les frontières ; les correspondances sont cherchées de gauche à
// droite, sans chevauchement, et la fin d'une correspondance vaut frontière
// pour le candidat qui suit. Les détecteurs nommés sont en temps linéaire en
// la longueur du segment (lectures bornées, aucun retour arrière, EX-10.23).
//
// Les positions sont des indices d'unités de code UTF-16 : les alphabets des
// cinq détecteurs nommés et leurs séparateurs sont dans le plan de base, et
// un demi-substitut n'est ni un chiffre ni une lettre ASCII ; compter en
// points de code (EX-10.9) donne donc les mêmes correspondances.

/** Longueur des IBAN par code pays (10.3.2). */
export const LONGUEURS_IBAN = Object.freeze({ CH: 21, LI: 21, DE: 22, FR: 27, IT: 27, AT: 20, ES: 24, NL: 18, BE: 16, GB: 22, LU: 20 });

const estChiffre = (c) => c >= 0x30 && c <= 0x39;
const estMajuscule = (c) => c >= 0x41 && c <= 0x5a;
const estMinuscule = (c) => c >= 0x61 && c <= 0x7a;
const estAlnum = (c) => estChiffre(c) || estMajuscule(c) || estMinuscule(c);
/** SEP : espace, espace insécable, espace insécable étroite (10.3.1). */
const estSep = (c) => c === 0x20 || c === 0xa0 || c === 0x202f;

/** Contexte de frontières d'un segment pour un détecteur. */
function frontieres(s, a, b) {
  let finPrecedente = -1;
  return {
    avant: (p) => p === a || p === finPrecedente || !estAlnum(s.charCodeAt(p - 1)),
    apres: (q) => q === b || !estAlnum(s.charCodeAt(q)),
    marquer: (q) => {
      finPrecedente = q;
    },
  };
}

// ------------------------------------------------------------ iban (10.3.2)

/** Reste MOD 97-10 par blocs de neuf chiffres (10.3.2 pas 3). */
export function resteIban(N) {
  const R = N.slice(4) + N.slice(0, 4);
  let D = "";
  for (const ch of R) {
    const c = ch.charCodeAt(0);
    D += estMajuscule(c) ? String(c - 55) : ch;
  }
  let r = 0;
  for (let k = 0; k < D.length; k += 9) r = Number(`${r}${D.slice(k, k + 9)}`) % 97;
  return r;
}

/**
 * IBAN des pays de la table, en majuscules, groupes séparés par un SEP isolé.
 * @param {string} s
 * @param {number} a
 * @param {number} b
 * @returns {{debut: number, fin: number, valeur: string}[]}
 */
export function detecterIban(s, a, b) {
  const f = frontieres(s, a, b);
  const sortie = [];
  let p = a;
  while (p + 4 <= b) {
    const c0 = s.charCodeAt(p);
    if (!estMajuscule(c0) || !f.avant(p)) {
      p++;
      continue;
    }
    const L = LONGUEURS_IBAN[s.slice(p, p + 2)];
    if (L === undefined || !estChiffre(s.charCodeAt(p + 2)) || !estChiffre(s.charCodeAt(p + 3))) {
      p++;
      continue;
    }
    let N = s.slice(p, p + 4);
    let j = p + 4;
    let lus = 0;
    let ok = true;
    while (lus < L - 4) {
      if (j >= b) {
        ok = false;
        break;
      }
      const c = s.charCodeAt(j);
      if (estMajuscule(c) || estChiffre(c)) {
        N += s[j];
        lus++;
        j++;
        continue;
      }
      // SEP isolé entre deux alphanumériques du candidat.
      if (estSep(c) && j + 1 < b && (estMajuscule(s.charCodeAt(j + 1)) || estChiffre(s.charCodeAt(j + 1))) && !estSep(s.charCodeAt(j - 1))) {
        j++;
        continue;
      }
      ok = false;
      break;
    }
    if (ok && f.apres(j) && resteIban(N) === 1) {
      sortie.push({ debut: p, fin: j, valeur: N });
      f.marquer(j);
      p = j;
      continue;
    }
    p++;
  }
  return sortie;
}

// ------------------------------------------------------------ avs (10.3.3)

/** Clé de contrôle d'un numéro AVS de treize chiffres (10.3.3 pas 3). */
export function cleAvs(N) {
  let S = 0;
  for (let i = 0; i < 12; i++) S += Number(N[i]) * (i % 2 === 0 ? 1 : 3);
  return (10 - (S % 10)) % 10;
}

/**
 * Numéro AVS 756.XXXX.XXXX.XX (séparateurs facultatifs, tous identiques).
 * @param {string} s
 * @param {number} a
 * @param {number} b
 */
export function detecterAvs(s, a, b) {
  const f = frontieres(s, a, b);
  const sortie = [];
  let p = a;
  while (p + 13 <= b) {
    if (s.charCodeAt(p) !== 0x37 || !s.startsWith("756", p) || !f.avant(p)) {
      p++;
      continue;
    }
    let j = p + 3;
    let N = "756";
    let sep = null;
    let ok = true;
    for (const n of [4, 4, 2]) {
      if (j < b) {
        const c = s.charCodeAt(j);
        if (c === 0x2e || estSep(c)) {
          if (sep === null) sep = c;
          else if (sep !== c) {
            ok = false;
            break;
          }
          j++;
        }
      }
      for (let k = 0; k < n; k++) {
        if (j >= b || !estChiffre(s.charCodeAt(j))) {
          ok = false;
          break;
        }
        N += s[j];
        j++;
      }
      if (!ok) break;
    }
    if (ok && f.apres(j) && cleAvs(N) === Number(N[12])) {
      sortie.push({ debut: p, fin: j, valeur: N });
      f.marquer(j);
      p = j;
      continue;
    }
    p++;
  }
  return sortie;
}

// ------------------------------------------------------------ carte (10.3.4)

/** Somme de Luhn nulle modulo 10 (10.3.4 pas 3). */
export function luhn(N) {
  let S = 0;
  for (let k = 0; k < N.length; k++) {
    let d = Number(N[N.length - 1 - k]);
    if (k % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    S += d;
  }
  return S % 10 === 0;
}

/**
 * Suite maximale de chiffres, SEP et `-` isolés, de 12 à 19 chiffres, qui
 * passe Luhn.
 * @param {string} s
 * @param {number} a
 * @param {number} b
 */
export function detecterCarte(s, a, b) {
  const f = frontieres(s, a, b);
  const sortie = [];
  let i = a;
  while (i < b) {
    if (!estChiffre(s.charCodeAt(i))) {
      i++;
      continue;
    }
    let j = i;
    let N = "";
    for (;;) {
      if (j < b && estChiffre(s.charCodeAt(j))) {
        if (N.length <= 19) N += s[j];
        j++;
      } else if (j < b && j + 1 < b && (estSep(s.charCodeAt(j)) || s.charCodeAt(j) === 0x2d) && estChiffre(s.charCodeAt(j + 1))) {
        j++;
      } else {
        break;
      }
    }
    if (N.length >= 12 && N.length <= 19 && f.avant(i) && f.apres(j) && luhn(N)) {
      sortie.push({ debut: i, fin: j, valeur: N });
      f.marquer(j);
    }
    i = j;
  }
  return sortie;
}

// ------------------------------------------------------------ email (10.3.5)

const LOCAL = new Set(Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+/=?^_`{|}~.-", (c) => c.charCodeAt(0)));
const estLocal = (c) => LOCAL.has(c);
const estDomaine = (c) => estAlnum(c) || c === 0x2e || c === 0x2d;

function dotString(L) {
  return L.length > 0 && !L.startsWith(".") && !L.endsWith(".") && !L.includes("..");
}

function domaineValide(D) {
  const labels = D.split(".");
  if (labels.length < 2) return false;
  for (const l of labels) {
    if (l.length < 1 || l.length > 63 || l.startsWith("-") || l.endsWith("-") || !/^[A-Za-z0-9-]+$/.test(l)) return false;
  }
  return /^[A-Za-z]{2,}$/.test(labels[labels.length - 1]);
}

/**
 * Adresse `Dot-string@Domain` : lecture bornée à 64 caractères à gauche de
 * chaque `@` et 256 à droite.
 * @param {string} s
 * @param {number} a
 * @param {number} b
 */
export function detecterEmail(s, a, b) {
  const sortie = [];
  let borneGauche = a;
  let k = s.indexOf("@", a);
  while (k !== -1 && k < b) {
    let l = k;
    let n = 0;
    while (l > borneGauche && estLocal(s.charCodeAt(l - 1)) && n < 65) {
      l--;
      n++;
    }
    let trouve = null;
    if (n <= 64) {
      const L = s.slice(l, k);
      let r = k + 1;
      while (r < b && r - (k + 1) < 256 && estDomaine(s.charCodeAt(r))) r++;
      if (r - (k + 1) <= 255 && dotString(L)) {
        let D = s.slice(k + 1, r);
        if (D.endsWith(".") || D.endsWith("-")) D = D.slice(0, -1);
        if (domaineValide(D)) trouve = { debut: l, fin: k + 1 + D.length, valeur: `${L}@${D.toLowerCase()}` };
      }
    }
    if (trouve) {
      sortie.push(trouve);
      borneGauche = trouve.fin;
      k = s.indexOf("@", trouve.fin);
    } else {
      k = s.indexOf("@", k + 1);
    }
  }
  return sortie;
}

// ------------------------------------------------------------ telephone (10.3.6)

const estSepTel = (c) => estSep(c) || c === 0x2d || c === 0x2e;

/**
 * Numéro international `+` suivi de 8 à 15 chiffres, groupe entre
 * parenthèses compris quand un chiffre le suit.
 * @param {string} s
 * @param {number} a
 * @param {number} b
 */
export function detecterTelephone(s, a, b) {
  const f = frontieres(s, a, b);
  const sortie = [];
  let p = s.indexOf("+", a);
  while (p !== -1 && p < b) {
    const c1 = p + 1 < b ? s.charCodeAt(p + 1) : -1;
    if (!f.avant(p) || !(c1 >= 0x31 && c1 <= 0x39)) {
      p = s.indexOf("+", p + 1);
      continue;
    }
    let j = p + 1;
    let fin = -1;
    let chiffres = 0;
    let N = "+";
    let enAttente = "";
    let groupeLu = false;
    let precedentSep = false;
    let trop = false;
    while (j < b) {
      const c = s.charCodeAt(j);
      if (estChiffre(c)) {
        N += enAttente + s[j];
        chiffres += enAttente.length + 1;
        enAttente = "";
        j++;
        fin = j;
        precedentSep = false;
        if (chiffres > 15) {
          trop = true;
          break;
        }
      } else if (estSepTel(c)) {
        if (precedentSep) break;
        precedentSep = true;
        j++;
      } else if (c === 0x28) {
        if (groupeLu) break;
        let k = j + 1;
        let g = "";
        while (k < b && estChiffre(s.charCodeAt(k)) && g.length <= 16) g += s[k++];
        if (g.length === 0 || k >= b || s.charCodeAt(k) !== 0x29) break;
        groupeLu = true;
        enAttente = g;
        j = k + 1;
        precedentSep = false;
      } else {
        break;
      }
    }
    if (!trop && fin !== -1 && f.apres(fin) && chiffres >= 8 && chiffres <= 15) {
      sortie.push({ debut: p, fin, valeur: N });
      f.marquer(fin);
      p = s.indexOf("+", fin);
      continue;
    }
    p = s.indexOf("+", p + 1);
  }
  return sortie;
}

// ------------------------------------------------------------ regex (10.3.7)

/**
 * Motif nommé (EX-10.10) : correspondances non vides, sans chevauchement ;
 * une correspondance vide est ignorée et la recherche avance d'un point de
 * code. Aucune frontière implicite. Après une correspondance, la recherche
 * reprend sur le reste du segment, dont le début vaut début de chaîne (la
 * fin d'une correspondance remplacée vaut frontière, EX-10.9).
 * @param {RegExp} regexp compilée avec le drapeau `u`
 * @param {string} s
 * @param {number} a
 * @param {number} b
 */
export function detecterRegex(regexp, s, a, b) {
  const sortie = [];
  const re = new RegExp(regexp.source, "gu");
  let base = a;
  let reste = s.slice(a, b);
  re.lastIndex = 0;
  for (;;) {
    const m = re.exec(reste);
    if (!m) break;
    if (m[0].length === 0) {
      if (m.index >= reste.length) break;
      const cp = reste.codePointAt(m.index);
      re.lastIndex = m.index + (cp > 0xffff ? 2 : 1);
      continue;
    }
    const debut = base + m.index;
    const fin = debut + m[0].length;
    sortie.push({ debut, fin, valeur: m[0] });
    reste = reste.slice(m.index + m[0].length);
    base = fin;
    re.lastIndex = 0;
  }
  return sortie;
}

/** Détecteurs nommés, par type. */
export const DETECTEURS_NOMMES = Object.freeze({
  iban: detecterIban,
  avs: detecterAvs,
  carte: detecterCarte,
  email: detecterEmail,
  telephone: detecterTelephone,
});
