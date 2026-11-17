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
 * Carte (10.3.4) : dans chaque suite maximale de chiffres et de SEP ou `-`
 * isolés, les sous-suites de groupes consécutifs de 12 à 19 chiffres,
 * bordées de frontières, éprouvées par premier groupe de gauche à droite, la
 * plus longue d'abord ; la première qui passe Luhn est la correspondance, et
 * la recherche reprend juste après elle, au groupe suivant de la même suite
 * (complément du 2026-11-16 de la révision 0.11). Au plus huit épreuves par
 * premier groupe, chacune en temps constant par des sommes préfixes : le
 * coût reste linéaire en la longueur du segment, même pour une suite de
 * millions de groupes.
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
    // Groupes de la suite maximale qui commence en i : [début, fin) dans la chaîne, et rang de leur premier chiffre dans la suite.
    const debuts = [];
    const fins = [];
    const rangs = [];
    let j = i;
    let n = 0;
    for (;;) {
      debuts.push(j);
      rangs.push(n);
      while (j < b && estChiffre(s.charCodeAt(j))) {
        j++;
        n++;
      }
      fins.push(j);
      if (j + 1 < b && (estSep(s.charCodeAt(j)) || s.charCodeAt(j) === 0x2d) && estChiffre(s.charCodeAt(j + 1))) j++;
      else break;
    }
    rangs.push(n);
    if (n >= 12) {
      // Sommes préfixes de Luhn : chiffres pris tels quels (T) ou doublés (D), par parité de rang.
      const T = [new Int32Array(n + 1), new Int32Array(n + 1)];
      const D = [new Int32Array(n + 1), new Int32Array(n + 1)];
      let r = 0;
      for (let g = 0; g < debuts.length; g++) {
        for (let k = debuts[g]; k < fins[g]; k++, r++) {
          const d = s.charCodeAt(k) - 0x30;
          const dd = d * 2 > 9 ? d * 2 - 9 : d * 2;
          const p = r % 2;
          T[p][r + 1] = T[p][r] + d;
          D[p][r + 1] = D[p][r] + dd;
          T[1 - p][r + 1] = T[1 - p][r];
          D[1 - p][r + 1] = D[1 - p][r];
        }
      }
      // Luhn des chiffres de rangs [x, y] : ceux de la parité de y tels quels, les autres doublés.
      const luhnRangs = (x, y) => {
        const py = y % 2;
        return (T[py][y + 1] - T[py][x] + D[1 - py][y + 1] - D[1 - py][x]) % 10 === 0;
      };
      let g1 = 0;
      while (g1 < debuts.length) {
        let g2 = -1;
        if (f.avant(debuts[g1])) {
          let gmax = -1;
          for (let g = g1; g < debuts.length && rangs[g + 1] - rangs[g1] <= 19; g++) if (rangs[g + 1] - rangs[g1] >= 12) gmax = g;
          for (let g = gmax; g >= g1 && rangs[g + 1] - rangs[g1] >= 12; g--) {
            if (f.apres(fins[g]) && luhnRangs(rangs[g1], rangs[g + 1] - 1)) {
              g2 = g;
              break;
            }
          }
        }
        if (g2 === -1) {
          g1++;
          continue;
        }
        let N = "";
        for (let g = g1; g <= g2; g++) N += s.slice(debuts[g], fins[g]);
        sortie.push({ debut: debuts[g1], fin: fins[g2], valeur: N });
        f.marquer(fins[g2]);
        g1 = g2 + 1;
      }
    }
    i = j;
  }
  return sortie;
}

// ------------------------------------------------------------ email (10.3.5)

const LOCAL = new Set(Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+/=?^_`{|}~.-", (c) => c.charCodeAt(0)));
const estLocal = (c) => LOCAL.has(c);
const estDomaine = (c) => estAlnum(c) || c === 0x2e || c === 0x2d;

/**
 * Domaine d'une adresse (10.3.5) : longueur du plus long préfixe de
 * `s[r0, r1)` qui est un domaine valide (deux labels au moins, chacun de 1 à
 * 63 caractères de [A-Za-z0-9-] ne commençant ni ne finissant par `-`, le
 * dernier de deux lettres ASCII au moins) et qui est la suite entière, si
 * elle compte au plus 255 caractères, ou suivi dans la suite d'un `.` ou d'un
 * `-` ; -1 sans un tel préfixe. Un seul parcours.
 */
function longueurDomaine(s, r0, r1) {
  let meilleur = -1;
  let debutLabel = r0;
  let labels = 0;
  let nonLettre = r0 - 1;
  for (let k = r0; k <= r1; k++) {
    const c = k < r1 ? s.charCodeAt(k) : -1;
    const bord = k === r1 ? r1 - r0 <= 255 : c === 0x2e || c === 0x2d;
    const l = k - debutLabel;
    if (bord && labels >= 1 && l >= 2 && l <= 63 && nonLettre < debutLabel) meilleur = k - r0;
    if (k === r1) break;
    if (c === 0x2e) {
      // Label complet [debutLabel, k) : 1 à 63 caractères, ni `-` initial ni `-` final.
      if (l < 1 || l > 63 || s.charCodeAt(debutLabel) === 0x2d || s.charCodeAt(k - 1) === 0x2d) break;
      labels++;
      debutLabel = k + 1;
    } else if (!estMajuscule(c) && !estMinuscule(c)) {
      nonLettre = k;
    }
  }
  return meilleur;
}

/**
 * Adresse `Dot-string@Domain` : lecture bornée à 64 caractères à gauche de
 * chaque `@` et 256 à droite ; la partie locale est la plus longue fin
 * `Dot-string` de la suite lue à gauche, le domaine le plus long préfixe
 * admissible de la suite lue à droite (complément du 2026-11-16 de la
 * révision 0.11).
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
    while (l > borneGauche && k - l < 64 && estLocal(s.charCodeAt(l - 1))) l--;
    let trouve = null;
    // Plus longue fin Dot-string de [l, k) : non vide, sans `.` final, après le dernier `..`, sans `.` initial.
    if (l < k && s.charCodeAt(k - 1) !== 0x2e) {
      let debut = l;
      for (let x = k - 2; x >= l; x--) {
        if (s.charCodeAt(x) === 0x2e && s.charCodeAt(x + 1) === 0x2e) {
          debut = x + 2;
          break;
        }
      }
      if (s.charCodeAt(debut) === 0x2e) debut++;
      let r = k + 1;
      while (r < b && r - (k + 1) < 256 && estDomaine(s.charCodeAt(r))) r++;
      const n = longueurDomaine(s, k + 1, r);
      if (n !== -1) trouve = { debut, fin: k + 1 + n, valeur: `${s.slice(debut, k)}@${s.slice(k + 1, k + 1 + n).toLowerCase()}` };
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
 * parenthèses compris quand un chiffre le suit. Le candidat finit à la plus
 * grande position prise par `fin` qui est une frontière et laisse de 8 à 15
 * chiffres (reprise au séparateur, complément du 2026-11-16 de la révision
 * 0.11) ; le parcours s'arrête au-delà de 15 chiffres.
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
    let chiffres = 0;
    let N = "+";
    let enAttente = "";
    let groupeLu = false;
    let precedentSep = false;
    let trouve = null;
    while (j < b) {
      const c = s.charCodeAt(j);
      if (estChiffre(c)) {
        N += enAttente + s[j];
        chiffres += enAttente.length + 1;
        enAttente = "";
        j++;
        precedentSep = false;
        if (chiffres > 15) break;
        if (chiffres >= 8 && f.apres(j)) trouve = { debut: p, fin: j, valeur: N };
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
    if (trouve) {
      sortie.push(trouve);
      f.marquer(trouve.fin);
      p = s.indexOf("+", trouve.fin);
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
