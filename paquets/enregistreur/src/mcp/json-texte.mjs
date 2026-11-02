// Lecture stricte d'un texte JSON reçu par le frontal MCP (CT-2 4.4 pas 1),
// avec la position de chaque valeur dans le texte. Le frontal ne resérialise
// jamais les arguments ni le résultat : il recopie leurs octets d'origine,
// blancs non significatifs retirés (EX-4.20, EX-4.43). Il lui faut donc,
// pour chaque membre, l'endroit exact où il commence et finit.
//
// Règles (RFC 8259, 4.4 pas 1) : texte UTF-8 valide, sans marque d'ordre
// d'octets ; clés en double, substituts isolés (échappés) et caractères de
// contrôle bruts dans une chaîne refusés ; profondeur d'imbrication au plus
// `profondeurMax` ; au plus `membresMax` membres ou éléments par objet ou
// tableau ; un nombre qui déborde la double précision arrête l'analyse
// (EX-4.44, `arguments_non_canonisables`).

/** Erreur de lecture : `raison` dit laquelle des règles a été violée. */
export class ErreurTexteJson extends Error {
  /**
   * @param {"utf8"|"bom"|"syntaxe"|"cle_double"|"substitut_isole"|"profondeur"|"membres"|"non_canonisable"} raison
   * @param {number} position indice dans le texte
   */
  constructor(raison, position) {
    super(`JSON refusé (${raison}) à la position ${position}`);
    this.name = "ErreurTexteJson";
    this.raison = raison;
    this.position = position;
  }
}

const DECODEUR = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Décode des octets UTF-8 sans tolérance (séquence invalide, marque d'ordre
 * d'octets refusées).
 * @param {Uint8Array} octets
 * @returns {string}
 */
export function decoderUtf8Strict(octets) {
  let t;
  try {
    t = DECODEUR.decode(octets);
  } catch {
    throw new ErreurTexteJson("utf8", 0);
  }
  if (t.charCodeAt(0) === 0xfeff) throw new ErreurTexteJson("bom", 0);
  return t;
}

const BLANCS = new Set([0x20, 0x09, 0x0a, 0x0d]);

/**
 * Analyse un texte JSON complet et rend son arbre de nœuds positionnés.
 * Nœud : `{ t, d, f }` (type, début, fin exclue dans le texte), plus
 * `membres: [{ cle, kd, kf, v }]` (objet), `elements: [nœud]` (tableau),
 * `valeur` (chaîne décodée, nombre en double, booléen, null).
 * @param {string} texte
 * @param {{profondeurMax?: number, membresMax?: number}} [options]
 * @returns {object}
 * @throws {ErreurTexteJson}
 */
export function analyserTexte(texte, options = {}) {
  const profondeurMax = options.profondeurMax ?? 128;
  const membresMax = options.membresMax ?? 100000;
  let i = 0;
  const n = texte.length;

  const blancs = () => {
    while (i < n && BLANCS.has(texte.charCodeAt(i))) i++;
  };
  const erreur = (raison) => new ErreurTexteJson(raison, i);

  function chaine() {
    // texte[i] === '"'
    const d = i;
    i++;
    let s = "";
    let debut = i;
    while (true) {
      if (i >= n) throw erreur("syntaxe");
      const c = texte.charCodeAt(i);
      if (c === 0x22) {
        s += texte.slice(debut, i);
        i++;
        break;
      }
      if (c < 0x20) throw erreur("syntaxe");
      if (c === 0x5c) {
        s += texte.slice(debut, i);
        i++;
        if (i >= n) throw erreur("syntaxe");
        const e = texte[i];
        const simples = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (e in simples) {
          s += simples[e];
          i++;
        } else if (e === "u") {
          const lireU = () => {
            const h = texte.slice(i + 1, i + 5);
            if (!/^[0-9A-Fa-f]{4}$/.test(h)) throw erreur("syntaxe");
            i += 5;
            return parseInt(h, 16);
          };
          const u = lireU();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (texte[i] === "\\" && texte[i + 1] === "u") {
              i++;
              const v = lireU();
              if (v < 0xdc00 || v > 0xdfff) throw erreur("substitut_isole");
              s += String.fromCharCode(u, v);
            } else {
              throw erreur("substitut_isole");
            }
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            throw erreur("substitut_isole");
          } else {
            s += String.fromCharCode(u);
          }
        } else {
          throw erreur("syntaxe");
        }
        debut = i;
        continue;
      }
      i++;
    }
    return { t: "chaine", d, f: i, valeur: s };
  }

  function nombre() {
    const d = i;
    const m = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    m.lastIndex = i;
    const r = m.exec(texte);
    if (!r || r[0].length === 0 || r[0] === "-") throw erreur("syntaxe");
    i += r[0].length;
    const v = Number(r[0]);
    if (!Number.isFinite(v)) {
      i = d;
      throw erreur("non_canonisable");
    }
    return { t: "nombre", d, f: i, valeur: v };
  }

  function valeur(profondeur) {
    blancs();
    if (i >= n) throw erreur("syntaxe");
    const c = texte[i];
    if (c === "{") return objet(profondeur + 1);
    if (c === "[") return tableau(profondeur + 1);
    if (c === '"') return chaine();
    if (c === "-" || (c >= "0" && c <= "9")) return nombre();
    for (const [mot, t, v] of [["true", "vrai", true], ["false", "faux", false], ["null", "nul", null]]) {
      if (texte.startsWith(mot, i)) {
        const d = i;
        i += mot.length;
        return { t, d, f: i, valeur: v };
      }
    }
    throw erreur("syntaxe");
  }

  function objet(profondeur) {
    if (profondeur > profondeurMax) throw erreur("profondeur");
    const d = i;
    i++;
    const membres = [];
    const vues = new Set();
    blancs();
    if (texte[i] === "}") {
      i++;
      return { t: "objet", d, f: i, membres };
    }
    while (true) {
      blancs();
      if (texte[i] !== '"') throw erreur("syntaxe");
      const k = chaine();
      if (vues.has(k.valeur)) {
        i = k.d;
        throw erreur("cle_double");
      }
      vues.add(k.valeur);
      blancs();
      if (texte[i] !== ":") throw erreur("syntaxe");
      i++;
      const v = valeur(profondeur);
      membres.push({ cle: k.valeur, kd: k.d, kf: k.f, v });
      if (membres.length > membresMax) throw erreur("membres");
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "}") {
        i++;
        return { t: "objet", d, f: i, membres };
      }
      throw erreur("syntaxe");
    }
  }

  function tableau(profondeur) {
    if (profondeur > profondeurMax) throw erreur("profondeur");
    const d = i;
    i++;
    const elements = [];
    blancs();
    if (texte[i] === "]") {
      i++;
      return { t: "tableau", d, f: i, elements };
    }
    while (true) {
      elements.push(valeur(profondeur));
      if (elements.length > membresMax) throw erreur("membres");
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "]") {
        i++;
        return { t: "tableau", d, f: i, elements };
      }
      throw erreur("syntaxe");
    }
  }

  const racine = valeur(0);
  blancs();
  if (i !== n) throw erreur("syntaxe");
  return racine;
}

/**
 * Membre d'un nœud objet, ou undefined.
 * @param {object|null|undefined} noeud
 * @param {string} cle
 * @returns {object|undefined}
 */
export function membre(noeud, cle) {
  if (!noeud || noeud.t !== "objet") return undefined;
  return noeud.membres.find((m) => m.cle === cle)?.v;
}

/**
 * Valeur JavaScript d'un nœud (objets à prototype ordinaire ; une clé
 * `__proto__` est une propriété propre).
 * @param {object} noeud
 * @returns {unknown}
 */
export function valeurDe(noeud) {
  switch (noeud.t) {
    case "objet": {
      const o = {};
      for (const m of noeud.membres) Object.defineProperty(o, m.cle, { value: valeurDe(m.v), enumerable: true, writable: true, configurable: true });
      return o;
    }
    case "tableau":
      return noeud.elements.map(valeurDe);
    default:
      return noeud.valeur;
  }
}

/**
 * Texte d'un nœud recopié depuis le texte reçu, blancs non significatifs
 * retirés (EX-4.43) : chaînes (échappements compris) et nombres gardent
 * leurs caractères, l'ordre des membres est conservé (EX-4.20).
 * @param {string} texte
 * @param {object} noeud
 * @returns {string}
 */
export function compacter(texte, noeud) {
  switch (noeud.t) {
    case "objet":
      return "{" + noeud.membres.map((m) => texte.slice(m.kd, m.kf) + ":" + compacter(texte, m.v)).join(",") + "}";
    case "tableau":
      return "[" + noeud.elements.map((e) => compacter(texte, e)).join(",") + "]";
    default:
      return texte.slice(noeud.d, noeud.f);
  }
}

/**
 * Forme décimale exacte normalisée d'un littéral numérique : signe,
 * chiffres significatifs sans zéros de tête ni de queue, exposant.
 * @param {string} s
 * @returns {string}
 */
function decimalExact(s) {
  const r = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(s);
  if (!r) return "?";
  let chiffres = r[2] + (r[3] ?? "");
  let exposant = BigInt(r[4] ?? 0) - BigInt((r[3] ?? "").length);
  chiffres = chiffres.replace(/^0+/, "");
  if (chiffres === "") return "0";
  const queue = chiffres.length - chiffres.replace(/0+$/, "").length;
  chiffres = chiffres.slice(0, chiffres.length - queue);
  exposant += BigInt(queue);
  return `${r[1]}${chiffres}e${exposant}`;
}

/**
 * EX-4.44 : un nombre est admis si sa valeur décimale exacte est celle de sa
 * forme JCS intégral (Number::toString de la double la plus proche).
 * @param {string} litteral
 * @returns {boolean}
 */
export function nombreRepresentable(litteral) {
  const v = Number(litteral);
  if (!Number.isFinite(v)) return false;
  return decimalExact(litteral) === decimalExact(String(v));
}

/**
 * Premier nombre d'un sous-arbre dont la forme JCS intégral n'a pas la
 * valeur décimale reçue (EX-4.44), ou null.
 * @param {string} texte
 * @param {object} noeud
 * @returns {string|null} le littéral fautif
 */
export function premierNombreNonRepresentable(texte, noeud) {
  const pile = [noeud];
  while (pile.length) {
    const x = pile.pop();
    if (x.t === "nombre") {
      const l = texte.slice(x.d, x.f);
      if (!nombreRepresentable(l)) return l;
    } else if (x.t === "objet") {
      for (let k = x.membres.length - 1; k >= 0; k--) pile.push(x.membres[k].v);
    } else if (x.t === "tableau") {
      for (let k = x.elements.length - 1; k >= 0; k--) pile.push(x.elements[k]);
    }
  }
  return null;
}

/**
 * Type JSON d'une valeur pour `data.result_type` (4.4 pas 12).
 * @param {object} noeud
 * @returns {"string"|"number"|"boolean"|"array"|"null"|"object"}
 */
export function typeJson(noeud) {
  return { objet: "object", tableau: "array", chaine: "string", nombre: "number", vrai: "boolean", faux: "boolean", nul: "null" }[noeud.t];
}

/**
 * Remplace, dans un objet compacté, la valeur de certains membres et en
 * ajoute d'autres, sans toucher au reste (ordre et octets conservés).
 * @param {string} texte
 * @param {object} noeud nœud objet
 * @param {{remplacer?: Map<string, string|null>, ajouterEnTete?: [string, string][], ajouterEnFin?: [string, string][]}} o
 *   `remplacer` : clé → texte JSON de la nouvelle valeur (null : membre retiré)
 * @returns {string}
 */
export function recomposerObjet(texte, noeud, o = {}) {
  const parties = [];
  for (const [k, v] of o.ajouterEnTete ?? []) parties.push(JSON.stringify(k) + ":" + v);
  for (const m of noeud.membres) {
    if (o.remplacer?.has(m.cle)) {
      const v = o.remplacer.get(m.cle);
      if (v !== null) parties.push(texte.slice(m.kd, m.kf) + ":" + v);
    } else {
      parties.push(texte.slice(m.kd, m.kf) + ":" + compacter(texte, m.v));
    }
  }
  for (const [k, v] of o.ajouterEnFin ?? []) parties.push(JSON.stringify(k) + ":" + v);
  return "{" + parties.join(",") + "}";
}
