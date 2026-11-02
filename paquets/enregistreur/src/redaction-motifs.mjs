// Motifs de rédaction (CT-2 EX-10.6, EX-10.23) : sous-ensemble commun
// ECMAScript/RE2 défini par une liste autorisée, règles de structure et de
// taille a) à c), compilation ECMAScript (drapeau `u`, réécriture des seules
// ouvertures `(?P<` reconnues par l'analyse), exécution sous une borne de
// temps. Le même contrôle vaut pour `extract` des gabarits d'effets (EX-7.6).
//
// L'analyse lit le motif point de code par point de code et construit un
// arbre ; tout ce que la liste autorisée ne nomme pas est refusé, avec la
// raison. Aucune normalisation : le motif est exécuté tel qu'il est écrit,
// sensible à la casse, sans drapeau.

import vm from "node:vm";

/** Taille développée maximale d'un motif (EX-10.6 règle c). */
export const TAILLE_MAX_MOTIF = 1000;
/** Borne d'un quantificateur `{n,m}` (EX-10.6 point 5). */
export const BORNE_QUANTIFICATEUR = 1000;
/**
 * Profondeur d'imbrication maximale des groupes : celle que le paquet
 * `regexp` de Go refuse au-delà (« expression nests too deeply ») ; un motif
 * de 1 024 caractères au plus (schéma) ne l'atteint pas.
 */
export const PROFONDEUR_MAX_MOTIF = 1000;

const SYNTAXE = new Set(["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"]);
/** Échappements de caractère admis hors classe et dans une classe (point 2). */
const ECHAPPEMENTS_PONCTUATION = new Set(["\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}", "/"]);
const ECHAPPEMENTS_CONTROLE = { t: 0x09, n: 0x0a, r: 0x0d, f: 0x0c, v: 0x0b };
const ECHAPPEMENTS_CLASSE = new Set(["d", "D", "w", "W"]);
const NOM_GROUPE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const NOMBRE_QUANTIFICATEUR = /^(0|[1-9][0-9]{0,3})$/;

/** Refus d'un motif, avec la raison (jamais une exception non attendue). */
export class MotifRefuse extends Error {
  /** @param {string} raison @param {number} [position] position en points de code */
  constructor(raison, position) {
    super(position === undefined ? raison : `${raison} (position ${position})`);
    this.name = "MotifRefuse";
    this.raison = raison;
    this.position = position ?? null;
  }
}

/**
 * Analyse un motif du sous-ensemble commun. Rend l'arbre et la source
 * ECMAScript (ouvertures `(?P<` reconnues réécrites `(?<`).
 * @param {string} motif
 * @returns {{arbre: object, sourceEcma: string}}
 * @throws {MotifRefuse}
 */
export function analyserMotif(motif) {
  if (typeof motif !== "string" || motif.length === 0) throw new MotifRefuse("motif vide");
  const p = Array.from(motif);
  let i = 0;
  const reecritures = []; // positions (points de code) des « P » à retirer
  const noms = new Set();
  let profondeur = 0;

  const fin = () => i >= p.length;
  const voir = (k = 0) => p[i + k];

  function hexa(c) {
    return c !== undefined && /^[0-9A-Fa-f]$/.test(c);
  }

  /** Échappement après « \ » ; `dansClasse` : point 3. Rend un nœud. */
  function echappement(dansClasse) {
    const debut = i;
    i++; // « \ »
    const c = voir();
    if (c === undefined) throw new MotifRefuse("barre oblique inverse finale", debut);
    if (ECHAPPEMENTS_PONCTUATION.has(c)) {
      i++;
      return { type: "car", code: c.codePointAt(0) };
    }
    if (c === "-" && dansClasse) {
      i++;
      return { type: "car", code: 0x2d };
    }
    if (Object.prototype.hasOwnProperty.call(ECHAPPEMENTS_CONTROLE, c)) {
      i++;
      return { type: "car", code: ECHAPPEMENTS_CONTROLE[c] };
    }
    if (c === "x") {
      if (hexa(voir(1)) && hexa(voir(2))) {
        const code = parseInt(voir(1) + voir(2), 16);
        i += 3;
        return { type: "car", code };
      }
      throw new MotifRefuse("\\x sans deux chiffres hexadécimaux (\\x{…} refusé)", debut);
    }
    if (ECHAPPEMENTS_CLASSE.has(c)) {
      i++;
      return { type: "classe" };
    }
    if ((c === "b" || c === "B") && !dansClasse) {
      i++;
      return { type: "frontiere" };
    }
    throw new MotifRefuse(`échappement \\${c} hors du sous-ensemble commun`, debut);
  }

  /** Classe `[…]` ou `[^…]` (point 3). */
  function classe() {
    const debut = i;
    i++; // « [ »
    if (voir() === "^") i++;
    const elements = [];
    while (!fin() && voir() !== "]") {
      const c = voir();
      if (c === "[") throw new MotifRefuse("« [ » dans une classe (classes POSIX et imbriquées refusées)", i);
      if (c === "\\") {
        const n = echappement(true);
        elements.push(n.type === "car" ? { car: n.code } : { classe: true });
      } else {
        elements.push({ car: c.codePointAt(0), tiret: c === "-" });
        i++;
      }
    }
    if (fin()) throw new MotifRefuse("classe non fermée", debut);
    i++; // « ] »
    if (elements.length === 0) throw new MotifRefuse("classe vide", debut);
    // Intervalles a-z et position du « - » littéral.
    const items = [];
    for (let k = 0; k < elements.length; k++) {
      const e = elements[k];
      if (e.tiret) {
        const premier = k === 0;
        const dernier = k === elements.length - 1;
        if (premier || dernier) {
          items.push({ car: 0x2d });
          continue;
        }
        const g = items.pop();
        const d = elements[k + 1];
        if (!g || g.car === undefined || g.intervalle || d.classe || d.tiret) {
          throw new MotifRefuse("« - » littéral seulement en première ou dernière position, intervalle entre deux caractères", debut);
        }
        if (g.car > d.car) throw new MotifRefuse("intervalle inversé dans une classe", debut);
        items.push({ intervalle: true, de: g.car, a: d.car });
        k++;
        continue;
      }
      items.push(e);
    }
    return { type: "classe" };
  }

  /** Nombre d'un quantificateur borné, sans zéro non significatif (point 5). */
  function nombre() {
    const debut = i;
    let s = "";
    while (!fin() && /^[0-9]$/.test(voir())) s += p[i++];
    if (s === "") return null;
    if (!NOMBRE_QUANTIFICATEUR.test(s)) {
      throw new MotifRefuse(/^0[0-9]/.test(s) ? "zéro non significatif dans un quantificateur" : "répétition au-delà de 1000", debut);
    }
    const n = Number(s);
    if (n > BORNE_QUANTIFICATEUR) throw new MotifRefuse("répétition au-delà de 1000", debut);
    return n;
  }

  /** Quantificateur éventuel après un atome ; null s'il n'y en a pas. */
  function quantificateur() {
    const c = voir();
    let q = null;
    const debut = i;
    if (c === "*" || c === "+" || c === "?") {
      i++;
      q = { min: c === "+" ? 1 : 0, max: c === "?" ? 1 : Infinity, facteur: 1 };
    } else if (c === "{") {
      i++;
      const n = nombre();
      if (n === null) throw new MotifRefuse("« { » littéral ou quantificateur mal formé", debut);
      if (voir() === "}") {
        i++;
        q = { min: n, max: n, facteur: Math.max(n, 1) };
      } else if (voir() === ",") {
        i++;
        if (voir() === "}") {
          i++;
          q = { min: n, max: Infinity, facteur: n + 1 };
        } else {
          const m = nombre();
          if (m === null || voir() !== "}") throw new MotifRefuse("quantificateur mal formé", debut);
          i++;
          if (n > m) throw new MotifRefuse("quantificateur {n,m} avec n > m", debut);
          q = { min: n, max: m, facteur: Math.max(m, 1) };
        }
      } else {
        throw new MotifRefuse("quantificateur mal formé", debut);
      }
    } else {
      return null;
    }
    if (voir() === "?") i++;
    else if (voir() === "+") throw new MotifRefuse("quantificateur possessif", i);
    return q;
  }

  /** Groupe `( … )`, `(?: … )`, `(?<nom> … )`, `(?P<nom> … )` (point 4). */
  function groupe() {
    const debut = i;
    if (++profondeur > PROFONDEUR_MAX_MOTIF) throw new MotifRefuse("groupes imbriqués au-delà de 1000", debut);
    i++; // « ( »
    if (voir() === "?") {
      if (voir(1) === ":") {
        i += 2;
      } else if (voir(1) === "<" && (voir(2) === "=" || voir(2) === "!")) {
        throw new MotifRefuse("recherche arrière", debut);
      } else if (voir(1) === "<" || (voir(1) === "P" && voir(2) === "<")) {
        if (voir(1) === "P") reecritures.push(i + 1);
        i += voir(1) === "P" ? 3 : 2;
        let nom = "";
        while (!fin() && voir() !== ">") nom += p[i++];
        if (fin()) throw new MotifRefuse("nom de groupe non fermé", debut);
        i++;
        if (!NOM_GROUPE.test(nom)) throw new MotifRefuse("nom de groupe hors de ^[A-Za-z][A-Za-z0-9_]{0,31}$", debut);
        if (noms.has(nom)) throw new MotifRefuse("nom de groupe en double", debut);
        noms.add(nom);
      } else if (voir(1) === "=" || voir(1) === "!") {
        throw new MotifRefuse("recherche avant", debut);
      } else {
        throw new MotifRefuse("drapeau en ligne, groupe atomique ou construction (?…) hors du sous-ensemble", debut);
      }
    }
    const corps = alternative();
    if (voir() !== ")") throw new MotifRefuse("groupe non fermé", debut);
    i++;
    profondeur--;
    return { type: "groupe", corps };
  }

  /** Suite d'éléments éventuellement quantifiés. */
  function suite() {
    const elements = [];
    while (!fin() && voir() !== "|" && voir() !== ")") {
      const c = voir();
      const debut = i;
      let atome;
      if (c === "\\") atome = echappement(false);
      else if (c === "[") atome = classe();
      else if (c === "(") atome = groupe();
      else if (c === "^" || c === "$") {
        i++;
        atome = { type: "ancre" };
      } else if (c === ".") throw new MotifRefuse("« . » hors du sous-ensemble (écrire [^\\n])", i);
      else if (c === "*" || c === "+" || c === "?" || c === "{") throw new MotifRefuse("quantificateur sans élément à répéter", i);
      else if (SYNTAXE.has(c)) throw new MotifRefuse(`« ${c} » littéral hors du sous-ensemble`, i);
      else {
        i++;
        atome = { type: "car", code: c.codePointAt(0) };
      }
      const q = quantificateur();
      if (q) {
        if (atome.type === "ancre" || atome.type === "frontiere") throw new MotifRefuse("quantificateur sur une ancre ou une frontière", debut);
        if (atome.type === "groupe") {
          // Règle a) : aucun quantificateur ni alternative dans le corps d'un groupe répété.
          if (contientRepetitionOuAlternative(atome.corps)) throw new MotifRefuse("règle a) : répétition imbriquée ou alternative sous répétition", debut);
          // Règle b) : un groupe quantifié consomme au moins un caractère.
          if (!consomme(atome.corps)) throw new MotifRefuse("règle b) : groupe quantifié qui peut être vide", debut);
        }
        atome = { type: "quantifie", element: atome, ...q };
        if (voir() === "*" || voir() === "+" || voir() === "?" || voir() === "{") throw new MotifRefuse("quantificateur sans élément à répéter", i);
      }
      elements.push(atome);
    }
    return { type: "suite", elements };
  }

  function alternative() {
    const branches = [suite()];
    while (voir() === "|") {
      i++;
      branches.push(suite());
    }
    return branches.length === 1 ? branches[0] : { type: "alternative", branches };
  }

  const arbre = alternative();
  if (!fin()) {
    throw new MotifRefuse(voir() === ")" ? "« ) » sans « ( »" : "motif mal formé", i);
  }
  if (tailleDeveloppee(arbre) > TAILLE_MAX_MOTIF) throw new MotifRefuse("règle c) : taille développée au-delà de 1000");
  const enlever = new Set(reecritures);
  const sourceEcma = p.filter((_, k) => !enlever.has(k)).join("");
  return { arbre, sourceEcma };
}

function contientRepetitionOuAlternative(n) {
  switch (n.type) {
    case "alternative":
    case "quantifie":
      return true;
    case "suite":
      return n.elements.some(contientRepetitionOuAlternative);
    case "groupe":
      return contientRepetitionOuAlternative(n.corps);
    default:
      return false;
  }
}

function consomme(n) {
  switch (n.type) {
    case "car":
    case "classe":
      return true;
    case "suite":
      return n.elements.some(consomme);
    case "groupe":
      return consomme(n.corps);
    case "alternative":
      return n.branches.every(consomme);
    case "quantifie":
      return n.min > 0 && consomme(n.element);
    default:
      return false;
  }
}

/** Taille développée (EX-10.6 règle c). */
export function tailleDeveloppee(n) {
  switch (n.type) {
    case "car":
    case "classe":
    case "ancre":
    case "frontiere":
      return 1;
    case "suite":
      return n.elements.reduce((s, e) => s + tailleDeveloppee(e), 0);
    case "alternative":
      return n.branches.reduce((s, e) => s + tailleDeveloppee(e), 0);
    case "groupe":
      return tailleDeveloppee(n.corps);
    case "quantifie":
      return tailleDeveloppee(n.element) * n.facteur;
    default:
      return 0;
  }
}

/**
 * Contrôle et compile un motif : refus d'EX-10.6 (liste autorisée, règles a
 * à c, zéro non significatif), puis compilation ECMAScript avec le drapeau
 * `u`.
 * @param {string} motif
 * @returns {{admis: true, regexp: RegExp, sourceEcma: string} | {admis: false, raison: string}}
 */
export function controlerMotif(motif) {
  try {
    const { sourceEcma } = analyserMotif(motif);
    let regexp;
    try {
      regexp = new RegExp(sourceEcma, "u");
    } catch (e) {
      return { admis: false, raison: `non compilable : ${e.message}` };
    }
    return { admis: true, regexp, sourceEcma };
  } catch (e) {
    if (e instanceof MotifRefuse) return { admis: false, raison: e.message };
    throw e;
  }
}

// ------------------------------------------------------------ borne de temps

/** Dépassement de la borne de temps d'EX-10.23. */
export class DepassementBudget extends Error {
  /** @param {string} operation `piece`, `extract`, `valeur` ou `jetons` */
  constructor(operation) {
    super(`budget de rédaction dépassé (${operation})`);
    this.name = "DepassementBudget";
    this.operation = operation;
    this.budget = true;
  }
}

const CONTEXTE = vm.createContext(Object.create(null));
const APPEL = new vm.Script("appel()", { filename: "noortrace-redaction-borne" });

/**
 * Exécute `f` sous la borne de temps d'EX-10.23 : une exécution dans un
 * contexte `node:vm` avec l'option `timeout` interrompt une recherche en
 * cours, y compris dans une fonction du contexte principal appelée depuis ce
 * contexte (R10 F-36). La borne est mesurée sur l'horloge monotone du
 * chien de garde de Node.js, depuis le début de l'opération.
 * @template T
 * @param {() => T} f
 * @param {number} budgetMs entier d'au moins 1
 * @param {string} operation pour l'erreur
 * @returns {T}
 * @throws {DepassementBudget}
 */
export function executerSousBorne(f, budgetMs, operation) {
  const borne = Math.max(1, Math.floor(budgetMs));
  const precedent = CONTEXTE.appel;
  CONTEXTE.appel = f;
  try {
    return APPEL.runInContext(CONTEXTE, { timeout: borne, breakOnSigint: false });
  } catch (e) {
    if (e?.code === "ERR_SCRIPT_EXECUTION_TIMEOUT") throw new DepassementBudget(operation);
    throw e;
  } finally {
    CONTEXTE.appel = precedent;
  }
}

/**
 * Première correspondance d'un motif compilé (sémantique leftmost-first),
 * correspondance entière ou texte du premier groupe capturant s'il a
 * participé (EX-7.6 pas 3).
 * @param {RegExp} regexp compilée avec le drapeau `u`
 * @param {string} texte
 * @param {{entiere?: boolean}} [o] `entiere` : la correspondance entière, sans groupe (B.3, `matches`)
 * @returns {string|null}
 */
export function premiereCorrespondance(regexp, texte, o = {}) {
  const re = new RegExp(regexp.source, "u");
  const m = re.exec(texte);
  if (!m) return null;
  if (o.entiere) return m[0];
  return m.length > 1 && m[1] !== undefined ? m[1] : m[0];
}
