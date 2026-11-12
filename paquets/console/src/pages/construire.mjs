// Générateur des écrans et du manifeste des pages de la console (contrat de
// l'étape 6, 3.3 ; CT-3 EX-13.33 point 2, EX-13.35). Produit, de façon
// déterministe (aucune date, aucun aléa, aucun chemin de la machine), les cinq
// écrans `ecrans/<écran>.html` et `manifeste.json` :
//
// - fichiers servis : chaque fichier de `statique/` (feuille de style, modules
//   des écrans, modules communs, libellés), les modules de la bibliothèque
//   atteints depuis les écrans, et la fermeture des importations statiques de
//   `@noble/hashes` et `@noble/curves` depuis la bibliothèque ;
// - carte d'importation, la même dans les cinq écrans, écrite par
//   `JSON.stringify` sans espace : `imports` (trois préfixes) et `integrity`
//   (chaque module JavaScript servi sous `/statique/`, chemins absolus triés,
//   `sha384-`) ;
// - chaque écran : `<meta charset>`, `<meta name="viewport">`, `<title>`, la
//   feuille de style à intégrité, la carte (seul script en ligne), le module
//   d'entrée à intégrité.
//
// `node src/pages/construire.mjs` vérifie que les fichiers produits sont à
// jour (code 1 sinon) ; `--ecrire` les réécrit. Les textes des écrans viennent
// de `statique/libelles/fr.mjs`.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const RACINE_PAQUET = path.resolve(ICI, "..", "..");
const STATIQUE = path.join(ICI, "statique");

/** Les cinq écrans de 3.1, dans l'ordre du manifeste. */
export const ECRANS = Object.freeze(["tickets", "ticket", "inscription", "annuaire", "connexion"]);

/** Préfixes de la carte d'importation (contrat 3.3). */
export const IMPORTS = Object.freeze({
  "noortrace-console/": "/statique/bibliotheque/",
  "@noble/hashes/": "/statique/modules/@noble/hashes/",
  "@noble/curves/": "/statique/modules/@noble/curves/",
});

const TYPES = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
});

const sha384 = (o) => "sha384-" + createHash("sha384").update(o).digest("base64");
const sha256Hex = (o) => "0x" + createHash("sha256").update(o).digest("hex");
const sha256B64 = (o) => "sha256-" + createHash("sha256").update(o).digest("base64");

// Ordre des chaînes par unités UTF-16, sans dépendre de la locale.
const comparer = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Racine d'un paquet `@noble/*`, telle que la bibliothèque et le serveur la résolvent. */
function racineNoble(paquet) {
  return path.dirname(fileURLToPath(import.meta.resolve(`${paquet}/utils.js`)));
}

// Analyse lexicale minimale d'un module ECMAScript : commentaires, chaînes,
// gabarits (et leurs expressions), expressions régulières et jetons
// significatifs, avec la profondeur des accolades. Elle suffit à trouver les
// déclarations `import` et `export … from` de premier niveau ; l'essai des
// pages la confronte à l'analyseur de V8 sur chaque fichier servi.
const MOTS_AVANT_REGEX = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);
const DEBUT_IDENTIFIANT = /[A-Za-z_$#\u0080-\uffff]/;
const SUITE_IDENTIFIANT = /[A-Za-z0-9_$\u0080-\uffff]/;

function jetons(src) {
  const sortie = [];
  const gabarits = [];
  let profondeur = 0;
  let i = 0;
  const n = src.length;
  const dernier = () => sortie[sortie.length - 1];
  const regexAdmise = () => {
    const d = dernier();
    if (d === undefined) return true;
    if (d.type === "nom") return MOTS_AVANT_REGEX.has(d.valeur);
    if (d.type === "ponctuation") return ![")", "]", "}"].includes(d.valeur);
    return false;
  };
  // Lit un gabarit à partir de i (après « ` » ou « } » d'une expression).
  const lireGabarit = () => {
    while (i < n) {
      const c = src[i];
      if (c === "\\") {
        i += 2;
      } else if (c === "`") {
        i += 1;
        sortie.push({ type: "gabarit", profondeur });
        return;
      } else if (c === "$" && src[i + 1] === "{") {
        i += 2;
        gabarits.push(profondeur);
        profondeur += 1;
        return;
      } else {
        i += 1;
      }
    }
    throw new Error("gabarit non fermé");
  };
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < n && src[i] !== "\n") i += 1;
    } else if (c === "/" && src[i + 1] === "*") {
      const fin = src.indexOf("*/", i + 2);
      if (fin < 0) throw new Error("commentaire non fermé");
      i = fin + 2;
    } else if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== c) {
        if (src[j] === "\\") j += 1;
        if (src[j] === "\n") throw new Error("chaîne non fermée");
        j += 1;
      }
      sortie.push({ type: "chaine", valeur: src.slice(i + 1, j), profondeur });
      i = j + 1;
    } else if (c === "`") {
      i += 1;
      lireGabarit();
    } else if (c === "/" && regexAdmise()) {
      let j = i + 1;
      let classe = false;
      while (j < n && (classe || src[j] !== "/")) {
        if (src[j] === "\\") j += 1;
        else if (src[j] === "[") classe = true;
        else if (src[j] === "]") classe = false;
        else if (src[j] === "\n") throw new Error("expression régulière non fermée");
        j += 1;
      }
      j += 1;
      while (j < n && SUITE_IDENTIFIANT.test(src[j])) j += 1;
      sortie.push({ type: "regex", profondeur });
      i = j;
    } else if (/\s/.test(c)) {
      i += 1;
    } else if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1] ?? ""))) {
      let j = i + 1;
      while (j < n && /[0-9A-Za-z_.]/.test(src[j])) j += 1;
      sortie.push({ type: "nombre", profondeur });
      i = j;
    } else if (DEBUT_IDENTIFIANT.test(c)) {
      let j = i + 1;
      while (j < n && SUITE_IDENTIFIANT.test(src[j])) j += 1;
      sortie.push({ type: "nom", valeur: src.slice(i, j), profondeur });
      i = j;
    } else if (c === "}" && gabarits.length > 0 && gabarits[gabarits.length - 1] === profondeur - 1) {
      profondeur -= 1;
      gabarits.pop();
      i += 1;
      lireGabarit();
    } else {
      if (c === "{") profondeur += 1;
      if (c === "}") profondeur -= 1;
      sortie.push({ type: "ponctuation", valeur: c, profondeur: c === "{" ? profondeur - 1 : profondeur });
      i += 1;
    }
  }
  return sortie;
}

/**
 * Les spécificateurs des importations et réexportations statiques d'un
 * module (`import … from "x"`, `import "x"`, `export … from "x"`), dans
 * l'ordre du texte ; ni `import(…)` ni `import.meta`.
 */
export function specificateurs(texte) {
  const t = jetons(texte);
  const sortie = [];
  const est = (k, type, valeur) => t[k] !== undefined && t[k].type === type && (valeur === undefined || t[k].valeur === valeur);
  for (let k = 0; k < t.length; k += 1) {
    if (t[k].profondeur !== 0 || t[k].type !== "nom" || (t[k].valeur !== "import" && t[k].valeur !== "export")) continue;
    if (k > 0 && est(k - 1, "ponctuation", ".")) continue;
    if (t[k].valeur === "import") {
      if (est(k + 1, "ponctuation", "(") || est(k + 1, "ponctuation", ".")) continue;
      if (est(k + 1, "chaine")) {
        sortie.push(t[k + 1].valeur);
        continue;
      }
    } else if (!est(k + 1, "ponctuation", "*") && !est(k + 1, "ponctuation", "{")) {
      continue;
    }
    // Jusqu'à « from "x" », ou la fin de la déclaration.
    let j = k + 1;
    while (j < t.length && !est(j, "ponctuation", ";") && !(est(j, "nom", "from") && est(j + 1, "chaine"))) {
      if (t[k].valeur === "export" && est(j, "ponctuation", "}") && t[j].profondeur === 0 && !est(j + 1, "nom", "from")) break;
      j += 1;
    }
    if (est(j, "nom", "from") && est(j + 1, "chaine")) sortie.push(t[j + 1].valeur);
  }
  return sortie;
}

function lister(rep, base = rep) {
  const sortie = [];
  for (const nom of fs.readdirSync(rep).sort(comparer)) {
    const f = path.join(rep, nom);
    if (fs.statSync(f).isDirectory()) sortie.push(...lister(f, base));
    else sortie.push(path.relative(base, f).split(path.sep).join("/"));
  }
  return sortie;
}

/**
 * Les fichiers servis sous `/statique/` : chemin → `{ paquet, fichier, absolu }`.
 * Lève une erreur sur un spécificateur hors des trois préfixes, un fichier
 * absent, ou un module de `statique/` qu'aucun écran n'atteint.
 */
export function fichiersServis() {
  const noble = { "@noble/hashes": racineNoble("@noble/hashes"), "@noble/curves": racineNoble("@noble/curves") };
  const servis = new Map();
  const ajouterFichier = (chemin, paquet, fichier) => {
    if (servis.has(chemin)) return false;
    const racine = paquet === "@noortrace/console" ? RACINE_PAQUET : noble[paquet];
    const absolu = path.join(racine, ...fichier.split("/"));
    if (!fs.existsSync(absolu)) throw new Error(`fichier introuvable : ${paquet} ${fichier}`);
    const ext = path.extname(fichier);
    if (!Object.hasOwn(TYPES, ext)) throw new Error(`type de fichier non servi : ${fichier}`);
    servis.set(chemin, { paquet, fichier, absolu, type: TYPES[ext] });
    return true;
  };
  // Chemin servi → (paquet, fichier) d'une URL de /statique/.
  const source = (chemin) => {
    for (const p of ["@noble/hashes", "@noble/curves"]) {
      const prefixe = `/statique/modules/${p}/`;
      if (chemin.startsWith(prefixe)) return [p, chemin.slice(prefixe.length)];
    }
    if (chemin.startsWith("/statique/bibliotheque/")) return ["@noortrace/console", `src/bibliotheque/${chemin.slice("/statique/bibliotheque/".length)}`];
    if (chemin.startsWith("/statique/modules/")) throw new Error(`module hors des paquets admis : ${chemin}`);
    return ["@noortrace/console", `src/pages${chemin}`];
  };
  const resoudre = (specificateur, depuis) => {
    for (const [prefixe, cible] of Object.entries(IMPORTS)) {
      if (specificateur.startsWith(prefixe)) return cible + specificateur.slice(prefixe.length);
    }
    if (specificateur.startsWith("./") || specificateur.startsWith("../")) return new URL(specificateur, `https://origine.invalid${depuis}`).pathname;
    throw new Error(`specificateur non admis dans ${depuis} : ${specificateur}`);
  };
  const pile = [];
  const visiter = (chemin) => {
    const { absolu, type } = servis.get(chemin);
    if (type !== TYPES[".mjs"]) return;
    for (const s of specificateurs(fs.readFileSync(absolu, "utf8"))) {
      const cible = resoudre(s, chemin);
      if (!cible.startsWith("/statique/")) throw new Error(`importation hors de /statique/ dans ${chemin} : ${s}`);
      const [paquet, fichier] = source(cible);
      if (ajouterFichier(cible, paquet, fichier)) pile.push(cible);
    }
  };
  // Points de départ : la feuille de style, les modules d'entrée et les
  // tables de libellés (importées selon la langue du document).
  const statiques = lister(STATIQUE);
  const departs = statiques.filter((f) => f === "console.css" || f.startsWith("ecrans/") || f.startsWith("libelles/"));
  for (const f of departs) {
    const chemin = `/statique/${f}`;
    ajouterFichier(chemin, "@noortrace/console", `src/pages${chemin}`);
    pile.push(chemin);
  }
  while (pile.length > 0) visiter(pile.pop());
  const nonAtteints = statiques.filter((f) => !servis.has(`/statique/${f}`));
  if (nonAtteints.length > 0) throw new Error(`fichiers de statique/ qu'aucun écran n'atteint : ${nonAtteints.join(", ")}`);
  return new Map([...servis.entries()].sort((a, b) => comparer(a[0], b[0])));
}

const echapper = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * Construit les fichiers produits.
 * @returns {Promise<{fichiers: Map<string, Buffer>, manifeste: object, carte: string, servis: Map<string, object>}>}
 *   `fichiers` : chemin relatif à `src/pages/` → octets
 */
export async function construire() {
  const libelles = (await import(pathToFileURL(path.join(STATIQUE, "libelles", "fr.mjs")).href)).default;
  const servis = fichiersServis();
  const octets = new Map([...servis.entries()].map(([chemin, f]) => [chemin, fs.readFileSync(f.absolu)]));
  const integrity = {};
  for (const [chemin, f] of servis) if (f.type === TYPES[".mjs"]) integrity[chemin] = sha384(octets.get(chemin));
  const carte = JSON.stringify({ imports: { ...IMPORTS }, integrity });
  const feuille = sha384(octets.get("/statique/console.css"));
  const fichiers = new Map();
  const ecrans = {};
  for (const e of ECRANS) {
    const entree = `/statique/ecrans/${e}.mjs`;
    if (!Object.hasOwn(integrity, entree)) throw new Error(`module d'entrée absent : ${entree}`);
    const html = [
      "<!doctype html>",
      '<html lang="fr">',
      "<head>",
      '<meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      `<title>${echapper(libelles[`ecran.${e}.titre`])}</title>`,
      `<link rel="stylesheet" href="/statique/console.css" integrity="${feuille}">`,
      `<script type="importmap">${carte}</script>`,
      `<script type="module" src="${entree}" integrity="${integrity[entree]}"></script>`,
      "</head>",
      "<body>",
      '<div id="principal"></div>',
      `<noscript><p>${echapper(libelles["ecran.sans_script"])}</p></noscript>`,
      "</body>",
      "</html>",
      "",
    ].join("\n");
    const b = Buffer.from(html, "utf8");
    const fichier = `ecrans/${e}.html`;
    fichiers.set(fichier, b);
    ecrans[e] = { fichier, sha384: sha384(b), sha256: sha256Hex(b) };
  }
  const manifeste = {
    version: 0,
    carte,
    carte_sha256: sha256B64(Buffer.from(carte, "utf8")),
    ecrans,
    statiques: [...servis.entries()].map(([chemin, f]) => ({
      chemin,
      source: { paquet: f.paquet, fichier: f.fichier },
      type: f.type,
      sha384: sha384(octets.get(chemin)),
      sha256: sha256Hex(octets.get(chemin)),
      octets: octets.get(chemin).length,
    })),
  };
  fichiers.set("manifeste.json", Buffer.from(JSON.stringify(manifeste, null, 2) + "\n", "utf8"));
  return { fichiers, manifeste, carte, servis };
}

/**
 * Ligne de commande : vérifie (code 1 si un fichier produit est périmé) ou,
 * avec `--ecrire`, réécrit. Rend le code de sortie.
 * @param {string[]} argv
 */
export async function principal(argv) {
  const ecrire = argv.length === 1 && argv[0] === "--ecrire";
  if (argv.length > 1 || (argv.length === 1 && !ecrire)) {
    process.stderr.write("usage : node src/pages/construire.mjs [--ecrire]\n");
    return 2;
  }
  let produit;
  try {
    produit = await construire();
  } catch (e) {
    process.stderr.write(`construire : ${e.message}\n`);
    return 1;
  }
  if (ecrire) {
    fs.mkdirSync(path.join(ICI, "ecrans"), { recursive: true });
    for (const [rel, b] of produit.fichiers) fs.writeFileSync(path.join(ICI, ...rel.split("/")), b);
    process.stdout.write(`construire : ${produit.fichiers.size} fichiers écrits\n`);
    return 0;
  }
  const perimes = [];
  for (const [rel, b] of produit.fichiers) {
    const f = path.join(ICI, ...rel.split("/"));
    if (!fs.existsSync(f) || !fs.readFileSync(f).equals(b)) perimes.push(rel);
  }
  const produits = new Set(produit.fichiers.keys());
  for (const f of fs.existsSync(path.join(ICI, "ecrans")) ? fs.readdirSync(path.join(ICI, "ecrans")).sort(comparer) : []) {
    if (!produits.has(`ecrans/${f}`)) perimes.push(`ecrans/${f} (en trop)`);
  }
  if (perimes.length > 0) {
    process.stderr.write(`construire : fichiers périmés (node src/pages/construire.mjs --ecrire) : ${perimes.join(", ")}\n`);
    return 1;
  }
  process.stdout.write("construire : fichiers à jour\n");
  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await principal(process.argv.slice(2));
}
