// Bibliothèque du plan de tests (CT-9, spec/CT-9-plan-de-tests.md) :
// lecture des identifiants définis par CT-1 à CT-8 (5.2), des occurrences de
// « CT-9 » dans spec/*.md (0.2), des titres describe/it de test/*.test.js et
// des étapes de .github/workflows/ci.yml (EX-4.2), impression des tables du
// texte depuis le catalogue (EX-4.4, EX-A.4), règles de couverture (a) à (d)
// de 5.1 et EX-5.5, rapport conforme à
// plan-de-tests-v0#/$defs/rapport_couverture (5.4, EX-5.9). Lecture seule :
// rien n'est écrit ici.
//
// Employée par scripts/tests/couverture.mjs (outil de couverture),
// scripts/vecteurs/generer-ct9.mjs (générateur) et
// test/plan-de-tests.test.js.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { definitions } from "../conformite/verifier-renvois.mjs";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Spécifications dont les identifiants sont inventoriés (5.2), dans l'ordre. */
export const SPECIFICATIONS = Object.freeze([
  ["CT-1", "spec/CT-1-evenements-et-formats.md"],
  ["CT-2", "spec/CT-2-enregistreur.md"],
  ["CT-3", "spec/CT-3-approbations.md"],
  ["CT-4", "spec/CT-4-registre.md"],
  ["CT-5", "spec/CT-5-ancrage.md"],
  ["CT-6", "spec/CT-6-verificateur.md"],
  ["CT-7", "spec/CT-7-securite-et-conformite.md"],
  ["CT-8", "spec/CT-8-deploiement-et-exploitation.md"],
]);
/** Fichiers relus pour les occurrences de « CT-9 » (0.2) et leur préfixe dans la clé TC-. */
export const FICHIERS_TC = Object.freeze([...SPECIFICATIONS, ["`spec/README.md`", "spec/README.md"]]);
export const TEXTE_CT9 = "spec/CT-9-plan-de-tests.md";
export const CATALOGUE = "spec/vecteurs/ct-9/catalogue.json";
export const INDEX_PAR_MENACE = "spec/vecteurs/ct-9/index-ta-par-menace.json";
export const MENACES = "spec/vecteurs/ct-7/menaces.json";
export const CI = ".github/workflows/ci.yml";
export const NIVEAUX = Object.freeze(["TU", "TV", "TI", "TE", "TA", "TM", "TR", "TQ"]);
/** Risques acceptés dont la borne chiffrée DOIT nommer ses mesures (EX-10.10). */
export const RA_MESURES_OBLIGATOIRES = new Set(["RA-15", "RA-55", "RA-66"]);
/** Tournures qui annoncent une partie à écrire dans un oracle ou un pas (EX-10.3). */
export const A_ECRIRE_EN_PROSE = /à écrire|à ajouter|restent? à éprouver|à tuer|non écrit/i;
/** Tables imprimées depuis le catalogue (EX-A.4), dans l'ordre du texte. */
export const TABLES = Object.freeze(["TC", "niveaux", "etapes", "NC", "stats", "TU", "TV", "TI", "TE", "TA", "scenarios", "RA", "TM", "TR", "TQ"]);

export const lireJSON = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
export const sha256 = (octets) => crypto.createHash("sha256").update(octets).digest("hex");
export const sha256Fichier = (p) => sha256(fs.readFileSync(p));

// ---------------------------------------------------------------------------
// Inventaire des identifiants (5.2, EX-5.6)
// ---------------------------------------------------------------------------

/**
 * Identifiants définis par le texte d'une spécification : EX- en gras et
 * familles en première cellule de table par definitions() de
 * verifier-renvois.mjs, hors préfixes CT- (tables de relations) et EIP-
 * (faux positif) ; pour CT-8, les lignes `DM-n` en début de ligne, les
 * `**IR-n**` et `**IC-n**` en gras et RB-1 à RB-8 des titres 10.12 à 10.19.
 */
export function identifiantsDefinis(ct, texte) {
  const d = definitions(texte);
  const ids = new Set(d.ex);
  for (const x of d.familles) if (!/^(CT|EIP)-/.test(x)) ids.add(x);
  if (ct === "CT-8") {
    for (const m of texte.matchAll(/^(DM-[0-9]+)\s/gm)) ids.add(m[1]);
    for (const m of texte.matchAll(/^\*\*((?:IR|IC)-[0-9]+)\b/gm)) ids.add(m[1]);
    for (const m of texte.matchAll(/^### 10\.1[2-9] (RB-[1-8])\b/gm)) ids.add(m[1]);
  }
  return ids;
}

/** Inventaire par spécification : { "CT-1": { ids: Set, sections: Set, texte } … }. */
export function inventaire(racine = RACINE) {
  const out = {};
  for (const [ct, f] of SPECIFICATIONS) {
    const texte = fs.readFileSync(path.join(racine, f), "utf8");
    out[ct] = { ids: identifiantsDefinis(ct, texte), sections: definitions(texte).sections, fichier: f, texte };
  }
  return out;
}

/** Préfixe de famille d'un identifiant nu : EX-3.4 → EX-3 ; TR-101 → TR ; AV-T-1 → AV-T. */
export const famille = (id) => id.replace(/[-.][0-9]+$/, "");

// ---------------------------------------------------------------------------
// Occurrences de « CT-9 » (0.2, EX-0.1) : procédé de
// scripts/deploiement/renvois.mjs
// ---------------------------------------------------------------------------

/**
 * Occurrences de « CT-9 » d'un texte : clé « <préfixe> <section> » où la
 * section est le dernier titre de niveau 2 à 4 hors bloc de code (« §s » si le
 * titre commence par un numéro, son texte entre guillemets sinon, « en-tête »
 * avant le premier titre) ; une entrée par occurrence, dans l'ordre des lignes.
 */
export function occurrencesTexte(prefixe, texte) {
  const out = [];
  let section = "« en-tête »";
  let code = false;
  texte.split("\n").forEach((l, i) => {
    if (l.startsWith("```")) code = !code;
    const t = !code && /^#{2,4}\s+(.*)$/.exec(l);
    if (t) {
      const n = /^([0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\.?\s/.exec(t[1]);
      section = n ? `§${n[1]}` : `« ${t[1]} »`;
    }
    const k = (l.match(/CT-9/g) || []).length;
    for (let j = 0; j < k; j++) out.push({ fichier: prefixe, key: `${prefixe} ${section}`, line: i + 1, texte: l, rang: j });
  });
  return out;
}

/** Toutes les occurrences de « CT-9 » de spec/CT-1-*.md à CT-8-*.md puis spec/README.md. */
export function occurrencesCT9(racine = RACINE) {
  return FICHIERS_TC.flatMap(([p, f]) => occurrencesTexte(p, fs.readFileSync(path.join(racine, f), "utf8")));
}

// ---------------------------------------------------------------------------
// Titres des tests (EX-4.2) et étapes de CI
// ---------------------------------------------------------------------------

const DELIMITEURS = new Set(['"', "'", "`"]);
const AVANT_REGEX = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^", null]);

/**
 * Titres des `describe` et `it` d'un fichier de test, par analyse lexicale du
 * source (commentaires, chaînes, gabarits et littéraux d'expression
 * rationnelle ignorés) : le titre est le texte source du premier argument,
 * entre ses délimiteurs, avant toute interpolation (EX-4.2). Rend
 * [{ describes: [titres englobants, du plus externe au plus interne], it }]
 * pour chaque `it`, et `describes` (liste de tous les titres de `describe`).
 * L'appartenance d'un `it` à un `describe` suit les accolades : un `describe`
 * se ferme quand la profondeur d'accolades revient à celle de son appel.
 */
export function titresTests(source) {
  const cas = [];
  const describes = [];
  const pile = []; // { title, depth }
  let depth = 0;
  let i = 0;
  let dernier = null; // dernier caractère significatif (pour distinguer / de regex)
  const n = source.length;
  const lireChaine = (q) => {
    // i sur le délimiteur ouvrant ; rend le texte source entre délimiteurs.
    let j = i + 1;
    let s = "";
    let gabarit = 0; // profondeur ${ } dans un gabarit
    while (j < n) {
      const c = source[j];
      if (c === "\\") { s += c + (source[j + 1] ?? ""); j += 2; continue; }
      if (q === "`" && c === "$" && source[j + 1] === "{") { gabarit++; s += "${"; j += 2; continue; }
      if (q === "`" && gabarit && c === "}") { gabarit--; s += c; j++; continue; }
      if (c === q && !gabarit) break;
      if (q !== "`" && c === "\n") break;
      s += c; j++;
    }
    i = j + 1;
    return s;
  };
  while (i < n) {
    const c = source[i];
    if (c === "/" && source[i + 1] === "/") { while (i < n && source[i] !== "\n") i++; continue; }
    if (c === "/" && source[i + 1] === "*") { const f = source.indexOf("*/", i + 2); i = f === -1 ? n : f + 2; continue; }
    if (DELIMITEURS.has(c)) { lireChaine(c); dernier = '"'; continue; }
    if (c === "/" && (AVANT_REGEX.has(dernier) || dernier === "return")) {
      let j = i + 1; let classe = false;
      while (j < n && source[j] !== "\n") {
        const d = source[j];
        if (d === "\\") { j += 2; continue; }
        if (d === "[") classe = true; else if (d === "]") classe = false;
        else if (d === "/" && !classe) break;
        j++;
      }
      i = j + 1; dernier = "/"; continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i; while (j < n && /[A-Za-z0-9_$]/.test(source[j])) j++;
      const mot = source.slice(i, j);
      const precedent = i > 0 ? source[i - 1] : null;
      if ((mot === "describe" || mot === "it") && precedent !== ".") {
        let k = j; while (k < n && /\s/.test(source[k])) k++;
        if (source[k] === "(") {
          k++; while (k < n && /\s/.test(source[k])) k++;
          if (DELIMITEURS.has(source[k])) {
            i = k;
            const titre = lireChaine(source[k]);
            if (mot === "describe") { describes.push(titre); pile.push({ title: titre, depth }); }
            else cas.push({ describes: pile.map((p) => p.title), it: titre });
            dernier = '"';
            continue;
          }
        }
      }
      i = j; dernier = mot === "return" ? "return" : "a";
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") { depth--; while (pile.length && pile[pile.length - 1].depth >= depth) pile.pop(); }
    if (!/\s/.test(c)) dernier = c;
    i++;
  }
  return { cas, describes };
}

/** Fichiers de test du dépôt (test/*.test.js), chemins relatifs triés. */
export function fichiersTests(racine = RACINE) {
  return fs.readdirSync(path.join(racine, "test")).filter((f) => f.endsWith(".test.js")).sort().map((f) => `test/${f}`);
}

/** Index des titres : Map(fichier relatif → résultat de titresTests). */
export function indexTitres(racine = RACINE) {
  const m = new Map();
  for (const f of fichiersTests(racine)) m.set(f, titresTests(fs.readFileSync(path.join(racine, f), "utf8")));
  return m;
}

/**
 * Vrai si le test cité existe : fichier indexé, `describe` présent (englobant
 * compris) et, si `it` est donné, un `it` de ce titre sous ce `describe`.
 */
export function titreExiste(index, t) {
  const r = index.get(t.file);
  if (!r) return false;
  if (t.it === undefined) return r.describes.includes(t.describe);
  return r.cas.some((c) => c.describes.includes(t.describe) && c.it === t.it);
}

/** Noms des étapes de ci.yml : valeurs exactes des membres `- name:`. */
export function etapesCI(texte) {
  return new Set([...texte.matchAll(/^\s*- name: (.+?)\s*$/gm)].map((m) => m[1]));
}

// ---------------------------------------------------------------------------
// Index des TA- par menace (EX-A.13)
// ---------------------------------------------------------------------------

/** { "MN-n": { test, state, scenarios } } pour chaque TA- à menace, dans l'ordre des TA-. */
export function indexParMenace(catalogue) {
  const index = {};
  const ta = catalogue.tests.filter((t) => t.level === "TA");
  for (const t of ta) {
    if (!t.adversarial?.threat) continue;
    index[t.adversarial.threat] = { test: t.id, state: t.status.state, scenarios: ta.filter((s) => s.adversarial.composition?.includes(t.id)).map((s) => s.id) };
  }
  return index;
}

// ---------------------------------------------------------------------------
// Impression des tables du texte (EX-4.4, EX-A.4)
// ---------------------------------------------------------------------------

const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
const uniq = (a) => a.filter((v, i) => a.indexOf(v) === i);

/** État imprimé d'une entrée (règle fixe d'EX-A.4). */
export function etatImprime(t) {
  const s = t.status;
  if (s.state !== "executable") return `à écrire (étape ${s.phase2_step})`;
  const sources = uniq([...(s.tests ?? []).map((x) => `\`${x.file}\``), ...(s.ci_steps ?? []).map(() => "étape de `ci.yml`")]);
  return `exécutable : ${sources.join(", ")}${s.complement ? ` ; complément à écrire (étape ${s.complement.phase2_step})` : ""}`;
}

/** Identifiants couverts résumés par famille : « CT-6 T- (11) » ; les sections « CT-n §s » ne comptent pas. */
export function resumeCouverts(ids) {
  const f = {};
  for (const id of ids) {
    if (/§/.test(id)) continue;
    const m = /^(CT-[1-8]) (.+)$/.exec(id);
    // Un identifiant sans spécification (EX-5.5) est compté sous « ? » ; la
    // règle (a) le signale comme erreur.
    const k = m ? `${m[1]} ${m[2].replace(/[-.][0-9]+$/, "-")}` : "?";
    f[k] = (f[k] ?? 0) + 1;
  }
  return Object.entries(f).map(([k, n]) => `${k} (${n})`).join(", ");
}

const etatTA = (t) => t.status.state !== "executable" ? `à écrire (étape ${t.status.phase2_step})` : t.status.complement ? `exécutable ; complément à écrire (étape ${t.status.complement.phase2_step})` : "exécutable";
const cibleTM = (m) => m.target === null ? "—" : typeof m.target === "object" ? Object.entries(m.target).map(([k, v]) => `${k} ≤ ${v}`).join(", ") + ` ${m.unit}` : typeof m.target === "number" ? `${m.target} ${m.unit}` : m.target;

/** Comptes par niveau : { TU: { n, exe, ae, c } … } (exécutables, à écrire, avec complément). */
export function statistiques(catalogue) {
  const st = {};
  for (const t of catalogue.tests) {
    st[t.level] ??= { n: 0, exe: 0, ae: 0, c: 0 };
    st[t.level].n++;
    st[t.level][t.status.state === "executable" ? "exe" : "ae"]++;
    if (t.status.complement) st[t.level].c++;
  }
  return st;
}

/**
 * Tables du texte imprimées depuis le catalogue : { nom: [lignes] }, la
 * première ligne étant l'en-tête et la deuxième le séparateur. Les noms sont
 * ceux des marqueurs `<!-- table X -->` du texte (TABLES).
 */
export function imprimerTables(C) {
  const blocs = {};
  const T = (nom, lignes) => { blocs[nom] = lignes; };
  const parNiveau = (n) => C.tests.filter((t) => t.level === n);
  T("TC", ["| Id | Spécification, section (ligne) | Ce qui est délégué à CT-9 | Réponse de CT-9 |", "|---|---|---|---|", ...C.traceability.map((r) => `| ${r.id} | ${esc(r.key)} (l. ${r.line}) | ${esc(r.delegated)} | ${esc(r.response)} |`)]);
  T("niveaux", ["| Niveau | Nom | Objet | Oracle | Section |", "|---|---|---|---|---|", ...C.levels.map((l) => `| ${l.id}- | ${esc(l.name)} | ${esc(l.object)} | ${esc(l.oracle)} | ${l.section} |`)]);
  T("etapes", ["| Étape | Composant livré | Livré quand |", "|---|---|---|", ...C.phase2_steps.map((e) => `| ${e.step} | ${esc(e.component)} | ${esc(e.delivered_when)} |`)]);
  T("NC", ["| Id | Catégorie | Identifiants | Justification |", "|---|---|---|---|", ...C.non_tests.map((n) => `| ${n.id} | \`${n.category}\` | ${esc(resumeCouverts(n.covers))} | ${esc(n.justification)} |`)]);
  const st = statistiques(C);
  const som = (k) => Object.values(st).reduce((a, v) => a + v[k], 0);
  T("stats", ["| Niveau | Entrées | Exécutables | dont avec complément à écrire | À écrire |", "|---|---|---|---|---|", ...Object.entries(st).map(([k, v]) => `| ${k}- | ${v.n} | ${v.exe} | ${v.c} | ${v.ae} |`), `| Total | ${C.tests.length} | ${som("exe")} | ${som("c")} | ${som("ae")} |`]);
  for (const niv of ["TU", "TV", "TI", "TE", "TQ"]) {
    T(niv, ["| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |", "|---|---|---|---|---|", ...parNiveau(niv).map((t) => `| ${t.id} | ${esc(t.title)} | ${esc(resumeCouverts(t.covers))} | ${t.threats.join(", ") || "—"} | ${esc(etatImprime(t))} |`)]);
  }
  T("TA", ["| TA | MN | Composant | État | Réponse retirée (où) | Tests |", "|---|---|---|---|---|---|", ...parNiveau("TA").filter((t) => t.adversarial.threat).map((t) => `| ${t.id} | ${t.adversarial.threat} | \`${t.adversarial.component}\` | ${etatTA(t)} | ${esc(t.adversarial.response_removed.where)} | ${uniq((t.status.tests ?? []).map((x) => `\`${x.file}\``)).join(", ") || "—"} |`)]);
  T("scenarios", ["| Scénario | Titre | Menaces | Tests composés | État |", "|---|---|---|---|---|", ...parNiveau("TA").filter((t) => !t.adversarial.threat).map((t) => `| ${t.id} | ${esc(t.title)} | ${t.threats.join(", ")} | ${t.adversarial.composition.join(", ")} | ${etatTA(t)} |`)]);
  T("RA", ["| RA | Risque | Test | État | Non testé par CT-9 |", "|---|---|---|---|---|", ...C.accepted_risks.map((r) => `| ${r.id} | ${esc(r.name)} | ${r.test} | ${r.test_state} | ${esc(r.not_tested)} |`)]);
  T("TM", ["| Id | Grandeur | Cible | Comparaison | Source | Seuil d'échec | Méthode | État | Mesure |", "|---|---|---|---|---|---|---|---|---|", ...parNiveau("TM").map((t) => { const m = t.measure; return `| ${t.id} | ${esc(m.quantity)} | ${esc(cibleTM(m))} | \`${m.comparison}\` | ${esc(m.source)} | ${esc(m.failure_threshold)} | \`${m.method}\` | ${esc(etatImprime(t))} | — |`; })]);
  T("TR", ["| Id | Épreuve | Participant | Matériel remis | Sections interdites | Grille | Verdict | État |", "|---|---|---|---|---|---|---|---|", ...parNiveau("TR").map((t) => { const r = t.replay; return `| ${t.id} | ${esc(t.title)} | ${esc(r.participant)} | ${esc(r.material.join(" ; "))} | ${esc(r.forbidden_sections.join(" ; "))} | ${r.grid ? `\`${r.grid}\`` : "verdict d'outil"} | ${esc(r.verdict_rule)} | ${esc(etatImprime(t))} |`; })]);
  const ordonne = {};
  for (const nom of TABLES) ordonne[nom] = blocs[nom];
  return ordonne;
}

/** Fichier intermédiaire des tables (EX-A.4) : un bloc par marqueur. */
export function texteTables(blocs) {
  return Object.entries(blocs).map(([nom, lignes]) => `<!-- table ${nom} -->\n${lignes.join("\n")}\n`).join("\n");
}

/** Tables du texte de CT-9 : { nom: [lignes] } lues sous chaque marqueur `<!-- table X -->` (lignes contiguës commençant par `|`). */
export function tablesDuTexte(texte) {
  const lignes = texte.split("\n");
  const out = {};
  lignes.forEach((l, i) => {
    const m = /^<!-- table ([A-Za-z]+) -->$/.exec(l);
    if (!m) return;
    const bloc = [];
    for (let j = i + 1; j < lignes.length && lignes[j].startsWith("|"); j++) bloc.push(lignes[j]);
    out[m[1]] = bloc;
  });
  return out;
}

const cellules = (l) => l.split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim());

/** Comparaison cellule par cellule des tables du texte et du catalogue (EX-4.4) : { compared, differences }. */
export function comparerTables(catalogue, texte) {
  const attendu = imprimerTables(catalogue);
  const lu = tablesDuTexte(texte);
  const differences = [];
  let compared = 0;
  for (const [nom, lignes] of Object.entries(attendu)) {
    const t = lu[nom];
    if (!t) { differences.push(`table ${nom} : marqueur absent du texte`); continue; }
    compared++;
    if (t.length !== lignes.length) differences.push(`table ${nom} : ${t.length} lignes dans le texte, ${lignes.length} dans le catalogue`);
    const n = Math.min(t.length, lignes.length);
    for (let i = 0; i < n; i++) {
      if (t[i] === lignes[i]) continue;
      const a = cellules(t[i]); const b = cellules(lignes[i]);
      if (a.length !== b.length) { differences.push(`table ${nom}, ligne ${i + 1} : ${a.length} cellules dans le texte, ${b.length} dans le catalogue`); continue; }
      a.forEach((c, j) => { if (c !== b[j]) differences.push(`table ${nom}, ligne ${i + 1}, cellule ${j + 1} : texte « ${c} », catalogue « ${b[j]} »`); });
    }
  }
  for (const nom of Object.keys(lu)) if (!attendu[nom]) differences.push(`table ${nom} : marqueur du texte sans table du catalogue`);
  return { compared, differences };
}

/**
 * Chiffres imprimés en 5.5 du texte (EX-5.10), comparés au rapport : totaux,
 * menaces, traçabilité, exécutables et titres, comptes par spécification.
 */
export function comparerChiffres55(texte, rapport) {
  const debut = texte.indexOf("### 5.5 ");
  const fin = texte.indexOf("\n## 6.", debut);
  if (debut === -1 || fin === -1) return ["section 5.5 introuvable dans le texte"];
  const s = texte.slice(debut, fin).replace(/\s+/g, " ");
  const d = [];
  const cmp = (nom, lu, calcule) => { if (lu === undefined) d.push(`5.5 : ${nom} non lu dans le texte`); else if (Number(lu) !== calcule) d.push(`5.5 : ${nom} ${lu} dans le texte, ${calcule} calculé`); };
  const I = rapport.identifiers;
  let m = /([0-9]+) identifiants définis par CT-1 à CT-8 : ([0-9]+) couverts par une entrée, ([0-9]+) par une justification NC-, \*\*([0-9]+) non couverts?\*\*/.exec(s);
  cmp("identifiants", m?.[1], I.total); cmp("couverts par une entrée", m?.[2], I.covered_by_tests); cmp("couverts par une justification", m?.[3], I.covered_by_nc); cmp("non couverts", m?.[4], I.uncovered);
  m = /([0-9]+) menaces sur ([0-9]+) avec un TA-/.exec(s);
  cmp("menaces avec un TA-", m?.[1], rapport.threats.with_ta); cmp("menaces", m?.[2], rapport.threats.total);
  m = /([0-9]+) occurrences de « CT-9 » et ([0-9]+) lignes TC-/.exec(s);
  cmp("occurrences de CT-9", m?.[1], rapport.traceability.occurrences); cmp("lignes TC-", m?.[2], rapport.traceability.rows);
  m = /([0-9]+) entrées exécutables citant ([0-9]+) titres/.exec(s);
  cmp("entrées exécutables", m?.[1], rapport.executable.total); cmp("titres et étapes cités", m?.[2], rapport.executable.titles_checked);
  for (const p of I.per_spec) {
    const r = new RegExp(`${p.spec} ([0-9]+), ([0-9]+), ([0-9]+)`).exec(s);
    cmp(`${p.spec} identifiants`, r?.[1], p.total); cmp(`${p.spec} couverts par une entrée`, r?.[2], p.covered_by_tests); cmp(`${p.spec} couverts par une justification`, r?.[3], p.covered_by_nc);
  }
  return d;
}

// ---------------------------------------------------------------------------
// Couverture (5.1, 5.4, EX-5.9)
// ---------------------------------------------------------------------------

/**
 * Calcule le rapport de couverture (#/$defs/rapport_couverture) sur un dépôt.
 *   racine        racine du dépôt (lecture seule) ;
 *   catalogue     objet catalogue déjà lu (sinon lu à cheminCatalogue) ;
 *   cheminCatalogue  chemin du catalogue (étiquette et condensé dans inputs ;
 *                 par défaut spec/vecteurs/ct-9/catalogue.json) ;
 *   octetsCatalogue  octets du catalogue si le fichier n'est pas celui du dépôt ;
 *   texteCT9      chemin du texte de CT-9 (tables, chiffres de 5.5) ;
 *   index         index TA- par menace à contrôler (objet) ou chemin, ou null ;
 *   date, commande  membres `date` et `tool.command` du rapport ;
 *   strict        les avertissements (sections citées inconnues, menaces
 *                 citées hors TA- inconnues, index absent) deviennent des erreurs.
 * Rend { rapport, avertissements, dependances } (dependances : entrées dont
 * status.depends_on nomme une proposition non adoptée, section 14).
 */
export function calculerCouverture({ racine = RACINE, catalogue = null, cheminCatalogue = CATALOGUE, octetsCatalogue = null, texteCT9 = TEXTE_CT9, index = INDEX_PAR_MENACE, date = null, commande = "node scripts/tests/couverture.mjs --json", strict = false } = {}) {
  const abs = (p) => path.isAbsolute(p) ? p : path.join(racine, p);
  const rel = (p) => { const r = path.relative(racine, abs(p)); return r.startsWith("..") ? abs(p) : r.split(path.sep).join("/"); };
  if (!octetsCatalogue) octetsCatalogue = fs.readFileSync(abs(cheminCatalogue));
  const C = catalogue ?? JSON.parse(octetsCatalogue.toString("utf8"));
  const INV = inventaire(racine);
  const connu = (id) => { const m = /^(CT-[1-8]) (.+)$/.exec(id); return Boolean(m && INV[m[1]] && INV[m[1]].ids.has(m[2])); };
  const sectionConnue = (id) => { const m = /^(CT-[1-8]) §(.+)$/.exec(id); return Boolean(m && INV[m[1]] && INV[m[1]].sections.has(m[2])); };
  const errors = [];
  const avertissements = [];
  const menaces = lireJSON(path.join(racine, MENACES));
  const mnIds = menaces.threats.map((t) => t.id);
  const mnConnu = new Set(mnIds);

  // Unicité et forme des identifiants du catalogue (EX-3.1).
  const vus = new Set();
  for (const t of C.tests) {
    if (vus.has(t.id)) errors.push(`identifiant en double : ${t.id}`);
    vus.add(t.id);
    if (!new RegExp(`^${t.level}-[1-9][0-9]*$`).test(t.id) || !NIVEAUX.includes(t.level)) errors.push(`${t.id} : identifiant ou niveau mal formé`);
  }

  // Règle (a) : identifiants couverts par une entrée (covers ; threats d'un TA-) ou par un NC-.
  const parTest = new Map();
  const parNC = new Map();
  const inconnus = [];
  const ajouter = (m, id, par) => (m.get(id) ?? m.set(id, []).get(id)).push(par);
  const malFormes = [];
  const formeConnue = (id) => /^CT-[1-8] /.test(id);
  for (const t of C.tests) {
    for (const id of t.covers) {
      if (!formeConnue(id)) { malFormes.push(`${t.id} : ${id}`); continue; }
      if (/§/.test(id)) { if (!sectionConnue(id)) avertissements.push(`${t.id} : section citée inconnue ${id}`); continue; }
      if (!connu(id)) inconnus.push(`${t.id} : ${id}`);
      ajouter(parTest, id, t.id);
    }
    if (t.level === "TA") for (const m of t.threats) { const id = `CT-7 ${m}`; if (!connu(id) || !mnConnu.has(m)) inconnus.push(`${t.id} : ${id}`); ajouter(parTest, id, t.id); }
    else for (const m of t.threats) if (!mnConnu.has(m)) avertissements.push(`${t.id} : menace citée inconnue ${m}`);
  }
  for (const nc of C.non_tests) for (const id of nc.covers) { if (!formeConnue(id)) { malFormes.push(`${nc.id} : ${id}`); continue; } if (!connu(id)) inconnus.push(`${nc.id} : ${id}`); ajouter(parNC, id, nc.id); }
  const per_spec = [];
  let total = 0, cbt = 0, cbn = 0, unc = 0;
  for (const [ct] of SPECIFICATIONS) {
    const ids = [...INV[ct].ids].map((x) => `${ct} ${x}`);
    const families = {};
    const uncovered = [];
    let a = 0, b = 0;
    for (const id of ids) {
      if (parTest.has(id)) a++; else if (parNC.has(id)) b++; else uncovered.push(id);
      const p = famille(id.split(" ")[1]);
      families[p] = (families[p] ?? 0) + 1;
    }
    per_spec.push({ spec: ct, total: ids.length, covered_by_tests: a, covered_by_nc: b, uncovered: uncovered.length, uncovered_ids: uncovered.sort(), families });
    total += ids.length; cbt += a; cbn += b; unc += uncovered.length;
  }

  // Règle (b) : menaces, égalités du bloc adversarial avec menaces.json (EX-10.1, EX-10.2), risques acceptés (10.6).
  const TA = C.tests.filter((t) => t.level === "TA");
  // Une menace a « un TA- » par son test TA-n propre (adversarial.threat non nul), pas par un scénario qui la cite.
  const avecTA = new Set(TA.filter((t) => t.adversarial?.threat).flatMap((t) => t.threats));
  const sansTA = mnIds.filter((m) => !avecTA.has(m));
  for (const m of menaces.threats) {
    const ta = TA.filter((t) => t.adversarial?.threat === m.id);
    if (ta.length !== 1) { errors.push(`${m.id} : ${ta.length} TA- de menace ${m.id} (un attendu)`); continue; }
    const t = ta[0];
    const a = t.adversarial;
    if (t.id !== `TA-${m.id.slice(3)}`) errors.push(`${m.id} : ${t.id} au lieu de TA-${m.id.slice(3)}`);
    if (JSON.stringify(t.threats) !== JSON.stringify([m.id])) errors.push(`${t.id} : threats diffère de [${m.id}]`);
    if (a.threat_test_text !== m.test) errors.push(`${t.id} : threat_test_text diffère du membre test de menaces.json`);
    if (JSON.stringify(t.covers) !== JSON.stringify(m.response.refs)) errors.push(`${t.id} : covers diffère de response.refs de menaces.json`);
    if (a.component !== m.component) errors.push(`${t.id} : component diffère de menaces.json`);
    if ((a.accepted_risk ?? null) !== (m.residual?.accepted_risk?.id ?? null)) errors.push(`${t.id} : accepted_risk diffère de menaces.json`);
  }
  for (const t of TA) if (t.adversarial?.threat && !mnConnu.has(t.adversarial.threat)) errors.push(`${t.id} : menace ${t.adversarial.threat} absente de menaces.json`);
  const raMenaces = menaces.threats.filter((t) => t.residual?.accepted_risk).map((t) => ({ ...t.residual.accepted_risk, threat: t.id }));
  if (C.accepted_risks.length !== raMenaces.length) errors.push(`risques acceptés : ${C.accepted_risks.length} dans le catalogue, ${raMenaces.length} dans menaces.json`);
  for (const r of raMenaces) {
    const c = C.accepted_risks.find((x) => x.id === r.id);
    if (!c) { errors.push(`${r.id} : absent du catalogue`); continue; }
    if (c.name !== r.name || c.bound !== r.bound || c.owner !== r.owner || c.threat !== r.threat) errors.push(`${r.id} : nom, borne, porteur ou menace diffèrent de menaces.json`);
  }
  for (const r of C.accepted_risks) {
    const t = C.tests.find((x) => x.id === r.test);
    if (!t || t.adversarial?.threat !== r.threat) errors.push(`${r.id} : test ${r.test} absent ou d'une autre menace`);
    else if (t.status.state !== r.test_state) errors.push(`${r.id} : test_state ${r.test_state} diffère de l'état de ${r.test} (${t.status.state})`);
    // EX-10.10 : une borne chiffrée nomme les TM- qui la mesurent ; chaque TM- cité existe avec une cible comparée et un seuil d'échec.
    for (const id of r.measured_by ?? []) {
      const tm = C.tests.find((x) => x.id === id);
      if (!tm || tm.level !== "TM") errors.push(`${r.id} : measured_by cite ${id}, qui n'est pas une entrée TM-`);
      else if (!tm.measure.failure_threshold || tm.measure.comparison === "aucune_cible") errors.push(`${r.id} : measured_by cite ${id}, sans seuil d'échec comparé`);
    }
    if (RA_MESURES_OBLIGATOIRES.has(r.id) && !(r.measured_by ?? []).length) errors.push(`${r.id} : borne chiffrée sans measured_by (EX-10.10)`);
  }
  // EX-10.3 : un TA- exécutable cite un it de test/adversarial.test.js terminé par « (tué) », une étape de CI, ou porte un complément ;
  // sans complément, son oracle et ses pas n'annoncent rien « à écrire ».
  for (const t of TA) {
    if (t.status.state !== "executable" || t.status.complement) continue;
    const mutant = (t.status.tests ?? []).some((x) => x.file === "test/adversarial.test.js" && /\(tués?\)$/.test(x.it ?? "")) || (t.status.ci_steps ?? []).length > 0 || /oracle sur les? vecteurs?/.test((t.status.tests ?? []).map((x) => x.it ?? "").join(" "));
    if (!mutant) errors.push(`${t.id} : exécutable sans mutant tué dans test/adversarial.test.js, sans étape de CI et sans complément (EX-10.3)`);
    if (A_ECRIRE_EN_PROSE.test([t.oracle, ...t.steps].join(" "))) errors.push(`${t.id} : exécutable sans complément dont l'oracle ou les pas annoncent une partie à écrire (EX-10.3)`);
  }
  // Dépendances à des propositions non adoptées (section 14) : chaque PA- existe dans CT-7, chaque PD- dans la table 17.2 de CT-9.
  const pdCT9 = new Set([...fs.readFileSync(abs(texteCT9), "utf8").matchAll(/^\| (PD-[0-9]+) \|/gm)].map((m) => m[1]));
  const dependances = [];
  for (const t of C.tests) for (const dep of t.status.depends_on ?? []) {
    dependances.push(`${t.id} (${dep})`);
    if (dep.startsWith("PA-") ? !connu(`CT-7 ${dep}`) : !pdCT9.has(dep)) errors.push(`${t.id} : depends_on cite ${dep}, inconnu`);
  }

  // Règle (c) : occurrences de « CT-9 » et lignes TC- (multi-ensembles de clés).
  const occ = occurrencesCT9(racine);
  const multi = (l) => { const m = new Map(); for (const k of l) m.set(k, (m.get(k) ?? 0) + 1); return m; };
  const mo = multi(occ.map((o) => o.key));
  const mt = multi(C.traceability.map((r) => r.key));
  const missing = [], orphans = [];
  for (const [k, n] of mo) if ((mt.get(k) ?? 0) < n) missing.push(`${k} (${n - (mt.get(k) ?? 0)})`);
  for (const [k, n] of mt) if ((mo.get(k) ?? 0) < n) orphans.push(`${k} (${n - (mo.get(k) ?? 0)})`);
  C.traceability.forEach((r, i) => { if (r.id !== `TC-${i + 1}`) errors.push(`${r.id} : attendu TC-${i + 1} (numérotation sans trou)`); });

  // Règle (d) : titres de tests et étapes de CI cités (EX-4.2, EX-5.4).
  const titres = indexTitres(racine);
  const ci = etapesCI(fs.readFileSync(path.join(racine, CI), "utf8"));
  const titles_missing = [];
  let titles_checked = 0;
  for (const t of C.tests) {
    if (t.status.state !== "executable") continue;
    for (const x of t.status.tests ?? []) {
      titles_checked++;
      if (!titreExiste(titres, x)) titles_missing.push({ test_id: t.id, file: x.file, title: x.it === undefined ? x.describe : `${x.describe} | ${x.it}` });
      if (!(t.status.command ?? "").includes(x.file)) errors.push(`${t.id} : command ne lance pas ${x.file} (EX-3.10)`);
    }
    for (const s of t.status.ci_steps ?? []) { titles_checked++; if (!ci.has(s)) titles_missing.push({ test_id: t.id, file: CI, title: s }); }
  }

  // EX-4.4 : tables du texte, chiffres de 5.5.
  const texte = fs.readFileSync(abs(texteCT9), "utf8");
  const tables = comparerTables(C, texte);

  // EX-A.13 : index TA- par menace, s'il est donné.
  if (index) {
    let lu = index;
    if (typeof index === "string") {
      if (fs.existsSync(abs(index))) lu = lireJSON(abs(index));
      else { lu = null; avertissements.push(`index TA- par menace absent : ${rel(index)}`); }
    }
    if (lu) {
      const attendu = indexParMenace(C);
      const membre = lu.index ?? lu;
      if (JSON.stringify(membre) !== JSON.stringify(attendu)) errors.push("index-ta-par-menace.json : membre index différent de celui calculé depuis le catalogue");
    }
  }

  if (malFormes.length) errors.push(...malFormes.map((x) => `identifiant sans spécification : ${x}`));
  if (inconnus.length) errors.push(...inconnus.map((x) => `identifiant cité inconnu : ${x}`));
  if (unc) errors.push(`${unc} identifiant(s) non couvert(s) : ${per_spec.flatMap((p) => p.uncovered_ids).join(", ")}`);
  if (sansTA.length) errors.push(`menaces sans TA- : ${sansTA.join(", ")}`);
  if (missing.length) errors.push(`occurrences de « CT-9 » sans ligne TC- : ${missing.join(" ; ")}`);
  if (orphans.length) errors.push(`lignes TC- sans occurrence : ${orphans.join(" ; ")}`);
  if (titles_missing.length) errors.push(...titles_missing.map((x) => `titre ou étape absent (${x.test_id}) : ${x.file} | ${x.title}`));
  if (tables.differences.length) errors.push(...tables.differences);
  const rapportPartiel = { identifiers: { total, covered_by_tests: cbt, covered_by_nc: cbn, uncovered: unc, per_spec }, threats: { total: mnIds.length, with_ta: mnIds.length - sansTA.length }, traceability: { occurrences: occ.length, rows: C.traceability.length }, executable: { total: C.tests.filter((t) => t.status.state === "executable").length, titles_checked } };
  const chiffres = comparerChiffres55(texte, rapportPartiel);
  tables.differences.push(...chiffres);
  errors.push(...chiffres);
  if (strict) errors.push(...avertissements);

  const rapport = {
    version: 0,
    kind: "rapport-couverture",
    date: date ?? new Date().toISOString().slice(0, 10),
    tool: { name: "scripts/tests/couverture.mjs", command: commande },
    inputs: {
      specs: SPECIFICATIONS.map(([, f]) => ({ file: f, sha256: sha256Fichier(path.join(racine, f)) })),
      catalogue: { file: rel(cheminCatalogue), sha256: sha256(octetsCatalogue) },
      threats: { file: MENACES, sha256: sha256Fichier(path.join(racine, MENACES)) },
      tests: fichiersTests(racine).map((f) => ({ file: f, sha256: sha256Fichier(path.join(racine, f)) })),
    },
    identifiers: { total, covered_by_tests: cbt, covered_by_nc: cbn, uncovered: unc, unknown_cited: inconnus, per_spec },
    threats: { total: mnIds.length, with_ta: mnIds.length - sansTA.length, without_ta: sansTA },
    traceability: { occurrences: occ.length, rows: C.traceability.length, missing, orphans },
    executable: { total: rapportPartiel.executable.total, titles_checked, titles_missing },
    text_tables: tables,
    verdict: errors.length ? "echec" : "reussi",
    errors,
  };
  return { rapport, avertissements, dependances };
}

/** Résumé lisible d'un rapport de couverture (sortie texte de l'outil). */
export function resumeRapport(r) {
  const l = [];
  l.push(`Couverture CT-9 (${r.date}) : verdict ${r.verdict}`);
  l.push(`- règle (a) : ${r.identifiers.total} identifiants définis par CT-1 à CT-8, ${r.identifiers.covered_by_tests} couverts par une entrée, ${r.identifiers.covered_by_nc} par une justification NC-, ${r.identifiers.uncovered} non couvert(s), ${r.identifiers.unknown_cited.length} cité(s) inconnu(s)`);
  for (const p of r.identifiers.per_spec) l.push(`    ${p.spec} : ${p.total} identifiants, ${p.covered_by_tests} par une entrée, ${p.covered_by_nc} par un NC-, ${p.uncovered} non couvert(s)`);
  l.push(`- règle (b) : ${r.threats.with_ta} menaces sur ${r.threats.total} avec un TA-${r.threats.without_ta.length ? ` ; sans : ${r.threats.without_ta.join(", ")}` : ""}`);
  l.push(`- règle (c) : ${r.traceability.occurrences} occurrences de « CT-9 », ${r.traceability.rows} lignes TC-, ${r.traceability.missing.length} manquante(s), ${r.traceability.orphans.length} orpheline(s)`);
  l.push(`- règle (d) : ${r.executable.total} entrées exécutables, ${r.executable.titles_checked} titres ou étapes cités, ${r.executable.titles_missing.length} absent(s)`);
  l.push(`- EX-4.4 : ${r.text_tables.compared} tables du texte comparées au catalogue, ${r.text_tables.differences.length} différence(s)`);
  if (r.errors.length) { l.push(`${r.errors.length} erreur(s) :`); for (const e of r.errors) l.push(`  [ÉCHEC] ${e}`); }
  return l.join("\n");
}
