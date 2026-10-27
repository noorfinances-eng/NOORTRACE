#!/usr/bin/env node
// Vérificateur de renvois de CT-7 (spec/CT-7-securite-et-conformite.md,
// annexe A.10 et A.8) : RV-1 à RV-9 sur le modèle de menace, la table de
// traçabilité et les clés de test ; MX-1 à MX-9 sur la matrice de
// conformité. Il imprime toutes les erreurs et sort avec le code 1 s'il y en
// a une, 0 sinon (EX-A.18, EX-A.13). Lancé par npm test (test/securite.test.js)
// et par l'intégration continue :
//
//   node scripts/conformite/verifier-renvois.mjs
//
// Il ne lit que des fichiers du dépôt : spec/*.md, spec/schemas,
// spec/vecteurs/ct-7/menaces.json, matrice-conformite.json, cles-de-test.json
// et les fichiers de clés des vecteurs (RV-9). Aucune connexion réseau.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as J from "../lib/journal.mjs";
import * as S from "../lib/securite.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

// ---------------------------------------------------------------------------
// Définitions d'une spécification (RV-3, MX-4)
// ---------------------------------------------------------------------------

/**
 * Définitions d'un texte de spécification : `ex` (exigences en gras
 * `**EX-s.k**` ou `**EX-s.k (`), `sections` (numéros des titres de niveau 2
 * à 4, et lettre d'un titre « Annexe X »), `familles` (première cellule `| XX-k |` d'une ligne de table, gras
 * retiré), hors blocs de code.
 */
export function definitions(texte) {
  const ex = new Set([...texte.matchAll(/\*\*(EX-[0-9A-Z]+\.[0-9]+)(?:\*\*| \()/g)].map((m) => m[1]));
  const sections = new Set();
  const familles = new Set();
  let enCode = false;
  for (const l of texte.split("\n")) {
    if (l.startsWith("```")) enCode = !enCode;
    if (enCode) continue;
    const t = /^#{2,4} ((?:[0-9]+|[A-Z])(?:\.[0-9]+)*)[. ]/.exec(l);
    if (t) sections.add(t[1]);
    const a = /^#{2,4} Annexe ([A-Z])\b/.exec(l);
    if (a) sections.add(a[1]);
    const f = /^\| (?:\*\*)?([A-Z]{1,3}(?:-[A-Z]{1,3})?-[0-9]+)(?:\*\*)? \|/.exec(l);
    if (f) familles.add(f[1]);
  }
  return { ex, sections, familles };
}

/** Vrai si le renvoi « CT-n X » existe dans `defs` (définitions par spécification). */
export function renvoiExiste(defs, renvoi) {
  const m = /^(CT-[1-9]) (.+)$/.exec(renvoi);
  if (!m || !defs[m[1]]) return false;
  const d = defs[m[1]];
  const r = m[2];
  if (r.startsWith("EX-")) return d.ex.has(r);
  if (r.startsWith("§")) return d.sections.has(r.slice(1));
  return d.familles.has(r);
}

// ---------------------------------------------------------------------------
// Schémas (RV-1, MX-1)
// ---------------------------------------------------------------------------

/**
 * Copie d'un schéma où chaque `contains: S` est écrit `not: { items: { not:
 * S } }` (équivalent pour un tableau, en draft 2020-12 sans `prefixItems`) :
 * le validateur de journal.mjs n'applique pas `contains`
 * (MOTS_CLES_VALIDATION), que le schéma de la matrice emploie.
 */
export function sansContains(schema) {
  if (Array.isArray(schema)) return schema.map(sansContains);
  if (schema === null || typeof schema !== "object") return schema;
  const out = {};
  for (const [k, v] of Object.entries(schema)) if (k !== "contains") out[k] = sansContains(v);
  if ("contains" in schema) out.allOf = [...(out.allOf ?? []), { not: { items: { not: sansContains(schema.contains) } } }];
  return out;
}

function lireSchema(nom) {
  return JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", `${nom}-v0.schema.json`), "utf8"));
}

// ---------------------------------------------------------------------------
// RV-7 : occurrences de « CT-7 » par spécification et par section
// ---------------------------------------------------------------------------

/** Fichiers comptés par RV-7, dans l'ordre de la table 0.2. */
export const FICHIERS_TRACABILITE = Object.freeze([
  ["CT-1", "CT-1-evenements-et-formats.md"],
  ["CT-2", "CT-2-enregistreur.md"],
  ["CT-3", "CT-3-approbations.md"],
  ["CT-4", "CT-4-registre.md"],
  ["CT-5", "CT-5-ancrage.md"],
  ["CT-6", "CT-6-verificateur.md"],
  ["spec/README.md", "README.md"],
]);

/**
 * Occurrences de « CT-7 » d'un texte, rattachées au dernier titre de niveau 2
 * à 4 qui les précède : « CT-n §s » si le titre commence par un numéro,
 * « CT-n « titre » » sinon, « CT-n « en-tête » » avant le premier titre
 * (`spec/README.md` écrit tel quel). Rend une liste { section, ligne }.
 */
export function occurrencesCT7(nom, texte) {
  const out = [];
  let section = "« en-tête »";
  texte.split("\n").forEach((l, i) => {
    const t = /^#{2,4} (.*)$/.exec(l);
    if (t) {
      const n = /^([0-9]+(?:\.[0-9]+)*)[. ]/.exec(t[1]);
      section = n ? `§${n[1]}` : `« ${t[1]} »`;
    }
    for (const _ of l.matchAll(/CT-7/g)) out.push({ cle: `${nom} ${section}`, ligne: i + 1 });
  });
  return out;
}

// ---------------------------------------------------------------------------
// RV-1 à RV-9
// ---------------------------------------------------------------------------

/**
 * RV-1 à RV-9. `entrees` : { specs (nom court → texte, CT-1 à CT-7), readme,
 * menaces (objet de menaces.json), cles (objet de cles-de-test.json),
 * clesRecalculees }. Rend la liste des erreurs { id, message }.
 */
export function verifierRV(entrees) {
  const { specs, readme, menaces, cles, clesRecalculees } = entrees;
  const erreurs = [];
  const err = (id, message) => erreurs.push({ id, message });
  const defs = Object.fromEntries(Object.entries(specs).map(([k, t]) => [k, definitions(t)]));
  const t7 = specs["CT-7"];
  let tables;
  try {
    tables = S.lireTablesCt7(t7);
  } catch (e) {
    err("RV-5", `tables de CT-7 illisibles : ${e.message}`);
    return erreurs;
  }

  // RV-1 : schéma du modèle de menace.
  for (const e of J.validerSchema(menaces, lireSchema("modele-menace"))) err("RV-1", `menaces.json ${e.chemin || "/"} : ${e.message}`);

  const menacesListe = Array.isArray(menaces?.threats) ? menaces.threats : [];

  // RV-2 : réponse, préfixe du test, numérotation, porteurs.
  const ids = menacesListe.map((t) => t.id);
  const attendus = ids.map((_, i) => `MN-${i + 1}`);
  const numeros = [...ids].sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)));
  if (new Set(ids).size !== ids.length || JSON.stringify(numeros) !== JSON.stringify(attendus)) err("RV-2", "identifiants MN- non uniques ou numérotés avec un trou");
  const ras = new Map();
  for (const t of menacesListe) {
    if (!(t.response?.refs?.length > 0) && !t.residual?.accepted_risk) err("RV-2", `${t.id} : ni renvoi dans la réponse ni risque accepté`);
    if (typeof t.test !== "string" || !t.test.startsWith(S.PREFIXE_TEST_CT9)) err("RV-2", `${t.id} : le test ne commence pas par « ${S.PREFIXE_TEST_CT9.trim()} »`);
    const ar = t.residual?.accepted_risk;
    if (ar) {
      if (!Object.values(S.PORTEURS).includes(ar.owner)) err("RV-2", `${t.id} : porteur ${ar.owner} hors de l'énumération`);
      if (!ras.has(ar.id)) ras.set(ar.id, []);
      ras.get(ar.id).push(t.id);
    }
  }
  const raNum = [...ras.keys()].map((r) => Number(r.slice(3))).sort((a, b) => a - b);
  if (raNum.some((n, i) => n !== i + 1)) err("RV-2", `identifiants RA- numérotés avec un trou : ${raNum.join(", ")}`);
  for (const [ra, mns] of ras) if (mns.length > 1) err("RV-2", `${ra} rattaché à plusieurs menaces : ${mns.join(", ")}`);

  // RV-3 : chaque renvoi existe (menaces.json, colonne « Réponse de CT-7 » de 0.2).
  const controler = (renvoi, ou) => {
    if (!renvoiExiste(defs, renvoi)) err("RV-3", `${ou} : renvoi ${renvoi} introuvable`);
  };
  for (const t of menacesListe) {
    for (const r of t.response?.refs ?? []) controler(r, `${t.id} (réponse)`);
    for (const r of t.detection?.refs ?? []) controler(r, `${t.id} (détection)`);
  }
  for (const c of tables.tracabilite) for (const r of renvoisReponse(c[3] ?? "")) controler(r, `${c[0]} (réponse de CT-7)`);

  // RV-4 : refs = renvois du texte ; aucun EX- sans « CT-n » devant.
  for (const t of menacesListe) {
    for (const k of ["response", "detection"]) {
      const texte = t[k]?.text ?? "";
      if (JSON.stringify(t[k]?.refs) !== JSON.stringify(S.refsDe(texte))) err("RV-4", `${t.id} (${k}) : refs différent des renvois du texte`);
      for (const m of texte.matchAll(/EX-[0-9A-Z]+\.[0-9]+/g)) {
        const avant = texte.slice(0, m.index);
        if (!/CT-[1-9] (?:EX-[0-9A-Z]+\.[0-9]+, )*$/.test(avant) && !/CT-[1-9] $/.test(avant)) err("RV-4", `${t.id} (${k}) : ${m[0]} sans « CT-n » devant`);
      }
    }
  }

  // RV-5 : tables 3.2, 3.4 et 3.5 égales au fichier.
  let reconstruit = null;
  try {
    reconstruit = S.construireMenaces(tables, specs);
  } catch (e) {
    err("RV-5", `tables de CT-7 incohérentes : ${e.message}`);
  }
  if (reconstruit) {
    if (JSON.stringify(reconstruit.components) !== JSON.stringify(menaces?.components)) err("RV-5", "table 3.2 (composants) différente de menaces.json");
    const parId = new Map(menacesListe.map((t) => [t.id, t]));
    for (const t of reconstruit.threats) {
      const f = parId.get(t.id);
      if (!f) err("RV-5", `${t.id} de la table 3.4 absente de menaces.json`);
      else {
        const { sources: s1, ...a } = t;
        const { sources: s2, ...b } = f;
        if (JSON.stringify(a) !== JSON.stringify(b)) err("RV-5", `${t.id} : ligne de la table 3.4 ou 3.5 différente de menaces.json`);
        if (JSON.stringify(s1) !== JSON.stringify(s2)) err("RV-6", `${t.id} : sources différentes de la table de rattachement de 3.3`);
      }
    }
    for (const f of menacesListe) if (!reconstruit.threats.some((t) => t.id === f.id)) err("RV-5", `${f.id} de menaces.json absente de la table 3.4`);
    for (const k of ["version", "kind", "spec", "spec_version", "date"]) if (reconstruit[k] !== menaces?.[k]) err("RV-5", `${k} : ${menaces?.[k]} au lieu de ${reconstruit[k]}`);
  }

  // RV-6 : lignes des tables sources.
  const declarees = new Map(tables.sources.map((c) => [`${c[0]} ${c[1]}`, Number(c[3])]));
  const rattachees = new Map();
  for (const t of menacesListe) {
    for (const s of t.sources ?? []) {
      const k = `${s.spec} ${s.section}`;
      if (!rattachees.has(k)) rattachees.set(k, new Set());
      rattachees.get(k).add(s.row);
    }
  }
  for (const st of menaces?.source_tables ?? []) {
    const k = `${st.spec} ${st.section}`;
    const lignes = specs[st.spec] ? S.lignesSources(specs[st.spec], st.section) : null;
    if (!lignes) {
      err("RV-6", `${k} : section introuvable`);
      continue;
    }
    if (st.rows !== lignes.length) err("RV-6", `${k} : rows ${st.rows}, la table en a ${lignes.length}`);
    if (declarees.get(k) !== lignes.length) err("RV-6", `${k} : la table 3.3 déclare ${declarees.get(k)} lignes, la table source en a ${lignes.length}`);
    for (const l of lignes) if (!rattachees.get(k)?.has(l)) err("RV-6", `${k} : ligne « ${l.slice(0, 80)} » rattachée à aucune menace`);
    for (const r of rattachees.get(k) ?? []) if (!lignes.includes(r)) err("RV-6", `${k} : ligne « ${r.slice(0, 80)} » inexistante dans la table source`);
  }
  for (const k of rattachees.keys()) if (!(menaces?.source_tables ?? []).some((st) => `${st.spec} ${st.section}` === k)) err("RV-6", `${k} : table rattachée absente de source_tables`);

  // RV-7 : traçabilité.
  const occurrences = new Map();
  for (const [nom, f] of FICHIERS_TRACABILITE) {
    const texte = nom === "spec/README.md" ? readme : specs[nom];
    for (const o of occurrencesCT7(nom, texte)) occurrences.set(o.cle, (occurrences.get(o.cle) ?? 0) + 1);
  }
  const lignesTR = new Map();
  for (const c of tables.tracabilite) {
    const m = /^(.*) \(l\. [0-9]+\)$/.exec(c[1]);
    if (!m) {
      err("RV-7", `${c[0]} : colonne « Spécification, section » illisible : ${c[1]}`);
      continue;
    }
    lignesTR.set(m[1], (lignesTR.get(m[1]) ?? 0) + 1);
  }
  for (const k of new Set([...occurrences.keys(), ...lignesTR.keys()])) {
    if ((occurrences.get(k) ?? 0) !== (lignesTR.get(k) ?? 0)) err("RV-7", `${k} : ${occurrences.get(k) ?? 0} occurrence(s) de « CT-7 », ${lignesTR.get(k) ?? 0} ligne(s) dans la table 0.2`);
  }
  const ids7 = tables.tracabilite.map((c) => c[0]);
  if (ids7.some((id, i) => id !== `TR-${i + 1}`)) err("RV-7", "identifiants TR- non numérotés dans l'ordre");
  for (const c of tables.tracabilite) {
    const x = (c[3] ?? "").trim();
    for (const s of sectionsCitees(x)) if (!defs["CT-7"].sections.has(s)) err("RV-7", `${c[0]} : section ${s} de CT-7 introuvable`);
    // Chaque réponse nomme quelque chose (EX-0.1) : un renvoi, une section, un identifiant de CT-7, « Ce document », ou « hors de CT-7 » et son porteur.
    const nomme = renvoisReponse(x).length > 0 || sectionsCitees(x).length > 0 || /^Ce document\b/.test(x) || /hors de CT-7.*(CT-[1-9]|client|exploitant)/.test(x);
    if (!nomme) err("RV-7", `${c[0]} : réponse de CT-7 vide ou sans référence`);
  }

  // RV-8 : risques acceptés de la table 3.5 et de menaces.json.
  const parMenace = new Map(menacesListe.map((t) => [t.id, t]));
  const vus = new Set();
  for (const c of tables.risques) {
    for (const mn of c[4].split(",").map((x) => x.trim())) {
      const t = parMenace.get(mn);
      const ar = t?.residual?.accepted_risk;
      if (!ar || ar.id !== c[0]) err("RV-8", `${c[0]} : sa menace ${mn} ne le porte pas dans menaces.json`);
      else if (ar.name !== c[1] || ar.bound !== c[2] || ar.owner !== S.PORTEURS[c[3]]) err("RV-8", `${c[0]} : nom, borne ou porteur différent dans menaces.json`);
      vus.add(`${c[0]} ${mn}`);
    }
  }
  for (const t of menacesListe) if (t.residual?.accepted_risk && !vus.has(`${t.residual.accepted_risk.id} ${t.id}`)) err("RV-8", `${t.residual.accepted_risk.id} de ${t.id} absent de la table 3.5`);

  // RV-9 : clés de test.
  if (JSON.stringify(cles) !== JSON.stringify(clesRecalculees)) err("RV-9", "cles-de-test.json différent des clés recalculées depuis les vecteurs");
  return erreurs;
}

/** Préfixes des identifiants que CT-7 définit et qu'une cellule de la table 0.2 peut citer sans « CT-7 » devant (RV-3). */
const FAMILLES_CT7 = ["CLE", "CR", "JS", "PA", "MN", "RA", "MC", "CL", "RV", "MX", "TR"];
const RE_IDENT_REPONSE = new RegExp(`(?:CT-([1-9]) )?(EX-[0-9A-Z]+\\.[0-9]+|(?:${FAMILLES_CT7.join("|")})-[0-9]+)\\b`, "g");

/**
 * Renvois de la colonne « Réponse de CT-7 » de la table 0.2 (RV-3) : les
 * renvois « CT-n … » de RV-4, plus chaque EX- ou identifiant d'une famille de
 * CT-7 écrit sans « CT-n » devant, lu dans la spécification de l'énumération
 * qui le précède (« CT-n EX-a, EX-b et EX-c », « CT-n EX-a à EX-b »), dans
 * CT-7 à défaut. Rend la liste des renvois « CT-n X », sans doublon.
 */
export function renvoisReponse(cellule) {
  const texte = cellule.replace(/`[^`]*`/g, " ");
  const out = S.refsDe(texte);
  let courant = null;
  let fin = -1;
  for (const m of texte.matchAll(RE_IDENT_REPONSE)) {
    const sep = fin >= 0 ? texte.slice(fin, m.index) : null;
    if (m[1]) courant = `CT-${m[1]}`;
    else if (!(sep !== null && /^(?:, | et | à |, et )$/.test(sep))) courant = "CT-7";
    fin = m.index + m[0].length;
    const r = `${courant} ${m[2]}`;
    if (!out.includes(r)) out.push(r);
  }
  return out;
}

/**
 * Sections de CT-7 nommées par une cellule « Réponse de CT-7 » (RV-7) :
 * « section(s) N », « annexe X.n », et les numéros « n.m » qui ne sont ni une
 * version, ni la partie d'un renvoi « CT-n … », ni un identifiant (MN-, EX-…).
 */
export function sectionsCitees(cellule) {
  const sans = cellule.replace(S.RE_RENVOI, " ").replace(/CT-[0-9](?: (?:§|EX-)?[0-9A-Z.]+)?/g, " ").replace(/`[^`]*`/g, " ");
  const out = new Set();
  for (const m of sans.matchAll(/[Ss]ections? ([0-9]+)(?: (?:et|à) ([0-9]+))?/g)) {
    out.add(m[1]);
    if (m[2]) out.add(m[2]);
  }
  for (const m of sans.matchAll(/[Aa]nnexe ([A-C](?:\.[0-9]+)?)/g)) out.add(m[1]);
  for (const m of sans.matchAll(/(?<![0-9A-Za-z.\-])([0-9]+\.[0-9]+)(?![0-9])/g)) {
    const avant = sans.slice(0, m.index);
    if (/(?:version|révision) $/.test(avant)) continue;
    out.add(m[1]);
  }
  for (const m of sans.matchAll(/(?<![0-9A-Za-z.\-])([A-C]\.[0-9]+)(?![0-9])/g)) out.add(m[1]);
  return [...out];
}

// ---------------------------------------------------------------------------
// MX-1 à MX-9 : matrice de conformité
// ---------------------------------------------------------------------------

const REL = { repond_a: "répond à", contribue_a: "contribue à", ne_couvre_pas: "ne couvre pas", releve_du_client: "relève du client" };
const MOTS_INTERDITS = ["est conforme", "sont conformes", "garantit la conformité", "certifi", "avis juridique"];

/** Statut d'une ligne selon EX-8.3 : un élément `repond_a` qui porte une condition compte comme `contribue_a`. */
export function statutDerive(elements) {
  const rel = elements.map((x) => (x.relation === "repond_a" && x.condition ? "contribue_a" : x.relation));
  if (!rel.some((r) => r === "repond_a" || r === "contribue_a")) return "hors_perimetre";
  if (rel.includes("repond_a") && !rel.includes("contribue_a") && !rel.includes("ne_couvre_pas")) return "couvert";
  return "partiel";
}

/** Écriture d'une pièce dans la table 8.4 (MX-8). */
export function ecrirePiece(p) {
  if (p.kind === "controle") return `${p.spec} contrôle ${p.ref}`;
  if (p.kind === "partie") return `${p.spec} partie \`${p.ref}\``;
  return `${p.spec} ${p.ref}`;
}

/** Lignes attendues des tables 8.2, 8.4, 8.9 et des clauses (cellules), depuis le fichier (MX-8). */
export function tablesAttenduesMatrice(m) {
  const elements = (r, rels) => r.elements.filter((x) => rels.includes(x.relation)).map((x) => `${x.relation === "repond_a" || x.relation === "contribue_a" ? REL[x.relation] + " : " : ""}${x.element}${x.condition ? ` (${x.condition})` : ""}${x.pieces.length ? " — " + x.pieces.map(ecrirePiece).join(", ") : ""}`).join(" ; ") || "—";
  return {
    textes: m.texts.map((t) => [t.id, t.source, t.title, `\`${t.nature}\``, t.version, t.addressee, `\`${t.applicability.status}\`${t.applicability.from.length ? " : " + t.applicability.from.map((f) => `à partir du ${f.date} (${f.scope})`).join(" ; ") : ""}`, t.applicability.note ?? "—"]),
    lignes: m.rows.map((r) => [r.id, `${r.text}, \`${r.applicability}\``, r.reference, `« ${r.quote} » (${r.facts.join(", ")})`, r.requirement, elements(r, ["repond_a", "contribue_a"]), elements(r, ["ne_couvre_pas"]), elements(r, ["releve_du_client"]), r.status]),
    lacunes: m.gaps.map((g) => [g.id, g.title, g.rows.join(", "), `\`${g.response}\``, g.bound, g.owner, `CT-7 ${g.rule}`]),
    clauses: m.clauses.map((c) => [c.id, c.title, c.serves.join(", ")]),
  };
}

/** Texte de l'annexe C de CT-7 (du titre « ## Annexe C » à la fin ou au titre de niveau 2 suivant). */
function annexeC(t7) {
  const i = t7.indexOf("\n## Annexe C");
  if (i < 0) return null;
  const reste = t7.slice(i + 1);
  const j = reste.indexOf("\n## ", 3);
  return j < 0 ? reste : reste.slice(0, j);
}

/** Faits de la table de l'annexe B de CT-7 (premières cellules, intervalles « X à Y » développés). */
export function faitsAnnexeB(t7) {
  const i = t7.indexOf("\n## Annexe B");
  const j = t7.indexOf("\n## Annexe C");
  const b = t7.slice(i, j < 0 ? undefined : j);
  const faits = new Set();
  for (const l of b.split("\n")) {
    if (!l.startsWith("| R")) continue;
    const c = S.cellules(l)[0];
    for (const m of c.matchAll(/(R[67])-F([0-9]+)(?: à (R[67])-F([0-9]+))?/g)) {
      const fin = m[4] ? Number(m[4]) : Number(m[2]);
      for (let n = Number(m[2]); n <= fin; n++) faits.add(`${m[1]}-F${n}`);
    }
  }
  return faits;
}

/**
 * MX-1 à MX-9 sur une matrice. `specs` : nom court → texte (CT-1 à CT-7) ;
 * `publie` : vrai pour le fichier publié (MX-8 compare alors aux tables de
 * CT-7 ; MX-8 ne s'exécute pas sur les cas invalides, EX-A.14). Rend la
 * liste des erreurs { id, message }.
 */
export function verifierMatrice(m, { specs, publie = true, schema = null }) {
  const erreurs = [];
  const err = (id, message) => erreurs.push({ id, message });
  const t7 = specs["CT-7"];
  const defs = Object.fromEntries(Object.entries(specs).map(([k, t]) => [k, definitions(t)]));

  // MX-1 : schéma.
  for (const e of J.validerSchema(m, sansContains(schema ?? lireSchema("matrice-conformite")))) err("MX-1", `${e.chemin || "/"} : ${e.message}`);
  if (!m || typeof m !== "object" || !Array.isArray(m.texts) || !Array.isArray(m.rows) || !Array.isArray(m.clauses) || !Array.isArray(m.gaps)) return erreurs;

  // MX-2 : identifiants, textes des lignes, champs recopiés.
  const suite = (liste, prefixe, quoi) => {
    const ids = liste.map((x) => x.id);
    if (ids.some((id, i) => id !== `${prefixe}-${i + 1}`)) err("MX-2", `${quoi} : identifiants ${prefixe}- non uniques ou numérotés avec un trou`);
  };
  suite(m.texts, "T", "texts");
  suite(m.rows, "MC", "rows");
  suite(m.clauses, "CL", "clauses");
  suite(m.gaps, "L", "gaps");
  const textes = new Map(m.texts.map((t) => [t.id, t]));
  for (const r of m.rows) {
    const t = textes.get(r.text);
    if (!t) err("MX-2", `${r.id} : texte ${r.text} inexistant`);
    else if (r.source_url !== t.url || r.read_on !== t.read_on || r.applicability !== t.applicability?.status) err("MX-2", `${r.id} : source_url, read_on ou applicability différent de ${t.id}`);
  }

  // MX-3 : statut dérivé.
  for (const r of m.rows) if (Array.isArray(r.elements) && statutDerive(r.elements) !== r.status) err("MX-3", `${r.id} : statut ${r.status}, ${statutDerive(r.elements)} attendu (EX-8.3)`);

  // MX-4 : pièces.
  const t1 = specs["CT-1"];
  const verifsCT1 = definitions(S.texteSection(t1, "11.4") ?? "").familles;
  const parties = new Set(lireSchema("dossier").$defs.part.properties.name.enum);
  const clausesC = new Map([...(annexeC(t7) ?? "").matchAll(/^### (CL-[0-9]+) (.+)$/gm)].map((x) => [x[1], x[2]]));
  for (const r of m.rows) {
    for (const x of r.elements ?? []) {
      for (const p of x.pieces ?? []) {
        const d = defs[p.spec];
        let ok = false;
        if (p.kind === "exigence") ok = !!d && d.ex.has(p.ref);
        else if (p.kind === "verification") ok = p.spec === "CT-1" ? verifsCT1.has(p.ref) : p.spec === "CT-6" ? !!d && d.familles.has(p.ref) : false;
        else if (p.kind === "controle") ok = p.spec === "CT-6" && /^[1-8]$/.test(p.ref);
        else if (p.kind === "partie") ok = p.spec === "CT-1" && parties.has(p.ref);
        else if (p.kind === "section") ok = !!d && p.ref.startsWith("§") && d.sections.has(p.ref.slice(1));
        else if (p.kind === "clause") ok = p.spec === "CT-7" && clausesC.has(p.ref);
        if (!ok) err("MX-4", `${r.id} : pièce ${p.kind} ${p.spec} ${p.ref} introuvable`);
      }
    }
  }

  // MX-5 : clauses.
  for (const c of m.clauses) {
    const serves = m.rows.filter((r) => (r.elements ?? []).some((x) => (x.pieces ?? []).some((p) => p.kind === "clause" && p.ref === c.id))).map((r) => r.id);
    if (JSON.stringify(serves) !== JSON.stringify(c.serves)) err("MX-5", `${c.id} : serves ${c.serves.join(", ")}, ${serves.join(", ") || "aucune ligne"} attendu`);
    if (serves.length === 0) err("MX-5", `${c.id} : clause qui ne sert aucune ligne`);
    if (!clausesC.has(c.id)) err("MX-5", `${c.id} : aucune sous-section dans l'annexe C`);
    else if (clausesC.get(c.id) !== c.title) err("MX-5", `${c.id} : titre différent de l'annexe C`);
  }
  for (const id of clausesC.keys()) if (!m.clauses.some((c) => c.id === id)) err("MX-5", `${id} de l'annexe C absente de clauses`);

  // MX-6 : lacunes.
  const lignes = new Set(m.rows.map((r) => r.id));
  for (const g of m.gaps) {
    for (const r of g.rows ?? []) if (!lignes.has(r)) err("MX-6", `${g.id} : ligne ${r} inexistante`);
    if (!/^EX-8\.[0-9]+$/.test(g.rule ?? "") || !defs["CT-7"].ex.has(g.rule)) err("MX-6", `${g.id} : règle ${g.rule} non définie dans la section 8 de CT-7`);
  }
  for (const r of m.rows) {
    const vise = (r.elements ?? []).some((x) => x.relation === "ne_couvre_pas" && (x.pieces ?? []).some((p) => p.spec === "CT-7"));
    if (vise && !m.gaps.some((g) => (g.rows ?? []).includes(r.id))) err("MX-6", `${r.id} : élément « ne couvre pas » qui cite CT-7, nommé par aucune lacune`);
  }

  // MX-7 : vocabulaire et citations.
  const parcourir = (v, chemin) => {
    if (typeof v === "string") {
      const bas = v.toLowerCase();
      for (const mot of MOTS_INTERDITS) if (bas.includes(mot)) err("MX-7", `${chemin} : « ${mot} »`);
    } else if (Array.isArray(v)) v.forEach((x, i) => parcourir(x, `${chemin}/${i}`));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) if (!(chemin === "" && k === "warning")) parcourir(x, `${chemin}/${k}`);
  };
  parcourir(m, "");
  for (const r of m.rows) {
    if (typeof r.quote !== "string" || r.quote.trim() === "") err("MX-7", `${r.id} : citation vide`);
    else if (r.quote.includes("...")) err("MX-7", `${r.id} : coupe écrite « ... » au lieu de « […] »`);
  }

  // MX-8 : tables de CT-7 égales au fichier (fichier publié seulement).
  if (publie) {
    const att = tablesAttenduesMatrice(m);
    const lues = {
      textes: S.tablesDe(S.texteSection(t7, "8.2") ?? "")[0]?.lignes ?? [],
      lignes: S.tablesDe(S.texteSection(t7, "8.4") ?? "")[0]?.lignes ?? [],
      lacunes: S.tablesDe(S.texteSection(t7, "8.9") ?? "")[0]?.lignes ?? [],
      clauses: S.tablesDe(annexeC(t7) ?? "")[0]?.lignes ?? [],
    };
    const noms = { textes: "8.2", lignes: "8.4", lacunes: "8.9", clauses: "annexe C" };
    for (const k of Object.keys(att)) {
      const a = att[k];
      const l = lues[k].map((c) => c.map((x) => x.replace(/\s+$/, "")));
      if (a.length !== l.length) err("MX-8", `table ${noms[k]} : ${l.length} ligne(s), ${a.length} dans le fichier`);
      for (let i = 0; i < Math.min(a.length, l.length); i++) {
        for (let j = 0; j < Math.max(a[i].length, l[i].length); j++) {
          if (a[i][j] !== l[i][j]) {
            err("MX-8", `table ${noms[k]}, ligne ${l[i][0]}, colonne ${j + 1} différente du fichier`);
            break;
          }
        }
      }
    }
  }

  // MX-9 : applicabilité et faits.
  for (const t of m.texts) {
    if (t.applicability?.status === "pas_encore_applicable") {
      const dates = (t.applicability.from ?? []).map((f) => f.date);
      if (!dates.length) err("MX-9", `${t.id} : pas encore applicable sans date`);
      else if (!dates.every((d) => d > m.date)) err("MX-9", `${t.id} : date d'application non postérieure à ${m.date}`);
    }
  }
  const faits = faitsAnnexeB(t7);
  for (const r of m.rows) for (const f of r.facts ?? []) if (!faits.has(f)) err("MX-9", `${r.id} : fait ${f} absent de l'annexe B`);
  return erreurs;
}

// ---------------------------------------------------------------------------
// Programme
// ---------------------------------------------------------------------------

/**
 * Lit le dépôt de `racine` et exécute RV-1 à RV-9 et MX-1 à MX-9. Rend la
 * liste des erreurs { id, message }.
 */
export function verifierDepot(racine = RACINE) {
  const specs = S.lireSpecifications(path.join(racine, "spec"));
  const readme = fs.readFileSync(path.join(racine, "spec", "README.md"), "utf8");
  const ct7 = path.join(racine, "spec", "vecteurs", "ct-7");
  const lire = (f) => {
    try {
      return J.analyserJSONStrict(fs.readFileSync(path.join(ct7, f)));
    } catch (e) {
      return { __erreur: `${f} : ${e.message}` };
    }
  };
  const menaces = lire("menaces.json");
  const matrice = lire("matrice-conformite.json");
  const cles = lire("cles-de-test.json");
  const erreurs = [];
  if (menaces.__erreur) erreurs.push({ id: "RV-1", message: menaces.__erreur });
  if (matrice.__erreur) erreurs.push({ id: "MX-1", message: matrice.__erreur });
  if (cles.__erreur) erreurs.push({ id: "RV-9", message: cles.__erreur });
  erreurs.push(...verifierRV({ specs, readme, menaces, cles, clesRecalculees: S.clesDeTest(path.join(racine, "spec", "vecteurs")) }));
  erreurs.push(...verifierMatrice(matrice, { specs, publie: true }));
  return erreurs;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  // Aucun argument : la commande vérifie le dépôt entier (EX-A.13). Les cas invalides de A.8 se rejouent par test/conformite.test.js.
  if (process.argv.length > 2) {
    console.error(`argument inattendu : ${process.argv[2]}\nusage : node scripts/conformite/verifier-renvois.mjs   (sans argument : vérifie le dépôt)`);
    process.exit(2);
  }
  const erreurs = verifierDepot();
  for (const e of erreurs) console.log(`[ÉCHEC] ${e.id} : ${e.message}`);
  const ids = [...new Set(erreurs.map((e) => e.id))];
  if (erreurs.length) {
    console.log(`${erreurs.length} erreur(s) : ${ids.join(", ")}`);
    process.exit(1);
  }
  console.log("RV-1 à RV-9 et MX-1 à MX-9 réussies : chaque renvoi existe, chaque menace a une réponse, les tables de CT-7 égalent menaces.json et matrice-conformite.json.");
}
