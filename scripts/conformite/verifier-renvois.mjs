#!/usr/bin/env node
// Vérificateur de renvois de CT-7 (spec/CT-7-securite-et-conformite.md,
// annexe A.10 et A.8) : RV-1 à RV-9 sur le modèle de menace, la table de
// traçabilité (numéros de ligne compris, RV-7), les renvois par numéro de
// ligne hors des tables de traçabilité (RV-3, sur leur ancre) et les clés de
// test ; MX-1 à MX-9 sur la matrice de
// conformité. Il imprime toutes les erreurs et sort avec le code 1 s'il y en
// a une, 0 sinon (EX-A.18, EX-A.13). Lancé par npm test (test/securite.test.js)
// et par l'intégration continue :
//
//   node scripts/conformite/verifier-renvois.mjs
//
// Il ne lit que des fichiers du dépôt : spec/*.md (CT-1 à CT-9 et README), spec/schemas,
// spec/vecteurs/ct-7/menaces.json, matrice-conformite.json, cles-de-test.json
// et les fichiers de clés des vecteurs (RV-9). Aucune connexion réseau.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
 * clesRecalculees, textes? (nom court → texte, clés de FICHIERS_CITATIONS :
 * renvois par numéro de ligne de RV-3, lus seulement s'il est donné) }. Rend
 * la liste des erreurs { id, message }.
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
  // RV-3, complément du 2026-11-17 : renvois par numéro de ligne hors des tables de traçabilité, sur leur ancre.
  if (entrees.textes) for (const m of verifierCitationsLignes(entrees.textes)) err("RV-3", m);

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
  const lignesOcc = new Map();
  for (const [nom, f] of FICHIERS_TRACABILITE) {
    const texte = nom === "spec/README.md" ? readme : specs[nom];
    for (const o of occurrencesCT7(nom, texte)) {
      occurrences.set(o.cle, (occurrences.get(o.cle) ?? 0) + 1);
      (lignesOcc.get(o.cle) ?? lignesOcc.set(o.cle, []).get(o.cle)).push(o.ligne);
    }
  }
  const lignesTR = new Map();
  const lignesCitees = new Map();
  for (const c of tables.tracabilite) {
    const m = /^(.*) \(l\. ([0-9]+)\)$/.exec(c[1]);
    if (!m) {
      err("RV-7", `${c[0]} : colonne « Spécification, section » illisible : ${c[1]}`);
      continue;
    }
    lignesTR.set(m[1], (lignesTR.get(m[1]) ?? 0) + 1);
    (lignesCitees.get(m[1]) ?? lignesCitees.set(m[1], []).get(m[1])).push({ id: c[0], ligne: Number(m[2]) });
  }
  for (const k of new Set([...occurrences.keys(), ...lignesTR.keys()])) {
    if ((occurrences.get(k) ?? 0) !== (lignesTR.get(k) ?? 0)) err("RV-7", `${k} : ${occurrences.get(k) ?? 0} occurrence(s) de « CT-7 », ${lignesTR.get(k) ?? 0} ligne(s) dans la table 0.2`);
    else {
      // Complément du 2026-11-17 : les numéros de ligne sont, en multiensemble, ceux des occurrences du texte courant.
      const attendues = [...(lignesOcc.get(k) ?? [])].sort((a, b) => a - b);
      const citees = [...(lignesCitees.get(k) ?? [])].sort((a, b) => a.ligne - b.ligne);
      if (citees.some((c, i) => c.ligne !== attendues[i])) err("RV-7", `${k} : ${citees.map((c) => `${c.id} (l. ${c.ligne})`).join(", ")} dans la table 0.2, occurrences de « CT-7 » aux lignes ${attendues.join(", ")} (citation décalée : recoller la table)`);
    }
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

// ---------------------------------------------------------------------------
// RV-3, complément du 2026-11-17 : renvois par numéro de ligne (« l. N »)
// ---------------------------------------------------------------------------

/** Spécifications lues pour les renvois par numéro de ligne : citantes et citées. */
export const FICHIERS_CITATIONS = Object.freeze({
  ...S.FICHIERS_SPEC,
  "CT-8": "CT-8-deploiement-et-exploitation.md",
  "CT-9": "CT-9-plan-de-tests.md",
  "spec/README.md": "README.md",
});

/**
 * Renvois par numéro de ligne à un fichier de `spec/` d'un texte, hors des
 * lignes des tables de traçabilité (`| TR-n |`, `| TC-n |`, contrôlées par
 * RV-7 et par leurs outils) : « `spec/CT-n-….md` l. … », « `CT-n` l. … »,
 * « CT-n l. … », « CT-n §s l. … », « CT-n §s, …, l. … », chacun d'une ou de
 * plusieurs plages `N` ou `N-M` séparées par des virgules ; les blancs
 * comprennent les fins de ligne. Rend [{ ligne, vers, plages: [[a, b]], texte }].
 */
export function citationsLignes(texte) {
  const rx = /(?:`spec\/(CT-[1-9])-[a-z-]+\.md`|`(CT-[1-9])`|(?<![`\/])(CT-[1-9]))(?:\s+§[0-9A-Z.]+)?(?:,\s+[^,;|()`\n]{1,20}?)*?,?\s+l\.\s+([0-9]+(?:-[0-9]+)?(?:,\s+[0-9]+(?:-[0-9]+)?)*)/g;
  const lignes = texte.split("\n");
  const out = [];
  for (const m of texte.matchAll(rx)) {
    const ligne = texte.slice(0, m.index).split("\n").length;
    if (/^\| (?:TR|TC)-[0-9]+ \|/.test(lignes[ligne - 1])) continue;
    const plages = m[4].split(/,\s+/).map((p) => {
      const [a, b] = p.split("-").map(Number);
      return [a, b ?? a];
    });
    out.push({ ligne, vers: m[1] ?? m[2] ?? m[3], plages, texte: m[0].replace(/\s+/g, " ") });
  }
  return out;
}

/**
 * Ancres des renvois par numéro de ligne : pour un couple (spécification qui
 * cite, spécification citée), le début de la première (`debut`) et de la
 * dernière (`fin`) ligne d'une plage citée, espaces de tête compris. Une
 * plage désigne son ancre quand ses deux lignes commencent par ces textes.
 * Une plage sans ancre (citation décalée, ou nouvelle) et une ancre qu'aucune
 * plage ne désigne échouent. Texte de chaque ancre établi le 2026-11-17 sur
 * le passage lu à la date de lecture de la citation.
 */
export const ANCRES_LIGNES = Object.freeze([
  { de: "CT-4", vers: "CT-1", debut: "5. L'inscription de la nouvelle clé dans `RecorderRegist", fin: "   registre relève du contrôle 8 (CT-6 §11)." },
  { de: "CT-4", vers: "CT-1", debut: "Le contrôle de ces valeurs contre le registre est le con", fin: "Le contrôle de ces valeurs contre le registre est le con" },
  { de: "CT-4", vers: "CT-1", debut: "- **L'ancre et le registre.** Sans le contrôle 8 (CT-6),", fin: "- **L'ancre et le registre.** Sans le contrôle 8 (CT-6)," },
  { de: "CT-8", vers: "CT-2", debut: "### 17.1 Santé", fin: "| `noortrace_build_info` | jauge (1) | `version`, `proto" },
  { de: "CT-8", vers: "CT-2", debut: "    \"socket\": \"/run/noortrace/mcp.sock\",", fin: "      \"path\": \"/var/log/noortrace/exploitation.ndjson\"," },
  { de: "CT-8", vers: "CT-2", debut: "| Grandeur | Définition | Cible | Condition |", fin: "**EX-16.1** Les cibles de latence s'entendent **hors tem" },
  { de: "CT-8", vers: "CT-3", debut: "### 12.1 Transport et authentification", fin: "**EX-12.3** Le service NE DOIT PAS recevoir la clé du jo" },
  { de: "CT-8", vers: "CT-3", debut: "**EX-12.12** Le service DEVRAIT exposer `GET <base>/v0/e", fin: "`ready` est faux tant qu'EX-8.3 n'est pas rempli ; révis" },
  { de: "CT-8", vers: "CT-5", debut: "### 8.9 Supervision", fin: "Aucune ligne ne porte un secret, un jeton ni une pièce." },
  { de: "CT-8", vers: "CT-4", debut: "### 10.4 Ports et volumes", fin: "`chain/README.md`, « Ports »." },
  { de: "CT-8", vers: "CT-4", debut: "`NOOR_HTTP_AUTH_TOKEN` (`chain/README.md`, point 5) ; il", fin: "signés » hors de la base) reçoivent les propositions cor" },
  { de: "CT-8", vers: "CT-4", debut: "### 10.3 Relais RPC chez un client", fin: "travers lui." },
  { de: "CT-8", vers: "CT-4", debut: "| Emplacement | Avant | Attendu | État |", fin: "| `chain/README.md`, « Ce qui change pour un réseau prod" },
  { de: "CT-8", vers: "CT-2", debut: "| Point d'observation | Point d'accroche d'un cadre qui", fin: "| Point d'observation | Point d'accroche d'un cadre qui" },
  { de: "CT-8", vers: "CT-2", debut: "règle 4). Si `ts lu < ts précédent − clock.max_backstep_", fin: "`clock.warn_skew_ms` (défaut 1 000). `ts` reste déclarat" },
  { de: "CT-8", vers: "CT-5", debut: "| `rfc3161.freshness` | `max_response_delay_s`, `clock_t", fin: "| `queue` | `path`, `max_pending`, `anchor_pending_alert" },
  { de: "CT-8", vers: "CT-5", debut: "    \"freshness\": { \"max_response_delay_s\": 60, \"clock_to", fin: "  \"registry\": { \"checkpoints\": \"nouveaux_evenements\", \"s" },
  { de: "CT-9", vers: "CT-4", debut: "garde d'admission et données des validateurs (EX-10.8, E", fin: "spécification, a été réussie les deux fois ; leurs remar" },
  { de: "CT-9", vers: "CT-7", debut: "### 3.5 Risques acceptés", fin: "| RA-81 | Outil de condensation non recoupé | Limité aux" },
  { de: "CT-9", vers: "CT-6", debut: "Le binaire est construit en phase 2 (étape 2 du plan) ;", fin: "Le binaire est construit en phase 2 (étape 2 du plan) ;" },
  { de: "CT-9", vers: "CT-3", debut: "### A.5 Épreuve d'acceptation", fin: "sont pas des vecteurs et ne sont pas publiées par le gén" },
  { de: "CT-9", vers: "CT-3", debut: "**EX-A.17** **Épreuve de lecture de la console.** Critèr", fin: "avec le contenu exact de `consulter`, de la requête `per" },
  { de: "CT-9", vers: "CT-4", debut: "### 7.12 Épreuve d'acceptation", fin: "ce poste et qu'elle reçoit avec le répertoire sinon (ni" },
  { de: "CT-9", vers: "CT-5", debut: "| CT-9 | Les identifiants EX- et AN-, les vecteurs `spec", fin: "| CT-9 | Les identifiants EX- et AN-, les vecteurs `spec" },
  { de: "CT-9", vers: "CT-5", debut: "| CT-9 | — | tests attachés aux EX- et AN- des deux part", fin: "| CT-9 | — | tests attachés aux EX- et AN- des deux part" },
  { de: "CT-9", vers: "CT-6", debut: "## 7. Ce que le vérificateur prouve et ne prouve pas", fin: "### 7.1 Ce qu'il faut lire dans un rapport" },
  { de: "CT-9", vers: "CT-6", debut: "### 7.9 Point de contrôle du journal : ce que le verdict", fin: "  (`keccak256(org_id ‖ journal_id ‖ checkpoint_hash)`) a" },
  { de: "CT-9", vers: "CT-7", debut: "## 9. Épreuves à l'aveugle", fin: "conformité » échoue, quels que soient ses autres élément" },
  { de: "CT-9", vers: "CT-7", debut: "**EX-A.29** `ct-7/acceptation-securite/consigne.md` reme", fin: "commencent par « Vérificateur : » et « Répertoire : »." },
  { de: "CT-9", vers: "CT-8", debut: "Trois épreuves, conduites par CT-9 à la porte 2, éprouve", fin: "EX-12.14), échoue quels que soient ses autres éléments." },
  { de: "CT-9", vers: "CT-2", debut: "## 16. Objectifs de performance et de capacité, méthode", fin: "rapport n'est pas une pièce et n'entre pas dans la chaîn" },
  { de: "CT-9", vers: "CT-5", debut: "### 3.6 Exigences de niveau de preuve, mesurables", fin: "| P-6 | Les points, leurs ancres (jetons, preuves, enreg" },
  { de: "CT-9", vers: "CT-5", debut: "### 7.2 Exigences d'exploitation, mesurables", fin: "politique `1.3.6.1.4.1.99999.1.1`, `scripts/vecteurs/ct6" },
  { de: "CT-9", vers: "CT-5", debut: "- **Les mesures en charge** du planificateur (débit de p", fin: "  0.6 (EX-8.5, règles 5 et 7) ; la taille sous ces règle" },
  { de: "CT-9", vers: "CT-8", debut: "## 7. Installation rapide", fin: "la porte 2, pas par pas, et publie chaque durée mesurée," },
  { de: "CT-9", vers: "CT-8", debut: "### 8.1 Durée et ce que CT-9 mesure", fin: "vérificateur sur le premier dossier (IC-15)." },
  { de: "CT-9", vers: "CT-8", debut: "| Pas | Objet | Budget (cible) | Exigences reprises |", fin: "| Total | | 450 min | |" },
  { de: "CT-9", vers: "CT-8", debut: "(CT-9) » ; l'exploitant PEUT remplacer un coefficient pa", fin: "| `f_pic`, `b_o`, `b_acq`, `b_crl`, `n_crl`, `m_0` | — |" },
  { de: "CT-9", vers: "CT-8", debut: "écoute (R8 NV-5). L'enregistreur, le service d'approbati", fin: "« à mesurer (CT-9, porte 2) »." },
  { de: "CT-9", vers: "CT-8", debut: "### 11.3 Objectifs de reprise", fin: "### 11.4 Reprise qui garde la continuité de la chaîne" },
  { de: "CT-9", vers: "CT-8", debut: "**EX-12.5** Le temps que l'enregistreur ajoute à un appe", fin: "relayer l'appel sans attendre, naît d'une erreur de `wri" },
  { de: "CT-9", vers: "CT-8", debut: "### 13.1 Exigences de parité, mesurables", fin: "   instructions comprise ; à mesurer (CT-9, porte 2)." },
]);

/**
 * Contrôle des renvois par numéro de ligne sur `textes` (nom court → texte,
 * clés de FICHIERS_CITATIONS) ; une ancre dont l'une des deux spécifications
 * manque n'est pas lue. Rend la liste des messages d'erreur.
 */
export function verifierCitationsLignes(textes) {
  const erreurs = [];
  const lignes = Object.fromEntries(Object.entries(textes).map(([k, t]) => [k, t.split("\n")]));
  const servies = new Set();
  for (const [de, texte] of Object.entries(textes)) {
    for (const c of citationsLignes(texte)) {
      const cible = lignes[c.vers];
      if (!cible) continue;
      for (const [a, b] of c.plages) {
        const k = ANCRES_LIGNES.findIndex((x) => x.de === de && x.vers === c.vers && a <= b && b <= cible.length && cible[a - 1].startsWith(x.debut) && cible[b - 1].startsWith(x.fin));
        if (k === -1) erreurs.push(`${de} l. ${c.ligne} : « ${c.texte} » : plage ${a === b ? a : `${a}-${b}`} de ${c.vers} sans ancre (citation décalée : établir la ligne d'après le texte cité, ou ancre à ajouter) ; l. ${a} : « ${(cible[a - 1] ?? "").slice(0, 60)} »`);
        else servies.add(k);
      }
    }
  }
  ANCRES_LIGNES.forEach((x, k) => {
    if (!servies.has(k) && textes[x.de] !== undefined && textes[x.vers] !== undefined) erreurs.push(`ancre ${x.de} → ${x.vers} « ${x.debut.slice(0, 60)} » désignée par aucune citation (citation décalée ou retirée)`);
  });
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
  const textes = Object.fromEntries(Object.entries(FICHIERS_CITATIONS).map(([k, f]) => [k, fs.readFileSync(path.join(racine, "spec", f), "utf8")]));
  erreurs.push(...verifierRV({ specs, readme, menaces, cles, clesRecalculees: S.clesDeTest(path.join(racine, "spec", "vecteurs")), textes }));
  erreurs.push(...verifierMatrice(matrice, { specs, publie: true }));
  return erreurs;
}

/** Chemin réel d'un fichier (liens symboliques résolus), ou null ; la garde de lancement le compare à celui du module. */
function cheminReel(p) {
  try {
    return fs.realpathSync(path.resolve(p));
  } catch {
    return null;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === cheminReel(process.argv[1])) {
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
  console.log("RV-1 à RV-9 et MX-1 à MX-9 réussies : chaque renvoi existe (numéros de ligne compris), chaque menace a une réponse, les tables de CT-7 égalent menaces.json et matrice-conformite.json.");
}
