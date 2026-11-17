// CT-5 EX-9.4 (complément du 2026-11-16) : l'ancre d'une période ne part
// qu'après le reçu de l'ancre de son point de clôture ; dans une même
// période, les ancres de ses points d'abord, la période ensuite ; entre
// périodes, `period_start`.
//
// Avant : quand l'ancre du point de clôture attendait le nonce à la clôture,
// la règle « période d'abord » faisait partir l'ancre de la période avant
// elle, dans la référence (scripts/lib/ancrage.mjs) comme dans le composant
// d'ancrage (paquets/ancrage) ; l'ancre du point, incluse après celle de la
// période, tombait dans la fenêtre de blocs de la période suivante, où le
// contrôle de complétude (EX-10.7) la dit orpheline. Deux traces publiées
// fixaient ce comportement (redemarrage-a-envoyer-cle-libre,
// registre-indisponible-cloture) ; elles suivent désormais le texte, et la
// trace registre-periode-apres-point-de-cloture exerce le cas.
//
// L'invariant (« aucune ancre de période envoyée avant le reçu des ancres des
// points de sa période ») est vérifié sur chaque trace publiée, sur des
// traces de travail qui exercent les autres chemins (clôture et reprise, clé
// libre), et par la confrontation des deux implémentations
// (test/fixtures/ancrage-confrontation : violationsAncrePeriode).
//
// Les vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge). Les mutants sont des
// copies sous NOORTRACE_TMP (défaut os.tmpdir()), détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { MODES, contexte, confronterParcours, violationsAncrePeriode } from "./fixtures/ancrage-confrontation/parcours.mjs";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CT5 = path.join(DEPOT, "spec", "vecteurs", "ct-5");
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const COPIES = [];
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const TRACES = ["registre-periode-apres-point-de-cloture", "redemarrage-a-envoyer-cle-libre", "registre-indisponible-cloture"];

/** Copie de RACINE (scripts/lib et paquets/ancrage/src), un fichier modifié par un remplacement unique ; rend sa racine. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-periode-apres-points-${nom}-`));
  COPIES.push(racine);
  for (const s of ["scripts/lib", "paquets/ancrage/src"]) {
    fs.mkdirSync(path.join(racine, path.dirname(s)), { recursive: true });
    if (s === sousArbre) fs.cpSync(path.join(RACINE, s), path.join(racine, s), { recursive: true });
    else fs.symlinkSync(path.join(RACINE, s), path.join(racine, s));
  }
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(DEPOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  const texte = fs.readFileSync(f, "utf8");
  expect(texte.split(ancien).length - 1, `copie ${nom} : « ${ancien.slice(0, 100)} »`).to.equal(1);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
const mutantReference = (nom, ancien, nouveau) => copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau);
const mutantComposant = (nom, ancien, nouveau) => copie(nom, "paquets/ancrage/src", PLANIFICATEUR, ancien, nouveau);

async function modules(racine) {
  const u = unique();
  return {
    A: await import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + u),
    P: await import(pathToFileURL(path.join(racine, PLANIFICATEUR)).href + u),
    T: await import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + u),
  };
}

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace. */
async function ecarts(t, racines = {}) {
  const A = (await modules(racines.R ?? RACINE)).A;
  const T = (await modules(racines.C ?? RACINE)).T;
  let r;
  try {
    r = A.verifierTrace(t).length;
  } catch (e) {
    r = `exception : ${e.message}`;
  }
  let c;
  try {
    c = T.rejouerTrace(t).ecarts.length;
  } catch (e) {
    c = `exception : ${e.message}`;
  }
  return { reference: r, composant: c };
}
const diverge = (n) => n !== 0;

/**
 * Traces de travail (non publiées) sur la période 1 de référence : `cloture` (l'ancre du point de clôture K4 échoue de
 * façon transitoire juste avant la clôture : la clé est libre, mais l'ancre de la période attend son reçu) et
 * `reprise` (file relue : l'ancre de la période et celle de K4 sont a_reprendre, la période échue la première, la clé
 * libre). L'attendu est la suite de la référence (la règle) ; le composant doit la reproduire.
 */
function tracesDeTravail(A) {
  const base = trace("registre-periode-apres-point-de-cloture");
  const config = base.config;
  const k4 = base.inputs.find((e) => e.type === "point_produit" && e.t === "2026-11-03T14:00:00.250Z").data;
  const cloture = base.inputs.find((e) => e.type === "periode_close").data;
  const AK4 = `ancre_registre_point:${k4.checkpoint_hash}`;
  const AP = `ancre_registre_periode:${cloture.period_hash}`;
  const inclusion = (t, id, b) => ({ t, type: "inclusion_registre", data: { request_id: id, block_number: b, capture_sha256: "0x" + "ab".repeat(32) } });
  const cas = {};
  cas.cloture = {
    version: 0, id: "travail-cloture-cle-libre", description: "travail", config, jitter_ms: [91], queue_before: [],
    inputs: [
      { t: "2026-11-03T13:59:00.000Z", type: "demarrage", data: {} },
      { t: "2026-11-03T14:00:00.250Z", type: "point_produit", data: k4 },
      { t: "2026-11-03T14:00:00.250Z", type: "echec_registre", data: { request_id: AK4, code: "noeud_injoignable" } },
      { t: "2026-11-03T14:00:00.250Z", type: "periode_close", data: cloture },
      { t: "2026-11-03T14:00:05.341Z", type: "tic", data: {} },
      inclusion("2026-11-03T14:00:06.000Z", AK4, 21082),
      inclusion("2026-11-03T14:00:07.000Z", AP, 21083),
      { t: "2026-11-03T14:00:30.000Z", type: "arret", data: {} },
    ],
    expected: [], queue_after: [],
  };
  // File de la trace `cloture` arrêtée juste après l'échec de K4 et la clôture, l'ancre de la période passée
  // a_reprendre par un refus transitoire antérieur : due avant celle de K4.
  const r0 = A.rejouerTrace({ ...cas.cloture, inputs: cas.cloture.inputs.slice(0, 4).concat([{ t: "2026-11-03T14:00:01.000Z", type: "arret", data: {} }]) });
  // Ligne d'une version antérieure : l'ancre de la période partie avant le reçu de K4 et en échec transitoire.
  const tentativeK4 = r0.file.find((d) => d.id === AK4).attempts[0];
  const tentativeAP = { ...tentativeK4, correlation_id: A.identifiantCorrelation("ancre_registre_periode", cloture.period_hash, 1), next_at: "2026-11-03T14:00:02.000Z" };
  const file = r0.file.map((d) => (d.id === AP ? { ...d, state: "a_reprendre", due_at: "2026-11-03T14:00:02.000Z", attempts: [tentativeAP], ...(d.attempts_total !== undefined ? { attempts_total: 1 } : {}) } : d));
  cas.reprise = {
    version: 0, id: "travail-reprise-cle-libre", description: "travail", config, jitter_ms: [], queue_before: file,
    inputs: [
      { t: "2026-11-03T14:00:01.500Z", type: "demarrage", data: {} },
      { t: "2026-11-03T14:00:02.000Z", type: "tic", data: {} },
      { t: "2026-11-03T14:00:05.341Z", type: "tic", data: {} },
      inclusion("2026-11-03T14:00:06.000Z", AK4, 21082),
      inclusion("2026-11-03T14:00:07.000Z", AP, 21083),
      { t: "2026-11-03T14:00:30.000Z", type: "arret", data: {} },
    ],
    expected: [], queue_after: [],
  };
  for (const t of Object.values(cas)) {
    const r = A.rejouerTrace(t);
    t.expected = r.actions;
    t.queue_after = r.file;
  }
  return { cas, AK4, AP };
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-9.4 : l'ancre d'une période ne part qu'après le reçu de l'ancre de son point de clôture (complément du 2026-11-16)", function () {
  this.timeout(300000);

  for (const id of TRACES) {
    it(`${id} : rejouée sans écart par la référence et par le composant`, async function () {
      expect(await ecarts(trace(id))).to.deep.equal({ reference: 0, composant: 0 });
    });
  }

  it("registre-periode-apres-point-de-cloture : à la clôture, l'ancre de K4 (point de clôture) et celle de la période attendent le nonce ; au reçu de K3, K4 part ; à l'échec transitoire de K4, la clé est libre mais rien ne part ; la période part au reçu de K4", function () {
    const t = trace("registre-periode-apres-point-de-cloture");
    const envois = t.expected.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id.split(":")[0]]);
    expect(envois).to.deep.equal([
      ["2026-11-03T13:54:00.000Z", "ancre_registre_point"],
      ["2026-11-03T14:00:01.000Z", "ancre_registre_point"],
      ["2026-11-03T14:00:07.137Z", "ancre_registre_point"],
      ["2026-11-03T14:00:08.000Z", "ancre_registre_periode"],
    ]);
    expect(t.expected.filter((a) => a.t === "2026-11-03T14:00:02.000Z" && a.action === "envoyer_registre")).to.deep.equal([]);
  });

  it("invariant : sur chacune des soixante-deux traces publiées, aucune ancre de période ne part avant le reçu (ou un autre état final) des ancres des points de sa période ; il est exercé (ancres de période parties derrière des ancres de points)", function () {
    const fichiers = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();
    // CT-5 A.3 (complément du 2026-11-16 : la clé retenue, la soumission OpenTimestamps tardive et l'alerte du refus après un
    // redémarrage, trois traces de plus ; puis l'ancre d'un point en reprise quand le point suivant de sa période est
    // admis, une de plus) : soixante-deux traces.
    expect(fichiers).to.have.lengthOf(62);
    let departs = 0;
    for (const f of fichiers) {
      const t = JSON.parse(fs.readFileSync(path.join(CT5, "planification", f), "utf8"));
      expect(violationsAncrePeriode(t.queue_before, t.expected, t.queue_after), f).to.deep.equal([]);
      departs += t.expected.filter((a) => a.action === "envoyer_registre" && a.request_id.startsWith("ancre_registre_periode:")).length;
    }
    expect(departs).to.be.above(40);
  });

  it("invariant : il signale l'ancre de la période partie avant celle de son point de clôture (suite de l'ancienne trace redemarrage-a-envoyer-cle-libre, ordre des deux envois inversé)", function () {
    const t = structuredClone(trace("redemarrage-a-envoyer-cle-libre"));
    const debut = t.inputs[0].t;
    const idx = (id, etat) => t.expected.findIndex((a) => a.t === debut && a.action === "ecrire_file" && a.request_id.startsWith(id) && a.detail.state === etat);
    const iPoint = idx("ancre_registre_point:", "envoyee");
    expect(iPoint).to.be.at.least(0);
    // L'ancienne suite : l'ancre de la période écrite envoyee au démarrage, celle du point (a_envoyer) ensuite.
    const AP = t.queue_before.find((d) => d.kind === "ancre_registre_periode").id;
    t.expected.splice(iPoint, 0, { t: debut, action: "ecrire_file", request_id: AP, detail: { state: "envoyee" } });
    const v = violationsAncrePeriode(t.queue_before, t.expected, t.queue_after);
    expect(v.map((x) => [x.periode.split(":")[0], x.point.split(":")[0], x.etat])).to.deep.equal([["ancre_registre_periode", "ancre_registre_point", "a_envoyer"]]);
  });

  it("traces de travail (clé libre) : à la clôture, l'ancre de la période attend (attente_nonce) le reçu de celle de K4 en reprise ; à l'échéance de sa propre reprise, de même ; les deux implémentations concordent et l'invariant tient", async function () {
    const { cas, AK4, AP } = tracesDeTravail((await modules(DEPOT)).A);
    // L'attendu est celui de la référence du dépôt ; sous NOORTRACE_REVUE_RACINE, le code d'avant est confronté à lui.
    const env = (t) => t.expected.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id]);
    expect(env(cas.cloture)).to.deep.equal([["2026-11-03T14:00:00.250Z", AK4], ["2026-11-03T14:00:05.341Z", AK4], ["2026-11-03T14:00:06.000Z", AP]]);
    expect(cas.cloture.expected.filter((a) => a.request_id === AP && a.detail.reason === "attente_nonce").map((a) => a.t)).to.deep.equal(["2026-11-03T14:00:00.250Z"]);
    expect(env(cas.reprise)).to.deep.equal([["2026-11-03T14:00:05.341Z", AK4], ["2026-11-03T14:00:06.000Z", AP]]);
    expect(cas.reprise.expected.filter((a) => a.request_id === AP && a.detail.reason === "attente_nonce").map((a) => a.t)).to.deep.equal(["2026-11-03T14:00:02.000Z"]);
    for (const t of Object.values(cas)) {
      expect(violationsAncrePeriode(t.queue_before, t.expected, t.queue_after), t.id).to.deep.equal([]);
      expect(await ecarts(t), t.id).to.deep.equal({ reference: 0, composant: 0 });
    }
  });

  it("confrontation : dans chacun des quatorze modes, cinquante parcours sans divergence ni violation de l'invariant", async function () {
    const ctx = contexte({ ...(await modules(RACINE)), vecteurs: CT5 });
    const ecartsModes = [];
    for (const mode of Object.keys(MODES)) {
      for (let g = 7000; g < 7050; g++) {
        const d = confronterParcours(ctx, g, mode);
        if (d) {
          ecartsModes.push(`${mode} ${g} ${d.ou}`);
          break;
        }
      }
    }
    expect(ecartsModes).to.deep.equal([]);
  });

  const MUTANTS_REFERENCE = [
    ["servir-sans-attente-des-points", ["registre-periode-apres-point-de-cloture"], "      if (!this.cleOccupee(d) && !this.attendPoints(d)) this.envoyerRegistre(d, t);", "      if (!this.cleOccupee(d)) this.envoyerRegistre(d, t);"],
    ["periode-d-abord", ["redemarrage-a-envoyer-cle-libre", "registre-indisponible-cloture"], "    candidats.sort((a, b) => a.subject.period_start - b.subject.period_start || (SORTE_PERIODE(a.kind) ? 1 : 0) - (SORTE_PERIODE(b.kind) ? 1 : 0) || (SORTE_PERIODE(a.kind) ? 0 : ms(a.subject.declared_at) - ms(b.subject.declared_at)));", "    candidats.sort((a, b) => (SORTE_PERIODE(a.kind) ? 0 : 1) - (SORTE_PERIODE(b.kind) ? 0 : 1) || (SORTE_PERIODE(a.kind) ? a.subject.period_start - b.subject.period_start : ms(a.subject.declared_at) - ms(b.subject.declared_at)));"],
    ["cloture-sans-attente-des-points", ["travail:cloture"], '      if (this.cleOccupee(a) || this.attendPoints(a)) this.programmer(a, t, t, "attente_nonce");', '      if (this.cleOccupee(a)) this.programmer(a, t, t, "attente_nonce");'],
    ["reprise-sans-attente-des-points", ["travail:reprise"], '          if (this.cleOccupee(d) || this.attendPoints(d)) this.programmer(d, t, t, "attente_nonce");', '          if (this.cleOccupee(d)) this.programmer(d, t, t, "attente_nonce");'],
  ];
  for (const [nom, ids, ancien, nouveau] of MUTANTS_REFERENCE) {
    it(`mutant ${nom} (référence) : ${ids.join(", ")} diverge (tué)`, async function () {
      const R = mutantReference(nom, ancien, nouveau);
      const { cas } = tracesDeTravail((await modules(DEPOT)).A);
      for (const id of ids) {
        const t = id.startsWith("travail:") ? cas[id.slice(8)] : trace(id);
        expect(diverge((await ecarts(t, { R })).reference), id).to.equal(true);
      }
    });
  }

  const MUTANTS_COMPOSANT = [
    ["suivant-sans-attente-des-points", ["registre-periode-apres-point-de-cloture"], "    candidates.sort(comparerAncresCle);\n    if (this.attendPoints(candidates[0])) return;\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  recuAbsent", "    candidates.sort(comparerAncresCle);\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  recuAbsent"],
    ["periode-d-abord", ["redemarrage-a-envoyer-cle-libre", "registre-indisponible-cloture"], "  a.subject.period_start - b.subject.period_start ||\n  (a.subject.kind === \"periode\" ? 1 : 0) - (b.subject.kind === \"periode\" ? 1 : 0) ||", "  (a.subject.kind === \"periode\" ? 0 : 1) - (b.subject.kind === \"periode\" ? 0 : 1) ||\n  a.subject.period_start - b.subject.period_start ||"],
    ["envoi-sans-attente-des-points", ["travail:cloture", "travail:reprise"], "    if (this.registreOccupe(d) || this.attendPoints(d)) {", "    if (this.registreOccupe(d)) {"],
  ];
  for (const [nom, ids, ancien, nouveau] of MUTANTS_COMPOSANT) {
    it(`mutant ${nom} (composant) : ${ids.join(", ")} diverge (tué)`, async function () {
      const C = mutantComposant(nom, ancien, nouveau);
      const { cas } = tracesDeTravail((await modules(DEPOT)).A);
      for (const id of ids) {
        const t = id.startsWith("travail:") ? cas[id.slice(8)] : trace(id);
        expect(diverge((await ecarts(t, { C })).composant), id).to.equal(true);
      }
    });
  }

  it("mutant commun (référence et composant faisant partir la période d'abord, sans attendre les points, comme avant) : les deux concordent entre eux, mais la confrontation signale l'invariant d'EX-9.4 et nomme la graine (tué)", async function () {
    const racine = fs.mkdtempSync(path.join(TMP, "noortrace-periode-apres-points-commun-"));
    COPIES.push(racine);
    for (const s of ["scripts/lib", "paquets/ancrage/src"]) {
      fs.mkdirSync(path.join(racine, path.dirname(s)), { recursive: true });
      fs.cpSync(path.join(RACINE, s), path.join(racine, s), { recursive: true });
    }
    for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(DEPOT, l), path.join(racine, l));
    const remplacer = (fichier, paires) => {
      const f = path.join(racine, fichier);
      let texte = fs.readFileSync(f, "utf8");
      for (const [ancien, nouveau] of paires) {
        expect(texte.split(ancien).length - 1, `mutant commun : « ${ancien.slice(0, 80)} »`).to.equal(1);
        texte = texte.replace(ancien, () => nouveau);
      }
      fs.writeFileSync(f, texte);
    };
    // Référence : périodes d'abord, et aucune attente des points (servir, clôture, reprise).
    remplacer("scripts/lib/ancrage.mjs", [
      [MUTANTS_REFERENCE[1][2], MUTANTS_REFERENCE[1][3]],
      [MUTANTS_REFERENCE[0][2], MUTANTS_REFERENCE[0][3]],
      [MUTANTS_REFERENCE[2][2], MUTANTS_REFERENCE[2][3]],
      [MUTANTS_REFERENCE[3][2], MUTANTS_REFERENCE[3][3]],
    ]);
    // Composant : de même (ordre, départ suivant au démarrage et en marche, envoi).
    remplacer(PLANIFICATEUR, [
      [MUTANTS_COMPOSANT[1][2], MUTANTS_COMPOSANT[1][3]],
      [MUTANTS_COMPOSANT[0][2], MUTANTS_COMPOSANT[0][3]],
      ["    candidates.sort(comparerAncresCle);\n    if (this.attendPoints(candidates[0])) return;\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  // ----- point admis", "    candidates.sort(comparerAncresCle);\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  // ----- point admis"],
      [MUTANTS_COMPOSANT[2][2], MUTANTS_COMPOSANT[2][3]],
    ]);
    const ctx = contexte({ ...(await modules(racine)), vecteurs: CT5 });
    let d = null;
    for (let g = 7000; g < 7100 && !d; g++) d = confronterParcours(ctx, g, "points");
    expect(d, "aucune divergence").to.not.equal(null);
    expect(d.ou, JSON.stringify(d).slice(0, 300)).to.equal("invariant EX-9.4");
    expect(d.graine).to.be.a("number");
  });
});
