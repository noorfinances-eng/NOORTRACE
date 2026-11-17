// CT-5 : confrontation de la référence (scripts/lib/ancrage.mjs) et du
// composant d'ancrage (paquets/ancrage) sur des parcours tirés de graines
// fixes (annexe A.4, complément du 2026-11-16), et ordre du démarrage
// (EX-8.12, complément du 2026-11-16).
//
// - Confrontation : huit modes (test/fixtures/ancrage-confrontation), un même
//   nombre de parcours par mode ; à la première divergence, l'essai nomme la
//   graine, le mode, le segment, l'entrée et l'action (ou la ligne de file)
//   des deux côtés. Les graines qui ont montré un écart sont rejouées à part.
// - Ordre du démarrage : une seule passe sur la file, dans l'ordre de la
//   file, `a_envoyer` comprise, après EX-4.4 et avant les départs ; une ancre
//   `a_envoyer` n'attend le nonce que si une ancre de sa clé est en vol ; les
//   échéances d'une demande `remplacee` relue restent closes, et seule une
//   période ouverte retrouve ses échéances passées sans demande ; les
//   prestataires épuisés se relisent de la file (EX-8.8) ; EX-8.10 : le délai
//   d'inclusion constaté au reçu court depuis la création de l'ancre.
//   Cinq traces nouvelles départagent (redemarrage-ordre-de-la-file,
//   redemarrage-a-envoyer-cle-libre, redemarrage-echeances-remplacees,
//   registre-inclusion-apres-attente, redemarrage-prestataires-epuises).
// - Clé de chaîne du verrou d'EX-9.4 (complément du 2026-11-16) : le journal
//   du sujet de l'ancre ; deux journaux d'une même file ne s'attendent pas
//   (trace registre-cle-par-journal, trois modes de confrontation à deux
//   journaux, mutants des deux verrous) ; un composant d'ancrage refuse à
//   l'admission le point et la clôture d'un autre journal.
// - Minuteries de période de deux journaux au même instant (EX-8.16,
//   complément du 2026-11-16) : dans l'ordre où elles ont été armées, quel
//   que soit le journal (trace minuteries-deux-journaux, trois modes de
//   confrontation où les deux journaux ont des points, mutants du composant).
// - Mutants : chaque règle retirée de la référence ou du composant (copie
//   sous NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin) fait diverger
//   une trace ou la confrontation (mutant tué), dont deux règles du
//   complément précédent (réponse qui ne s'applique pas, détail de la
//   soumission OpenTimestamps).
//
// Les vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { MODES, contexte, confronterParcours, decrire } from "./fixtures/ancrage-confrontation/parcours.mjs";
import { monterComposant, remisePoint, remiseCloture, serieSynthetique, attenteCalme, repertoireTemporaire, enAttente, JOURNAL } from "./fixtures/ancrage-composant/outils.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";

/** Parcours par mode (graines PREMIERE à PREMIERE + PARCOURS − 1) : moins de 60 s pour les huit modes sur la CI. */
const PARCOURS = 100;
const PREMIERE = 7000;
/** Graines qui ont montré un écart des deux implémentations (mode, graine, écart). */
const GRAINES_ECARTS = [
  ["points", 1000, "ancre a_envoyer de clé occupée traitée dans une boucle finale par le composant (EX-8.12)"],
  ["coupe", 1021, "ancre a_envoyer de clé libre : attente_nonce toujours émise par la référence, départ dans l'ordre de la file par le composant (EX-8.12, EX-9.4)"],
  ["points", 1025, "échéances d'une demande remplacee relue closes une seconde fois par le composant (EX-8.12, EX-4.4)"],
  ["points", 7113, "inclusion_late comptée depuis le premier envoi par la référence (EX-8.10)"],
  ["rfc", 100982, "prestataire épuisé avant l'arrêt oublié par le composant (EX-8.12, EX-8.8)"],
  ["journaux+points2", 7002, "échéance d'un journal et cadence de l'autre au même instant : toutes les échéances avant toutes les cadences dans le composant, ordre d'armement dans la référence (EX-8.16)"],
];
const TRACES = ["redemarrage-ordre-de-la-file", "redemarrage-a-envoyer-cle-libre", "redemarrage-echeances-remplacees", "registre-inclusion-apres-attente", "redemarrage-prestataires-epuises"];

/** Copie d'un sous-arbre de RACINE sous TMP (node_modules, spec et package.json liés), un fichier modifié par un remplacement unique. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-confrontation-${nom}-`));
  COPIES.push(racine);
  for (const s of ["scripts/lib", "paquets/ancrage/src"]) {
    fs.mkdirSync(path.join(racine, path.dirname(s)), { recursive: true });
    if (s === sousArbre) fs.cpSync(path.join(RACINE, s), path.join(racine, s), { recursive: true });
    else fs.symlinkSync(path.join(RACINE, s), path.join(racine, s));
  }
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`copie ${nom} : « ${ancien.slice(0, 120)} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
const mutantReference = (nom, ancien, nouveau) => copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau);
const mutantComposant = (nom, ancien, nouveau) => copie(nom, "paquets/ancrage/src", PLANIFICATEUR, ancien, nouveau);

/** Modules des deux implémentations sous `racine`. */
async function modules(racine) {
  const u = unique();
  return {
    A: await import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + u),
    P: await import(pathToFileURL(path.join(racine, PLANIFICATEUR)).href + u),
    T: await import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + u),
  };
}
const contexteDe = async (racine) => contexte({ ...(await modules(racine)), vecteurs: CT5 });

/** Première divergence sur les graines données, ou null. */
function premiereDivergence(ctx, mode, graines) {
  for (const g of graines) {
    const d = confronterParcours(ctx, g, mode);
    if (d) return d;
  }
  return null;
}
const plage = (debut, n) => Array.from({ length: n }, (_, i) => debut + i);

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, racines = {}) {
  const t = trace(id);
  const ref = (await modules(racines.R ?? RACINE)).A;
  const comp = (await modules(racines.C ?? RACINE)).T;
  let r;
  try {
    r = ref.verifierTrace(t).length;
  } catch (e) {
    r = `exception : ${e.message}`;
  }
  let c;
  try {
    c = comp.rejouerTrace(t).ecarts.length;
  } catch (e) {
    c = `exception : ${e.message}`;
  }
  return { reference: r, composant: c };
}
const diverge = (n) => n !== 0;

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 A.4 : confrontation de la référence et du composant d'ancrage sur des parcours tirés de graines fixes (complément du 2026-11-16)", function () {
  this.timeout(120000);
  let ctx;
  before(async function () {
    ctx = await contexteDe(RACINE);
  });

  for (const mode of Object.keys(MODES)) {
    it(`mode ${mode} : ${PARCOURS} parcours (graines ${PREMIERE} à ${PREMIERE + PARCOURS - 1}), aucune divergence ; sinon la graine, le segment, l'entrée et l'action qui diffère sont nommés`, function () {
      const d = premiereDivergence(ctx, mode, plage(PREMIERE, PARCOURS));
      expect(d, d ? decrire(d) : "").to.equal(null);
    });
  }

  for (const [mode, graine, ecart] of GRAINES_ECARTS) {
    it(`graine ${graine} (mode ${mode}), qui a montré un écart (${ecart}) : plus de divergence`, function () {
      const d = confronterParcours(ctx, graine, mode);
      expect(d, d ? decrire(d) : "").to.equal(null);
    });
  }

  it("une divergence est nommée : graine, mode, segment, entrée, puis l'action des deux côtés", function () {
    const d = { graine: 42, mode: "points", segment: 1, entree: "2026-11-03T14:00:30.000Z demarrage", ou: "expected", indice: 7, reference: { action: "programmer" }, composant: { action: "journaliser" } };
    expect(decrire(d)).to.equal('graine 42 (mode points), segment 1, entrée 2026-11-03T14:00:30.000Z demarrage : première divergence (expected, indice 7) ; référence {"action":"programmer"} ; composant {"action":"journaliser"}');
  });
});

describe("CT-5 EX-8.12, EX-8.10, EX-8.8 : ordre du démarrage et derniers écarts entre la référence et le composant (complément du 2026-11-16)", function () {
  this.timeout(120000);

  for (const id of TRACES) {
    it(`${id} : rejouée sans écart par la référence et par le composant`, async function () {
      expect(await ecarts(id)).to.deep.equal({ reference: 0, composant: 0 });
    });
  }

  it("redemarrage-ordre-de-la-file : au démarrage, la passe suit l'ordre de la file ; l'ancre de la période attend le nonce à sa place, entre le renvoi de l'ancre en vol et le jeton de clôture", function () {
    const t = trace("redemarrage-ordre-de-la-file");
    const debut = t.inputs[0].t;
    const ordre = t.expected.filter((a) => a.t === debut).map((a) => `${a.action} ${a.request_id?.split(":")[0] ?? "-"} ${a.detail.event ?? a.detail.reason ?? a.detail.state ?? ""}`.trim());
    expect(ordre.slice(0, 7)).to.deep.equal(["journaliser - anchoring_started", "journaliser ancre_registre_point anchor_retry", "envoyer_registre ancre_registre_point", "programmer ancre_registre_periode attente_nonce", "programmer jeton_periode attente_registre", "ecrire_file ots_periode a_reprendre", "programmer ots_periode immediat"]);
  });

  it("redemarrage-a-envoyer-cle-libre : aucune attente du nonce au démarrage ; l'ancre du point de clôture part après la passe, celle de la période à son reçu (EX-9.4)", function () {
    const t = trace("redemarrage-a-envoyer-cle-libre");
    const debut = t.inputs[0].t;
    expect(t.expected.filter((a) => a.t === debut && a.detail.reason === "attente_nonce")).to.deep.equal([]);
    // CT-5 EX-9.4 (complément du 2026-11-16) : « l'ancre de la période ne part qu'après le reçu de l'ancre du point de
    // clôture de la même clé » ; la trace publiée faisait partir l'ancre de la période d'abord, avant celle de K2.
    expect(t.expected.filter((a) => a.action === "envoyer_registre").map((a) => a.request_id.split(":")[0])).to.deep.equal(["ancre_registre_point", "ancre_registre_periode"]);
  });

  const MUTANTS_REFERENCE = [
    // Complément du 2026-11-16 (clé de chaîne du verrou d'EX-9.4) : cleOccupee prend l'ancre dont elle juge la clé.
    ["attente-nonce-toujours", "redemarrage-a-envoyer-cle-libre", '        } else if (d.state === "a_envoyer" && this.cleOccupee(d)) {', '        } else if (d.state === "a_envoyer") {'],
    ["inclusion-premier-envoi", "registre-inclusion-apres-attente", "    const creation = ms(d.created_at);", "    const creation = ms(d.attempts[0].started_at);"],
  ];
  for (const [nom, id, ancien, nouveau] of MUTANTS_REFERENCE) {
    it(`mutant ${nom} (référence) : ${id} diverge (tué)`, async function () {
      expect(diverge((await ecarts(id, { R: mutantReference(nom, ancien, nouveau) })).reference)).to.equal(true);
    });
  }

  const MUTANTS_COMPOSANT = [
    ["attente-nonce-boucle-finale", "redemarrage-ordre-de-la-file", '        } else if (d.state === "a_envoyer" && this.registreOccupe(d)) {', '        } else if (false) {'],
    ["depart-ordre-de-la-file", "redemarrage-a-envoyer-cle-libre", "    for (const d of cles.values()) if (!this.registreOccupe(d)) this.dispatcherRegistreSuivantDemarrage(d.subject.org_id, d.subject.journal_id);", "    for (const d of aEnvoyer) if (d.kind.startsWith(\"ancre_registre_\")) this.dispatcherRegistre(d);"],
    ["echeances-remplacees-rouvertes", "redemarrage-echeances-remplacees", '      else if (d.state === "remplacee") for (const k of d.deadlines) p.echeances.set(k, { state: "remplacee", request: d.id });\n', ""],
    ["periode-close-rouverte", "redemarrage-ordre-de-la-file", "    for (const p of this.periodes.values()) if (p.points.size && !p.close) this.activerEcheances(p);", "    for (const p of this.periodes.values()) if (p.points.size) this.activerEcheances(p);"],
    ["epuises-oublies", "redemarrage-prestataires-epuises", '        for (const a of d.attempts) if (a.outcome === "echec_permanente" && a.provider !== null) i.epuises.add(a.provider);\n', ""],
  ];
  for (const [nom, id, ancien, nouveau] of MUTANTS_COMPOSANT) {
    it(`mutant ${nom} (composant) : ${id} diverge (tué)`, async function () {
      expect(diverge((await ecarts(id, { C: mutantComposant(nom, ancien, nouveau) })).composant)).to.equal(true);
    });
  }

  // La confrontation tue aussi les mutants : deux règles du complément précédent (EX-8.5, règle 2 ; EX-8.16) et deux de
  // celui-ci, chacune dans sa copie (une seule règle retirée à la fois).
  const MUTANTS_CONFRONTATION = [
    ["reference", "demande-inconnue", "rfc", plage(PREMIERE, PARCOURS), 'error_code: "demande_inconnue", attempt: data.attempt ?? null, provider: null, kept: false });', 'error_code: "tentative_inconnue", attempt: data.attempt ?? null });'],
    ["composant", "detail-soumission", "ots", plage(PREMIERE, PARCOURS), "    this.nouvelleTentative(req, { detail: `soumission a ${this.config.opentimestamps.calendars.length} calendriers` });", '    this.nouvelleTentative(req, { detail: "soumission envoyee" });'],
    ["composant", "attente-nonce-boucle-finale", "points", plage(PREMIERE, PARCOURS), '        } else if (d.state === "a_envoyer" && this.registreOccupe(d)) {', '        } else if (false) {'],
    ["composant", "epuises-oublies", "rfc", [100982], '        for (const a of d.attempts) if (a.outcome === "echec_permanente" && a.provider !== null) i.epuises.add(a.provider);\n', ""],
  ];
  for (const [cote, nom, mode, graines, ancien, nouveau] of MUTANTS_CONFRONTATION) {
    it(`mutant ${nom} (${cote}) : la confrontation en mode ${mode} diverge et nomme la graine (tué)`, async function () {
      const racine = cote === "reference" ? mutantReference(`c-${nom}`, ancien, nouveau) : mutantComposant(`c-${nom}`, ancien, nouveau);
      const d = premiereDivergence(await contexteDe(racine), mode, graines);
      expect(d, "aucune divergence").to.not.equal(null);
      expect(decrire(d)).to.match(/^graine \d+ \(mode [a-z+]+\), segment \d+, entrée /);
    });
  }

  it("INDEX.md, CT-5 (EX-8.12, EX-8.10, A.3, A.4, note de révision) et spec/README.md nomment les cinq traces et la confrontation ; A.4 compte soixante-deux traces, vingt-cinq à file", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const readme = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "README.md"), "utf8");
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5 "));
    for (const id of TRACES) {
      expect(index).to.include(`| \`${id}.json\` |`);
      expect(a3).to.include(`${id}.json`);
      expect(ct5).to.include(`\`${id}\``);
    }
    // CT-5 A.3 et A.4 (complément du 2026-11-16, clé de chaîne du verrou d'EX-9.4 : une trace de plus, sans file ; puis
    // minuteries de deux journaux, EX-8.16 : une de plus, sans file ; puis refus de l'ancre d'une période et ordre des ancres de points, EX-8.10 et EX-9.4 : deux de plus, dont une à file ; puis l'ancre de la période après celle de son point de clôture et l'âge d'abandon OpenTimestamps, EX-9.4 et EX-8.11 : deux de plus, dont une à file ; puis la clé retenue par l'ancre d'une période, la soumission OpenTimestamps tardive et l'alerte du refus après un redémarrage, EX-9.4, EX-8.11 et EX-8.10 : trois de plus, dont deux à file ; puis l'ancre d'un point en reprise quand le point suivant de sa période est admis, EX-9.5 et EX-9.4 : une de plus, sans file) : soixante-deux traces, vingt-cinq à file.
    expect(a3).to.include("cinquante-deux traces");
    expect(a3).to.include("cinquante-trois traces");
    expect(a3).to.include("cinquante-quatre traces");
    expect(a4).to.include("les soixante-deux traces de 8.10 et A.3");
    expect(a4).to.include("(vingt-cinq traces)");
    expect(a4).to.include("`test/ancrage-confrontation-aleatoire.test.js`");
    expect(readme).to.include("Les soixante-deux traces normatives");
    for (const texte of ["Complément du 2026-11-16 (ordre du démarrage).", "une seule passe sur la file, dans l'ordre de la file", "au reçu, ce délai court depuis la création de l'ancre"]) expect(ct5).to.include(texte);
  });
});

describe("CT-5 EX-9.4 : la clé de chaîne du verrou des envois au registre est le journal du sujet de l'ancre (complément du 2026-11-16)", function () {
  this.timeout(120000);
  const TRACE = "registre-cle-par-journal";
  const constantes = JSON.parse(fs.readFileSync(path.join(CT5, "constantes.json"), "utf8"));

  it(`${TRACE} : rejouée sans écart par la référence et par le composant`, async function () {
    expect(await ecarts(TRACE)).to.deep.equal({ reference: 0, composant: 0 });
  });

  it(`${TRACE} : deux journaux de la même organisation ; l'ancre de la période de l'un part à sa clôture pendant que l'ancre d'un point de l'autre attend son reçu, sans attente du nonce`, function () {
    const t = trace(TRACE);
    const journaux = new Set(t.inputs.filter((e) => e.type === "point_produit" || e.type === "periode_close").map((e) => `${e.data.org_id}|${e.data.journal_id}`));
    expect(journaux.size).to.equal(2);
    expect(t.expected.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id.split(":")[0]])).to.deep.equal([["2026-11-05T09:13:00.000Z", "ancre_registre_point"], ["2026-11-05T09:13:10.000Z", "ancre_registre_periode"]]);
    expect(t.expected.filter((a) => a.detail.reason === "attente_nonce")).to.deep.equal([]);
  });

  // Chaque verrou ramené à une autre clé (une copie, une règle à la fois) : la trace ou la confrontation à deux journaux
  // diverge. La confrontation tire le second journal dans la même organisation (journal-sinistres) ou dans une autre
  // (même journal_id) : un verrou par journal_id seul, ou par organisation seule, diverge aussi.
  const VERROU_REFERENCE = 'if (autre !== d && autre.kind.startsWith("ancre_registre_") && autre.state === "envoyee" && this.cleChaine(autre.subject) === k) return true;';
  const VERROU_COMPOSANT = "if (autre.subject.org_id === d.subject.org_id && autre.subject.journal_id === d.subject.journal_id) return true;";
  const MUTANTS = [
    ["reference", "verrou-global", VERROU_REFERENCE, VERROU_REFERENCE.replace(" && this.cleChaine(autre.subject) === k", "")],
    ["composant", "verrou-global", VERROU_COMPOSANT, "return true;"],
    ["composant", "verrou-organisation-seule", VERROU_COMPOSANT, "if (autre.subject.org_id === d.subject.org_id) return true;"],
    ["composant", "verrou-journal-id-seul", VERROU_COMPOSANT, "if (autre.subject.journal_id === d.subject.journal_id) return true;"],
  ];
  for (const [cote, nom, ancien, nouveau] of MUTANTS) {
    it(`mutant ${nom} (${cote}) : la confrontation à deux journaux diverge et nomme la graine (tué)`, async function () {
      const racine = cote === "reference" ? mutantReference(`j-${nom}`, ancien, nouveau) : mutantComposant(`j-${nom}`, ancien, nouveau);
      const d = premiereDivergence(await contexteDe(racine), "journaux", plage(PREMIERE, PARCOURS));
      expect(d, "aucune divergence").to.not.equal(null);
      expect(decrire(d)).to.match(/^graine \d+ \(mode journaux\), segment \d+, entrée /);
    });
  }
  for (const [cote, nom, ancien, nouveau] of MUTANTS.filter(([, nom]) => nom !== "verrou-journal-id-seul")) {
    it(`mutant ${nom} (${cote}) : ${TRACE} diverge (tué)`, async function () {
      const e = cote === "reference" ? await ecarts(TRACE, { R: mutantReference(`t-${nom}`, ancien, nouveau) }) : await ecarts(TRACE, { C: mutantComposant(`t-${nom}`, ancien, nouveau) });
      expect(diverge(e[cote === "reference" ? "reference" : "composant"])).to.equal(true);
    });
  }

  // Au démarrage, deux journaux dont chacun a une ancre a_envoyer et aucune en vol (arrêt entre la ligne a_envoyer et
  // la ligne envoyee de chacune, EX-8.5, règle 1) : après la passe, chaque journal fait partir la sienne (EX-8.12,
  // point 6 ; EX-9.4). La confrontation n'atteint pas ce cas (arrêt brutal au même endroit dans les deux journaux).
  const demarrageDeuxJournaux = (A) => {
    const t = trace(TRACE);
    const avant = (id) => ({ ...t.queue_after.find((d) => d.id.startsWith(id)), state: "a_envoyer", due_at: null, attempts: [], attempts_total: 0, result: null });
    return { version: 0, id: "demarrage-deux-journaux", description: "essai", config: t.config, jitter_ms: [], queue_before: [avant("ancre_registre_point:"), avant("ancre_registre_periode:")], inputs: [{ t: "2026-11-05T09:20:00.000Z", type: "demarrage", data: {} }, { t: "2026-11-05T09:20:01.000Z", type: "arret", data: {} }], expected: [], queue_after: [] };
  };
  const confronterDemarrage = async (racines = {}) => {
    const A = (await modules(racines.R ?? RACINE)).A;
    const T = (await modules(racines.C ?? RACINE)).T;
    const tr = demarrageDeuxJournaux(A);
    const r = A.rejouerTrace(tr);
    const envois = r.actions.filter((a) => a.action === "envoyer_registre").map((a) => [a.t, a.request_id.split(":")[0]]);
    return { envois, ecarts: T.rejouerTrace({ ...tr, expected: r.actions, queue_after: r.file }).ecarts.length };
  };
  it("démarrage sur deux journaux à ancre a_envoyer, aucune en vol : les deux ancres partent après la passe, chacune dans son journal ; le composant rend les mêmes actions", async function () {
    expect(await confronterDemarrage()).to.deep.equal({ envois: [["2026-11-05T09:20:00.000Z", "ancre_registre_point"], ["2026-11-05T09:20:00.000Z", "ancre_registre_periode"]], ecarts: 0 });
  });
  it("mutant servir-une-cle (référence : une seule clé servie par passe de départs) : au démarrage sur deux journaux, l'ancre du second ne part qu'à l'entrée suivante et le composant diverge (tué)", async function () {
    const r = await confronterDemarrage({ R: mutantReference("servir-une-cle", "    for (const k of cles) {\n      const d = candidats.find", "    for (const k of cles.slice(0, 1)) {\n      const d = candidats.find") });
    expect(r.envois).to.deep.equal([["2026-11-05T09:20:00.000Z", "ancre_registre_point"], ["2026-11-05T09:20:01.000Z", "ancre_registre_periode"]]);
    expect(r.ecarts).to.not.equal(0);
  });

  it("un composant d'ancrage sert un seul journal : le point et la clôture d'un autre journal, signés par une clé de test qu'il connaît pour le sien, sont refusés à l'admission (point : règle period_start ; manifeste : règle signature, la clé n'étant pas une clé de ce journal) et ne créent aucune demande (EX-9.4, CT-2 EX-13.7)", async function () {
    this.timeout(300000);
    const PERIODE = 1793862000;
    const dir = repertoireTemporaire("ancrage-cle-par-journal-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 } });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const composant = m.creer();
      const calme = attenteCalme(composant);
      await composant.demarrer();
      const autre = serieSynthetique({ periodStart: PERIODE, evenementsAuxMinutes: { 1: 1 }, journalId: constantes.reference_journal.journal_id, sel: "autre-journal" });
      expect(autre.points[2].journal_id).to.not.equal(JOURNAL);
      expect(await composant.remettrePoint(remisePoint(autre.points[2]))).to.deep.equal({ admis: false, regle: "period_start" });
      expect(await composant.remettreCloture(remiseCloture(autre))).to.deep.equal({ admis: false, regle: "signature" });
      await calme();
      expect(composant.demandes().filter((d) => d.subject.journal_id !== JOURNAL)).to.deep.equal([]);
      expect(m.journal.de("anchor_admission_refused").map((l) => [l.data.object, l.data.rule])).to.deep.equal([["point", "period_start"], ["manifeste", "signature"]]);
      // Le journal du contexte reste admis (premier point de sa série).
      expect((await composant.remettrePoint(remisePoint(m.serie.points[0]))).admis).to.equal(true);
      await calme();
      await composant.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("CT-5 (EX-9.4, note de révision, A.3, A.4), INDEX.md et spec/README.md disent la clé de chaîne du verrou et nomment la trace", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const readme = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "README.md"), "utf8");
    const ex94 = ct5.slice(ct5.indexOf("**EX-9.4**"), ct5.indexOf("**EX-9.5**"));
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5 "));
    expect(index).to.include(`| \`${TRACE}.json\` |`);
    expect(a3).to.include(`${TRACE}.json`);
    expect(ex94).to.include("Complément du 2026-11-16 (clé de chaîne de ce verrou).");
    expect(ex94).to.include("deux ancres ont la même clé de chaîne quand leurs sujets ont le même `org_id` et le même `journal_id`");
    expect(ex94).to.include("une même adresse NE DOIT PAS être la clé de chaîne");
    expect(ex94).to.include(`(trace \`${TRACE}\`)`);
    expect(ct5).to.include("Complément du 2026-11-16 (clé de chaîne du verrou d'EX-9.4)");
    expect(a4).to.include("trois modes de plus mettent deux journaux dans la même file");
    expect(readme).to.include("verrou de la clé de chaîne porté par le journal de l'ancre");
  });
});

describe("CT-5 EX-8.16 : minuteries de période de deux journaux au même instant, dans l'ordre où elles ont été armées (complément du 2026-11-16)", function () {
  this.timeout(120000);
  const TRACE = "minuteries-deux-journaux";

  it(`${TRACE} : rejouée sans écart par la référence et par le composant`, async function () {
    expect(await ecarts(TRACE)).to.deep.equal({ reference: 0, composant: 0 });
  });

  it(`${TRACE} : à 13:55, l'échéance D_11 du journal de référence, son alerte point_manquant (cadence armée par K2 à 13:53), puis l'échéance D_11 du journal des vecteurs (ouvert à 13:54)`, function () {
    const t = trace(TRACE);
    expect(new Set(t.inputs.filter((e) => e.type === "point_produit").map((e) => e.data.journal_id)).size).to.equal(2);
    const a = t.expected.filter((x) => x.t === "2026-11-03T13:55:00.000Z" && x.request_id === null).map((x) => [x.action, x.detail.k ?? x.detail.event ?? x.detail.code]);
    expect(a).to.deep.equal([["echeance", 11], ["journaliser", "point_manquant"], ["alerter", "point_manquant"], ["echeance", 11]]);
  });

  // Le composant d'avant rangeait toutes les échéances (rang 0) avant toutes les cadences (rang 1) : chaque moitié de
  // cet ordre, remise dans une copie, fait diverger la trace ou la confrontation où les deux journaux ont des points.
  const ECHEANCE = "candidat(at, 0, p.armementEcheances * 1e4 + k, () => {";
  const CADENCE = "        candidat(at, 0, p.armementCadence * 1e4, () => {";
  const MUTANTS = [
    ["echeances-par-periode", ECHEANCE, "candidat(at, 0, p.period_start * 100 + k, () => {"],
    ["cadences-apres-echeances", CADENCE, "        candidat(at, 1, p.period_start, () => {"],
  ];
  for (const [nom, ancien, nouveau] of MUTANTS) {
    it(`mutant ${nom} (composant) : la confrontation en mode journaux+points2 diverge et nomme la graine (tué)`, async function () {
      const d = premiereDivergence(await contexteDe(mutantComposant(`m-${nom}`, ancien, nouveau)), "journaux+points2", plage(PREMIERE, PARCOURS));
      expect(d, "aucune divergence").to.not.equal(null);
      expect(decrire(d)).to.match(/^graine \d+ \(mode journaux\+points2\), segment \d+, entrée /);
    });
  }
  it("mutant cadences-apres-echeances (composant) : minuteries-deux-journaux diverge (tué)", async function () {
    expect(diverge((await ecarts(TRACE, { C: mutantComposant("t-cadences-apres-echeances", CADENCE, "        candidat(at, 1, p.period_start, () => {") })).composant)).to.equal(true);
  });

  it("CT-5 (EX-8.16, note de révision, A.3, A.4), INDEX.md et spec/README.md disent l'ordre des minuteries de deux journaux et nomment la trace", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const readme = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "README.md"), "utf8");
    const ex816 = ct5.slice(ct5.indexOf("**EX-8.16**"), ct5.indexOf("### 8.11 Vérifications"));
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5 "));
    expect(index).to.include(`| \`${TRACE}.json\` |`);
    expect(a3).to.include(`${TRACE}.json`);
    expect(ex816).to.include("l'ordre d'armement des minuteries de période vaut quel que soit leur journal");
    expect(ex816).to.include(`(trace \`${TRACE}\`)`);
    expect(ct5).to.include("Complément du 2026-11-16 (contrôle d'OP-9 pour l'ancre d'une période ; clé de chaîne d'une seule organisation ; minuteries de deux journaux)");
    expect(a4).to.include("trois modes encore, où le second journal produit aussi les points de la période 1");
    expect(readme).to.include("minuteries de période de deux journaux au même instant, dans l'ordre où elles ont été armées");
  });
});
