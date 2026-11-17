// CT-5 : soumission OpenTimestamps, deux passages où la référence
// (scripts/lib/ancrage.mjs) et le composant d'ancrage (paquets/ancrage)
// divergeaient sans trace qui les exerce ; le complément du 2026-11-16 écrit
// la ligne qui manquait :
//
// - EX-8.11 (EX-6.2, point 4) : une soumission qui obtient moins de
//   `min_responses` réponses valables, quelle que soit l'attestation, est
//   close `reponses_insuffisantes` et traitée comme une réponse RFC 3161 en
//   échec transitoire : `rejeter_reponse` et ligne `anchor_response_rejected`,
//   puis l'attente d'EX-8.9 (trace `ots-reponses-insuffisantes`) ;
// - EX-8.12 et EX-8.9 : une soumission `envoyee` au démarrage est close
//   `redemarrage`, comme la tentative d'un jeton, et repart aussitôt avec le
//   même engagement ; la tentative `redemarrage` interrompt sa série, et une
//   série relue ne compte que les tentatives que la ligne porte (trace
//   `redemarrage-ots-soumission-envoyee`).
//
// Chaque règle retirée de la référence ou du composant (copie sous
// NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin) fait diverger le rejeu
// ou l'attente (mutant tué). Les vecteurs sont lus dans le dépôt ; le code est
// lu dans le dépôt, ou sous NOORTRACE_REVUE_RACINE (code d'avant : essai rouge).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));

/** Copie d'un sous-arbre de RACINE sous TMP (node_modules, spec et package.json liés), un fichier modifié par un remplacement unique. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-ots-soumission-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, path.dirname(sousArbre)), { recursive: true });
  fs.cpSync(path.join(RACINE, sousArbre), path.join(racine, sousArbre), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`copie ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + unique());
const composant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + unique());
const planificateur = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "planificateur.mjs")).href + unique());
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const mutantReference = (nom, ancien, nouveau) => reference(copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau));
const mutantComposant = (nom, ancien, nouveau) => copie(nom, "paquets/ancrage/src", PLANIFICATEUR, ancien, nouveau);
/** L'ancienne attente du composant : toutes les tentatives en échec de la demande, sans série. */
const ANCIENNE_ATTENTE = "this.now + Math.min(this.config.rfc3161.retry.max_ms, this.config.rfc3161.retry.initial_ms * this.config.rfc3161.retry.factor ** Math.max(0, req.attempts.filter((x) => x.outcome === \"echec_transitoire\").length - 1)) + this.gigue()";

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, { R = null, C = null } = {}) {
  const t = trace(id);
  const ref = R ?? (await reference(RACINE));
  const comp = C ?? (await composant(RACINE));
  return { reference: ref.verifierTrace(t).length, composant: comp.rejouerTrace(t).ecarts.length };
}

const OP1 = "ots_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";

/**
 * File relue après deux arrêts : la soumission de la période 1 porte un échec
 * `reponses_insuffisantes` (rang 1) puis une tentative close par le
 * redémarrage (rang 2), et attend sa reprise (`a_reprendre`, 14:00:30).
 */
function fileRelueApresRedemarrage() {
  const t = trace("redemarrage-ots-soumission-envoyee");
  return t.queue_before.map((d) => {
    if (d.id !== OP1) return d;
    const attempts = d.attempts.map((a) => (a.outcome === "en_cours" ? { ...a, outcome: "echec_transitoire", error_code: "redemarrage", detail: "redemarrage : reponse non recue", next_at: "2026-11-03T14:00:30.000Z" } : a));
    return { ...d, state: "a_reprendre", due_at: "2026-11-03T14:00:30.000Z", attempts };
  });
}

/**
 * Composant d'ancrage sur cette file : démarrage à 14:00:30 (la soumission
 * repart au rang 3), puis échec de la tentative 3 à 14:00:31, par une réponse
 * à un seul calendrier (`reponse_ots`) ou par une réponse hors schéma
 * (`rejeter`). Rend l'échéance de la reprise programmée (`backoff`).
 */
async function repriseApresEchec(racine, { horsSchema = false } = {}) {
  const P = await planificateur(racine);
  const { noncesVecteurs } = await composant(racine);
  const t = trace("redemarrage-ots-soumission-envoyee");
  const p = P.creerPlanificateur(t.config, { gigues: [0], nonces: noncesVecteurs(), fileInitiale: fileRelueApresRedemarrage() });
  const depart = p.traiter({ t: "2026-11-03T14:00:30.000Z", type: "demarrage", data: {} });
  expect(depart.filter((a) => a.action === "soumettre_ots").map((a) => a.request_id)).to.deep.equal([OP1]);
  const actions = horsSchema
    ? p.rejeter(OP1, { t: "2026-11-03T14:00:31.000Z", attempt: 3, code: "entree_non_conforme", detail: "reponse hors schema" })
    : p.traiter({ t: "2026-11-03T14:00:31.000Z", type: "reponse_ots", data: { request_id: OP1, calendars_answered: 1, attestation: "aucune", proof_sha256: null, proof_size: null } });
  return actions.filter((a) => a.action === "programmer" && a.request_id === OP1 && a.detail.reason === "backoff").map((a) => a.detail.next_at);
}

describe("CT-5 : soumission OpenTimestamps (EX-8.11, EX-8.12, EX-8.9 ; complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("EX-8.11 : ots-reponses-insuffisantes est rejouée sans écart ; reponses_insuffisantes, rejeter_reponse de classe transitoire et anchor_response_rejected à chaque soumission en échec, attestation Bitcoin d'un seul calendrier comprise ; attentes k = 1 puis 2", async function () {
    expect(await ecarts("ots-reponses-insuffisantes")).to.deep.equal({ reference: 0, composant: 0 });
    const t = trace("ots-reponses-insuffisantes");
    expect(t.expected.filter((a) => a.action === "rejeter_reponse").map((a) => [a.t, a.detail.error_code, a.detail.class])).to.deep.equal([
      ["2026-11-03T14:00:01.000Z", "reponses_insuffisantes", "transitoire"],
      ["2026-11-03T14:00:07.000Z", "reponses_insuffisantes", "transitoire"],
    ]);
    expect(t.expected.filter((a) => a.action === "journaliser" && a.detail.event === "anchor_response_rejected").map((a) => [a.detail.error_code, a.detail.attempt, a.detail.provider])).to.deep.equal([
      ["reponses_insuffisantes", 1, null],
      ["reponses_insuffisantes", 2, null],
    ]);
    expect(t.inputs.find((e) => e.t === "2026-11-03T14:00:07.000Z").data).to.include({ attestation: "complete", calendars_answered: 1 });
    const ots = t.queue_after.find((d) => d.id === OP1);
    expect([ots.state, ots.attempts.map((a) => a.error_code)]).to.deep.equal(["en_attente", ["reponses_insuffisantes", "reponses_insuffisantes", null]]);
  });

  it("EX-8.12, EX-8.9 : redemarrage-ots-soumission-envoyee est rejouée sans écart ; la tentative en cours est close redemarrage, la soumission repart aussitôt au rang 3 ; l'échec suivant attend retry.initial_ms plus la gigue (k = 1)", async function () {
    expect(await ecarts("redemarrage-ots-soumission-envoyee")).to.deep.equal({ reference: 0, composant: 0 });
    const t = trace("redemarrage-ots-soumission-envoyee");
    const avant = t.queue_before.find((d) => d.id === OP1);
    expect([avant.state, avant.attempts.map((a) => a.outcome)]).to.deep.equal(["envoyee", ["echec_transitoire", "en_cours"]]);
    const apres = t.queue_after.find((d) => d.id === OP1);
    expect(apres.attempts.map((a) => [a.n, a.error_code])).to.deep.equal([[1, "reponses_insuffisantes"], [2, "redemarrage"], [3, "reponses_insuffisantes"], [4, null]]);
    expect(t.expected.filter((a) => a.action === "programmer" && a.detail.reason === "backoff").map((a) => a.detail.next_at)).to.deep.equal(["2026-11-03T14:00:36.750Z"]);
    for (const f of ["avant", "apres"]) expect(fs.existsSync(path.join(CT5, "reprise", `redemarrage-ots-soumission-envoyee.${f}.ndjson`)), f).to.equal(true);
  });

  it("EX-8.9 (composant) : une série relue s'arrête à la tentative redemarrage ; après une réponse à trop peu de calendriers, reprise à 14:00:36 (k = 1)", async function () {
    expect(await repriseApresEchec(RACINE)).to.deep.equal(["2026-11-03T14:00:36.000Z"]);
  });

  it("EX-8.9 (composant) : de même après une réponse hors schéma à la soumission (rejeter) : reprise à 14:00:36 (k = 1)", async function () {
    expect(await repriseApresEchec(RACINE, { horsSchema: true })).to.deep.equal(["2026-11-03T14:00:36.000Z"]);
  });

  it("mutant CT-5 EX-8.11 (référence) : sans rejeter_reponse ni anchor_response_rejected, ots-reponses-insuffisantes diverge (tué)", async function () {
    const R = await mutantReference(
      "rejet-ref",
      "        this.emettre(t, \"rejeter_reponse\", d.id, { error_code: att.error_code, class: \"transitoire\" });\n        this.journaliser(t, d.id, { event: \"anchor_response_rejected\", error_code: att.error_code, ...this.rangTentative(d, att.n), provider: null });\n",
      "",
    );
    expect((await ecarts("ots-reponses-insuffisantes", { R })).reference).to.be.above(0);
  });

  it("mutant CT-5 EX-8.12 (référence) : la soumission envoyee non close au démarrage, redemarrage-ots-soumission-envoyee diverge (tué)", async function () {
    // Complément du 2026-11-16 : la condition couvre aussi une ligne a_reprendre qui porte une tentative en cours (EX-8.12).
    const R = await mutantReference("redemarrage-ref", "        if (d.state === \"envoyee\" || (d.state === \"a_reprendre\" && d.attempts.some((a) => a.outcome === \"en_cours\"))) {\n          this.perdreTentatives(d, t);\n", "        if (d.state === \"envoyee\" || (d.state === \"a_reprendre\" && d.attempts.some((a) => a.outcome === \"en_cours\"))) {\n");
    expect((await ecarts("redemarrage-ots-soumission-envoyee", { R })).reference).to.be.above(0);
  });

  it("mutants CT-5 EX-8.11 (composant) : code calendriers_insuffisants, ou attestation Bitcoin d'un seul calendrier admise, ots-reponses-insuffisantes diverge (tués)", async function () {
    // Complément du 2026-11-16 : le code est choisi entre reponses_insuffisantes et preuve_absente (EX-8.11).
    const code = await composant(mutantComposant("code-comp", "      const code = insuffisantes ? \"reponses_insuffisantes\" : \"preuve_absente\";", "      const code = insuffisantes ? \"calendriers_insuffisants\" : \"preuve_absente\";"));
    expect((await ecarts("ots-reponses-insuffisantes", { C: code })).composant).to.be.above(0);
    const seuil = await composant(mutantComposant("seuil-comp", "    const assez = req.state === \"en_attente\" || data.calendars_answered >= o.min_responses;", "    const assez = true;"));
    expect((await ecarts("ots-reponses-insuffisantes", { C: seuil })).composant).to.be.above(0);
  });

  it("mutant CT-5 EX-8.12 (composant) : la soumission envoyee laissée en_cours au démarrage, redemarrage-ots-soumission-envoyee diverge (tué)", async function () {
    const C = await composant(mutantComposant("redemarrage-comp", "          for (const a of d.attempts) {\n            if (a.outcome !== \"en_cours\") continue;\n            a.outcome = \"echec_transitoire\";\n            a.error_code = \"redemarrage\";\n            a.detail = \"redemarrage : reponse non recue\";\n            a.next_at = this.horodatage(this.now);\n          }\n          d.due_at = this.horodatage(this.now);\n          this.ecrire(d, \"a_reprendre\");\n          this.programmer(d, this.now, \"immediat\", \"reprise_ots\");", "          d.due_at = this.horodatage(this.now);\n          this.ecrire(d, \"a_reprendre\");\n          this.programmer(d, this.now, \"immediat\", \"reprise_ots\");"));
    expect((await ecarts("redemarrage-ots-soumission-envoyee", { C })).composant).to.be.above(0);
  });

  it("mutants CT-5 EX-8.9 (composant) : k compté sur toutes les tentatives en échec, la série relue n'est plus interrompue par redemarrage (tués)", async function () {
    const reponse = mutantComposant("k-reponse-comp", "      const { d: attente } = this.attenteReprise(req, { id: null }, {}, null);\n      const at = this.now + attente;", `      const at = ${ANCIENNE_ATTENTE};`);
    expect((await ecarts("redemarrage-ots-soumission-envoyee", { C: await composant(reponse) })).composant).to.be.above(0);
    expect(await repriseApresEchec(reponse)).to.not.deep.equal(["2026-11-03T14:00:36.000Z"]);
    const horsSchema = mutantComposant("k-hors-schema-comp", "      const at = this.now + this.attenteReprise(req, { id: null }, {}, null).d;", `      const at = ${ANCIENNE_ATTENTE};`);
    expect(await repriseApresEchec(horsSchema, { horsSchema: true })).to.not.deep.equal(["2026-11-03T14:00:36.000Z"]);
  });

  it("INDEX.md et CT-5 (A.3, A.4, EX-8.11, EX-8.12, note de révision) nomment les deux traces ; A.4 compte soixante-deux traces, vingt-cinq à file (complément du 2026-11-16)", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5 "));
    for (const id of ["ots-reponses-insuffisantes", "redemarrage-ots-soumission-envoyee"]) {
      expect(index).to.include(`| \`${id}.json\` |`);
      expect(a3).to.include(`${id}.json`);
      expect(ct5).to.include(`trace \`${id}\``);
    }
    expect(index).to.include("`redemarrage-ots-soumission-envoyee.avant.ndjson`");
    expect(a3).to.include("quarante traces");
    // A.4 (complément du 2026-11-16, ordre du démarrage : cinq traces de plus, quatre à file ; clé de chaîne du verrou d'EX-9.4 : une de plus, sans file ; minuteries de deux journaux, EX-8.16 : une de plus, sans file ; puis refus de l'ancre d'une période et ordre des ancres de points, EX-8.10 et EX-9.4 : deux de plus, dont une à file ; puis l'ancre de la période après celle de son point de clôture et l'âge d'abandon OpenTimestamps, EX-9.4 et EX-8.11 : deux de plus, dont une à file ; puis la clé retenue par l'ancre d'une période, la soumission OpenTimestamps tardive et l'alerte du refus après un redémarrage, EX-9.4, EX-8.11 et EX-8.10 : trois de plus, dont deux à file ; puis l'ancre d'un point en reprise quand le point suivant de sa période est admis, EX-9.5 et EX-9.4 : une de plus, sans file) : soixante-deux traces, vingt-cinq à file.
    expect(a4).to.include("les soixante-deux traces de 8.10 et A.3");
    expect(a4).to.include("(vingt-cinq traces)");
    expect(ct5).to.include("code `reponses_insuffisantes`");
  });
});
