// CT-5 EX-8.11 (complément du 2026-11-16) : l'âge d'abandon d'une preuve
// OpenTimestamps en attente (`upgrade.give_up_after_s`, alerte `ots_give_up`)
// court depuis `created_at` de la demande, écrit à sa création et porté par
// chaque ligne, au démarrage comme en marche ; la jauge
// `noortrace_anchoring_ots_pending_age_s`, que la règle
// `noortrace_ancrage_ots_abandon` de CT-8 compare à `give_up_after_s`, part de
// la même origine.
//
// Avant : la référence (scripts/lib/ancrage.mjs) comptait depuis la première
// soumission de sa marche, que la soumission reprise après un redémarrage
// remplaçait ; le composant d'ancrage (paquets/ancrage) depuis la preuve en
// attente (`result.obtained_at`), relue au démarrage, et sa jauge aussi.
// L'un et l'autre faisaient repartir l'attente à chaque redémarrage pendant la
// soumission. Trace redemarrage-ots-abandon-origine, à horloge avancée
// (give_up_after_s au minimum du schéma, 3 600 s).
//
// Les vecteurs sont lus dans le dépôt ; le code est lu dans le dépôt, ou sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge). Les mutants sont des
// copies sous NOORTRACE_TMP (défaut os.tmpdir()), détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CT5 = path.join(DEPOT, "spec", "vecteurs", "ct-5");
const TRACE = "redemarrage-ots-abandon-origine";
const COPIES = [];
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;

function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-ots-abandon-${nom}-`));
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

async function ecarts(t, racines = {}) {
  const A = await import(pathToFileURL(path.join(racines.R ?? RACINE, "scripts", "lib", "ancrage.mjs")).href + unique());
  const T = await import(pathToFileURL(path.join(racines.C ?? RACINE, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + unique());
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

/** Jauge noortrace_anchoring_ots_pending_age_s du composant (racine donnée) pour une file, à l'instant donné. */
async function jaugeAge(racine, file, maintenant) {
  const { Supervision } = await import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "supervision.mjs")).href + unique());
  const s = new Supervision({});
  s.releverFile(file, maintenant);
  const m = /^noortrace_anchoring_ots_pending_age_s (\d+)$/m.exec(s.metriques());
  return m ? Number(m[1]) : null;
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-8.11 : l'âge d'abandon d'une preuve OpenTimestamps en attente court depuis created_at de la demande (complément du 2026-11-16)", function () {
  this.timeout(120000);

  it(`${TRACE} : rejouée sans écart par la référence et par le composant`, async function () {
    expect(await ecarts(trace(TRACE))).to.deep.equal({ reference: 0, composant: 0 });
  });

  it(`${TRACE} : soumission close par le redémarrage de 14:30 et reprise, preuve en attente à 14:30:01 ; à 15:01:03, 3 602,75 s après created_at, ots_give_up est levée et la mise à niveau suivante part un jour plus tard`, function () {
    const t = trace(TRACE);
    expect(t.config.opentimestamps.upgrade.give_up_after_s).to.equal(3600);
    const op = t.queue_after.find((d) => d.kind === "ots_periode");
    expect(op.created_at).to.equal("2026-11-03T14:00:00.250Z");
    expect(op.result.obtained_at).to.equal("2026-11-03T14:30:01.000Z");
    expect(t.expected.filter((a) => a.action === "alerter" && a.detail.code === "ots_give_up").map((a) => a.t)).to.deep.equal(["2026-11-03T15:01:03.000Z"]);
    expect(op.due_at).to.equal("2026-11-04T15:01:03.000Z");
  });

  it("jauge noortrace_anchoring_ots_pending_age_s : comptée depuis created_at de la demande (3 600 s à 15:00:00.250), non depuis la preuve en attente (1 799 s)", async function () {
    const op = trace(TRACE).queue_after.find((d) => d.kind === "ots_periode");
    expect(await jaugeAge(RACINE, [op], Date.parse("2026-11-03T15:00:00.250Z"))).to.equal(3600);
  });

  it("CT-5 (EX-8.11, EX-6.6, 8.9, A.3) nomme l'origine et la trace", function () {
    const ct5 = fs.readFileSync(path.join(DEPOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    expect(ct5).to.include("Complément du 2026-11-16 (origine de l'âge d'abandon). Cet âge court depuis `created_at` de la demande");
    expect(ct5).to.include("comptés depuis la création de la demande (EX-8.11, complément du 2026-11-16)");
    expect(ct5).to.include("redemarrage-ots-abandon-origine.json");
  });

  const MUTANTS = [
    ["reference", "depuis-la-preuve", "scripts/lib", "scripts/lib/ancrage.mjs", "    if (t - ms(d.created_at) >= o.upgrade.give_up_after_s * 1000) {", "    if (t - ms(d.result?.obtained_at ?? d.created_at) >= o.upgrade.give_up_after_s * 1000) {"],
    ["composant", "depuis-la-preuve", "paquets/ancrage/src", "paquets/ancrage/src/planificateur/planificateur.mjs", "    const depuis = this.now - ms(req.created_at);", "    const depuis = this.now - ms(req.result?.obtained_at ?? req.created_at);"],
  ];
  for (const [cote, nom, arbre, fichier, ancien, nouveau] of MUTANTS) {
    it(`mutant ${nom} (${cote}) : ${TRACE} diverge (tué)`, async function () {
      const r = copie(`${cote}-${nom}`, arbre, fichier, ancien, nouveau);
      const e = await ecarts(trace(TRACE), cote === "reference" ? { R: r } : { C: r });
      expect(e[cote]).to.not.equal(0);
    });
  }

  it("mutant jauge-depuis-la-preuve (composant) : la jauge rend 1 799 s (tué)", async function () {
    const r = copie("jauge", "paquets/ancrage/src", "paquets/ancrage/src/planificateur/supervision.mjs", "        const t = decoderHorodatage(d.created_at);", "        const t = decoderHorodatage(d.result.obtained_at);");
    const op = trace(TRACE).queue_after.find((d) => d.kind === "ots_periode");
    expect(await jaugeAge(r, [op], Date.parse("2026-11-03T15:00:00.250Z"))).to.equal(1799);
  });
});
