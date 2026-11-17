// CT-5 (complément du 2026-11-16) : deux règles du registre que le texte ne
// tranchait pas, et que la référence (scripts/lib/ancrage.mjs) et le
// composant d'ancrage (paquets/ancrage) suivent désormais ensemble.
//
// - EX-8.10, 8.9 : le refus définitif (`refus_*`) de l'ancre d'une période la
//   reprend au pas `retry.max_ms`, sans gigue, et lève l'alerte
//   `prestataires_epuises` critique, une fois par ancre depuis le démarrage
//   (trace registre-refus-ancre-periode). Avant : aucune alerte, ni dans la
//   référence ni dans le composant.
// - EX-9.4, EX-8.12 : quand la clé de chaîne se libère, part la première
//   candidate de la clé : les ancres de période par `period_start`, puis les
//   ancres de points par `checkpoint_ts`, l'ordre de la file ne départageant
//   que les égalités (trace registre-ordre-des-points, où deux ancres créées
//   au même instant par une reconstruction sont dans l'ordre de la file à
//   rebours de leurs `checkpoint_ts`). Avant : la référence suivait l'ordre
//   de la file, le composant les `checkpoint_ts`.
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
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const COPIES = [];
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;

/** Copie de RACINE (scripts/lib et paquets/ancrage/src), un fichier modifié par un remplacement unique ; rend sa racine. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-refus-ordre-${nom}-`));
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

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, racines = {}) {
  const t = trace(id);
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

/** Une trace diverge : au moins un écart, ou une exception du rejeu (gigue épuisée…). */
const diverge = (n) => n !== 0;

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-5 EX-8.10 : refus définitif de l'ancre d'une période (complément du 2026-11-16)", function () {
  this.timeout(120000);

  it("registre-refus-ancre-periode est rejouée sans écart par la référence et par le composant", async function () {
    expect(await ecarts("registre-refus-ancre-periode")).to.deep.equal({ reference: 0, composant: 0 });
  });

  it("au premier refus : anchor_retry de mode reprise, alerte prestataires_epuises critique, a_reprendre, reprise à retry.max_ms sans gigue ; au second refus, aucune seconde alerte ; la gigue de la trace n'est consommée que par l'échec transitoire", function () {
    const t = trace("registre-refus-ancre-periode");
    const ap = t.queue_after.find((d) => d.kind === "ancre_registre_periode").id;
    const a = (instant) => t.expected.filter((x) => x.t === instant && x.request_id === ap).map((x) => [x.action, x.detail.event ?? x.detail.code ?? x.detail.state ?? x.detail.reason, x.detail.severity ?? x.detail.next_at ?? x.detail.error_code ?? null]);
    expect(a("2026-11-03T14:00:02.000Z")).to.deep.equal([
      ["journaliser", "anchor_retry", "refus_emetteur_inconnu"],
      ["alerter", "prestataires_epuises", "critique"],
      ["ecrire_file", "a_reprendre", null],
      ["programmer", "backoff", "2026-11-03T14:05:02.000Z"],
    ]);
    expect(a("2026-11-03T14:05:03.000Z")).to.deep.equal([
      ["journaliser", "anchor_retry", "refus_emetteur_inconnu"],
      ["ecrire_file", "a_reprendre", null],
      ["programmer", "backoff", "2026-11-03T14:10:03.000Z"],
    ]);
    expect(t.jitter_ms).to.deep.equal([137]);
    expect(t.expected.find((x) => x.t === "2026-11-03T14:10:04.000Z" && x.action === "programmer" && x.request_id === ap)?.detail.next_at).to.equal("2026-11-03T14:10:24.137Z");
    expect(t.expected.filter((x) => x.action === "alerter" && x.detail.code === "prestataires_epuises")).to.have.lengthOf(1);
  });

  it("mutants : sans l'alerte dans la référence, sans l'alerte dans le composant, ou avec une gigue consommée par le refus : la trace diverge (tués)", async function () {
    const R = mutantReference("alerte-ref", '    if (permanent && !s.alertes.has("prestataires_epuises")) {', '    if (false) {');
    expect(diverge((await ecarts("registre-refus-ancre-periode", { R })).reference)).to.equal(true);
    const C = mutantComposant("alerte-comp", "      if (permanent) {\n        const i = this.interneDe(d.id);", "      if (false) {\n        const i = this.interneDe(d.id);");
    expect(diverge((await ecarts("registre-refus-ancre-periode", { C })).composant)).to.equal(true);
    const G = mutantReference("gigue-ref", "const next = t + (permanent ? r.max_ms : Math.min(", "const next = t + (permanent ? r.max_ms + this.aleatoire.gigue() : Math.min(");
    expect(diverge((await ecarts("registre-refus-ancre-periode", { R: G })).reference)).to.equal(true);
  });
});

describe("CT-5 EX-9.4 : ordre des ancres d'une même clé, au démarrage et en marche (complément du 2026-11-16)", function () {
  this.timeout(120000);

  it("registre-ordre-des-points est rejouée sans écart par la référence et par le composant", async function () {
    expect(await ecarts("registre-ordre-des-points")).to.deep.equal({ reference: 0, composant: 0 });
  });

  it("les ancres de K4 et K5, créées au même instant, sont dans l'ordre de la file à rebours de leurs checkpoint_ts ; au reçu de l'ancre de K3, celle de K4 part, puis celle de K5", function () {
    const t = trace("registre-ordre-des-points");
    const recreees = t.queue_after.filter((d) => d.kind === "ancre_registre_point" && d.created_at === "2026-11-03T14:01:30.000Z");
    const ordreFile = [...recreees].sort((a, b) => (a.id < b.id ? -1 : 1));
    expect(ordreFile.map((d) => d.subject.declared_at)).to.deep.equal(["2026-11-03T14:01:00.000Z", "2026-11-03T14:00:00.250Z"]);
    const envois = t.expected.filter((x) => x.action === "envoyer_registre").map((x) => [x.t, t.queue_after.find((d) => d.id === x.request_id).subject.declared_at]);
    expect(envois).to.deep.equal([
      ["2026-11-03T14:01:30.000Z", "2026-11-03T13:54:00.000Z"],
      ["2026-11-03T14:01:32.000Z", "2026-11-03T14:00:00.250Z"],
      ["2026-11-03T14:01:33.000Z", "2026-11-03T14:01:00.000Z"],
    ]);
  });

  it("mutants : l'ordre de la file seul, dans la référence ou dans le composant : la trace diverge (tués)", async function () {
    // Complément du 2026-11-16 (EX-9.4 : par period_start, puis, dans une période, les points par checkpoint_ts avant la
    // période) : les lignes mutées sont celles de cette règle ; le mutant garde l'ordre de la file seul.
    const R = mutantReference("ordre-file-ref", "    candidats.sort((a, b) => a.subject.period_start - b.subject.period_start || (SORTE_PERIODE(a.kind) ? 1 : 0) - (SORTE_PERIODE(b.kind) ? 1 : 0) || (SORTE_PERIODE(a.kind) ? 0 : ms(a.subject.declared_at) - ms(b.subject.declared_at)));", "    candidats.sort(() => 0);");
    expect(diverge((await ecarts("registre-ordre-des-points", { R })).reference)).to.equal(true);
    const C = mutantComposant("ordre-file-comp", "    candidates.sort(comparerAncresCle);\n    if (this.attendPoints(candidates[0])) return;\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  recuAbsent(d) {", "    candidates.sort(comparerDemandes);\n    if (this.attendPoints(candidates[0])) return;\n    this.dispatcherRegistre(candidates[0]);\n  }\n\n  recuAbsent(d) {");
    expect(diverge((await ecarts("registre-ordre-des-points", { C })).composant)).to.equal(true);
  });
});
