// Renvois par numéro de ligne (« l. N ») entre les spécifications de spec/,
// complément du 2026-11-17 : une citation décalée fait échouer le contrôle.
//
// - Tables de traçabilité : les numéros de ligne de la table 0.2 de CT-7 sont,
//   section par section, ceux des occurrences de « CT-7 » (RV-7 de
//   scripts/conformite/verifier-renvois.mjs, CT-7 annexe A.10) ; ceux de la
//   table de 0.2 de la spécification du déploiement, ceux des occurrences de
//   « CT-8 » (scripts/deploiement/renvois.mjs, annexe A.2 de cette
//   spécification).
// - Renvois écrits hors de ces tables (« `spec/CT-n-….md` l. N », « CT-n
//   l. N », « CT-n §s, …, l. N ») : chaque plage désigne son ancre
//   (`ANCRES_LIGNES`, RV-3), et chaque ancre est désignée.
//
// Copies altérées en mémoire (RV-3, RV-7) ou dans un répertoire temporaire
// (renvois.mjs, qui lit spec/ sur le disque) ; le dépôt passe.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as S from "../scripts/lib/securite.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as R from "../scripts/conformite/verifier-renvois.mjs";
import * as D from "../scripts/deploiement/renvois.mjs";
import { creerRepertoireTemporaire } from "./aides/temporaires.mjs";

const SPEC = path.join(PROJECT_ROOT, "spec");
const lire = (f) => fs.readFileSync(path.join(SPEC, f), "utf8");
const TEXTES = Object.fromEntries(Object.entries(R.FICHIERS_CITATIONS).map(([k, f]) => [k, lire(f)]));
const SPECS = S.lireSpecifications(SPEC);
const README = lire("README.md");
const CT7_VECTEURS = path.join(SPEC, "vecteurs", "ct-7");
const lireJSON = (f) => J.analyserJSONStrict(fs.readFileSync(path.join(CT7_VECTEURS, f)));

describe("renvois par numéro de ligne entre les spécifications (complément du 2026-11-17 ; CT-7 RV-3 et RV-7, annexe A.10 ; vérificateur de renvois du déploiement)", function () {
  this.timeout(120000);
  let entrees;
  const ids = (erreurs) => [...new Set(erreurs.map((e) => e.id))];
  const messages = (erreurs, id) => erreurs.filter((e) => e.id === id).map((e) => e.message);

  before(function () {
    const base = { specs: SPECS, readme: README, menaces: lireJSON("menaces.json"), cles: lireJSON("cles-de-test.json"), clesRecalculees: S.clesDeTest(path.join(SPEC, "vecteurs")), textes: TEXTES };
    entrees = (modif = {}) => ({ ...base, ...modif, textes: { ...base.textes, ...(modif.textes ?? {}) } });
  });

  /** Décale d'une unité le numéro de ligne de la ligne de table `id` (« (l. N) »). */
  const decalerLigneTable = (texte, id) => {
    const rx = new RegExp(`^(\\| ${id} \\| .*? \\(l\\. )([0-9]+)(\\) \\|)`, "m");
    expect(rx.test(texte), id).to.equal(true);
    return texte.replace(rx, (_, a, n, b) => `${a}${Number(n) + 1}${b}`);
  };

  it("le dépôt passe : RV-3 et RV-7 sans erreur sur CT-1 à CT-9 et spec/README.md, renvois.mjs sans écart ; chaque renvoi par numéro de ligne hors des tables désigne son ancre (28 citations, 42 ancres)", function () {
    const e = R.verifierRV(entrees());
    expect(e.filter((x) => ["RV-3", "RV-7"].includes(x.id)), JSON.stringify(e)).to.deep.equal([]);
    expect(R.verifierCitationsLignes(TEXTES)).to.deep.equal([]);
    const citations = Object.values(TEXTES).flatMap((t) => R.citationsLignes(t));
    expect(citations).to.have.length(28);
    expect(R.ANCRES_LIGNES).to.have.length(42);
    expect(D.verifierRenvois(PROJECT_ROOT).erreurs).to.deep.equal([]);
  });

  it("RV-7 : un numéro de ligne de la table 0.2 de CT-7 décalé d'une unité (TR-47, CT-4 §1) fait échouer RV-7, le nombre de lignes restant égal", function () {
    const e = R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": decalerLigneTable(SPECS["CT-7"], "TR-47") } }));
    expect(messages(e, "RV-7").join("\n")).to.match(/CT-4 §1 : .*TR-47 .*citation décalée/);
  });

  it("une ligne insérée en tête de CT-4 (révision qui déplace le texte) : RV-7 échoue sur les lignes TR- de CT-4, RV-3 sur les renvois hors des tables vers CT-4 (déploiement, plan de tests), sans que les comptes changent", function () {
    const ct4 = SPECS["CT-4"].replace("\n", "\nLigne ajoutée.\n");
    const e = R.verifierRV(entrees({ specs: { ...SPECS, "CT-4": ct4 }, textes: { "CT-4": ct4 } }));
    expect(messages(e, "RV-7").some((m) => /occurrence\(s\)/.test(m)), "comptes égaux").to.equal(false);
    expect(messages(e, "RV-7").filter((m) => m.startsWith("CT-4 ")).length).to.be.at.least(5);
    expect(messages(e, "RV-3").some((m) => /^CT-8 l\. [0-9]+ : « `spec\/CT-4-registre\.md` l\./.test(m))).to.equal(true);
    expect(messages(e, "RV-3").some((m) => /^CT-9 l\. [0-9]+ : « CT-4 l\. /.test(m))).to.equal(true);
  });

  it("RV-3 : un renvoi hors des tables décalé d'une ligne (« CT-4 l. … » des relectures de CT-4 §7.12, dans le plan de tests) n'a plus d'ancre ; l'ancre qu'il désignait reste désignée par les deux autres citations", function () {
    const lignes = TEXTES["CT-9"].split("\n");
    const toutes = R.citationsLignes(TEXTES["CT-9"]).filter((x) => x.vers === "CT-4" && x.plages.length === 1 && x.texte.startsWith("CT-4 l."));
    expect(toutes.length).to.equal(3);
    const c = toutes.find((x) => lignes[x.ligne - 1].includes(`l. ${x.plages[0].join("-")}`));
    const [a, b] = c.plages[0];
    lignes[c.ligne - 1] = lignes[c.ligne - 1].replace(`l. ${a}-${b}`, `l. ${a + 1}-${b + 1}`);
    const e = R.verifierRV(entrees({ textes: { "CT-9": lignes.join("\n") } }));
    expect(messages(e, "RV-3"), JSON.stringify(e)).to.have.length(1);
    expect(messages(e, "RV-3")[0]).to.match(new RegExp(`^CT-9 l\\. ${c.ligne} : .* sans ancre \\(citation décalée`));
  });

  it("RV-3 : une plage dont seule la dernière ligne est décalée (`spec/CT-4-registre.md` l. a-b devenu a-(b + 1), dans le déploiement) n'a plus d'ancre", function () {
    const c = R.citationsLignes(TEXTES["CT-8"]).find((x) => x.vers === "CT-4" && x.plages.length === 1 && x.plages[0][0] < x.plages[0][1]);
    const [a, b] = c.plages[0];
    const lignes = TEXTES["CT-8"].split("\n");
    expect(lignes[c.ligne - 1]).to.include(`l. ${a}-${b}`);
    lignes[c.ligne - 1] = lignes[c.ligne - 1].replace(`l. ${a}-${b}`, `l. ${a}-${b + 1}`);
    const e = R.verifierRV(entrees({ textes: { "CT-8": lignes.join("\n") } }));
    expect(messages(e, "RV-3").join("\n")).to.match(new RegExp(`^CT-8 l\\. ${c.ligne} : .* plage ${a}-${b + 1} de CT-4 sans ancre`, "m"));
  });

  it("RV-3 : un renvoi retiré laisse son ancre désignée par aucune citation ; un renvoi nouveau sans ancre échoue", function () {
    const retire = TEXTES["CT-8"].replace(/`spec\/CT-2-enregistreur\.md` l\. ([0-9]+) \|/, "`spec/CT-2-enregistreur.md`, glossaire |");
    expect(retire).to.not.equal(TEXTES["CT-8"]);
    const e1 = R.verifierRV(entrees({ textes: { "CT-8": retire } }));
    expect(messages(e1, "RV-3").join("\n")).to.match(/ancre CT-8 → CT-2 « \| Point d'observation .* désignée par aucune citation/);
    const ajout = TEXTES["CT-5"] + "\nVoir CT-1 §8, règle 5, l. 12.\n";
    const e2 = R.verifierRV(entrees({ textes: { "CT-5": ajout } }));
    expect(messages(e2, "RV-3").join("\n")).to.match(/^CT-5 l\. [0-9]+ : « CT-1 §8, règle 5, l\. 12 » : plage 12 de CT-1 sans ancre/m);
  });

  it("renvois.mjs : un numéro de ligne de la table de 0.2 du déploiement décalé d'une unité (TC-51, CT-4 §1) est un écart, comptes égaux ; sur le dépôt, la commande rend 0", function () {
    const dir = creerRepertoireTemporaire("noortrace-renvois-lignes-", process.env.NOORTRACE_TMP ?? os.tmpdir());
    try {
      fs.mkdirSync(path.join(dir, "spec"));
      for (const f of fs.readdirSync(SPEC).filter((x) => x.endsWith(".md"))) fs.copyFileSync(path.join(SPEC, f), path.join(dir, "spec", f));
      expect(D.verifierRenvois(dir).erreurs).to.deep.equal([]);
      fs.writeFileSync(path.join(dir, "spec", D.FICHIER_CT8), decalerLigneTable(lire(D.FICHIER_CT8), "TC-51"));
      const r = D.verifierRenvois(dir);
      expect(r.occurrences).to.equal(r.lignes);
      expect(r.erreurs.join("\n")).to.match(/CT-4 §1 : .*TC-51 .*citation décalée/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    const cli = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "deploiement", "renvois.mjs")], { encoding: "utf8" });
    expect(cli.status, cli.stdout).to.equal(0);
  });
});
