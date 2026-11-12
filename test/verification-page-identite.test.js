// Page de vérification (CT-6 §18, révision 0.6) : identité du rapport de la
// page et de celui du binaire (EX-18.10), sous Node.
//
// travailleur.js, tel que construire.mjs le produit (prélude, wasm_exec.js de
// go1.27.3 sans changement, pilote), est exécuté dans un contexte `vm` qui
// n'offre que ce qu'offre un travailleur dédié du navigateur ; le pilote y
// reçoit l'artefact puis les fichiers de chaque vérification, comme de la
// page. Chaque dossier de spec/vecteurs/ct-1/dossiers et de
// spec/vecteurs/ct-6/dossiers, sans et avec ancres-test.json, sans et avec
// chaine.json, en français et en anglais, sans et avec --exiger 4,5,8, plus
// une configuration avec --detail et --exiger tous, rend les mêmes sorties
// standard et d'erreur et le même code, octet pour octet, que le binaire
// natif linux/amd64 de la même construction exécuté avec les arguments
// d'EX-18.8 dans un répertoire /entrees (racine montée par unshare --root).
//
// Sans go1.27.3 (NOORTRACE_GO_BIN, à défaut le PATH), ou sans unshare --root,
// l'essai est mis en attente.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { construireTout, dossiersVecteurs, enAttente, environnementGo, essaiRacineNatif, repertoireTemporaire, sha256, VERSION } from "./fixtures/verification-page/outils.mjs";

const FIL = new URL("./fixtures/verification-page/identite-fil.mjs", import.meta.url);

/** Les configurations d'EX-18.13 (1), plus une avec --detail et --exiger tous. */
function configurations() {
  const r = [];
  for (const ancres of [false, true]) {
    for (const entetes of [false, true]) {
      for (const langue of ["fr", "en"]) {
        for (const exiger of [null, "4,5,8"]) r.push({ ancres, entetes, langue, exiger, detail: false });
      }
    }
  }
  r.push({ ancres: true, entetes: true, langue: "en", exiger: "tous", detail: true });
  return r;
}

describe("page de vérification : même rapport que le binaire (CT-6 EX-18.10)", function () {
  this.timeout(60 * 60 * 1000);
  let dir;
  let construit = null;
  let attente = null;

  before(function () {
    const env = environnementGo();
    if (env === null) {
      attente = "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)";
      return;
    }
    dir = repertoireTemporaire("noortrace-page-identite");
    construit = construireTout(dir, env);
    const raison = essaiRacineNatif(construit.natif);
    if (raison !== null) attente = `binaire natif non exécutable dans /entrees (${raison})`;
  });

  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("les 190 dossiers × (sans, avec ancres) × (sans, avec chaine.json) × (fr, en) × (sans, avec --exiger 4,5,8), et --detail : sorties et codes égaux octet pour octet, lisible et --json", async function () {
    if (attente) return enAttente(this, attente);
    const dossiers = dossiersVecteurs();
    expect(dossiers).to.have.length(190);
    const configs = configurations();
    const n = Math.max(1, Math.min(4, os.availableParallelism ? os.availableParallelism() : os.cpus().length));
    const lots = Array.from({ length: n }, () => []);
    dossiers.forEach((d, i) => lots[i % n].push(d));
    const resultats = await Promise.all(lots.map((lot, i) => new Promise((resoudre, rejeter) => {
      const w = new Worker(FIL, {
        workerData: {
          travailleur: path.join(construit.page, "travailleur.js"),
          wasm: path.join(construit.page, "noortrace-verifier.wasm"),
          natif: construit.natif,
          racine: path.join(dir, `racine-${i}`),
          dossiers: lot,
          configurations: configs,
        },
      });
      let fin = null;
      w.on("message", (m) => {
        if (m.type === "fin") fin = m;
      });
      w.on("error", rejeter);
      w.on("exit", (code) => (fin ? resoudre(fin) : rejeter(new Error(`fil ${i} terminé sans résultat (code ${code})`))));
    })));
    const discordances = resultats.flatMap((x) => x.discordances);
    const executions = resultats.reduce((s, x) => s + x.executions, 0);
    const codes = {};
    for (const x of resultats) for (const [k, v] of Object.entries(x.codes)) codes[k] = (codes[k] ?? 0) + v;
    console.log(`      identité : ${executions} exécutions comparées, codes du binaire ${JSON.stringify(codes)}, ${discordances.length} discordance(s)`);
    expect(discordances, discordances.slice(0, 20).join("\n")).to.deep.equal([]);
    expect(executions).to.equal(190 * configs.length * 2);
    // Les quatre codes sont représentés.
    for (const c of ["0", "1", "2", "3"]) expect(codes[c] ?? 0, `code ${c}`).to.be.above(0);
    // Version et empreinte annoncées par le travailleur : celles de l'artefact.
    const wasm = fs.readFileSync(path.join(construit.page, "noortrace-verifier.wasm"));
    for (const x of resultats) {
      expect(x.version).to.equal(VERSION);
      expect(x.empreinte).to.equal(`0x${sha256(wasm)}`);
      if (x.versionJson !== null) expect(x.versionJson).to.equal(VERSION);
    }
  });
});
