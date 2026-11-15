// Figeage de la conception (scripts/lib/figeage.mjs, scripts/conception/figeage.mjs ;
// spec/figeage/LISEZMOI.md) : corrections de la revue de sécurité interne de
// l'étape 8 (fichier de spec/ au nom non figeable ignoré en
// silence, date future admise, caractère bidirectionnel admis).
//
// Chaque essai éprouve ensuite un mutant de la règle (copie de scripts/lib sous
// NOORTRACE_TMP, règle retirée, oracle en échec, copie détruite). Racine des
// scripts éprouvés : le dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const sha256 = (o) => crypto.createHash("sha256").update(o).digest("hex");

const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "figeage.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-figeage-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  const f = path.join(racine, "scripts", "lib", "figeage.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

/** Manifeste et registre d'un état figé minimal, construits en mémoire. */
function etatMinimal(F) {
  const table = new Map([["spec/CT-1.md", "a".repeat(64)], ["spec/vecteurs/x.json", "b".repeat(64)]]);
  const manifeste = F.ecrireManifeste(table);
  const condense = sha256(Buffer.from(manifeste, "utf8"));
  const registre = { conception: F.VERSION_CONCEPTION, date_figeage: "2026-11-02", manifeste: F.FICHIER_MANIFESTE, manifeste_sha256: condense, modifications: [] };
  return { manifeste, condense, registre, fichiers: new Map(table) };
}

describe("Figeage, référence : chemins non figeables, caractères bidirectionnels, date future", function () {
  let F;
  before(async function () {
    F = await importer(RACINE);
  });

  const oracleChemins = (M) => {
    const e = etatMinimal(M);
    const fichiers = new Map(e.fichiers);
    fichiers.set("spec/vecteurs/a‮b.md", "c".repeat(64));
    fichiers.set("spec/x\\y.md", "d".repeat(64));
    fichiers.set("spec/figeage/modifications.json", "e".repeat(64));
    const v = M.verifierFigeage({ manifeste: e.manifeste, condenseManifeste: e.condense, registre: e.registre, fichiers });
    const nonAdmis = v.erreurs.filter((x) => /nom non admis sous spec\//.test(x));
    return nonAdmis.length === 2 && nonAdmis.some((x) => x.includes("a\u202eb.md")) && nonAdmis.some((x) => x.includes("x\\\\y.md")) && !v.erreurs.some((x) => x.includes("spec/figeage/")) && v.ecarts.length === 0;
  };

  it("cheminFigeable refuse un caractère de format bidirectionnel (U+202E, U+2066), « spec/figeage » lui-même et une barre inverse ; verifierFigeage signale en erreur, jamais en silence, un fichier présent au nom non figeable ; spec/figeage/ reste hors du périmètre", function () {
    expect(F.cheminFigeable("spec/vecteurs/a‮b.md")).to.equal(false);
    expect(F.cheminFigeable("spec/vecteurs/a⁦b.md")).to.equal(false);
    expect(F.cheminFigeable("spec/figeage")).to.equal(false);
    expect(F.cheminFigeable("spec/figeagex/x.md")).to.equal(true);
    expect(F.cheminFigeable("spec/x\\y.md")).to.equal(false);
    expect(F.cheminFigeable("spec/CT-1-evenements-et-formats.md")).to.equal(true);
    expect(F.sousFigeage("spec/figeage/modifications.json")).to.equal(true);
    expect(F.sousFigeage("spec/figeage")).to.equal(true);
    expect(F.sousFigeage("spec/figeagex/x.md")).to.equal(false);
    expect(oracleChemins(F)).to.equal(true);
  });

  it("mutant (chemins) : avec le « continue » d'origine, le fichier au nom non figeable n'est ni dans l'état ni dans les écarts (tué par l'oracle)", async function () {
    const M = await importer(mutant("chemins", 'if (!cheminFigeable(chemin)) {\n      erreurs.push(`fichier au nom non admis sous spec/ : ${JSON.stringify(chemin)} (chemin non figeable : barre inverse, caractère de contrôle ou de format bidirectionnel, composant vide, « . » ou « .. »)`);\n      continue;\n    }', "if (!cheminFigeable(chemin)) continue;"));
    expect(oracleChemins(M)).to.equal(false);
  });

  const oracleDate = (M) => {
    const e = etatMinimal(M);
    const r = structuredClone(e.registre);
    r.modifications.push({ id: "MC-1", date: "2999-12-31", etape: 8, motif: "essai", fichiers: [{ chemin: "spec/CT-1.md", avant: "a".repeat(64), apres: "f".repeat(64) }] });
    const erreurs = M.controlerRegistre(r, { dateMax: "2026-11-13" });
    const sansBorne = M.controlerRegistre(r);
    return erreurs.length === 1 && /postérieure au jour de la vérification 2026-11-13/.test(erreurs[0]) && sansBorne.length === 0;
  };

  it("une modification datée après le jour de la vérification (dateMax) est une erreur du registre ; la date du jour elle-même est admise ; sans dateMax, la forme seule est contrôlée", function () {
    expect(oracleDate(F)).to.equal(true);
    const e = etatMinimal(F);
    const r = structuredClone(e.registre);
    r.modifications.push({ id: "MC-1", date: "2026-11-13", etape: 8, motif: "essai", fichiers: [{ chemin: "spec/CT-1.md", avant: "a".repeat(64), apres: "f".repeat(64) }] });
    expect(F.controlerRegistre(r, { dateMax: "2026-11-13" })).to.deep.equal([]);
    expect(() => F.consignerModification({ manifeste: e.manifeste, condenseManifeste: e.condense, registre: e.registre, fichiers: new Map([["spec/CT-1.md", "f".repeat(64)], ["spec/vecteurs/x.json", "b".repeat(64)]]), date: "2999-12-31", etape: 8, motif: "essai", dateMax: "2026-11-13" })).to.throw(/postérieure au jour/);
  });

  it("mutant (date) : sans la borne haute, 2999-12-31 passe le registre (tué par l'oracle)", async function () {
    const M = await importer(mutant("date", "else if (typeof dateMax === \"string\" && mod.date > dateMax) erreurs.push(`${lieu} : date ${mod.date} postérieure au jour de la vérification ${dateMax}`);\n", ""));
    expect(oracleDate(M)).to.equal(false);
  });

  it("outil : scripts/conception/figeage.mjs rend 1 et nomme un fichier à barre inverse ajouté sous spec/ d'un dépôt d'essai, 0 une fois le fichier retiré ; --consigner --date dans le futur est refusé (code 2) sans rien écrire", function () {
    this.timeout(60000);
    const depot = fs.mkdtempSync(path.join(TMP, "noortrace-revue-figeage-depot-"));
    MUTANTS.push(depot);
    const git = (...a) => spawnSync("git", a, { cwd: depot, encoding: "utf8" });
    expect(git("init", "-q").status).to.equal(0);
    fs.mkdirSync(path.join(depot, "spec"));
    fs.writeFileSync(path.join(depot, "spec", "CT-1.md"), "texte\n");
    const outil = (...a) => spawnSync(process.execPath, [path.join(RACINE, "scripts", "conception", "figeage.mjs"), "--racine", depot, ...a], { encoding: "utf8" });
    expect(outil("--initialiser", "--date", "2026-11-02").status).to.equal(0);
    expect(outil().status).to.equal(0);
    fs.writeFileSync(path.join(depot, "spec", "x\\y.md"), "ajout\n");
    const r = outil();
    expect(r.status).to.equal(1);
    expect(r.stdout).to.match(/\[ERREUR\] fichier au nom non admis sous spec\/ : "spec\/x\\\\y\.md"/);
    fs.rmSync(path.join(depot, "spec", "x\\y.md"));
    expect(outil().status).to.equal(0);
    fs.writeFileSync(path.join(depot, "spec", "CT-1.md"), "texte modifié\n");
    const registreAvant = fs.readFileSync(path.join(depot, "spec", "figeage", "modifications.json"), "utf8");
    const futur = outil("--consigner", "--motif", "essai", "--date", "2999-12-31");
    expect(futur.status).to.equal(2);
    expect(futur.stderr).to.match(/postérieure au jour de la consignation/);
    expect(fs.readFileSync(path.join(depot, "spec", "figeage", "modifications.json"), "utf8")).to.equal(registreAvant);
    expect(outil("--consigner", "--motif", "essai", "--etape", "8").status).to.equal(0);
    expect(outil().status).to.equal(0);
  });
});
