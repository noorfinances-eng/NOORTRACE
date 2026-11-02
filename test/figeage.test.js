// Tests du figeage de la conception v1.0 (spec/figeage/LISEZMOI.md ;
// scripts/lib/figeage.mjs, scripts/conception/figeage.mjs).
//
// Ce fichier exige : que le dépôt soit conforme (chaque écart à la
// conception figée consigné), que le manifeste soit au format de sha256sum et
// que son condensé soit celui du registre ; puis, sur des états construits en
// mémoire, que chaque modification, ajout ou suppression non consigné soit
// signalé, qu'une chaîne de modifications consignées soit acceptée, qu'un
// registre mal formé ou un manifeste retouché soit refusé, et que la
// consignation produise l'entrée attendue. Rien n'est écrit dans le dépôt.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as F from "../scripts/lib/figeage.mjs";
import { executer, fichiersPresents } from "../scripts/conception/figeage.mjs";

const sha = (t) => createHash("sha256").update(t).digest("hex");
const ecrivain = () => {
  let texte = "";
  return { write: (s) => { texte += s; }, get texte() { return texte; } };
};

// État figé de démonstration : trois fichiers.
const A = sha("a"), B = sha("b"), C = sha("c"), A2 = sha("a2"), D = sha("d");
const TABLE = new Map([["spec/CT-1-x.md", A], ["spec/schemas/s.json", B], ["spec/vecteurs/ct-1/v.json", C]]);
const MANIFESTE = F.ecrireManifeste(TABLE);
const CONDENSE = sha(MANIFESTE);
const registre = (modifications = []) => ({
  conception: "1.0",
  date_figeage: "2026-11-02",
  manifeste: F.FICHIER_MANIFESTE,
  manifeste_sha256: CONDENSE,
  modifications,
});
const verifier = (fichiers, reg = registre(), manifeste = MANIFESTE) =>
  F.verifierFigeage({ manifeste, condenseManifeste: sha(manifeste), registre: reg, fichiers: new Map(fichiers) });

describe("Figeage de la conception v1.0", function () {
  describe("dépôt", function () {
    it("le dépôt est conforme : chaque écart à la conception figée est consigné (code 0)", function () {
      const sortie = ecrivain();
      const erreur = ecrivain();
      const code = executer(["--json"], { sortie, erreur });
      const rapport = JSON.parse(sortie.texte);
      expect(rapport.erreurs, erreur.texte).to.deep.equal([]);
      expect(rapport.ecarts).to.deep.equal([]);
      expect(rapport.conforme).to.equal(true);
      expect(code).to.equal(0);
    });

    it("le manifeste est au format de sha256sum, trié, et son condensé est celui du registre", function () {
      const octets = fs.readFileSync(path.join(PROJECT_ROOT, F.FICHIER_MANIFESTE));
      const reg = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, F.FICHIER_REGISTRE), "utf8"));
      expect(sha(octets)).to.equal(reg.manifeste_sha256);
      const { table, erreurs } = F.lireManifeste(octets.toString("utf8"));
      expect(erreurs).to.deep.equal([]);
      expect(table.size).to.be.greaterThan(4000);
      for (const chemin of table.keys()) expect(chemin.startsWith(F.REPERTOIRE_FIGEAGE)).to.equal(false);
      expect(F.controlerRegistre(reg)).to.deep.equal([]);
      expect(reg.date_figeage).to.equal("2026-11-02");
    });

    it("la liste des fichiers présents exclut spec/figeage/ et les fichiers ignorés", function () {
      const fichiers = fichiersPresents(PROJECT_ROOT);
      expect([...fichiers.keys()].some((c) => c.startsWith(F.REPERTOIRE_FIGEAGE))).to.equal(false);
      expect(fichiers.has("spec/CT-1-evenements-et-formats.md")).to.equal(true);
      expect(fichiers.has("spec/vecteurs/ct-2/verificateur-independant/noortrace-ct2")).to.equal(false);
    });

    it("usage incorrect : code 2", function () {
      expect(executer(["--inconnu"], { sortie: ecrivain(), erreur: ecrivain() })).to.equal(2);
      expect(executer(["--motif", "x"], { sortie: ecrivain(), erreur: ecrivain() })).to.equal(2);
      expect(executer(["--consigner", "--initialiser"], { sortie: ecrivain(), erreur: ecrivain() })).to.equal(2);
      expect(executer(["--initialiser", "--date", "2026-11-02"], { sortie: ecrivain(), erreur: ecrivain() })).to.equal(2);
    });
  });

  describe("vérification sur des états construits", function () {
    it("état figé intact : aucune erreur, aucun écart", function () {
      const r = verifier(TABLE);
      expect(r.erreurs).to.deep.equal([]);
      expect(r.ecarts).to.deep.equal([]);
    });

    it("modification, ajout et suppression non consignés : trois écarts nommés", function () {
      const r = verifier([["spec/CT-1-x.md", A2], ["spec/schemas/s.json", B], ["spec/nouveau.md", D]]);
      expect(r.erreurs).to.deep.equal([]);
      expect(r.ecarts.map((e) => [e.chemin, e.nature])).to.deep.equal([
        ["spec/CT-1-x.md", "modifié sans consignation"],
        ["spec/nouveau.md", "ajouté sans consignation"],
        ["spec/vecteurs/ct-1/v.json", "supprimé sans consignation"],
      ]);
    });

    it("chaîne de modifications consignées : acceptée", function () {
      const reg = registre([
        { id: "MC-1", date: "2026-11-03", etape: 1, motif: "Première retouche.", fichiers: [{ chemin: "spec/CT-1-x.md", avant: A, apres: A2 }] },
        { id: "MC-2", date: "2026-11-03", etape: null, motif: "Ajout et retrait.", fichiers: [
          { chemin: "spec/CT-1-x.md", avant: A2, apres: A },
          { chemin: "spec/nouveau.md", avant: null, apres: D },
          { chemin: "spec/vecteurs/ct-1/v.json", avant: C, apres: null },
        ] },
      ]);
      const r = verifier([["spec/CT-1-x.md", A], ["spec/schemas/s.json", B], ["spec/nouveau.md", D]], reg);
      expect(r.erreurs).to.deep.equal([]);
      expect(r.ecarts).to.deep.equal([]);
    });

    it("condensé « avant » qui ne suit pas l'état rejoué : erreur", function () {
      const reg = registre([{ id: "MC-1", date: "2026-11-03", etape: 1, motif: "x", fichiers: [{ chemin: "spec/CT-1-x.md", avant: B, apres: A2 }] }]);
      const r = verifier([["spec/CT-1-x.md", A2], ["spec/schemas/s.json", B], ["spec/vecteurs/ct-1/v.json", C]], reg);
      expect(r.erreurs.some((e) => e.includes("ne correspond pas à l'état rejoué"))).to.equal(true);
    });

    it("manifeste retouché : erreur, même si les fichiers suivent le manifeste retouché", function () {
      const retouche = F.ecrireManifeste(new Map([...TABLE, ["spec/CT-1-x.md", A2]]));
      const r = F.verifierFigeage({ manifeste: retouche, condenseManifeste: sha(retouche), registre: registre(), fichiers: new Map([...TABLE, ["spec/CT-1-x.md", A2]]) });
      expect(r.erreurs.some((e) => e.startsWith("manifeste modifié"))).to.equal(true);
    });

    it("manifeste mal formé : non trié, en double, hors périmètre, sans saut de ligne final", function () {
      const z = sha("z");
      expect(F.lireManifeste(`${z}  spec/b\n${z}  spec/a\n`).erreurs.join("\n")).to.include("non triés");
      expect(F.lireManifeste(`${z}  spec/a\n${z}  spec/a\n`).erreurs.join("\n")).to.include("en double");
      expect(F.lireManifeste(`${z}  scripts/a\n`).erreurs.join("\n")).to.include("hors du périmètre");
      expect(F.lireManifeste(`${z}  spec/figeage/x\n`).erreurs.join("\n")).to.include("hors du périmètre");
      expect(F.lireManifeste(`${z}  spec/../a\n`).erreurs.join("\n")).to.include("hors du périmètre");
      expect(F.lireManifeste(`${z}  spec/a`).erreurs.join("\n")).to.include("saut de ligne");
      expect(F.lireManifeste(`${z} spec/a\n`).erreurs.join("\n")).to.include("forme attendue");
    });

    it("registre mal formé : identifiant, date, étape, motif, membres, avant égal à après", function () {
      const base = { id: "MC-1", date: "2026-11-03", etape: 1, motif: "x", fichiers: [{ chemin: "spec/a", avant: A, apres: A2 }] };
      const erreurs = (mod) => F.controlerRegistre(registre([mod])).join("\n");
      expect(erreurs({ ...base, id: "MC-2" })).to.include("au lieu de « MC-1 »");
      expect(erreurs({ ...base, date: "2026-11-01" })).to.include("antérieure");
      expect(erreurs({ ...base, date: "2026-13-01" })).to.include("AAAA-MM-JJ");
      expect(erreurs({ ...base, etape: 9 })).to.include("etape");
      expect(erreurs({ ...base, motif: "  " })).to.include("motif vide");
      expect(erreurs({ ...base, auteur: "x" })).to.include("inconnu");
      expect(erreurs({ ...base, fichiers: [] })).to.include("non vide");
      expect(erreurs({ ...base, fichiers: [{ chemin: "spec/a", avant: A, apres: A }] })).to.include("égaux");
      expect(erreurs({ ...base, fichiers: [{ chemin: "spec/b", avant: A, apres: A2 }, { chemin: "spec/a", avant: A, apres: A2 }] })).to.include("non triés");
      expect(F.controlerRegistre({ ...registre(), conception: "1.1" }).join("\n")).to.include("conception");
    });

    it("consignation : une entrée MC-n avec les écarts constatés, puis état conforme", function () {
      const fichiers = new Map([["spec/CT-1-x.md", A2], ["spec/schemas/s.json", B], ["spec/vecteurs/ct-1/v.json", C], ["spec/nouveau.md", D]]);
      const suivant = F.consignerModification({ manifeste: MANIFESTE, condenseManifeste: CONDENSE, registre: registre(), fichiers, date: "2026-11-03", etape: 1, motif: "Démonstration." });
      expect(suivant.modifications).to.deep.equal([{
        id: "MC-1", date: "2026-11-03", etape: 1, motif: "Démonstration.",
        fichiers: [{ chemin: "spec/CT-1-x.md", avant: A, apres: A2 }, { chemin: "spec/nouveau.md", avant: null, apres: D }],
      }]);
      const r = F.verifierFigeage({ manifeste: MANIFESTE, condenseManifeste: CONDENSE, registre: suivant, fichiers });
      expect(r.erreurs).to.deep.equal([]);
      expect(r.ecarts).to.deep.equal([]);
      expect(() => F.consignerModification({ manifeste: MANIFESTE, condenseManifeste: CONDENSE, registre: suivant, fichiers, date: "2026-11-03", etape: 1, motif: "x" })).to.throw("rien à consigner");
    });
  });
});
