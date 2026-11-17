// Annuaire exporté : instants qui respectent le motif sans se décoder (CT-1 §3)
// au rejeu, et cas que l'INDEX.md de ct-3 nomme (CT-3 EX-13.19, points 4 et 6 ;
// EX-A.10 ; complément du 2026-11-16) :
//   - une opération `expirer` dont l'instant ne se décode pas ne se rejoue pas :
//     le rejeu s'arrête à elle (`/operations/<j>`), en plus de l'écart du point 2 ;
//   - un `received_at` qui ne se décode pas donne `preuve_discordante` ;
//   - les instants que posent les opérations rejouées (`created_at`,
//     `received_at`, `validated_at`, `revoked_at`) sont le texte de leur `at`,
//     et `updated_at` est comparé au texte de l'`at` de la dernière opération :
//     seul le point 2 relève ces opérations ;
//   - l'INDEX.md nomme, dans sa section « Cas nommés », chaque fichier `.json`
//     des vingt répertoires qu'EX-A.10 énumère, dans les deux sens.
// Les quatre cas d'`annuaire/exports/` sont joués sur la bibliothèque de
// référence (`scripts/lib/console.mjs`) et sur le module d'annuaire qu'exécute
// le service (`@noortrace/console/annuaire`). Chaque lecture retirée de la
// référence (copie sous NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin)
// fait échouer son cas (mutant tué).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as A from "@noortrace/approbation";
import * as B from "@noortrace/console/annuaire";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CT3 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3");
const EXPORTS = path.join(CT3, "annuaire", "exports");
const lireExport = (f) => JSON.parse(fs.readFileSync(path.join(EXPORTS, f), "utf8"));
const conforme = (d) => A.annuaireConforme(d);
const COPIES = [];

const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "console.mjs")).href + `?t=${Date.now()}-${Math.random()}`);

/** La référence du dépôt, un remplacement unique appliqué (copie sous TMP). */
async function mutant(nom, ancien, nouveau) {
  const rep = fs.mkdtempSync(path.join(TMP, `noortrace-annuaire-instants-${nom}-`));
  COPIES.push(rep);
  const texte = fs.readFileSync(path.join(PROJECT_ROOT, "scripts", "lib", "console.mjs"), "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien.slice(0, 120)} » trouvé ${n} fois`);
  fs.mkdirSync(path.join(rep, "scripts", "lib"), { recursive: true });
  fs.writeFileSync(path.join(rep, "scripts", "lib", "console.mjs"), texte.replace(ancien, () => nouveau));
  return reference(rep);
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

const ri = (j) => ({ code: "revision_incoherente", pointer: `/operations/${j}/at` });
const ENTRIES = { code: "operations_incoherentes", pointer: "/entries" };

/** Les quatre cas et leurs écarts, tels qu'EX-13.19 (points 2, 4 et 6, complément du 2026-11-16) les donne. */
const CAS = {
  "expiration-instant-indecodable.json": [{ code: "operations_incoherentes", pointer: "/operations/4" }, ri(4)],
  "inscription-instant-indecodable.json": [{ code: "preuve_discordante", pointer: "/entries/1/addresses/0/proof" }, ri(2)],
  "instants-indecodables-rejoues.json": [ri(1), ri(5), ri(8)],
  "remplacement-instants-indecodables.json": [ri(3), ri(4)],
};

/** Vrai si l'instant respecte le motif de CT-1 §3 sans se décoder (date absente du calendrier). */
const indecodable = (t) => /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/.test(t) && !(Date.parse(t) >= 0 && new Date(Date.parse(t)).toISOString() === t);

describe("annuaire exporté, instants indécodables : les cas d'exports/ exercent ce qu'ils disent (EX-13.19)", function () {
  it("exports/attendu.json porte les quatre cas, avec les écarts du texte", function () {
    const att = lireExport("attendu.json");
    for (const [f, ecarts] of Object.entries(CAS)) {
      const c = att.cases.find((x) => x.file === f);
      expect(c, f).to.not.equal(undefined);
      expect(c.errors, f).to.deep.equal(ecarts);
      expect(c.checks, f).to.deep.equal(["AN-9"]);
    }
  });

  it("chaque instant relevé au point 2 respecte le motif sans se décoder, et le document en porte le texte là où le rejeu le pose", function () {
    for (const [f, ecarts] of Object.entries(CAS)) {
      const d = lireExport(f);
      expect(conforme(d), f).to.equal(true);
      const ops = ecarts.filter((e) => e.code === "revision_incoherente").map((e) => d.operations[Number(e.pointer.split("/")[2])]);
      for (const o of ops) expect(indecodable(o.at), `${f} ${o.seq}`).to.equal(true);
      const instants = d.entries.flatMap((e) => [e.created_at, ...e.addresses.flatMap((a) => [a.validated_at, a.revoked_at, a.proof.received_at])]);
      for (const o of ops) if (o.op !== "expirer") expect(instants, `${f} ${o.seq} ${o.op}`).to.include(o.at);
    }
    // expirer : l'entrée retirée n'est plus dans le document ; inscription : created_at et received_at
    const e = lireExport("expiration-instant-indecodable.json");
    expect(e.operations[4].op).to.equal("expirer");
    const i = lireExport("inscription-instant-indecodable.json");
    expect([i.entries[1].created_at, i.entries[1].addresses[0].proof.received_at]).to.deep.equal([i.operations[2].at, i.operations[2].at]);
    // dernière opération et updated_at : le même texte, indécodable
    const r = lireExport("instants-indecodables-rejoues.json");
    expect(r.updated_at).to.equal(r.operations.at(-1).at);
    expect(indecodable(r.updated_at)).to.equal(true);
    // valider qui remplace, puis desactiver
    const m = lireExport("remplacement-instants-indecodables.json");
    const [ancienne, nouvelle] = m.entries[0].addresses;
    expect([ancienne.revocation_cause, ancienne.revoked_at, nouvelle.validated_at]).to.deep.equal(["remplacee", m.operations[3].at, m.operations[3].at]);
    expect([nouvelle.revocation_cause, nouvelle.revoked_at, m.updated_at]).to.deep.equal(["desactivation", m.operations[4].at, m.operations[4].at]);
  });
});

for (const [nom, charger] of [
  ["bibliothèque de référence (scripts/lib/console.mjs)", () => reference(PROJECT_ROOT)],
  ["module d'annuaire du service (@noortrace/console/annuaire)", async () => B],
]) {
  describe(`annuaire exporté, ${nom} : instants indécodables au rejeu (EX-13.19, complément du 2026-11-16)`, function () {
    this.timeout(60000);
    let L;
    before(async function () {
      L = await charger();
    });
    const titres = {
      "expiration-instant-indecodable.json": "point 6 : une opération expirer dont l'instant ne se décode pas ne se rejoue pas (/operations/4), en plus du point 2",
      "inscription-instant-indecodable.json": "point 4 : un received_at indécodable donne preuve_discordante ; point 6 : l'inscription se rejoue, created_at et received_at au texte de l'at (aucun /entries)",
      "instants-indecodables-rejoues.json": "point 6 : validated_at (valider), revoked_at (revoquer) au texte de l'at ; point 2 : updated_at comparé au texte de la dernière (aucun /entries ni /updated_at)",
      "remplacement-instants-indecodables.json": "point 6 : revoked_at d'une adresse remplacée (valider) et d'une désactivation (desactiver) au texte de l'at (aucun /entries)",
    };
    for (const [f, ecarts] of Object.entries(CAS)) {
      it(`${f} — ${titres[f]}`, function () {
        expect(L.verifierAnnuaireExporte(lireExport(f), { conforme })).to.deep.equal(ecarts);
      });
    }
  });
}

describe("annuaire exporté, bibliothèque de référence : chaque lecture retirée fait échouer son cas (mutants)", function () {
  this.timeout(60000);
  const MUTANTS = [
    ["expirer-date-tolerante", "expiration-instant-indecodable.json", "return !e.addresses.some((a) => a.validated_at !== null) && msHorodatage(at) >= msHorodatage(e.created_at) + ttl;", "return !e.addresses.some((a) => a.validated_at !== null) && Date.parse(at) >= msHorodatage(e.created_at) + ttl;", [ri(4)]],
    ["reception-indecodable-concordante", "inscription-instant-indecodable.json", "msHorodatage(champs.issued_at) <= recu && recu < msHorodatage(champs.expires_at);", "(Number.isNaN(recu) || (msHorodatage(champs.issued_at) <= recu && recu < msHorodatage(champs.expires_at)));", [ri(2)]],
    ["reception-reecrite", "inscription-instant-indecodable.json", "received_at: op.at };", "received_at: horodatage(Date.parse(op.at)) };", [ENTRIES, ...CAS["inscription-instant-indecodable.json"]]],
    [
      "creation-reecrite",
      "inscription-instant-indecodable.json",
      "created_at: op.at, addresses: [] };\n        etat.entries.push(cible);\n        etat.crees.add(op.entry);\n      }\n      // EX-13.19, point 6 (révision 0.6)",
      "created_at: horodatage(Date.parse(op.at)), addresses: [] };\n        etat.entries.push(cible);\n        etat.crees.add(op.entry);\n      }\n      // EX-13.19, point 6 (révision 0.6)",
      [ENTRIES, ...CAS["inscription-instant-indecodable.json"]],
    ],
    ["validation-reecrite", "instants-indecodables-rejoues.json", "validated_at: op.at, validated_by: op.by });", "validated_at: horodatage(Date.parse(op.at)), validated_by: op.by });", [ENTRIES, ...CAS["instants-indecodables-rejoues.json"]]],
    ["revocation-reecrite", "instants-indecodables-rejoues.json", "revoked_at: op.at, revoked_by: op.by, revocation_cause: personne", "revoked_at: horodatage(Date.parse(op.at)), revoked_by: op.by, revocation_cause: personne", [ENTRIES, ...CAS["instants-indecodables-rejoues.json"]]],
    ["mise-a-jour-decodee", "instants-indecodables-rejoues.json", "if (doc.updated_at !== derniere)", "if (msHorodatage(doc.updated_at) !== msHorodatage(derniere))", [...CAS["instants-indecodables-rejoues.json"], { code: "revision_incoherente", pointer: "/updated_at" }]],
    ["remplacement-reecrit", "remplacement-instants-indecodables.json", 'revoked_at: op.at, revoked_by: op.by, revocation_cause: "remplacee"', 'revoked_at: horodatage(Date.parse(op.at)), revoked_by: op.by, revocation_cause: "remplacee"', [ENTRIES, ...CAS["remplacement-instants-indecodables.json"]]],
    ["desactivation-reecrite", "remplacement-instants-indecodables.json", 'revoked_at: op.at, revoked_by: op.by, revocation_cause: "desactivation"', 'revoked_at: horodatage(Date.parse(op.at)), revoked_by: op.by, revocation_cause: "desactivation"', [ENTRIES, ...CAS["remplacement-instants-indecodables.json"]]],
  ];
  for (const [nom, f, ancien, nouveau, ecarts] of MUTANTS) {
    it(`mutant ${nom} : ${f} s'écarte de son attendu`, async function () {
      const M = await mutant(nom, ancien, nouveau);
      const r = M.verifierAnnuaireExporte(lireExport(f), { conforme });
      expect(r).to.not.deep.equal(CAS[f]);
      expect(r).to.deep.equal(ecarts);
    });
  }
});

describe("INDEX.md de ct-3 : section « Cas nommés », plancher d'EX-A.10 (complément du 2026-11-16)", function () {
  /** Les répertoires qu'EX-A.10 énumère, lus dans le texte. */
  function famillesDuTexte() {
    const md = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-3-approbations.md"), "utf8");
    const regle = md.slice(md.indexOf("**EX-A.10**"), md.indexOf("**EX-A.11**"));
    const debut = regle.indexOf("Complément du 2026-11-16 : les cas ainsi comptés");
    expect(debut, "EX-A.10 : complément du 2026-11-16").to.be.at.least(0);
    const phrase = regle.slice(debut, regle.indexOf("L'`INDEX.md` les nomme", debut));
    return [...phrase.matchAll(/`([a-z0-9/-]+\/)`/g)].map((m) => m[1]);
  }

  /** Lignes de la section : répertoire → chemins nommés. */
  function section() {
    const index = fs.readFileSync(path.join(CT3, "INDEX.md"), "utf8");
    const debut = index.indexOf("\n## Cas nommés (EX-A.10)\n");
    expect(debut, "section « Cas nommés »").to.be.at.least(0);
    const fin = index.indexOf("\n## ", debut + 1);
    const texte = index.slice(debut, fin === -1 ? undefined : fin);
    const lignes = texte.split("\n").filter((l) => l.startsWith("- `"));
    return new Map(lignes.map((l) => {
      const [tete, reste] = l.slice(2).split(" : ");
      return [tete.slice(1, -1), reste.split(", ").map((x) => x.slice(1, -1))];
    }));
  }

  it("le texte énumère vingt répertoires, ceux de la section, dans le même ordre", function () {
    const familles = famillesDuTexte();
    expect(familles).to.have.length(20);
    expect([...section().keys()]).to.deep.equal(familles);
  });

  it("dans les deux sens : chaque cas nommé est présent, chaque fichier .json de ces répertoires est nommé", function () {
    for (const [rep, noms] of section()) {
      const presents = fs.readdirSync(path.join(CT3, rep), { withFileTypes: true }).filter((e) => e.isFile() && e.name.endsWith(".json")).map((e) => rep + e.name);
      expect([...noms].sort(), rep).to.deep.equal(presents.sort());
      expect(noms.length, rep).to.be.at.least(1);
    }
  });

  it("les quatre cas nouveaux d'exports/ sont nommés", function () {
    const noms = section().get("annuaire/exports/");
    for (const f of Object.keys(CAS)) expect(noms, f).to.include(`annuaire/exports/${f}`);
  });
});
