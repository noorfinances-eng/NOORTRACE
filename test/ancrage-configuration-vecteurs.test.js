// Famille `configuration` des vecteurs de CT-5 (EX-4.9, AN-1 ; complément du
// 2026-11-16) : des documents ancrage-v0 tirés de l'exemple d'EX-4.8, valides
// et refusés, avec le verdict et la liste triée des règles violées (règles 4,
// 4 bis, 8 et 9). Produite par scripts/vecteurs/generer-ct5.mjs ; deux
// générations sont identiques ; la référence (verifierConfiguration) et le
// composant d'ancrage (validerConfiguration) rendent chacun l'attendu ; une
// règle retirée de l'une ou de l'autre (copie sous NOORTRACE_TMP, défaut
// os.tmpdir(), détruite à la fin) fait échouer un cas (mutant tué).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as J from "../scripts/lib/journal.mjs";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const FICHIER = JSON.parse(fs.readFileSync(path.join(CT5, "configuration", "configuration.json"), "utf8"));
const unique = () => `?t=${Date.now()}-${Math.random()}`;

function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-configuration-${nom}-`));
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
const composant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "configuration.mjs")).href + unique());
after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

const tri = (liste) => [...new Set(liste.map(String))].sort();
/** Cas dont le verdict ou les règles diffèrent de l'attendu, pour la référence (A) et le composant (C). */
function ecarts(A, C) {
  const ref = [];
  const comp = [];
  for (const c of FICHIER.cases) {
    const r = A.verifierConfiguration(c.input.document, { profil: c.input.profil, checkpoint_interval_s: c.input.checkpoint_interval_s });
    if (JSON.stringify(tri(r.violations.map((v) => v.rule))) !== JSON.stringify(c.expected.regles) || r.valide !== c.expected.valide) ref.push(c.id);
    const k = C.validerConfiguration(c.input.document, { profil: c.input.profil, checkpointIntervalEnregistreur: c.input.checkpoint_interval_s });
    if (JSON.stringify(tri(k.erreurs.map((e) => e.regle))) !== JSON.stringify(c.expected.regles) || k.valide !== c.expected.valide) comp.push(c.id);
  }
  return { reference: ref, composant: comp };
}

describe("CT-5 : famille configuration (EX-4.9, AN-1 ; règles 4, 4 bis et 9 ; complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("le fichier suit #/$defs/fichier_vecteurs (cas_configuration) ; deux générations sont identiques et égales au dépôt ; cas valides et refusés, chaque règle 4, 8, 9 et le schéma (4 bis) refusent au moins un cas", async function () {
    const schema = J.analyserJSONStrict(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", "planificateur-ancrage-v0.schema.json")));
    expect(J.validerSchema(FICHIER, schema, { fragment: "#/$defs/fichier_vecteurs" })).to.deep.equal([]);
    expect(FICHIER.family).to.equal("configuration");
    const G = await import(pathToFileURL(path.join(RACINE, "scripts", "vecteurs", "generer-ct5.mjs")).href + unique());
    const a = G.familleConfiguration();
    const b = G.familleConfiguration();
    expect(J.canonicaliserJCS(a)).to.equal(J.canonicaliserJCS(b));
    expect(JSON.stringify(a, null, 2) + "\n").to.equal(fs.readFileSync(path.join(CT5, "configuration", "configuration.json"), "utf8"));
    const regles = new Set(FICHIER.cases.flatMap((c) => c.expected.regles));
    expect([...regles].sort()).to.deep.equal(["4", "8", "9", "schema"]);
    expect(FICHIER.cases.filter((c) => c.expected.valide).length).to.be.at.least(5);
    expect(FICHIER.cases.filter((c) => !c.expected.valide).length).to.be.at.least(10);
    expect(new Set(FICHIER.cases.map((c) => c.input.profil))).to.deep.equal(new Set(["developpement", "production"]));
  });

  it("la référence (verifierConfiguration) et le composant d'ancrage (validerConfiguration) rendent l'attendu de chaque cas", async function () {
    expect(ecarts(await reference(RACINE), await composant(RACINE))).to.deep.equal({ reference: [], composant: [] });
  });

  it("mutants de la référence : sans la règle 9, sans le prestataire interne jamais qualifié, sans la source d'en-têtes en production (tués)", async function () {
    const C = await composant(RACINE);
    const M9 = await reference(copie("ref-9", "scripts/lib", "scripts/lib/ancrage.mjs", "    for (const [ou, oid] of oids) {", "    for (const [ou, oid] of []) {"));
    expect(ecarts(M9, C).reference).to.include.members(["oid-second-arc-40", "oid-arc-2-128", "oid-der-trop-long"]);
    const M4 = await reference(copie("ref-4-interne", "scripts/lib", "scripts/lib/ancrage.mjs", "if (p.role === \"interne\" && p.qualified !== null && p.qualified !== undefined) v(4,", "if (false) v(4,"));
    expect(ecarts(M4, C).reference).to.include.members(["interne-qualifie", "interne-qualifie-production"]);
    const M4b = await reference(copie("ref-4-entetes", "scripts/lib", "scripts/lib/ancrage.mjs", "if (o.enabled === true && o.headers_source === null) v(4,", "if (false) v(4,"));
    expect(ecarts(M4b, C).reference).to.deep.equal(["source-entetes-nulle-production"]);
  });

  it("mutants du composant : sans l'arc borné à 128 bits, sans « aucune » avec un secret nul (tués)", async function () {
    const A = await reference(RACINE);
    const Marc = await composant(copie("comp-arc", "paquets/ancrage/src", "paquets/ancrage/src/planificateur/requete-der.mjs", "  for (const a of arcs) if (a > ARC_OID_MAX) throw", "  for (const a of []) if (a > ARC_OID_MAX) throw"));
    expect(ecarts(A, Marc).composant).to.deep.equal(["oid-arc-2-128"]);
    const Msecret = await composant(copie("comp-secret", "paquets/ancrage/src", "paquets/ancrage/src/planificateur/configuration.mjs", "if (p.auth.method === \"aucune\" && p.auth.secret !== null && p.auth.secret !== undefined) violer(", "if (false) violer("));
    expect(ecarts(A, Msecret).composant).to.deep.equal(["aucune-avec-secret"]);
  });

  it("INDEX.md décrit la famille et chacun de ses cas ; CT-5 A.3 et A.4 la nomment", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    expect(index).to.include("## configuration/ (EX-4.9, AN-1 ; complément du 2026-11-16)");
    for (const c of FICHIER.cases) expect(index).to.include(`| \`${c.id}\` | ${c.input.profil} |`);
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8");
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    expect(a3).to.include("configuration/");
    expect(a3).to.include("configuration.json");
    const a4 = ct5.slice(ct5.indexOf("### A.4 Familles"), ct5.indexOf("### A.5"));
    expect(a4).to.include("| `configuration` |");
  });
});
