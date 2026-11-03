// Tests adversariaux de CT-9 (famille TA-) exécutables aujourd'hui sur les
// vecteurs et les bibliothèques de référence du dépôt (CT-7 §3.4, EX-3.2 :
// « le test échoue si la réponse est retirée »).
//
// Méthode. Chaque test TA-<n> rattaché à la menace MN-<n> de CT-7 fait deux
// choses : (1) il rejoue l'oracle sur la bibliothèque de référence et attend le
// verdict des vecteurs (le test tel qu'il tourne dans l'intégration continue) ;
// (2) il fabrique un MUTANT, copie de scripts/ où la réponse de sécurité est
// retirée par un remplacement textuel exact et unique, et attend que le mutant
// accepte ce que la référence refuse. Un mutant « tué » prouve que l'oracle de
// (1) échouerait si la réponse était retirée. Aucun fichier du dépôt n'est
// modifié : les mutants vivent dans un répertoire temporaire, détruit à la fin.
//
// Le fichier se lit depuis test/ (racine du dépôt = ..) ou depuis un autre
// répertoire avec NOORTRACE_RACINE ; les mutants sont créés sous
// NOORTRACE_TMP (défaut : os.tmpdir()). Un mutant qui lève une exception avant
// l'oracle est un mutant mal posé (CT-9 EX-10.6) : les fabriques de divergence
// laissent l'exception faire échouer le test au lieu de la compter.

import { expect } from "chai";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const RACINE = process.env.NOORTRACE_RACINE ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = path.join(RACINE, "spec");
const VECTEURS = path.join(SPEC, "vecteurs");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const lireJSON = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));
const lireDossier = (rep) => Object.fromEntries(fs.readdirSync(rep).filter((f) => f !== "attendu.json").map((f) => [f, fs.readFileSync(path.join(rep, f))]));
const schemaJSON = (n) => lireJSON(SPEC, "schemas", `${n}-v0.schema.json`);
const importer = (racine, rel) => import(pathToFileURL(path.join(racine, "scripts", rel)).href);
const ref = (rel) => importer(RACINE, rel);
const egal = (a, b) => {
  try {
    assert.deepStrictEqual(a, b);
    return true;
  } catch {
    return false;
  }
};

// ---------------------------------------------------------------------------
// Fabrique de mutants
// ---------------------------------------------------------------------------
const MUTANTS = [];
/**
 * Copie scripts/lib, scripts/verify, scripts/conformite et scripts/registre dans un répertoire
 * temporaire (spec/, node_modules/, package.json et deploiement/ y sont liés
 * symboliquement), puis applique chaque remplacement { fichier, ancien,
 * nouveau, tous } ; `ancien` doit apparaître exactement une fois (ou au moins
 * une fois si `tous`). Rend { racine, importer(rel), chemin(rel) }.
 */
function mutant(nom, remplacements) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-mutant-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  for (const d of ["lib", "verify", "conformite", "registre"]) fs.cpSync(path.join(RACINE, "scripts", d), path.join(racine, "scripts", d), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json", "deploiement"]) fs.symlinkSync(path.join(RACINE, l), path.join(racine, l));
  for (const r of remplacements) {
    const f = path.join(racine, "scripts", r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (r.tous ? n < 1 : n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
    fs.writeFileSync(f, r.tous ? texte.split(r.ancien).join(r.nouveau) : texte.replace(r.ancien, () => r.nouveau));
  }
  return { racine, importer: (rel) => importer(racine, rel), chemin: (rel) => path.join(racine, "scripts", rel) };
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

/** Rapport JSON du vérificateur de CT-6 (scripts/verify/dossier.mjs) d'une racine de scripts donnée. */
function rapportDossier(racine, repDossier, args = []) {
  const r = spawnSync(process.execPath, [path.join(racine, "scripts", "verify", "dossier.mjs"), repDossier, ...args, "--json"], { encoding: "utf8", cwd: RACINE, maxBuffer: 64 * 1024 * 1024 });
  expect(r.status, r.stderr).to.be.oneOf([0, 1, 3]);
  return JSON.parse(r.stdout);
}
/** Arguments du vérificateur pour un dossier de spec/vecteurs/ct-6/dossiers, d'après son attendu.json. */
function dossierCt6(nom) {
  const rep = path.join(VECTEURS, "ct-6", "dossiers", nom);
  const a = lireJSON(rep, "attendu.json");
  const args = [];
  if (a.anchors) args.push("--ancres", path.resolve(rep, a.anchors));
  if (a.bitcoin_headers) args.push("--entetes-bitcoin", path.resolve(rep, a.bitcoin_headers));
  return { rep, a, args };
}
const dossierCt1 = (nom) => path.join(VECTEURS, "ct-1", "dossiers", nom);
/** Rejoue un dossier ct-6 par la référence puis par le mutant ; rend les deux rapports et l'attendu. */
function paireCt6(m, nom) {
  const { rep, a, args } = dossierCt6(nom);
  return { a, reference: rapportDossier(RACINE, rep, args), mutant: rapportDossier(m.racine, rep, args) };
}

// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux TA- exécutables (mutants des bibliothèques de référence, CT-7 EX-3.2)", function () {
  this.timeout(600_000);

  // -------------------------------------------------------------------------
  describe("clés et cérémonie (CT-7 §5, CR-) : composant cles", function () {
    const cas = (nom) => fs.readFileSync(path.join(VECTEURS, "ct-7", "ceremonies", nom, "proces-verbal.json"));
    const faillit = async (S, nom) => S.verifierCeremonie(cas(nom)).failed;

    it("TA-32 (MN-32) : invalide-cr2-un-seul-participant échoue à CR-2 ; mutant securite.mjs sans aucune faute CR-2 : CR-2 disparaît des échecs (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr2-un-seul-participant")).to.include("CR-2");
      const m = mutant("mn32", [{ fichier: "lib/securite.mjs", ancien: 'faute("CR-2", ', nouveau: '((_a, _b) => {})("CR-2", ', tous: true }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr2-un-seul-participant")).to.not.include("CR-2");
    });

    it("TA-36 (MN-36) : invalide-cr2-adresse-en-double échoue à CR-2 ; mutant sans la règle « adresses de participants en double » : CR-2 passe (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr2-adresse-en-double")).to.include("CR-2");
      const m = mutant("mn36", [{ fichier: "lib/securite.mjs", ancien: 'if (new Set(pv.participants.map((p) => p.address)).size !== pv.participants.length) faute("CR-2", "adresses de participants en double");', nouveau: "if (false) faute(\"CR-2\", \"retirée par le mutant TA-36\");" }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr2-adresse-en-double")).to.not.include("CR-2");
    });

    it("TA-37 et TA-42 (MN-37, MN-42) : invalide-cr6-classe-d-en-production échoue à CR-6 ; la table CLASSES_ADMISES_PRODUCTION exclut D pour gouvernance et tsa_interne ; mutant sans la règle de classe en production : CR-6 passe (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr6-classe-d-en-production")).to.include("CR-6");
      expect(S0.CLASSES_ADMISES_PRODUCTION.gouvernance).to.not.include("D");
      expect(S0.CLASSES_ADMISES_PRODUCTION.tsa_interne).to.not.include("D");
      const m = mutant("mn37", [{ fichier: "lib/securite.mjs", ancien: 'if (production && !CLASSES_ADMISES_PRODUCTION[k.usage].includes(k.custody_class)) faute("CR-6"', nouveau: 'if (false) faute("CR-6"' }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr6-classe-d-en-production")).to.not.include("CR-6");
    });

    it("TA-39 (MN-39) : invalide-cr7-sauvegarde-enregistreur échoue à CR-7 ; SAUVEGARDE_PAR_USAGE.validateur vaut aucune ; mutant sans la règle « aucune sauvegarde » : CR-7 passe (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr7-sauvegarde-enregistreur")).to.include("CR-7");
      expect(S0.SAUVEGARDE_PAR_USAGE.validateur).to.equal("aucune");
      const m = mutant("mn39", [{ fichier: "lib/securite.mjs", ancien: 'if (regle === "aucune" && b.scheme !== "aucune") faute("CR-7"', nouveau: 'if (false) faute("CR-7"' }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr7-sauvegarde-enregistreur")).to.not.include("CR-7");
    });

    it("TA-92 (MN-92) : invalide-cr4-temoin-auditeur-seul échoue à CR-4 ; mutant où l'auditeur peut remplacer le témoin : CR-4 passe (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr4-temoin-auditeur-seul")).to.include("CR-4");
      const m = mutant("mn92", [{ fichier: "lib/securite.mjs", ancien: 'if (!st.witnessed_by.some((w) => role(w) === "temoin" && w !== st.performed_by)) faute("CR-4"', nouveau: 'if (false) faute("CR-4"' }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr4-temoin-auditeur-seul")).to.not.include("CR-4");
    });

    it("TA-94 (MN-94) : invalide-cr12-restauration-sans-detenteur échoue à CR-12 ; mutant sans le compte des détenteurs de part : CR-12 passe (tué)", async function () {
      const S0 = await ref("lib/securite.mjs");
      expect(await faillit(S0, "invalide-cr12-restauration-sans-detenteur")).to.include("CR-12");
      const m = mutant("mn94", [{ fichier: "lib/securite.mjs", ancien: 'if (nb("detenteur_part") < d.k) faute("CR-12"', nouveau: 'if (false) faute("CR-12"' }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(await faillit(S1, "invalide-cr12-restauration-sans-detenteur")).to.not.include("CR-12");
    });
  });

  // -------------------------------------------------------------------------
  describe("attestation de périmètre (CT-7 §7, CT-1 AT-, CT-6 §5.5) : composants verificateur et administrateur_client", function () {
    const REP = path.join(VECTEURS, "ct-7", "attestations");
    const schemasCt1 = (J) => J.registreSchemas(["evenement", "manifeste", "dossier", "point-de-controle", "attestation-perimetre"].map(schemaJSON));
    const rapportCt1 = async (racine, nom) => {
      const J = await importer(racine, "lib/journal.mjs");
      const r = J.verifierDossier(lireDossier(dossierCt1(nom)), { schemas: schemasCt1(J) });
      return { valide: r.valide, echecs: J.controlesEnEchec(r), at: Object.fromEntries(r.attestation.checks.map((c) => [c.id, c.status])), retenue: r.attestation.retenue, avertissements: r.attestation.avertissements.map((w) => w.id) };
    };
    const MUT_AT3 = { fichier: "lib/securite.mjs", ancien: "else if (e.adresse !== x.address) fautes.push(", nouveau: "else if (false) fautes.push(" };

    it("TA-81 (MN-81) : chaque cas invalide-at3-* de attestations.json échoue à AT-3 ; s-haut et v-hors-domaine restent refusés par le contrôle de forme, fait avant tout recouvrement (CT-7 EX-7.6) ; mutant qui ne compare plus l'adresse recouvrée à l'adresse déclarée : la signature substituée passe (tué)", async function () {
      const f = lireJSON(REP, "attestations.json");
      const cas = f.cases.filter((c) => c.name.startsWith("invalide-at3-"));
      expect(cas.map((c) => c.name)).to.include.members(["invalide-at3-signature-substituee", "invalide-at3-s-haut", "invalide-at3-v-hors-domaine"]);
      const S0 = await ref("lib/securite.mjs");
      const m = mutant("mn81", [MUT_AT3]);
      const S1 = await m.importer("lib/securite.mjs");
      const at3 = (S, c) => S.verifierAttestation(c.input.signed, c.input.approver_set).checks.find((x) => x.id === "AT-3").status;
      for (const c of cas) expect(at3(S0, c), c.name).to.equal("echoue");
      for (const c of cas) expect(at3(S1, c), `${c.name} (mutant)`).to.equal(c.name === "invalide-at3-signature-substituee" ? "reussi" : "echoue");
    });

    it("TA-83 (MN-83) : chaque signature croisée de croises.json présentée comme attestation échoue à AT-3 (D_P recalculé depuis le fichier, préfixe propre) ; mutant qui accepte l'adresse déclarée sans recouvrement : la signature croisée passe (tué)", async function () {
      const f = lireJSON(REP, "croises.json");
      const signee = lireJSON(REP, "exemple", "attestation-signee.json");
      const jeu = lireJSON(REP, "exemple", "jeu.json");
      const cas = f.cases.filter((c) => c.presented_as === "attestation");
      expect(cas.length).to.be.at.least(3);
      const S0 = await ref("lib/securite.mjs");
      const m = mutant("mn83", [MUT_AT3]);
      const S1 = await m.importer("lib/securite.mjs");
      for (const c of cas) {
        const s = structuredClone(signee);
        s.signatures[0].signature = c.signature;
        const r0 = S0.verifierAttestation(s, jeu);
        expect([r0.checks[2].status, r0.recovered[0]], c.name).to.deep.equal(["echoue", c.expected.recovered]);
        const r1 = S1.verifierAttestation(s, jeu);
        expect(r1.checks[2].status, `${c.name} (mutant)`).to.equal("reussi");
      }
    });

    it("TA-87 (MN-87) : controlerDeclaration refuse une adresse IPv4 de documentation (192.0.2.10) dans host ; mutant sans le contrôle des membres sans adresse IP : aucune erreur (tué)", async function () {
      const P = lireJSON(REP, "exemple", "attestation.json");
      expect(P.agents[0].host).to.be.a("string");
      P.agents[0].host = "192.0.2.10";
      const S0 = await ref("lib/securite.mjs");
      expect(S0.controlerDeclaration(P).erreurs.some((e) => e.includes("/agents/0/host") && e.includes("adresse IP refusée"))).to.equal(true);
      const m = mutant("mn87", [{ fichier: "lib/securite.mjs", ancien: "if (MEMBRES_SANS_ADRESSE_IP.includes(k) && contientAdresseIP(x)) erreurs.push(", nouveau: "if (false) erreurs.push(" }]);
      const S1 = await m.importer("lib/securite.mjs");
      expect(S1.controlerDeclaration(P).erreurs).to.deep.equal([]);
    });

    it("TA-79 et TA-80 (MN-79, MN-80) : valide-at5-autre-journal et valide-at5-hors-validite font échouer AT-5 et l'attestation n'est pas retenue ; mutant qui pose toujours AT-5 réussie : attestation retenue (tué)", async function () {
      const m = mutant("mn79", [{ fichier: "lib/securite.mjs", ancien: 'if (f.length) poser("AT-5", "echoue"', nouveau: 'if (false) poser("AT-5", "echoue"' }]);
      for (const nom of ["valide-at5-autre-journal", "valide-at5-hors-validite"]) {
        const r0 = await rapportCt1(RACINE, nom);
        expect([r0.valide, r0.echecs, r0.at["AT-5"], r0.retenue], nom).to.deep.equal([true, [], "echoue", false]);
        const r1 = await rapportCt1(m.racine, nom);
        expect([r1.at["AT-5"], r1.retenue], `${nom} (mutant)`).to.deep.equal(["reussi", true]);
      }
    });

    it("TA-86 (MN-86) : valide-at6-inscription-posterieure fait échouer AT-6 ; mutant sans la comparaison des seq et des ts : AT-6 réussit (tué)", async function () {
      const nom = "valide-at6-inscription-posterieure";
      const r0 = await rapportCt1(RACINE, nom);
      expect([r0.valide, r0.at["AT-6"], r0.retenue]).to.deep.equal([true, "echoue", false]);
      const m = mutant("mn86", [
        { fichier: "lib/securite.mjs", ancien: "if (ins.seq > ev.seq) f.push(", nouveau: "if (false) f.push(" },
        { fichier: "lib/securite.mjs", ancien: "if (!(ti <= te)) f.push(", nouveau: "if (false) f.push(" },
      ]);
      const r1 = await rapportCt1(m.racine, nom);
      expect([r1.at["AT-6"], r1.retenue]).to.deep.equal(["reussi", true]);
    });

    it("TA-84 (MN-84) : valide-at6-inscription-signature-fausse fait échouer AT-6 ; mutant qui ne vérifie plus la signature E-8 de l'inscription : AT-6 réussit (tué)", async function () {
      const nom = "valide-at6-inscription-signature-fausse";
      const r0 = await rapportCt1(RACINE, nom);
      expect([r0.valide, r0.at["AT-6"], r0.retenue]).to.deep.equal([true, "echoue", false]);
      const m = mutant("mn84", [
        { fichier: "lib/securite.mjs", ancien: '"E-8", "E-11"]', nouveau: '"E-11"]' },
        { fichier: "lib/securite.mjs", ancien: 'if (res["E-8"]?.ok !== true && res["E-8"]?.ok !== false) f.push(', nouveau: "if (false) f.push(" },
      ]);
      const r1 = await rapportCt1(m.racine, nom);
      expect([r1.at["AT-6"], r1.retenue]).to.deep.equal(["reussi", true]);
    });

    it("TA-90 (MN-90) : valide-at6-cle-non-ancree laisse AT-6 non exécutée (ancre_absente) ; mutant sans la comparaison de la clé de l'inscription à celle de l'événement prouvé : AT-6 réussit (tué)", async function () {
      const nom = "valide-at6-cle-non-ancree";
      const r0 = await rapportCt1(RACINE, nom);
      expect([r0.valide, r0.at["AT-6"], r0.at["AT-7"]]).to.deep.equal([true, "non_execute", "non_execute"]);
      const m = mutant("mn90", [{ fichier: "lib/securite.mjs", ancien: "else if (ins.recorder_key_id !== ev.recorder_key_id) {", nouveau: "else if (false) {" }]);
      const r1 = await rapportCt1(m.racine, nom);
      expect(r1.at["AT-6"]).to.equal("reussi");
    });

    it("TA-82 (MN-82) : valide-at4-jeu-different porte AV-AT-2 ; mutant sans l'avertissement : aucun avertissement (tué)", async function () {
      const nom = "valide-at4-jeu-different";
      const r0 = await rapportCt1(RACINE, nom);
      expect([r0.valide, r0.retenue, r0.avertissements]).to.deep.equal([true, true, ["AV-AT-2"]]);
      const m = mutant("mn82", [{ fichier: "lib/securite.mjs", ancien: 'if (!memes) avertissements.unshift({ id: "AV-AT-2"', nouveau: 'if (false) avertissements.unshift({ id: "AV-AT-2"' }]);
      const r1 = await rapportCt1(m.racine, nom);
      expect(r1.avertissements).to.deep.equal([]);
    });

    it("TA-89 (MN-89) : valide-at1-taille (ct-1) et valide-seq-7-complet-attestation-non-retenue (ct-6) gardent le verdict valide avec une AT- en échec ; mutant qui compte les AT- dans failed_checks : verdict invalide (tué)", async function () {
      const m = mutant("mn89", [{ fichier: "lib/verificateur.mjs", ancien: 'const estAT = (id) => id.startsWith("AT-");', nouveau: "const estAT = (id) => false;" }]);
      const r0 = rapportDossier(RACINE, dossierCt1("valide-at1-taille"));
      expect([r0.verdict, r0.failed_checks, r0.checks.find((c) => c.id === "AT-1").status]).to.deep.equal(["valide", [], "echoue"]);
      const r1 = rapportDossier(m.racine, dossierCt1("valide-at1-taille"));
      expect([r1.verdict, r1.failed_checks]).to.deep.equal(["invalide", ["AT-1"]]);
      const p = paireCt6(m, "valide-seq-7-complet-attestation-non-retenue");
      expect([p.reference.verdict, p.reference.failed_checks]).to.deep.equal(["valide", []]);
      expect([p.mutant.verdict, p.mutant.failed_checks]).to.deep.equal(["invalide", ["AT-3"]]);
    });

    it("TA-78 (MN-78) : l'énoncé de valide-seq-7-complet-attestation dit le périmètre « déclaré, non prouvé » ; mutant qui écrit « vérifié » : l'énoncé applique « vérifié » au périmètre (tué)", async function () {
      const m = mutant("mn78", [{ fichier: "lib/verificateur.mjs", ancien: "le périmètre de capture est déclaré, non prouvé, par l'attestation", nouveau: "le périmètre de capture est vérifié par l'attestation" }]);
      const p = paireCt6(m, "valide-seq-7-complet-attestation");
      expect(p.reference.statement.fr).to.include("le périmètre de capture est déclaré, non prouvé");
      expect(/périmètre de capture est (prouvé|vérifié)/.test(p.reference.statement.fr)).to.equal(false);
      expect(/périmètre de capture est (prouvé|vérifié)/.test(p.mutant.statement.fr)).to.equal(true);
    });

    it("TA-85 et TA-98 (MN-85, MN-98) : sans inscription, le fragment FP porte la clause fixe « non inscrite au journal (ni sa date ni son rang ne sont établis) » (ct-1 valide-seq-7-attestation-sans-inscription, ct-6 valide-seq-7-complet-attestation-non-retenue exclu car non retenue) ; mutant qui annonce une inscription : la clause disparaît (tué)", async function () {
      const CLAUSE = "non inscrite au journal (ni sa date ni son rang ne sont établis)";
      const m = mutant("mn85", [{ fichier: "lib/verificateur.mjs", ancien: ", non inscrite au journal (ni sa date ni son rang ne sont établis)", nouveau: ", inscrite au journal" }]);
      const rep = dossierCt1("valide-seq-7-attestation-sans-inscription");
      const r0 = rapportDossier(RACINE, rep);
      expect(r0.verdict).to.equal("valide");
      expect(r0.statement.fr).to.include(CLAUSE);
      const r1 = rapportDossier(m.racine, rep);
      expect(r1.statement.fr).to.not.include(CLAUSE);
      expect(r1.statement.fr).to.include("inscrite au journal");
    });

    it("TA-91 (MN-91) : valide-at7-nom-reannonce fait réussir AT-7 et FP ne dit que « de même nom » ; mutant qui affirme la vigueur de l'attestation : FP dit « en vigueur » (tué)", async function () {
      const m = mutant("mn91", [{ fichier: "lib/verificateur.mjs", ancien: " sous une version de politique de même nom que celle de cet événement", nouveau: " en vigueur pour cet événement" }]);
      const rep = dossierCt1("valide-at7-nom-reannonce");
      const r0 = rapportDossier(RACINE, rep);
      expect([r0.verdict, r0.checks.find((c) => c.id === "AT-7").status]).to.deep.equal(["valide", "reussi"]);
      expect(r0.statement.fr).to.include("de même nom que celle de cet événement");
      expect(r0.statement.fr).to.not.match(/attestation[^.]*en vigueur pour cet événement/);
      const r1 = rapportDossier(m.racine, rep);
      expect(r1.statement.fr).to.match(/en vigueur pour cet événement/);
    });
  });

  // -------------------------------------------------------------------------
  describe("vérificateur hors ligne (CT-6 contrôles 4, 5, 6, 8 ; CT-1 K-) : composants verificateur, registre, exploitant, ancrage", function () {
    const forcer = (id) => ({ fichier: "lib/registre.mjs", ancien: `poser("${id}", a.statut, a.raison, d);`, nouveau: `poser("${id}", "reussi", null, d);` });
    const forcerResume = (id) => ({ fichier: "lib/registre.mjs", ancien: `poser("${id}", a.statut, a.raison, a.statut === "reussi" ?`, nouveau: `poser("${id}", "reussi", null, true ?` });
    const tue = (p, id) => {
      expect([p.reference.exit_code, p.reference.verdict, p.reference.failed_checks], `référence ${id}`).to.deep.equal([1, "invalide", [id]]);
      expect(p.mutant.failed_checks, `mutant ${id}`).to.not.include(id);
    };

    it("TA-34 (MN-34) : invalide-r10-inscription-cle-inconnue échoue à R-10 ; mutant qui pose R-10 réussie : R-10 disparaît des échecs (tué)", function () {
      tue(paireCt6(mutant("mn34", [forcer("R-10")]), "invalide-r10-inscription-cle-inconnue"), "R-10");
    });

    it("TA-54 (MN-54) : invalide-r2-jeu-substitue échoue à R-2 (quorum sur le jeu du réviseur) ; mutant qui pose R-2 réussie : R-2 disparaît des échecs (tué)", function () {
      tue(paireCt6(mutant("mn54", [forcer("R-2")]), "invalide-r2-jeu-substitue"), "R-2");
    });

    it("TA-59 (MN-59) : invalide-r8-autre-contrat échoue à R-8 ; mutant qui pose R-8 réussie : R-8 disparaît des échecs (tué)", function () {
      tue(paireCt6(mutant("mn59", [forcerResume("R-8")]), "invalide-r8-autre-contrat"), "R-8");
    });

    it("TA-71 (MN-71) : invalide-r4-autre-chaine échoue à R-4 ; mutant qui pose R-4 réussie : R-4 disparaît des échecs (tué)", function () {
      tue(paireCt6(mutant("mn71", [forcer("R-4")]), "invalide-r4-autre-chaine"), "R-4");
    });

    it("TA-17 et TA-69 (MN-17, MN-69) : invalide-r6-entete-modifie, invalide-r7-recu-falsifie, invalide-r9-cloture-autre-periode, invalide-r11-ancre-de-periode et invalide-k8-empreinte échouent chacun à la vérification nommée ; un mutant par vérification la pose réussie : elle disparaît des échecs (tués)", function () {
      const plans = [
        ["invalide-r6-entete-modifie", "R-6", forcerResume("R-6")],
        ["invalide-r7-recu-falsifie", "R-7", forcerResume("R-7")],
        ["invalide-r9-cloture-autre-periode", "R-9", forcer("R-9")],
        ["invalide-r11-ancre-de-periode", "R-11", { fichier: "lib/registre.mjs", ancien: 'poser("R-11", statut, raison, detail);', nouveau: 'poser("R-11", "reussi", null, detail);' }],
        ["invalide-k8-empreinte", "K-8", { fichier: "lib/verificateur.mjs", ancien: 'if (fautes.length) poserK("K-8", [8], "echoue", null, fautes.join(" ; "));', nouveau: 'if (false) poserK("K-8", [8], "echoue", null, fautes.join(" ; "));' }],
      ];
      for (const [nom, id, r] of plans) tue(paireCt6(mutant(`mn69-${id.toLowerCase()}`, [r]), nom), id);
    });

    it("TA-17 et TA-61 (MN-17, MN-61) : invalide-t2-jeton-autre-manifeste (T-2), invalide-o2-preuve-autre-manifeste (O-2) et invalide-k7-jeton-autre-empreinte (K-7, par T-2 sur checkpoint_hash) échouent ; mutants qui ne comparent plus l'empreinte recalculée : ils passent (tués)", function () {
      const mutT2 = { fichier: "lib/horodatage.mjs", ancien: 'else if (!egalOctets(empreinte, attendu)) res["T-2"] = echoue(', nouveau: 'else if (false) res["T-2"] = echoue(' };
      const mutO2 = { fichier: "lib/ots.mjs", ancien: 'else if (hex(preuve.empreinte) !== periodHash) res["O-2"] = echoue(', nouveau: 'else if (false) res["O-2"] = echoue(' };
      const mT = mutant("mn61-t2", [mutT2]);
      const mO = mutant("mn61-o2", [mutO2]);
      tue(paireCt6(mT, "invalide-t2-jeton-autre-manifeste"), "T-2");
      tue(paireCt6(mO, "invalide-o2-preuve-autre-manifeste"), "O-2");
      tue(paireCt6(mT, "invalide-k7-jeton-autre-empreinte"), "K-7");
    });

    it("TA-70 (MN-70) : invalide-o5-chaine-sans-travail échoue à O-5 ; mutant qui ne recalcule plus la preuve de travail au-dessus du point de contrôle : O-5 passe (tué)", function () {
      tue(paireCt6(mutant("mn70", [{ fichier: "lib/ots.mjs", ancien: "if (entierLE(dSHA(h(i))) > cible) return echec(", nouveau: "if (false) return echec(" }]), "invalide-o5-chaine-sans-travail"), "O-5");
    });

    it("TA-68 (MN-68) : invalide-t1-octet-en-trop échoue à T-1 ; mutant dont le lecteur DER tolère des octets après la fin de la structure : T-1 passe (tué)", function () {
      tue(paireCt6(mutant("mn68", [{ fichier: "lib/horodatage.mjs", ancien: "if (fin !== buf.length) throw new ErreurDER(", nouveau: "if (false) throw new ErreurDER(" }]), "invalide-t1-octet-en-trop"), "T-1");
    });

    it("TA-67 (MN-67) : invalide-n3-cle-enregistreur échoue à N-3 ; mutant qui ne compare plus cles.json aux enregistreurs du fichier d'ancres : N-3 passe (tué)", function () {
      tue(paireCt6(mutant("mn67", [{ fichier: "lib/verificateur.mjs", ancien: 'if (differences.length) n3 = { status: "echoue"', nouveau: 'if (false) n3 = { status: "echoue"' }]), "invalide-n3-cle-enregistreur"), "N-3");
    });

    it("TA-74 (MN-74) : invalide-k4-point-trop-court (ct-1) échoue à K-4 ; mutant qui pose K-4 réussie : le dossier devient valide (tué)", async function () {
      const nom = dossierCt1("invalide-k4-point-trop-court");
      const J0 = await ref("lib/journal.mjs");
      const schemas = (J) => J.registreSchemas(["evenement", "manifeste", "dossier", "point-de-controle", "attestation-perimetre"].map(schemaJSON));
      const r0 = J0.verifierDossier(lireDossier(nom), { schemas: schemas(J0) });
      expect([r0.valide, J0.controlesEnEchec(r0)]).to.deep.equal([false, ["K-4"]]);
      const m = mutant("mn74", [{ fichier: "lib/journal.mjs", ancien: 'k4.length ? k4.forEach((m) => rapport.echec("K-4", m)) : rapport.succes("K-4"', nouveau: 'false ? k4.forEach((m) => rapport.echec("K-4", m)) : rapport.succes("K-4"' }]);
      const J1 = await m.importer("lib/journal.mjs");
      const r1 = J1.verifierDossier(lireDossier(nom), { schemas: schemas(J1) });
      expect([r1.valide, J1.controlesEnEchec(r1)]).to.deep.equal([true, []]);
    });
  });

  // -------------------------------------------------------------------------
  describe("service d'approbation et noyau (CT-3 §5 à §9, SG-, TK-) : composants hote_agent, cles, approbation_console", function () {
    const CT3 = path.join(VECTEURS, "ct-3");
    const schemasDe = (A) => A.registreSchemas(A.FICHIERS_SCHEMAS.map((f) => lireJSON(SPEC, "schemas", f)));
    /** Pas de la trace dont le rejeu diffère de l'attendu (1-indexés) ; un rejeu qui lève fait échouer le test (mutant mal posé, EX-10.6). */
    const ecartsTrace = (A, t) => {
      const { pas } = A.rejouerTrace(t, { schemas: schemasDe(A) });
      return pas.map((r, i) => (egal(r, t.steps[i].expected) ? null : i + 1)).filter((x) => x !== null);
    };
    const trace = (nom) => lireJSON(CT3, "tickets", `${nom}.json`);
    const tueTrace = async (nom, m, pasAttendus) => {
      const A0 = await ref("lib/approbation.mjs");
      expect(ecartsTrace(A0, trace(nom)), `${nom} : référence`).to.deep.equal([]);
      const A1 = await m.importer("lib/approbation.mjs");
      const ecarts = ecartsTrace(A1, trace(nom));
      expect(ecarts, `${nom} : pas divergents attendus`).to.include.members(pasAttendus);
    };

    it("TA-3 (MN-3) : evaluation/niveaux.json, cas fenetre-epuisee : une fenêtre au plafond max_calls atteint rend a_approuver ; mutant qui ignore remaining : autorise (tué)", async function () {
      const doc = lireJSON(CT3, "evaluation", "niveaux.json");
      const c = doc.cases.find((x) => x.id === "fenetre-epuisee");
      expect(c.windows.some((w) => w.remaining === 0)).to.equal(true);
      const P = lireJSON(CT3, doc.policy);
      const A0 = await ref("lib/approbation.mjs");
      const r0 = A0.evaluer(P, c.request, { fenetres: c.windows, t: c.t, policy_version: doc.policy_version });
      expect([r0.rule, r0.decision]).to.deep.equal([c.expected.rule, c.expected.decision]);
      expect(r0.decision).to.equal("a_approuver");
      const m = mutant("mn3", [{ fichier: "lib/approbation.mjs", ancien: "ms(w.start) <= tMs && tMs < ms(w.end) && w.remaining >= 1)", nouveau: "ms(w.start) <= tMs && tMs < ms(w.end))" }]);
      const A1 = await m.importer("lib/approbation.mjs");
      expect(A1.evaluer(P, c.request, { fenetres: c.windows, t: c.t, policy_version: doc.policy_version }).decision).to.equal("autorise");
    });

    it("TA-5 (MN-5) : tickets/consommation-tardive.json : un consommer hors de l'état approuve est refusé (requete_invalide, pas 13) ; mutant sans ce refus : la trace diverge (tué)", async function () {
      await tueTrace("consommation-tardive", mutant("mn5", [{ fichier: "lib/approbation.mjs", ancien: 'if (tk.state !== "approuve") return this.refuser(sortie, "requete_invalide", tk, "consommer", atMs, data);', nouveau: "if (false) return null;" }]), [13]);
    });

    it("TA-6 (MN-6) : tickets/plafond.json : la demande au-delà de max_open_tickets reçoit plafond_atteint (pas 4) ; mutant sans plafond : la trace diverge (tué)", async function () {
      await tueTrace("plafond", mutant("mn6", [{ fichier: "lib/approbation.mjs", ancien: 'if (ouverts >= this.service.max_open_tickets) return this.refuser(sortie, "plafond_atteint");', nouveau: "if (false) return null;" }]), [4]);
    });

    it("TA-38 (MN-38) : tickets/jeu-reassigne.json : le ticket expire avec la raison « jeu reassigne » ; mutant qui ne marque plus la réassignation : la trace diverge au pas 10 (tué)", async function () {
      await tueTrace("jeu-reassigne", mutant("mn38", [{ fichier: "lib/approbation.mjs", ancien: 'if (cause === "jeu_non_attendu") tk.set_reassigned = true;', nouveau: "if (false) tk.set_reassigned = true;" }]), [10]);
    });

    it("TA-50 (MN-50) : tickets/jeu-seuil-abaisse.json : le seuil effectif ne baisse jamais pendant la vie du ticket ; mutant qui suit la baisse : la trace diverge aux pas 6 et 8 (tué)", async function () {
      await tueTrace("jeu-seuil-abaisse", mutant("mn50", [{ fichier: "lib/approbation.mjs", ancien: "tk.effective_required = Math.max(tk.effective_required ?? 0, jeu.threshold.required);", nouveau: "tk.effective_required = jeu.threshold.required;" }]), [6, 8]);
    });

    const remises = () => ["valides", "invalides"].flatMap((rep) => fs.readdirSync(path.join(CT3, "decisions", rep)).filter((f) => f.endsWith(".json")).sort().map((f) => lireJSON(CT3, "decisions", rep, f)));

    it("TA-44 (MN-44) : decisions/ : les remises à signature invalide (SG-5) ou à approbateur hors du jeu (SG-6) sont refusées ; mutants sans SG-5 ou sans SG-6 : au moins une de ces remises est scellée ou refusée pour une autre raison (tués)", async function () {
      const A0 = await ref("lib/approbation.mjs");
      const S0 = schemasDe(A0);
      const cibles = remises().filter((c) => ["signature_invalide", "approbateur_hors_jeu"].includes(c.expected.reason));
      expect(cibles.length).to.be.at.least(2);
      for (const c of cibles) {
        const r = A0.verifierRemise(c.remise, c.context, { schemas: S0 });
        expect({ result: r.result, reason: r.reason }, c.id).to.deep.equal(c.expected);
      }
      const m5 = mutant("mn44-sg5", [{ fichier: "lib/approbation.mjs", ancien: 'if (!J.verifierSignatureApprobation(A, a.signatures[i], a.approvers[i]).ok) return refus("SG-5", "signature_invalide");', nouveau: "if (false) return null;" }]);
      const m6 = mutant("mn44-sg6", [{ fichier: "lib/approbation.mjs", ancien: 'if (a.approvers.some((x) => !js.members.includes(x))) return refus("SG-6", "approbateur_hors_jeu");', nouveau: "if (false) return null;" }]);
      for (const [m, raison] of [[m5, "signature_invalide"], [m6, "approbateur_hors_jeu"]]) {
        const A1 = await m.importer("lib/approbation.mjs");
        const S1 = schemasDe(A1);
        const divergents = cibles.filter((c) => c.expected.reason === raison).filter((c) => {
          const r = A1.verifierRemise(c.remise, c.context, { schemas: S1 });
          return !egal({ result: r.result, reason: r.reason }, c.expected);
        });
        expect(divergents.length, `mutant sans ${raison}`).to.be.at.least(1);
      }
    });

    it("TA-48 (MN-48) : decisions/invalides sg7-auto-approbation : la remise signée par le demandeur est refusée par SG-7 ; mutant sans SG-7 : scellée (tué)", async function () {
      const c = remises().find((x) => x.id === "sg7-auto-approbation");
      const A0 = await ref("lib/approbation.mjs");
      const r0 = A0.verifierRemise(c.remise, c.context, { schemas: schemasDe(A0) });
      expect([r0.result, r0.reason, r0.check]).to.deep.equal(["refuse", "auto_approbation", "SG-7"]);
      const m = mutant("mn48", [{ fichier: "lib/approbation.mjs", ancien: 'if (a.approvers.some((x) => demandeur.includes(String(x).toLowerCase()))) return refus("SG-7", "auto_approbation");', nouveau: "if (false) return null;" }]);
      const A1 = await m.importer("lib/approbation.mjs");
      expect(A1.verifierRemise(c.remise, c.context, { schemas: schemasDe(A1) }).result).to.equal("scelle");
    });

    it("TA-49 (MN-49) : signatures/normalisation.json : chaque forme refusée l'est par le noyau (r, s hors de ]0, n[, v hors de {0, 1, 27, 28}) ; mutant qui délègue ces contrôles : au moins une forme refusée est normalisée (tué)", async function () {
      const doc = lireJSON(CT3, "signatures", "normalisation.json");
      const refusees = doc.cases.filter((c) => c.expected === null);
      expect(refusees.length).to.be.at.least(5);
      const A0 = await ref("lib/approbation.mjs");
      for (const c of refusees) expect(A0.normaliserSignature(c.signature), c.id).to.deep.equal({ signature: null, reason: c.reason });
      const m = mutant("mn49", [
        { fichier: "lib/approbation.mjs", ancien: "if (rn === 0n || rn >= N_SECP256K1 || s === 0n || s >= N_SECP256K1) return refus;", nouveau: "if (false) return refus;" },
        { fichier: "lib/approbation.mjs", ancien: "if (v !== 27 && v !== 28) return refus;", nouveau: "if (false) return refus;" },
      ]);
      const A1 = await m.importer("lib/approbation.mjs");
      const passees = refusees.filter((c) => A1.normaliserSignature(c.signature).signature !== null).map((c) => c.id);
      expect(passees.length, "formes refusées acceptées par le mutant").to.be.at.least(4);
    });
  });

  // -------------------------------------------------------------------------
  describe("console d'approbation et annuaire (CT-3 §9, §13, CS-, AN-) : composant approbation_console", function () {
    const CT3 = path.join(VECTEURS, "ct-3");
    const fichiers = (...p) => fs.readdirSync(path.join(CT3, ...p)).filter((f) => f.endsWith(".json")).sort();

    it("TA-45 (MN-45) : console/reponses : une réponse du portefeuille qui ne recouvre pas l'adresse de l'approbateur sur le D_A de la console n'aboutit à aucun vote (adresse_differente) ; mutant sans la comparaison : accepte (tué)", async function () {
      const cas = fichiers("console", "reponses").map((f) => lireJSON(CT3, "console", "reponses", f)).filter((c) => c.expected.reason === "adresse_differente");
      expect(cas.length).to.be.at.least(1);
      const K0 = await ref("lib/console.mjs");
      const m = mutant("mn45", [{ fichier: "lib/console.mjs", ancien: 'if (recovered !== String(adresse).toLowerCase()) return refus("adresse_differente", recovered);', nouveau: "if (false) return null;" }]);
      const K1 = await m.importer("lib/console.mjs");
      for (const c of cas) {
        const d = K0.condenses(c.input.a).d_a;
        expect(K0.verifierReponse(c.input.response, d, c.input.approver).outcome, c.id).to.equal("refuse");
        expect(K1.verifierReponse(c.input.response, d, c.input.approver).outcome, `${c.id} (mutant)`).to.equal("accepte");
      }
    });

    it("TA-46 (MN-46) : console/decouverte : deux annonces de même uuid par des objets différents sont exclues toutes deux ; mutant sans l'exclusion : un portefeuille est retenu et au moins un cas diverge (tué)", async function () {
      const cas = fichiers("console", "decouverte").map((f) => lireJSON(CT3, "console", "decouverte", f));
      const K0 = await ref("lib/console.mjs");
      for (const c of cas) expect(K0.decouvrir(c.input.announcements), c.id).to.deep.equal(c.expected);
      const m = mutant("mn46", [{ fichier: "lib/console.mjs", ancien: "else if (present.provider !== provider) {", nouveau: "else if (false) {" }]);
      const K1 = await m.importer("lib/console.mjs");
      const divergents = cas.filter((c) => !egal(K1.decouvrir(c.input.announcements), c.expected)).map((c) => c.id);
      expect(divergents.length).to.be.at.least(1);
    });

    it("TA-47 (MN-47) : annuaire/traces/confiscation.json : une adresse déjà attribuée n'est jamais réattribuée (adresse_deja_attribuee, pas 3 et 5) ; mutant sans ce refus : la trace diverge (tué)", async function () {
      const t = lireJSON(CT3, "annuaire", "traces", "confiscation.json");
      const rejouer = (K) => {
        let doc = lireJSON(CT3, "annuaire", t.initial);
        let defis = [];
        const ecarts = [];
        for (const [i, p] of t.steps.entries()) {
          const r = K.appliquerOperation(doc, p.method, p.request, p.at, { defis, nonce: p.challenges[0] ?? null, identifiant: "compteur" });
          if (!egal({ accepted: r.accepted, reason: r.reason }, { accepted: p.expected.accepted, reason: p.expected.reason })) ecarts.push(i + 1);
          doc = r.annuaire;
          defis = r.defis;
        }
        return ecarts;
      };
      expect(rejouer(await ref("lib/console.mjs"))).to.deep.equal([]);
      const m = mutant("mn47", [{ fichier: "lib/console.mjs", ancien: 'return refus("adresse_deja_attribuee");', nouveau: ";", tous: true }]);
      expect(rejouer(await m.importer("lib/console.mjs"))).to.include.members([3]);
    });
  });

  // -------------------------------------------------------------------------
  describe("enregistreur : analyse stricte, agrégation, passerelle, écrivain, segments (CT-2) : composants hote_agent, mandataire_mcp, passerelle_modele, ecrivain_stockage", function () {
    const CT2 = path.join(VECTEURS, "ct-2");
    const SCHEMAS_CT2 = (J) => J.registreSchemas(["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"].map(schemaJSON));

    it("TA-4 (MN-4) : jcs-integral ct1-4-cle-en-double est refusé, et un argument décimal non représentable en double (1.00000000000000001) est refusé au relais (-32602 nombre_non_representable) ; mutants sans ces contrôles : la clé en double est canonisée et la requête est relayée (tués)", async function () {
      const C0 = await ref("lib/capture.mjs");
      const cas = lireJSON(CT2, "jcs-integral", "cas.json").find((c) => c.name === "ct1-4-cle-en-double");
      expect(cas.canonical).to.equal(null);
      expect(() => C0.jcsIntegralDuTexte(cas.input)).to.throw();
      const ligne = '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pay__virement","arguments":{"amount":1.00000000000000001}}}';
      expect(C0.lireRequeteHote(ligne).erreur).to.deep.equal({ code: -32602, message: "Invalid params", data: { reason: "nombre_non_representable" } });
      const m = mutant("mn4", [
        { fichier: "lib/capture.mjs", ancien: "if (Object.hasOwn(v, k)) erreur(`clé en double « ${k} »`, true);", nouveau: "if (false) erreur(`clé en double « ${k} »`, true);" },
        { fichier: "lib/capture.mjs", ancien: 'if (!textesDesNombres(r.texte.slice(e.debut, e.fin)).every(nombreExact)) return { erreur: { code: -32602, message: "Invalid params", data: { reason: "nombre_non_representable" } }, id: msg.id ?? null };', nouveau: "if (false) return null;" },
      ]);
      const C1 = await m.importer("lib/capture.mjs");
      expect(C1.jcsIntegralDuTexte(cas.input)).to.be.a("string");
      expect(C1.lireRequeteHote(ligne).erreur).to.equal(undefined);
    });

    it("TA-7 (MN-7, partie exécutable ; la partie « définition changée entre deux tools/list » exige un serveur vivant, phase 2, étape 4) : pieces-mcp/agregation : un outil noortrace.* annoncé par un serveur est rejeté (nom_reserve) ; mutant sans l'espace réservé : il est annoncé (tué)", async function () {
      const at = lireJSON(CT2, "pieces-mcp", "agregation", "attendu.json");
      const serveurs = lireJSON(CT2, "pieces-mcp", "agregation", "serveurs.json");
      const reserves = at.rejected.filter((r) => r.reason === "nom_reserve");
      expect(reserves.length).to.be.at.least(1);
      const C0 = await ref("lib/capture.mjs");
      const r0 = C0.agregerOutils(serveurs, { prefix: at.prefix, page_size: at.page_size });
      expect(r0.rejected).to.deep.equal(at.rejected);
      const m = mutant("mn7", [{ fichier: "lib/capture.mjs", ancien: 'if (typeof original !== "string" || original.startsWith("noortrace.")) {', nouveau: 'if (typeof original !== "string") {' }]);
      const C1 = await m.importer("lib/capture.mjs");
      const r1 = C1.agregerOutils(serveurs, { prefix: at.prefix, page_size: at.page_size });
      expect(r1.rejected.filter((r) => r.reason === "nom_reserve")).to.deep.equal([]);
      expect(r1.announced.some((a) => String(a.original).startsWith("noortrace."))).to.equal(true);
    });

    it("TA-13 (MN-13) : pieces-modele/gemini-refus-mcp-fournisseur : une requête qui déclare un serveur MCP au fournisseur est refusée (serveurs_mcp_fournisseur) ; mutant sans le refus : elle part (tué)", async function () {
      const nom = "gemini-refus-mcp-fournisseur";
      const at = lireJSON(CT2, "pieces-modele", nom, "attendu.json");
      expect(at.refused.reason).to.equal("serveurs_mcp_fournisseur");
      const ligne = lireJSON(CT2, "pieces-modele", nom, "requete-ligne.json");
      const corps = fs.readFileSync(path.join(CT2, "pieces-modele", nom, "requete.json"));
      const ROUTES = [{ path: "/v1beta/models", format: "gemini", provider_label: "gemini" }, { path: "/v1/models", format: "gemini", provider_label: "gemini" }];
      // Réponse simulée du fournisseur : la référence refuse avant de la lire ; le mutant, lui, relaie et la consomme.
      const reponse = { status: 200, content_type: "application/json; charset=UTF-8", corps: Buffer.from(JSON.stringify({ candidates: [{ content: { parts: [{ text: "ok" }], role: "model" }, finishReason: "STOP", index: 0 }], modelVersion: "m" }), "utf8") };
      const echange = async (racine) => {
        const C = await importer(racine, "lib/capture.mjs");
        const J = await importer(racine, "lib/journal.mjs");
        const PII = C.chargerPolitique(lireJSON(CT2, "redaction", "politique-pii-v1.json"), { schemas: SCHEMAS_CT2(J) });
        return C.echangeGemini({ method: ligne.method, target: ligne.target, routes: ROUTES, hote_connu: ligne.host_known !== false, requete: { corps, content_type: "application/json" }, reponse, politique: PII, prompt_in_request: at.options.prompt_in_request, prompt_system: at.options.prompt_system });
      };
      const r0 = await echange(RACINE);
      expect([r0.refus.status, r0.refus.raison]).to.deep.equal([at.refused.status, "serveurs_mcp_fournisseur"]);
      const m = mutant("mn13", [{ fichier: "lib/capture.mjs", ancien: 'if (provider_mcp !== "relayer") return refuser("serveurs_mcp_fournisseur", { entries: n });', nouveau: "if (false) return null;" }]);
      const r1 = await echange(m.racine);
      expect(r1.refus?.raison).to.not.equal("serveurs_mcp_fournisseur");
    });

    it("TA-20 (MN-20) : evenements/journal-demo/segment.ndjson privé de sa fin de ligne finale : la relecture tronque à la dernière ligne complète (tronque vrai) ; mutant qui lit une ligne non terminée : il l'accepte (tué)", async function () {
      const texte = fs.readFileSync(path.join(CT2, "evenements", "journal-demo", "segment.ndjson"), "utf8");
      expect(texte.endsWith("\n")).to.equal(true);
      const total = texte.trimEnd().split("\n").length - 1;
      const sansFin = texte.slice(0, -1);
      const cles = lireJSON(CT2, "evenements", "journal-demo", "cles.json");
      const relire = async (racine) => {
        const C = await importer(racine, "lib/capture.mjs");
        const J = await importer(racine, "lib/journal.mjs");
        const r = C.relireSegment(sansFin, { schemas: SCHEMAS_CT2(J), clesPubliques: cles });
        return [r.evenements.length, r.tronque, r.corrompu];
      };
      expect(await relire(RACINE)).to.deep.equal([total - 1, true, null]);
      const m = mutant("mn20", [{ fichier: "lib/capture.mjs", ancien: "const finLigne = buf.indexOf(0x0a, pos);", nouveau: "const finLigne = buf.indexOf(0x0a, pos) < 0 ? buf.length : buf.indexOf(0x0a, pos);" }]);
      expect(await relire(m.racine)).to.deep.equal([total, false, null]);
    });

    it("TA-21 (MN-21) : l'écrivain bloque (mode dégradé horloge) un recul au-delà de max_backstep_ms et un saut en avant au-delà de max_forward_ms mesuré contre l'horloge monotone ; mutant sans ces deux contrôles : les événements sont scellés à la date fausse (tué)", async function () {
      const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
      const JOURNAL = "0x" + "11".repeat(32);
      const essai = async (racine) => {
        const C = await importer(racine, "lib/capture.mjs");
        const J = await importer(racine, "lib/journal.mjs");
        const cle = J.cleEd25519DepuisGraine(J.sha256(Buffer.from("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01", "utf8")));
        const politique = (v) => C.partielPolitique({ policy_version: v, policy_sha256: J.sha256(Buffer.from(v)) });
        const ecrivain = () => new C.Ecrivain({ org_id: ORG, journal_id: JOURNAL, recorder_key_id: "rec-test-01", cles: { "rec-test-01": cle.clePrivee }, schemas: SCHEMAS_CT2(J), dernier: null });
        const out = {};
        const e1 = ecrivain();
        e1.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:05.000Z" });
        try {
          out.recul = e1.sceller(politique("v2"), { ts_lu: "2026-11-10T09:59:59.999Z" }).ts;
        } catch (err) {
          out.recul = err instanceof C.ErreurModeDegrade ? `degrade:${err.raison}` : `erreur:${err.message}`;
        }
        const e2 = ecrivain();
        e2.sceller(politique("v1"), { ts_lu: "2026-11-10T10:00:00.000Z", mono: 1000 });
        try {
          out.saut = e2.sceller(politique("v2"), { ts_lu: "2026-11-10T10:03:00.000Z", mono: 2000 }).ts;
        } catch (err) {
          out.saut = err instanceof C.ErreurModeDegrade ? `degrade:${err.raison}` : `erreur:${err.message}`;
        }
        return out;
      };
      expect(await essai(RACINE)).to.deep.equal({ recul: "degrade:horloge", saut: "degrade:horloge" });
      const m = mutant("mn21", [
        { fichier: "lib/capture.mjs", ancien: 'if (!capture && lu < prec - this.max_backstep_ms) throw new ErreurModeDegrade("horloge"', nouveau: 'if (false) throw new ErreurModeDegrade("horloge"' },
        { fichier: "lib/capture.mjs", ancien: 'if (avanceMurale > avanceMonotone + this.max_forward_ms) throw new ErreurModeDegrade("horloge"', nouveau: 'if (false) throw new ErreurModeDegrade("horloge"' },
      ]);
      expect(await essai(m.racine)).to.deep.equal({ recul: "2026-11-10T10:00:05.000Z", saut: "2026-11-10T10:03:00.000Z" });
    });

    it("TA-14 (MN-14, partie exécutable ; la démonstration en mode passerelle est de phase 2, étape 4) : le schéma de configuration refuse un model.mode inconnu ; schéma mutant sans l'énumération : accepté (tué)", async function () {
      const J = await ref("lib/journal.mjs");
      const C = await ref("lib/capture.mjs");
      const config = lireJSON(RACINE, "deploiement", "config", "rapide", "configuration.json");
      expect(config.model.mode).to.equal("passerelle");
      config.model.mode = "inconnu";
      const noms = ["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"];
      const S0 = J.registreSchemas(noms.map(schemaJSON));
      expect(J.validerSchema(config, S0[C.ID_SCHEMA_CONFIGURATION], { registre: S0 }).some((e) => e.chemin === "/model/mode")).to.equal(true);
      const schemaMutant = schemaJSON("configuration-enregistreur");
      let retire = 0;
      (function retirer(v) {
        if (Array.isArray(v)) v.forEach(retirer);
        else if (v && typeof v === "object") {
          if (Array.isArray(v.enum) && v.enum.includes("passerelle") && v.enum.includes("icap")) {
            delete v.enum;
            retire += 1;
          }
          Object.values(v).forEach(retirer);
        }
      })(schemaMutant);
      expect(retire).to.equal(1);
      const S1 = J.registreSchemas([schemaMutant, ...noms.filter((n) => n !== "configuration-enregistreur").map(schemaJSON)]);
      expect(J.validerSchema(config, S1[C.ID_SCHEMA_CONFIGURATION], { registre: S1 })).to.deep.equal([]);
    });

    it("TA-43 (MN-43, partie exécutable) : le schéma refuse une valeur littérale là où une référence de secret est attendue (model.static_tokens[0].token) ; schéma mutant dont la définition secret_reference admet n'importe quelle forme : accepté (tué)", async function () {
      const J = await ref("lib/journal.mjs");
      const C = await ref("lib/capture.mjs");
      const config = lireJSON(RACINE, "deploiement", "config", "rapide", "configuration.json");
      expect(config.model.static_tokens[0].token).to.have.property("file");
      config.model.static_tokens[0].token = "jeton-colle-en-clair-0123456789abcdef";
      const noms = ["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"];
      const S0 = J.registreSchemas(noms.map(schemaJSON));
      const chemin = "/model/static_tokens/0/token";
      expect(J.validerSchema(config, S0[C.ID_SCHEMA_CONFIGURATION], { registre: S0 }).some((e) => e.chemin.startsWith(chemin))).to.equal(true);
      const schemaMutant = schemaJSON("configuration-enregistreur");
      expect(schemaMutant.$defs.secret_reference.$ref).to.be.a("string");
      schemaMutant.$defs.secret_reference = {};
      const S1 = J.registreSchemas([schemaMutant, ...noms.filter((n) => n !== "configuration-enregistreur").map(schemaJSON)]);
      expect(J.validerSchema(config, S1[C.ID_SCHEMA_CONFIGURATION], { registre: S1 }).filter((e) => e.chemin.startsWith(chemin))).to.deep.equal([]);
    });

    it("TA-23 (MN-23, oracle sur le vecteur) : evenements/journal-demo : chaque version de politique employée est annoncée par un événement noortrace.journal.politique de seq inférieur à son premier usage ; la réponse retirée serait un générateur qui n'émet plus cet événement, et le vecteur régénéré différerait (CI : git diff)", async function () {
      const J = await ref("lib/journal.mjs");
      const evs = lireJSON(CT2, "evenements", "journal-demo", "evenements.json");
      const versions = new Map();
      for (const e of evs) if (!versions.has(e.code.policy_version)) versions.set(e.code.policy_version, e.seq);
      expect(versions.size).to.be.at.least(1);
      for (const [v, premier] of versions) {
        const annonce = evs.find((e) => e.execution.tool === J.OUTIL_POLITIQUE && e.execution.arguments?.value?.policy_version === v);
        expect(annonce, `annonce de ${v}`).to.not.equal(undefined);
        expect(annonce.seq, `annonce de ${v} avant son premier usage`).to.be.at.most(premier);
      }
    });
  });

  // -------------------------------------------------------------------------
  describe("ingestion OpenTelemetry et copies WORM (CT-2 §6.8, §12.6) : composants sdk_otel, worm_gel", function () {
    const CT2 = path.join(VECTEURS, "ct-2");

    it("TA-15 et TA-16 (MN-15, MN-16) : nomOutil préfixe toujours l'alias de la source et remplace par nom-invalide un nom qui porte « __ » ou noortrace. (vecteur otel/json-outil-nom-invalide) ; mutants sans préfixe ou sans la règle « __ » : un nom d'une autre source passe (tués)", async function () {
      const OT0 = await ref("lib/otel.mjs");
      expect(OT0.nomOutil("otel-sinistres", "paiement__creer").tool).to.equal("otel-sinistres__nom-invalide");
      expect(OT0.nomOutil("otel-sinistres", "noortrace.journal.politique").tool).to.equal("otel-sinistres__nom-invalide");
      expect(OT0.nomOutil("otel-sinistres", "creer").tool).to.equal("otel-sinistres__creer");
      expect(fs.readFileSync(path.join(CT2, "otel", "json-outil-nom-invalide", "attendu.json"), "utf8")).to.include("otel-sinistres__nom-invalide");
      const m16 = mutant("mn16", [{ fichier: "lib/otel.mjs", ancien: 'const valide = RE_NOM_DECLARE.test(N) && !N.includes("__") && !N.startsWith("noortrace.") && C.longueurPointsDeCode(`${alias}__${N}`) <= 128;', nouveau: 'const valide = RE_NOM_DECLARE.test(N) && !N.startsWith("noortrace.") && C.longueurPointsDeCode(`${alias}__${N}`) <= 128;' }]);
      const OT16 = await m16.importer("lib/otel.mjs");
      expect(OT16.nomOutil("otel-sinistres", "paiement__creer").tool).to.equal("otel-sinistres__paiement__creer");
      const m15 = mutant("mn15", [{ fichier: "lib/otel.mjs", ancien: 'return { tool: `${alias}__${valide ? N : "nom-invalide"}`', nouveau: 'return { tool: `${valide ? N : "nom-invalide"}`' }]);
      const OT15 = await m15.importer("lib/otel.mjs");
      expect(OT15.nomOutil("otel-sinistres", "creer").tool).to.equal("creer");
    });

    it("TA-27 (MN-27) : worm/etats.json s3-sans-mode et s3-mode-governance rendent non_conforme ; mutant sans le contrôle du mode de verrou : conforme (tué)", async function () {
      const doc = lireJSON(CT2, "worm", "etats.json");
      const cibles = ["s3-sans-mode", "s3-mode-governance"].map((id) => doc.cases.find((c) => c.id === id));
      const W0 = await ref("lib/worm.mjs");
      for (const c of cibles) expect(W0.etatVerrou(c.input).verdict, c.id).to.equal("non_conforme");
      const m = mutant("mn27", [
        { fichier: "lib/worm.mjs", ancien: 'if (mode === null) reasons.push("mode_absent");', nouveau: "if (false) reasons.push(\"mode_absent\");" },
        { fichier: "lib/worm.mjs", ancien: 'else if (mode !== attenduMode) reasons.push("mode_non_conforme");', nouveau: "else if (false) reasons.push(\"mode_non_conforme\");" },
      ]);
      const W1 = await m.importer("lib/worm.mjs");
      for (const c of cibles) expect(W1.etatVerrou(c.input).verdict, `${c.id} (mutant)`).to.equal("conforme");
    });

    it("TA-28 (MN-28) : worm/gardes.json meme-identite : une levée accordée par l'identité qui l'a demandée est refusée ; mutant sans la règle de garde : valide (tué)", async function () {
      const c = lireJSON(CT2, "worm", "gardes.json").cases.find((x) => x.id === "meme-identite");
      const W0 = await ref("lib/worm.mjs");
      const r0 = W0.verifierGarde(c.input.records);
      expect([r0.valid, r0.errors.map((e) => e.code)]).to.deep.equal([false, ["meme_identite"]]);
      const m = mutant("mn28", [{ fichier: "lib/worm.mjs", ancien: 'if (approuvee >= 0 && enregistrements[approuvee].actor === r.actor) fautes.add("meme_identite");', nouveau: 'if (false) fautes.add("meme_identite");' }]);
      const W1 = await m.importer("lib/worm.mjs");
      expect(W1.verifierGarde(c.input.records).valid).to.equal(true);
    });
  });

  // -------------------------------------------------------------------------
  describe("planificateur d'ancrage (CT-5 §8, AN-) : composants ancrage, reseau, cles", function () {
    const CT5 = path.join(VECTEURS, "ct-5");
    /**
     * La référence reproduit la trace ; le mutant diverge d'abord au pas `index`
     * (0-indexé dans verifierTrace, qui borne les écarts d'actions à cinq) où
     * l'action attendue est `attendu` ; `file` exige en plus un écart sur la file
     * finale. Un mutant qui lève est un mutant mal posé (EX-10.6) : l'exception
     * fait échouer le test.
     */
    const traceDiverge = async (nom, m, { index, attendu, file = false }) => {
      const t = lireJSON(CT5, "planification", `${nom}.json`);
      const A0 = await ref("lib/ancrage.mjs");
      expect(A0.verifierTrace(t), `${nom} : référence`).to.deep.equal([]);
      const A1 = await m.importer("lib/ancrage.mjs");
      const ecarts = A1.verifierTrace(t);
      const premier = ecarts.find((e) => e.index !== undefined);
      expect(premier, `${nom} : le mutant doit diverger sur les actions`).to.not.equal(undefined);
      expect([premier.index, premier.attendu?.action], `${nom} : première divergence`).to.deep.equal([index, attendu]);
      if (file) expect(ecarts.some((e) => e.queue !== undefined), `${nom} : la file finale doit diverger`).to.equal(true);
    };

    it("TA-60 (MN-60) : planification/horloge-suspecte.json : un jeton dont genTime s'écarte de l'envoi au-delà de clock_tolerance_s est promu et marqué horloge_suspecte ; mutant sans le marquage : la trace diverge au pas 28 (tué)", async function () {
      await traceDiverge("horloge-suspecte", mutant("mn60", [{ fichier: "lib/ancrage.mjs", ancien: 'if (Math.abs(genTime - envoi) > f.clock_tolerance_s * 1000) res.avertissements.push("horloge_suspecte");', nouveau: 'if (false) res.avertissements.push("horloge_suspecte");' }]), { index: 28, attendu: "journaliser" });
    });

    it("TA-76 (MN-76) : planification/reponse-tardive.json : une réponse reçue au-delà de max_response_delay_s est classée reponse_tardive ; mutant sans le contrôle de fraîcheur : la trace diverge au pas 44 (tué)", async function () {
      await traceDiverge("reponse-tardive", mutant("mn76", [{ fichier: "lib/ancrage.mjs", ancien: "if (t - envoi > f.max_response_delay_s * 1000) {", nouveau: "if (false) {" }]), { index: 44, attendu: "rejeter_reponse" });
    });

    it("TA-62 (MN-62, partie exécutable ; le retrait de la relève elle-même est le complément) : planification/principal-injoignable.json : la relève par le secours configuré est consignée (anchor_fallback) ; le test éprouve le mécanisme, pas l'existence d'un secours utilisable (CT-5 EX-11.3) ; mutant sans la consignation de la relève : la trace diverge au pas 47 (tué)", async function () {
      await traceDiverge("principal-injoignable", mutant("mn62", [{ fichier: "lib/ancrage.mjs", ancien: 'this.journaliser(t, d.id, { event: "anchor_fallback", to: secours.id, reason: cause });', nouveau: ";" }]), { index: 47, attendu: "journaliser" });
    });

    it("TA-63 (MN-63) : planification/point-manquant.json : l'absence de point admis au-delà de 2 × c_K lève l'alerte point_manquant ; mutant sans l'alerte : la trace diverge au pas 3 (tué)", async function () {
      await traceDiverge("point-manquant", mutant("mn63", [{ fichier: "lib/ancrage.mjs", ancien: 'this.alerter(t, null, "point_manquant", "majeure");', nouveau: ";" }]), { index: 3, attendu: "alerter" });
    });

    it("TA-64 (MN-64) : planification/file-perdue.json : les demandes manquantes sont recréées au démarrage et l'alerte file_perdue est levée ; mutant sans la reconstruction : la trace diverge dès le pas 1 et sur la file finale ; mutant sans l'alerte : la trace diverge au pas 17 (tués)", async function () {
      await traceDiverge("file-perdue", mutant("mn64-reconstruction", [
        { fichier: "lib/ancrage.mjs", ancien: "      this.periodeClose(t, m, { seulement: manquantes });\n", nouveau: "      ;\n" },
        { fichier: "lib/ancrage.mjs", ancien: "      this.pointProduit(t, k);\n", nouveau: "      ;\n" },
      ]), { index: 1, attendu: "ecrire_file", file: true });
      await traceDiverge("file-perdue", mutant("mn64-alerte", [{ fichier: "lib/ancrage.mjs", ancien: 'if (recreees > 0) this.alerter(t, null, "file_perdue", "critique");', nouveau: 'if (false) this.alerter(t, null, "file_perdue", "critique");' }]), { index: 17, attendu: "alerter" });
    });

    it("TA-65 (MN-65) : verifierConfiguration (AN-1, règle 4) refuse en production un principal sans statut qualified ; mutant sans la règle 4 pour le principal : accepté (tué)", async function () {
      const md = fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8");
      const bloc = /<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(md);
      const doc = JSON.parse(bloc[1]);
      doc.rfc3161.providers.find((p) => p.role === "principal").qualified = null;
      const A0 = await ref("lib/ancrage.mjs");
      expect(A0.verifierConfiguration(doc, { lecteurCertificat: () => true, checkpoint_interval_s: 60 }).violations.map((v) => v.rule)).to.deep.equal([4]);
      const m = mutant("mn65", [{ fichier: "lib/ancrage.mjs", ancien: "if (principal && (principal.qualified === null || principal.qualified === undefined)) v(4,", nouveau: "if (false) v(4," }]);
      const A1 = await m.importer("lib/ancrage.mjs");
      expect(A1.verifierConfiguration(doc, { lecteurCertificat: () => true, checkpoint_interval_s: 60 }).violations).to.deep.equal([]);
    });
  });

  // -------------------------------------------------------------------------
  describe("registre (CT-4 CP-, RG-, transactions) : composants registre, exploitant", function () {
    const CT4 = path.join(VECTEURS, "ct-4");

    it("TA-56 (MN-56) : capture/capture.json cp4-autre-jeu, cp4-valset-hash-index et cp4-certificat-autre-bloc sont refusés par CP-4 (certificat_invalide) ; mutant sans les contrôles CP-4 : CP-4 réussit (tué)", async function () {
      const famille = lireJSON(CT4, "capture", "capture.json");
      const constantes = lireJSON(CT4, "constantes.json");
      const cibles = famille.cases.filter((c) => c.id.startsWith("cp4-"));
      expect(cibles.map((c) => c.id)).to.deep.equal(["cp4-autre-jeu", "cp4-valset-hash-index", "cp4-certificat-autre-bloc"]);
      const noms = ["instance-registre-v0", "inscription-client-v0", "operations-registre-v0", "registre-v0", "validateurs-v0", "ancres-confiance-v0", "politique-approbation-v0"];
      const verifier = async (racine, c) => {
        const C = await importer(racine, "lib/conventions-registre.mjs");
        const schemas = C.registreSchemasCt4(noms.map((n) => lireJSON(SPEC, "schemas", `${n}.schema.json`)));
        const rep = path.join(CT4, c.input.directory);
        const lire = (n) => (fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null);
        const validators = c.input.validators.startsWith("constantes.json") ? { validators: constantes.test_validators.validators.map(({ id, pubKeyHex }) => ({ id, pubKeyHex })) } : lireJSON(RACINE, c.input.validators);
        const r = C.verifierCapture({ index: lireJSON(rep, c.input.index), lireFichier: lire, validators, bft_chain_id: c.input.bft_chain_id, schemas });
        return r.checks.find((x) => x.check === "CP-4");
      };
      for (const c of cibles) {
        const v = await verifier(RACINE, c);
        expect([v.status, v.code], c.id).to.deep.equal(["echoue", "certificat_invalide"]);
      }
      const m = mutant("mn56", [{ fichier: "lib/conventions-registre.mjs", ancien: 'C("CP-4", ', nouveau: 'C("CP-4", true || ', tous: true }]);
      for (const c of cibles) expect((await verifier(m.racine, c)).status, `${c.id} (mutant)`).to.equal("reussi");
    });

    it("TA-72 (MN-72, oracle sur le vecteur) : transactions.json : chaque appel de contrat porte un sélecteur de la table de CT-4 §6.7.1 et des arguments alignés sur 32 octets, avec une valeur nulle ; le seul transfert de valeur (approvisionnement) n'a pas de données et le seul déploiement n'a pas de destinataire ; aucun champ de contenu n'est transporté", async function () {
      const C = await ref("lib/conventions-registre.mjs");
      const selecteurs = new Set(Object.values(C.SELECTEURS).map((s) => String(s).toLowerCase()));
      const doc = lireJSON(CT4, "transactions.json");
      // Les cas donnés en transaction brute (raw_transaction) éprouvent le décodage et les refus de RG-15 ; l'oracle porte sur les champs des transactions construites.
      const construits = doc.cases.filter((c) => c.input.fields);
      expect(construits.length).to.be.at.least(10);
      const sortes = { appel: 0, transfert: 0, deploiement: 0 };
      // Le code de déploiement du contrat (seule transaction sans destinataire) ; sa variante refusée « avec destinataire » porte le même code.
      const codeDeploiement = construits.find((c) => c.input.fields.to === null).input.fields.data;
      for (const c of construits) {
        const f = c.input.fields;
        if (f.data === codeDeploiement) {
          sortes.deploiement += 1;
          expect(f.value, `${c.id} : value`).to.equal("0");
        } else if (f.data === "0x") {
          sortes.transfert += 1;
          expect(c.id, "un transfert de valeur n'est qu'un approvisionnement").to.match(/^approvisionnement/);
          expect(BigInt(f.value) > 0n, `${c.id} : value`).to.equal(true);
        } else {
          sortes.appel += 1;
          expect(selecteurs.has(f.data.slice(0, 10).toLowerCase()), `${c.id} : sélecteur`).to.equal(true);
          expect((f.data.length - 10) % 64, `${c.id} : mots de 32 octets`).to.equal(0);
          expect(f.value, `${c.id} : value`).to.equal("0");
        }
      }
      expect(sortes.deploiement).to.be.at.least(1);
      expect(sortes.transfert).to.be.at.least(1);
      expect(sortes.appel).to.equal(construits.length - sortes.transfert - sortes.deploiement);
    });
  });
});

// ---------------------------------------------------------------------------
// Démon de l'étape 4 (paquets/enregistreur) : la même attaque est jouée sur le
// démon du dépôt (la réponse en place : le test passe) puis sur un mutant du
// paquet (copie de paquets/enregistreur où la réponse est retirée par un
// remplacement exact, EX-10.5 : le test échoue, le mutant est tué). Démons
// réels `bin/noortrace --config` (magasin de bail `file`, classe D, frontal
// MCP Streamable HTTP à jetons statiques, serveur d'outils stdio de test,
// service d'approbation simulé joint en HTTP) ou modules du paquet importés
// par leur chemin.
// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux TA- exécutables sur le démon de l'étape 4 (mutants du paquet @noortrace/enregistreur, CT-7 EX-3.2)", function () {
  this.timeout(600_000);
  let base;
  let service;
  let serveurService;
  let fournisseur;
  let n = 0;

  // Modules du démon et outils des tests, chargés depuis la racine du dépôt
  // (EX-10.8 : le fichier peut être lu hors de test/ avec NOORTRACE_RACINE).
  let REFERENCE, mutantPaquet, detruireMutants, configurationDemon, demonModele, demarrer, arreter, poster, appelerOutil, attendre, sante, tuerAuxiliaireBail;
  let ServiceApprobationFactice, lireEvenements, configurationModele, configurationIcap, JETON_MODELE, FournisseurSimule, reponseEntiere, transaction, enteteRequete;
  const charger = (rel) => import(pathToFileURL(path.join(RACINE, rel)).href);

  before(async function () {
    ({ REFERENCE, mutantPaquet, detruireMutants, configurationDemon, demonModele, demarrer, arreter, poster, appelerOutil, attendre, sante, tuerAuxiliaireBail } = await charger("test/fixtures/enregistreur-adversarial/demon.mjs"));
    ({ ServiceApprobationFactice } = await charger("paquets/enregistreur/src/service-approbation-factice.mjs"));
    ({ lireEvenements } = await charger("paquets/enregistreur/src/index.mjs"));
    ({ configurationModele, configurationIcap, JETON_MODELE } = await charger("test/fixtures/enregistreur-modele/outils.mjs"));
    ({ FournisseurSimule, reponseEntiere } = await charger("test/fixtures/enregistreur-modele/fournisseur.mjs"));
    ({ transaction, enteteRequete } = await charger("test/fixtures/enregistreur-modele/client-icap.mjs"));
    base = fs.mkdtempSync(path.join(TMP, "noortrace-adversarial-demon-"));
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
    fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
  });

  after(async function () {
    serveurService?.close();
    await fournisseur?.arreter();
    detruireMutants?.();
    if (base) fs.rmSync(base, { recursive: true, force: true });
  });

  /** Configuration neuve d'un démon (répertoire propre) ; le service simulé suit son journal. */
  async function configuration(modifier, o = {}) {
    const dir = path.join(base, `d${++n}`);
    fs.mkdirSync(dir);
    const c = await configurationDemon(dir, { approbation: serveurService.address().port, modifier, ...o });
    service.org_id = c.config.recorder.org_id;
    service.journal_id = c.config.recorder.journal_id;
    return c;
  }

  /** Joue `scenario(c, demon)` sur un démon du paquet donné et rend son observation ; le démon est arrêté ensuite. */
  async function jouer(paquet, modifier, scenario, o = {}) {
    const c = await configuration(modifier, o);
    const p = await demarrer(paquet, c, path.join(c.dir, "configuration.json"));
    try {
      return await scenario(c, p);
    } finally {
      await arreter(p);
    }
  }

  /** Joue `scenario(c, demon)` sur un démon du frontal modèle (mode passerelle ou icap) du paquet donné. */
  async function jouerModele(paquet, mode, modifier, scenario) {
    const dir = path.join(base, `d${++n}`);
    fs.mkdirSync(dir);
    const brut = mode === "icap" ? configurationIcap(dir, fournisseur.url) : configurationModele(dir, fournisseur.url);
    const c = await demonModele(dir, brut, mode);
    if (modifier) modifier(c.config, c.env);
    const p = await demarrer(paquet, c, path.join(dir, "configuration.json"));
    try {
      return await scenario(c, p);
    } finally {
      await arreter(p);
    }
  }

  /** Fichiers écrits sous un répertoire (stockage, journal d'exploitation), récursivement. */
  const fichiersSous = (rep) => fs.readdirSync(rep, { recursive: true }).map((f) => path.join(rep, f)).filter((f) => fs.statSync(f).isFile());

  const evenementsOutils = async (c) => (await lireEvenements(c.journal)).filter((e) => !e.execution.tool.startsWith("noortrace."));

  it("TA-30 (MN-30) : configuration modèle de production (deploiement/config/modele-production) posée à signer.class = D : noortrace validate-config rend le code 2 et une erreur sur /signer/class en production, aucune en developpement ; mutant sans le refus de la classe D en production : aucune erreur sur /signer/class (tué)", async function () {
    const conf = lireJSON(RACINE, "deploiement", "config", "modele-production", "configuration.json");
    expect(conf.recorder.environment).to.equal("production");
    conf.signer.class = "D";
    const dir = path.join(base, "ta30");
    fs.mkdirSync(dir);
    const valider = (paquet, environnement) => {
      const f = path.join(dir, `${environnement}.json`);
      fs.writeFileSync(f, JSON.stringify({ ...conf, recorder: { ...conf.recorder, environment: environnement } }));
      const r = spawnSync(process.execPath, [paquet.bin("noortrace"), "validate-config", f], { encoding: "utf8" });
      return { code: r.status, classe: `${r.stdout}${r.stderr}`.split("\n").filter((l) => l.startsWith("erreur : /signer/class :")) };
    };
    const prod = valider(REFERENCE, "production");
    expect(prod.code).to.equal(2);
    expect(prod.classe).to.deep.equal(['erreur : /signer/class : classe D refusée en production (EX-11.8) ; valeur : "D"']);
    expect(valider(REFERENCE, "developpement").classe).to.deep.equal([]);
    const m = mutantPaquet("mn30", [{ fichier: "configuration.mjs", ancien: 'if (prod && classe === "D") err("/signer/class"', nouveau: 'if (false) err("/signer/class"' }]);
    expect(valider(m, "production").classe).to.deep.equal([]);
  });

  it("TA-2 (MN-2) : démon réel : un tools/call dont _meta[\"noortrace/delegation\"] déclare launched_by, on_behalf_of hors liste et run_id, sur une connexion configurée pour agent-demo : launched_by de la configuration, run_id admis, on_behalf_of remplacé (delegation_refused) ; sans délégation admise : run_id de session ; mutant qui recopie le launched_by déclaré (tué)", async function () {
    const JETON_B = "jeton-hote-b-de-test-adversarial-ta2";
    const modifier = (cfg, env) => {
      const h = cfg.mcp.hosts[0];
      Object.assign(h, { launched_by: "agent-demo", on_behalf_of: "service-sinistres", accept_declared_delegation: true, allowed_on_behalf_of: ["service-sinistres"] });
      cfg.mcp.http.static_tokens.push({ id: "hote-b", token: { env: "NOORTRACE_TEST_JETON_HOTE_B" } });
      cfg.mcp.hosts.push({ ...h, id: "hote-b", match: { static_token: "hote-b" }, launched_by: "agent-demo-b", host_group: "agent-demo-b", accept_declared_delegation: false, allowed_on_behalf_of: [] });
      env.NOORTRACE_TEST_JETON_HOTE_B = JETON_B;
    };
    const declaree = { "noortrace/delegation": { launched_by: "u.autre@assureur-demo.example", on_behalf_of: "service-autre", run_id: "run-ta2-0001" } };
    const scenario = async (c, p) => {
      const a = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__lire", { id: "S-ta2" }, { meta: declaree });
      const b = await appelerOutil(c.portHttp, JETON_B, "demo__lire", { id: "S-ta2-b" }, { meta: declaree });
      expect([a.statut, b.statut]).to.deep.equal([200, 200]);
      const [ea, eb] = await evenementsOutils(c);
      return { a: ea.delegation, b: eb.delegation, sessionB: b.session, refus: p.lignes().filter((l) => l.event === "delegation_refused").map((l) => l.data) };
    };
    const r = await jouer(REFERENCE, modifier, scenario);
    expect(r.a).to.deep.equal({ launched_by: "agent-demo", on_behalf_of: "service-sinistres", run_id: "run-ta2-0001", scope: r.a.scope });
    expect(r.refus).to.deep.equal([{ component: "frontal_mcp", field: "on_behalf_of", reason: "hors_liste", length: "service-autre".length }]);
    expect(r.b.launched_by).to.equal("agent-demo-b");
    expect(r.b.on_behalf_of).to.equal("service-sinistres");
    expect(r.b.run_id).to.equal(r.sessionB);
    const m = mutantPaquet("mn2", [{ fichier: "mcp/delegation.mjs", ancien: "const launched_by = lanceurDe(h.launched_by, p.identite ?? {});", nouveau: "const launched_by = typeof d.launched_by === \"string\" ? d.launched_by : lanceurDe(h.launched_by, p.identite ?? {});" }]);
    const r1 = await jouer(m, modifier, scenario);
    expect(r1.a.launched_by).to.equal("u.autre@assureur-demo.example");
  });

  it("TA-8 (MN-8) : démon réel, frontal MCP Streamable HTTP, deux connexions d'hôte à jetons distincts : tools/call sans autorisation puis avec un jeton de 32 octets aléatoires : 401, deux lignes auth_failed, aucun événement ; avec le jeton de l'hôte B : événement attribué à l'hôte B ; mutant sans la vérification du jeton : l'appel sans jeton est relayé et un événement est écrit (tué)", async function () {
    const JETON_B = "jeton-hote-b-de-test-adversarial-ta8";
    const modifier = (cfg, env) => {
      cfg.mcp.http.static_tokens.push({ id: "hote-b", token: { env: "NOORTRACE_TEST_JETON_HOTE_B" } });
      cfg.mcp.hosts.push({ ...cfg.mcp.hosts[0], id: "hote-b", match: { static_token: "hote-b" }, launched_by: "agent-b", host_group: "agent-b" });
      env.NOORTRACE_TEST_JETON_HOTE_B = JETON_B;
    };
    const scenario = async (c, p) => {
      const sans = await appelerOutil(c.portHttp, null, "demo__lire", { id: "S-sans" });
      const faux = await appelerOutil(c.portHttp, randomBytes(32).toString("base64url"), "demo__lire", { id: "S-faux" });
      const apresDeux = await evenementsOutils(c);
      const b = await appelerOutil(c.portHttp, JETON_B, "demo__lire", { id: "S-b" });
      return { statuts: [sans.statut, faux.statut, b.statut], apresDeux, tous: await evenementsOutils(c), auth: p.lignes().filter((l) => l.event === "auth_failed").map((l) => l.data) };
    };
    const r = await jouer(REFERENCE, modifier, scenario);
    expect(r.statuts).to.deep.equal([401, 401, 200]);
    expect(r.auth).to.deep.equal([{ transport: "http", reason: "absent", status: 401 }, { transport: "http", reason: "jeton_inconnu", status: 401 }]);
    expect(r.apresDeux).to.deep.equal([]);
    expect(r.tous.map((e) => [e.execution.tool, e.delegation.launched_by])).to.deep.equal([["demo__lire", "agent-b"]]);
    const m = mutantPaquet("mn8", [
      { fichier: "mcp/hote-http.mjs", ancien: 'if (!m) throw new ErreurAuthentification(401, "absent");\n    const recu = Buffer.from(m[1], "utf8");', nouveau: 'const recu = Buffer.from(m?.[1] ?? "", "utf8");' },
      { fichier: "mcp/hote-http.mjs", ancien: "for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;", nouveau: "for (const [k] of this.jetons) if (true) id = k;" },
    ]);
    const r1 = await jouer(m, modifier, scenario);
    expect(r1.statuts[0]).to.equal(200);
    expect(r1.apresDeux.length).to.be.at.least(1);
  });

  it("TA-7 (MN-7, partie phase 2 sur le démon de l'étape 4) : description de lire changée côté serveur entre deux tools/list : ligne tool_definition_changed (ancienne et nouvelle empreintes) et pièce de la nouvelle définition, de SHA-256 différent, au contexte de l'appel suivant ; mutant sans l'empreinte comparée : aucune ligne (tué)", async function () {
    const scenario = async (c, p) => {
      const jeton = c.env.NOORTRACE_TEST_JETON_HOTE;
      const ini = await poster(c.portHttp, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "hote-ta7", version: "1.0.0" } } }, { jeton });
      const o = { jeton, session: ini.session };
      await poster(c.portHttp, { jsonrpc: "2.0", method: "notifications/initialized" }, o);
      let id = 10;
      const lister = async () => (await poster(c.portHttp, { jsonrpc: "2.0", id: ++id, method: "tools/list" }, o)).corps.result.tools.find((t) => t.name === "demo__lire").description;
      const appeler = (nom) => poster(c.portHttp, { jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name: nom, arguments: { id: "S-ta7" } } }, o);
      const avant = await lister();
      await appeler("demo__lire");
      await appeler("demo__changer");
      let apres = avant;
      await attendre(async () => (apres = await lister()) !== avant, 15000, 100);
      await appeler("demo__lire");
      const lires = (await evenementsOutils(c)).filter((e) => e.execution.tool === "demo__lire");
      const def = lires.map((e) => e.context[0].sha256);
      const pieces = def.map((h) => fs.existsSync(path.join(c.journal, "pieces", h.slice(2, 4), h.slice(2))));
      return { avant, apres, lignes: p.lignes().filter((l) => l.event === "tool_definition_changed").map((l) => l.data), def, pieces };
    };
    const r = await jouer(REFERENCE, null, scenario);
    expect(r.apres).to.not.equal(r.avant);
    expect(r.def).to.have.length(2);
    expect(r.def[1]).to.not.equal(r.def[0]);
    expect(r.pieces).to.deep.equal([true, true]);
    expect(r.lignes).to.deep.equal([{ server: "demo", tool_announced: "demo__lire", old_sha256: r.def[0], new_sha256: r.def[1] }]);
    const m = mutantPaquet("mn7", [{ fichier: "mcp/frontal.mjs", ancien: "if (a !== b && avant.annonces.length && !this.demarrage) {", nouveau: "if (false) {" }]);
    const r1 = await jouer(m, null, scenario);
    expect(r1.apres).to.not.equal(r1.avant);
    expect(r1.lignes).to.deep.equal([]);
  });

  it("TA-9 (MN-9) : démon réel lancé par le superutilisateur, serveur stdio configuré sous l'utilisateur nobody : l'outil sonder tente de lire le fichier du secret relay_mac_key (0400) et d'écrire sous storage.root ; les deux accès rendent EACCES et aucun fichier n'apparaît sous storage.root ; mutant qui lance le serveur sous l'utilisateur du démon : les deux accès réussissent (tué)", async function () {
    if (typeof process.getuid !== "function" || process.getuid() !== 0) {
      this.test.title += " — en attente : le démon doit être lancé par le superutilisateur pour changer d'utilisateur (EX-3.5)";
      this.skip();
    }
    const modifier = (cfg, env) => {
      const f = path.join(path.dirname(cfg.storage.root), "secrets", "cle-mac-relais");
      fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
      fs.writeFileSync(f, env.NOORTRACE_TEST_CLE_MAC, { mode: 0o400 });
      cfg.storage.relay_mac_key = { file: f, encoding: "hex" };
      cfg.policy.servers.demo.transport.user = "nobody";
    };
    const scenario = async (c) => {
      const secret = c.config.storage.relay_mac_key.file;
      const r = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__sonder", { secret, repertoire: c.config.storage.root });
      const sonde = fs.existsSync(path.join(c.config.storage.root, "sonde-ta9"));
      return { ...r.corps.result.structuredContent, sonde };
    };
    const r = await jouer(REFERENCE, modifier, scenario);
    expect(r).to.deep.equal({ lecture: "EACCES", ecriture: "EACCES", uid: 65534, sonde: false });
    const m = mutantPaquet("mn9", [{ fichier: "mcp/amont.mjs", ancien: "if (typeof process.getuid === \"function\" && process.getuid() !== c.uid) ids = { uid: c.uid, gid: c.gid };", nouveau: "if (false) ids = { uid: c.uid, gid: c.gid };" }]);
    const r1 = await jouer(m, modifier, scenario);
    expect(r1).to.deep.equal({ lecture: "ok", ecriture: "ok", uid: 0, sonde: true });
  });

  it("TA-11 (MN-11, partie phase 2 sur le démon de l'étape 4) : passerelle, route en credentials propre : la clé marquée que l'hôte met dans x-api-key n'arrive pas au fournisseur simulé, qui reçoit celle de la configuration, et n'est dans aucun fichier écrit ; mutant qui relaie l'en-tête de l'hôte : sa clé traverse (tué)", async function () {
    const MARQUEUR = `cle-hote-marquee-ta11-${randomBytes(8).toString("hex")}`;
    const scenario = async (c) => {
      const avant = fournisseur.requetes.length;
      const corps = { model: "modele-ta11", max_tokens: 16, messages: [{ role: "user", content: "Statut ?" }] };
      const r = await fetch(`http://127.0.0.1:${c.port}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": JETON_MODELE, "x-api-key": MARQUEUR }, body: JSON.stringify(corps) });
      await r.text();
      await attendre(async () => (await lireEvenements(c.journal)).some((e) => e.execution.tool === "noortrace.modele.echange"), 15000);
      const recu = fournisseur.requetes.slice(avant).map((x) => x.entetes["x-api-key"]);
      const fuites = fichiersSous(c.dir).filter((f) => fs.readFileSync(f).includes(MARQUEUR));
      return { statut: r.status, recu, fuites };
    };
    const r = await jouerModele(REFERENCE, "passerelle", null, scenario);
    expect(r.statut).to.equal(200);
    expect(r.recu).to.deep.equal(["cle-fournisseur-fictive-de-test"]);
    expect(r.fuites).to.deep.equal([]);
    const m = mutantPaquet("mn11", [{ fichier: "modele/passerelle.mjs", ancien: 'if (route.credentials === "propre") {\n      const s = this.secrets.get(`/policy/model/routes/${x.indice}/secret`);\n      if (s) envoyes[nomAuth] = nomAuth === "authorization" ? `Bearer ${Buffer.from(s).toString("utf8")}` : Buffer.from(s).toString("utf8");\n    } else if (typeof h[nomAuth] === "string") {', nouveau: 'if (false) {\n      const s = this.secrets.get(`/policy/model/routes/${x.indice}/secret`);\n      if (s) envoyes[nomAuth] = nomAuth === "authorization" ? `Bearer ${Buffer.from(s).toString("utf8")}` : Buffer.from(s).toString("utf8");\n    } else if (typeof h[nomAuth] === "string") {' }]);
    const r1 = await jouerModele(m, "passerelle", null, scenario);
    expect(r1.recu).to.deep.equal([MARQUEUR]);
  });

  it("TA-12 (MN-12) : démon réel en mode icap, allowed_sources = [203.0.113.5/32] : REQMOD puis RESPMOD depuis une adresse absente (127.0.0.1) : 403 consigné (auth_failed, client_icap_refuse), aucun échange écrit ; mutant sans l'authentification des clients ICAP : un échange est écrit à partir de la transaction fabriquée (tué)", async function () {
    const modifier = (cfg) => {
      cfg.model.icap.allowed_sources = ["203.0.113.5/32"];
    };
    const MSG = { model: "modele-ta12", max_tokens: 16, messages: [{ role: "user", content: "Statut ?" }] };
    const scenario = async (c, p) => {
      const ad = { address: "127.0.0.1", port: c.port };
      const corps = Buffer.from(JSON.stringify(MSG));
      const req = enteteRequete("POST https://api.fournisseur.example/v1/messages HTTP/1.1", [["Host", "api.fournisseur.example"], ["Content-Type", "application/json"], ["Content-Length", String(corps.length)]]);
      const r1 = await transaction(ad, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: { "X-Client-IP": "127.0.0.1" }, req, corps: [corps] });
      let r2 = null;
      if (r1.statut === 200) {
        const reponse = Buffer.from(JSON.stringify(reponseEntiere("anthropic-messages", MSG, 1)));
        r2 = await transaction(ad, { methode: "RESPMOD", service: "/noortrace/respmod", entetes: { "X-Client-IP": "127.0.0.1" }, req: r1.sections["req-hdr"], res: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nrequest-id: req-ta12\r\n\r\n", corps: [reponse] });
        await attendre(async () => (await lireEvenements(c.journal)).some((e) => e.execution.tool === "noortrace.modele.echange"), 15000).catch(() => {});
      }
      const echanges = (await lireEvenements(c.journal)).filter((e) => e.execution.tool === "noortrace.modele.echange");
      return { statuts: [r1.statut, r2?.statut ?? null], refus: p.lignes().filter((l) => l.event === "auth_failed").map((l) => l.data), echanges: echanges.length };
    };
    const r = await jouerModele(REFERENCE, "icap", modifier, scenario);
    expect(r.statuts).to.deep.equal([403, null]);
    expect(r.refus).to.deep.equal([{ transport: "icap", reason: "client_icap_refuse" }]);
    expect(r.echanges).to.equal(0);
    const m = mutantPaquet("mn12", [{ fichier: "modele/icap.mjs", ancien: "if (!admis) {", nouveau: "if (false) {" }]);
    const r1 = await jouerModele(m, "icap", modifier, scenario);
    expect(r1.statuts).to.deep.equal([200, 200]);
    expect(r1.echanges).to.equal(1);
  });

  it("TA-24 (MN-24) : coffre des originaux à clé propre (CoffreOriginaux.dechiffrer du paquet) : demande seule, puis approbation de la même identité, puis d'une seconde identité autorisée : deux refus, un succès, trois lignes au registre des accès ; mutant sans seconde approbation : l'original est rendu au demandeur seul (tué)", async function () {
    const essai = async (paquet, nom) => {
      const { CoffreOriginaux } = await paquet.importer("coffre.mjs");
      const dir = path.join(base, `ta24-${nom}`);
      const coffre = new CoffreOriginaux({ chemin: path.join(dir, "coffre"), cle: new Uint8Array(randomBytes(32)) });
      const sha256 = `0x${"ab".repeat(32)}`;
      const original = Buffer.from('{"iban":"CH9300762011623852957"}');
      await coffre.deposer(sha256, original);
      expect(fs.readFileSync(coffre.fichier(sha256)).includes(original)).to.equal(false);
      const registre = path.join(dir, "acces", "registre.ndjson");
      const demande = { par: "alice", motif: "requête du tribunal 2026-17" };
      const autorises = ["alice", "bob"];
      const issues = [];
      for (const approbation of [null, { par: "alice", sha256, motif: demande.motif }, { par: "bob", sha256, motif: demande.motif }]) {
        try {
          const o = await coffre.dechiffrer({ sha256, demande, approbation, autorises, registre });
          issues.push(Buffer.from(o).equals(original) ? "original" : "autre");
        } catch (e) {
          issues.push(e.raison ?? String(e));
        }
      }
      const lignes = fs.readFileSync(registre, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      return { issues, lignes: lignes.map((l) => [l.requester, l.approver, l.result, l.refusal]) };
    };
    const r = await essai(REFERENCE, "reference");
    expect(r.issues).to.deep.equal(["seconde_approbation_absente", "approbateur_identique_au_demandeur", "original"]);
    expect(r.lignes).to.deep.equal([["alice", null, "refuse", "seconde_approbation_absente"], ["alice", "alice", "refuse", "approbateur_identique_au_demandeur"], ["alice", "bob", "accorde", null]]);
    const m = mutantPaquet("mn24", [
      { fichier: "coffre.mjs", ancien: 'else if (!d.approbation || typeof approbateur !== "string" || approbateur.length === 0) raison = "seconde_approbation_absente";', nouveau: 'else if (false) raison = "seconde_approbation_absente";' },
      { fichier: "coffre.mjs", ancien: 'else if (approbateur === demandeur) raison = "approbateur_identique_au_demandeur";', nouveau: 'else if (false) raison = "approbateur_identique_au_demandeur";' },
      { fichier: "coffre.mjs", ancien: 'else if (!d.autorises.includes(approbateur)) raison = "approbateur_non_autorise";', nouveau: 'else if (false) raison = "approbateur_non_autorise";' },
      { fichier: "coffre.mjs", ancien: 'else if (shaOuNull(d.approbation.sha256) !== h || d.approbation.motif !== motif) raison = "approbation_d_une_autre_demande";', nouveau: 'else if (false) raison = "approbation_d_une_autre_demande";' },
    ]);
    const r1 = await essai(m, "mutant");
    expect(r1.issues[0]).to.equal("original");
  });

  it("TA-26 (MN-26, partie non conditionnée par PA-1) : démon réel, points de contrôle toutes les 10 s : arrêt puis redémarrage ; la ligne startup du redémarrage est écrite avec l'époque du nouveau bail, et la série des points qui chevauche le redémarrage n'a aucun trou supérieur à c_K + 1 s (constaterCadence, CT-5 AN-2) ; mutant sans la ligne startup : aucune ligne au redémarrage (tué)", async function () {
    const A = await ref("lib/ancrage.mjs");
    const modifier = (cfg) => {
      cfg.checkpoint_interval_s = 10;
    };
    const scenario = async (paquet) => {
      const c = await configuration(modifier);
      const f = path.join(c.dir, "configuration.json");
      const points = () => {
        const rep = path.join(c.journal, "points");
        if (!fs.existsSync(rep)) return [];
        return fs.readdirSync(rep).flatMap((n) => fs.readFileSync(path.join(rep, n), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)));
      };
      let p = await demarrer(paquet, c, f);
      await attendre(() => points().length >= 1, 30000, 200);
      await arreter(p);
      const avant = points();
      const lignesAvant = p.lignes().length;
      p = await demarrer(paquet, c, f);
      await attendre(() => points().length >= avant.length + 2, 40000, 200);
      await arreter(p);
      const lignes = p.lignes().slice(lignesAvant);
      const epoque = lignes.find((l) => l.event === "lease_acquired")?.data.epoch ?? null;
      const apres = points().slice(avant.length);
      const cadence = A.constaterCadence({ period_start: Number(avant.at(-1).period_start), points: apres, checkpoint_interval_s: 10, previous_closing_ts: avant.at(-1).checkpoint_ts });
      return { startup: lignes.filter((l) => l.event === "startup").map((l) => l.data.epoch), epoque, cadence };
    };
    const r = await scenario(REFERENCE);
    expect(r.epoque).to.equal(2);
    expect(r.startup).to.deep.equal([2]);
    expect(r.cadence).to.deep.equal({ conforme: true, ecarts: [] });
    const m = mutantPaquet("mn26", [{ fichier: "coeur.mjs", ancien: 'this.journal.consigner("info", "noyau", "startup", {', nouveau: '((_n, _c, _e, _d) => {})("info", "noyau", "startup", {' }]);
    const r1 = await scenario(m);
    expect(r1.startup).to.deep.equal([]);
  });

  /** Segments bruts d'un journal : [{ nom, epoch, first_seq, evenements }] (12.1 : en-tête puis une ligne par événement). */
  const segmentsBruts = (journal) =>
    fs.readdirSync(path.join(journal, "segments")).filter((n) => n.startsWith("seg-")).sort().map((nom) => {
      const lignes = fs.readFileSync(path.join(journal, "segments", nom), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      return { nom, epoch: Number(lignes[0].epoch), first_seq: Number(lignes[0].first_seq), evenements: lignes.slice(1) };
    });

  it("TA-10 (MN-10, partie phase 2 sur le démon de l'étape 4) : écriture relayée puis démon tué avant le scellement : au redémarrage, un événement de reprise par intention ouverte, autant que d'exécutions côté serveur ; bail perdu après le relais : -31017 à l'hôte ; mutant sans intention durable avant relais : aucun événement (tué)", async function () {
    const scenario = async (paquet) => {
      const c = await configuration();
      const executions = path.join(c.dir, "executions.ndjson");
      c.config.policy.servers.demo.transport.command.push("--executions", executions);
      const f = path.join(c.dir, "configuration.json");
      let p = await demarrer(paquet, c, f);
      const vol = appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__ecrire_lent", { id: "S-vol", attente_ms: 120000 }).catch((e) => ({ coupure: e.code ?? e.message }));
      await attendre(() => fs.existsSync(executions) && fs.readFileSync(executions, "utf8").includes("S-vol"), 15000);
      p.kill("SIGKILL");
      await p.fin;
      await vol;
      p = await demarrer(paquet, c, f);
      await arreter(p);
      const evts = (await lireEvenements(c.journal)).filter((e) => e.execution.tool === "demo__ecrire_lent");
      const servi = fs.readFileSync(executions, "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((x) => x.outil === "ecrire_lent").length;
      return { evts, servi, recuperees: p.lignes().filter((l) => l.event === "intent_recovered").map((l) => l.data.intent_id) };
    };
    const r = await scenario(REFERENCE);
    expect(r.servi).to.equal(1);
    expect(r.evts).to.have.length(r.servi);
    expect(r.evts[0].execution).to.include({ status: "executee", is_error: true, duration_ms: 0 });
    expect(r.recuperees).to.have.length(1);
    // -31017 (EX-4.46) : le bail est perdu pendant le relais (auxiliaire flock(1) tué) ; l'appel exécuté est rendu non durable.
    const c = await configuration();
    const executions = path.join(c.dir, "executions.ndjson");
    c.config.policy.servers.demo.transport.command.push("--executions", executions);
    const p = await demarrer(REFERENCE, c, path.join(c.dir, "configuration.json"));
    try {
      const vol = appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__ecrire_lent", { id: "S-panne", attente_ms: 1500 });
      await attendre(() => fs.existsSync(executions) && fs.readFileSync(executions, "utf8").includes("S-panne"), 15000);
      tuerAuxiliaireBail(p);
      const err = (await vol).corps.error;
      expect(err.code).to.equal(-31017);
      expect(err.data.reason).to.equal("bail");
      expect(err.data.intent_id).to.be.a("string");
    } finally {
      await arreter(p);
    }
    const m = mutantPaquet("mn10", [{ fichier: "coeur.mjs", ancien: 'if (appel.class === "ecriture" || ticket) {', nouveau: "if (false) {" }]);
    const r1 = await scenario(m);
    expect(r1.servi).to.equal(1);
    expect(r1.evts).to.deep.equal([]);
  });

  it("TA-19 (MN-19) : deux démons sur le même journal et le même bail file : A écrit, perd son verrou (flock(1) tué), B prend le bail (époque 2) ; A, appelé, refuse (-31010, lease_lost) ; aucun événement de A après l'époque de B, chaîne sans fourche ; mutant dont le bail file se dit toujours valide : A écrit, fourche (tué)", async function () {
    const scenario = async (paquet) => {
      const ca = await configuration(null, { instance: "inst-a" });
      const cb = await configurationDemon(ca.dir, { instance: "inst-b", journal_id: ca.config.recorder.journal_id, approbation: serveurService.address().port });
      cb.config.lease.store.path = ca.config.lease.store.path;
      cb.config.storage.root = ca.config.storage.root;
      cb.config.mcp.socket = path.join(path.dirname(ca.config.mcp.socket), "mcp-b.sock");
      cb.config.supervision.ops_log.path = path.join(ca.dir, "exploitation-b.ndjson");
      const jeton = ca.env.NOORTRACE_TEST_JETON_HOTE;
      const a = await demarrer(paquet, ca, path.join(ca.dir, "a.json"));
      let b = null;
      try {
        const r0 = await appelerOutil(ca.portHttp, jeton, "demo__ecrire", { id: "S-A1", montant: "10" });
        expect(r0.corps.result?.isError, JSON.stringify(r0.corps)).to.equal(false);
        b = await demarrer(paquet, cb, path.join(ca.dir, "b.json"), "standby");
        tuerAuxiliaireBail(a);
        await attendre(async () => (await sante(cb.portSante))?.corps?.status === "ok", 30000, 100);
        const epoqueB = b.lignes().find((l) => l.event === "lease_acquired").data.epoch;
        const rB = await appelerOutil(cb.portHttp, jeton, "demo__ecrire", { id: "S-B1", montant: "20" });
        const rA = await appelerOutil(ca.portHttp, jeton, "demo__ecrire", { id: "S-A2", montant: "30" });
        return { epoqueB, rB: rB.corps, rA: rA.corps, perteA: a.lignes().some((l) => l.event === "lease_lost"), segments: segmentsBruts(ca.journal) };
      } finally {
        await arreter(b);
        await arreter(a);
      }
    };
    /** Événements de toutes les époques, triés par seq ; fourche : deux événements d'un même seq, ou un prev_hash discontinu. */
    const analyser = (r) => {
      const tous = r.segments.flatMap((s) => s.evenements.map((e) => ({ ...e, epoque: s.epoch }))).sort((x, y) => x.seq - y.seq);
      const seqs = tous.map((e) => e.seq);
      const continu = tous.every((e, i) => i === 0 || (e.seq === tous[i - 1].seq + 1 && e.prev_hash === tous[i - 1].hash));
      const debutB = Math.min(...r.segments.filter((s) => s.epoch === r.epoqueB).map((s) => s.first_seq));
      const aApresB = r.segments.filter((s) => s.epoch < r.epoqueB).flatMap((s) => s.evenements).filter((e) => e.seq >= debutB);
      return { seqs, continu, aApresB: aApresB.length, outils: tous.map((e) => [e.epoque, e.execution.tool, e.execution.arguments?.value?.id ?? null]) };
    };
    const r = await scenario(REFERENCE);
    expect(r.epoqueB).to.equal(2);
    expect(r.rB.result?.isError, JSON.stringify(r.rB)).to.equal(false);
    expect(r.rA.error?.code, JSON.stringify(r.rA)).to.equal(-31010);
    expect(r.perteA).to.equal(true);
    const x = analyser(r);
    expect(x.aApresB).to.equal(0);
    expect(x.continu, JSON.stringify(x.outils)).to.equal(true);
    expect(new Set(x.seqs).size).to.equal(x.seqs.length);
    // Réponse retirée : le contrôle du bail par l'écrivain (MagasinBailFichier.valide) et le contrôle
    // du jeton de clôture avant chaque écriture (GardeEpoque, CT-2 EX-13.5 (1) lu sur le répertoire du
    // journal, correction D-1), seconde défense contre la même menace (MN-19 : « si le jeton de clôture
    // n'est plus vérifié, les deux écrivent ») ; sans ce second retrait, la garde arrêterait le mutant.
    const m = mutantPaquet("mn19", [
      { fichier: "bail.mjs", ancien: "  valide() {\n    return this.detenu;\n  }\n\n  async liberer() {\n    const aux = this.auxiliaire;", nouveau: "  valide() {\n    return true;\n  }\n\n  async liberer() {\n    const aux = this.auxiliaire;" },
      { fichier: "ha/cloture.mjs", ancien: "  async depassee() {\n    if (this.depassement) return this.depassement;", nouveau: "  async depassee() {\n    return null;" },
    ]);
    const r1 = await scenario(m);
    const x1 = analyser(r1);
    expect(r1.rA.result?.isError, JSON.stringify(r1.rA)).to.equal(false);
    expect(x1.aApresB).to.be.at.least(1);
    expect(x1.continu).to.equal(false);
  });

  // ---------------------------------------------------------------------
  // Lot des signataires (classes A, B, C) : TA-31 et TA-33 sur un service de
  // signature réel (Vault Transit en conteneur épinglé par condensé), joués
  // par test/fixtures/enregistreur-signataires/ta.mjs. Sans Docker ou sans
  // l'image, en attente (titre complété par la condition).
  async function signataires(ctx) {
    const o = await charger("test/fixtures/enregistreur-signataires/outils.mjs");
    const dispo = o.dockerEtImage(o.IMAGES_SIGNATAIRES["vault-transit"]);
    if (!dispo.ok) {
      ctx.test.title += ` — en attente : ${dispo.condition}`;
      ctx.skip();
    }
    const { certificats } = await charger("test/fixtures/enregistreur-worm/outils.mjs");
    const ta = await charger("test/fixtures/enregistreur-signataires/ta.mjs");
    const d = path.join(base, `signataires-${++n}`);
    fs.mkdirSync(d);
    return { ...ta, tls: certificats(path.join(d, "tls")), d };
  }

  it("TA-33 (MN-33) : installation rapide modifiée (mode erreur, version sans -observation, signataire vault-transit) ; backend arrêté sans reprise : -31010 de raison cle rendu à l'hôte, jauge noortrace_degraded de raison cle à 1 plus de 60 s, aucun nouvel événement dans le segment ; mutant où l'écrivain continue sans signature : un événement est écrit pendant la panne (tué)", async function () {
    const { scenarioTa33, oracleTa33, tls, d } = await signataires(this);
    const commun = { base: d, tls, service, serveurService };
    const ref = await scenarioTa33(REFERENCE, { ...commun, nom: "ref", attenteMaxMs: 120000 });
    expect(oracleTa33(ref), JSON.stringify({ ...oracleTa33(ref), appel: ref.appel.corps, jauge: ref.jauge })).to.deep.equal({ capturePrealable: true, cle31010: true, jaugePlusDe60s: true, aucunNouvelEvenement: true });
    expect(ref.lignes.some((l) => l.event === "signer_unavailable" && l.data?.backend === "vault-transit")).to.equal(true);
    const m = mutantPaquet("mn33", [
      { fichier: "ecrivain.mjs", ancien: 'this.degrade.entrer("cle");\n      throw err;', nouveau: "sig = new Uint8Array(64);" },
      { fichier: "coeur.mjs", ancien: 'this.degrade.entrer("cle", { event: "signer_unavailable" });', nouveau: "void 0;" },
    ]);
    const mut = await scenarioTa33(m, { ...commun, nom: "mut", attenteMaxMs: 15000 });
    expect(oracleTa33(mut).aucunNouvelEvenement, `mutant : ${JSON.stringify({ ...oracleTa33(mut), appel: mut.appel.corps })}`).to.equal(false);
  });

  it("TA-31 (MN-31) : Vault Transit à journal d'audit ; le démon produit n objets signés ; noortrace-ctl cle rapprocher sur l'intervalle : écart 0, code 0 ; une signature hors écrivain par le même backend et la même identité d'usage : écart 1, code 3 (incident, CT-7 4.6) ; mutant qui n'exécute plus la comparaison : écart 0 malgré la signature externe (tué)", async function () {
    const { scenarioTa31, tls, d } = await signataires(this);
    const commun = { base: d, tls, approbation: serveurService.address().port, service };
    const lire = (x) => JSON.parse(x.sortie);
    const ref = await scenarioTa31(REFERENCE, { ...commun, nom: "ref" });
    for (const r of ref.reponses) expect(r.corps?.result?.isError, JSON.stringify(r.corps)).to.equal(false);
    expect(ref.signatureExterne).to.equal(200);
    expect(ref.sansExterne.code, ref.sansExterne.erreur).to.equal(0);
    const a = lire(ref.sansExterne);
    expect(a.backend_operations, JSON.stringify(a)).to.be.at.least(ref.evenements);
    expect(a.ecart, JSON.stringify(a)).to.equal(0);
    expect(ref.avecExterne.code).to.equal(3);
    expect(lire(ref.avecExterne)).to.deep.include({ ecart: 1, incident: true });
    const m = mutantPaquet("mn31", [{ fichier: "signataires/rapprochement.mjs", ancien: "const ecart = backend - justifiees;", nouveau: "const ecart = 0;" }]);
    const mut = await scenarioTa31(m, { ...commun, nom: "mut" });
    expect(mut.signatureExterne).to.equal(200);
    expect(lire(mut.avecExterne).ecart, mut.avecExterne.sortie).to.equal(0);
    expect(mut.avecExterne.code).to.equal(0);
  });
});
