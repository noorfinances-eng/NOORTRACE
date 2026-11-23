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
import http from "node:http";
import os from "node:os";
import path from "node:path";
import crypto, { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
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

    it("TA-42 (MN-42) : procès-verbal de création, en production, d'une clé tsa_interne (ECDSA P-256) en classe D, signé par les trois participants : CR-6 échoue et elle seule, le même procès-verbal en classe C est valide ; mutant sans la règle de classe en production et mutant dont la table admet D pour tsa_interne : le procès-verbal en classe D est valide (tués)", async function () {
      const S0 = await ref("lib/securite.mjs");
      // Clé du serveur RFC 3161 interne : SubjectPublicKeyInfo DER d'une clé P-256 dérivée d'un libellé d'essai (aucune valeur secrète écrite).
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.setPrivateKey(crypto.createHash("sha256").update("noortrace/tests/adversarial/ta-42/tsa-interne").digest());
      const spki = Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), ecdh.getPublicKey()]);
      const comptes = new Map(lireJSON(VECTEURS, "ct-3", "constantes.json").accounts.map((a) => [a.address, a.private_key]));
      const proces = (classe) => {
        const pv = JSON.parse(cas("valide-creation-enregistreur").toString("utf8"));
        expect([pv.environment, pv.purpose]).to.deep.equal(["production", "creation"]);
        pv.keys = [{ ...pv.keys[0], key_id: "tsa-interne-test-01", usage: "tsa_interne", algorithm: "ecdsa_p256", custody_class: classe, public_key: "0x" + spki.toString("hex"), fingerprint: "0x" + crypto.createHash("sha256").update(spki).digest("hex"), address: null }];
        const signe = S0.signerCeremonie(pv, new Map(pv.participants.map((p) => [p.id, comptes.get(p.address)])));
        expect(signe.signatures.length).to.equal(pv.participants.length);
        return Buffer.from(JSON.stringify(signe), "utf8");
      };
      const classeD = proces("D");
      const r0 = S0.verifierCeremonie(classeD);
      expect([r0.verdict, r0.failed, r0.not_executed], r0.statuses.find((s) => s.id === "CR-6").detail).to.deep.equal(["invalide", ["CR-6"], []]);
      expect(r0.statuses.find((s) => s.id === "CR-6").detail).to.include("tsa_interne");
      expect(S0.verifierCeremonie(proces("C")).verdict).to.equal("valide");
      const sansRegle = await mutant("mn42-regle", [{ fichier: "lib/securite.mjs", ancien: 'if (production && !CLASSES_ADMISES_PRODUCTION[k.usage].includes(k.custody_class)) faute("CR-6"', nouveau: 'if (false) faute("CR-6"' }]).importer("lib/securite.mjs");
      expect([sansRegle.verifierCeremonie(classeD).verdict, sansRegle.verifierCeremonie(classeD).failed]).to.deep.equal(["valide", []]);
      const tableD = await mutant("mn42-table", [{ fichier: "lib/securite.mjs", ancien: 'tsa_interne: Object.freeze(["A", "B", "C"]),', nouveau: 'tsa_interne: Object.freeze(["A", "B", "C", "D"]),' }]).importer("lib/securite.mjs");
      expect([tableD.verifierCeremonie(classeD).verdict, tableD.verifierCeremonie(classeD).failed]).to.deep.equal(["valide", []]);
      // Ce second mutant ne retire que la réponse de MN-42 : la classe D d'une clé d'enregistreur reste refusée.
      expect(await faillit(tableD, "invalide-cr6-classe-d-en-production")).to.deep.equal(["CR-6"]);
    });

    it("TA-93 (MN-93) : valide-production-sans-ancre, procès-verbal de production valide que rien n'ancre : verifierCeremonie et scripts/verify/ceremonie.mjs (--json et sortie lisible) portent la réserve date_declaree_seulement, verdict valide et code 0 inchangés ; mutant de la bibliothèque sans la réserve et mutant de la commande qui ne l'imprime plus : le procès-verbal est accepté sans réserve (tués)", async function () {
      const nom = "valide-production-sans-ancre";
      const fichier = path.join(VECTEURS, "ct-7", "ceremonies", nom, "proces-verbal.json");
      const attendu = lireJSON(VECTEURS, "ct-7", "ceremonies", nom, "attendu.json");
      expect(JSON.parse(cas(nom).toString("utf8")).environment).to.equal("production");
      expect([attendu.verdict, attendu.failed, attendu.not_executed]).to.deep.equal(["valide", [], []]);
      const RESERVE = "date_declaree_seulement";
      const PHRASE = "daté par déclaration seulement";
      const bibliotheque = async (racine) => {
        const S = await importer(racine, "lib/securite.mjs");
        const r = S.verifierCeremonie(cas(nom));
        expect(S.attenduCeremonie(r), "le verdict du vecteur ne dépend pas de la réserve").to.deep.equal(attendu);
        return r.reserves;
      };
      const commande = (racine) => {
        const lancer = (...options) => spawnSync(process.execPath, [path.join(racine, "scripts", "verify", "ceremonie.mjs"), fichier, ...options], { encoding: "utf8", cwd: RACINE });
        const j = lancer("--json");
        const l = lancer();
        expect([j.status, l.status], `${j.stderr}${l.stderr}`).to.deep.equal([0, 0]);
        const rapport = JSON.parse(j.stdout);
        expect([rapport.verdict, rapport.digest, rapport.failed]).to.deep.equal([attendu.verdict, attendu.digest, attendu.failed]);
        expect(rapport.reserves, "le rapport JSON garde sa forme").to.be.an("array");
        return { json: rapport.reserves, lisible: l.stdout.includes(PHRASE) };
      };
      expect(await bibliotheque(RACINE)).to.deep.equal([RESERVE]);
      expect(commande(RACINE)).to.deep.equal({ json: [RESERVE], lisible: true });
      const mBib = mutant("mn93-bibliotheque", [{ fichier: "lib/securite.mjs", ancien: "const reserves = production ? [RESERVE_DATE_DECLAREE] : [];", nouveau: "const reserves = false ? [RESERVE_DATE_DECLAREE] : [];" }]);
      expect(await bibliotheque(mBib.racine)).to.deep.equal([]);
      expect(commande(mBib.racine)).to.deep.equal({ json: [], lisible: false });
      const mCmd = mutant("mn93-commande", [
        { fichier: "verify/ceremonie.mjs", ancien: "statuses: r.statuses, reserves: r.reserves }", nouveau: "statuses: r.statuses, reserves: [] }" },
        { fichier: "verify/ceremonie.mjs", ancien: "for (const phrase of S.phrasesReservesCeremonie(r)) console.log(phrase);", nouveau: "for (const phrase of []) console.log(phrase);" },
      ]);
      expect(await bibliotheque(mCmd.racine), "la bibliothèque du second mutant garde la réserve").to.deep.equal([RESERVE]);
      expect(commande(mCmd.racine)).to.deep.equal({ json: [], lisible: false });
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
      // Complément du 2026-11-23 de CT-6 (EX-6.26) : ces dossiers portent des pièces d'essai, leur verdict est `incomplet`
      // (code 3), jamais `valide` ; la règle éprouvée ici est que l'AT- en échec ne rend pas le dossier invalide.
      const m = mutant("mn89", [{ fichier: "lib/verificateur.mjs", ancien: 'const estAT = (id) => id.startsWith("AT-");', nouveau: "const estAT = (id) => false;" }]);
      const r0 = rapportDossier(RACINE, dossierCt1("valide-at1-taille"));
      expect([r0.verdict, r0.exit_code, r0.incomplete_reasons, r0.failed_checks, r0.checks.find((c) => c.id === "AT-1").status]).to.deep.equal(["incomplet", 3, ["piece_essai"], [], "echoue"]);
      const r1 = rapportDossier(m.racine, dossierCt1("valide-at1-taille"));
      expect([r1.verdict, r1.failed_checks]).to.deep.equal(["invalide", ["AT-1"]]);
      const p = paireCt6(m, "valide-seq-7-complet-attestation-non-retenue");
      expect([p.reference.verdict, p.reference.exit_code, p.reference.failed_checks]).to.deep.equal(["incomplet", 3, []]);
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
      // Verdict `incomplet` (pièces d'essai de CT-1, CT-6 EX-6.26) ; rien n'échoue.
      expect([r0.verdict, r0.failed_checks]).to.deep.equal(["incomplet", []]);
      expect(r0.statement.fr).to.include(CLAUSE);
      const r1 = rapportDossier(m.racine, rep);
      expect(r1.statement.fr).to.not.include(CLAUSE);
      expect(r1.statement.fr).to.include("inscrite au journal");
    });

    it("TA-91 (MN-91) : valide-at7-nom-reannonce fait réussir AT-7 et FP ne dit que « de même nom » ; mutant qui affirme la vigueur de l'attestation : FP dit « en vigueur » (tué)", async function () {
      const m = mutant("mn91", [{ fichier: "lib/verificateur.mjs", ancien: " sous une version de politique de même nom que celle de cet événement", nouveau: " en vigueur pour cet événement" }]);
      const rep = dossierCt1("valide-at7-nom-reannonce");
      const r0 = rapportDossier(RACINE, rep);
      expect([r0.verdict, r0.failed_checks, r0.checks.find((c) => c.id === "AT-7").status]).to.deep.equal(["incomplet", [], "reussi"]);
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
      const m = mutant("mn74", [{ fichier: "lib/journal.mjs", ancien: 'rapport.juger("K-4", k4, null,', nouveau: 'rapport.juger("K-4", [], null,' }]);
      const J1 = await m.importer("lib/journal.mjs");
      const r1 = J1.verifierDossier(lireDossier(nom), { schemas: schemas(J1) });
      expect([r1.valide, J1.controlesEnEchec(r1)]).to.deep.equal([true, []]);
    });

    it("TA-61 (MN-61, complément T-4 et T-5 de la révision 0.4 de CT-6) : invalide-t4-sid-introuvable échoue à T-4 (EX-9.10), invalide-t5-algorithme-inconnu à T-5 (EX-9.24, cas 1) ; mutant qui laisse T-4 non exécutée pour un sid sans certificat, mutant qui admet un algorithme inconnu : T-4 ou T-5 disparaît des échecs, le dossier à sid introuvable devient valide (tués)", function () {
      const t4 = paireCt6(mutant("mn61-t4", [{ fichier: "lib/horodatage.mjs", ancien: "if ((ancresTsa?.autorites.length ?? 0) > 0 || jeton.certificatsPresents) {", nouveau: "if (false) {" }]), "invalide-t4-sid-introuvable");
      tue(t4, "T-4");
      expect(t4.mutant.checks.find((c) => c.id === "T-4"), "T-4 du mutant").to.include({ status: "non_execute", reason: "ancre_absente" });
      expect(t4.mutant.verdict, "le mutant ne dit plus invalide").to.not.equal("invalide");
      const t5 = paireCt6(mutant("mn61-t5", [{ fichier: "lib/horodatage.mjs", ancien: 'else if (S.cle.verdict === "admis" && regle.verdict !== "admis") res["T-5"] = echoue(', nouveau: 'else if (false) res["T-5"] = echoue(' }]), "invalide-t5-algorithme-inconnu");
      tue(t5, "T-5");
      // Sans T-5, c'est la signature elle-même (T-6) qui tombe : le dossier reste invalide, mais plus pour la raison que la révision 0.4 nomme.
      expect(t5.mutant.checks.find((c) => c.id === "T-6").status, "T-6 du mutant").to.equal("echoue");
    });

    it("TA-68 (MN-68, complément O-1 et bornes des clés RSA) : invalide-o1-octet-en-trop échoue à O-1 ; invalide-t5-rsa-8200 et invalide-t5-exposant à T-5, invalide-t7-intermediaire-rsa-8200 à T-7 (CT-6 EX-9.23) ; mutant dont le lecteur .ots tolère des octets après l'arbre, mutant sans la borne haute de 8192 bits et mutant sans les bornes de l'exposant : la vérification nommée disparaît des échecs (tués)", function () {
      tue(paireCt6(mutant("mn68-o1", [{ fichier: "lib/ots.mjs", ancien: "if (!l.fin()) throw new ErreurOts(`${buf.length - l.pos} octet(s) après l'arbre`);", nouveau: "if (false) throw new ErreurOts(`${buf.length - l.pos} octet(s) après l'arbre`);" }]), "invalide-o1-octet-en-trop"), "O-1");
      const mBits = mutant("mn68-rsa-bits", [{ fichier: "lib/horodatage.mjs", ancien: "if (bits > BORNES_RSA.bitsMax) return {", nouveau: "if (false) return {" }]);
      tue(paireCt6(mBits, "invalide-t5-rsa-8200"), "T-5");
      tue(paireCt6(mBits, "invalide-t7-intermediaire-rsa-8200"), "T-7");
      const mExposant = mutant("mn68-rsa-exposant", [
        { fichier: "lib/horodatage.mjs", ancien: "if (e < BORNES_RSA.exposantMin || e > BORNES_RSA.exposantMax) return {", nouveau: "if (false) return {" },
        { fichier: "lib/horodatage.mjs", ancien: "if (e % 2n === 0n) return {", nouveau: "if (false) return {" },
      ]);
      tue(paireCt6(mExposant, "invalide-t5-exposant"), "T-5");
    });

    it("TA-66 (MN-66, complément mutant JavaScript confronté au binaire Go de CT-6) : sur invalide-t2-jeton-autre-manifeste et invalide-r10-inscription-cle-inconnue, la référence JavaScript et le binaire rendent même verdict, même code et mêmes vérifications en échec ; un mutant JavaScript qui dit valide à tort est contredit par le binaire : la confrontation voit la discordance (tués)", function () {
      const binaire = [process.env.NOORTRACE_VERIFIER_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")].find((b) => b && fs.existsSync(b));
      if (!binaire) {
        this.test.title += " — en attente : binaire du vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN ou verificateur/dist/noortrace-verifier-linux-amd64)";
        this.skip();
      }
      const go = (repDossier, args) => {
        const r = spawnSync(binaire, [repDossier, ...args, "--json"], { encoding: "utf8", cwd: RACINE, maxBuffer: 64 * 1024 * 1024 });
        expect(r.status, r.stderr).to.be.oneOf([0, 1, 3]);
        return JSON.parse(r.stdout);
      };
      const resume = (r) => ({ verdict: r.verdict, exit_code: r.exit_code, failed_checks: r.failed_checks });
      const plans = [
        ["invalide-t2-jeton-autre-manifeste", "T-2", mutant("mn66-t2", [{ fichier: "lib/horodatage.mjs", ancien: 'else if (!egalOctets(empreinte, attendu)) res["T-2"] = echoue(', nouveau: 'else if (false) res["T-2"] = echoue(' }])],
        ["invalide-r10-inscription-cle-inconnue", "R-10", mutant("mn66-r10", [forcer("R-10")])],
      ];
      for (const [nom, id, m] of plans) {
        const { rep, a, args } = dossierCt6(nom);
        const reference = rapportDossier(RACINE, rep, args);
        const independant = go(rep, args);
        expect(independant.verifier.implementation, nom).to.equal("binaire_go");
        expect(resume(reference), `${nom} : référence`).to.deep.equal({ verdict: "invalide", exit_code: a.exit_code, failed_checks: [id] });
        expect(resume(independant), `${nom} : référence et binaire concordent`).to.deep.equal(resume(reference));
        const mutantJs = rapportDossier(m.racine, rep, args);
        expect(mutantJs.failed_checks, `${nom} : le mutant ne voit plus ${id}`).to.not.include(id);
        // Le mutant ne dit plus `invalide` ; il ne dit pas `valide` non plus : le dossier porte des pièces d'essai, et le
        // complément du 2026-11-23 (CT-6 EX-6.26) le garde au code 3. La discordance avec le binaire reste entière.
        expect([mutantJs.verdict, mutantJs.exit_code], `${nom} : le mutant ne dit plus invalide, à tort`).to.deep.equal(["incomplet", 3]);
        expect(resume(mutantJs), `${nom} : la confrontation au binaire voit la discordance`).to.not.deep.equal(resume(independant));
      }
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

    it("TA-5 (MN-5, complément RL-2 et RL-3 sur la bibliothèque de référence) : verifierRelais, sur la retenue et l'exécution relayée de CT-2 annexe A.2 : un MAC des arguments en clair différent de celui inscrit est refusé RL-2, un second relais d'une approbation déjà servie est refusé RL-3 ; mutant sans la comparaison des MAC et mutant sans RL-3 : ces relais passent (tués)", async function () {
      const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
      const debutA2 = CT2.indexOf("### A.2");
      expect(debutA2).to.be.greaterThan(0);
      const RETENUE = JSON.parse(CT2.slice(CT2.indexOf("```json\n", debutA2) + 8, CT2.indexOf("\n```", CT2.indexOf("```json\n", debutA2))));
      const RELAYE = JSON.parse(/\n(\{"approval":\{"approvers"[^\n]+)\n/.exec(CT2)[1]);
      const DECISION = RELAYE.approval;
      expect([RETENUE.execution.status, RELAYE.execution.status, DECISION.decision, DECISION.ticket]).to.deep.equal(["retenue", "executee", "approuve", RETENUE.policy.ticket]);
      const ARGS_CLAIR = { claim_id: "2026-77812", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" };
      const J = await ref("lib/journal.mjs");
      const CLE_MAC = Buffer.from(J.sha256(Buffer.from("noortrace/vecteurs/v0/cle-mac-relais/test", "utf8")).slice(2), "hex");
      const essai = async (racine) => {
        const A = await importer(racine, "lib/approbation.mjs");
        const mac = A.macRelais(CLE_MAC, ARGS_CLAIR);
        const base = () => ({ reponse: null, decisionScellee: structuredClone(DECISION), retenue: structuredClone(RETENUE), appel: { execution: { tool: RELAYE.execution.tool, arguments: structuredClone(RELAYE.execution.arguments) }, delegation: structuredClone(RELAYE.delegation) }, macRetenue: mac, macAppel: mac, executees: [], intentionsOuvertes: [], relaisEnCours: [], maintenantMs: J.msHorodatage(RELAYE.ts), timeoutMs: 0, expireAfterMs: 3600000 });
        const verdict = (o) => A.verifierRelais(o)?.check ?? null;
        expect(verdict(base()), "relais nominal").to.equal(null);
        // RL-2 : arguments en clair modifiés derrière la même pièce rédigée (seul le MAC les distingue) ; MAC de la retenue absent.
        const autreIban = verdict({ ...base(), macAppel: A.macRelais(CLE_MAC, { ...ARGS_CLAIR, beneficiary_iban: "CH5604835012345678009" }) });
        const sansMac = verdict({ ...base(), macRetenue: null });
        // RL-3 : l'approbation a déjà servi.
        const dejaExecutee = verdict({ ...base(), executees: [{ execution: { status: "executee" }, approval: { ticket: DECISION.ticket } }] });
        const intention = verdict({ ...base(), intentionsOuvertes: [DECISION.ticket] });
        const enCours = verdict({ ...base(), relaisEnCours: [DECISION.ticket] });
        return { autreIban, sansMac, dejaExecutee, intention, enCours };
      };
      expect(await essai(RACINE)).to.deep.equal({ autreIban: "RL-2", sansMac: "RL-2", dejaExecutee: "RL-3", intention: "RL-3", enCours: "RL-3" });
      const sansMac = mutant("mn5-rl2", [{ fichier: "lib/approbation.mjs", ancien: 'if (typeof macRetenue !== "string" || typeof macAppel !== "string" || macRetenue !== macAppel) return refus("RL-2");', nouveau: "if (false) return null;" }]);
      const r2 = await essai(sansMac.racine);
      expect([r2.autreIban, r2.sansMac], "mutant sans la comparaison des MAC").to.deep.equal([null, null]);
      expect([r2.dejaExecutee, r2.intention, r2.enCours]).to.deep.equal(["RL-3", "RL-3", "RL-3"]);
      const sansRl3 = mutant("mn5-rl3", [
        { fichier: "lib/approbation.mjs", ancien: 'if (executees.some((ev) => ev?.execution?.status === "executee" && ev.approval?.ticket === ticket)) return refus("RL-3");', nouveau: "if (false) return null;" },
        { fichier: "lib/approbation.mjs", ancien: 'if (intentionsOuvertes.includes(ticket) || relaisEnCours.includes(ticket)) return refus("RL-3");', nouveau: "if (false) return null;" },
      ]);
      const r3 = await essai(sansRl3.racine);
      expect([r3.dejaExecutee, r3.intention, r3.enCours], "mutant sans RL-3").to.deep.equal([null, null, null]);
      expect([r3.autreIban, r3.sansMac]).to.deep.equal(["RL-2", "RL-2"]);
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

    /**
     * Copie réelle d'un répertoire du dépôt (la source est résolue par realpath, les liens sont déréférencés, la
     * destination doit être neuve) : aucune écriture du mutant ne peut traverser un lien vers le dépôt.
     */
    const copierReel = (source, destination) => {
      expect(fs.existsSync(destination), `${destination} existe déjà`).to.equal(false);
      fs.cpSync(fs.realpathSync(source), destination, { recursive: true, dereference: true });
      expect(fs.lstatSync(destination).isSymbolicLink()).to.equal(false);
    };
    /** Copie de la page de référence console/ à côté d'un mutant de scripts/ (la fabrique d'EX-10.5 ne copie pas console/), avec ses remplacements ; l'intégrité sha384 de console.js est recalculée dans index.html pour que Chromium charge la page mutante. */
    const mutantConsole = (nom, remplacements) => {
      const m = mutant(nom, []);
      copierReel(path.join(RACINE, "console"), path.join(m.racine, "console"));
      for (const r of remplacements) {
        const f = path.join(m.racine, "console", r.fichier);
        const texte = fs.readFileSync(f, "utf8");
        const n = texte.split(r.ancien).length - 1;
        if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans console/${r.fichier}`);
        fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
      }
      const index = path.join(m.racine, "console", "index.html");
      const sri = "sha384-" + crypto.createHash("sha384").update(fs.readFileSync(path.join(m.racine, "console", "console.js"))).digest("base64");
      fs.writeFileSync(index, fs.readFileSync(index, "utf8").replace(/<script type="module" src="console.js" integrity="[^"]+">/, `<script type="module" src="console.js" integrity="${sri}">`));
      return m;
    };
    const PAGES_LIVREES = path.join(RACINE, "paquets", "console", "src", "pages");
    /** Fichiers lus statiquement : page de référence (console/) ou pages livrées (paquets/console/src/pages), depuis une racine donnée. */
    const sources = (racine, livrees) => {
      const rep = livrees ? path.join(racine, "paquets", "console", "src", "pages") : path.join(racine, "console");
      return fs.readdirSync(rep, { recursive: true }).map((f) => path.join(rep, f)).filter((f) => /\.(js|mjs|html)$/.test(f) && fs.statSync(f).isFile()).map((f) => [path.relative(racine, f), fs.readFileSync(f, "utf8")]);
    };
    const occurrences = (racine, livrees, motifs) => sources(racine, livrees).flatMap(([f, t]) => motifs.filter((m) => t.toLowerCase().includes(m.toLowerCase())).map((m) => `${f} : ${m}`));
    /** Sert une racine (console/ et scripts/lib/console.mjs de la référence) ; le serveur de console et le service ne répondent pas : la page s'initialise sans eux. */
    const servir = (racineConsole) => new Promise((resolve) => {
      const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
      const srv = http.createServer((req, res) => {
        const u = new URL(req.url, "http://127.0.0.1");
        let f = null;
        if (u.pathname === "/console/" || u.pathname === "/console/index.html") f = path.join(racineConsole, "console", "index.html");
        else if (u.pathname.startsWith("/console/")) f = path.join(racineConsole, "console", u.pathname.slice("/console/".length));
        else if (u.pathname === "/scripts/lib/console.mjs") f = path.join(RACINE, "scripts", "lib", "console.mjs");
        if (!f || !fs.existsSync(f) || !fs.statSync(f).isFile()) {
          res.writeHead(u.pathname.startsWith("/v0/") ? 400 : 404, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: { code: "indisponible", message: "indisponible", data: {} } }));
        }
        res.writeHead(200, { "Content-Type": types[path.extname(f)] ?? "application/octet-stream" });
        res.end(fs.readFileSync(f));
      });
      srv.listen(0, "127.0.0.1", () => resolve({ srv, origine: `http://127.0.0.1:${srv.address().port}` }));
    });
    /** Compte dans Chromium, page de référence chargée depuis `racineConsole` : les champs de fichier et les éléments du parcours c. */
    const compterDansChromium = async (chromium, racineConsole) => {
      const { srv, origine } = await servir(racineConsole);
      const navigateur = await chromium.launch();
      try {
        const page = await navigateur.newPage();
        const erreurs = [];
        page.on("pageerror", (e) => erreurs.push(String(e)));
        await page.goto(`${origine}/console/`, { waitUntil: "load" });
        await page.waitForSelector("h1");
        await page.waitForTimeout(1500);
        const n = await page.evaluate(() => ({
          fichiers: document.querySelectorAll('input[type="file"]').length,
          parcoursC: Array.from(document.querySelectorAll("*")).filter((e) => /walletconnect|portefeuille mobile|wc:/i.test(`${e.getAttribute("data-testid") ?? ""} ${e.childElementCount === 0 ? e.textContent : ""}`)).length,
          titre: document.querySelector("h1")?.textContent ?? null,
        }));
        return { ...n, erreurs };
      } finally {
        await navigateur.close();
        srv.close();
      }
    };
    const chromiumOuAttente = async (ctx) => {
      try {
        const { chromium } = await import("playwright");
        const b = await chromium.launch();
        await b.close();
        return chromium;
      } catch (e) {
        const raison = `Chromium par Playwright indisponible (${String(e.message ?? e).split("\n")[0]})`;
        // CT-3 EX-13.36 : sous NOORTRACE_EXIGER_CHROMIUM=1 (travail console-chromium de l'intégration continue), l'attente est impossible.
        if (process.env.NOORTRACE_EXIGER_CHROMIUM === "1") throw new Error(`NOORTRACE_EXIGER_CHROMIUM=1 : ${raison}`);
        ctx.test.title += ` — en attente : ${raison} (CT-3 EX-13.36)`;
        ctx.skip();
        return null;
      }
    };

    it("TA-35 (MN-35) : la page de référence console/ et les pages livrées de paquets/console ne portent ni champ de fichier, ni lireFichierCle, ni signerCondense, ni keystore ; dans Chromium, la page de référence n'a aucun input[type=file] ; mutant de la page de référence (intégrité recalculée) et mutant des pages livrées qui ajoutent un champ de fichier de clé : le champ apparaît (tués)", async function () {
      this.timeout(120_000);
      // Un champ de fichier s'écrit en HTML (type="file") ou se construit par le DOM (type: "file", setAttribute).
      const MOTIFS = ['type="file"', "type='file'", 'type: "file"', 'type:"file"', '"type", "file"', "lireFichierCle", "signerCondense", "keystore"];
      expect(occurrences(RACINE, false, MOTIFS), "page de référence").to.deep.equal([]);
      expect(occurrences(RACINE, true, MOTIFS), "pages livrées").to.deep.equal([]);
      const mRef = mutantConsole("mn35-reference", [{ fichier: "console.js", ancien: 'racine.appendChild(el("h1", { texte: "Console d\'approbation NOORTRACE (référence)" }));', nouveau: 'racine.appendChild(el("h1", { texte: "Console d\'approbation NOORTRACE (référence)" }));\nracine.appendChild(el("input", { testid: "fichier-cle", attrs: { type: "file", accept: ".json" } }));' }]);
      expect(occurrences(mRef.racine, false, MOTIFS)).to.deep.equal(['console/console.js : type: "file"']);
      const mLivre = mutant("mn35-livree", []);
      fs.mkdirSync(path.join(mLivre.racine, "paquets", "console", "src"), { recursive: true });
      copierReel(PAGES_LIVREES, path.join(mLivre.racine, "paquets", "console", "src", "pages"));
      const ticket = path.join(mLivre.racine, "paquets", "console", "src", "pages", "ecrans", "ticket.html");
      const t = fs.readFileSync(ticket, "utf8");
      expect(t.split('<div id="principal"></div>').length - 1).to.equal(1);
      fs.writeFileSync(ticket, t.replace('<div id="principal"></div>', '<div id="principal"></div>\n<input type="file" accept=".json">'));
      expect(occurrences(mLivre.racine, true, MOTIFS)).to.deep.equal(['paquets/console/src/pages/ecrans/ticket.html : type="file"']);
      const chromium = await chromiumOuAttente(this);
      const r0 = await compterDansChromium(chromium, RACINE);
      expect([r0.fichiers, r0.titre, r0.erreurs], "référence dans Chromium").to.deep.equal([0, "Console d'approbation NOORTRACE (référence)", []]);
      const r1 = await compterDansChromium(chromium, mRef.racine);
      expect([r1.fichiers, r1.erreurs], "mutant dans Chromium").to.deep.equal([1, []]);
    });

    it("TA-52 (MN-52) : la page de référence console/ ne porte rien du parcours c (walletconnect, relais, portefeuille mobile, URI wc:), ni dans Chromium ; la console livrée a walletconnect nul par défaut et refuse de démarrer quand il est posé (parcours_non_offert) ; mutants de la page, du défaut livré et du serveur livré sans le refus : le parcours est offert sans activation (tués)", async function () {
      this.timeout(120_000);
      const MOTIFS = ["walletconnect", "portefeuille mobile", "wc:", "relay"];
      expect(occurrences(RACINE, false, MOTIFS), "page de référence").to.deep.equal([]);
      // Console livrée : défaut et refus au démarrage (paquets/console/src/serveur).
      const CONSOLE_LIVREE = path.join(RACINE, "paquets", "console");
      const { materielTls, fichierComptes, ecrireConfiguration } = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "exploitation-console", "serveur", "outils.mjs")).href);
      const demarrage = async (paquet, dossier) => {
        const serveur = await import(pathToFileURL(path.join(paquet, "src", "serveur", "index.mjs")).href);
        const conf = await import(pathToFileURL(path.join(paquet, "src", "serveur", "configuration.mjs")).href);
        const tls = materielTls(dossier);
        if (!tls) {
          this.test.title += " — en attente : openssl indisponible (matériel TLS du serveur de console)";
          this.skip();
        }
        const { config } = ecrireConfiguration(dossier, { tls, comptes: fichierComptes([{ name: "a", password: "b" }]), autres: { walletconnect: { relay_url: "wss://relais.example", project_id: { env: "NOORTRACE_TEST_PROJET_WC" } } } });
        process.env.NOORTRACE_TEST_PROJET_WC = "identifiant-de-projet-d-essai";
        try {
          const srv = await serveur.demarrerServeur({ config, base: dossier });
          await srv.arreter();
          return { defaut: conf.DEFAUTS.walletconnect, demarre: true, refus: null };
        } catch (e) {
          return { defaut: conf.DEFAUTS.walletconnect, demarre: false, refus: e.rapport ?? String(e.message) };
        } finally {
          delete process.env.NOORTRACE_TEST_PROJET_WC;
        }
      };
      const copiePaquet = (nom, remplacements) => {
        const m = mutant(nom, []);
        const paquet = path.join(m.racine, "paquets", "console");
        fs.mkdirSync(path.dirname(paquet), { recursive: true });
        copierReel(CONSOLE_LIVREE, paquet);
        for (const r of remplacements) {
          const f = path.join(paquet, "src", r.fichier);
          const texte = fs.readFileSync(f, "utf8");
          const n = texte.split(r.ancien).length - 1;
          if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans paquets/console/src/${r.fichier}`);
          fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
        }
        return paquet;
      };
      const base = fs.mkdtempSync(path.join(TMP, "noortrace-ta52-"));
      MUTANTS.push(base);
      expect(await demarrage(CONSOLE_LIVREE, path.join(base, "reference"))).to.deep.equal({ defaut: null, demarre: false, refus: { valide: false, errors: [{ code: "parcours_non_offert", pointer: "/walletconnect" }] } });
      const pDefaut = copiePaquet("mn52-defaut", [{ fichier: "serveur/configuration.mjs", ancien: "  walletconnect: null,\n});", nouveau: '  walletconnect: Object.freeze({ relay_url: "wss://relais.example", project_id: { env: "NOORTRACE_TEST_PROJET_WC" } }),\n});' }]);
      const r1 = await demarrage(pDefaut, path.join(base, "defaut"));
      expect(r1.defaut, "mutant : le parcours c est activé par défaut").to.not.equal(null);
      const pRefus = copiePaquet("mn52-refus", [{ fichier: "serveur/index.mjs", ancien: 'if (c.walletconnect !== null) throw refusDemarrage("parcours_non_offert", "/walletconnect", "parcours c non offert par cette console");', nouveau: 'if (false) throw refusDemarrage("parcours_non_offert", "/walletconnect", "parcours c non offert par cette console");' }]);
      const r2 = await demarrage(pRefus, path.join(base, "refus"));
      expect([r2.demarre, r2.refus], "mutant : le serveur démarre avec walletconnect posé").to.deep.equal([true, null]);
      // Page de référence : mutant qui offre le parcours c.
      const mRef = mutantConsole("mn52-reference", [{ fichier: "console.js", ancien: 'racine.appendChild(el("h1", { texte: "Console d\'approbation NOORTRACE (référence)" }));', nouveau: 'racine.appendChild(el("h1", { texte: "Console d\'approbation NOORTRACE (référence)" }));\nracine.appendChild(bouton("Portefeuille mobile (WalletConnect)", "parcours-c-walletconnect", () => {}));' }]);
      expect(occurrences(mRef.racine, false, MOTIFS)).to.deep.equal(["console/console.js : walletconnect", "console/console.js : portefeuille mobile"]);
      const chromium = await chromiumOuAttente(this);
      const r0 = await compterDansChromium(chromium, RACINE);
      expect([r0.parcoursC, r0.erreurs], "référence dans Chromium").to.deep.equal([0, []]);
      const r3 = await compterDansChromium(chromium, mRef.racine);
      expect(r3.parcoursC, "mutant dans Chromium").to.be.at.least(1);
      expect(r3.erreurs).to.deep.equal([]);
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
        { fichier: "lib/ancrage.mjs", ancien: "      this.periodeClose(t, m, { seulement: manquantes, acquisitions });\n", nouveau: "      ;\n" },
        { fichier: "lib/ancrage.mjs", ancien: "      this.pointProduit(t, k, { acquisitions });\n", nouveau: "      ;\n" },
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

    it("TA-58 (MN-58) : trace empreinte-squattee du générateur de CT-5 (PD-10) : l'ancre de la période part avant toute requête RFC 3161 ; le refus empreinte_squattee du registre passe la demande en refusee, lève l'alerte critique, consigne anchor_refused et n'ouvre aucun nouvel essai ; mutant sans le passage en refusee ni l'alerte : la trace diverge au pas 47 et la file finale diffère (tué)", async function () {
      const G = await import(pathToFileURL(path.join(RACINE, "scripts", "vecteurs", "generer-ct5.mjs")).href);
      const t = G.traceEmpreinteSquattee();
      expect(t.id).to.equal("empreinte-squattee");
      const types = t.inputs.map((e) => e.type);
      const echec = t.inputs.find((e) => e.type === "echec_registre");
      expect(echec.data.code).to.equal("empreinte_squattee");
      expect(echec.data.request_id.startsWith("ancre_registre_periode:")).to.equal(true);
      // L'ancre part avant la requête RFC 3161 de la période (CT-4 EX-8.4, CT-5 EX-4.7) ; le refus n'est suivi d'aucun envoi au registre.
      const actions = t.expected.map((a) => a.action);
      const envoiAncre = t.expected.findIndex((a) => a.action === "envoyer_registre" && a.request_id === echec.data.request_id);
      const requeteJeton = t.expected.findIndex((a) => a.action === "envoyer_rfc3161" && a.request_id.startsWith("jeton_periode:"));
      expect(envoiAncre).to.be.greaterThan(-1);
      // Lecture littérale d'EX-8.4, règle 2 (CT-5 EX-9.7, variante B) : l'ancre de la période n'étant pas incluse, la
      // requête RFC 3161 du periodHash ne part jamais ; le jeton de clôture reste attente_registre.
      expect(requeteJeton, "aucune requête RFC 3161 de la période").to.equal(-1);
      expect(t.queue_after.find((d) => d.id.startsWith("jeton_periode:")).state).to.equal("attente_registre");
      expect(t.expected.filter((a) => a.action === "envoyer_registre" && a.request_id === echec.data.request_id).length, "un seul envoi de l'ancre").to.equal(1);
      expect(types.filter((x) => x === "tic").length).to.be.at.least(2);
      expect(t.expected.filter((a) => a.action === "alerter" && a.detail?.code === "empreinte_squattee").length).to.equal(1);
      expect(t.expected.some((a) => a.action === "journaliser" && a.detail?.event === "anchor_refused")).to.equal(true);
      expect(t.queue_after.find((d) => d.id === echec.data.request_id).state).to.equal("refusee");
      expect(actions.slice(47, 50)).to.deep.equal(["ecrire_file", "alerter", "journaliser"]);
      const A0 = await ref("lib/ancrage.mjs");
      expect(A0.verifierTrace(t), "référence").to.deep.equal([]);
      const m = mutant("mn58", [
        { fichier: "lib/ancrage.mjs", ancien: '      this.ecrire(d, t, "refusee");\n      this.alerter(t, d.id, "empreinte_squattee", "critique");\n', nouveau: "      ;\n" },
      ]);
      const A1 = await m.importer("lib/ancrage.mjs");
      const ecarts = A1.verifierTrace(t);
      const premier = ecarts.find((e) => e.index !== undefined);
      expect(premier, "le mutant doit diverger sur les actions").to.not.equal(undefined);
      expect([premier.index, premier.attendu?.action]).to.deep.equal([47, "ecrire_file"]);
      expect(ecarts.some((e) => e.queue !== undefined), "la file finale doit diverger (la demande n'est plus refusee)").to.equal(true);
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

    it("TA-57 (MN-57) : le condensé d'inscription de register-digest-rec-test-01 (ct-4/condenses.json) est redonné ; une demande d'inscription de la même clé signée au seuil par les membres pour l'organisation B est refusée pour l'organisation A (RG-12 signataire_different) ; mutant qui retire org_id de la préimage, côté signataire et côté vérificateur : les mêmes signatures valent pour A (tué)", async function () {
      const cas = lireJSON(CT4, "condenses.json").cases.find((c) => c.id === "register-digest-rec-test-01");
      const comptes = lireJSON(VECTEURS, "ct-3", "constantes.json").accounts;
      const membres = comptes.map((a) => a.address);
      const orgB = "0x" + "b".repeat(64);
      expect(orgB).to.not.equal(cas.input.org_id);
      const essai = async (racine) => {
        const C = await importer(racine, "lib/conventions-registre.mjs");
        const dA = C.condenseInscription(cas.input);
        const dB = C.condenseInscription({ ...cas.input, org_id: orgB });
        // Le jeu de B signe la demande de B (deux membres, seuil 2, rangées par adresse).
        const signatures = C.rangerSignatures(comptes.slice(0, 2).map((a) => C.signerCondense(a.private_key, dB.digest)));
        expect(C.verifier("RG-13", () => C.verifierJeuSignatures({ digest: dB.digest, signatures, membres, seuil: 2 })).status, "sous B").to.equal("reussi");
        const sousA = C.verifier("RG-13", () => C.verifierJeuSignatures({ digest: dA.digest, signatures, membres, seuil: 2 }));
        return { digestA: dA.digest, longueur: dA.preimage_length, memeCondense: dA.digest === dB.digest, sousA: { status: sousA.status, check: sousA.check, code: sousA.code } };
      };
      const r0 = await essai(RACINE);
      expect([r0.digestA, r0.longueur, r0.memeCondense]).to.deep.equal([cas.expected.digest, 198, false]);
      expect(r0.sousA).to.deep.equal({ status: "echoue", check: "RG-12", code: "signataire_different" });
      const m = mutant("mn57", [{ fichier: "lib/conventions-registre.mjs", ancien: "Buffer.from(ETIQUETTES.inscription, \"utf8\"), b32(org_id), b32(journal_id),", nouveau: "Buffer.from(ETIQUETTES.inscription, \"utf8\"), b32(journal_id)," }]);
      const r1 = await essai(m.racine);
      expect(r1.memeCondense, "sans org_id, A et B ont le même condensé").to.equal(true);
      expect(r1.sousA.status, "les signatures de B valent pour A").to.equal("reussi");
    });

    // Outil de référence scripts/registre/noortrace-registre.mjs sur le réseau Hardhat en mémoire (31337, --sans-capture ;
    // CT-4 EX-A.6) : préparation partagée par TA-40, TA-53 et TA-73, faite au premier essai qui la demande (réseau,
    // contrats, manifeste d'essai, parcours de la section 7 jusqu'à l'inscription du client), défaite dans le crochet
    // after de cette section.
    const H = { prete: null };
    const sortie = (code, out) => {
      const s = JSON.parse(out);
      expect(s.exit_code).to.equal(code);
      return s;
    };
    /** Exécute une commande de l'outil d'une racine donnée (référence ou mutant), en processus. */
    const outilDe = async (racine, args) => {
      const { executer } = await importer(racine, "registre/noortrace-registre.mjs");
      let out = "";
      const { code } = await executer(args, { stdout: { write: (s) => (out += s) }, stderr: { write: () => {} } });
      return sortie(code, out);
    };
    const R = (racine, args) => outilDe(racine, [...args, "--instance", H.instance, "--rpc", H.url, "--sans-capture"]);
    const refus = (s, code, result = "refuse") => expect([s.result, s.error?.code], JSON.stringify(s.error)).to.deep.equal([result, code]);
    const reussite = (s) => expect([s.result, s.error], JSON.stringify(s.error)).to.deep.equal(["reussi", null]);
    /** Mutant de l'outil : la fabrique d'EX-10.5 plus un lien vers hh-artifacts/, que l'outil lit depuis sa racine (ABI de compilation). */
    const mutantOutil = (nom, remplacements) => {
      const m = mutant(nom, remplacements.map((r) => ({ fichier: "registre/noortrace-registre.mjs", ancien: r.ancien, nouveau: r.nouveau })));
      fs.symlinkSync(path.join(RACINE, "hh-artifacts"), path.join(m.racine, "hh-artifacts"));
      return m.racine;
    };
    const hardhat = () => (H.prete ??= preparerHardhat());
    async function preparerHardhat() {
      const { network } = await import("hardhat");
      const { deployNoortrace } = await ref("lib/noortrace.mjs");
      const C = await ref("lib/conventions-registre.mjs");
      const J = await ref("lib/journal.mjs");
      H.conn = await network.create();
      await H.conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
      ({ deployment: H.deploiement } = await deployNoortrace(H.conn.ethers, { networkName: "essai-ct9-registre" }));
      H.srv = http.createServer(async (req, res) => {
        let corps = "";
        for await (const b of req) corps += b;
        const r = JSON.parse(corps);
        let reponse;
        try {
          reponse = { jsonrpc: "2.0", id: r.id, result: await H.conn.provider.request({ method: r.method, params: r.params }) };
        } catch (err) {
          reponse = { jsonrpc: "2.0", id: r.id, error: { code: err.code ?? -32000, message: err.message } };
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(reponse));
      });
      await new Promise((resolve) => H.srv.listen(0, "127.0.0.1", resolve));
      H.url = `http://127.0.0.1:${H.srv.address().port}`;
      H.E = fs.mkdtempSync(path.join(TMP, "noortrace-ta-registre-"));
      MUTANTS.push(H.E);
      // Manifeste d'essai de l'H.instance Hardhat (CT-4 EX-A.6), comme test/registreCt4.test.js.
      const deployeur = H.deploiement.deployeur.toLowerCase();
      const genese = { chainId: 31337, alloc: [{ address: deployeur, balanceWei: "10000000000000000000000" }], rules: { chainId: "noortrace-31337-essai", ...C.REGLES_SANS_EMISSION } };
      fs.writeFileSync(path.join(H.E, "genese.json"), JSON.stringify(genese, null, 2) + "\n");
      const val = lireJSON(RACINE, "test", "fixtures", "certificat-commit", "validators.json").validators;
      H.manifeste = {
        version: 0, revision: 1, previous_sha256: null, published_at: "2026-10-25T00:00:00.000Z", nature: "developpement",
        bft_chain_id: "noortrace-31337-essai", evm_chain_id: 31337,
        evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-10-25T00:00:00.000Z", source: "réseau Hardhat en mémoire des tests (CT-4 EX-A.6)" },
        genesis: { file: "genese.json", sha256: J.sha256(fs.readFileSync(path.join(H.E, "genese.json"))), rules_line: C.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
        noorcore: { repository: "https://github.com/noorfinances-eng/noorchain-core", commit: "618fcef8805ef5b4cb9291a3dd97be710e489297", go_version: "1.26.9", patches: [], artifacts: [{ kind: "binaire", name: "sans objet : réseau Hardhat", sha256: C.HACHAGE_NUL, build: "sans objet" }] },
        validator_sets: [{ from_height: 1, to_height: null, validators: val, source: "jeu du réseau de développement, sans effet sur le réseau Hardhat", valset_hash: C.hachageJeuValidateurs(val), operators: val.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: null })) }],
        fees: { ...C.FRAIS_DEFAUT },
        contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n, i) => ({ name: n, address: H.deploiement.contrats[n].adresse.toLowerCase(), deployer: deployeur, nonce: i, constructor_args: n === "AttestationRegistry" ? [] : n === "CuratorSetRegistry" ? [deployeur] : [H.deploiement.contrats.CuratorSetRegistry.adresse.toLowerCase()], transaction_hash: H.deploiement.contrats[n].tx, block_number: H.deploiement.contrats[n].bloc, block_hash: null, evidence: null, to_height: null })),
        compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
        accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
        source: "manifeste d'essai du réseau Hardhat en mémoire (CT-4 EX-A.6)",
      };
      H.instance = path.join(H.E, "instance.json");
      fs.writeFileSync(H.instance, JSON.stringify(H.manifeste, null, 2) + "\n");
      // Parcours de la section 7 jusqu'à l'inscription du client (jeu, assignation, approvisionnement).
      reussite(await R(RACINE, ["etat"]));
      reussite(await outilDe(RACINE, ["cles-essai", "--instance", H.instance, "--sortie", path.join(H.E, "cles")]));
      H.publiques = lireJSON(H.E, "cles", "cles-essai.json");
      H.dossier = path.join(H.E, "dossier.json");
      reussite(await R(RACINE, ["inscrire-client", "--preparer", "--org", "essai-ct9", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(H.E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", H.dossier]));
      reussite(await R(RACINE, ["inscrire-client", "--dossier", H.dossier, "--exploitant", "hardhat:0", "--captures", path.join(H.E, "captures")]));
      return H;
    }

    after(function () {
      H.srv?.close();
    });

    it("TA-40 (MN-40, complément) : approvisionner --vers une adresse aléatoire hors d'EX-8.20 est refusé compte_inattendu (OP-5) et rien ne part ; mutant de l'outil sans le contrôle du destinataire : le transfert part et l'adresse est approvisionnée (tué)", async function () {
      const { conn, E, manifeste, deploiement, publiques, dossier } = await hardhat();
      const { Wallet } = await import("ethers");
      const solde = async (a) => BigInt(await conn.provider.request({ method: "eth_getBalance", params: [a, "latest"] }));
      const cible = Wallet.createRandom().address.toLowerCase();
      // Confirmation hors bande exigée par CT-4 EX-8.21 (pièce non vide, --confirmation), pour atteindre le contrôle du destinataire.
      const confirmation = path.join(E, "confirmation-approvisionnement-mn40.txt");
      fs.writeFileSync(confirmation, "Confirmation hors bande de l'approvisionnement, consignée (EX-8.21).\n");
      const args = ["approvisionner", "--vers", cible, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures"), "--confirmation", confirmation];
      const r0 = await R(RACINE, args);
      refus(r0, "compte_inattendu");
      expect(r0.error.check).to.equal("OP-5");
      expect(await solde(cible)).to.equal(0n);
      const m = mutantOutil("mn40", [{ ancien: "if (!admission) throw new Arret(\"compte_inattendu\", \"OP-5\",", nouveau: "if (false) throw new Arret(\"compte_inattendu\", \"OP-5\"," }]);
      const r1 = await R(m, args);
      reussite(r1);
      expect(r1.outputs.to).to.equal(cible);
      expect(await solde(cible)).to.equal(BigInt(r1.outputs.amount_wei));
      expect(await solde(cible) > 0n).to.equal(true);
    });

    it("TA-53 (MN-53, complément) : reassigner sans --demande est refusé usage (inutilisable) ; vers un jeu dont admin() diffère sans --changement-administrateur, refusé jeu_invalide (OP-5) ; mutant sans l'exigence de --demande et mutant sans la comparaison d'admin() : la réassignation part (tués)", async function () {
      const { conn, E, manifeste, deploiement, publiques, dossier } = await hardhat();
      const d = lireJSON(dossier);
      const fabrique = await conn.ethers.getContractFactory("CuratorSet");
      const { Wallet } = await import("ethers");
      const deployer = async (admin) => {
        const c = await fabrique.deploy(admin, [Wallet.createRandom().address], 1);
        await c.waitForDeployment();
        return (await c.getAddress()).toLowerCase();
      };
      const csr = await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address);
      const jeuCourant = async () => (await csr.curatorSetOf(d.organisation.org_id)).toLowerCase();
      const demandeEcrite = path.join(E, "demande-reassignation.txt");
      fs.writeFileSync(demandeEcrite, "Demande de réassignation du jeu de essai-ct9, consignée (EX-8.10).\n");
      const base = ["reassigner", "--org-id", d.organisation.org_id, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures"), "--confirmer", d.organisation.org_id];
      // Sans --demande.
      const memeAdmin = await deployer(publiques.set_admin);
      const initial = await jeuCourant();
      expect(initial).to.not.equal(memeAdmin);
      refus(await R(RACINE, [...base, "--jeu", memeAdmin]), "usage", "inutilisable");
      expect(await jeuCourant()).to.equal(initial);
      const sansDemande = mutantOutil("mn53-demande", [
        { ancien: 'const demandeEcrite = lireOctets(exigerOption(o, "demande"));', nouveau: 'const demandeEcrite = o.demande ? lireOctets(o.demande) : Buffer.alloc(0);' },
        { ancien: 'if (!demandeEcrite.length) throw new Arret("entree_illisible", null, "--demande : la demande écrite du client est vide (EX-8.10)");', nouveau: "if (false) throw null;" },
      ]);
      const r1 = await R(sansDemande, [...base, "--jeu", memeAdmin]);
      reussite(r1);
      expect([r1.outputs.previous, await jeuCourant()]).to.deep.equal([initial, memeAdmin]);
      // admin() différent, avec --demande.
      const autreAdmin = await deployer(deploiement.deployeur);
      const r2 = await R(RACINE, [...base, "--jeu", autreAdmin, "--demande", demandeEcrite]);
      refus(r2, "jeu_invalide");
      expect(r2.error.check).to.equal("OP-5");
      expect(await jeuCourant()).to.equal(memeAdmin);
      const sansAdmin = mutantOutil("mn53-admin", [{ ancien: 'if (!o["changement-administrateur"] && adminNouveau !== adminPrecedent) throw new Arret("jeu_invalide", "OP-5",', nouveau: 'if (false) throw new Arret("jeu_invalide", "OP-5",' }]);
      const r3 = await R(sansAdmin, [...base, "--jeu", autreAdmin, "--demande", demandeEcrite]);
      reussite(r3);
      expect([r3.outputs.previous, r3.outputs.new_set.admin, await jeuCourant()]).to.deep.equal([memeAdmin, deploiement.deployeur.toLowerCase(), autreAdmin]);
    });

    it("TA-73 (MN-73, partie reassigner ; administrer-jeu et approvisionner sans --confirmation sont éprouvés par test/registre-revue.test.js, CT-4 EX-8.21) : reassigner sans --confirmer <org_id> est refusé usage (inutilisable) même avec la demande écrite ; mutant sans l'exigence de --confirmer : la réassignation part (tué)", async function () {
      const { conn, E, manifeste, deploiement, publiques, dossier } = await hardhat();
      const d = lireJSON(dossier);
      const fabrique = await conn.ethers.getContractFactory("CuratorSet");
      const { Wallet } = await import("ethers");
      const csr = await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address);
      const jeuCourant = async () => (await csr.curatorSetOf(d.organisation.org_id)).toLowerCase();
      const courant = await jeuCourant();
      const adminCourant = (await (await conn.ethers.getContractAt("CuratorSet", courant)).admin()).toLowerCase();
      const c = await fabrique.deploy(adminCourant, [Wallet.createRandom().address], 1);
      await c.waitForDeployment();
      const nouveau = (await c.getAddress()).toLowerCase();
      const demandeEcrite = path.join(E, "demande-reassignation-73.txt");
      fs.writeFileSync(demandeEcrite, "Demande écrite du client pour la réassignation (EX-8.10, EX-8.21).\n");
      const args = ["reassigner", "--org-id", d.organisation.org_id, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures"), "--jeu", nouveau, "--demande", demandeEcrite];
      refus(await R(RACINE, args), "usage", "inutilisable");
      expect(await jeuCourant()).to.equal(courant);
      const m = mutantOutil("mn73", [{ ancien: 'if (String(exigerOption(o, "confirmer")).toLowerCase() !== orgId) throw new Arret("usage", null, "--confirmer doit répéter l\'org_id réassigné (EX-8.10)");', nouveau: "if (false) throw null;" }]);
      const r1 = await R(m, args);
      reussite(r1);
      expect([r1.outputs.previous, await jeuCourant()]).to.deep.equal([courant, nouveau]);
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
  let supportWorm = null;
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
    await supportWorm?.fermer();
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

  it("TA-5 (MN-5, complément RL-2 et RL-3 sur le code livré) : verifierRelais de paquets/enregistreur (src/approbations.mjs), sur la retenue et l'exécution relayée de CT-2 annexe A.2 : un MAC des arguments en clair différent est refusé RL-2, un second relais d'une approbation déjà servie est refusé RL-3 ; mutant sans la comparaison des MAC et mutant sans RL-3 : ces relais passent (tués)", async function () {
    const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
    const debutA2 = CT2.indexOf("### A.2");
    const RETENUE = JSON.parse(CT2.slice(CT2.indexOf("```json\n", debutA2) + 8, CT2.indexOf("\n```", CT2.indexOf("```json\n", debutA2))));
    const RELAYE = JSON.parse(/\n(\{"approval":\{"approvers"[^\n]+)\n/.exec(CT2)[1]);
    const DECISION = RELAYE.approval;
    expect([RETENUE.execution.status, RELAYE.execution.status, DECISION.decision, DECISION.ticket]).to.deep.equal(["retenue", "executee", "approuve", RETENUE.policy.ticket]);
    const J = await charger("scripts/lib/journal.mjs");
    const politique = () => ({ approval: { expire_after_ms: 3600000, rules: { separation: { self_approval: "permise", identities: [] } } } });
    const essai = async (paquet) => {
      const { verifierRelais } = await paquet.importer("approbations.mjs");
      const ctx = ({ premiers = [], intentions = [], relais = [], mac = "0xmac-inscrit" } = {}) => ({
        index: { decisions: new Map([[DECISION.ticket, { approval: structuredClone(DECISION) }]]), retenuesParHash: new Map([[RETENUE.hash, structuredClone(RETENUE)]]), premiersExecutes: new Set(premiers) },
        macs: new Map([[RETENUE.hash, mac]]), intentionsOuvertes: new Set(intentions), relaisEnCours: new Set(relais), politique,
      });
      const appel = (mac = "0xmac-inscrit") => ({ ticket: DECISION.ticket, tool: RETENUE.execution.tool, delegation: structuredClone(RELAYE.delegation), arguments: structuredClone(RELAYE.execution.arguments), mac, approvalReponse: null, instant: J.msHorodatage(RELAYE.ts), timeoutOutil: 0 });
      const verdict = (a, c) => {
        const r = verifierRelais(a, c);
        return r.ok ? null : r.verification;
      };
      expect(verdict(appel(), ctx()), "relais nominal").to.equal(null);
      return {
        autreMac: verdict(appel("0xmac-des-arguments-modifies"), ctx()),
        sansMacInscrit: verdict(appel(), ctx({ mac: null })),
        dejaExecutee: verdict(appel(), ctx({ premiers: [DECISION.ticket] })),
        intention: verdict(appel(), ctx({ intentions: [DECISION.ticket] })),
        enCours: verdict(appel(), ctx({ relais: [DECISION.ticket] })),
      };
    };
    expect(await essai(REFERENCE)).to.deep.equal({ autreMac: "RL-2", sansMacInscrit: "RL-2", dejaExecutee: "RL-3", intention: "RL-3", enCours: "RL-3" });
    const sansMac = mutantPaquet("mn5-rl2", [{ fichier: "approbations.mjs", ancien: 'if (!macInscrit || macInscrit !== appel.mac) return non("RL-2");', nouveau: 'if (false) return non("RL-2");' }]);
    const r2 = await essai(sansMac);
    expect([r2.autreMac, r2.sansMacInscrit], "mutant sans la comparaison des MAC").to.deep.equal([null, null]);
    expect([r2.dejaExecutee, r2.intention, r2.enCours]).to.deep.equal(["RL-3", "RL-3", "RL-3"]);
    const sansRl3 = mutantPaquet("mn5-rl3", [{ fichier: "approbations.mjs", ancien: "} else if (ctx.index.premiersExecutes.has(appel.ticket) || ctx.intentionsOuvertes.has(appel.ticket) || ctx.relaisEnCours.has(appel.ticket)) {", nouveau: "} else if (false) {" }]);
    const r3 = await essai(sansRl3);
    expect([r3.dejaExecutee, r3.intention, r3.enCours], "mutant sans RL-3").to.deep.equal([null, null, null]);
    expect([r3.autreMac, r3.sansMacInscrit]).to.deep.equal(["RL-2", "RL-2"]);
  });

  it("TA-43 (MN-43, partie phase 2 sur le démon de l'étape 4) : démon réel, frontal MCP Streamable HTTP : un tools/call avec un jeton inconnu puis avec le jeton de l'hôte ; aucune des deux valeurs n'apparaît au journal d'exploitation ni sous le répertoire du démon (EX-17.3) ; mutant dont la ligne auth_failed consigne l'en-tête présenté : la valeur est au journal (tué)", async function () {
    const JETON_INCONNU = `jeton-presente-ta43-${randomBytes(16).toString("hex")}`;
    const scenario = async (c, p) => {
      const jetonHote = c.env.NOORTRACE_TEST_JETON_HOTE;
      expect(jetonHote).to.be.a("string");
      const faux = await appelerOutil(c.portHttp, JETON_INCONNU, "demo__lire", { id: "S-faux" });
      const bon = await appelerOutil(c.portHttp, jetonHote, "demo__lire", { id: "S-bon" });
      await attendre(() => p.lignes().some((l) => l.event === "auth_failed"));
      await attendre(async () => (await evenementsOutils(c)).length >= 1);
      const fichiers = fichiersSous(c.dir).filter((f) => f !== path.join(c.dir, "configuration.json"));
      expect(fichiers.some((f) => f === c.config.supervision.ops_log.path), "le journal d'exploitation est sous le répertoire").to.equal(true);
      const porteurs = (valeur) => fichiers.filter((f) => fs.readFileSync(f).includes(valeur)).map((f) => path.relative(c.dir, f));
      // La configuration écrite ne porte que des références de secrets (EX-15.3), jamais la valeur du jeton de l'hôte.
      expect(fs.readFileSync(path.join(c.dir, "configuration.json"), "utf8").includes(jetonHote)).to.equal(false);
      return { statuts: [faux.statut, bon.statut], auth: p.lignes().filter((l) => l.event === "auth_failed").map((l) => l.data.reason), inconnu: porteurs(JETON_INCONNU), hote: porteurs(jetonHote) };
    };
    const r0 = await jouer(REFERENCE, null, scenario);
    expect(r0.statuts).to.deep.equal([401, 200]);
    expect(r0.auth).to.deep.equal(["jeton_inconnu"]);
    expect([r0.inconnu, r0.hote], "aucun fichier du démon ne porte un jeton").to.deep.equal([[], []]);
    const m = mutantPaquet("mn43", [{ fichier: "mcp/hote-http.mjs", ancien: 'this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "http", reason: e.raison, status: e.statut });', nouveau: 'this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "http", reason: e.raison, status: e.statut, authorization: req.headers.authorization ?? null });' }]);
    const r1 = await jouer(m, null, scenario);
    expect(r1.statuts).to.deep.equal([401, 200]);
    expect(r1.inconnu.length, "mutant : la valeur présentée est journalisée").to.be.at.least(1);
    expect(r1.inconnu.every((f) => f.endsWith(".ndjson") || f.endsWith(".log") || f.includes("exploitation")), `fichiers porteurs : ${r1.inconnu.join(", ")}`).to.equal(true);
    expect(r1.hote, "le jeton de l'hôte, lui, n'est écrit nulle part").to.deep.equal([]);
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
    // journal, correction révélée par TE-11), seconde défense contre la même menace (MN-19 : « si le jeton de clôture
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
  // Signataires (classes A, B, C) : TA-31 et TA-33 sur un service de
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

  it("TA-25 (MN-25) : démon réel dans un arbre d'installation de la forme de l'image de référence, image attendue lue dans le fichier monté : l'arbre publié consigne à startup l'empreinte publiée ; l'arbre modifié d'un octet est signalé (image_match faux, ligne image_mismatch) ; mutant sans la comparaison de l'empreinte à la version publiée : l'arbre modifié tourne sans signal (tué)", async function () {
    const { arbreInstallation, modifierUnOctet, ecrireImageAttendue } = await charger("test/fixtures/enregistreur-adversarial/image.mjs");
    const { empreinteCode } = await charger("paquets/enregistreur/src/empreinte-image.mjs");
    const IMAGE = `noortrace/enregistreur:0.1.0@sha256:${"25".repeat(32)}`;
    const d = path.join(base, "ta25");
    fs.mkdirSync(d);
    const OCTET = "paquets/enregistreur/src/horloge.mjs";
    const publie = arbreInstallation(path.join(d, "publie"));
    const publiee = empreinteCode({ racine: publie.racine }).code_sha256;
    expect(publiee).to.match(/^0x[0-9a-f]{64}$/);
    /** Démarre le démon de l'arbre avec l'image attendue de la version publiée ; rend ce que le journal d'exploitation en dit. */
    const observer = async (arbre) => {
      const c = await configuration();
      c.arguments = ["--image-attendue", ecrireImageAttendue(path.join(c.dir, "image-attendue.json"), { image: IMAGE, code_sha256: publiee })];
      const p = await demarrer(arbre, c, path.join(c.dir, "configuration.json"));
      try {
        const lignes = p.lignes();
        return {
          startup: lignes.filter((l) => l.event === "startup").map((l) => ({ image_expected: l.data.image_expected, code_sha256: l.data.code_sha256, image_match: l.data.image_match })),
          ecarts: lignes.filter((l) => l.event === "image_mismatch").map((l) => ({ level: l.level, ...l.data })),
        };
      } finally {
        await arreter(p);
      }
    };
    // Version publiée : l'empreinte consignée est la publiée, rien n'est signalé.
    expect(await observer(publie)).to.deep.equal({ startup: [{ image_expected: IMAGE, code_sha256: publiee, image_match: true }], ecarts: [] });
    // Image modifiée d'un octet, lancée à la place de la version publiée : l'écart est signalé.
    const modifie = arbreInstallation(path.join(d, "modifie"));
    modifierUnOctet(modifie, OCTET);
    const modifiee = empreinteCode({ racine: modifie.racine }).code_sha256;
    expect(modifiee).to.not.equal(publiee);
    expect(await observer(modifie)).to.deep.equal({
      startup: [{ image_expected: IMAGE, code_sha256: modifiee, image_match: false }],
      ecarts: [{ level: "error", image_expected: IMAGE, expected_code_sha256: publiee, code_sha256: modifiee }],
    });
    // Mutant : la même image modifiée, dont le démon ne compare plus son empreinte à la version publiée.
    const m = mutantPaquet("mn25", [{ fichier: "empreinte-image.mjs", ancien: "const concorde = calcule.code_sha256 === attendu.code_sha256;", nouveau: "const concorde = true;" }]);
    const mutant = arbreInstallation(path.join(d, "mutant"), { enregistreur: m.paquet });
    modifierUnOctet(mutant, OCTET);
    const mut = await observer(mutant);
    expect(mut.startup).to.have.lengthOf(1);
    expect(mut.startup[0].code_sha256, "le mutant consigne encore une empreinte, qui n'est pas la publiée").to.match(/^0x[0-9a-f]{64}$/).and.to.not.equal(publiee);
    expect(mut.startup[0].image_match, "mutant : écart non relevé à startup").to.equal(true);
    expect(mut.ecarts, "mutant : l'image modifiée tourne sans signal").to.deep.equal([]);
  });

  // TA-29 et TA-75 (compléments de l'étape 8) : le démon réel et noortrace-ctl
  // contre un S3 à Object Lock en conteneur (image épinglée par condensé),
  // joués par test/fixtures/enregistreur-adversarial/supervision.mjs ; les
  // règles de CT-8 §10 sont jugées par l'évaluateur réduit des essais. Sans
  // Docker ou sans l'image, en attente (titre complété par la condition).
  async function supervisionWorm(ctx) {
    const o = await charger("test/fixtures/enregistreur-adversarial/supervision.mjs");
    const dispo = o.supportDisponible();
    if (!dispo.ok) {
      ctx.test.title += ` — en attente : ${dispo.condition}`;
      ctx.skip();
    }
    if (!supportWorm) {
      const d = path.join(base, "support-worm");
      fs.mkdirSync(d);
      supportWorm = await o.monterSupport(d, `noortrace-adversarial-s3-${process.pid}`);
    }
    return { ...o, decor: supportWorm };
  }

  it("TA-29 (MN-29, complément ; mutant du démon) : démon réel, support WORM fermé et segment fermé : noortrace_worm_copy_pending ≥ 1 après un tour du fil de supervision, la règle noortrace_copie_worm_en_retard se déclenche à l'échéance et pas avant ; support rouvert : jauge à 0 ; mutant sans la comparaison horaire du fil de supervision : jauge jamais écrite, aucune alerte (tué)", async function () {
    const { decor, demonSupportFerme, avecWorm, etatsAlerte, serieTenue, REGLES } = await supervisionWorm(this);
    const REGLE = "noortrace_copie_worm_en_retard";
    const ET = { __name__: "noortrace_worm_copy_pending", instance: "127.0.0.1:8500", job: "enregistreur", role: "active" };
    const MIN = 60000;
    expect(REGLES.find((r) => r.alert === REGLE)).to.include({ for: "1h" });
    /** Support fermé, segment fermé, un tour de supervision ; puis, si demandé, support rouvert jusqu'au retour de la jauge à 0. */
    const jouer29 = async (paquet, etiquette, rouvrir) => {
      await decor.support.rouvrir();
      const worm = await decor.worm(etiquette);
      const c = await configuration((cfg, env) => avecWorm(decor, worm, path.dirname(cfg.supervision.ops_log.path))(cfg, env), { segment_max_bytes: 6144 });
      const s = await demonSupportFerme(paquet, c, decor);
      try {
        const ferme = await s.enAttente();
        const controles = s.lignes().filter((l) => l.event === "integrity_check" && l.data.check === "configuration_worm").map((l) => l.data.ok);
        const echecs = s.lignes().filter((l) => l.event === "worm_copy_failed").map((l) => l.data.raison);
        let rouvert = null;
        if (rouvrir) {
          await s.rouvrir();
          await attendre(async () => (await s.enAttente()) === 0, 180000, 500);
          rouvert = await s.enAttente();
        }
        return { ferme, rouvert, segmentsFermes: s.segmentsFermes, controles, echecs };
      } finally {
        await s.arreter();
      }
    };
    const ref = await jouer29(REFERENCE, "ref", true);
    expect(ref.segmentsFermes).to.be.at.least(1);
    expect(ref.controles, "le fil de supervision a fait son tour, support fermé").to.include(false);
    expect(ref.echecs).to.include("injoignable");
    expect(ref.ferme, "noortrace_worm_copy_pending, support fermé").to.be.at.least(1);
    expect(ref.rouvert, "noortrace_worm_copy_pending, support rouvert").to.equal(0);
    // Horloge accélérée de la supervision : la valeur relevée support fermé tient 91 min, puis celle relevée après la réouverture.
    expect(etatsAlerte(REGLE, REGLES, serieTenue(ET, [ref.ferme, ref.rouvert], [91, 10]), [59 * MIN, 60 * MIN, 90 * MIN, 92 * MIN])).to.deep.equal([false, true, true, false]);
    // Mutant : le contrôle horaire du fil de supervision ne compare plus les fichiers fermés au registre des copies
    // (la reprise des copies en échec connues de l'instance, au même tour, reste en place).
    const m = mutantPaquet("mn29", [{ fichier: "worm/controles.mjs", ancien: 'const c = this.coeur;\n    await this.copies.balayer().catch((e) => this._echec("copie_worm", e, { balayage: "echec" }));', nouveau: "const c = this.coeur;" }]);
    const mut = await jouer29(m, "mut", false);
    expect(mut.segmentsFermes, "même attaque : un segment fermé sans copie").to.be.at.least(1);
    expect(mut.controles, "le fil de supervision du mutant a fait son tour, support fermé").to.include(false);
    expect(mut.ferme, "mutant : jauge jamais écrite").to.be.oneOf([null, 0]);
    expect(etatsAlerte(REGLE, REGLES, serieTenue(ET, [mut.ferme], [101]), [60 * MIN, 90 * MIN, 100 * MIN]), "mutant : aucune alerte").to.deep.equal([false, false, false]);
  });

  it("TA-75 (MN-75, complément ; mutant de la relecture hors du démon) : gel posé, une version passée à off hors de l'outil, règles du démon coupées : noortrace-ctl worm gel etat du Lecteur rend un code non nul, noortrace_releve_externe_ok{check=\"registre_gels\"} vaut 0, la règle critique d'EX-10.9 se déclenche ; mutant dont la relecture ne juge plus l'état relu : code 0, jauge à 1, aucune alerte (tué)", async function () {
    const { decor, gelSurveille, etatsAlerte, serieTenue, REGLES } = await supervisionWorm(this);
    const REGLE = "noortrace_releve_externe_echec";
    const ET = { __name__: "noortrace_releve_externe_ok", check: "registre_gels", instance: "127.0.0.1:9100", job: "hote", role: "hote" };
    const MIN = 60000;
    // L'attaquant de MN-75 coupe les règles dont la source est le démon ; celle de la relecture externe n'en est pas.
    const horsDemon = REGLES.filter((r) => r.labels.component !== "enregistreur");
    expect(REGLES.find((r) => r.alert === "noortrace_gel_non_pose").labels.component).to.equal("enregistreur");
    expect(horsDemon.find((r) => r.alert === REGLE).labels).to.include({ component: "exploitation", severity: "critique", exigence: "CT-8 EX-10.9" });
    const alerte = (jauge) => etatsAlerte(REGLE, horsDemon, serieTenue(ET, [jauge], [6]), [0, 3 * MIN]);
    const dir = path.join(base, "ta75");
    fs.mkdirSync(dir);
    const g = await gelSurveille(decor, dir);
    const version = (r) => JSON.parse(r.stdout.trim().split("\n").at(-1)).versions.find((v) => v.key === g.objet.key && v.version_id === g.objet.version_id);
    const m = mutantPaquet("mn75", [{ fichier: "worm/gel.mjs", ancien: 'if (attenduOn && etat !== "on") ecarts++;', nouveau: "if (false) ecarts++;" }]);
    // Gel intact : la relecture réussit, par la référence comme par le mutant.
    for (const [paquet, nom] of [[REFERENCE, "ref-intact"], [m, "mut-intact"]]) {
      const r = await g.relire(paquet, nom);
      expect(r.status, r.stderr).to.equal(0);
      expect(version(r), nom).to.include({ legal_hold: "on", attendu: "on" });
      expect(r.jauge, nom).to.equal(1);
      expect(alerte(r.jauge), nom).to.deep.equal([false, false]);
    }
    // Version passée à off hors de l'outil, par l'administrateur du client.
    expect(await g.passerOff()).to.equal(200);
    const etatRef = await g.etat(REFERENCE);
    expect(etatRef.status, "code de noortrace-ctl worm gel etat sous les identifiants du Lecteur").to.not.equal(0);
    expect(version(etatRef)).to.include({ legal_hold: "off", attendu: "on" });
    const ref = await g.relire(REFERENCE, "ref-off");
    // CT-8 EX-10.9 : la commande de référence « rend le code de la relecture » après avoir écrit les jauges.
    expect(ref.status, `sonde.mjs releve rend le code de la relecture (EX-10.9) ; ${ref.stderr}`).to.equal(etatRef.status);
    expect(version(ref)).to.include({ legal_hold: "off", attendu: "on" });
    expect(ref.jauge, "jauge après une relecture en échec").to.equal(0);
    expect(alerte(ref.jauge), "règle critique d'EX-10.9, règles du démon coupées").to.deep.equal([true, true]);
    // Mutant : la version off est relue, plus jugée ; hors du démon, rien ne s'allume.
    const etatMut = await g.etat(m);
    expect(version(etatMut), "le mutant relit la même version off").to.include({ legal_hold: "off", attendu: "on" });
    expect(etatMut.status, "mutant : code de noortrace-ctl worm gel etat").to.equal(0);
    const mut = await g.relire(m, "mut-off");
    expect(mut.status, mut.stderr).to.equal(0);
    expect(mut.jauge, "mutant : jauge").to.equal(1);
    expect(alerte(mut.jauge), "mutant : aucune alerte hors du démon").to.deep.equal([false, false]);
  });
});

// ---------------------------------------------------------------------------
// Composant d'ancrage de la phase 2 (étape 5) : mutants du paquet
// @noortrace/ancrage (CT-9 EX-10.5), importés par leur chemin de fichier et
// montés sur le décor des essais du composant (horloge réglable, autorités
// RFC 3161 internes, le principal et le secours en TLS mutuel). Sans openssl
// pour le matériel TLS du décor, en attente (titre complété par la condition).
// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux TA- exécutables sur le composant d'ancrage de l'étape 5 (mutants du paquet @noortrace/ancrage, CT-7 EX-3.2)", function () {
  this.timeout(600_000);
  const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
  let base;
  let REFERENCE_ANCRAGE, mutantPaquetAncrage, detruireMutantsAncrage, monterAncrage, texteDesFichiers, texteAvecOctets;
  const charger = (rel) => import(pathToFileURL(path.join(RACINE, rel)).href);

  before(async function () {
    ({ REFERENCE_ANCRAGE, mutantPaquetAncrage, detruireMutantsAncrage, monterAncrage, texteDesFichiers, texteAvecOctets } = await charger("test/fixtures/enregistreur-adversarial/ancrage.mjs"));
    base = fs.mkdtempSync(path.join(TMP, "noortrace-adversarial-ancrage-"));
  });

  after(function () {
    detruireMutantsAncrage?.();
    if (base) fs.rmSync(base, { recursive: true, force: true });
  });

  function enAttente(ctx, condition) {
    ctx.test.title += ` — en attente : ${condition}`;
    ctx.skip();
  }

  it("TA-62 (MN-62, complément ; mutant du composant d'ancrage) : composant réel, principal injoignable à la clôture : la demande du jeton de la période est relevée par le secours à manifest.fallback_after_s et pas avant (anchor_fallback consigné, raison delai), le jeton du secours est obtenu ; mutant sans la relève par délai : aucune relève, aucune requête au secours, aucun jeton (tué)", async function () {
    const jouer = async (paquet, nom) => {
      const x = await monterAncrage(paquet, { dir: path.join(base, nom), periode: PERIODE });
      if (x.condition) return x;
      try {
        x.m.transport.pannes.add(x.m.principal.prestataire.url);
        await x.jouerPeriode();
        await x.m.horloge.avancer(290000, x.calme);
        const d0 = x.jetonPeriode();
        const avant = { releves: x.m.journal.de("anchor_fallback").length, etat: d0.state, prestataires: [...new Set(d0.attempts.map((a) => a.provider))] };
        await x.m.horloge.avancer(40000, x.calme);
        const d = x.jetonPeriode();
        const file = texteDesFichiers(x.m.configuration.queue.path).flatMap((f) => f.texte.split("\n").filter(Boolean).map((l) => JSON.parse(l))).filter((l) => l.id === d.id);
        return {
          condition: null,
          avant,
          releves: x.m.journal.de("anchor_fallback").map((l) => ({ level: l.level, component: l.component, to: l.data.to, reason: l.data.reason, request_id: l.data.request_id })),
          id: d.id,
          etat: d.state,
          obtenuDe: d.result?.provider ?? null,
          prestataires: [...new Set(d.attempts.map((a) => a.provider))],
          transitoires: d.attempts.filter((a) => a.provider === "qtsa-principal" && a.outcome === "echec_transitoire").length,
          reprises: x.m.journal.de("anchor_retry").length,
          defauts: x.m.journal.lignes.filter((l) => l.event === "anchoring_supervision_failed" || (l.event === "anchor_response_rejected" && l.data.error_code === "entree_refusee")).length,
          etatsEnFile: file.map((l) => l.state),
          demarre: x.composant.etat().demarre && !x.composant.etat().arrete,
        };
      } finally {
        await x.fermer();
      }
    };
    const ref = await jouer(REFERENCE_ANCRAGE, "ta62-ref");
    if (ref.condition) return enAttente(this, ref.condition);
    // Avant l'échéance de relève : le principal seul, en échec transitoire, aucune relève.
    expect(ref.avant).to.deep.equal({ releves: 0, etat: ref.avant.etat, prestataires: ["qtsa-principal"] });
    expect(ref.avant.etat).to.be.oneOf(["a_reprendre", "envoyee"]);
    // À l'échéance : relève consignée, jeton du secours obtenu, file durable à jour.
    expect(ref.releves).to.deep.equal([{ level: "warning", component: "ancrage", to: "qtsa-secours", reason: "delai", request_id: ref.id }]);
    expect(ref.etat).to.equal("obtenue");
    expect(ref.obtenuDe).to.equal("qtsa-secours");
    expect(ref.prestataires).to.deep.equal(["qtsa-principal", "qtsa-secours"]);
    expect(ref.etatsEnFile.at(-1), "dernière ligne de la demande dans la file durable").to.equal("obtenue");
    expect(ref.defauts).to.equal(0);
    const m = mutantPaquetAncrage("mn62-composant", [{ fichier: "planificateur/planificateur.mjs", ancien: "this.releverParDelai(req);", nouveau: ";" }]);
    const mut = await jouer(m, "ta62-mut");
    // Le mutant vit et reprend chez le principal (aucune exception avant l'oracle) ; la relève n'a pas lieu.
    expect(mut.demarre, "mutant : composant en marche").to.equal(true);
    expect(mut.defauts, "mutant : aucune entrée refusée ni défaut de supervision").to.equal(0);
    expect(mut.avant).to.deep.equal(ref.avant);
    expect(mut.transitoires, "mutant : tentatives transitoires chez le principal").to.be.at.least(2);
    expect(mut.reprises, "mutant : reprises consignées").to.be.at.least(1);
    expect(mut.releves, "mutant : aucune relève consignée").to.deep.equal([]);
    expect(mut.prestataires, "mutant : aucune requête au secours").to.deep.equal(["qtsa-principal"]);
    expect(mut.obtenuDe, "mutant : aucun jeton").to.equal(null);
    expect(mut.etat, "mutant : la demande reste sans jeton").to.not.equal("obtenue");
    expect(mut.etatsEnFile, "mutant : la file ne porte aucune ligne obtenue").to.not.include("obtenue");
  });

  it("TA-41 (MN-41, complément ; mutants du composant d'ancrage) : secret du principal à valeur résolue marquée, jeton obtenu en TLS mutuel : marqueur absent des fichiers, du journal et des métriques, seule la référence dans la configuration en vigueur ; mutant sans la copie privée du prestataire résolu : la valeur y remplace la référence ; mutant dont le journal d'acquisition recopie la valeur (tués)", async function () {
    const MARQUEUR = "MARQUEUR-TA-41-9d3f6a1c0b7e4528";
    const REFERENCE_SECRET = { file: "/run/secrets/qtsa-principal-client.pem" };
    const jouer = async (paquet, nom) => {
      const x = await monterAncrage(paquet, { dir: path.join(base, nom), periode: PERIODE, secret: (pem) => new Uint8Array(Buffer.concat([Buffer.from(`${MARQUEUR}\n`, "utf8"), Buffer.from(pem)])) });
      if (x.condition) return x;
      try {
        const resolu = Buffer.from(x.m.secrets.get("/rfc3161/providers/0/auth/secret")).toString("latin1");
        await x.jouerPeriode();
        await x.m.horloge.avancer(2000, x.calme);
        const d = x.jetonPeriode();
        const fichiers = [...texteDesFichiers(x.m.contexte.racineStockage), ...texteDesFichiers(x.m.configuration.queue.path)];
        const journal = JSON.stringify(x.m.journal.lignes);
        const textes = [...fichiers.map((f) => [path.basename(f.fichier), f.texte]), ["journal", journal], ["metriques", x.composant.metriques()]];
        const enVigueur = x.composant.configuration.rfc3161.providers.find((p) => p.id === "qtsa-principal").auth.secret;
        return {
          condition: null,
          controle: { marqueurDansLaValeurResolue: resolu.includes(MARQUEUR), clePriveeDansLaValeurResolue: resolu.includes("PRIVATE KEY") },
          etat: d.state,
          obtenuDe: d.result?.provider ?? null,
          fichiers: fichiers.map((f) => path.basename(f.fichier)),
          traces: x.m.journal.lignes.filter((l) => l.event.startsWith("planificateur_")).length,
          fuites: textes.filter(([, t]) => t.includes(MARQUEUR) || t.includes("PRIVATE KEY")).map(([ou]) => ou),
          secretEnVigueur: enVigueur instanceof Uint8Array ? "octets" : enVigueur,
          marqueurEnVigueur: texteAvecOctets(x.composant.configuration).includes(MARQUEUR),
          defauts: x.m.journal.lignes.filter((l) => l.event === "anchoring_supervision_failed" || (l.event === "anchor_response_rejected" && l.data.error_code === "entree_refusee")).length,
        };
      } finally {
        await x.fermer();
      }
    };
    const ref = await jouer(REFERENCE_ANCRAGE, "ta41-ref");
    if (ref.condition) return enAttente(this, ref.condition);
    // Contrôles positifs : le marqueur est dans la valeur résolue, la requête authentifiée est partie et a abouti, les fichiers lus existent.
    expect(ref.controle).to.deep.equal({ marqueurDansLaValeurResolue: true, clePriveeDansLaValeurResolue: true });
    expect({ etat: ref.etat, obtenuDe: ref.obtenuDe }).to.deep.equal({ etat: "obtenue", obtenuDe: "qtsa-principal" });
    expect(ref.fichiers).to.include("acquisitions.ndjson");
    expect(ref.fichiers.some((f) => /^file-[0-9]+\.ndjson$/.test(f)), ref.fichiers.join(" ")).to.equal(true);
    expect(ref.traces).to.be.at.least(1);
    // Oracle : la valeur n'est nulle part, seule la référence figure dans la configuration en vigueur.
    expect(ref.fuites).to.deep.equal([]);
    expect(ref.secretEnVigueur).to.deep.equal(REFERENCE_SECRET);
    expect(ref.marqueurEnVigueur).to.equal(false);
    const m = mutantPaquetAncrage("mn41-copie", [{ fichier: "composant.mjs", ancien: "const p = structuredClone(brut);", nouveau: "const p = brut;" }]);
    const mut = await jouer(m, "ta41-mut");
    // Le mutant sert comme la référence (jeton du principal obtenu, aucun défaut) ; la valeur résolue a pris la place de la référence.
    expect(mut.defauts, "mutant : aucune entrée refusée ni défaut de supervision").to.equal(0);
    expect({ etat: mut.etat, obtenuDe: mut.obtenuDe }, "mutant : jeton du principal obtenu").to.deep.equal({ etat: "obtenue", obtenuDe: "qtsa-principal" });
    expect(mut.secretEnVigueur, "mutant : la configuration en vigueur ne porte plus la référence").to.not.deep.equal(REFERENCE_SECRET);
    expect(mut.marqueurEnVigueur, "mutant : le marqueur apparaît dans la configuration en vigueur").to.equal(true);
    // Second mutant, de la forme que le catalogue prescrit (CT-9, TA-41, pas 4) : la journalisation recopie la valeur résolue ;
    // ici le journal d'acquisition, qui écrit la valeur du secret d'accès à la place de l'identifiant du prestataire.
    const m2 = mutantPaquetAncrage("mn41-journal", [{ fichier: "rfc3161/acquisition.mjs", ancien: "provider_id: prestataire.id,", nouveau: 'provider_id: Buffer.from(prestataire.auth?.secret ?? prestataire.id).toString("latin1"),' }]);
    const mut2 = await jouer(m2, "ta41-mut2");
    expect(mut2.defauts, "second mutant : aucune entrée refusée ni défaut de supervision").to.equal(0);
    expect({ etat: mut2.etat, obtenuDe: mut2.obtenuDe }, "second mutant : jeton du principal obtenu").to.deep.equal({ etat: "obtenue", obtenuDe: "qtsa-principal" });
    expect(mut2.secretEnVigueur, "second mutant : la configuration en vigueur garde la référence").to.deep.equal(REFERENCE_SECRET);
    expect(mut2.fuites, "second mutant : le marqueur apparaît dans le journal d'acquisition").to.deep.equal(["acquisitions.ndjson"]);
  });
});

// ---------------------------------------------------------------------------
// Tests adversariaux joués sur la démonstration de référence (CT-2 §19) :
// composition `demo/compose.yaml` lancée sous un projet propre à l'essai.
// La réponse retirée est une règle de la composition (réseau, volume), le
// mode de capture du démon, ou l'exécution du rapprochement : le mutant est
// une copie d'un fichier de `demo/` où un remplacement exact et unique est
// appliqué (`mutantDeDemo`), jamais un fichier du dépôt. En attente,
// condition nommée, sans démon Docker ou sans les images de la
// démonstration dans le magasin local.
// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux TA- joués sur la démonstration de référence (composition docker compose de CT-2 §19, CT-7 EX-3.2)", function () {
  this.timeout(900_000);
  let D = null;
  let ctx = null;
  let c = null;
  let travail = null;
  const CONFIG_DEMO = lireJSON(RACINE, "demo", "configuration-demo.json");

  before(async function () {
    D = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "demonstration", "outils.mjs")).href);
    const etat = D.etatDocker();
    if (!etat.ok) {
      ctx = { condition: etat.condition };
      return;
    }
    travail = fs.mkdtempSync(path.join(TMP, "noortrace-ta-demonstration-"));
    c = new D.Composition({ nom: `noortrace-demo-ta-${process.pid}`, port: await D.portLibre() });
    c.lancer();
    const code = c.attendre("verificateur", 300000);
    ctx = { code, sortie: c.journal("verificateur") };
  });

  after(function () {
    if (c) c.demonter();
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      D.enAttente(this, ctx?.condition ?? "composition non lancée");
      return false;
    }
    expect(ctx.code, ctx.sortie).to.equal(0);
    return true;
  }

  /** Compteur des `tools/call` reçus par le serveur d'outils, lu depuis son propre réseau. */
  const appelsOutils = () => JSON.parse(c.executer("outils-demo", 'fetch("http://outils-demo:8000/sante").then((r)=>r.text()).then((t)=>console.log(t))').stdout.trim().split("\n").at(-1)).appels;
  /** Adresse IPv4 d'un service sur un réseau du projet. */
  const adresseDe = (service, reseau) => c.inspecter(service).NetworkSettings.Networks[c.ressource(reseau)].IPAddress;

  it("TA-1 (MN-1) : dans la démonstration de référence, le conteneur de l'agent tente une connexion TCP directe au serveur d'outils, par son nom puis par son adresse : code non nul, aucun paquet ne quitte le conteneur, tentative datée au journal du conteneur, aucun appel reçu ni événement ; composition mutante où agent-demo est aussi sur le réseau outils : la connexion aboutit sans événement (tué)", function () {
    if (!pret.call(this)) return;
    const ip = adresseDe("outils-demo", "outils");
    // L'attaque : connexion TCP au port du serveur d'outils, par le nom du service puis par son adresse ; code 0 si l'une aboutit.
    const attaque = `
      const net = require("net");
      const tenter = (host) => new Promise((r) => { const s = net.connect({ host, port: 8000 }); const fin = (x) => { s.destroy(); r(x); }; s.setTimeout(3000, () => fin("delai")); s.once("connect", () => fin("etablie")); s.once("error", (e) => fin(e.code)); });
      (async () => {
        const constats = { nom: await tenter("outils-demo"), adresse: await tenter(${JSON.stringify(ip)}) };
        let outil = null;
        if (constats.adresse === "etablie") {
          const r = await fetch("http://${ip}:8000/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "claims.get", arguments: { claim_id: "2026-81044" } } }) });
          outil = (await r.json()).result?.isError === false;
        }
        console.log(JSON.stringify({ ...constats, outil }));
        process.exit(Object.values(constats).includes("etablie") ? 0 : 1);
      })();`;
    const evenementsAvant = c.evenements(CONFIG_DEMO).length;
    const appelsAvant = appelsOutils();
    const reference = c.executer("agent-demo", attaque);
    // Avec la règle : la connexion échoue (code non nul). Le réseau des hôtes est interne : le conteneur de l'agent n'a ni
    // résolution du nom, ni route vers le réseau des outils ; aucun paquet n'atteint le pare-feu de l'hôte, qui n'a donc rien à journaliser.
    expect(reference.code, reference.stdout + reference.stderr).to.equal(1);
    const constats = JSON.parse(reference.stdout.trim().split("\n").at(-1));
    expect(constats.nom).to.be.oneOf(["ENOTFOUND", "EAI_AGAIN"]);
    expect(constats.adresse).to.be.oneOf(["ENETUNREACH", "EHOSTUNREACH", "delai"]);
    expect(constats.outil).to.equal(null);
    expect(Object.keys(c.inspecter("agent-demo").NetworkSettings.Networks)).to.deep.equal([c.ressource("hotes")]);
    expect(JSON.parse(D.docker(["network", "inspect", c.ressource("hotes")]).stdout)[0].Internal).to.equal(true);
    // La tentative que l'agent de la démonstration fait lui-même est consignée, datée, au journal de son conteneur.
    const lignes = D.docker(["logs", "--timestamps", c.conteneur("agent-demo")]).stdout.split("\n").filter((l) => l.includes("connexion directe, sans l'enregistreur"));
    expect(lignes).to.have.lengthOf(1);
    expect(lignes[0]).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z agent-demo : connexion directe, sans l'enregistreur : outils-demo:8000 injoignable \([A-Z_]+\) ; modele-demo:8080 injoignable \([A-Z_]+\)$/);
    // Le serveur d'outils n'a rien reçu et le journal ne porte aucun événement de plus.
    expect(appelsOutils()).to.equal(appelsAvant);
    expect(c.evenements(CONFIG_DEMO).length).to.equal(evenementsAvant);
    // Mutant : la règle de réseau qui isole l'agent du réseau des serveurs d'outils est retirée de la composition.
    const mutant = D.mutantDeDemo(travail, "compose.yaml", "      ANTHROPIC_API_KEY: cle-factice-agent-demo\n    networks:\n      - hotes\n", "      ANTHROPIC_API_KEY: cle-factice-agent-demo\n    networks:\n      - hotes\n      - outils\n");
    const mut = c.executer("agent-demo", attaque, { fichier: mutant });
    expect(mut.code, mut.stdout + mut.stderr).to.equal(0);
    expect(JSON.parse(mut.stdout.trim().split("\n").at(-1))).to.deep.equal({ nom: "etablie", adresse: "etablie", outil: true });
    expect(appelsOutils()).to.equal(appelsAvant + 1);
    expect(c.evenements(CONFIG_DEMO).length).to.equal(evenementsAvant);
  });

  it("TA-22 (MN-22) : dans la démonstration de référence, le conteneur de l'agent liste storage.root : code de retour non nul, le chemin n'existe pas ; composition mutante où le volume du journal est monté dans le conteneur de l'agent : le chemin existe (sous le compte de l'agent, le mode 0700 du démon refuse encore le listage ; sous le compte du démon, le listage réussit et un segment s'ouvre) (tué)", function () {
    if (!pret.call(this)) return;
    const racine = CONFIG_DEMO.storage.root;
    const journal = `${racine}/${CONFIG_DEMO.recorder.org_id.slice(2)}/${CONFIG_DEMO.recorder.journal_id.slice(2)}`;
    // L'attaque : lister storage.root et ouvrir un segment ; code 0 si le listage réussit.
    const attaque = `
      const fs = require("fs");
      const r = { existe: fs.existsSync(${JSON.stringify(racine)}), liste: null, erreur: null, segment: null };
      try {
        r.liste = fs.readdirSync(${JSON.stringify(racine)}).length;
        const segments = ${JSON.stringify(journal)} + "/segments";
        r.segment = fs.readFileSync(segments + "/" + fs.readdirSync(segments).sort()[0], "utf8").split("\\n")[0].includes("noortrace_segment");
      } catch (e) { r.erreur = e.code; }
      console.log(JSON.stringify(r));
      process.exit(r.liste === null ? 1 : 0);`;
    const reference = c.executer("agent-demo", attaque);
    expect(reference.code, reference.stdout + reference.stderr).to.equal(1);
    expect(JSON.parse(reference.stdout.trim().split("\n").at(-1))).to.deep.equal({ existe: false, liste: null, erreur: "ENOENT", segment: null });
    // Mutant : le volume du journal est monté dans le conteneur de l'agent.
    const mutant = D.mutantDeDemo(travail, "compose.yaml", "      ANTHROPIC_API_KEY: cle-factice-agent-demo\n    networks:\n      - hotes\n", `      ANTHROPIC_API_KEY: cle-factice-agent-demo\n    volumes:\n      - type: volume\n        source: journal\n        target: ${racine}\n    networks:\n      - hotes\n`);
    const mut = c.executer("agent-demo", attaque, { fichier: mutant });
    const vu = JSON.parse(mut.stdout.trim().split("\n").at(-1));
    expect(vu.existe, mut.stdout + mut.stderr).to.equal(true);
    // Seconde barrière, que le mutant ne retire pas : storage.root est au compte du démon, en 0700.
    expect([mut.code, vu.liste, vu.erreur]).to.deep.equal([1, null, "EACCES"]);
    const sousLeCompteDuDemon = c.dc(["run", "--rm", "--no-deps", "-T", "--user", c.inspecter("enregistreur").Config.User, "--entrypoint", "/usr/local/bin/node", "agent-demo", "-e", attaque], { fichier: mutant });
    expect(sousLeCompteDuDemon.status, sousLeCompteDuDemon.stdout + sousLeCompteDuDemon.stderr).to.equal(0);
    expect(JSON.parse(sousLeCompteDuDemon.stdout.trim().split("\n").at(-1))).to.deep.include({ existe: true, erreur: null, segment: true });
  });

  it("TA-14 (MN-14, partie sur la démonstration de référence) : la ligne startup du démon de la démonstration dit model_mode passerelle, et l'attestation de périmètre de la démonstration déclare le canal passerelle pour agent-demo ; démon lancé avec la même configuration en mode miroir : sa ligne startup dit miroir, canal que l'attestation ne déclare pas (tué)", async function () {
    if (!pret.call(this)) return;
    const attestation = lireJSON(RACINE, "demo", "attestation-perimetre-demo.json");
    const canaux = attestation.agents.find((a) => a.agent_id === "agent-demo").capture_channels;
    /** Oracle : le mode de capture consigné au démarrage est un canal que l'attestation déclare. */
    const oracle = (ligne) => ({ mode: ligne.data.model_mode, declare: canaux.includes(ligne.data.model_mode) });
    const reference = c.journalExploitation().find((l) => l.event === "startup");
    expect(oracle(reference)).to.deep.equal({ mode: "passerelle", declare: true });
    expect(canaux).to.include("passerelle");
    // Mutant : la même configuration, lancée dans un autre mode que passerelle (deux remplacements exacts).
    let texte = fs.readFileSync(path.join(RACINE, "demo", "configuration-demo.json"), "utf8");
    for (const [ancien, nouveau] of [['"mode": "passerelle"', '"mode": "miroir"'], ['"mirror": null', '"mirror": { "socket": "/run/noortrace/miroir.sock" }']]) {
      expect(texte.split(ancien).length - 1, ancien).to.equal(1);
      texte = texte.replace(ancien, () => nouveau);
    }
    const configMutante = path.join(travail, "configuration-miroir.json");
    fs.writeFileSync(configMutante, texte, { mode: 0o644 });
    const E = c.inspecter("enregistreur");
    const nom = `noortrace-ta14-${process.pid}`;
    const args = ["run", "--detach", "--rm", "--name", nom, "--network", "none", "--user", E.Config.User, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
      "--tmpfs", "/run/temporaire:mode=1777", "--tmpfs", "/var/lib/noortrace:uid=10001,gid=10001,mode=0700", "--tmpfs", "/var/log/noortrace:uid=10001,gid=10001,mode=0750", "--tmpfs", "/run/noortrace:uid=10001,gid=10001,mode=0700",
      "-v", `${configMutante}:/etc/noortrace/configuration.json:ro`];
    for (const f of ["ancrage-demo.json:/etc/noortrace/ancrage.json", "instance-registre.json:/etc/noortrace/instance-registre.json", "cle-rec-test-01.pem:/etc/noortrace/cles/rec-test-01.pem"]) args.push("-v", `${path.join(RACINE, "demo", f.split(":")[0])}:${f.split(":")[1]}:ro`);
    for (const v of E.Config.Env.filter((x) => /^(NOORTRACE_DEMO_|TMPDIR=)/.test(x))) args.push("-e", v);
    const lance = D.docker([...args, E.Config.Image, "--config", "/etc/noortrace/configuration.json"]);
    expect(lance.status, lance.stderr).to.equal(0);
    let mutant = null;
    try {
      for (let k = 0; k < 60 && !mutant; k++) {
        const r = D.docker(["exec", nom, "/usr/local/bin/node", "-e", 'const fs=require("fs");try{process.stdout.write(fs.readFileSync("/var/log/noortrace/exploitation.ndjson","utf8"))}catch{}']);
        mutant = r.stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.event === "startup") ?? null;
        if (!mutant) await D.pause(500);
      }
    } finally {
      D.docker(["rm", "-f", nom]);
    }
    expect(mutant, "ligne startup du démon mutant absente").to.not.equal(null);
    expect(oracle(mutant)).to.deep.equal({ mode: "miroir", declare: false });
  });

  it("TA-18 (MN-18) : sur la démonstration de référence, le rapprochement de CT-7 EX-3.8 compare le relevé d'usage du simulateur au journal : trois requêtes, trois échanges, aucun écart ; après un échange envoyé au simulateur avec la clé de la passerelle, hors de l'enregistreur : écart de 1 rapporté (clé, route), code 3 ; outil mutant sans la comparaison : aucun écart rapporté (tué)", function () {
    if (!pret.call(this)) return;
    const env = Object.fromEntries(c.inspecter("enregistreur").Config.Env.map((x) => [x.slice(0, x.indexOf("=")), x.slice(x.indexOf("=") + 1)]));
    const cle = env.NOORTRACE_DEMO_CLE_MODELE;
    const segments = () => {
      const d = fs.mkdtempSync(path.join(travail, "segments-"));
      return c.extraire("journal", `${CONFIG_DEMO.recorder.org_id.slice(2)}/${CONFIG_DEMO.recorder.journal_id.slice(2)}/segments`, d);
    };
    const releve = (nom) => {
      const r = c.executer("modele-demo", 'fetch("http://modele-demo:8080/demo/usage").then((r)=>r.text()).then((t)=>console.log(t))');
      expect(r.code, r.stderr).to.equal(0);
      const f = path.join(travail, nom);
      fs.writeFileSync(f, r.stdout.trim().split("\n").at(-1));
      return f;
    };
    const rapprocher = (outil, fichierReleve, rep) => {
      const r = spawnSync(process.execPath, [outil, "--configuration", path.join(RACINE, "demo", "configuration-demo.json"), "--segments", rep, "--usage", fichierReleve, "--json"], { encoding: "utf8", env: { ...process.env, NOORTRACE_DEMO_CLE_MODELE: cle } });
      return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
    };
    const OUTIL = path.join(RACINE, "demo", "rapprochement.mjs");
    const empreinte = D.empreinteCle(cle);
    // Séquence de 19.2 jouée : n événements d'échange et n requêtes.
    const avant = rapprocher(OUTIL, releve("usage-avant.json"), segments());
    expect(avant.code, avant.stderr).to.equal(0);
    expect(avant.rapport).to.deep.equal({ version: 0, lignes: [{ key_sha256_16: empreinte, route: "/v1/messages", provider_label: "demo", declared: 3, journaled: 3, gap: 0 }], incident: false });
    // L'attaque : un échange de modèle envoyé au simulateur avec la clé de la passerelle, hors de l'enregistreur.
    const directe = c.executer("modele-demo", `fetch("http://modele-demo:8080/v1/messages",{method:"POST",headers:{"content-type":"application/json","anthropic-version":"2023-06-01","x-api-key":${JSON.stringify(cle)}},body:JSON.stringify({model:"modele-demo-1",max_tokens:16,messages:[{role:"user",content:"Traite le sinistre 2026-81044."}]})}).then((r)=>{console.log(r.status);process.exit(r.status===200?0:1)})`);
    expect(directe.code, directe.stdout + directe.stderr).to.equal(0);
    const rep = segments();
    const fichierReleve = releve("usage-apres.json");
    // Rien d'autre que le rapprochement ne le voit : le journal n'a aucun événement de plus, le démon reste sain.
    expect(c.evenements(CONFIG_DEMO).filter((e) => e.execution.tool === "noortrace.modele.echange")).to.have.lengthOf(3);
    expect(D.docker(["inspect", "--format", "{{.State.Health.Status}}", c.conteneur("enregistreur")]).stdout.trim()).to.equal("healthy");
    const apres = rapprocher(OUTIL, fichierReleve, rep);
    expect(apres.code, apres.stderr).to.equal(3);
    expect(apres.rapport).to.deep.equal({ version: 0, lignes: [{ key_sha256_16: empreinte, route: "/v1/messages", provider_label: "demo", declared: 4, journaled: 3, gap: 1 }], incident: true });
    expect(JSON.stringify(apres.rapport)).to.not.include(cle);
    // Mutant : le rapprochement n'est plus exécuté (l'écart n'est plus calculé).
    const mutant = D.mutantDeDemo(travail, "rapprochement.mjs", "gap: declarees - journalisees };", "gap: 0 };");
    const mut = rapprocher(mutant, fichierReleve, rep);
    expect(mut.code, mut.stderr).to.equal(0);
    expect(mut.rapport.lignes[0]).to.deep.include({ declared: 4, journaled: 3, gap: 0 });
    expect(mut.rapport.incident).to.equal(false);
  });
});
// ---------------------------------------------------------------------------
// Étape 8 (S-5 d) : second mutant des TA-44, TA-47, TA-48,
// TA-49 et TA-50 sur le PAQUET LIVRÉ `paquets/approbation` (service
// d'approbation), au point de la réponse correspondante ; oracle : les mêmes
// vecteurs figés que la référence. Les copies mutées du paquet sont faites par
// `test/fixtures/approbation-service/mutants.mjs` (copie sous NOORTRACE_TMP,
// node_modules du dépôt lié, remplacement exact et unique, détruites à la fin) ;
// `copiePaquet` est chargé depuis RACINE, comme le reste du fichier
// (NOORTRACE_RACINE compris).
// TA-45 (vérification de la réponse du portefeuille) et TA-46 (découverte des
// fournisseurs) n'ont aucun point dans le service : leurs réponses livrées sont
// dans `paquets/console`.
describe("CT-9 : TA-44 à TA-50 sur le paquet livré paquets/approbation (étape 8)", function () {
  this.timeout(600_000);
  const CT3 = path.join(VECTEURS, "ct-3");
  const COPIES = [];
  after(function () {
    for (const c of COPIES) c.detruire();
  });
  const paquetMutant = async (nom, remplacements, o) => {
    const { copiePaquet } = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "approbation-service", "mutants.mjs")).href);
    const c = copiePaquet(nom, remplacements, o);
    COPIES.push(c);
    return c;
  };
  const livre = (rel) => import(pathToFileURL(path.join(RACINE, "paquets", "approbation", "src", rel)).href);
  const remises = () => ["valides", "invalides"].flatMap((rep) => fs.readdirSync(path.join(CT3, "decisions", rep)).filter((f) => f.endsWith(".json")).sort().map((f) => lireJSON(CT3, "decisions", rep, f)));
  const trace = (nom) => lireJSON(CT3, "tickets", `${nom}.json`);
  /** Rejeu d'une trace de l'annexe A.6 sur la machine du paquet (même procédé que approbation-service-vecteurs) ; pas divergents, 1-indexés. */
  // Versions chargées comme le service les garde après le `charger` d'une trace (CT-3 annexe A.6 : approval de trace,
  // policy_sha256 synthétique, approval_sha256 calculé), pour que chaque réponse `evaluer` porte les neuf membres des
  // vecteurs ; données construites par la fixture du service, machine prise dans le paquet (livré ou muté).
  let F;
  before(async function () {
    F = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "approbation-service", "outils.mjs")).href);
  });
  const ecartsTraceService = (M, t) => {
    const m = new M.Machine({ org_id: t.org_id, journal_id: t.journal_id, identifiants: { mode: "compteur" }, max_open_tickets: t.service.max_open_tickets, escalation: t.service.escalation, administrators: t.service.administrators });
    const { version } = F.machineDeTrace(t);
    m.ajouterVersion(version(t.policy_version));
    m.fixerEnVigueur(t.policy_version);
    const ecarts = [];
    t.steps.forEach((s, k) => {
      if (s.input.kind === "charger" && !m.version(s.input.data.policy_version)) m.ajouterVersion(version(s.input.data.policy_version));
      const r = m.entree(s.input, { evaluation: s.input.kind === "evaluer" ? s.input.data.evaluation : undefined });
      const obtenu = { tickets: m.etats(), accepted: r.accepted, reason: r.reason, response: r.response, remises: r.remises, windows: m.copieFenetres() };
      if (!egal(obtenu, s.expected)) ecarts.push(k + 1);
    });
    return ecarts;
  };

  it("TA-44 (MN-44, paquet livré) : verifierRemise du service refuse SG-5 et SG-6 sur decisions/ ; mutants du service sans SG-5 ou sans SG-6 : au moins une remise diverge (tués)", async function () {
    const S0 = await livre("signatures.mjs");
    const cibles = remises().filter((c) => ["signature_invalide", "approbateur_hors_jeu"].includes(c.expected.reason));
    expect(cibles.length).to.be.at.least(2);
    for (const c of cibles) {
      const r = S0.verifierRemise(c.remise, c.context);
      expect({ result: r.result, reason: r.reason }, c.id).to.deep.equal(c.expected);
    }
    const m5 = await paquetMutant("ta44-sg5", [{ fichier: "src/signatures.mjs", ancien: 'if (adresseDuVote(champs, a.signatures[i]) !== a.approvers[i]) return non("SG-5", "signature_invalide");', nouveau: "if (false) return null;" }]);
    const m6 = await paquetMutant("ta44-sg6", [{ fichier: "src/signatures.mjs", ancien: 'if (!a.approvers.every((x) => jeu.members.includes(x))) return non("SG-6", "approbateur_hors_jeu");', nouveau: "if (false) return null;" }]);
    for (const [m, raison] of [[m5, "signature_invalide"], [m6, "approbateur_hors_jeu"]]) {
      const S1 = await m.importer("src/signatures.mjs");
      const divergents = cibles.filter((c) => c.expected.reason === raison).filter((c) => {
        const r = S1.verifierRemise(c.remise, c.context);
        return !egal({ result: r.result, reason: r.reason }, c.expected);
      });
      expect(divergents.length, `mutant du service sans ${raison}`).to.be.at.least(1);
    }
  });

  it("TA-48 (MN-48, paquet livré) : sg7-auto-approbation refusée par SG-7 du service ; mutant du service sans SG-7 : scellée (tué)", async function () {
    const c = remises().find((x) => x.id === "sg7-auto-approbation");
    const S0 = await livre("signatures.mjs");
    const r0 = S0.verifierRemise(c.remise, c.context);
    expect([r0.result, r0.reason, r0.check]).to.deep.equal(["refuse", "auto_approbation", "SG-7"]);
    const m = await paquetMutant("ta48", [{ fichier: "src/signatures.mjs", ancien: 'if (id && a.approvers.some((x) => id.addresses.includes(x))) return non("SG-7", "auto_approbation");', nouveau: "if (false) return null;" }]);
    const S1 = await m.importer("src/signatures.mjs");
    expect(S1.verifierRemise(c.remise, c.context).result).to.equal("scelle");
  });

  it("TA-49 (MN-49, paquet livré) : normaliserSignature du service refuse chaque forme refusée de signatures/normalisation.json ; mutant qui délègue ces contrôles : au moins quatre formes refusées sont normalisées (tué)", async function () {
    const doc = lireJSON(CT3, "signatures", "normalisation.json");
    const refusees = doc.cases.filter((c) => c.expected === null);
    expect(refusees.length).to.be.at.least(5);
    const S0 = await livre("signatures.mjs");
    for (const c of refusees) expect(S0.normaliserSignature(c.signature), c.id).to.equal(null);
    const m = await paquetMutant("ta49", [
      { fichier: "src/signatures.mjs", ancien: "if (r < 1n || r >= N_SECP256K1 || s < 1n || s >= N_SECP256K1) return null;", nouveau: "if (false) return null;" },
      { fichier: "src/signatures.mjs", ancien: "if (v !== 27 && v !== 28) return null;", nouveau: "if (false) return null;" },
    ]);
    const S1 = await m.importer("src/signatures.mjs");
    const passees = refusees.filter((c) => S1.normaliserSignature(c.signature) !== null).map((c) => c.id);
    expect(passees.length, "formes refusées acceptées par le mutant du service").to.be.at.least(4);
  });

  it("TA-50 (MN-50, paquet livré) : tickets/jeu-seuil-abaisse.json rejouée sur la machine du service sans écart ; mutant du service qui suit la baisse du seuil : la trace diverge aux pas 6 et 8 (tué)", async function () {
    const M0 = await livre("tickets.mjs");
    expect(ecartsTraceService(M0, trace("jeu-seuil-abaisse")), "paquet livré").to.deep.equal([]);
    const m = await paquetMutant("ta50", [{ fichier: "src/tickets.mjs", ancien: "t.effective_required = Math.max(t.effective_required ?? 0, jeu.threshold.required);", nouveau: "t.effective_required = jeu.threshold.required;" }]);
    const M1 = await m.importer("src/tickets.mjs");
    expect(ecartsTraceService(M1, trace("jeu-seuil-abaisse")), "pas divergents attendus").to.include.members([6, 8]);
  });

  it("TA-47 (MN-47, paquet livré) : la trace annuaire/traces/confiscation.json rejouée par le canal de la console du service refuse la réattribution (adresse_deja_attribuee, pas 3 et 5) ; copie du module d'annuaire exécuté par le service sans ce refus : le service accepte au pas 3 (tué)", async function () {
    const t = lireJSON(CT3, "annuaire", "traces", "confiscation.json");
    /** Rejeu par `ServiceApprobation.console` d'une copie du paquet (ou du paquet livré) ; pas divergents, 1-indexés. */
    const rejouer = async (S, M, An) => {
      const initial = lireJSON(CT3, "annuaire", t.initial);
      let at = 0;
      let nonce;
      const service = new S.ServiceApprobation({
        config: { org_id: initial.org_id, journal_id: "0x" + "00".repeat(32), body_max_bytes: 16 * 1024 * 1024, escalation: [] },
        machine: new M.Machine({ org_id: initial.org_id, journal_id: "0x" + "00".repeat(32) }),
        magasin: null,
        supervision: { consigner() {}, compter() {} },
        annuaire: new An.EtatAnnuaire({ document: initial, defis: [], persiste: false }),
        horloge: () => at,
        tirerNonce: () => nonce,
        minuterie: false,
      });
      const ecarts = [];
      for (const [i, p] of t.steps.entries()) {
        at = Date.parse(p.at);
        nonce = p.challenges[0] ?? undefined;
        // le service tire ses identifiants d'entrée au hasard : `apb-000N` de la trace désigne la N-ième entrée créée
        const requete = { ...p.request };
        const n = typeof requete.entry === "string" ? /^apb-0*([1-9][0-9]*)$/.exec(requete.entry) : null;
        if (n) requete.entry = service.annuaire.document.entries[Number(n[1]) - 1]?.id ?? requete.entry;
        let obtenu;
        try {
          await service.console(p.method, requete);
          obtenu = { accepted: true, reason: null };
        } catch (e) {
          if (e?.name !== "ErreurService" || typeof e.code !== "string") throw e;
          obtenu = { accepted: false, reason: e.code };
        }
        if (!egal(obtenu, { accepted: p.expected.accepted, reason: p.expected.reason })) ecarts.push(i + 1);
      }
      return ecarts;
    };
    expect(await rejouer(await livre("service.mjs"), await livre("tickets.mjs"), await livre("annuaire.mjs")), "paquet livré").to.deep.equal([]);
    const m = await paquetMutant("ta47", [], { console: [{ fichier: "src/bibliotheque/annuaire.mjs", ancien: 'return refus("adresse_deja_attribuee");', nouveau: ";", tous: true }] });
    const ecarts = await rejouer(await m.importer("src/service.mjs"), await m.importer("src/tickets.mjs"), await m.importer("src/annuaire.mjs"));
    expect(ecarts).to.include.members([3]);
  });
});

// ---------------------------------------------------------------------------
// Étape 8 (revue de sécurité, CT-3 EX-9.15) : TA- nouveau sur la page
// livrée (paquets/console).
// Mutant : copie du paquet sous NOORTRACE_TMP, comparaison des vues retirée,
// écrans et manifeste régénérés par construire.mjs ; servi par le simulateur
// des essais des pages (option `paquet`).
describe("CT-9 : tests adversariaux TA- exécutables sur la page livrée de la console (mutants du paquet @noortrace/console, CT-7 EX-3.2)", function () {
  this.timeout(300_000);
  const PAQUET_CONSOLE = path.join(RACINE, "paquets", "console");
  const COPIES = [];
  let navigateur = null;
  let indisponible = null;
  let site;
  let pf;
  let B;

  before(async function () {
    const fixtures = (rel) => import(pathToFileURL(path.join(RACINE, "test", "fixtures", "exploitation-console", rel)).href);
    site = await fixtures("pages/site.mjs");
    pf = await fixtures("portefeuille.mjs");
    B = await import(pathToFileURL(path.join(PAQUET_CONSOLE, "src", "bibliotheque", "index.mjs")).href);
    try {
      const playwright = await import("playwright");
      navigateur = await playwright.chromium.launch();
    } catch (e) {
      indisponible = String(e.message).split("\n")[0];
    }
  });
  after(async () => {
    if (navigateur) await navigateur.close();
    for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
  });

  function mutantConsole(nom, remplacements) {
    const racine = fs.mkdtempSync(path.join(TMP, `noortrace-mutant-${nom}-`));
    COPIES.push(racine);
    const copie = path.join(racine, "console");
    fs.mkdirSync(path.join(copie, "node_modules", "@noble"), { recursive: true });
    for (const d of ["src", "schemas"]) fs.cpSync(path.join(PAQUET_CONSOLE, d), path.join(copie, d), { recursive: true });
    fs.copyFileSync(path.join(PAQUET_CONSOLE, "package.json"), path.join(copie, "package.json"));
    const depuis = createRequire(path.join(PAQUET_CONSOLE, "src", "serveur", "index.mjs"));
    for (const p of ["hashes", "curves"]) fs.symlinkSync(path.dirname(depuis.resolve(`@noble/${p}/utils.js`)), path.join(copie, "node_modules", "@noble", p));
    for (const r of remplacements) {
      const f = path.join(copie, "src", "pages", "statique", r.fichier);
      const texte = fs.readFileSync(f, "utf8");
      const n = texte.split(r.ancien).length - 1;
      if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
      fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
    }
    const g = spawnSync(process.execPath, [path.join(copie, "src", "pages", "construire.mjs"), "--ecrire"], { encoding: "utf8" });
    if (g.status !== 0) throw new Error(`mutant ${nom} : construire.mjs a rendu ${g.status} : ${g.stderr}`);
    return copie;
  }

  /** Scénario e1 du relecteur sur le paquet `paquet` : première lecture bénigne (125.00), suivantes réelles (12500.00) ; signature demandée si l'écran est offert. */
  async function deuxVues(paquet) {
    const ID1 = "oidc https://idp.assureur-demo.example approbateur-1";
    const lire = (rel) => lireJSON(VECTEURS, "ct-3", rel);
    const VUE = () => structuredClone(lire("console/modeles/apr-2201-approuve.json").input.view);
    const REFERENCE = () => structuredClone(lire("annuaire/annuaires/reference.json"));
    const dA = (vue) => B.condenses({ decision: "approuve", journal_id: vue.journal_id, org_id: vue.org_id, request_hash: vue.request_hash, ticket: vue.ticket }).d_a;
    const benigne = () => {
      const vue = VUE();
      vue.request.arguments = { claim_id: "2026-81044", amount: "125.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" };
      vue.request.intent = "Régler le sinistre 2026-81044 : 125.00 CHF au bénéficiaire du contrat";
      vue.retained_event.intent = vue.request.intent;
      const piece = new TextEncoder().encode('{"claim_id":"2026-81044","amount":"125.00","currency":"CHF","beneficiary_iban":"[REDIGE:iban]"}');
      vue.arguments_piece = Buffer.from(piece).toString("base64");
      vue.retained_event.execution.arguments = { sha256: B.versHex(B.sha256(piece)), length: piece.length, redacted: true };
      vue.effects[0].amount = "125.00";
      const h = B.hachageEvenement(vue.retained_event);
      vue.retained_event.hash = h;
      vue.request_hash = h;
      vue.digests = { approuve: dA(vue), refuse: B.condenses({ decision: "refuse", journal_id: vue.journal_id, org_id: vue.org_id, request_hash: h, ticket: vue.ticket }).d_a };
      return vue;
    };
    let n = 0;
    const service = {
      consulter: () => site.ok(++n === 1 ? benigne() : VUE()),
      annuaire: (c) => site.ok(B.annuaireDeSession(REFERENCE(), c.session_identity)),
      tickets: (c) => site.ok(c.related_to === undefined ? { tickets: [] } : { tickets: [], related: [] }),
      voter: (c) => site.ok({ ticket: c.ticket, state: "verification" }),
    };
    const contexte = await navigateur.newContext();
    try {
      const sim = new site.Simulateur({ session: { session_identity: ID1, auth_time: "2026-11-05T09:20:00.000Z", administrator: false, reauth_max_age_s: 900, delai_signature_ms: 300000 }, service, paquet });
      const portefeuilles = new pf.Portefeuilles({ portefeuilles: [{ id: "a", comptes: [1] }], annonces: [pf.annonce("a", "11111111-1111-4111-8111-111111111111", "Portefeuille A", "example.portefeuille-a")] });
      await sim.installer(contexte);
      await portefeuilles.installer(contexte);
      const page = await contexte.newPage();
      const erreurs = [];
      page.on("pageerror", (e) => erreurs.push(String(e)));
      await page.clock.setFixedTime(new Date("2026-11-05T09:25:00.000Z"));
      await page.goto(site.ORIGINE + "/tickets/apr-2201");
      await page.waitForSelector('button[data-decision="approuve"]:not([disabled])');
      await page.click('button[data-decision="approuve"]');
      await page.click("text=Confirmer : approuver");
      await page.locator(".fournisseur", { hasText: "Portefeuille A" }).getByRole("button").click();
      await page.waitForSelector('#zone-signature [data-code="demande_modifiee"], #ecran-signature');
      const ecran = await page.locator("#ecran-signature").count();
      const modifiee = await page.locator('#zone-signature [data-code="demande_modifiee"]').count();
      if (ecran) {
        await page.click("text=Demander la signature au portefeuille");
        await page.waitForSelector("#zone-resultat [data-code], #zone-resultat [data-resultat]");
      }
      return { ecran, modifiee, signes: portefeuilles.requetes(null, "personal_sign").map((x) => x.params[0]), votes: sim.corps("voter").length, dB: dA(VUE()), erreurs, ecarts: sim.ecarts };
    } finally {
      await contexte.close();
    }
  }

  it("TA-44 (MN-44, page livrée, deux vues) : le service sert une demande bénigne à la lecture (i) et la vraie à la lecture (ii) ; la page n'offre pas l'écran de signature, affiche demande_modifiee, aucun personal_sign ni voter ; mutant de la page sans la comparaison des vues : l'écran est offert et le D_A de la seconde vue est signé (tué)", async function () {
    if (!navigateur) {
      this.test.title += ` — en attente : Chromium indisponible (${indisponible})`;
      return this.skip();
    }
    const ref = await deuxVues(PAQUET_CONSOLE);
    expect(ref.erreurs).to.deep.equal([]);
    expect(ref.ecarts).to.deep.equal([]);
    expect([ref.ecran, ref.modifiee, ref.signes, ref.votes]).to.deep.equal([0, 1, [], 0]);
    const m = mutantConsole("mn44-deux-vues", [{ fichier: "ecrans/ticket.mjs", ancien: "const modifiee = !memeDemande(etat.vue, lu.vue);", nouveau: "const modifiee = false;" }]);
    const mut = await deuxVues(m);
    expect([mut.ecran, mut.modifiee], "mutant : écran de signature offert").to.deep.equal([1, 0]);
    expect(mut.signes, "mutant : D_A de la seconde vue signé").to.deep.equal([mut.dB]);
    expect(mut.votes, "mutant : vote envoyé").to.equal(1);
  });
});

// ---------------------------------------------------------------------------
// Revue de l'étape 8 : TA-73 et TA-43 ne mutaient que
// l'outil de référence et le schéma de l'enregistreur ; ces deux `it` mutent
// l'agent d'inscription livré au
// point de sa réponse (MN-73 : consommation de la confirmation hors bande au
// versement ; MN-43 : résolution des secrets, fichier lisible de son seul
// propriétaire).
// ---------------------------------------------------------------------------
describe("CT-9 : tests adversariaux TA- sur l'agent d'inscription livré (mutants du paquet @noortrace/inscription, revue de l'étape 8, TA-73)", function () {
  this.timeout(900000);
  const PAQUET_INSCRIPTION = path.join(RACINE, "paquets", "inscription");
  const chargerFixture = (rel) => import(pathToFileURL(path.join(RACINE, "test", "fixtures", "inscription", rel)).href);
  const COPIES = [];
  after(function () {
    for (const c of COPIES) fs.rmSync(c, { recursive: true, force: true });
  });
  /** Copie de paquets/inscription (src, schemas, bin, package.json ; node_modules lié) où chaque remplacement, unique, retire la réponse. */
  function mutantInscription(nom, remplacements) {
    const racine = fs.mkdtempSync(path.join(TMP, `noortrace-mutant-inscription-${nom}-`));
    COPIES.push(racine);
    for (const d of ["src", "schemas", "bin"]) fs.cpSync(path.join(PAQUET_INSCRIPTION, d), path.join(racine, d), { recursive: true });
    fs.copyFileSync(path.join(PAQUET_INSCRIPTION, "package.json"), path.join(racine, "package.json"));
    fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(racine, "node_modules"));
    for (const r of remplacements) {
      const f = path.join(racine, "src", r.fichier);
      const texte = fs.readFileSync(f, "utf8");
      const n = texte.split(r.ancien).length - 1;
      if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
      fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
    }
    return { racine, importer: (rel) => import(pathToFileURL(path.join(racine, "src", rel)).href) };
  }

  it("TA-73 (MN-73, agent livré) : une confirmation hors bande n'autorise qu'un approvisionnement : le versement la consomme et un second approvisionner de la même clé est refusé à la remise (confirmation_absente, rien n'est envoyé) ; mutant d'approvisionner sans consommerConfirmation : la confirmation reste libre, le second est admis (tué)", async function () {
    const E = await chargerFixture("reseau-essai.mjs");
    const O = await chargerFixture("outils.mjs");
    const { keccak256, octetsVersHex, utf8 } = await import("@noortrace/noyau");
    const { SignataireChaineFichier } = await import("@noortrace/ancrage/registre");
    const X = "exploitant operateur-1";
    const JOURNAL = "journal-principal";
    const JID = octetsVersHex(keccak256(utf8(JOURNAL)));
    const dir = O.repertoireTemporaire("noortrace-ta73-");
    const reseau = await E.demarrerReseau();
    const pont = await E.ouvrirPont(reseau.provider, { noorcore: true });
    const manifeste = E.ecrireManifesteEssai(path.join(dir, "instance"), reseau);
    const scenario = async (racinePaquet, nom) => {
      const a = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, delai_s: 3, clesRepertoire: dir, racinePaquet });
      try {
        const slug = `ta73-${nom}`;
        const k = randomBytes(32);
        fs.writeFileSync(path.join(dir, `${slug}.cle`), k.toString("hex"), { mode: 0o600 });
        const chaine = new SignataireChaineFichier(new Uint8Array(k)).adresse();
        const doc = O.documentCle({ keyId: `rec-${slug}`, journalId: JID, chainKey: chaine, publique: O.cleEd25519(slug).publique });
        const prep = await a.executer(X, { commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: [1, 2, 3].map((i) => O.compteHardhat(i).adresse), seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
        expect(prep.sortie?.result, JSON.stringify(prep.sortie?.error ?? prep)).to.equal("reussi");
        const orgId = octetsVersHex(keccak256(utf8(slug)));
        const c = await a.confirmation(X, { operation: "approvisionner", objet: { org_id: orgId, cle_chaine: chaine }, personne_client: "Responsable de l'essai", canal: "appel téléphonique au numéro du contrat", instant: "2026-11-13T10:00:00.000Z", piece_sha256: "0x" + "ab".repeat(32) });
        expect(c.accepte, JSON.stringify(c)).to.equal(true);
        const t1 = await a.executer(X, { commande: "approvisionner", slug, parametres: { cle_chaine: chaine } });
        expect(t1.sortie?.result, JSON.stringify(t1.sortie?.error ?? t1)).to.equal("reussi");
        const envois = pont.envoisRecus.length;
        const r2 = await a.travail(X, { commande: "approvisionner", slug, parametres: { cle_chaine: chaine } });
        if (r2.accepte) await a.attendre(r2.id);
        const lignes = fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
        return { r2, envoisApres: pont.envoisRecus.length - envois, consommations: lignes.filter((l) => l.consommation).length };
      } finally {
        await a.arreter();
        fs.rmSync(a.base, { recursive: true, force: true });
      }
    };
    try {
      const ref = await scenario(null, "ref");
      expect(ref.r2).to.deep.include({ accepte: false, code: "confirmation_absente" });
      expect(ref.consommations, "une ligne de consommation").to.equal(1);
      expect(ref.envoisApres).to.equal(0);
      // Mutant : la confirmation exigée est cherchée (confirmationRequise) mais n'est plus consommée au versement.
      const m = mutantInscription("mn73", [{ fichier: "agent/commandes/approvisionner.mjs", ancien: "outputs.confirmation_sha256 = consommerConfirmation(ctx, critere).piece_sha256;", nouveau: "outputs.confirmation_sha256 = confirmationRequise(ctx, critere).piece_sha256;" }]);
      const mut = await scenario(m.racine, "mut");
      expect(mut.consommations, "mutant : la confirmation n'est pas consommée").to.equal(0);
      expect(mut.r2.accepte, `mutant : la réponse retirée, un second approvisionnement est admis sur la même confirmation (${JSON.stringify(mut.r2)})`).to.equal(true);
    } finally {
      await pont.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("TA-43 (MN-43, agent livré) : l'agent ne charge une clé fichier: que d'un fichier lisible de son seul propriétaire, et ne démarre pas avec un jeton du nœud dans un fichier lisible d'autres ; mutants sans le contrôle du mode (clés ; jeton) : clé en 0644 chargée, agent démarré (tués)", async function () {
    const O = await chargerFixture("outils.mjs");
    const dir = O.repertoireTemporaire("noortrace-ta43-");
    try {
      const K = await import(pathToFileURL(path.join(PAQUET_INSCRIPTION, "src", "agent", "cles.mjs")).href);
      const f = path.join(dir, "cle-0644.cle");
      fs.writeFileSync(f, "11".repeat(32), { mode: 0o644 });
      fs.chmodSync(f, 0o644);
      const ctx = { role: "cle_chaine", nature: "developpement", evmChainId: 31337 };
      expect(() => K.signataire(`fichier:${f}`, ctx)).to.throw(K.ErreurReference, /lisible par d'autres/);
      const m1 = mutantInscription("mn43-cles", [{ fichier: "agent/cles.mjs", ancien: 'if ((st.mode & 0o077) !== 0) throw new ErreurReference("reference_refusee", `${quoi} : fichier lisible par d\'autres que son propriétaire (EX-7.3)`);', nouveau: "void 0;" }]);
      const MK = await m1.importer("agent/cles.mjs");
      expect(MK.signataire(`fichier:${f}`, ctx).adresse(), "mutant : la réponse retirée, la clé en 0644 est chargée").to.match(/^0x[0-9a-f]{40}$/);
      // Jeton du nœud en fichier lisible de tous : l'agent livré ne démarre pas ; le mutant démarre.
      const jeton = path.join(dir, "jeton-0644");
      fs.writeFileSync(jeton, "jeton-essai-sans-valeur", { mode: 0o644 });
      fs.chmodSync(jeton, 0o644);
      fs.cpSync(path.join(VECTEURS, "ct-4", "manifestes", "valides", "developpement"), path.join(dir, "instance"), { recursive: true });
      const manifeste = path.join(dir, "instance", "instance-r1.json");
      let refus = null;
      try {
        await O.demarrerAgentEssai({ manifeste, rpc: "http://127.0.0.1:9", comptes: {}, delai_s: 1, jeton: `fichier:${jeton}` });
      } catch (e) {
        refus = e;
      }
      expect(refus?.message, "agent livré : jeton en 0644 refusé").to.match(/jeton : fichier lisible par d'autres/);
      const m2 = mutantInscription("mn43-jeton", [{ fichier: "agent/index.mjs", ancien: 'if ((st.mode & 0o077) !== 0 || st.uid !== process.getuid()) throw new ErreurConfiguration("jeton : fichier lisible par d\'autres que son propriétaire");', nouveau: "void 0;" }]);
      const a = await O.demarrerAgentEssai({ manifeste, rpc: "http://127.0.0.1:9", comptes: {}, delai_s: 1, jeton: `fichier:${jeton}`, racinePaquet: m2.racine });
      try {
        expect(a.pret, "mutant : la réponse retirée, l'agent démarre avec un jeton lisible de tous").to.include({ pret: true });
      } finally {
        await a.arreter();
        fs.rmSync(a.base, { recursive: true, force: true });
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// -----------------------------------------------------------------------------
// Scénarios adversariaux de bout en bout de CT-9 §10.5 (TA-103 à TA-107) et
// TA-96, joués sur la démonstration de référence (CT-2 §19) lancée par étapes,
// avec les surcharges de demo/pannes/ (mutants des paquets portés par l'image,
// horloge pilotable par libfaketime, prestataires RFC 3161 internes). Chaque
// scénario se joue d'abord avec toutes les réponses en place (son oracle de
// bout en bout, EX-10.9), puis avec UNE réponse d'un test composé retirée dans
// le démon ou le composant d'ancrage (mutant de l'image, CT-9 EX-10.5,
// EX-10.6) : l'attaque que ce test couvre aboutit alors (expected_without_response).
//
// Lu depuis test/ ou hors de test/ avec NOORTRACE_RACINE (EX-10.8) ; aucun
// fichier du dépôt n'est écrit (répertoires de travail sous NOORTRACE_TMP).
// En attente, condition nommée, sans démon Docker, sans les images de la
// démonstration, ou (TA-105) sans la bibliothèque libfaketime à l'empreinte
// fixée (NOORTRACE_LIBFAKETIME).
// Bloc propre : ses noms (P, N, CONFIG, S, REGLAGES, travailNeuf, etat) ne
// valent que pour les deux describe qui suivent.
{
const P = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "pannes", "outils.mjs")).href);
const N = await import(pathToFileURL(path.join(RACINE, "paquets", "noyau", "src", "index.mjs")).href);
const CONFIG = P.CONFIG_DEMO;
const S = (...n) => n.map((x) => path.join(P.PANNES, x));
const REGLAGES = { rfc3161: { manifest: { fallback_after_s: 60 }, checkpoints: { interval_s: 60, provider_role: "principal", fallback_after_s: 30 } }, queue: { anchor_pending_alert_s: 60 } };

/** Répertoire de travail neuf d'un essai, sous NOORTRACE_TMP (mode 0755 pour les montages liés). */
function travailNeuf(nom) {
  const d = fs.mkdtempSync(path.join(TMP, `noortrace-pannes-${nom}-`));
  fs.chmodSync(d, 0o755);
  return d;
}

/** La démonstration peut-elle être lancée ici ? `{ ok, condition }`. */
const etat = P.etatDocker();

// ===========================================================================
// TA-103 à TA-107 : attaques jouées sur la démonstration de référence, et
// mutants de l'image qui retirent une réponse du démon ; un describe par
// scénario (CT-9 EX-A.11).
// ===========================================================================
describe("CT-9 §10.5 : scénarios adversariaux joués sur la démonstration de référence (composition docker compose de CT-2 §19)", function () {
  this.timeout(3_600_000);

  describe("TA-103 (MN-1, MN-2, MN-3, MN-4, MN-5, MN-6, MN-7, MN-9, MN-15, MN-22) : l'agent supprime ou réécrit", function () {
    let c = null;
    let travail = null;
    let ctx = null;

    before(async function () {
      if (!etat.ok) {
        ctx = { condition: etat.condition };
        return;
      }
      travail = travailNeuf("ta103-104");
      c = new P.CompositionPannes({ nom: `noortrace-pannes-ta103-${process.pid}`, port: await P.portLibre() });
      c.lancer(["agent-demo"]);
      ctx = { code: c.attendre("agent-demo", 300000) };
    });

    after(function () {
      if (c) c.demonter();
      if (travail) fs.rmSync(travail, { recursive: true, force: true });
    });

    function pret() {
      if (!ctx || ctx.condition) {
        P.enAttente(this, ctx?.condition ?? "composition non lancée");
        return false;
      }
      expect(ctx.code, "l'agent de la démonstration a terminé").to.equal(0);
      return true;
    }

    it("TA-103 (MN-1, MN-2, MN-3, MN-4, MN-5, MN-6, MN-7, MN-9, MN-15, MN-22) : sur la démonstration de référence, les attaques de l'agent sont refusées ou journalisées (connexion directe, launched_by déclaré, fractionnement, clé en double, ré-émission, demandes multipliées, outil réservé) ; aucun événement n'est absent ni réécrit, la série des points est continue (borne RA-1 à RA-6, RA-8, RA-13, RA-19)", function () {
      if (!pret.call(this)) return;
      const ev0 = c.evenements(CONFIG);
      const appelsAvant = c.appelsOutils();
      // MN-1 : connexion TCP directe au serveur d'outils, par son nom puis par son adresse.
      const adr = JSON.parse(P.docker(["inspect", c.conteneur("outils-demo")]).stdout)[0].NetworkSettings.Networks[c.ressource("outils")].IPAddress;
      const directe = c.executer("agent-demo", `const net=require("net");const t=(h)=>new Promise((r)=>{const s=net.connect({host:h,port:8000});const f=(x)=>{s.destroy();r(x)};s.setTimeout(3000,()=>f("delai"));s.once("connect",()=>f("etablie"));s.once("error",(e)=>f(e.code))});Promise.all([t("outils-demo"),t(${JSON.stringify(adr)})]).then((v)=>console.log(JSON.stringify(v)))`);
      const [parNom, parAdresse] = JSON.parse(directe.stdout.trim().split("\n").at(-1));
      expect(parNom).to.be.oneOf(["ENOTFOUND", "EAI_AGAIN"]);
      expect(parAdresse).to.be.oneOf(["ENETUNREACH", "EHOSTUNREACH", "delai"]);
      expect(c.appelsOutils(), "le serveur d'outils n'a reçu aucun appel direct").to.equal(appelsAvant);
      // MN-2 : délégation déclarée (launched_by, on_behalf_of hors liste) ignorée.
      const r2 = c.appel("demo__claims.get", { claim_id: "2026-81044" }, { meta: { "noortrace/delegation": { launched_by: "u.autre@assureur-demo.example", on_behalf_of: "service-autre", run_id: "run-ta2" } } });
      expect(r2.json.result.isError, JSON.stringify(r2.json)).to.equal(false);
      const evA = c.evenements(CONFIG);
      const eNom = evA.find((e) => e.seq > ev0.at(-1).seq && e.execution.tool === "demo__claims.get");
      expect(eNom.delegation.launched_by).to.equal("agent-demo");
      // MN-3 : deux paiements de 3700 (sous 5000) : autorisés automatiquement, aucune approbation demandée mais tracés.
      const r3a = c.appel("demo__payments.create", { claim_id: "2026-81044", amount: "3700.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" });
      const r3b = c.appel("demo__payments.create", { claim_id: "2026-81044", amount: "3700.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 8" });
      expect(r3a.json.result.isError, JSON.stringify(r3a.json)).to.equal(false);
      expect(r3b.json.result.isError).to.equal(false);
      // MN-4 : clé d'argument en double (analyse stricte) et nombre non représentable.
      const r4 = c.mcp('{"jsonrpc":"2.0","id":"ta4","method":"tools/call","params":{"name":"demo__payments.create","arguments":{"claim_id":"2026-81044","amount":"100.00","amount":"9000.00","currency":"CHF","beneficiary_iban":"CH93 0076 2011 6238 5295 7"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","noortrace/delegation":{"run_id":"run-demo-0001"}}}}', { nom: "demo__payments.create" });
      expect(r4.json.error.data.reason).to.equal("cle_double");
      // MN-7, MN-15 : un outil de l'espace réservé noortrace.* est refusé.
      const r7 = c.appel("noortrace.journal.politique", { x: 1 });
      expect(r7.json.error.message).to.match(/Unknown tool/);
      // MN-6 : inondation — un demandeur multiplie les demandes soumises à approbation. Chacune est soit retenue (ticket
      // ouvert), soit refusée par le service (plafond de tickets ouverts par demandeur, CT-3 EX-14.1, aussi éprouvé sur
      // le service par TA-6) ; aucune n'est relayée sans décision, et la chaîne reste intègre. Plusieurs paiements > 5000.
      const nTickets0 = c.journalExploitation().filter((l) => l.event === "approval_opened").length;
      for (let k = 0; k < 6; k++) c.appel("demo__payments.create", { claim_id: "2026-81044", amount: `${6100 + k}.00`, currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" });
      const ops = c.journalExploitation();
      const nTickets1 = ops.filter((l) => l.event === "approval_opened").length;
      expect(nTickets1, "chaque paiement au-delà du seuil ouvre un ticket (retenu, jamais relayé sans décision)").to.be.above(nTickets0);
      // Aucun événement n'est absent ni réécrit : les seq se suivent, la chaîne est continue.
      const ev = c.evenements(CONFIG);
      const seqs = ev.map((e) => e.seq);
      expect(new Set(seqs).size).to.equal(seqs.length);
      expect(seqs.every((s, i) => i === 0 || s === seqs[i - 1] + 1), "séquence sans trou").to.equal(true);
      expect(ev.every((e, i) => i === 0 || e.prev_hash === N.hacherEvenement(ev[i - 1])), "chaînage continu").to.equal(true);
    });
  });

  // =========================================================================
  // TA-104 : l'opérateur réécrit après coup. Celui qui tient l'enregistreur
  // remplace la politique et redémarre, puis réécrit un événement d'un
  // segment fermé (accès d'administrateur au volume du journal).
  // =========================================================================
  describe("TA-104 (MN-17, MN-18, MN-19, MN-23, MN-26, MN-27, MN-28, MN-74, MN-84, MN-85, MN-86, MN-96) : l'opérateur réécrit après coup", function () {
    let c = null;
    let travail = null;
    let passage = null;
    let ctx = null;
    const REP = `${CONFIG.recorder.org_id.slice(2)}/${CONFIG.recorder.journal_id.slice(2)}`;
    const VERSION = "demo-2026-12-remplacee";
    /** Configuration de la démonstration dont la politique est remplacée (nouvelle version, seuil d'approbation relevé). */
    function configurationRemplacee() {
      const config = structuredClone(CONFIG);
      config.policy.version = VERSION;
      config.policy.approval.rules.rules[2].when.all[1].value = "50000";
      return config;
    }
    const ancrageDemo = () => JSON.parse(fs.readFileSync(path.join(P.DEMO, "ancrage-demo.json"), "utf8"));
    /** Événements de politique (outil noortrace.journal.politique) d'une version. */
    const annonces = (ev, version) => ev.filter((e) => e.execution?.tool === "noortrace.journal.politique" && e.execution?.arguments?.value?.policy_version === version);

    before(async function () {
      if (!etat.ok) {
        ctx = { condition: etat.condition };
        return;
      }
      travail = travailNeuf("ta104");
      passage = path.join(travail, "passage");
      c = new P.CompositionPannes({ nom: `noortrace-pannes-ta104-${process.pid}`, port: await P.portLibre(), env: { NOORTRACE_PANNES_TRAVAIL: passage } });
      c.lancer(["agent-demo"]);
      ctx = { code: c.attendre("agent-demo", 300000) };
    });

    after(function () {
      if (c) c.demonter();
      if (travail) fs.rmSync(travail, { recursive: true, force: true });
    });

    function pret() {
      if (!ctx || ctx.condition) {
        P.enAttente(this, ctx?.condition ?? "composition non lancée");
        return false;
      }
      expect(ctx.code, "l'agent de la démonstration a terminé").to.equal(0);
      return true;
    }

    it("TA-104 (MN-17, MN-23, MN-26) : sur la démonstration de référence, l'opérateur remplace la politique, redémarre, puis réécrit un événement d'un segment fermé ; politique et redémarrage sont dans la chaîne, la relecture signale l'événement réécrit (hash_different), aucun dossier valide n'en sort (borne RA-15 à RA-17, RA-20, RA-23, RA-24, RA-63, RA-66, RA-71, RA-72, RA-80)", async function () {
      if (!pret.call(this)) return;
      // Politique remplacée sans annonce de l'opérateur, puis redémarrage avec la configuration remplacée.
      P.ecrireConfigurationPannes(passage, { configuration: configurationRemplacee(), ancrage: ancrageDemo() });
      const evAvant = c.evenements(CONFIG);
      expect(annonces(evAvant, VERSION), "version inconnue avant le remplacement").to.deep.equal([]);
      const nOps = c.journalExploitation().length;
      c.dc(["stop", "-t", "10", "enregistreur"]);
      const cr = new P.CompositionPannes({ nom: c.nom, port: c.port, surcharges: S("compose.configuration.yaml"), env: { NOORTRACE_PANNES_TRAVAIL: passage } });
      cr.lancerSeul("enregistreur", ["--force-recreate"]);
      await cr.sain("enregistreur", 120000);
      const ops = cr.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "startup"), "le redémarrage est au journal d'exploitation (ligne startup)").to.equal(true);
      const annonce = ops.find((l) => l.event === "policy_announced" && l.data?.policy_version === VERSION);
      expect(annonce, "la politique remplacée est annoncée au démarrage (policy_announced)").to.not.equal(undefined);
      const evApres = cr.evenements(CONFIG);
      expect(annonces(evApres, VERSION).map((e) => e.seq), "la politique remplacée est un événement de la chaîne").to.deep.equal([annonce.seq]);
      // Réécriture, sous le compte 0, d'un événement d'un segment fermé (le premier), démon arrêté.
      const segs = cr.segments(CONFIG);
      expect(segs.length, "un segment fermé avant le redémarrage").to.be.at.least(2);
      cr.dc(["stop", "-t", "10", "enregistreur"]);
      const nOps2 = cr.journalExploitation().length;
      const alt = JSON.parse(cr.ecrireVolume("journal", `const fs=require("fs");const f="/v/${REP}/segments/${segs[0]}";const l=fs.readFileSync(f,"utf8").split("\\n");const k=l.findIndex((x,i)=>i>0&&x.includes("2026-81044"));if(k<0){console.log(JSON.stringify({seq:null}));process.exit(0)}const seq=JSON.parse(l[k]).seq;l[k]=l[k].replace("2026-81044","2026-81045");fs.writeFileSync(f,l.join("\\n"));console.log(JSON.stringify({seq}));`).trim().split("\n").at(-1));
      expect(alt.seq, "un événement du segment fermé porte l'identifiant du sinistre").to.be.a("number");
      cr.lancerSeul("enregistreur");
      await cr.sain("enregistreur", 120000);
      const ops2 = cr.journalExploitation().slice(nOps2);
      const signale = ops2.find((l) => l.event === "integrity_check" && l.data?.check === "relecture" && l.data?.segment === segs[0]);
      expect(signale, "la relecture du segment réécrit est au journal d'exploitation").to.not.equal(undefined);
      expect(signale.data, "l'événement réécrit est signalé").to.deep.include({ ok: false, raison: "hash_different" });
      const metriques = await fetch(`http://127.0.0.1:${c.port}/metrics`).then((r) => r.text());
      expect(metriques).to.match(/^noortrace_integrity_check_failures_total\{check="relecture"\} [1-9][0-9]*$/m);
      // Aucun dossier valide de l'événement réécrit : export refusé, ou dossier refusé par les deux vérificateurs.
      const ex = cr.exporterDossier(alt.seq, "reecrit", travail);
      if (ex.dossier) {
        const v = P.verifierDeux(ex.dossier, { ancres: P.ANCRES_DEMO });
        expect(v.js.rapport?.verdict, "vérificateur JavaScript").to.not.equal("valide");
        expect(v.js.code).to.not.equal(0);
        if (v.go) {
          expect(v.go.rapport?.verdict, "vérificateur Go").to.not.equal("valide");
          expect(v.go.code).to.not.equal(0);
        }
      } else {
        expect(ex.refus, "export refusé").to.be.a("string");
      }
    });

    it("TA-104 (MN-23, réponse retirée) : un mutant du démon (image) qui n'annonce plus dans la chaîne une politique remplacée ; après le remplacement de la politique et le redémarrage, la démonstration mutante applique la nouvelle version sans événement de politique ni ligne policy_announced (tué)", async function () {
      if (!pret.call(this)) return;
      const config = configurationRemplacee();
      config.policy.version = `${VERSION}-mutant`;
      P.ecrireConfigurationPannes(passage, { configuration: config, ancrage: ancrageDemo() });
      const src = P.mutantImage("enregistreur", path.join(travail, "mut-mn23"), [{ fichier: "coeur.mjs", ancien: "    if (!d.annoncer) return null;", nouveau: "    return null;" }]);
      const cm = new P.CompositionPannes({ nom: c.nom, port: c.port, surcharges: S("compose.configuration.yaml", "compose.mutant-enregistreur.yaml"), env: { NOORTRACE_PANNES_TRAVAIL: passage, NOORTRACE_PANNES_SRC_ENREGISTREUR: src } });
      const nOps = cm.journalExploitation().length;
      cm.recreerEnregistreur();
      await cm.sain("enregistreur", 120000);
      const ops = cm.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "startup"), "le démon mutant a démarré").to.equal(true);
      expect(ops.some((l) => l.event === "policy_announced" && l.data?.policy_version === config.policy.version), "le mutant n'annonce pas la politique remplacée").to.equal(false);
      expect(annonces(cm.evenements(CONFIG), config.policy.version), "aucun événement de politique pour la version remplacée").to.deep.equal([]);
    });
  });

  // =========================================================================
  // TA-105 : l'horloge est manipulée. Horloge murale du processus du démon
  // pilotée par libfaketime (précondition de TA-105) ; les binaires Go
  // ne sont pas touchés (CT-9 §16).
  // =========================================================================
  describe("TA-105 (MN-21, MN-60, MN-76, MN-93) : l'horloge est manipulée", function () {
    let c = null;
    let horloge = null;
    let travail = null;
    let ctx = null;

    before(async function () {
      const faketime = P.libfaketime();
      if (!etat.ok || !faketime.ok) {
        ctx = { condition: etat.ok ? faketime.condition : etat.condition };
        return;
      }
      travail = travailNeuf("ta105");
      horloge = new P.HorlogePilotable(path.join(travail, "horloge"), faketime.chemin);
      c = new P.CompositionPannes({ nom: `noortrace-pannes-ta105-${process.pid}`, port: await P.portLibre(), surcharges: S("compose.horloge.yaml"), env: { NOORTRACE_PANNES_HORLOGE: horloge.dir } });
      c.lancer(["agent-demo"]);
      ctx = { code: c.attendre("agent-demo", 300000) };
    });

    after(function () {
      if (c) c.demonter();
      if (travail) fs.rmSync(travail, { recursive: true, force: true });
    });

    function pret() {
      if (!ctx || ctx.condition) {
        P.enAttente(this, ctx?.condition ?? "composition non lancée");
        return false;
      }
      expect(ctx.code).to.equal(0);
      return true;
    }

    it("TA-105 (MN-21) : horloge murale du démon pilotée par libfaketime (hors binaires Go, CT-9 §16) — un recul au-delà de clock.max_backstep_ms (clock_backstep) et un saut au-delà de clock.max_forward_ms (clock_forward_jump) font entrer en mode dégradé « horloge » ; noortrace-ctl clock --accept en sort ; les dates restent non décroissantes (borne RA-18, RA-54)", async function () {
      if (!pret.call(this)) return;
      const nOps = c.journalExploitation().length;
      // Recul de 120 s (> max_backstep_ms 5000).
      horloge.placer(-120);
      await P.pause(1500);
      const recul = c.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect([recul.json.error.code, recul.json.error.data.reason], JSON.stringify(recul.json)).to.deep.equal([-31017, "horloge"]);
      let ops = c.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "clock_backstep"), "clock_backstep consigné").to.equal(true);
      expect(ops.some((l) => l.event === "degraded_enter" && l.data.reason === "horloge"), "mode dégradé horloge").to.equal(true);
      // Saut en avant (de −120 à +120 : avance murale de 240 s > max_forward_ms 60 000 ms).
      horloge.placer(120);
      await P.pause(1500);
      const saut = c.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect([saut.json.error.code, saut.json.error.data.reason]).to.deep.equal([-31010, "horloge"]);
      await P.pause(1000);
      ops = c.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "clock_forward_jump"), "clock_forward_jump consigné").to.equal(true);
      // Confirmation de l'exploitant : sortie du mode dégradé.
      const acc = c.ctl(["clock", "--accept"]);
      expect([acc.code, acc.reponse?.event], acc.stdout + acc.stderr).to.deep.equal([0, "clock_accepted"]);
      await P.pause(500);
      const apres = c.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect(apres.json.result.isError, JSON.stringify(apres.json)).to.equal(false);
      ops = c.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "clock_accepted"), "clock_accepted consigné").to.equal(true);
      expect(ops.filter((l) => l.event === "degraded_exit" && l.data.reason === "horloge").length, "sortie du mode horloge").to.be.above(0);
      // Les ts des événements scellés restent non décroissants (CT-1 §5.2).
      const ts = c.evenements(CONFIG).map((e) => N.decoderHorodatage(e.ts));
      expect(ts.every((t, i) => i === 0 || t >= ts[i - 1]), "ts non décroissant").to.equal(true);
      horloge.placer(0);
    });

    it("TA-105 (MN-21, réponse retirée) : un mutant du démon (image) sans les deux contrôles d'horloge de l'écrivain (recul et saut) ; sous un saut en avant de l'horloge murale que la référence bloque, aucun mode dégradé n'est levé et un événement est scellé à une date future fausse (tué)", async function () {
      if (!pret.call(this)) return;
      const src = P.mutantImage("enregistreur", path.join(travail, "mut-mn21"), [
        { fichier: "horloge.mjs", ancien: "if (tsPrecedent !== null && lu < tsPrecedent - r.max_backstep_ms) {", nouveau: "if (false) {" },
        { fichier: "horloge.mjs", ancien: "if (avanceMurale > avanceMonotone + r.max_forward_ms) {", nouveau: "if (false) {" },
      ]);
      const cm = new P.CompositionPannes({ nom: c.nom, port: c.port, surcharges: S("compose.horloge.yaml", "compose.mutant-enregistreur.yaml"), env: { NOORTRACE_PANNES_HORLOGE: horloge.dir, NOORTRACE_PANNES_SRC_ENREGISTREUR: src } });
      cm.lancerSeul("enregistreur", ["--force-recreate"]);
      await cm.sain("enregistreur", 120000);
      const nOps = cm.journalExploitation().length;
      const avant = cm.evenements(CONFIG).length;
      // Saut en avant de l'horloge murale (240 s au-delà du cours monotone) : la référence le bloque (clock_forward_jump,
      // -31010), le mutant l'accepte et scelle un ts dans le futur, ce qu'EX-7.13 exclut.
      horloge.placer(240);
      await P.pause(1500);
      const r1 = cm.appel("demo__claims.get", { claim_id: "2026-81044" });
      const r2 = cm.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect(r1.json.result?.isError, JSON.stringify(r1.json)).to.equal(false);
      expect(r2.json.result?.isError).to.equal(false);
      const ev = cm.evenements(CONFIG);
      expect(ev.length, "le mutant scelle de nouveaux événements malgré le saut d'horloge").to.be.above(avant);
      // La date fausse : au moins un événement scellé porte un ts dans le futur, plus de 100 s après l'instant réel.
      const reel = Date.now();
      expect(ev.slice(avant).some((e) => N.decoderHorodatage(e.ts) - reel > 100000), "événement scellé à une date future fausse (saut d'horloge non détecté)").to.equal(true);
      const ops = cm.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "degraded_enter" && l.data.reason === "horloge"), "le mutant n'entre pas en mode dégradé horloge").to.equal(false);
      horloge.placer(0);
    });
  });

  // =========================================================================
  // TA-106 : l'enregistreur tombe.
  // =========================================================================
  describe("TA-106 (MN-10, MN-19, MN-20, MN-26, MN-29, MN-33, MN-64) : l'enregistreur tombe", function () {
    let c = null;
    let travail = null;
    let passage = null;
    let ctx = null;
    const REP = `${CONFIG.recorder.org_id.slice(2)}/${CONFIG.recorder.journal_id.slice(2)}`;

    before(async function () {
      if (!etat.ok) {
        ctx = { condition: etat.condition };
        return;
      }
      travail = travailNeuf("ta106");
      passage = path.join(travail, "passage");
      // Prestataires RFC 3161 internes : nécessaires pour que le composant d'ancrage ait une file à reconstruire.
      c = new P.CompositionPannes({ nom: `noortrace-pannes-ta106-${process.pid}`, port: await P.portLibre(), surcharges: S("compose.configuration.yaml", "compose.prestataires.yaml"), env: { NOORTRACE_PANNES_TRAVAIL: passage } });
      P.ecrireConfigurationPannes(passage, { ancrage: P.documentAncragePannes([]) });
      const aut = P.preparerPrestataires(c, ["principal", "secours", "decalee"], passage);
      P.ecrireConfigurationPannes(passage, { ancrage: P.documentAncragePannes([P.prestataireInterne("principal", "principal", aut.principal), P.prestataireInterne("secours", "secours", aut.secours)], REGLAGES) });
      c.lancer(["agent-demo"]);
      ctx = { code: c.attendre("agent-demo", 300000) };
    });

    after(function () {
      if (c) c.demonter();
      if (travail) fs.rmSync(travail, { recursive: true, force: true });
    });

    function pret() {
      if (!ctx || ctx.condition) {
        P.enAttente(this, ctx?.condition ?? "composition non lancée");
        return false;
      }
      expect(ctx.code).to.equal(0);
      return true;
    }

    it("TA-106 (MN-10, MN-20, MN-26, MN-64) : arrêt brutal (SIGKILL), dernier segment privé de sa fin de ligne, redémarrage — relecture tronquée à la dernière ligne complète (segment_truncated), époque plus grande (lease_acquired), chaîne sans trou ni fourche ; file d'ancrage effacée reconstruite au démarrage (anchoring_queue_rebuilt), alerte file_perdue (borne RA-9, RA-17, RA-25, RA-29, RA-66, RA-67)", async function () {
      if (!pret.call(this)) return;
      const evAvant = c.evenements(CONFIG);
      const nOps = c.journalExploitation().length;
      // Arrêt brutal.
      c.dc(["kill", "-s", "SIGKILL", "enregistreur"]);
      const segs = c.segments(CONFIG);
      const dernier = segs.at(-1);
      // Segment privé de sa dernière fin de ligne (fin de segment déchirée, EX-12.10).
      const info = JSON.parse(c.ecrireVolume("journal", `const fs=require("fs");const f="/v/${REP}/segments/${dernier}";const b=fs.readFileSync(f);console.log(JSON.stringify({octets:b.length,finLF:b.subarray(-1)[0]===10}));fs.writeFileSync(f,b.subarray(0,b.length-1));`).trim().split("\n").at(-1));
      expect(info.finLF, "le segment se terminait par une fin de ligne").to.equal(true);
      c.lancerSeul("enregistreur");
      await c.sain("enregistreur", 120000);
      let ops = c.journalExploitation().slice(nOps);
      const truncat = ops.find((l) => l.event === "segment_truncated" && l.data.segment === dernier);
      expect(truncat, "segment tronqué à la reprise").to.not.equal(undefined);
      const epoque = ops.find((l) => l.event === "lease_acquired");
      expect(Number(epoque.data.epoch), "nouvelle époque plus grande").to.be.above(1);
      expect(ops.some((l) => l.event === "startup"), "ligne startup au redémarrage").to.equal(true);
      // La chaîne reprend sans fourche : un appel passe et la relecture est continue.
      const r = c.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect(r.json.result.isError, JSON.stringify(r.json)).to.equal(false);
      const ev = c.evenements(CONFIG);
      expect(ev.every((e, i) => i === 0 || (e.seq === ev[i - 1].seq + 1 && e.prev_hash === N.hacherEvenement(ev[i - 1]))), "chaîne continue sans fourche").to.equal(true);
      expect(ev.length, "l'événement de la ligne déchirée est perdu, les suivants repartent").to.be.at.least(evAvant.length - 1);
      // File d'ancrage effacée pendant un arrêt : reconstruite, alerte file_perdue.
      // Précondition : un point de contrôle est au stockage avant l'arrêt. L'enregistreur produit ses points à la cadence
      // c_K (checkpoint_interval_s) ; quand ses deux marches de ce scénario tombent chacune entre deux limites de c_K,
      // il n'en a produit aucun, la file ne porte aucune demande, et rien n'est à recréer : CT-5 EX-8.12 ne recrée que
      // les demandes d'une période close et celles du dernier point d'une période ouverte, et ne lève file_perdue que si
      // au moins une demande est recréée. L'appel ci-dessus est un événement nouveau : le point suivant le couvre.
      const cK = JSON.parse(fs.readFileSync(path.join(passage, "configuration-pannes.json"), "utf8")).checkpoint_interval_s ?? 60;
      const point = await P.jusqua((3 * cK + 30) * 1000, () => c.points(CONFIG).length > 0, 1000);
      expect(point, `un point de contrôle est au stockage avant l'arrêt (attendu au plus ${3 * cK + 30} s)`).to.equal(true);
      const nOps2 = c.journalExploitation().length;
      c.dc(["stop", "-t", "10", "enregistreur"]);
      const file = JSON.parse(c.ecrireVolume("journal", `const fs=require("fs");const d="/v/ancrage";const l=fs.existsSync(d)?fs.readdirSync(d,{recursive:true}):[];console.log(JSON.stringify(l));fs.rmSync(d,{recursive:true,force:true});`).trim().split("\n").at(-1));
      expect(file.length, "la file d'ancrage portait des fichiers").to.be.above(0);
      c.lancerSeul("enregistreur");
      await c.sain("enregistreur", 120000);
      ops = c.journalExploitation().slice(nOps2);
      const rebuilt = ops.find((l) => l.event === "anchoring_queue_rebuilt");
      expect(rebuilt, "la file est reconstruite au démarrage").to.not.equal(undefined);
      expect(Number(rebuilt.data.recreated), "des demandes manquantes sont recréées").to.be.above(0);
      expect(ops.some((l) => l.event === "alerte_file_perdue"), "alerte file_perdue levée").to.equal(true);
    });

    it("TA-106 (MN-20, réponse retirée) : un mutant du démon (image) dont la relecture d'un segment accepte une dernière ligne incomplète au lieu de la tronquer ; après un arrêt brutal qui laisse une fin de segment déchirée, le mutant relit la ligne non terminée comme un événement complet au lieu de la tronquer (tué)", async function () {
      if (!pret.call(this)) return;
      const src = P.mutantImage("enregistreur", path.join(travail, "mut-mn20"), [{ fichier: "segments.mjs", ancien: 'if (!l.complete) {\n      tronquerOuCorrompre(k, "ligne_incomplete");\n      return;\n    }', nouveau: "if (false) {\n      tronquerOuCorrompre(k, \"ligne_incomplete\");\n      return;\n    }" }]);
      const cm = new P.CompositionPannes({ nom: c.nom, port: c.port, surcharges: [...c.surcharges, path.join(P.PANNES, "compose.mutant-enregistreur.yaml")], env: { NOORTRACE_PANNES_TRAVAIL: passage, NOORTRACE_PANNES_SRC_ENREGISTREUR: src } });
      cm.recreerEnregistreur();
      await cm.sain("enregistreur", 120000);
      // Écrire quelques événements, arrêter brutalement, déchirer la fin du dernier segment (retirer sa dernière fin de ligne).
      for (let k = 0; k < 2; k++) cm.appel("demo__claims.get", { claim_id: "2026-81044" });
      const evAvant = cm.evenements(CONFIG);
      cm.dc(["kill", "-s", "SIGKILL", "enregistreur"]);
      const dernier = cm.segments(CONFIG).at(-1);
      const info = JSON.parse(cm.ecrireVolume("journal", `const fs=require("fs");const f="/v/${REP}/segments/${dernier}";const b=fs.readFileSync(f);console.log(JSON.stringify({finLF:b.subarray(-1)[0]===10}));fs.writeFileSync(f,b.subarray(0,b.length-1));`).trim().split("\n").at(-1));
      expect(info.finLF).to.equal(true);
      const nOps = cm.journalExploitation().length;
      cm.lancerSeul("enregistreur");
      await cm.sain("enregistreur", 120000);
      const ops = cm.journalExploitation().slice(nOps);
      // Le mutant ne tronque pas la fin déchirée : aucune ligne segment_truncated, et l'événement de la ligne non terminée est gardé.
      expect(ops.some((l) => l.event === "segment_truncated"), "le mutant ne tronque pas la fin déchirée").to.equal(false);
      const evApres = cm.evenements(CONFIG);
      expect(evApres.length, "le mutant garde l'événement de la ligne non terminée (la référence l'aurait retiré)").to.equal(evAvant.length);
    });
  });

  // =========================================================================
  // TA-107 : un prestataire est injoignable.
  // =========================================================================
  describe("TA-107 (MN-55, MN-58, MN-62, MN-63, MN-76) : un prestataire est injoignable", function () {
    let c = null;
    let travail = null;
    let passage = null;
    let ctx = null;

    before(async function () {
      if (!etat.ok) {
        ctx = { condition: etat.condition };
        return;
      }
      travail = travailNeuf("ta107");
      passage = path.join(travail, "passage");
      c = new P.CompositionPannes({ nom: `noortrace-pannes-ta107-${process.pid}`, port: await P.portLibre(), surcharges: S("compose.configuration.yaml", "compose.prestataires.yaml"), env: { NOORTRACE_PANNES_TRAVAIL: passage } });
      P.ecrireConfigurationPannes(passage, { ancrage: P.documentAncragePannes([]) });
      const aut = P.preparerPrestataires(c, ["principal", "secours", "decalee"], passage);
      P.ecrireConfigurationPannes(passage, { ancrage: P.documentAncragePannes([P.prestataireInterne("principal", "principal", aut.principal), P.prestataireInterne("secours", "secours", aut.secours)], REGLAGES) });
      c.lancer(["agent-demo"]);
      ctx = { code: c.attendre("agent-demo", 300000), aut };
    });

    after(function () {
      if (c) c.demonter();
      if (travail) fs.rmSync(travail, { recursive: true, force: true });
    });

    function pret() {
      if (!ctx || ctx.condition) {
        P.enAttente(this, ctx?.condition ?? "composition non lancée");
        return false;
      }
      expect(ctx.code).to.equal(0);
      return true;
    }

    it("TA-107 (MN-62, MN-63, MN-76) : le prestataire RFC 3161 principal (serveur interne) est coupé pendant la contresignature des points — la relève par le secours (joint en TLS mutuel) est consignée (anchor_fallback, reason delai), le point est contresigné par le secours, et la capture n'est jamais bloquée (borne RA-50, RA-52, RA-55, RA-56, RA-65)", async function () {
      if (!pret.call(this)) return;
      const nOps = c.journalExploitation().length;
      c.dc(["stop", "-t", "5", "horodatage-principal"]);
      // La capture n'est jamais bloquée : un appel passe pendant la coupure.
      const r = c.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect(r.json.result.isError, JSON.stringify(r.json)).to.equal(false);
      const fallback = await P.jusqua(120000, () => c.journalExploitation().slice(nOps).find((l) => l.event === "anchor_fallback" && l.data.to === "tsa-secours") ?? false, 5000);
      expect(fallback, "relève vers le secours consignée").to.not.equal(false);
      expect(fallback.data.reason).to.equal("delai");
      const apres = await P.jusqua(120000, () => c.journalExploitation().slice(nOps).find((l) => l.event === "checkpoint_countersigned" && l.data.provider === "tsa-secours") ?? false, 5000);
      expect(apres, "point contresigné par le secours après la relève").to.not.equal(false);
    });

    it("TA-107 (MN-62, réponse retirée) : un mutant du composant d'ancrage (image) sans la relève par délai du planificateur (releverParDelai) ; sous la même coupure du principal, aucune anchor_fallback n'est consignée et aucune tentative n'est faite chez le secours pour la demande en cours (tué)", async function () {
      if (!pret.call(this)) return;
      const src = P.mutantImage("ancrage", path.join(travail, "mut-mn62"), [{ fichier: "planificateur/planificateur.mjs", ancien: "this.releverParDelai(req);", nouveau: ";" }]);
      const cm = new P.CompositionPannes({ nom: c.nom, port: c.port, surcharges: [...c.surcharges, path.join(P.PANNES, "compose.mutant-ancrage.yaml")], env: { NOORTRACE_PANNES_TRAVAIL: passage, NOORTRACE_PANNES_SRC_ANCRAGE: src } });
      cm.recreerEnregistreur();
      await cm.sain("enregistreur", 120000);
      cm.dc(["stop", "-t", "5", "horodatage-principal"]);
      const nOps = cm.journalExploitation().length;
      // Le composant sert comme la référence jusqu'à l'oracle : la capture n'est jamais bloquée pendant la coupure.
      const r = cm.appel("demo__claims.get", { claim_id: "2026-81044" });
      expect(r.json.result.isError, JSON.stringify(r.json)).to.equal(false);
      // Laisser passer bien plus que fallback_after_s (30 s) : avec la réponse, la relève aurait eu lieu ; sans elle, jamais.
      await P.pause(120000);
      const ops = cm.journalExploitation().slice(nOps);
      expect(ops.some((l) => l.event === "anchor_fallback"), "le mutant ne relève jamais vers le secours").to.equal(false);
      // Et le composant a bien tenté (et échoué) chez le principal coupé : la demande reste en attente, jamais relevée.
      expect(ops.some((l) => l.event === "anchor_response_rejected"), "le composant réessaie le prestataire coupé sans jamais relever").to.equal(true);
    });
  });
});

// ===========================================================================
// TA-96 : copie WORM du journal d'exploitation (CT-8 EX-11.22, PA-18) ; une
// ligne effacée du fichier local est détectée par comparaison à la copie.
// ===========================================================================
describe("CT-9 TA-96 (MN-96) : copie WORM du journal d'exploitation de la démonstration de référence", function () {
  this.timeout(1_200_000);
  let W = null;

  before(async function () {
    const w = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "enregistreur-worm", "outils.mjs")).href);
    const dispo = w.dockerDisponible([w.IMAGES.s3]);
    if (!etat.ok) {
      W = { condition: etat.condition };
      return;
    }
    if (!dispo.ok) {
      W = { condition: dispo.condition };
      return;
    }
    W = { w };
  });

  it("TA-96 (MN-96) : le journal d'exploitation de la démonstration est copié sur un support WORM (S3 à Object Lock, simulateur local) ; une ligne effacée du fichier local est détectée par comparaison à la copie verrouillée — réponse retirée (ne pas copier) : l'effacement passe inaperçu (tué)", async function () {
    if (!W || W.condition) {
      P.enAttente(this, W?.condition ?? "support WORM indisponible");
      return;
    }
    const w = W.w;
    const travail = travailNeuf("ta96");
    const c = new P.CompositionPannes({ nom: `noortrace-pannes-ta96-${process.pid}`, port: await P.portLibre() });
    let s3 = null;
    let prox = null;
    try {
      c.lancer(["agent-demo"]);
      expect(c.attendre("agent-demo", 300000)).to.equal(0);
      // Journal d'exploitation de la démonstration, lu depuis son volume.
      const lignes = c.lireVolume("exploitation", 'const fs=require("fs");for(const f of fs.readdirSync("/v").filter((n)=>n.endsWith(".ndjson")).sort())process.stdout.write(fs.readFileSync("/v/"+f))');
      const octets = Buffer.from(lignes, "utf8");
      expect(octets.length, "le journal d'exploitation porte des lignes").to.be.above(0);
      // Support WORM : S3 à Object Lock (mode COMPLIANCE), bucket neuf (CT-2 EX-12.16, EX-12.30).
      const tls = w.certificats(path.join(travail, "tls"));
      fs.writeFileSync(path.join(travail, "ca.pem"), tls.caPem);
      s3 = await w.demarrerS3(`noortrace-ta96-s3-${process.pid}`);
      prox = await w.mandataireTls(tls, { port: s3.port });
      const bucket = `noortrace-ta96-${process.pid}`;
      await w.creerBucketVerrouille(prox.origine, bucket, { ca: tls.caPem, jours: 4018, mode: "COMPLIANCE" });
      const { OperationsS3, identifiantsS3 } = await import(pathToFileURL(path.join(RACINE, "paquets", "enregistreur", "src", "index.mjs")).href);
      const ops = new OperationsS3({ worm: { type: "s3-object-lock", bucket, prefix: "exploitation/", mode: "compliance", retain_days: 4018, endpoint: prox.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false }, identifiants: identifiantsS3(new TextEncoder().encode(w.identifiantsRole("ecrivain"))), tls: { ca: tls.caPem }, delais: [20, 20, 20] });
      // Réponse en place : la copie WORM du journal d'exploitation (CT-8 EX-11.22).
      const cle = "exploitation/instance-demo/exploitation-0001.ndjson";
      const copie = await ops.copier(cle, octets);
      expect(copie.statut, JSON.stringify(copie)).to.equal(200);
      // L'administrateur efface une ligne du fichier local (MN-96) ; la copie WORM, verrouillée, ne change pas.
      const toutes = octets.toString("utf8").split("\n").filter(Boolean);
      const localAltere = Buffer.from(`${[...toutes.slice(0, 5), ...toutes.slice(6)].join("\n")}\n`, "utf8");
      // Comparaison local ↔ copie : la copie relue diffère du local.
      const relu = await ops.lire(cle);
      const egaliteAvant = Buffer.compare(relu.corps, octets) === 0;
      const egaliteApres = Buffer.compare(relu.corps, localAltere) === 0;
      expect(egaliteAvant, "la copie WORM est l'exacte image du journal local avant l'effacement").to.equal(true);
      expect(egaliteApres, "l'effacement est détecté : le local ne concorde plus avec la copie WORM").to.equal(false);
      // Réponse retirée : sans la copie WORM (tâche d'exploitation non exécutée, MN-96), aucun objet verrouillé ne témoigne
      // du journal avant l'effacement — une clé jamais copiée ne se relit pas (statut ≠ 200), la comparaison est impossible.
      const temoin = await ops.lire("exploitation/instance-demo/jamais-copie.ndjson").catch(() => ({ statut: 0 }));
      expect(temoin.statut, "sans la copie, aucun témoin de l'effacement (RA-80)").to.not.equal(200);
    } finally {
      await prox?.fermer();
      if (s3) w.arreterConteneur(`noortrace-ta96-s3-${process.pid}`);
      c.demonter();
      fs.rmSync(travail, { recursive: true, force: true });
    }
  });
});
}
