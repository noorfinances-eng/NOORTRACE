// Composant d'ancrage, lot D : manifeste d'instance (CT-4 §4.8, §6.8, RG-16 à
// RG-20) et ancre `registry` du réviseur dérivée (CT-6 §12.2), rejoués
// contre la famille `manifestes` de spec/vecteurs/ct-4 (manifestes valides
// de développement et de production, révisions, refus de RG-16 à RG-20) et
// éprouvés sur des formes hostiles.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { sha256Hex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const lireOctets = (p) => new Uint8Array(fs.readFileSync(path.join(RACINE, p)));

describe("ancrage, lot D : manifeste d'instance (CT-4 §4.8, RG-16 à RG-20)", function () {
  this.timeout(60000);

  it("copie embarquée du schéma instance-registre-v0 égale au fichier de spec/schemas ; les quatre contrats exigés", function () {
    expect(R.SCHEMA_INSTANCE_REGISTRE).to.deep.equal(lireJson("spec/schemas/instance-registre-v0.schema.json"));
    expect(R.NOMS_CONTRATS).to.deep.equal(["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]);
    const m = lireJson("spec/vecteurs/ct-4/manifestes/valides/production/instance-r2.json");
    expect(R.verifierManifesteSchema(m).valide).to.equal(true);
    expect(R.verifierManifesteSchema({ ...m, contracts: m.contracts.filter((c) => c.name !== "PeriodRegistry") }).valide).to.equal(false, "contrat manquant (contains)");
    expect(R.verifierManifesteSchema({ ...m, nature: "essai" }).valide).to.equal(false);
    expect(R.verifierManifesteSchema({ ...m, fees: { ...m.fees, max_fee_per_gas_wei: "2" } }).valide).to.equal(false);
  });

  it("manifestes.json : verdicts RG-16 à RG-20, premier refus et ancre registry dérivée de chacun des 24 cas", function () {
    const f = lireJson("spec/vecteurs/ct-4/manifestes/manifestes.json");
    expect(f.cases).to.have.length(24);
    for (const c of f.cases) {
      const i = c.input;
      const r = R.verifierManifesteRepertoire({
        repertoire: path.join(RACINE, "spec/vecteurs/ct-4", i.directory), fichiers: { manifest: i.manifest, previous: i.previous, genesis: i.genesis },
        racine: RACINE, ancre: i.registry ?? null,
      });
      expect(r.verdicts, c.id).to.deep.equal(c.expected.verdicts);
      if (c.refusal) expect(r.refusal, c.id).to.deep.equal(c.refusal);
      else expect(r.refusal, c.id).to.equal(null);
      if (c.expected.registry === null) expect(r.registry, c.id).to.equal(null);
      else {
        expect({ ...r.registry, source: null }, c.id).to.deep.equal({ ...c.expected.registry, source: null });
        // L'ancre dérivée a la forme de registry du fichier d'ancres de CT-6 §12.2 : chain_id, contracts, validator_sets, source.
        expect(Object.keys(r.registry).sort()).to.deep.equal(["chain_id", "contracts", "source", "validator_sets"]);
        if (r.verdicts["RG-18"] === "reussi") expect(R.lireJeux({ sets: r.registry.validator_sets }), c.id).to.not.equal(null);
      }
    }
  });

  it("ligne de règles (EX-4.3) du réseau de développement et SHA-256 de la genèse publiée (RG-17)", function () {
    const genese = lireJson("chain/config/alloc-dev.json");
    expect(R.ligneRegles(genese)).to.equal("chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1");
    expect(sha256Hex(lireOctets("chain/config/alloc-dev.json"))).to.equal("0x510e24e41cc401faa4e092338060cee0dc4629e5781a69af7a50b37edb6f4537");
    const m = lireJson("spec/vecteurs/ct-4/manifestes/valides/developpement/instance-r1.json");
    expect(R.verifierGenese(m, lireOctets("chain/config/alloc-dev.json")).statut).to.equal("reussi");
    expect(R.verifierGenese(m, lireOctets("spec/vecteurs/ct-4/manifestes/valides/production/genese.json")).motif).to.equal("genese_differente");
    expect(R.verifierGenese(m, new Uint8Array(0)).motif).to.equal("genese_differente");
  });

  it("jeux de validateurs (RG-18) et contrats (RG-19) sur des formes hostiles : trois validateurs, opérateur en double, intervalles, adresse de création, contrat en double", function () {
    const m = lireJson("spec/vecteurs/ct-4/manifestes/valides/production/instance-r1.json");
    const jeu = m.validator_sets[0];
    expect(R.verifierJeuxValidateurs(m).statut).to.equal("reussi");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, validators: jeu.validators.slice(0, 3), operators: jeu.operators.slice(0, 3) }] }).motif).to.equal("jeu_invalide");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, operators: [...jeu.operators.slice(0, 3), jeu.operators[0]] }] }).motif).to.equal("operateurs_incoherents");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, operators: jeu.operators.map((o) => ({ ...o, operator: "unique" })) }] }).motif).to.equal("domaine_de_panne");
    expect(R.verifierJeuxValidateurs({ ...m, nature: "developpement", validator_sets: [{ ...jeu, operators: jeu.operators.map((o) => ({ ...o, operator: "unique" })) }] }).statut).to.equal("reussi", "hors production, un seul opérateur est admis");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, from_height: 2 }] }).motif).to.equal("intervalles_incoherents");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, to_height: 10 }, { ...jeu, from_height: 10 }] }).motif).to.equal("intervalles_incoherents");
    expect(R.verifierJeuxValidateurs({ ...m, validator_sets: [{ ...jeu, valset_hash: "0x" + "00".repeat(32) }] }).motif).to.equal("valset_hash_different");
    const lecteur = { lire: (nom) => { try { return lireOctets(path.join("spec/vecteurs/ct-4/manifestes/valides/production", nom)); } catch { return null; } } };
    expect(R.verifierContrats(m, lecteur).statut).to.equal("reussi");
    expect(R.verifierContrats({ ...m, contracts: [...m.contracts, m.contracts[0]] }, lecteur).motif).to.equal("contrats_en_service");
    expect(R.verifierContrats({ ...m, contracts: m.contracts.map((c) => (c.name === "RecorderRegistry" ? { ...c, nonce: c.nonce + 1 } : c)) }, lecteur).motif).to.equal("adresse_creation");
    expect(R.verifierContrats({ ...m, contracts: m.contracts.map((c) => (c.name === "RecorderRegistry" ? { ...c, evidence: null } : c)) }, lecteur).motif).to.equal("preuve_absente", "production : evidence non nulle (EX-4.28)");
    expect(R.verifierContrats({ ...m, contracts: m.contracts.map((c) => (c.name === "RecorderRegistry" ? { ...c, evidence: { capture: { ...c.evidence.capture, sha256: "0x" + "11".repeat(32) } } } : c)) }, lecteur).motif).to.equal("preuve_invalide");
    expect(R.contratsEnService(m).PeriodRegistry.address).to.equal("0x9b9548e8fe03f5ea6250dee3ad4d8e8c5ddee3d5");
    expect(R.contratsEnService({ ...m, contracts: m.contracts.map((c) => ({ ...c, to_height: 5 })) })).to.equal(null);
    // Ancre dérivée (RG-20) : les quatre membres, sources des jeux reprises.
    const ancre = R.ancreReviseur(m);
    expect(ancre.chain_id).to.equal("noortrace-1912124-vecteur");
    expect(ancre.contracts.attestation_registry).to.equal("0x041071037487a4ec03765616ffd395cb277deb46");
    expect(ancre.validator_sets[0].source).to.equal(jeu.source);
    expect(R.ancreReviseur({ ...m, contracts: m.contracts.slice(1) })).to.equal(null);
    // Manifeste hors schéma, ou illisible : RG-16 schema, RG-17 à RG-20 échouent, aucune ancre.
    const r = R.verifierManifeste({ manifesteOctets: new TextEncoder().encode("{\"version\":0}"), geneseOctets: new Uint8Array(0), lecteur });
    expect(r.verdicts).to.deep.equal({ "RG-16": "echoue", "RG-17": "echoue", "RG-18": "echoue", "RG-19": "echoue", "RG-20": "echoue" });
    expect(r.refusal).to.deep.equal({ check: "RG-16", code: "schema" });
    expect(r.registry).to.equal(null);
    expect(R.verifierManifeste({ manifesteOctets: Uint8Array.of(0xff), geneseOctets: new Uint8Array(0), lecteur }).refusal.code).to.equal("schema");
  });
});
