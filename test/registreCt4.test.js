import { expect } from "chai";
import { network } from "hardhat";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { HDNodeWallet, Interface, Transaction, Wallet } from "ethers";
import { PROJECT_ROOT, bootstrapOrg, deployNoortrace } from "../scripts/lib/noortrace.mjs";
import * as C from "../scripts/lib/conventions-registre.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { verifierCertificat } from "../scripts/lib/certificat-commit.mjs";
import { ENTREES_GENEREES, certifierBloc, exemplesAnnotes, genererCt4, racineAdmise } from "../scripts/vecteurs/generer-ct4.mjs";
import { executer } from "../scripts/registre/noortrace-registre.mjs";

// CT-4 (spec/CT-4-registre.md) : conventions calculées hors chaîne (RG-1 à
// RG-20), vecteurs spec/vecteurs/ct-4 rejoués et régénérés à l'identique,
// exemples annotés de la spécification contre leurs schémas, outil de
// référence scripts/registre/noortrace-registre.mjs hors ligne (signer,
// exporter, verifier, publier-jeu) et sur le réseau Hardhat en mémoire
// (identifiant EVM 31337, manifeste d'essai noortrace-31337-essai,
// --sans-capture), avec au moins un refus par vérification OP- (EX-A.6), puis
// la capture (CP-1 à CP-6, 9.3), la reprise de 8.6 et l'examen d'EX-8.18
// derrière un pont JSON-RPC qui sert des en-têtes, reçus et certificats
// synthétiques signés par le jeu d'essai de A.2 (EX-A.6).

const REP = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-4");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const famille = (f) => lireJSON(path.join(REP, f));
const sha = (s) => "0x" + createHash("sha256").update(s).digest("hex");
const SCHEMAS = C.registreSchemasCt4(["instance-registre-v0", "inscription-client-v0", "operations-registre-v0", "registre-v0", "validateurs-v0", "ancres-confiance-v0", "politique-approbation-v0"].map((n) => lireJSON(path.join(PROJECT_ROOT, "spec", "schemas", `${n}.schema.json`))));
const ABI = (n) => new Interface(lireJSON(path.join(PROJECT_ROOT, "hh-artifacts", "contracts", `${n}.sol`, `${n}.json`)).abi);

const TEMPORAIRES = [];
function repertoireTemporaire(prefixe) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
  TEMPORAIRES.push(d);
  return d;
}

function conformeSortie(s) {
  const e = J.validerSchema(s, SCHEMAS[C.ID_SCHEMA_OPERATIONS], { registre: SCHEMAS, fragment: "#/$defs/sortie" });
  expect(e, JSON.stringify(e.slice(0, 3))).to.deep.equal([]);
}

/** Exécute une commande de l'outil en processus ; rend la sortie JSON (conforme à #/$defs/sortie). */
async function outil(args, env = {}) {
  let out = "";
  let err = "";
  const avant = {};
  for (const [k, v] of Object.entries(env)) {
    avant[k] = process.env[k];
    process.env[k] = v;
  }
  try {
    const { code } = await executer(args, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) } });
    const s = JSON.parse(out);
    conformeSortie(s);
    expect(s.exit_code).to.equal(code);
    s.stderr = err;
    return s;
  } finally {
    for (const [k, v] of Object.entries(avant)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function attendreRefus(s, code, result = "refuse") {
  expect(s.result, JSON.stringify(s.error)).to.equal(result);
  expect(s.error?.code, JSON.stringify(s.error)).to.equal(code);
}

function attendreReussite(s, result = "reussi") {
  expect(s.result, JSON.stringify(s.error)).to.equal(result);
  expect(s.error).to.equal(null);
}

// ---------------------------------------------------------------------------
// Vecteurs
// ---------------------------------------------------------------------------

describe("CT-4 — vecteurs spec/vecteurs/ct-4", function () {
  after(function () {
    for (const d of TEMPORAIRES.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it("la régénération dans un répertoire temporaire redonne les mêmes octets (EX-A.1)", function () {
    this.timeout(120000);
    const tmp = repertoireTemporaire("ct4-vecteurs-");
    genererCt4({ racine: tmp });
    const lister = (r, base = "") =>
      fs
        .readdirSync(path.join(r, base), { withFileTypes: true })
        .filter((e) => !(base === "" && e.name === "verificateur-independant"))
        .flatMap((e) => (e.isDirectory() ? lister(r, path.join(base, e.name)) : [path.join(base, e.name)]))
        .sort();
    const a = lister(REP);
    const b = lister(tmp);
    expect(b).to.deep.equal(a);
    for (const f of a) expect(fs.readFileSync(path.join(tmp, f)).equals(fs.readFileSync(path.join(REP, f))), f).to.equal(true);
  });

  it("le générateur refuse une racine qui porte une autre entrée et n'efface jamais verificateur-independant/", function () {
    this.timeout(120000);
    const etrangere = repertoireTemporaire("ct4-etranger-");
    fs.writeFileSync(path.join(etrangere, "autre.txt"), "à garder\n");
    expect(() => genererCt4({ racine: etrangere })).to.throw(/entrées que le générateur n'écrit pas/);
    expect(fs.readdirSync(etrangere)).to.deep.equal(["autre.txt"]);
    expect(() => racineAdmise(path.join(etrangere, "autre.txt"))).to.throw(/n'est pas un répertoire/);
    const avecGo = repertoireTemporaire("ct4-go-");
    fs.mkdirSync(path.join(avecGo, "verificateur-independant"));
    fs.writeFileSync(path.join(avecGo, "verificateur-independant", "main.go"), "package main\n");
    genererCt4({ racine: avecGo });
    expect(fs.readFileSync(path.join(avecGo, "verificateur-independant", "main.go"), "utf8")).to.equal("package main\n");
    expect(fs.readdirSync(avecGo).sort()).to.deep.equal([...ENTREES_GENEREES, "verificateur-independant"].sort());
  });

  it("chaque fichier de famille est conforme à fichier_vecteurs et chaque RG-, OP- hors ligne et CP- a un cas réussi et un cas en échec (EX-A.3)", function () {
    const fichiers = ["identifiants.json", "doctypes.json", "empreintes.json", "condenses.json", "appels.json", "transactions.json", "manifestes/manifestes.json", "demandes/demandes.json", "inscription/inscription.json", "capture/capture.json"];
    const reussis = new Set();
    const echoues = new Set();
    for (const f of fichiers) {
      const doc = famille(f);
      expect(J.validerSchema(doc, SCHEMAS[C.ID_SCHEMA_OPERATIONS], { registre: SCHEMAS, fragment: "#/$defs/fichier_vecteurs" }), f).to.deep.equal([]);
      for (const c of doc.cases) {
        if (c.expected?.verdicts) for (const [k, v] of Object.entries(c.expected.verdicts)) (v === "reussi" ? reussis : echoues).add(k);
        else if (c.refusal) echoues.add(c.refusal.check);
        else for (const k of c.checks) reussis.add(k);
        if (c.refusal) echoues.add(c.refusal.check);
      }
    }
    const exigees = [...Array.from({ length: 20 }, (_, i) => `RG-${i + 1}`), "OP-4", "OP-6", "OP-7", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"];
    for (const id of exigees) {
      expect(reussis.has(id), `${id} sans cas réussi`).to.equal(true);
      expect(echoues.has(id), `${id} sans cas en échec`).to.equal(true);
    }
    const index = fs.readFileSync(path.join(REP, "INDEX.md"), "utf8").split("\n");
    expect(index[2]).to.match(/^Produit par `scripts\/vecteurs\/generer-ct4\.mjs`/);
  });

  it("identifiants, doctypes et empreintes : RG-1 à RG-4 rejoués", function () {
    for (const c of famille("identifiants.json").cases) {
      const r = C.verifier(c.checks[0], () => (c.input.kind === "slug" ? C.orgIdDuSlug(c.input.value, { production: c.input.production }) : C.journalIdDuNom(c.input.value)));
      if (c.refusal) expect([r.status, r.check, r.code], c.id).to.deep.equal(["echoue", c.refusal.check, c.refusal.code]);
      else expect(r.valeurs, c.id).to.equal(c.expected.org_id ?? c.expected.journal_id);
    }
    for (const c of famille("doctypes.json").cases) {
      const r = C.verifier("RG-3", () => (c.input.label !== undefined ? C.docTypeDuLibelle(c.input.label) : C.libelleDuDocType(c.input.doc_type)));
      if (c.refusal) expect([r.status, r.code], c.id).to.deep.equal(["echoue", c.refusal.code]);
      else expect(r.valeurs, c.id).to.equal(c.expected.doc_type ?? c.expected.label);
    }
    for (const c of famille("empreintes.json").cases) {
      const r = C.verifier("RG-4", () => C.empreinteAncre({ ...c.input, declaree: c.input.fingerprint ?? null }));
      if (c.refusal) expect([r.status, r.code], c.id).to.deep.equal(["echoue", c.refusal.code]);
      else {
        expect(r.valeurs, c.id).to.deep.equal(c.expected);
        if (c.input.manifest) expect(J.hachageManifeste(lireJSON(path.join(PROJECT_ROOT, c.input.manifest)))).to.equal(c.input.period_hash);
      }
    }
    const attendu = lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "manifestes", "attendu.json"));
    for (const n of [1, 2, 3]) expect(famille("empreintes.json").cases.find((c) => c.id === `ct1-periode-${n}`).expected.fingerprint).to.equal(attendu.periodes[n - 1].anchor_fingerprint);
  });

  it("condenses : RG-5 à RG-13 rejoués, préimages aux longueurs de 6.6.2", function () {
    const longueurs = { "RG-6": 101, "RG-7": 198, "RG-8": 142, "RG-9": 138, "RG-10": 108, "RG-11": 148 };
    const fonctions = { "RG-6": C.condenseCloture, "RG-7": C.condenseInscription, "RG-8": C.condenseRevocation, "RG-9": C.condenseAncre, "RG-10": C.condenseRevocationAncre, "RG-11": C.condenseOperationJeu };
    for (const c of famille("condenses.json").cases) {
      const id = c.checks.includes("RG-13") ? "RG-13" : c.checks[0];
      let r;
      if (id === "RG-5") r = C.verifier("RG-5", () => C.verifierChampsCloture(c.input.period_meta, { precedente: c.input.previous ?? null, slug: c.input.slug ?? null, nom_journal: c.input.journal_name ?? null }));
      else if (fonctions[id]) r = C.verifier(id, () => fonctions[id](c.input));
      else if (id === "RG-12") r = C.verifier("RG-12", () => C.verifierSignature(c.input));
      else r = C.verifier("RG-13", () => C.verifierJeuSignatures({ digest: c.input.digest, signatures: c.input.signatures, membres: c.input.members, seuil: c.input.threshold }));
      if (c.refusal) expect([r.status, r.check, r.code], c.id).to.deep.equal(["echoue", c.refusal.check, c.refusal.code]);
      else {
        expect(r.status, `${c.id} : ${r.detail}`).to.equal("reussi");
        expect(r.valeurs, c.id).to.deep.equal(c.expected);
        if (longueurs[id]) expect(c.expected.preimage_length, c.id).to.equal(longueurs[id]);
      }
    }
  });

  it("appels : RG-14 rejoué et confronté à l'encodeur d'ethers (ABI de compilation) et aux transactions réelles de la capture", function () {
    const contratDe = { anchor: "AttestationRegistry", revoke: "AttestationRegistry", submitPeriod: "PeriodRegistry", registerRecorder: "RecorderRegistry", revokeRecorder: "RecorderRegistry", setCuratorSet: "CuratorSetRegistry", addCuratorSigned: "CuratorSet", removeCuratorSigned: "CuratorSet", setThresholdSigned: "CuratorSet", proposeAdminSigned: "CuratorSet", acceptAdminSigned: "CuratorSet" };
    const capture = lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "registre", "capture", "capture.json"));
    for (const c of famille("appels.json").cases) {
      if (Object.hasOwn(c.input, "contract")) {
        expect(C.argumentsConstructeur(c.input.contract, c.input.args), c.id).to.equal(c.expected.constructor_args);
        continue;
      }
      const r = C.verifier("RG-14", () => C.verifierDonneesAppel(c.input.function, c.input.args, c.input.calldata ?? null));
      if (c.refusal) {
        expect([r.status, r.code], c.id).to.deep.equal(["echoue", c.refusal.code]);
        continue;
      }
      expect(r.valeurs, c.id).to.deep.equal(c.expected);
      // Confrontation à ethers.
      const a = c.input.args;
      const sig = (s) => [s.v, s.r, s.s];
      const ordre = {
        anchor: () => [a.fingerprint, a.doc_type, a.issuer, sig(a.signature)],
        submitPeriod: () => [[a.period_meta.org_id, a.period_meta.journal_id, a.period_meta.period_hash, a.period_meta.root, a.period_meta.period_start, a.period_meta.period_end, a.period_meta.first_seq, a.period_meta.last_seq, a.period_meta.version, a.period_meta.uri], a.signatures.map(sig)],
        registerRecorder: () => [a.org_id, a.journal_id, a.chain_key, a.ed25519_public_key, a.signatures.map(sig)],
        revokeRecorder: () => [a.org_id, a.chain_key, a.signatures.map(sig)],
        setCuratorSet: () => [a.org_id, a.curator_set],
        addCuratorSigned: () => [a.curator, a.nonce, sig(a.signature)],
        removeCuratorSigned: () => [a.curator, a.nonce, sig(a.signature)],
        setThresholdSigned: () => [a.threshold, a.nonce, sig(a.signature)],
        proposeAdminSigned: () => [a.new_admin, a.nonce, sig(a.signature)],
        acceptAdminSigned: () => [a.nonce, sig(a.signature)],
      }[c.input.function]();
      expect(ABI(contratDe[c.input.function]).encodeFunctionData(c.input.function, ordre), c.id).to.equal(c.expected.calldata);
      if (c.input.transaction_hash) expect(capture.transactions.some((t) => t.hash === c.input.transaction_hash), c.id).to.equal(true);
    }
    // Constructeurs : confrontation à ethers.
    const cs = famille("appels.json").cases.find((c) => c.id === "constructeur-curator-set");
    expect(ABI("CuratorSet").encodeDeploy([cs.input.args.initial_admin, cs.input.args.members, cs.input.args.threshold])).to.equal(cs.expected.constructor_args);
  });

  it("transactions : RG-15 rejoué ; sérialisation confrontée à ethers ; transactions de la capture redonnées octet pour octet (EX-A.4)", function () {
    const cles = { "hardhat:0": Wallet.fromPhrase("test test test test test test test test test test test junk").privateKey };
    const constantes = famille("constantes.json");
    for (const e of constantes.recorders) cles[`sha256:${e.chain_key_seed}`] = e.chain_key_private;
    for (const c of famille("transactions.json").cases) {
      const r = C.verifier("RG-15", () => C.verifierTransaction(c.input.raw_transaction, c.input.context));
      if (c.refusal) expect([r.status, r.code], c.id).to.deep.equal(["echoue", c.refusal.code]);
      else expect(r.status, `${c.id} : ${r.detail}`).to.equal("reussi");
      if (c.expected) {
        const s = C.signerTransaction(c.input.fields, cles[c.input.signer_key]);
        expect(s, c.id).to.deep.equal(c.expected);
        expect(s.raw_transaction).to.equal(c.input.raw_transaction);
        const t = Transaction.from(s.raw_transaction);
        expect(t.hash, c.id).to.equal(s.transaction_hash);
        expect(t.from.toLowerCase(), c.id).to.equal(s.from);
        expect(t.unsignedHash, c.id).to.equal(s.signing_hash);
      }
    }
    const capture = lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "registre", "capture", "capture.json"));
    for (const t of capture.transactions) {
      const c = famille("transactions.json").cases.find((x) => x.id === `capture-${t.bloc}`);
      expect(c.expected.transaction_hash).to.equal(t.hash);
      expect(c.refusal).to.deep.equal({ check: "RG-15", code: "frais_non_conformes" });
    }
    expect(C.fraisRemplacement(1)).to.equal(2n);
    expect(C.fraisRemplacement(2)).to.equal(3n);
    expect(C.fraisRemplacement(3)).to.equal(4n);
    expect(C.fraisRemplacement(10)).to.equal(11n);
  });

  it("manifestes : RG-16 à RG-20 rejoués, ancre registry dérivée ; preuves de déploiement synthétiques vérifiées", function () {
    for (const c of famille("manifestes/manifestes.json").cases) {
      const rep = path.join(REP, c.input.directory);
      const r = C.verifierManifesteInstance({
        octets: fs.readFileSync(path.join(rep, c.input.manifest)),
        precedent: c.input.previous ? fs.readFileSync(path.join(rep, c.input.previous)) : null,
        genese: fs.readFileSync(path.join(rep, c.input.genesis)),
        lireCapture: (n) => (fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null),
        ancre: c.input.registry ?? null,
        schemas: SCHEMAS,
      });
      expect(r.verdicts, c.id).to.deep.equal(c.expected.verdicts);
      expect(r.registry, c.id).to.deep.equal(c.expected.registry);
      const premier = r.checks.find((x) => x.status !== "reussi");
      expect(premier ? { check: premier.check, code: premier.code } : null, c.id).to.deep.equal(c.refusal);
    }
    // L'ancre dérivée de l'exemple de 4.8 est celle du fichier d'ancres de test de CT-6, hors source.
    const dev = famille("manifestes/manifestes.json").cases.find((c) => c.id === "developpement-exemple").expected.registry;
    const ct6 = lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "ancres", "ancres-test.json")).registry;
    const sansSource = (x) => ({ ...x, source: null, validator_sets: x.validator_sets.map((j) => ({ ...j, source: null })) });
    expect(sansSource(dev)).to.deep.equal(sansSource(ct6));
  });

  it("demandes et dossiers : schéma, OP-4, OP-6 et OP-7 rejoués", function () {
    for (const c of famille("demandes/demandes.json").cases) {
      const r = C.verifierDemande(lireJSON(path.join(REP, c.input.file)), { schemas: SCHEMAS, membres: c.input.members, signataireAttendu: c.input.administrator });
      expect(r.refusal, `${c.id} : ${r.detail}`).to.deep.equal(c.refusal);
      if (!c.refusal) expect(lireJSON(path.join(REP, c.input.file)).digest).to.equal(c.expected.digest);
    }
    for (const c of famille("inscription/inscription.json").cases) {
      const r = C.verifierDossierInscription(lireJSON(path.join(REP, c.input.file)), { schemas: SCHEMAS, nature: c.input.nature, comptes: c.input.operator_accounts });
      expect(r.status === "reussi" ? null : { check: r.check, code: r.code }, `${c.id} : ${r.detail}`).to.deep.equal(c.refusal);
    }
    // L'approver_set du dossier fini est conforme au jeu_approbateurs de CT-3 (7.10).
    const fini = lireJSON(path.join(REP, "inscription", "valides", "relecteur-exemple-fini.json"));
    expect(J.validerSchema(fini.result.approver_set, SCHEMAS["https://noortrace.example/schemas/v0/politique-approbation.schema.json"], { registre: SCHEMAS, fragment: "#/$defs/jeu_approbateurs" })).to.deep.equal([]);
  });

  it("capture : CP-2 à CP-6 rejoués ; export des parties égal à spec/vecteurs/ct-6/registre/periode-1 (EX-9.8 à EX-9.10)", function () {
    const constantes = famille("constantes.json");
    for (const c of famille("capture/capture.json").cases) {
      const rep = path.join(REP, c.input.directory);
      const lire = (n) => (fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null);
      const validators = c.input.validators.startsWith("constantes.json") ? { validators: constantes.test_validators.validators.map(({ id, pubKeyHex }) => ({ id, pubKeyHex })) } : lireJSON(path.join(PROJECT_ROOT, c.input.validators));
      if (c.input.indexes) {
        const parties = C.exporterParties({ captures: c.input.indexes.map((n) => ({ index: lireJSON(path.join(rep, n)), lireFichier: lire })), jeux: [{ from_height: 1, to_height: null, validators: validators.validators, source: "jeu" }], source: "essai" });
        const ref = (n) => lireJSON(path.join(PROJECT_ROOT, c.expected.reference, n));
        const sansSource = (v) => JSON.parse(JSON.stringify(v, (k, x) => (k === "source" ? undefined : x)));
        expect(sansSource(parties.registre)).to.deep.equal(sansSource(ref("registre.json")));
        expect(sansSource(parties.certificat_commit)).to.deep.equal(sansSource(ref("certificat-commit.json")));
        expect(sansSource(parties.validateurs)).to.deep.equal(sansSource(ref("validateurs.json")));
        continue;
      }
      const r = C.verifierCapture({ index: lireJSON(path.join(rep, c.input.index)), lireFichier: lire, validators, bft_chain_id: c.input.bft_chain_id, schemas: SCHEMAS });
      expect(Object.fromEntries(r.checks.map((x) => [x.check, x.status])), c.id).to.deep.equal(c.expected.verdicts);
      const premier = r.checks.find((x) => x.status !== "reussi");
      expect(premier ? { check: premier.check, code: premier.code } : null, c.id).to.deep.equal(c.refusal);
    }
  });

  it("les exemples annotés de CT-4 sont conformes à leurs schémas ; ceux de 7.7, 7.10 et 9.4 sont dans les vecteurs", function () {
    const cibles = {
      "instance-registre": [C.ID_SCHEMA_INSTANCE, ""],
      "inscription-client": [C.ID_SCHEMA_INSCRIPTION, ""],
      "operations-registre": [C.ID_SCHEMA_OPERATIONS, ""],
      "operations-registre/sortie": [C.ID_SCHEMA_OPERATIONS, "#/$defs/sortie"],
      "operations-registre/demande_signature": [C.ID_SCHEMA_OPERATIONS, "#/$defs/demande_signature"],
      validateurs: ["https://noortrace.example/schemas/v0/validateurs.schema.json", ""],
    };
    const exemples = exemplesAnnotes();
    expect(exemples.map((e) => e.schema)).to.deep.equal(["instance-registre", "operations-registre/sortie", "operations-registre/demande_signature", "inscription-client", "operations-registre", "validateurs"]);
    for (const e of exemples) {
      const [id, frag] = cibles[e.schema];
      expect(J.validerSchema(e.valeur, SCHEMAS[id], { registre: SCHEMAS, fragment: frag }), e.schema).to.deep.equal([]);
    }
    expect(lireJSON(path.join(REP, "demandes", "valides", "inscription-rec-exemple-01.json"))).to.deep.equal(exemples[2].valeur);
    expect(lireJSON(path.join(REP, "inscription", "valides", "relecteur-exemple-fini.json"))).to.deep.equal(exemples[3].valeur);
    expect(lireJSON(path.join(REP, "capture", "periode-1", "capture-16648-0-inscription.json"))).to.deep.equal(exemples[4].valeur);
    // Le certificat de la preuve synthétique de production est signé par le jeu d'essai de A.2.
    const constantes = famille("constantes.json");
    const cert = lireJSON(path.join(REP, "manifestes", "valides", "production", "preuves", "certificat-101.json")).result;
    expect(verifierCertificat(cert, { validators: constantes.test_validators.validators.map(({ id, pubKeyHex }) => ({ id, pubKeyHex })) }).valide).to.equal(true);
  });
});

// ---------------------------------------------------------------------------
// Exigences vérifiables hors ligne (identifiants EX- et RG-, pour CT-9)
// ---------------------------------------------------------------------------

describe("CT-4 — exigences vérifiables hors ligne", function () {
  this.timeout(120000);
  after(function () {
    for (const d of TEMPORAIRES.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });
  const fichiers = ["identifiants.json", "doctypes.json", "empreintes.json", "condenses.json", "appels.json", "transactions.json", "manifestes/manifestes.json", "demandes/demandes.json", "inscription/inscription.json", "capture/capture.json"];
  const tous = () => fichiers.flatMap((f) => famille(f).cases.map((c) => ({ ...c, famille: f })));
  const regles = { 1: "6.2", 2: "6.4", 3: "6.5", 4: "6.7", 5: "6.8", 6: "6.9", 7: "6.10", 8: "6.11", 9: "6.12", 10: "6.13", 11: "6.14", 12: "6.15", 13: "6.16", 14: "6.17", 15: "6.18", 16: "6.19", 17: "6.20", 18: "6.21", 19: "6.22", 20: "6.23" };
  for (const n of Object.keys(regles)) {
    it(`RG-${n} (EX-${regles[n]}) : au moins un cas réussi et un cas en échec dans les vecteurs`, function () {
      const id = `RG-${n}`;
      const cas = tous().filter((c) => c.checks.includes(id) || c.refusal?.check === id);
      // Un cas refusé sur une autre vérification ne compte pas : l'évaluation s'arrête au premier échec (EX-A.3).
      const ok = cas.some((c) => (c.expected?.verdicts ? c.expected.verdicts[id] === "reussi" : c.refusal === null));
      const ko = cas.some((c) => (c.expected?.verdicts ? c.expected.verdicts[id] === "echoue" : c.refusal?.check === id));
      expect(ok, `${id} sans cas réussi`).to.equal(true);
      expect(ko, `${id} sans cas en échec`).to.equal(true);
    });
  }

  it("EX-4.2 : une genèse sans section rules, ou avec une émission, est refusée par RG-17", function () {
    const rep = path.join(REP, "manifestes", "valides", "production");
    const m = lireJSON(path.join(rep, "instance-r1.json"));
    const lire = (n) => (fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null);
    for (const [g, code] of [[{ chainId: m.evm_chain_id, alloc: [{ address: C.ADRESSE_NULLE.replace(/0$/, "1"), balanceWei: "1" }] }, "regles_invalides"], [{ ...lireJSON(path.join(rep, "genese.json")), rules: { ...lireJSON(path.join(rep, "genese.json")).rules, possEnabled: true } }, "regles_invalides"]]) {
      const octets = Buffer.from(JSON.stringify(g));
      const mm = { ...m, genesis: { ...m.genesis, sha256: J.sha256(octets) } };
      const r = C.verifierManifesteInstance({ octets: Buffer.from(JSON.stringify(mm)), genese: octets, lireCapture: lire, schemas: SCHEMAS });
      expect(r.checks.find((x) => x.check === "RG-17").code).to.equal(code);
    }
  });

  it("EX-4.3 : la ligne de règles du réseau de développement est celle de la spécification", function () {
    const g = lireJSON(path.join(PROJECT_ROOT, "chain", "config", "alloc-dev.json"));
    expect(C.ligneRegles(g)).to.equal("chainId=noortrace-2124-dev evmChainId=2124 possEnabled=false possRewards=0x0000000000000000000000000000000000000000 possCapWei=0 possGenesisUnix=0 possHalvingSec=0 possSubperiodSec=0 possEmissionModel=noormint/v1");
    expect(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-4-registre.md"), "utf8")).to.include(C.ligneRegles(g));
  });

  it("EX-4.6 : identifiant BFT noortrace-<n>-<suffixe>, le nombre étant l'identifiant EVM", function () {
    expect(C.nombreBFT("noortrace-2124-dev")).to.equal(2124);
    for (const faux of ["noortrace-02124-dev", "noortrace-2124-DEV", "noortrace-2124-", "noorchain-2-1-local", "noortrace-2124-abcdefghijklmnopq"]) expect(C.nombreBFT(faux), faux).to.equal(null);
  });

  it("EX-4.7, EX-4.28 : l'outil refuse un manifeste de production non inscrit, d'identifiant 2121 à 2124 ou sans preuve de déploiement", async function () {
    const t = repertoireTemporaire("ct4-prod-");
    const base = lireJSON(path.join(REP, "manifestes", "valides", "production", "instance-r1.json"));
    const variantes = {
      "absent.json": { ...base, evm_chain_id_registration: { ...base.evm_chain_id_registration, status: "absent" } },
      "sans-preuve.json": { ...base, contracts: base.contracts.map((c, i) => (i === 0 ? { ...c, evidence: null } : c)) },
      "evm-2124.json": { ...base, evm_chain_id: 2124, bft_chain_id: "noortrace-2124-vecteur" },
      "evm-2121.json": { ...base, evm_chain_id: 2121, bft_chain_id: "noortrace-2121-vecteur" },
    };
    for (const [n, v] of Object.entries(variantes)) {
      fs.writeFileSync(path.join(t, n), JSON.stringify(v));
      attendreRefus(await outil(["etat", "--instance", path.join(t, n), "--rpc", "http://127.0.0.1:1"]), "instance_illisible", "inutilisable");
    }
    fs.writeFileSync(path.join(t, "base.json"), JSON.stringify(base));
    attendreRefus(await outil(["etat", "--instance", path.join(t, "base.json"), "--rpc", "http://127.0.0.1:1"]), "noeud_injoignable", "inutilisable");
  });

  it("EX-4.14, EX-5.11 : aucun outil ne s'appuie sur finalized, safe ni eth_subscribe", function () {
    for (const f of ["scripts/registre/noortrace-registre.mjs", "scripts/lib/conventions-registre.mjs"]) {
      const texte = fs.readFileSync(path.join(PROJECT_ROOT, f), "utf8");
      expect(texte, f).to.not.match(/["'](finalized|safe)["']/);
      expect(texte, f).to.not.include("eth_subscribe");
    }
  });

  it("7.2 : hors du sous-ensemble de validerSchema, les schémas de CT-4 n'emploient que contains, dans instance-registre-v0, que RG-16 vérifie à part", function () {
    const inventaire = (n) => J.motsClesHorsSousEnsemble(lireJSON(path.join(PROJECT_ROOT, "spec", "schemas", `${n}.schema.json`)));
    expect(inventaire("instance-registre-v0")).to.deep.equal([0, 1, 2, 3].map((i) => ({ chemin: `#/properties/contracts/allOf/${i}/contains`, motCle: "contains" })));
    for (const n of ["inscription-client-v0", "operations-registre-v0"]) expect(inventaire(n), n).to.deep.equal([]);
    expect(J.MOTS_CLES_VALIDATION).to.include.members(["allOf", "oneOf", "pattern", "additionalProperties", "uniqueItems"]).and.to.not.include("contains");
  });

  it("EX-4.17, EX-5.1, EX-5.3 : limite de gaz au-delà de 2^24, contrat hors de la liste, adresse autre que CREATE(deployer, nonce) : manifeste refusé", async function () {
    const t = repertoireTemporaire("ct4-man-");
    const base = lireJSON(path.join(REP, "manifestes", "valides", "developpement", "instance-r1.json"));
    const variantes = {
      "gaz.json": { ...base, fees: { ...base.fees, gas_limit: 16777217 } },
      "poss.json": { ...base, contracts: [...base.contracts, { ...base.contracts[0], name: "PoSSRegistry" }] },
      "adresse.json": { ...base, contracts: base.contracts.map((c, i) => (i === 0 ? { ...c, nonce: 83 } : c)) },
    };
    for (const [n, v] of Object.entries(variantes)) {
      fs.writeFileSync(path.join(t, n), JSON.stringify(v));
      attendreRefus(await outil(["etat", "--instance", path.join(t, n), "--rpc", "http://127.0.0.1:1"]), "instance_illisible", "inutilisable");
    }
  });

  it("EX-4.19, EX-7.9 : provision P_k = provision_days × b_k + gas_limit et seuil de recomplément", function () {
    const p = C.provision(C.FRAIS_DEFAUT, C.BUDGET_JOUR_DEFAUT);
    expect(C.BUDGET_JOUR_DEFAUT).to.equal(10800000);
    expect(p.provision_wei).to.equal(327000000n);
    expect(p.refill_below_wei).to.equal(78600000n);
    expect(C.coutMaximal(C.FRAIS_DEFAUT)).to.equal(3000000n);
    expect(Number(10n ** 18n / 10800000n)).to.be.closeTo(9.3e10, 0.05e10);
  });

  it("EX-5.10, 5.7, 6.7.1 : sujets des événements et sélecteurs recalculés depuis les ABI de compilation", function () {
    const contrats = ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry", "CuratorSet"];
    const evenements = new Map();
    const fonctions = new Map();
    for (const n of contrats) {
      const i = ABI(n);
      i.forEachEvent((e) => evenements.set(e.name, e.topicHash));
      i.forEachFunction((f) => fonctions.set(f.name, f.selector));
    }
    for (const [nom, e] of Object.entries(C.EVENEMENTS)) expect(evenements.get(nom), nom).to.equal(e.topic);
    for (const [nom, sel] of Object.entries(C.SELECTEURS)) expect(fonctions.get(nom), nom).to.equal(sel);
  });

  it("EX-7.3 : une clé se désigne par env:<VARIABLE>", async function () {
    const t = repertoireTemporaire("ct4-env-");
    const ref = lireJSON(path.join(REP, "demandes", "valides", "inscription-rec-test-01.json"));
    const f = path.join(t, "d.json");
    fs.writeFileSync(f, JSON.stringify({ ...ref, signatures: [] }));
    const cle = HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/1").privateKey;
    const s = await outil(["signer", "--demande", f, "--cle", "env:NOORTRACE_CLE_ESSAI"], { NOORTRACE_CLE_ESSAI: cle });
    attendreReussite(s);
    expect(lireJSON(f).signatures).to.deep.equal(ref.signatures.filter((x) => x.signer === s.outputs.signer));
    attendreRefus(await outil(["signer", "--demande", f, "--cle", "env:NOORTRACE_VARIABLE_ABSENTE"]), "entree_illisible", "inutilisable");
  });

  it("EX-A.2 : la génération ne réécrit aucune entrée (CT-1, CT-6, genèse, jeu de validateurs)", function () {
    const entrees = ["spec/vecteurs/ct-1/manifestes", "spec/vecteurs/ct-1/cles", "spec/vecteurs/ct-6/registre/capture"].flatMap((d) => fs.readdirSync(path.join(PROJECT_ROOT, d)).map((f) => path.join(d, f))).concat(["test/fixtures/certificat-commit/validators.json", "chain/config/alloc-dev.json", "spec/CT-4-registre.md"]);
    const avant = Object.fromEntries(entrees.map((f) => [f, sha(fs.readFileSync(path.join(PROJECT_ROOT, f)))]));
    genererCt4({ racine: repertoireTemporaire("ct4-entrees-") });
    for (const f of entrees) expect(sha(fs.readFileSync(path.join(PROJECT_ROOT, f))), f).to.equal(avant[f]);
  });
});

// ---------------------------------------------------------------------------
// Outil de référence, hors ligne
// ---------------------------------------------------------------------------

describe("CT-4 — outil de référence hors ligne (signer, exporter, verifier, publier-jeu)", function () {
  this.timeout(120000);
  after(function () {
    for (const d of TEMPORAIRES.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it("publier-jeu rend la sortie de 9.7 pour le jeu du réseau de développement (RG-18, CT-6 EX-11.8)", async function () {
    const t = repertoireTemporaire("ct4-jeu-");
    const s = await outil(["publier-jeu", "--validateurs", "test/fixtures/certificat-commit/validators.json", "--depuis", "1", "--source", "chain/runtime/validators.json du réseau de développement noortrace-2124-dev, publié par l'exploitant", "--sortie", path.join(t, "jeu.json")]);
    attendreReussite(s);
    expect(s.outputs.validator_set_hash).to.equal("0xa47d27f6d6b0231de99fb6b587c266ef2ec50ba94a9976506c6ff98f9968b751");
    expect(lireJSON(path.join(t, "jeu.json"))).to.deep.equal(exemplesAnnotes().find((e) => e.schema === "validateurs").valeur);
    // Refus : jeu de trois validateurs (EX-4.11), fichier existant.
    const trois = path.join(t, "trois.json");
    fs.writeFileSync(trois, JSON.stringify({ validators: lireJSON(path.join(PROJECT_ROOT, "test/fixtures/certificat-commit/validators.json")).validators.slice(0, 3) }));
    attendreRefus(await outil(["publier-jeu", "--validateurs", trois, "--source", "x", "--sortie", path.join(t, "j2.json")]), "entree_illisible", "inutilisable");
    attendreRefus(await outil(["publier-jeu", "--validateurs", "test/fixtures/certificat-commit/validators.json", "--source", "x", "--sortie", path.join(t, "jeu.json")]), "usage", "inutilisable");
  });

  it("signer recalcule le condensé, signe en RFC 6979 et range les signatures ; refuse une demande altérée (OP-6) et un signataire en double (OP-7)", async function () {
    const t = repertoireTemporaire("ct4-signer-");
    const ref = lireJSON(path.join(REP, "demandes", "valides", "inscription-rec-test-01.json"));
    const f = path.join(t, "demande.json");
    fs.writeFileSync(f, JSON.stringify({ ...ref, signatures: [] }, null, 2));
    attendreReussite(await outil(["signer", "--demande", f, "--cle", "hardhat:1"]));
    const s2 = await outil(["signer", "--demande", f, "--cle", "hardhat:2"]);
    attendreReussite(s2);
    expect(s2.outputs.complete).to.equal(true);
    expect(lireJSON(f)).to.deep.equal(ref);
    attendreRefus(await outil(["signer", "--demande", f, "--cle", "hardhat:2"]), "signature_non_canonique");
    const altere = path.join(t, "alteree.json");
    fs.writeFileSync(altere, JSON.stringify({ ...ref, signatures: [], fields: { ...ref.fields, journal_id: C.journalIdDuNom("journal-principal") } }));
    const r = await outil(["signer", "--demande", altere, "--cle", "hardhat:1"]);
    attendreRefus(r, "condense_different");
    expect(r.error.check).to.equal("OP-6");
    // Une clé fichier: lisible par d'autres est refusée (EX-7.3).
    const cle = path.join(t, "cle.cle");
    fs.writeFileSync(cle, Wallet.createRandom().privateKey + "\n", { mode: 0o644 });
    fs.chmodSync(cle, 0o644);
    attendreRefus(await outil(["signer", "--demande", f, "--cle", `fichier:${cle}`]), "entree_illisible", "inutilisable");
    // Une demande d'un autre réseau ne se signe pas avec hardhat:.
    const autre = path.join(t, "autre.json");
    fs.writeFileSync(autre, JSON.stringify({ ...ref, evm_chain_id: 1912124, signatures: [] }));
    attendreRefus(await outil(["signer", "--demande", autre, "--cle", "hardhat:1"]), "reseau_non_developpement");
  });

  it("exporter rend, depuis les captures, les parties de la période 1 égales à celles de CT-6 ; verifier rend R-1 à R-10 réussies", async function () {
    const t = repertoireTemporaire("ct4-export-");
    const instance = path.join(REP, "manifestes", "valides", "developpement", "instance-r1.json");
    const manifeste = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "manifestes", "periode-1.json");
    const cles = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "dossiers", "valide-seq-7", "cles.json");
    const s = await outil(["exporter", "--instance", instance, "--manifeste", manifeste, "--cles", cles, "--captures", path.join(REP, "capture", "periode-1"), "--sortie", path.join(t, "parties")]);
    attendreReussite(s);
    expect(s.outputs.entries).to.deep.equal([{ role: "inscription", block_number: 16648 }, { role: "inscription", block_number: 16652 }, { role: "ancre", block_number: 16660 }, { role: "cloture", block_number: 16668 }]);
    const sansSource = (v) => JSON.parse(JSON.stringify(v, (k, x) => (k === "source" ? undefined : x)));
    for (const n of ["registre.json", "certificat-commit.json", "validateurs.json"]) expect(sansSource(lireJSON(path.join(t, "parties", n))), n).to.deep.equal(sansSource(lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "registre", "periode-1", n))));
    const v = await outil(["verifier", "--instance", instance, "--parties", path.join(t, "parties"), "--manifeste", manifeste, "--cles", cles]);
    attendreReussite(v);
    expect(v.outputs.anchor_source).to.equal("publication_exploitant");
    expect(v.outputs.verifications.map((x) => `${x.id}:${x.status}`)).to.deep.equal(Array.from({ length: 10 }, (_, i) => `R-${i + 1}:reussi`));
    // Avec le fichier d'ancres de test de CT-6.
    const v2 = await outil(["verifier", "--instance", instance, "--parties", path.join(t, "parties"), "--manifeste", manifeste, "--cles", cles, "--ancres", path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "ancres", "ancres-test.json")]);
    attendreReussite(v2);
    expect(v2.outputs.anchor_source).to.equal("fichier_ancres");
    // Période 2 : une autre clôture ; le contrôle 8 échoue sur R-9.
    const v3 = await outil(["verifier", "--instance", instance, "--parties", path.join(t, "parties"), "--manifeste", path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "manifestes", "periode-2.json"), "--cles", cles]);
    expect(v3.result).to.equal("echoue");
    expect(v3.outputs.verifications.find((x) => x.id === "R-9").status).to.equal("echoue");
    // Export refusé : capture altérée (EX-9.11).
    const alt = repertoireTemporaire("ct4-export-alt-");
    for (const f of fs.readdirSync(path.join(REP, "capture", "periode-1"))) fs.copyFileSync(path.join(REP, "capture", "periode-1", f), path.join(alt, f));
    fs.writeFileSync(path.join(alt, "certificat-16660.json"), fs.readFileSync(path.join(alt, "certificat-16652.json")));
    const e = await outil(["exporter", "--instance", instance, "--manifeste", manifeste, "--cles", cles, "--captures", alt, "--sortie", path.join(t, "parties-2")]);
    attendreRefus(e, "capture_incomplete");
  });

  it("la commande en ligne rend une sortie JSON et le code de sortie de EX-7.4", function () {
    const r = spawnSync(process.execPath, ["scripts/registre/noortrace-registre.mjs", "commande-inconnue"], { cwd: PROJECT_ROOT, encoding: "utf8" });
    expect(r.status).to.equal(2);
    const s = JSON.parse(r.stdout);
    conformeSortie(s);
    expect(s.error.code).to.equal("usage");
    const r2 = spawnSync(process.execPath, ["scripts/registre/noortrace-registre.mjs", "etat", "--rpc", "http://127.0.0.1:1", "--instance", path.join(REP, "manifestes", "valides", "developpement", "instance-r1.json")], { cwd: PROJECT_ROOT, encoding: "utf8" });
    expect(r2.status).to.equal(2);
    expect(JSON.parse(r2.stdout).error.code).to.equal("noeud_injoignable");
  });
});

// ---------------------------------------------------------------------------
// Outil de référence sur le réseau Hardhat en mémoire
// ---------------------------------------------------------------------------

/**
 * Pont HTTP JSON-RPC vers le fournisseur EIP-1193 d'une connexion Hardhat,
 * avec des crochets d'essai (intercepter, alterer) et, pour la capture, une
 * synthèse (syntheseCapture) consultée avant le fournisseur (EX-A.6).
 */
function pont(provider, crochets, synthese = null) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const r = JSON.parse(corps);
    let reponse;
    try {
      const f = crochets.intercepter?.(r.method, r.params);
      let result;
      if (f !== undefined) result = await f;
      else {
        const s = synthese ? await synthese(r.method, r.params) : undefined;
        result = s !== undefined ? s : await provider.request({ method: r.method, params: r.params });
      }
      reponse = { jsonrpc: "2.0", id: r.id, result: crochets.alterer ? crochets.alterer(r.method, r.params, result) : result };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: r.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

/**
 * Synthèse de capture (EX-A.6) : pour toute hauteur demandée, le pont sert un
 * en-tête dont `hash` est le BFTBlockHash, des reçus qui le portent et un
 * certificat signé par le jeu d'essai de A.2 (noor_getCommitCertificate),
 * ainsi que noor_txindexStatus à la tête ; le reste va au fournisseur.
 */
function syntheseCapture(provider, { jeu, bftChainId }) {
  const rpc = (method, params) => provider.request({ method, params });
  const cache = new Map();
  const rawDe = (t) => {
    const v = Number(BigInt(t.yParity ?? t.v));
    const tx = Transaction.from({ type: Number(BigInt(t.type)), chainId: BigInt(t.chainId), nonce: Number(BigInt(t.nonce)), maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas), maxFeePerGas: BigInt(t.maxFeePerGas), gasLimit: BigInt(t.gas), to: t.to ?? null, value: BigInt(t.value), data: t.input, accessList: t.accessList ?? [], signature: { r: t.r, s: t.s, v: 27 + (v >= 27 ? v - 27 : v) } });
    if (tx.hash !== t.hash) throw new Error(`transaction ${t.hash} non reconstruite (${tx.hash})`);
    return tx.serialized;
  };
  const bloc = async (q) => {
    const reel = await rpc("eth_getBlockByNumber", [q, true]);
    if (!reel) return null;
    const h = Number(BigInt(reel.number));
    if (cache.has(h)) return cache.get(h);
    const recus = [];
    for (const t of reel.transactions) recus.push(await rpc("eth_getTransactionReceipt", [t.hash]));
    const r = certifierBloc({ h, txsRaw: reel.transactions.map(rawDe), recus, bftChainId, validateurs: jeu, entete: reel });
    cache.set(h, r);
    return r;
  };
  return async (method, params) => {
    if (method === "eth_getBlockByNumber") {
      const b = await bloc(params[0]);
      return b ? b.entete : null;
    }
    if (method === "eth_getTransactionReceipt") {
      const r = await rpc(method, params);
      if (!r) return null;
      return { ...r, blockHash: (await bloc(r.blockNumber)).entete.hash };
    }
    if (method === "noor_getCommitCertificate") {
      const b = await bloc(params[0]);
      if (!b) throw Object.assign(new Error("unknown block"), { code: -32000 });
      return b.certificat;
    }
    if (method === "noor_txindexStatus") return { last_indexed_height: Number(BigInt(await rpc("eth_blockNumber", []))) };
    return undefined;
  };
}

/** Manifeste d'essai d'une instance Hardhat (EX-A.6), écrit dans E avec sa genèse ; `validators` : le jeu déclaré. */
function manifesteEssai(E, deploiement, { validators, source }) {
  const deployeur = deploiement.deployeur.toLowerCase();
  const genese = { chainId: 31337, alloc: [{ address: deployeur, balanceWei: "10000000000000000000000" }], rules: { chainId: "noortrace-31337-essai", ...C.REGLES_SANS_EMISSION } };
  fs.writeFileSync(path.join(E, "genese.json"), JSON.stringify(genese, null, 2) + "\n");
  const csr = deploiement.contrats.CuratorSetRegistry.adresse.toLowerCase();
  const manifeste = {
    version: 0,
    revision: 1,
    previous_sha256: null,
    published_at: "2026-10-25T00:00:00.000Z",
    nature: "developpement",
    bft_chain_id: "noortrace-31337-essai",
    evm_chain_id: 31337,
    evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-10-25T00:00:00.000Z", source: "réseau Hardhat en mémoire des tests (CT-4 EX-A.6)" },
    genesis: { file: "genese.json", sha256: J.sha256(fs.readFileSync(path.join(E, "genese.json"))), rules_line: C.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
    noorcore: { repository: "https://github.com/noorfinances-eng/noorchain-core", commit: "618fcef8805ef5b4cb9291a3dd97be710e489297", go_version: "1.26.9", patches: [], artifacts: [{ kind: "binaire", name: "sans objet : réseau Hardhat", sha256: C.HACHAGE_NUL, build: "sans objet" }] },
    validator_sets: [{ from_height: 1, to_height: null, validators, source, valset_hash: C.hachageJeuValidateurs(validators), operators: validators.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: null })) }],
    fees: { ...C.FRAIS_DEFAUT },
    contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n, i) => ({ name: n, address: deploiement.contrats[n].adresse.toLowerCase(), deployer: deployeur, nonce: i, constructor_args: n === "AttestationRegistry" ? [] : n === "CuratorSetRegistry" ? [deployeur] : [csr], transaction_hash: deploiement.contrats[n].tx, block_number: deploiement.contrats[n].bloc, block_hash: null, evidence: null, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
    source: "manifeste d'essai du réseau Hardhat en mémoire (CT-4 EX-A.6)",
  };
  const instance = path.join(E, "instance.json");
  fs.writeFileSync(instance, JSON.stringify(manifeste, null, 2) + "\n");
  expect(J.validerSchema(manifeste, SCHEMAS[C.ID_SCHEMA_INSTANCE], { registre: SCHEMAS })).to.deep.equal([]);
  return { manifeste, instance };
}

/** Demande de signature faite à la main, hors de condense (EX-8.19) : condensé recalculé, jeu et seuil donnés, aucune signature. */
async function demandeManuelle(conn, { operation, contract, fields, set, threshold }) {
  const b = await conn.provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] });
  const demande = { version: 0, operation, evm_chain_id: 31337, contract, fields, digest: null, eip191_digest: null, signer_set: { curator_set: set, threshold, height: Number(BigInt(b.number)), block_hash: String(b.hash).toLowerCase() }, signatures: [], prepared_at: new Date().toISOString() };
  const calc = C.condenseDeDemande(demande);
  return { ...demande, digest: calc.digest, eip191_digest: calc.eip191_digest };
}

/** Fabrique d'adresses neuves admises par EX-8.20 : la clé de chaîne d'une demande d'inscription préparée par condense (--demande). */
function fabriqueCleAdmise(R, repertoire) {
  let n = 0;
  return async () => {
    const adresse = Wallet.createRandom().address.toLowerCase();
    const d = lireJSON(path.join(repertoire(), "dossier.json"));
    const demande = path.join(repertoire(), `demande-approvisionnement-${++n}.json`);
    attendreReussite(await R(["condense", "inscription", "--org-id", d.organisation.org_id, "--journal-id", d.journals[0].journal_id, "--cle-chaine-adresse", adresse, "--cle-ed25519", sha(`cle ed25519 d'essai ${n}`), "--sortie", demande]));
    return { adresse, demande };
  };
}

describe("CT-4 — outil de référence sur le réseau Hardhat en mémoire (31337, --sans-capture)", function () {
  this.timeout(300000);
  let conn;
  let srv;
  let url;
  let E;
  let instance;
  let deploiement;
  let manifeste;
  const crochets = {};

  const R = (args) => outil([...args, "--instance", instance, "--rpc", url, "--sans-capture"]);
  const cleAdmise = fabriqueCleAdmise(R, () => E);
  const cleFichier = (nom, valeur) => {
    const f = path.join(E, nom);
    fs.writeFileSync(f, valeur + "\n", { mode: 0o600 });
    fs.chmodSync(f, 0o600);
    return `fichier:${f}`;
  };

  before(async function () {
    conn = await network.create();
    await conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
    ({ deployment: deploiement } = await deployNoortrace(conn.ethers, { networkName: "essai-ct4" }));
    ({ serveur: srv, url } = await pont(conn.provider, crochets));
    E = repertoireTemporaire("ct4-hardhat-");
    const val = lireJSON(path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json"));
    ({ manifeste, instance } = manifesteEssai(E, deploiement, { validators: val.validators, source: "jeu du réseau de développement, sans effet sur le réseau Hardhat" }));
  });

  after(async function () {
    srv?.close();
    for (const d of TEMPORAIRES.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  afterEach(function () {
    delete crochets.intercepter;
    delete crochets.alterer;
  });

  it("parcours de la section 7 : client inscrit, clé inscrite, racine ancrée, période close, reprise sans renvoi", async function () {
    const etat = await R(["etat"]);
    attendreReussite(etat);
    expect(etat.outputs.evm_chain_id).to.equal(31337);
    expect(etat.outputs.manifest_sha256).to.equal(J.sha256(fs.readFileSync(instance)));
    const ce = await outil(["cles-essai", "--instance", instance, "--sortie", path.join(E, "cles")]);
    attendreReussite(ce);
    for (const f of fs.readdirSync(path.join(E, "cles"))) expect(fs.statSync(path.join(E, "cles", f)).mode & 0o777, f).to.equal(0o600);
    const publiques = lireJSON(path.join(E, "cles", "cles-essai.json"));
    // cles-essai.json ne porte aucune valeur secrète (7.5).
    const texteCles = fs.readFileSync(path.join(E, "cles", "cles-essai.json"), "utf8");
    for (const f of fs.readdirSync(path.join(E, "cles")).filter((x) => /\.(cle|graine)$/.test(x))) expect(texteCles.includes(fs.readFileSync(path.join(E, "cles", f), "utf8").trim().slice(2)), f).to.equal(false);
    const prep = await R(["inscrire-client", "--preparer", "--org", "essai-ct4", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", path.join(E, "dossier.json")]);
    attendreReussite(prep);
    expect(prep.outputs.amount_wei).to.equal("327000000");
    expect(prep.checks.map((c) => c.id)).to.include.members(["OP-1", "OP-2", "OP-4", "OP-5"]);
    const ic = await R(["inscrire-client", "--dossier", path.join(E, "dossier.json"), "--exploitant", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreReussite(ic);
    expect(ic.outputs.set_read.members).to.deep.equal(lireJSON(path.join(E, "dossier.json")).approvers.members);
    attendreReussite(await R(["inscrire-client", "--dossier", path.join(E, "dossier.json"), "--exploitant", "hardhat:0", "--captures", path.join(E, "captures")]), "deja_fait");
    const set = ic.outputs.curator_set;
    const cs = await conn.ethers.getContractAt("CuratorSet", set);
    expect((await cs.admin()).toLowerCase()).to.equal(publiques.set_admin);
    expect(await conn.ethers.provider.getBalance(publiques.recorders[0].chain_key)).to.equal(327000000n);
    // Inscription de la clé.
    attendreReussite(await R(["condense", "inscription", "--dossier", path.join(E, "dossier.json"), "--key-id", "rec-essai-01", "--sortie", path.join(E, "demande-inscription.json")]));
    attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-inscription.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-1.cle")}`]));
    attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-inscription.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-2.cle")}`]));
    const cleChaine = `fichier:${path.join(E, "cles", "cle-chaine-rec-essai-01.cle")}`;
    const insc = await R(["inscrire-cle", "--demande", path.join(E, "demande-inscription.json"), "--cle-chaine", cleChaine, "--dossier", path.join(E, "dossier.json"), "--captures", path.join(E, "captures")]);
    attendreReussite(insc);
    expect(insc.outputs.is_active_recorder).to.equal(true);
    expect(BigInt(insc.outputs.cost_wei)).to.equal(BigInt(insc.outputs.gas_used));
    // L'envoi est écrit avant la soumission, au format envoi, et l'expéditeur est la clé de chaîne.
    const envois = fs.readdirSync(path.join(E, "captures")).filter((f) => f.startsWith("envoi-"));
    for (const f of envois) expect(J.validerSchema(lireJSON(path.join(E, "captures", f)), SCHEMAS[C.ID_SCHEMA_OPERATIONS], { registre: SCHEMAS, fragment: "#/$defs/envoi" })).to.deep.equal([]);
    const envoiInscription = lireJSON(path.join(E, "captures", `envoi-${insc.outputs.transaction_hash}.json`));
    expect(envoiInscription.from).to.equal(publiques.recorders[0].chain_key);
    expect(C.verifier("RG-15", () => C.verifierTransaction(envoiInscription.raw_transaction, { evm_chain_id: 31337, fees: manifeste.fees, objet: "appel", to: manifeste.contracts[3].address })).status).to.equal("reussi");
    // Période 1 : manifeste, ancre, clôture.
    const me = await R(["manifeste-essai", "--dossier", path.join(E, "dossier.json"), "--key-id", "rec-essai-01", "--graine", `graine:${path.join(E, "cles", "rec-essai-01.graine")}`, "--sortie", path.join(E, "periode-1")]);
    attendreReussite(me);
    const man1 = lireJSON(path.join(E, "periode-1", "manifeste.json"));
    expect(J.verifierManifeste(man1)).to.deep.equal([]);
    expect(J.verifierSignatureManifeste(man1, lireJSON(path.join(E, "periode-1", "manifeste.sig")), publiques.recorders[0].public_key)).to.equal(true);
    const man1F = path.join(E, "periode-1", "manifeste.json");
    const caps = path.join(E, "captures");
    const dossierF = path.join(E, "dossier.json");
    // Demande de clôture avant l'ancre : refusée par condense (EX-8.4, OP-10) ; le periodHash n'est remis à personne.
    const dc0 = await R(["condense", "cloture", "--manifeste", man1F, "--captures", caps, "--sortie", path.join(E, "demande-cloture-0.json")]);
    attendreRefus(dc0, "ancre_manquante");
    expect(dc0.error.check).to.equal("OP-10");
    expect(fs.existsSync(path.join(E, "demande-cloture-0.json"))).to.equal(false);
    // Clôture avant l'ancre, par une demande faite à la main et signée au seuil : refusée par clore (EX-8.4, OP-10).
    const aLaMain = await demandeManuelle(conn, { operation: "cloture", contract: manifeste.contracts[2].address, fields: { period_meta: C.metaDuManifeste(man1, "") }, set, threshold: 2 });
    fs.writeFileSync(path.join(E, "demande-cloture-main.json"), JSON.stringify(aLaMain));
    for (const i of [1, 3]) attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-cloture-main.json"), "--cle", `fichier:${path.join(E, "cles", `approbateur-${i}.cle`)}`]));
    const tot = await R(["clore", "--demande", path.join(E, "demande-cloture-main.json"), "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]);
    attendreRefus(tot, "ancre_manquante");
    expect(tot.error.check).to.equal("OP-10");
    const anc = await R(["ancrer", "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]);
    attendreReussite(anc);
    expect(anc.outputs.fingerprint).to.equal(me.outputs.fingerprint);
    attendreReussite(await R(["ancrer", "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]), "deja_fait");
    // Demande de clôture : expires_at à 24 h (EX-8.19) ; signer écrit les champs en clair sur la sortie d'erreur (EX-7.10).
    attendreReussite(await R(["condense", "cloture", "--manifeste", man1F, "--captures", caps, "--sortie", path.join(E, "demande-cloture-1.json")]));
    const demande1 = lireJSON(path.join(E, "demande-cloture-1.json"));
    expect(Date.parse(demande1.expires_at) - Date.now()).to.be.within(86400000 - 60000, 86400000 + 1000);
    const s1 = await outil(["signer", "--demande", path.join(E, "demande-cloture-1.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-1.cle")}`]);
    attendreReussite(s1);
    expect(s1.stderr).to.include("fields").and.to.include(J.hachageManifeste(man1));
    attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-cloture-1.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-3.cle")}`]));
    // Une demande expirée n'est pas signée (EX-8.19).
    fs.writeFileSync(path.join(E, "demande-expiree.json"), JSON.stringify({ ...demande1, expires_at: "2026-10-24T00:00:00.000Z" }));
    attendreRefus(await outil(["signer", "--demande", path.join(E, "demande-expiree.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-2.cle")}`]), "demande_expiree");
    // Une demande déjà relayée pour la même position avec un autre periodHash : demande_existante (EX-8.19).
    const autreHash = sha("autre periodHash");
    fs.writeFileSync(path.join(caps, `demande-cloture-${autreHash}.json`), JSON.stringify({ ...demande1, fields: { period_meta: { ...demande1.fields.period_meta, period_hash: autreHash } } }));
    const de = await R(["condense", "cloture", "--manifeste", man1F, "--captures", caps, "--sortie", path.join(E, "demande-cloture-1-bis.json")]);
    attendreRefus(de, "demande_existante");
    expect(de.error.check).to.equal("OP-10");
    fs.rmSync(path.join(caps, `demande-cloture-${autreHash}.json`));
    const clo = await R(["clore", "--demande", path.join(E, "demande-cloture-1.json"), "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]);
    attendreReussite(clo);
    // La demande relayée est copiée dans --captures (EX-8.19).
    expect(lireJSON(path.join(caps, `demande-cloture-${J.hachageManifeste(man1)}.json`)).digest).to.equal(demande1.digest);
    const pr = await conn.ethers.getContractAt("PeriodRegistry", manifeste.contracts[2].address);
    const p = await pr.getPeriod(BigInt(clo.outputs.period_id));
    expect(p.periodHash).to.equal(J.hachageManifeste(man1));
    expect(p.publisher.toLowerCase()).to.equal(publiques.recorders[0].chain_key);
    // Reprise : relancée, la commande rend deja_fait sans rien envoyer (EX-7.13).
    const nbEnvois = fs.readdirSync(path.join(E, "captures")).filter((f) => f.startsWith("envoi-")).length;
    attendreReussite(await R(["clore", "--demande", path.join(E, "demande-cloture-1.json"), "--manifeste", path.join(E, "periode-1", "manifeste.json"), "--cle-chaine", cleChaine, "--dossier", path.join(E, "dossier.json"), "--captures", path.join(E, "captures")]), "deja_fait");
    expect(fs.readdirSync(path.join(E, "captures")).filter((f) => f.startsWith("envoi-")).length).to.equal(nbEnvois);
    // Le dossier : chaque étape incluse (sans capture, result reste nul).
    const d = lireJSON(path.join(E, "dossier.json"));
    expect(J.validerSchema(d, SCHEMAS[C.ID_SCHEMA_INSCRIPTION], { registre: SCHEMAS })).to.deep.equal([]);
    expect(d.steps.map((s) => `${s.step}:${s.state}`)).to.deep.equal(["jeu_approbateurs:incluse", "assignation:incluse", "lecture_jeu:faite", "approvisionnement:incluse", "inscription:incluse", "premiere_ancre:incluse", "premiere_cloture:incluse"]);
    expect(d.steps.find((s) => s.step === "premiere_cloture").subject).to.equal(J.hachageManifeste(man1));
    expect(d.result).to.equal(null);
    // Période 2 : la suite (continuité, CT-1 §10.3).
    attendreReussite(await R(["manifeste-essai", "--dossier", path.join(E, "dossier.json"), "--key-id", "rec-essai-01", "--graine", `graine:${path.join(E, "cles", "rec-essai-01.graine")}`, "--evenements", "0", "--sortie", path.join(E, "periode-2")]));
    const man2 = lireJSON(path.join(E, "periode-2", "manifeste.json"));
    expect(man2.period_start).to.equal(man1.period_end);
    expect(man2.first_seq).to.equal(man1.last_seq + 1);
    expect(man2.prev_period_hash).to.equal(J.hachageManifeste(man1));
    expect(man2.root).to.equal(C.HACHAGE_NUL);
  });

  it("révocation, administration du jeu, réassignation et approvisionnement", async function () {
    const d = lireJSON(path.join(E, "dossier.json"));
    const cleChaineAdr = d.recorders[0].chain_key;
    // Administration du jeu : setThreshold 3 signé par la clé de gouvernance, relayé.
    const set = (await (await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address)).curatorSetOf(d.organisation.org_id)).toLowerCase();
    attendreReussite(await R(["condense", "administration_jeu", "--jeu", set, "--op", "CuratorSet.setThreshold", "--arg", "3", "--sortie", path.join(E, "demande-admin.json")]));
    attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-admin.json"), "--cle", `fichier:${path.join(E, "cles", "admin-jeu.cle")}`]));
    const adm = await R(["administrer-jeu", "--demande", path.join(E, "demande-admin.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreReussite(adm);
    expect(await (await conn.ethers.getContractAt("CuratorSet", set)).getThreshold()).to.equal(3n);
    // La même demande, rejouée : nonce périmé (OP-5).
    attendreRefus(await R(["administrer-jeu", "--demande", path.join(E, "demande-admin.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]), "pas_administrateur");
    // Révocation au nouveau seuil de 3.
    attendreReussite(await R(["condense", "revocation", "--org-id", d.organisation.org_id, "--cle-chaine-adresse", cleChaineAdr, "--sortie", path.join(E, "demande-revocation.json")]));
    for (const i of [1, 2]) attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-revocation.json"), "--cle", `fichier:${path.join(E, "cles", `approbateur-${i}.cle`)}`]));
    const insuff = await R(["revoquer-cle", "--demande", path.join(E, "demande-revocation.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreRefus(insuff, "signatures_insuffisantes");
    expect(insuff.error.check).to.equal("OP-7");
    attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-revocation.json"), "--cle", `fichier:${path.join(E, "cles", "approbateur-3.cle")}`]));
    attendreReussite(await R(["revoquer-cle", "--demande", path.join(E, "demande-revocation.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]));
    attendreReussite(await R(["revoquer-cle", "--demande", path.join(E, "demande-revocation.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]), "deja_fait");
    // Une ancre sous la clé révoquée est refusée (OP-9).
    attendreRefus(await R(["ancrer", "--manifeste", path.join(E, "periode-2", "manifeste.json"), "--cle-chaine", `fichier:${path.join(E, "cles", "cle-chaine-rec-essai-01.cle")}`, "--dossier", path.join(E, "dossier.json"), "--captures", path.join(E, "captures")]), "cle_chaine_non_inscrite");
    // Une nouvelle inscription de la clé révoquée est refusée (OP-8).
    attendreReussite(await R(["condense", "inscription", "--dossier", path.join(E, "dossier.json"), "--key-id", "rec-essai-01", "--sortie", path.join(E, "demande-reinscription.json")]));
    for (const i of [1, 2, 3]) attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-reinscription.json"), "--cle", `fichier:${path.join(E, "cles", `approbateur-${i}.cle`)}`]));
    attendreRefus(await R(["inscrire-cle", "--demande", path.join(E, "demande-reinscription.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "captures")]), "cle_revoquee");
    // Réassignation (EX-8.10) : --confirmer, --demande (SHA-256 consigné), nouveau jeu qui répond comme un CuratorSet et administré par la même clé de gouvernance.
    const publiques = lireJSON(path.join(E, "cles", "cles-essai.json"));
    const fabrique = await conn.ethers.getContractFactory("CuratorSet");
    const autre = await fabrique.deploy(publiques.set_admin, [Wallet.createRandom().address], 1);
    await autre.waitForDeployment();
    const autreAdmin = await fabrique.deploy(deploiement.deployeur, [Wallet.createRandom().address], 1);
    await autreAdmin.waitForDeployment();
    const demandeEcrite = path.join(E, "demande-reassignation.txt");
    fs.writeFileSync(demandeEcrite, "Demande de réassignation du jeu de essai-ct4, consignée (EX-8.10).\n");
    const base = ["reassigner", "--org-id", d.organisation.org_id, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures")];
    attendreRefus(await R([...base, "--jeu", await autre.getAddress(), "--confirmer", C.HACHAGE_NUL, "--demande", demandeEcrite]), "usage", "inutilisable");
    attendreRefus(await R([...base, "--jeu", await autre.getAddress(), "--confirmer", d.organisation.org_id]), "usage", "inutilisable");
    const ja = await R([...base, "--jeu", await autreAdmin.getAddress(), "--confirmer", d.organisation.org_id, "--demande", demandeEcrite]);
    attendreRefus(ja, "jeu_invalide");
    expect(ja.error.check).to.equal("OP-5");
    attendreRefus(await R([...base, "--jeu", manifeste.contracts[0].address, "--confirmer", d.organisation.org_id, "--demande", demandeEcrite]), "jeu_invalide");
    const re = await R([...base, "--jeu", await autre.getAddress(), "--confirmer", d.organisation.org_id, "--demande", demandeEcrite]);
    attendreReussite(re);
    expect(re.outputs.previous).to.equal(set);
    expect(re.outputs.request_sha256).to.equal(J.sha256(fs.readFileSync(demandeEcrite)));
    expect(re.outputs.new_set.admin).to.equal(publiques.set_admin);
    // Approvisionnement (8.7, EX-8.20) : clé de chaîne du dossier déjà au-dessus du seuil ; clé d'une demande d'inscription ; destinataire hors d'EX-8.20 ; budget non entier ; trésorerie d'un autre compte ; plafond du manifeste.
    attendreReussite(await R(["approvisionner", "--vers", cleChaineAdr, "--dossier", path.join(E, "dossier.json"), "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures")]), "deja_fait");
    const neuve = await cleAdmise();
    const ap = await R(["approvisionner", "--vers", neuve.adresse, "--demande", neuve.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreReussite(ap);
    expect(ap.outputs.amount_wei).to.equal(String(30 * 1000 + 3000000));
    expect(ap.outputs.admitted_as).to.equal("demande");
    const horsListe = await R(["approvisionner", "--vers", Wallet.createRandom().address, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreRefus(horsListe, "compte_inattendu");
    expect(horsListe.error.check).to.equal("OP-5");
    attendreRefus(await R(["approvisionner", "--vers", neuve.adresse, "--demande", neuve.demande, "--budget-jour", "12.5", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures")]), "usage", "inutilisable");
    attendreRefus(await R(["approvisionner", "--vers", neuve.adresse, "--demande", neuve.demande, "--tresorerie", "hardhat:1", "--captures", path.join(E, "captures")]), "compte_inattendu");
    const plafonne = path.join(E, "instance-plafond.json");
    fs.writeFileSync(plafonne, JSON.stringify({ ...manifeste, fees: { ...manifeste.fees, max_daily_budget_gas: 500 } }));
    const pe = await outil(["approvisionner", "--vers", neuve.adresse, "--demande", neuve.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures"), "--instance", plafonne, "--rpc", url, "--sans-capture"]);
    attendreRefus(pe, "provision_excessive");
    expect(pe.error.check).to.equal("OP-3");
  });

  it("refus des vérifications OP-1 à OP-12 (au moins un par vérification, EX-A.6)", async function () {
    // OP-1 : autre chaîne ; code absent ; défaut du réseau de développement hors 2124 ; --sans-capture hors 31337.
    crochets.alterer = (m, _p, result) => (m === "eth_chainId" ? "0x7a6a" : result);
    attendreRefus(await R(["etat"]), "chaine_differente");
    delete crochets.alterer;
    const autre = path.join(E, "instance-autre.json");
    fs.writeFileSync(autre, JSON.stringify({ ...manifeste, evm_chain_id: 31338, bft_chain_id: "noortrace-31338-essai" }));
    attendreRefus(await outil(["etat", "--instance", autre, "--rpc", url, "--sans-capture"]), "usage", "inutilisable");
    const sansCode = path.join(E, "instance-sans-code.json");
    const m2 = JSON.parse(JSON.stringify(manifeste));
    m2.contracts[0].nonce = 99;
    m2.contracts[0].address = C.adresseCreation(m2.contracts[0].deployer, 99);
    fs.writeFileSync(sansCode, JSON.stringify(m2));
    attendreRefus(await outil(["etat", "--instance", sansCode, "--rpc", url, "--sans-capture"]), "code_absent");
    const dep = path.join(E, "deployments");
    fs.mkdirSync(dep, { recursive: true });
    fs.writeFileSync(path.join(dep, "noorcore.json"), JSON.stringify({ reseau: "noorcore", chainId: "2124", deployeur: deploiement.deployeur, contrats: deploiement.contrats }));
    attendreRefus(await outil(["etat", "--rpc", url], { NOORTRACE_DEPLOYMENTS_DIR: dep, NOORTRACE_VALIDATORS_FILE: path.join(PROJECT_ROOT, "test", "fixtures", "certificat-commit", "validators.json") }), "reseau_non_developpement");
    // OP-1 sans --sans-capture : binaire sans noor_getCommitCertificate (-32601), puis jeu de validateurs différent.
    crochets.intercepter = (m) => (m === "noor_getCommitCertificate" ? Promise.reject(Object.assign(new Error("the method noor_getCommitCertificate does not exist/is not available"), { code: -32601 })) : undefined);
    attendreRefus(await outil(["etat", "--instance", instance, "--rpc", url]), "entree_illisible", "inutilisable");
    crochets.intercepter = (m) => (m === "noor_getCommitCertificate" ? Promise.resolve({ chainId: "noortrace-31337-essai", valsetHash: C.HACHAGE_NUL }) : undefined);
    attendreRefus(await outil(["etat", "--instance", instance, "--rpc", url]), "jeu_validateurs_different");
    // OP-2 : nœud injoignable ; suiveur (index local vide).
    attendreRefus(await outil(["etat", "--instance", instance, "--rpc", "http://127.0.0.1:1", "--sans-capture"]), "noeud_injoignable", "inutilisable");
    crochets.intercepter = (m) => (m === "noor_getCommitCertificate" ? Promise.resolve({ chainId: "noortrace-31337-essai", valsetHash: manifeste.validator_sets[0].valset_hash }) : m === "noor_txindexStatus" ? Promise.resolve({ last_indexed_height: 0 }) : undefined);
    attendreRefus(await outil(["etat", "--instance", instance, "--rpc", url]), "noeud_suiveur");
    delete crochets.intercepter;
    // OP-4 : organisation existante ; seuil hors bornes.
    const prepare = (org, seuil, sortieF) => R(["inscrire-client", "--preparer", "--org", org, "--journal", "journal-principal", "--seuil", String(seuil), "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", sortieF]);
    attendreRefus(await prepare("essai-ct4", 2, path.join(E, "d-existant.json")), "organisation_existante");
    attendreRefus(await prepare("essai-ct4-bis", 4, path.join(E, "d-seuil.json")), "jeu_invalide");
    // OP-5 : compte inattendu pour la trésorerie.
    attendreRefus(await R(["inscrire-client", "--preparer", "--org", "essai-ct4-ter", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--tresorerie", "hardhat:1", "--sortie", path.join(E, "d-tre.json")]), "compte_inattendu");
    // Nouveau client pour les refus OP-3 et OP-6 à OP-11.
    attendreReussite(await prepare("essai-ct4-refus", 2, path.join(E, "d2.json")));
    attendreReussite(await R(["inscrire-client", "--dossier", path.join(E, "d2.json"), "--exploitant", "hardhat:0", "--captures", path.join(E, "c2")]));
    const d2 = lireJSON(path.join(E, "d2.json"));
    const cles = Object.fromEntries(["approbateur-1", "approbateur-2", "approbateur-3"].map((n) => [n, `fichier:${path.join(E, "cles", `${n}.cle`)}`]));
    // OP-6 : demande altérée (condensé).
    attendreReussite(await R(["condense", "inscription", "--dossier", path.join(E, "d2.json"), "--key-id", "rec-essai-01", "--sortie", path.join(E, "d2-demande.json")]));
    // Le dossier d2 reprend la clé Ed25519 et la clé de chaîne du premier client : une autre organisation, donc admises.
    for (const k of ["approbateur-1", "approbateur-2"]) attendreReussite(await outil(["signer", "--demande", path.join(E, "d2-demande.json"), "--cle", cles[k]]));
    fs.writeFileSync(path.join(E, "d2-alteree.json"), JSON.stringify({ ...lireJSON(path.join(E, "d2-demande.json")), digest: sha("x") }));
    attendreRefus(await R(["inscrire-cle", "--demande", path.join(E, "d2-alteree.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]), "condense_different");
    // OP-7 : signataire hors du jeu.
    const horsJeu = { ...lireJSON(path.join(E, "d2-demande.json")) };
    horsJeu.signatures = C.rangerSignatures([horsJeu.signatures[0], C.signerCondense(Wallet.createRandom().privateKey, horsJeu.digest)]);
    fs.writeFileSync(path.join(E, "d2-hors-jeu.json"), JSON.stringify(horsJeu));
    attendreRefus(await R(["inscrire-cle", "--demande", path.join(E, "d2-hors-jeu.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]), "signataire_hors_jeu");
    // OP-3 : envoi en attente pour l'expéditeur, puis solde insuffisant.
    const enAttente = { from: deploiement.deployeur.toLowerCase(), to: manifeste.contracts[3].address, nonce: 999, type: 2, max_fee_per_gas: "1", max_priority_fee_per_gas: "1", gas_limit: "3000000", value: "0", raw_transaction: "0x02c0", transaction_hash: sha("en attente"), submitted_to: [url], submitted_at: "2026-10-25T00:00:00.000Z" };
    fs.writeFileSync(path.join(E, "c2", `envoi-${enAttente.transaction_hash}.json`), JSON.stringify(enAttente));
    attendreRefus(await R(["inscrire-cle", "--demande", path.join(E, "d2-demande.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]), "transaction_en_attente");
    fs.rmSync(path.join(E, "c2", `envoi-${enAttente.transaction_hash}.json`));
    const vide = cleFichier("vide.cle", Wallet.createRandom().privateKey);
    attendreRefus(await R(["inscrire-cle", "--demande", path.join(E, "d2-demande.json"), "--expediteur", vide, "--captures", path.join(E, "c2")]), "solde_insuffisant");
    // Inscription réelle ; rejouée, la même demande rend deja_fait, dossier ou non (7.11).
    attendreReussite(await R(["inscrire-cle", "--demande", path.join(E, "d2-demande.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]));
    attendreReussite(await R(["inscrire-cle", "--demande", path.join(E, "d2-demande.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]), "deja_fait");
    // OP-8 : la même clé de chaîne sous un autre journal et une autre clé Ed25519 (cle_deja_active, réservé au cas où les champs diffèrent).
    attendreReussite(await R(["condense", "inscription", "--org-id", d2.organisation.org_id, "--journal-id", C.journalIdDuNom("journal-second"), "--cle-chaine-adresse", d2.recorders[0].chain_key, "--cle-ed25519", sha("autre cle ed25519"), "--sortie", path.join(E, "d2-demande-journal.json")]));
    for (const k of ["approbateur-1", "approbateur-2"]) attendreReussite(await outil(["signer", "--demande", path.join(E, "d2-demande-journal.json"), "--cle", cles[k]]));
    const dejaActive = await R(["inscrire-cle", "--demande", path.join(E, "d2-demande-journal.json"), "--relayeur", "hardhat:0", "--captures", path.join(E, "c2")]);
    attendreRefus(dejaActive, "cle_deja_active");
    expect(dejaActive.error.check).to.equal("OP-8");
    // OP-9 : empreinte prise par un autre émetteur (8.3).
    attendreReussite(await R(["manifeste-essai", "--dossier", path.join(E, "d2.json"), "--key-id", "rec-essai-01", "--graine", `graine:${path.join(E, "cles", "rec-essai-01.graine")}`, "--sortie", path.join(E, "d2-p1")]));
    const man = lireJSON(path.join(E, "d2-p1", "manifeste.json"));
    const f = C.empreinteAncre({ org_id: man.org_id, journal_id: man.journal_id, period_hash: J.hachageManifeste(man) }).fingerprint;
    const tiers = Wallet.createRandom();
    const att = await conn.ethers.getContractAt("AttestationRegistry", manifeste.contracts[0].address);
    const sig = C.signerCondense(tiers.privateKey, C.condenseAncre({ chain_id: 31337, contract: manifeste.contracts[0].address, fingerprint: f, doc_type: C.DOC_TYPE_PERIODE }).digest);
    await (await att.anchor(f, C.DOC_TYPE_PERIODE, tiers.address, { v: sig.v, r: sig.r, s: sig.s })).wait();
    const sq = await R(["ancrer", "--manifeste", path.join(E, "d2-p1", "manifeste.json"), "--cle-chaine", `fichier:${path.join(E, "cles", "cle-chaine-rec-essai-01.cle")}`, "--dossier", path.join(E, "d2.json"), "--captures", path.join(E, "c2")]);
    attendreRefus(sq, "empreinte_squattee");
    // OP-10 : période non vide à racine nulle (RG-5).
    fs.mkdirSync(path.join(E, "d2-hs"));
    const hs2 = { ...man, root: C.HACHAGE_NUL };
    fs.writeFileSync(path.join(E, "d2-hs", "racine-nulle.json"), JSON.stringify(hs2));
    attendreRefus(await R(["condense", "cloture", "--manifeste", path.join(E, "d2-hs", "racine-nulle.json"), "--captures", path.join(E, "c2"), "--sortie", path.join(E, "d2-hs", "demande.json")]), "periode_invalide");
    // OP-10 par clore : la même période, demandée à la main et signée au seuil sans passer par condense, est refusée (periode_invalide).
    const set2 = (await (await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address)).curatorSetOf(d2.organisation.org_id)).toLowerCase();
    const dm = await demandeManuelle(conn, { operation: "cloture", contract: manifeste.contracts[2].address, fields: { period_meta: C.metaDuManifeste(hs2, "") }, set: set2, threshold: 2 });
    fs.writeFileSync(path.join(E, "d2-hs", "demande-main.json"), JSON.stringify(dm));
    for (const k of ["approbateur-1", "approbateur-2"]) attendreReussite(await outil(["signer", "--demande", path.join(E, "d2-hs", "demande-main.json"), "--cle", cles[k]]));
    const pi = await R(["clore", "--demande", path.join(E, "d2-hs", "demande-main.json"), "--manifeste", path.join(E, "d2-hs", "racine-nulle.json"), "--relayeur", "hardhat:0", "--dossier", path.join(E, "d2.json"), "--captures", path.join(E, "c2")]);
    attendreRefus(pi, "periode_invalide");
    expect(pi.error.check).to.equal("OP-10");
    // Destinataires admis par EX-8.20 pour les refus qui suivent (préparés avant les crochets).
    const [x11, x12, x13, x14, x15] = [await cleAdmise(), await cleAdmise(), await cleAdmise(), await cleAdmise(), await cleAdmise()];
    const approvisionner = (x, rep, ...reste) => R(["approvisionner", "--vers", x.adresse, "--demande", x.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, rep), ...reste]);
    // OP-11 : reçu de status 0x0 (point RPC qui le sert ainsi) : echoue, transaction_annulee.
    crochets.alterer = (m, _p, result) => (m === "eth_getTransactionReceipt" && result ? { ...result, status: "0x0" } : result);
    const a11 = await approvisionner(x11, "c2");
    attendreRefus(a11, "transaction_annulee", "echoue");
    expect(a11.error.check).to.equal("OP-11");
    // OP-12 : relecture à la hauteur du bloc qui contredit l'écriture.
    crochets.alterer = (m, params, result) => (m === "eth_getBalance" && typeof params[1] === "string" && params[1].startsWith("0x") ? "0x0" : result);
    const a12 = await approvisionner(x12, "c2");
    attendreRefus(a12, "transaction_annulee", "echoue");
    expect(a12.error.check).to.equal("OP-12");
    delete crochets.alterer;
    // Une transaction refusée à l'entrée par tous les points : rien n'est parti, l'envoi est mis de côté.
    crochets.intercepter = (m) => (m === "eth_sendRawTransaction" ? Promise.reject(Object.assign(new Error("transaction underpriced"), { code: -32000 })) : undefined);
    attendreRefus(await approvisionner(x13, "c2"), "transaction_refusee");
    expect(fs.readdirSync(path.join(E, "c2")).some((x) => x.startsWith("refus-envoi-"))).to.equal(true);
    delete crochets.intercepter;
    // Sans reçu dans le délai : incertain (code 3), reprise par capturer --envoi.
    crochets.intercepter = (m) => (m === "eth_sendRawTransaction" ? Promise.resolve(sha("jamais incluse")) : m === "eth_getTransactionReceipt" ? Promise.resolve(null) : undefined);
    const inc = await approvisionner(x14, "c4", "--delai", "1");
    attendreRefus(inc, "recu_absent", "incertain");
    expect(inc.exit_code).to.equal(3);
    delete crochets.intercepter;
    // Un envoi sans issue bloque l'expéditeur (OP-3, EX-8.14).
    attendreRefus(await approvisionner(x15, "c4"), "transaction_en_attente");
  });

  it("EX-5.6, EX-7.7 : bootstrapOrg admet un administrateur du jeu, la clé de gouvernance ; défaut inchangé", async function () {
    const [admin] = await conn.ethers.getSigners();
    const csr = await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address);
    const gouvernance = Wallet.createRandom().address;
    const approbateurs = [Wallet.createRandom().address, Wallet.createRandom().address];
    const a = await bootstrapOrg(conn.ethers, { curatorSetRegistry: csr, admin, setAdmin: gouvernance, slug: "gouvernance-ct4", approvers: approbateurs, threshold: 1 });
    expect(await a.curatorSet.admin()).to.equal(gouvernance);
    expect(a.record.admin).to.equal(gouvernance);
    const b = await bootstrapOrg(conn.ethers, { curatorSetRegistry: csr, admin, slug: "gouvernance-ct4-defaut", approvers: approbateurs, threshold: 1 });
    expect(await b.curatorSet.admin()).to.equal(admin.address);
  });

  it("EX-3.3 : le relayeur transmet les champs tels qu'ils ont été signés", async function () {
    const demande = lireJSON(path.join(E, "demande-inscription.json"));
    const inscription = lireJSON(path.join(E, "dossier.json")).steps.find((x) => x.step === "inscription");
    const envoi = lireJSON(path.join(E, "captures", `envoi-${inscription.transaction_hash}.json`));
    expect(envoi.to).to.equal(manifeste.contracts[3].address);
    const tx = C.decoderTransaction(envoi.raw_transaction);
    const sigs = C.signaturesPourTransaction(demande, 2).map(({ v, r, s: ss }) => ({ v, r, s: ss }));
    expect(tx.data).to.equal(C.donneesAppel("registerRecorder", { ...demande.fields, signatures: sigs }));
  });

  it("EX-4.1 : un dossier qui désigne une autre instance est refusé", async function () {
    const d = lireJSON(path.join(E, "dossier.json"));
    const f = path.join(E, "dossier-autre-instance.json");
    fs.writeFileSync(f, JSON.stringify({ ...d, instance: { ...d.instance, genesis_sha256: sha("autre genese") } }, null, 2));
    attendreRefus(await R(["inscrire-client", "--dossier", f, "--exploitant", "hardhat:0", "--captures", path.join(E, "captures")]), "chaine_differente");
  });

  it("EX-4.15, EX-4.17, EX-8.13 : chaque envoi est de type 2, frais 1 et 1 wei, limite fees.gas_limit, liste d'accès vide, value nul hors approvisionnement", function () {
    const envois = fs.readdirSync(path.join(E, "captures")).filter((f) => f.startsWith("envoi-"));
    expect(envois.length).to.be.greaterThan(5);
    for (const f of envois) {
      const e = lireJSON(path.join(E, "captures", f));
      const tx = C.decoderTransaction(e.raw_transaction);
      expect([tx.chain_id, tx.max_fee_per_gas, tx.max_priority_fee_per_gas, tx.gas_limit, tx.access_list.length], f).to.deep.equal([31337n, 1n, 1n, 3000000n, 0]);
      if (tx.data !== "0x") expect(tx.value, f).to.equal(0n);
    }
  });

  it("EX-5.7 : les approbateurs et la clé de gouvernance n'ont reçu aucune provision", async function () {
    const publiques = lireJSON(path.join(E, "cles", "cles-essai.json"));
    for (const a of [...publiques.approvers, publiques.set_admin]) expect(await conn.ethers.provider.getBalance(a), a).to.equal(0n);
  });

  it("EX-6.1 : les condensés recalculés sont ceux que rendent les fonctions de lecture des contrats", async function () {
    const [rr, pr, ar] = [3, 2, 0].map((i) => manifeste.contracts[i].address);
    const R_ = await conn.ethers.getContractAt("RecorderRegistry", rr);
    const P_ = await conn.ethers.getContractAt("PeriodRegistry", pr);
    const A_ = await conn.ethers.getContractAt("AttestationRegistry", ar);
    const org = C.orgIdDuSlug("condenses-ct4");
    const j = C.journalIdDuNom("journal-01");
    const ck = Wallet.createRandom().address.toLowerCase();
    const ed = sha("cle ed25519 d'essai");
    expect(await R_.registerDigest(org, j, ck, ed)).to.equal(C.condenseInscription({ chain_id: 31337, contract: rr, org_id: org, journal_id: j, chain_key: ck, ed25519_public_key: ed }).digest);
    const meta = { ...C.metaDuManifeste(lireJSON(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "manifestes", "periode-2.json")), "urn:noortrace:periode:0002") };
    expect(await P_.periodDigest([meta.org_id, meta.journal_id, meta.period_hash, meta.root, meta.period_start, meta.period_end, meta.first_seq, meta.last_seq, meta.version, meta.uri])).to.equal(C.condenseCloture({ chain_id: 31337, contract: pr, period_meta: meta }).digest);
    expect(await A_.anchorDigest(ed, C.DOC_TYPE_PERIODE)).to.equal(C.condenseAncre({ chain_id: 31337, contract: ar, fingerprint: ed, doc_type: C.DOC_TYPE_PERIODE }).digest);
    expect(await A_.revokeDigest(ed)).to.equal(C.condenseRevocationAncre({ chain_id: 31337, contract: ar, fingerprint: ed }).digest);
    const set = (await (await conn.ethers.getContractAt("CuratorSetRegistry", manifeste.contracts[1].address)).curatorSetOf(lireJSON(path.join(E, "dossier.json")).organisation.org_id)).toLowerCase();
    const CS = await conn.ethers.getContractAt("CuratorSet", set);
    for (const op of Object.keys(C.OPERATIONS_JEU)) {
      const arg = C.argumentOperationJeu(op, op.endsWith("setThreshold") ? "2" : ck);
      expect(await CS.adminOpDigest(C.keccakTexte(op), arg, 7n), op).to.equal(C.condenseOperationJeu({ chain_id: 31337, contract: set, op, arg, nonce: "7" }).digest);
    }
  });

  it("EX-7.1, EX-7.5 : --captures est exigé pour envoyer ; l'envoi est écrit avant la soumission", async function () {
    attendreRefus(await R(["approvisionner", "--vers", Wallet.createRandom().address, "--tresorerie", "hardhat:0"]), "usage", "inutilisable");
    const rep = path.join(E, "c5");
    const x = await cleAdmise();
    let vuAvant = null;
    crochets.intercepter = (m, params) => {
      if (m === "eth_sendRawTransaction") {
        const h = C.hex(C.keccak(C.octets(params[0])));
        vuAvant = fs.existsSync(path.join(rep, `envoi-${h}.json`));
      }
      return undefined;
    };
    attendreReussite(await R(["approvisionner", "--vers", x.adresse, "--demande", x.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", rep]));
    expect(vuAvant).to.equal(true);
  });

  it("EX-7.12 : le dossier remis au client ne porte aucune valeur secrète", function () {
    const texte = fs.readFileSync(path.join(E, "dossier.json"), "utf8");
    for (const f of fs.readdirSync(path.join(E, "cles")).filter((x) => /\.(cle|graine)$/.test(x))) expect(texte.includes(fs.readFileSync(path.join(E, "cles", f), "utf8").trim().slice(2)), f).to.equal(false);
  });

  it("EX-8.2 : une clôture hors de la suite du journal est refusée (OP-10, discontinuité)", async function () {
    const m2 = lireJSON(path.join(E, "periode-2", "manifeste.json"));
    fs.mkdirSync(path.join(E, "periode-2-decalee"), { recursive: true });
    fs.writeFileSync(path.join(E, "periode-2-decalee", "manifeste.json"), JSON.stringify({ ...m2, period_start: m2.period_start + 3600, period_end: m2.period_end + 3600 }));
    attendreRefus(await R(["condense", "cloture", "--manifeste", path.join(E, "periode-2-decalee", "manifeste.json"), "--captures", path.join(E, "captures"), "--sortie", path.join(E, "periode-2-decalee", "demande.json")]), "discontinuite_temporelle");
    fs.writeFileSync(path.join(E, "periode-2-decalee", "sequence.json"), JSON.stringify({ ...m2, first_seq: m2.first_seq + 1, last_seq: m2.last_seq + 1 }));
    attendreRefus(await R(["condense", "cloture", "--manifeste", path.join(E, "periode-2-decalee", "sequence.json"), "--captures", path.join(E, "captures"), "--sortie", path.join(E, "periode-2-decalee", "demande-2.json")]), "discontinuite_sequence");
  });

  it("EX-8.15, EX-8.17 : la transaction est soumise, en mêmes octets, à chaque point --rpc ; son coût est gasUsed × 1 wei", async function () {
    const x = await cleAdmise();
    const second = {};
    const vus = [];
    second.intercepter = (m, params) => {
      if (m === "eth_sendRawTransaction") vus.push(params[0]);
      return undefined;
    };
    crochets.intercepter = (m, params) => {
      if (m === "eth_sendRawTransaction") vus.push(params[0]);
      return undefined;
    };
    const { serveur, url: url2 } = await pont(conn.provider, second);
    try {
      const s = await outil(["approvisionner", "--vers", x.adresse, "--demande", x.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "c6"), "--instance", instance, "--rpc", `${url},${url2}`, "--sans-capture"]);
      attendreReussite(s);
      expect(vus.length).to.equal(2);
      expect(vus[0]).to.equal(vus[1]);
      expect(s.outputs.cost_wei).to.equal(String(s.outputs.gas_used));
    } finally {
      serveur.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Capture derrière un pont synthétique (EX-A.6)
// ---------------------------------------------------------------------------

describe("CT-4 — capture derrière un pont synthétique (CP-1 à CP-6, 9.3, 8.6, EX-7.16, EX-8.18 ; EX-A.6)", function () {
  this.timeout(600000);
  let conn;
  let srv;
  let url;
  let E;
  let instance;
  let deploiement;
  let manifeste;
  let synthese;
  const crochets = {};
  const jeu = lireJSON(path.join(REP, "constantes.json")).test_validators.validators;
  const R = (args) => outil([...args, "--instance", instance, "--rpc", url]);
  const cleAdmise = fabriqueCleAdmise(R, () => E);
  const capturesDe = (rep) => fs.readdirSync(rep).filter((f) => /^capture-\d+-\d+-[a-z_]+\.json$/.test(f)).sort();

  before(async function () {
    conn = await network.create();
    await conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
    ({ deployment: deploiement } = await deployNoortrace(conn.ethers, { networkName: "essai-ct4-capture" }));
    synthese = syntheseCapture(conn.provider, { jeu, bftChainId: "noortrace-31337-essai" });
    ({ serveur: srv, url } = await pont(conn.provider, crochets, synthese));
    E = repertoireTemporaire("ct4-capture-");
    ({ manifeste, instance } = manifesteEssai(E, deploiement, { validators: jeu.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source: "jeu d'essai de CT-4 A.2, qui signe les certificats synthétiques du pont des tests (EX-A.6)" }));
  });

  after(async function () {
    srv?.close();
    for (const d of TEMPORAIRES.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  afterEach(function () {
    delete crochets.intercepter;
    delete crochets.alterer;
  });

  it("parcours de la section 7 avec capture : chaque étape capturee ou faite, result rempli (EX-7.15, EX-7.16), chaque index conforme à CP-2 à CP-6 et porteur de son envoi", async function () {
    const etat = await R(["etat"]);
    attendreReussite(etat);
    expect(etat.checks.map((c) => `${c.id}:${c.status}`)).to.include.members(["OP-1:reussi", "OP-2:reussi"]);
    attendreReussite(await outil(["cles-essai", "--instance", instance, "--sortie", path.join(E, "cles")]));
    const dossierF = path.join(E, "dossier.json");
    const caps = path.join(E, "captures");
    attendreReussite(await R(["inscrire-client", "--preparer", "--org", "essai-capture", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", dossierF]));
    const ic = await R(["inscrire-client", "--dossier", dossierF, "--exploitant", "hardhat:0", "--captures", caps]);
    attendreReussite(ic);
    expect(ic.checks.filter((c) => c.id.startsWith("CP-")).map((c) => `${c.id}:${c.status}`)).to.deep.equal(["CP-1:reussi", "CP-2:reussi", "CP-3:reussi", "CP-4:reussi", "CP-5:reussi", "CP-6:reussi"]);
    let d = lireJSON(dossierF);
    expect(d.steps.map((s) => `${s.step}:${s.state}`)).to.deep.equal(["jeu_approbateurs:capturee", "assignation:capturee", "lecture_jeu:faite", "approvisionnement:capturee", "inscription:a_faire", "premiere_ancre:a_faire", "premiere_cloture:a_faire"]);
    expect(d.steps[0].contract).to.equal(ic.outputs.curator_set);
    expect(ic.outputs.set_deployment.capture).to.equal(d.steps[0].capture);
    attendreReussite(await R(["inscrire-client", "--dossier", dossierF, "--exploitant", "hardhat:0", "--captures", caps]), "deja_fait");
    // Inscription, ancre et clôture, capturées.
    const cleChaine = `fichier:${path.join(E, "cles", "cle-chaine-rec-essai-01.cle")}`;
    attendreReussite(await R(["condense", "inscription", "--dossier", dossierF, "--key-id", "rec-essai-01", "--sortie", path.join(E, "demande-inscription.json")]));
    for (const i of [1, 2]) attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-inscription.json"), "--cle", `fichier:${path.join(E, "cles", `approbateur-${i}.cle`)}`]));
    const insc = await R(["inscrire-cle", "--demande", path.join(E, "demande-inscription.json"), "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]);
    attendreReussite(insc);
    expect(insc.outputs.capture).to.match(/^capture-\d+-0-inscription\.json$/);
    expect(insc.outputs.retention.retention_heights).to.equal(3000000);
    attendreReussite(await R(["manifeste-essai", "--dossier", dossierF, "--key-id", "rec-essai-01", "--graine", `graine:${path.join(E, "cles", "rec-essai-01.graine")}`, "--sortie", path.join(E, "periode-1")]));
    const man1F = path.join(E, "periode-1", "manifeste.json");
    attendreReussite(await R(["ancrer", "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]));
    attendreReussite(await R(["condense", "cloture", "--manifeste", man1F, "--captures", caps, "--sortie", path.join(E, "demande-cloture-1.json")]));
    for (const i of [1, 3]) attendreReussite(await outil(["signer", "--demande", path.join(E, "demande-cloture-1.json"), "--cle", `fichier:${path.join(E, "cles", `approbateur-${i}.cle`)}`]));
    const clo = await R(["clore", "--demande", path.join(E, "demande-cloture-1.json"), "--manifeste", man1F, "--cle-chaine", cleChaine, "--dossier", dossierF, "--captures", caps]);
    attendreReussite(clo);
    d = lireJSON(dossierF);
    expect(J.validerSchema(d, SCHEMAS[C.ID_SCHEMA_INSCRIPTION], { registre: SCHEMAS })).to.deep.equal([]);
    expect(d.steps.map((s) => s.state)).to.deep.equal(["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]);
    expect(d.result).to.not.equal(null);
    expect(d.result.curator_set).to.equal(ic.outputs.curator_set);
    expect(d.result.recorders[0].registration.capture).to.equal(insc.outputs.capture);
    expect(d.result.set_read.members).to.deep.equal(d.approvers.members);
    // Chaque index passe CP-2 à CP-6 à la relecture, porte l'envoi écrit avant la soumission, et l'issue de l'envoi est connue.
    const index = capturesDe(caps);
    expect(index.length).to.equal(6);
    const lire = (n) => (fs.existsSync(path.join(caps, n)) ? fs.readFileSync(path.join(caps, n)) : null);
    for (const f of index) {
      const idx = lireJSON(path.join(caps, f));
      const v = C.verifierCapture({ index: idx, lireFichier: lire, validators: { validators: manifeste.validator_sets[0].validators }, bft_chain_id: manifeste.bft_chain_id, schemas: SCHEMAS });
      expect(v.checks.map((c) => `${c.check}:${c.status}`), f).to.deep.equal(["CP-2:reussi", "CP-3:reussi", "CP-4:reussi", "CP-5:reussi", "CP-6:reussi"]);
      expect(idx.sending.transaction_hash, f).to.equal(idx.transaction_hash);
      expect(idx.validator_set_hash, f).to.equal(manifeste.validator_sets[0].valset_hash);
      expect(lireJSON(path.join(caps, `issue-${idx.transaction_hash}.json`)).block_number, f).to.equal(idx.block_number);
    }
    expect(fs.existsSync(path.join(caps, `demande-cloture-${J.hachageManifeste(lireJSON(man1F))}.json`))).to.equal(true);
  });

  it("capturer --transaction (avec --dossier) et la conduite de 9.3 : certificat « not yet persisted » réessayé, « unknown block » la tête au-delà (incertain, code 3), binaire sans correctif (inutilisable), certificat élagué", async function () {
    const d = lireJSON(path.join(E, "dossier.json"));
    const jeuEtape = d.steps.find((s) => s.step === "jeu_approbateurs");
    const horsLatest = (m, p) => m === "noor_getCommitCertificate" && p[0] !== "latest";
    // Deux refus « not yet persisted » sur le bloc qui vient d'être inclus (la tête est à sa hauteur), puis le certificat : attempts = 3 (9.3).
    let n = 0;
    crochets.intercepter = (m, p) => (horsLatest(m, p) && ++n <= 2 ? Promise.reject(Object.assign(new Error("certificate not yet persisted"), { code: -32000 })) : undefined);
    const z = await cleAdmise();
    const az = await R(["approvisionner", "--vers", z.adresse, "--demande", z.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", path.join(E, "captures")]);
    attendreReussite(az);
    expect(n).to.equal(3);
    expect(lireJSON(path.join(E, "captures", az.outputs.capture)).attempts).to.equal(3);
    delete crochets.intercepter;
    // Sur un bloc passé, « not yet persisted » ne se réessaie pas : la tête est au-delà (certificat_indisponible, incertain).
    crochets.intercepter = (m, p) => (horsLatest(m, p) ? Promise.reject(Object.assign(new Error("certificate not yet persisted"), { code: -32000 })) : undefined);
    const passe = await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--contrat", jeuEtape.contract, "--captures", path.join(E, "c-passe")]);
    attendreRefus(passe, "certificat_indisponible", "incertain");
    expect(passe.error.message).to.include("tête au-delà du bloc");
    delete crochets.intercepter;
    // capturer --transaction redonne l'index du dossier dans un autre répertoire.
    const c1 = await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--contrat", jeuEtape.contract, "--captures", path.join(E, "c-bis")]);
    attendreReussite(c1);
    expect(c1.outputs.capture).to.equal(jeuEtape.capture);
    expect(c1.outputs.block_hash).to.equal(jeuEtape.block_hash);
    expect(lireJSON(path.join(E, "c-bis", c1.outputs.capture)).attempts).to.equal(1);
    // Même capture, le rôle et le contrat déduits de la transaction et du reçu : même index (8.6).
    const c1b = await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--captures", path.join(E, "c-bis-2")]);
    attendreReussite(c1b);
    expect(lireJSON(path.join(E, "c-bis-2", c1b.outputs.capture)).contract).to.equal(jeuEtape.contract);
    // --dossier : l'étape dont transaction_hash est celui de la transaction capturée passe à capturee (EX-7.16).
    const copie = path.join(E, "dossier-copie.json");
    const dc = JSON.parse(JSON.stringify(d));
    const eInsc = dc.steps.find((s) => s.step === "inscription");
    Object.assign(eInsc, { state: "incluse", capture: null });
    dc.result = null;
    fs.writeFileSync(copie, JSON.stringify(dc, null, 2));
    const cd = await R(["capturer", "--transaction", eInsc.transaction_hash, "--role", "inscription", "--contrat", manifeste.contracts[3].address, "--captures", path.join(E, "captures"), "--dossier", copie]);
    attendreReussite(cd);
    expect(cd.outputs.dossier).to.deep.equal({ step: "inscription", subject: eInsc.subject, state: "capturee" });
    const relu = lireJSON(copie);
    expect(relu.steps.find((s) => s.step === "inscription").capture).to.equal(cd.outputs.capture);
    expect(relu.result).to.not.equal(null);
    // « unknown block » alors que la tête dépasse la hauteur : certificat_indisponible sans réessai, incertain (code 3).
    crochets.intercepter = (m, p) => (horsLatest(m, p) ? Promise.reject(Object.assign(new Error("unknown block"), { code: -32000 })) : undefined);
    const c2 = await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--contrat", jeuEtape.contract, "--captures", path.join(E, "c-ter")]);
    attendreRefus(c2, "certificat_indisponible", "incertain");
    expect(c2.exit_code).to.equal(3);
    expect(c2.error.check).to.equal("CP-4");
    // Binaire sans correctif (-32601) : inutilisable.
    crochets.intercepter = (m, p) => (horsLatest(m, p) ? Promise.reject(Object.assign(new Error("the method noor_getCommitCertificate does not exist/is not available"), { code: -32601 })) : undefined);
    attendreRefus(await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--contrat", jeuEtape.contract, "--captures", path.join(E, "c-quater")]), "entree_illisible", "inutilisable");
    // Certificat élagué chez ce nœud : certificat_elague, incertain (9.5).
    crochets.intercepter = (m, p) => (horsLatest(m, p) ? synthese(m, p).then((c) => ({ ...c, retention: { heights: 3000000, pruned: true } })) : undefined);
    const c4 = await R(["capturer", "--transaction", jeuEtape.transaction_hash, "--role", "jeu_approbateurs", "--contrat", jeuEtape.contract, "--captures", path.join(E, "c-quinquies")]);
    attendreRefus(c4, "certificat_elague", "incertain");
    expect(c4.error.check).to.equal("CP-4");
  });

  it("8.6, EX-8.16 : sans reçu, incertain ; capturer --envoi --renvoyer ; --remplacer au même nonce à ⌈1,1 × p⌉ avec les issues remplacee et incluse ; --remplacer refusé si la transaction est connue ou qu'un point ne répond pas ; EX-8.18 : examen_requis puis --apres-examen", async function () {
    const caps = path.join(E, "captures");
    const x = await cleAdmise();
    const approvisionner = (k, ...reste) => R(["approvisionner", "--vers", k.adresse, "--demande", k.demande, "--budget-jour", "1000", "--tresorerie", "hardhat:0", "--captures", caps, ...reste]);
    // Envoi accepté par le point mais jamais transmis ni inclus : le pont rend le hachage sans rien faire.
    const retenir = (m, p) => (m === "eth_sendRawTransaction" ? Promise.resolve(C.hex(C.keccak(C.octets(p[0])))) : undefined);
    crochets.intercepter = retenir;
    const inc = await approvisionner(x, "--delai", "1");
    attendreRefus(inc, "recu_absent", "incertain");
    delete crochets.intercepter;
    const fEnvoi = path.join(caps, inc.outputs.envoi);
    expect(fs.existsSync(fEnvoi)).to.equal(true);
    expect(fs.existsSync(path.join(caps, `issue-${inc.outputs.transaction_hash}.json`))).to.equal(false);
    // L'expéditeur est bloqué tant que l'issue est inconnue (OP-3).
    attendreRefus(await approvisionner(x), "transaction_en_attente");
    // --remplacer tant qu'un point ne répond pas sur la transaction : refus (noeud_injoignable, EX-8.16).
    crochets.intercepter = (m) => (m === "eth_getTransactionByHash" ? Promise.reject(Object.assign(new Error("point en erreur"), { code: -32000 })) : undefined);
    attendreRefus(await R(["capturer", "--envoi", fEnvoi, "--remplacer", "--cle", "hardhat:0", "--captures", caps]), "noeud_injoignable", "inutilisable");
    delete crochets.intercepter;
    // --renvoyer : les mêmes octets, soumis de nouveau, sont inclus et capturés ; l'issue est écrite.
    const rv = await R(["capturer", "--envoi", fEnvoi, "--renvoyer", "--captures", caps]);
    attendreReussite(rv);
    expect(rv.outputs.transaction_hash).to.equal(inc.outputs.transaction_hash);
    expect(rv.outputs.capture).to.match(/-approvisionnement\.json$/);
    expect(lireJSON(path.join(caps, `issue-${inc.outputs.transaction_hash}.json`)).status).to.equal("0x1");
    expect(lireJSON(path.join(caps, rv.outputs.capture)).sending.transaction_hash).to.equal(inc.outputs.transaction_hash);
    // Connue d'un point : --remplacer refusé (usage) ; --renvoyer la rend deja incluse sans nouvel envoi.
    attendreRefus(await R(["capturer", "--envoi", fEnvoi, "--remplacer", "--cle", "hardhat:0", "--captures", caps]), "usage", "inutilisable");
    // Remplacement : un second envoi retenu, inconnu de tous, remplacé au même nonce à 2 wei (EX-4.15, RG-15).
    const y = await cleAdmise();
    crochets.intercepter = retenir;
    const inc2 = await approvisionner(y, "--delai", "1");
    attendreRefus(inc2, "recu_absent", "incertain");
    delete crochets.intercepter;
    const original = lireJSON(path.join(caps, inc2.outputs.envoi));
    attendreRefus(await R(["capturer", "--envoi", path.join(caps, inc2.outputs.envoi), "--remplacer", "--cle", "hardhat:1", "--captures", caps]), "compte_inattendu");
    const rp = await R(["capturer", "--envoi", path.join(caps, inc2.outputs.envoi), "--remplacer", "--cle", "hardhat:0", "--captures", caps]);
    attendreReussite(rp);
    expect(rp.outputs.replaced).to.equal(original.transaction_hash);
    expect(rp.outputs.transaction_hash).to.not.equal(original.transaction_hash);
    const remplacant = lireJSON(path.join(caps, `envoi-${rp.outputs.transaction_hash}.json`));
    expect([remplacant.nonce, remplacant.max_fee_per_gas, remplacant.max_priority_fee_per_gas, remplacant.to, remplacant.value]).to.deep.equal([original.nonce, "2", "2", original.to, original.value]);
    expect(C.decoderTransaction(remplacant.raw_transaction).data).to.equal(C.decoderTransaction(original.raw_transaction).data);
    const issueOriginal = lireJSON(path.join(caps, `issue-${original.transaction_hash}.json`));
    expect([issueOriginal.state, issueOriginal.replaced_by]).to.deep.equal(["remplacee", rp.outputs.transaction_hash]);
    expect(lireJSON(path.join(caps, `issue-${rp.outputs.transaction_hash}.json`)).block_number).to.equal(rp.outputs.block_number);
    expect(rp.outputs.cost_wei).to.equal(String(2 * rp.outputs.gas_used));
    // L'expéditeur n'est plus bloqué ; le destinataire est à sa provision.
    attendreReussite(await approvisionner(y), "deja_fait");
    // EX-8.18 : consommation au-delà de deux fois le budget depuis le dernier approvisionnement capturé : examen_requis, puis --apres-examen.
    await conn.provider.request({ method: "hardhat_setBalance", params: [y.adresse, "0x1"] });
    const ex = await approvisionner(y);
    attendreRefus(ex, "examen_requis");
    expect(BigInt(ex.outputs.consumption_since_last_funding_wei)).to.be.greaterThan(BigInt(ex.outputs.twice_budget_wei));
    const ap = await approvisionner(y, "--apres-examen", "solde relevé par l'exploitant");
    attendreReussite(ap);
    expect(ap.outputs.review).to.equal("solde relevé par l'exploitant");
    expect(BigInt(ap.outputs.balance_after_wei)).to.equal(BigInt(ap.outputs.provision_wei));
  });

  it("EX-7.16 : une étape envoyee se reprend par la capture de la transaction connue, jamais par un renvoi", async function () {
    const caps = path.join(E, "captures-reprise");
    const dossierF = path.join(E, "dossier-reprise.json");
    attendreReussite(await R(["inscrire-client", "--preparer", "--org", "essai-reprise", "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(E, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", dossierF]));
    // Le reçu du déploiement du jeu n'arrive pas dans le délai : l'étape reste envoyee, avec son transaction_hash et le contrat attendu.
    crochets.intercepter = (m) => (m === "eth_getTransactionReceipt" ? Promise.resolve(null) : undefined);
    const inc = await R(["inscrire-client", "--dossier", dossierF, "--exploitant", "hardhat:0", "--captures", caps, "--delai", "1"]);
    attendreRefus(inc, "recu_absent", "incertain");
    delete crochets.intercepter;
    let d = lireJSON(dossierF);
    expect([d.steps[0].step, d.steps[0].state, d.steps[0].transaction_hash]).to.deep.equal(["jeu_approbateurs", "envoyee", inc.outputs.transaction_hash]);
    expect(d.steps[0].contract).to.match(/^0x[0-9a-f]{40}$/);
    const envois = () => fs.readdirSync(caps).filter((f) => f.startsWith("envoi-")).length;
    expect(envois()).to.equal(1);
    // Reprise : le reçu existe, l'étape passe par incluse puis capturee sans nouvel envoi du déployeur ; les autres étapes suivent (la clé de chaîne, qui a dépensé depuis sa première provision, est recomplétée).
    const re = await R(["inscrire-client", "--dossier", dossierF, "--exploitant", "hardhat:0", "--captures", caps]);
    attendreReussite(re);
    d = lireJSON(dossierF);
    expect(d.steps.slice(0, 4).map((s) => `${s.step}:${s.state}`)).to.deep.equal(["jeu_approbateurs:capturee", "assignation:capturee", "lecture_jeu:faite", "approvisionnement:capturee"]);
    expect(d.steps[0].transaction_hash).to.equal(inc.outputs.transaction_hash);
    expect(d.steps[0].contract).to.equal(re.outputs.curator_set);
    expect(re.outputs.set_deployment.transaction_hash).to.equal(inc.outputs.transaction_hash);
    expect(envois()).to.equal(3);
    // Relancée, la commande ne renvoie rien (deja_fait).
    attendreReussite(await R(["inscrire-client", "--dossier", dossierF, "--exploitant", "hardhat:0", "--captures", caps]), "deja_fait");
    expect(envois()).to.equal(3);
  });
});
