// Composant d'ancrage, lot D : recalculs du registre (CT-6 §11.3 : hachage BFT,
// racine des reçus, certificat de commit, jeu de validateurs), capture CP-2 à
// CP-6 (CT-4 §9.4) et export des parties (CT-4 §9.6, CT-5 EX-10.4), rejoués
// contre spec/vecteurs/ct-6/registre (capture unique, trie.json, attendu.json,
// variantes, periode-1, periode-1-point) et spec/vecteurs/ct-4/capture ;
// parties exportées éprouvées par le binaire Go de CT-6 sur un dossier.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { octetsVersHex, hexVersOctets, sha256Hex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const CAPTURE = "spec/vecteurs/ct-6/registre/capture";
const ATTENDU = lireJson("spec/vecteurs/ct-6/registre/attendu.json");
const TRIE = lireJson("spec/vecteurs/ct-6/registre/trie.json");
const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");
const JEU = R.lireJeu(lireJson(`${CAPTURE}/validators.json`));
const BFT = "noortrace-2124-dev";
const JEUX_DEV = { sets: [{ from_height: 1, to_height: null, validators: lireJson("test/fixtures/certificat-commit/validators.json").validators, source: "validators.json du réseau de développement, clés publiques seulement" }] };

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

/** Construit le binaire Go de CT-6 (go1.27.3) ; null si la chaîne de compilation manque. */
function construireVerificateur(dir) {
  // Un binaire déjà construit (NOORTRACE_VERIFIER_BIN) évite une reconstruction par exécution.
  const prebuilt = process.env.NOORTRACE_VERIFIER_BIN ?? null;
  if (prebuilt && fs.existsSync(prebuilt)) return prebuilt;
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOTOOLCHAIN: "local", GOFLAGS: "-mod=vendor" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  try {
    execFileSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(RACINE, "verificateur"), stdio: "pipe" });
  } catch {
    return null;
  }
  return sortie;
}

describe("ancrage, lot D : recalculs, capture et export du registre (CT-6 §11, CT-4 §9)", function () {
  this.timeout(120000);

  it("copies embarquées des schémas égales aux fichiers de spec/schemas", function () {
    expect(R.SCHEMA_OPERATIONS_REGISTRE).to.deep.equal(lireJson("spec/schemas/operations-registre-v0.schema.json"));
    expect(R.SCHEMA_REGISTRE).to.deep.equal(lireJson("spec/schemas/registre-v0.schema.json"));
    expect(R.SCHEMA_VALIDATEURS).to.deep.equal(lireJson("spec/schemas/validateurs-v0.schema.json"));
    // Les comptes de rôles retirés du schéma enregistré sont appliqués par verifierRegistreV0.
    expect(R.BORNES_ROLES).to.deep.equal({ cloture: [1, 1], ancre: [1, 1], inscription: [0, 8], ancre_point_de_controle: [0, 1] });
  });

  it("trie.json : racine des reçus synthétiques, couples génériques (nœuds de moins de 32 octets inclus) et trie vide (EX-11.5)", function () {
    for (const c of TRIE.recus) expect(octetsVersHex(R.racineRecus(c.receipts)), `recus n=${c.n}`).to.equal(c.root);
    for (const c of TRIE.generique) {
      const couples = c.pairs.map((p) => ({ cle: hexVersOctets(p.key), valeur: hexVersOctets(p.value) }));
      expect(octetsVersHex(R.racineTrie(couples)), `generique n=${c.n}`).to.equal(c.root);
    }
    expect(octetsVersHex(R.racineTrie([]))).to.equal(TRIE.vide);
    expect(() => R.racineTrie([{ cle: Uint8Array.of(1), valeur: Uint8Array.of(2) }, { cle: Uint8Array.of(1), valeur: Uint8Array.of(3) }])).to.throw(TypeError);
    // hex-prefix : feuille et extension, longueurs paire et impaire.
    expect(octetsVersHex(R.hexPrefix(Uint8Array.of(1, 2, 3), true))).to.equal("0x3123");
    expect(octetsVersHex(R.hexPrefix(Uint8Array.of(1, 2), false))).to.equal("0x0012");
    expect(octetsVersHex(R.hexPrefix(Uint8Array.of(1, 2), true))).to.equal("0x2012");
    expect(octetsVersHex(R.hexPrefix(Uint8Array.of(1), false))).to.equal("0x11");
  });

  it("attendu.json : préimage et hachage BFT, encodage des reçus et racine, certificats (signataires, hachage du jeu) des huit blocs capturés (EX-11.4 à EX-11.8, EX-11.14)", function () {
    expect(octetsVersHex(JEU.hash)).to.equal(ATTENDU.capture.valset_hash);
    expect(octetsVersHex(R.lireJeu(CONSTANTES.test_validators).hash)).to.equal(CONSTANTES.test_validators.valset_hash);
    const substitue = R.lireJeu(ATTENDU.jeu_substitue.validators);
    expect(octetsVersHex(substitue.hash)).to.equal(ATTENDU.jeu_substitue.valset_hash);
    expect(R.quorum(4)).to.equal(3);
    expect(R.quorum(7)).to.equal(5);
    expect(ATTENDU.blocs).to.have.length(8);
    for (const b of ATTENDU.blocs) {
      const bloc = lireJson(`${CAPTURE}/bloc-${b.height}.json`).result;
      const h = R.hachageBlocBft(bloc);
      expect(octetsVersHex(h.preimage), `bft ${b.height}`).to.equal(b.bft_preimage);
      expect(octetsVersHex(h.hash), `bft ${b.height}`).to.equal(b.bft_block_hash);
      expect(bloc.hash).to.equal(b.block_hash_served);
      const recus = bloc.transactions.map((tx) => lireJson(`${CAPTURE}/recu-${tx}.json`).result);
      expect(recus.map((r) => octetsVersHex(R.encoderRecu(r))), `reçus ${b.height}`).to.deep.equal(b.receipt_encodings);
      expect(octetsVersHex(R.racineRecus(recus)), `racine ${b.height}`).to.equal(b.receipts_root);
      const cert = lireJson(`${CAPTURE}/certificat-${b.height}.json`);
      const v = R.verifierCertificat(cert, { bftChainId: BFT, hauteur: b.height, blockHash: bloc.hash, jeu: JEU });
      expect(v.ok, `certificat ${b.height} : ${v.raison}`).to.equal(true);
      expect(v.signataires).to.deep.equal(b.certificate.precommit_signers);
      expect(v.proposition.validatorId).to.equal(b.certificate.proposer);
      expect(v.avertissements).to.deep.equal([]);
      expect(octetsVersHex(R.racineTransactions(v.txsRaw)), `txRoot ${b.height}`).to.equal(bloc.transactionsRoot);
      // Jeu substitué (R-2), autre chaîne (R-4), autre hauteur, autre blockHash : refusés.
      expect(R.verifierCertificat(cert, { bftChainId: BFT, hauteur: b.height, blockHash: bloc.hash, jeu: substitue }).ok).to.equal(false);
      expect(R.verifierCertificat(cert, { bftChainId: "noortrace-9999-test", hauteur: b.height, blockHash: bloc.hash, jeu: JEU }).ok).to.equal(false);
      expect(R.verifierCertificat(cert, { bftChainId: BFT, hauteur: b.height + 1, blockHash: bloc.hash, jeu: JEU }).ok).to.equal(false);
      expect(R.verifierCertificat(cert, { bftChainId: BFT, hauteur: b.height, blockHash: "0x" + "00".repeat(32), jeu: JEU }).ok).to.equal(false);
      // Journal décodé égal à l'événement attendu.
      const j = recus[b.transaction_index].logs[0];
      const role = b.role === "ancre_point_de_controle" ? "ancre" : b.role;
      const d = R.decoderJournal(role, { address: j.address.toLowerCase(), topics: j.topics, data: j.data });
      for (const [k, val] of Object.entries(b.event)) if (typeof val === "string") expect(String(d[k]), `${b.height} ${k}`).to.equal(val);
    }
  });

  it("variantes de certificat : ligne non canonique acceptée avec AV-R-2, quorum insuffisant refusé, precommit d'un autre type refusé, signature altérée refusée", function () {
    const registre = lireJson("spec/vecteurs/ct-6/registre/variantes/valide-ligne-non-canonique/registre.json");
    const bloc = registre.entries.find((e) => e.block.number === "0x411c").block;
    const nonCanonique = lireJson("spec/vecteurs/ct-6/registre/variantes/valide-ligne-non-canonique/certificat-commit.json").certificates.find((c) => c.height === "0x411c");
    const v = R.verifierCertificat(nonCanonique, { bftChainId: BFT, hauteur: 16668, blockHash: bloc.hash, jeu: JEU });
    expect(v.ok, v.raison).to.equal(true);
    expect(v.avertissements).to.deep.equal(["AV-R-2"]);
    const quorum = lireJson("spec/vecteurs/ct-6/registre/variantes/invalide-r5-quorum/certificat-commit.json").certificates.find((c) => c.height === "0x411c");
    const vq = R.verifierCertificat(quorum, { bftChainId: BFT, hauteur: 16668, blockHash: bloc.hash, jeu: JEU });
    expect(vq.ok).to.equal(false);
    expect(vq.raison).to.match(/quorum/);
    // Precommit dont l'enveloppe est de type CONS_PREVOTE : ligne invalide ; signature altérée : invalide ; proposition absente : illisible.
    const original = lireJson(`${CAPTURE}/certificat-16668.json`).result;
    const prevote = { ...original, precommits: original.precommits.map((p, k) => (k === 0 ? { line: p.line.replace("CONS_PRECOMMIT", "CONS_PREVOTE") } : p)) };
    expect(R.verifierCertificat(prevote, { bftChainId: BFT, hauteur: 16668, blockHash: bloc.hash, jeu: JEU }).ok).to.equal(false);
    const altere = { ...original, precommits: original.precommits.map((p, k) => (k === 0 ? { line: p.line.replace(/"sig":"(.)/, (m, c) => `"sig":"${c === "A" ? "B" : "A"}`) } : p)) };
    expect(R.verifierCertificat(altere, { bftChainId: BFT, hauteur: 16668, blockHash: bloc.hash, jeu: JEU }).ok).to.equal(false);
    const sansProposition = { ...original, proposal: undefined };
    expect(R.verifierCertificat(sansProposition, { bftChainId: BFT, hauteur: 16668, blockHash: bloc.hash, jeu: JEU }).motif).to.equal("certificat_invalide");
    // Lecture tolérante (EX-11.6) : « Domain », membres en double (dernier retenu), espaces ; refus : nom différent, base64 URL, entier non entier, Type chaîne.
    const l = R.lireLigne(original.precommits[0].line);
    expect(l.refus).to.equal(undefined);
    expect(l.canonique).to.equal(true);
    expect(R.lireLigne(original.precommits[0].line.replace('"domain"', '"DOMAIN"')).canonique).to.equal(false);
    expect(R.lireLigne(original.precommits[0].line.replace('"domaine"', '"domaine"').replace('"domain":"noor/v1/bft"', '"domaine":"noor/v1/bft"')).refus).to.be.a("string");
    expect(R.lireLigne(original.precommits[0].line.replace(/"valsetHash":"([^"]+)"/, (m, b) => `"valsetHash":"${b.replace(/\+/g, "-").replace(/\//g, "_")}"`)).refus).to.be.a("string");
    expect(R.lireLigne(original.precommits[0].line.replace('"height":16668', '"height":16668.0')).refus).to.be.a("string");
    expect(R.lireLigne(original.precommits[0].line.replace('"Type":2', '"Type":"2"')).refus).to.be.a("string");
    expect(R.lireLigne(original.precommits[0].line.replace('"Type":2', '"Type":256')).refus).to.be.a("string");
    const typeNul = R.lireLigne(original.precommits[0].line.replace('"Type":2', '"Type":null'));
    expect(typeNul.refus).to.equal(undefined);
    expect(R.lireLigne("[]").refus).to.be.a("string");
    expect(R.lireLigne("").refus).to.be.a("string");
    expect(R.lireLigne("x".repeat(4194305)).refus).to.be.a("string");
    // Base64 du nœud : remplissage exigé, bits de bourrage non nuls tolérés, alphabet URL refusé.
    expect(R.decoderBase64Noeud("AQID")).to.deep.equal({ octets: Uint8Array.of(1, 2, 3), canonique: true });
    expect(R.decoderBase64Noeud("AQI=").octets).to.deep.equal(Uint8Array.of(1, 2));
    expect(R.decoderBase64Noeud("AQJ=").canonique).to.equal(false);
    expect(R.decoderBase64Noeud("AQI")).to.equal(null);
    expect(R.decoderBase64Noeud("AQ-D")).to.equal(null);
    expect(R.decoderBase64Noeud("AQ=D")).to.equal(null);
    expect(R.decoderBase64Noeud("AQ\nID").octets).to.deep.equal(Uint8Array.of(1, 2, 3));
  });

  it("jeux de validateurs : manifeste d'instance, validateurs-v0, validators.json ; bornes et formes refusées", function () {
    const manifeste = { validator_sets: [{ from_height: 1, to_height: 16660, validators: JEUX_DEV.sets[0].validators, source: "a" }, { from_height: 16661, to_height: null, validators: CONSTANTES.test_validators.validators, source: "b" }] };
    const jeux = R.lireJeux(manifeste);
    expect(jeux).to.have.length(2);
    expect(octetsVersHex(R.jeuPourHauteur(jeux, 16660).jeu.hash)).to.equal(ATTENDU.capture.valset_hash);
    expect(octetsVersHex(R.jeuPourHauteur(jeux, 16661).jeu.hash)).to.equal(CONSTANTES.test_validators.valset_hash);
    expect(R.jeuPourHauteur(jeux, 0)).to.equal(null);
    expect(R.lireJeux(lireJson(`${CAPTURE}/validators.json`))).to.have.length(1);
    expect(R.lireJeux({ validator_sets: [{ from_height: 10, to_height: 5, validators: JEUX_DEV.sets[0].validators }] })).to.equal(null);
    expect(R.lireJeux({ validators: [] })).to.equal(null);
    expect(R.lireJeux({ validators: [{ id: "v1", pubKeyHex: "0x04" + "00".repeat(64) }] })).to.equal(null, "pas un point de la courbe");
    expect(R.lireJeux({ validators: [{ id: "v1", pubKeyHex: JEUX_DEV.sets[0].validators[0].pubKeyHex }, { id: "v1", pubKeyHex: JEUX_DEV.sets[0].validators[1].pubKeyHex }] })).to.equal(null, "identifiants en double");
    expect(R.lireJeux({ validators: Array.from({ length: 129 }, (_, k) => ({ id: `v${k}`, pubKeyHex: JEUX_DEV.sets[0].validators[0].pubKeyHex })) })).to.equal(null, "plus de 128 validateurs");
    // Le hachage ne dépend que des clés telles que déclarées (compressée et non compressée diffèrent).
    const comprime = { validators: JEUX_DEV.sets[0].validators.map((v) => ({ id: v.id, pubKeyHex: octetsVersHex(R.clePubliqueNonCompressee(hexVersOctets(v.pubKeyHex))) })) };
    expect(octetsVersHex(R.lireJeu(comprime).hash)).to.equal(ATTENDU.capture.valset_hash);
  });

  it("capture.json (CT-4) : CP-2 à CP-6 sur les quatre captures de la période 1 et les treize variantes, premier échec et code attendus", function () {
    const f = lireJson("spec/vecteurs/ct-4/capture/capture.json");
    let joues = 0;
    for (const c of f.cases) {
      if (!c.input.index) continue;
      const dir = path.join(RACINE, "spec/vecteurs/ct-4", c.input.directory);
      const index = JSON.parse(fs.readFileSync(path.join(dir, c.input.index), "utf8"));
      const jeux = c.input.validators === "constantes.json#/test_validators" ? CONSTANTES.test_validators : lireJson(c.input.validators);
      const v = R.verifierCapture({ fichiers: dir, index, jeux, bftChainId: c.input.bft_chain_id });
      for (const k of ["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"]) expect(v.verdicts[k], `${c.id} ${k}`).to.equal(c.expected.verdicts[k]);
      if (c.refusal) expect(v.premierEchec, c.id).to.deep.equal({ check: c.refusal.check, code: c.refusal.code });
      else expect(v.premierEchec, c.id).to.equal(null);
      expect(v.checks.map((x) => x.id)).to.deep.equal(["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"]);
      joues++;
    }
    expect(joues).to.equal(17);
  });

  it("export-periode-1 (CT-4 EX-9.8 à EX-9.10) : registre.json (hors source), certificat-commit.json et validateurs.json égaux à spec/vecteurs/ct-6/registre/periode-1", function () {
    const dir = path.join(RACINE, "spec/vecteurs/ct-4/capture/periode-1");
    const cas = lireJson("spec/vecteurs/ct-4/capture/capture.json").cases.find((c) => c.id === "export-periode-1");
    const captures = cas.input.indexes.map((n) => ({ index: JSON.parse(fs.readFileSync(path.join(dir, n), "utf8")) }));
    const ex = R.exporterPartiesRegistre({ repertoire: dir, captures, jeux: JEUX_DEV, source: "essai" });
    const ref = lireJson("spec/vecteurs/ct-6/registre/periode-1/registre.json");
    expect({ ...ex.registre, source: ref.source }).to.deep.equal(ref);
    expect(ex.certificatCommit).to.deep.equal(lireJson("spec/vecteurs/ct-6/registre/periode-1/certificat-commit.json"));
    expect(ex.validateurs).to.deep.equal(lireJson("spec/vecteurs/ct-6/registre/periode-1/validateurs.json"));
    expect(ex.registre.entries.map((e) => ({ role: e.role, block_number: Number(e.block.number), transaction_index: e.transaction_index }))).to.deep.equal(cas.expected.entries);
    expect(ex.certificatCommit.certificates.map((c) => Number(c.height))).to.deep.equal(cas.expected.certificates);
    expect(ex.validateurs.sets).to.have.length(cas.expected.sets);
    // Choix des captures d'un dossier (EX-9.8) : clôture par periodHash, ancre par empreinte, inscription de la clé du manifeste.
    const indexes = captures.map((c) => c.index);
    const choix = R.choisirCaptures({ repertoire: dir, indexes, periodHash: "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914", fingerprint: "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6", inscriptions: [{ clePublique: CONSTANTES.recorders[1].public_key }] });
    expect(choix.map((c) => `${c.role}:${c.index.block_number}`)).to.deep.equal(["cloture:16668", "ancre:16660", "inscription:16652"]);
    expect(() => R.choisirCaptures({ repertoire: dir, indexes, periodHash: "0x" + "11".repeat(32), fingerprint: "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6" })).to.throw(/capture_incomplete/);
  });

  it("periode-1-point (CT-5 EX-10.4, CT-6 EX-11.23) : entrée ancre_point_de_controle reconstruite depuis la capture du bloc 18928, parties égales à la référence", function () {
    // Index de capture du bloc 18928 (complément EX-A.15), reconstruit depuis les fichiers bruts de la capture unique.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-registre-export-"));
    for (const n of fs.readdirSync(path.join(RACINE, CAPTURE))) if (/^(bloc|recu|certificat)-/.test(n)) fs.copyFileSync(path.join(RACINE, CAPTURE, n), path.join(dir, n));
    const sha = (n) => sha256Hex(new Uint8Array(fs.readFileSync(path.join(dir, n))));
    const point = ATTENDU.checkpoint_anchor.transaction;
    const bloc = lireJson(`${CAPTURE}/bloc-18928.json`).result;
    const index = {
      version: 0, role: "ancre", evm_chain_id: 2124, bft_chain_id: BFT, contract: CONSTANTES.contracts.attestation_registry,
      transaction_hash: point.hash, block_number: 18928, block_hash: bloc.hash, transaction_index: 0, log_index: 0,
      files: { block: { name: "bloc-18928.json", sha256: sha("bloc-18928.json") }, receipts: [{ name: `recu-${point.hash}.json`, sha256: sha(`recu-${point.hash}.json`) }], certificate: { name: "certificat-18928.json", sha256: sha("certificat-18928.json") } },
      node: { rpc: "http://127.0.0.1:8645", validator_id: "v1" }, validator_set_hash: ATTENDU.capture.valset_hash, captured_at: "2026-10-26T01:25:00.000Z", attempts: 1,
      checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })), sending: null,
    };
    expect(R.verifierIndexCapture(index).valide).to.equal(true);
    const v = R.verifierCapture({ fichiers: dir, index, jeux: JEUX_DEV, bftChainId: BFT });
    expect(v.premierEchec, JSON.stringify(v.checks)).to.equal(null);
    expect(R.decoderJournal("ancre", v.journal)).to.deep.equal({ name: "Anchored", fingerprint: point.fingerprint, issuer: point.issuer, docType: R.DOC_TYPE_POINT_DE_CONTROLE });
    // Rôle de l'entrée : ancre_point_de_controle d'après le docType du journal (CT-5 EX-10.4).
    expect(R.roleEntree(index, v.journal)).to.equal("ancre_point_de_controle");
    const entree = R.entreeRegistre({ repertoire: dir, index });
    const ref = lireJson("spec/vecteurs/ct-6/registre/periode-1-point/registre.json");
    expect(entree).to.deep.equal(ref.entries.find((e) => e.role === "ancre_point_de_controle"));
    // Parties complètes : les quatre captures de la période 1 plus celle du point.
    const dir1 = path.join(RACINE, "spec/vecteurs/ct-4/capture/periode-1");
    const captures = ["capture-16648-0-inscription.json", "capture-16652-0-inscription.json", "capture-16660-0-ancre.json", "capture-16668-0-cloture.json"].map((n) => ({ index: JSON.parse(fs.readFileSync(path.join(dir1, n), "utf8")) }));
    captures.push({ index, role: "ancre_point_de_controle" });
    const ex = R.exporterPartiesRegistre({ repertoire: dir, captures, jeux: JEUX_DEV, source: "essai" });
    expect({ ...ex.registre, source: ref.source }).to.deep.equal(ref);
    expect(ex.certificatCommit).to.deep.equal(lireJson("spec/vecteurs/ct-6/registre/periode-1-point/certificat-commit.json"));
    expect(ex.validateurs).to.deep.equal(lireJson("spec/vecteurs/ct-6/registre/periode-1-point/validateurs.json"));
    expect(R.verifierRegistreV0(ex.registre).valide).to.equal(true);
    // Deux entrées de rôle ancre_point_de_controle : refusé (une au plus, EX-11.23).
    expect(() => R.exporterPartiesRegistre({ repertoire: dir, captures: [...captures, { index, role: "ancre_point_de_controle" }], jeux: JEUX_DEV, source: "essai" })).to.throw(/ancre_point_de_controle/);
    // Une ancre de période ne devient jamais une entrée ancre_point_de_controle, ni l'inverse (AN-45, CT-6 R-11).
    expect(() => R.entreeRegistre({ repertoire: dir1, index: captures[2].index, role: "ancre_point_de_controle" })).to.throw(/forme du rôle/);
    expect(() => R.entreeRegistre({ repertoire: dir, index, role: "ancre" })).to.throw(/forme du rôle/);
    // Capture manquante : l'export s'arrête (EX-9.11).
    fs.rmSync(path.join(dir, "certificat-18928.json"));
    expect(() => R.exporterPartiesRegistre({ repertoire: dir, captures, jeux: JEUX_DEV, source: "essai" })).to.throw(/capture_incomplete/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("bornes de CT-6 §15.1 et formes hostiles : reçus, journaux, sujets, entrées, certificats, en-tête", function () {
    const recu = lireJson(`${CAPTURE}/recu-0x70edd263160e4fcd6c6887ac21daf4556720ef662facdf9bb12292366f120779.json`).result;
    expect(R.lireRecu(recu)).to.not.equal(null);
    expect(R.lireRecu({ ...recu, type: "0x5" })).to.equal(null);
    expect(R.lireRecu({ ...recu, status: "0x2" })).to.equal(null);
    expect(R.lireRecu({ ...recu, cumulativeGasUsed: "0x017ad1" })).to.equal(null, "quantité à zéro de tête");
    expect(R.lireRecu({ ...recu, logs: Array.from({ length: 257 }, () => recu.logs[0]) })).to.equal(null, "plus de 256 journaux");
    expect(R.lireRecu({ ...recu, logs: [{ ...recu.logs[0], topics: Array(5).fill(recu.logs[0].topics[0]) }] })).to.equal(null, "plus de 4 sujets");
    expect(R.lireRecu({ ...recu, logs: [{ ...recu.logs[0], data: "0xabc" }] })).to.equal(null, "données de longueur impaire");
    expect(R.lireRecu({ ...recu, logs: [{ ...recu.logs[0], address: "0x12" }] })).to.equal(null);
    // En-tête : quantité en majuscules ou hachage de 31 octets refusés.
    const bloc = lireJson(`${CAPTURE}/bloc-16660.json`).result;
    expect(R.hachageBlocBft({ ...bloc, gasUsed: "0x17AD1" })).to.equal(null);
    expect(R.hachageBlocBft({ ...bloc, stateRoot: bloc.stateRoot.slice(0, -2) })).to.equal(null);
    expect(R.hachageBlocBft({ ...bloc, baseFeePerGas: "0x1" + "0".repeat(64) })).to.equal(null, "baseFeePerGas au-delà de 256 bits");
    expect(R.champsEntete({ ...bloc, number: undefined })).to.equal(null);
    // registre.json : 18 entrées, deux clôtures, aucune ancre, rôle hors énumération, entête avec un champ en trop : refusés par le schéma ou les comptes.
    const registre = lireJson("spec/vecteurs/ct-6/registre/periode-1/registre.json");
    const [inscription, , ancre, cloture] = registre.entries;
    expect(R.verifierRegistreV0(registre).valide).to.equal(true);
    expect(R.verifierRegistreV0({ ...registre, entries: [ancre, cloture, ...Array(16).fill(inscription)] }).valide).to.equal(false, "18 entrées");
    expect(R.verifierRegistreV0({ ...registre, entries: [ancre, cloture, ...Array(9).fill(inscription)] }).valide).to.equal(false, "9 inscriptions");
    expect(R.verifierRegistreV0({ ...registre, entries: [ancre, cloture, cloture] }).valide).to.equal(false, "deux clôtures");
    expect(R.verifierRegistreV0({ ...registre, entries: [cloture, inscription] }).valide).to.equal(false, "aucune ancre");
    expect(R.verifierRegistreV0({ ...registre, entries: [ancre, { ...cloture, role: "autre" }] }).valide).to.equal(false);
    expect(R.verifierRegistreV0({ ...registre, entries: [ancre, { ...cloture, block: { ...cloture.block, miner: "0x" + "00".repeat(20) } }] }).valide).to.equal(false, "champ d'en-tête non engagé");
    expect(R.verifierRegistreV0({ ...registre, source: "" }).valide).to.equal(false);
    expect(R.verifierRegistreV0({ ...registre, source: "x".repeat(513) }).valide).to.equal(false);
    // certificat-commit.json : 17 certificats, 129 precommits, hauteur en majuscules.
    const cc = lireJson("spec/vecteurs/ct-6/registre/periode-1/certificat-commit.json");
    expect(R.verifierCertificatCommitV0(cc).valide).to.equal(true);
    expect(R.verifierCertificatCommitV0({ ...cc, certificates: Array(17).fill(cc.certificates[0]) }).valide).to.equal(false);
    expect(R.verifierCertificatCommitV0({ ...cc, certificates: [{ ...cc.certificates[0], precommits: Array(129).fill(cc.certificates[0].precommits[0]) }] }).valide).to.equal(false);
    expect(R.lireCertificat({ ...cc.certificates[0], height: "0x4108".toUpperCase() })).to.equal(null);
    expect(R.lireCertificat({ ...cc.certificates[0], precommits: Array(129).fill(cc.certificates[0].precommits[0]) })).to.equal(null);
    expect(R.lireCertificat({ ...cc.certificates[0], valsetHash: ATTENDU.capture.valset_hash.toUpperCase() })).to.equal(null);
    // validateurs.json : 17 jeux refusés.
    const val = lireJson("spec/vecteurs/ct-6/registre/periode-1/validateurs.json");
    expect(R.verifierValidateursV0({ ...val, sets: Array(17).fill(val.sets[0]) }).valide).to.equal(false);
    // Index de capture : rôle hors énumération, nom de fichier avec chemin, 257 reçus, log_index hors borne, champ en trop.
    const index = lireJson("spec/vecteurs/ct-4/capture/periode-1/capture-16660-0-ancre.json");
    expect(R.verifierIndexCapture(index).valide).to.equal(true);
    expect(R.verifierIndexCapture({ ...index, role: "point" }).valide).to.equal(false);
    expect(R.verifierIndexCapture({ ...index, files: { ...index.files, block: { ...index.files.block, name: "../bloc-16660.json" } } }).valide).to.equal(false);
    expect(R.verifierIndexCapture({ ...index, files: { ...index.files, receipts: Array(257).fill(index.files.receipts[0]) } }).valide).to.equal(false);
    expect(R.verifierIndexCapture({ ...index, log_index: 256 }).valide).to.equal(false);
    expect(R.verifierIndexCapture({ ...index, extra: 1 }).valide).to.equal(false);
    expect(R.verifierIndexCapture({ ...index, node: { rpc: "http://127.0.0.1:8645", validator_id: "v1", jeton: "x" } }).valide).to.equal(false);
    // Fichier JSON-RPC : non UTF-8, sans result, trop grand.
    expect(R.lireFichierRpc(Uint8Array.of(0xff, 0xfe))).to.equal(null);
    expect(R.lireFichierRpc(new TextEncoder().encode('{"jsonrpc":"2.0","id":1}'))).to.equal(null);
    expect(R.lireFichierRpc(new Uint8Array(16 * 1024 * 1024 + 1))).to.equal(null);
    // Nom de fichier hors convention : non lu par le lecteur de répertoire.
    const lecteur = R.lecteurRepertoire(path.join(RACINE, CAPTURE));
    expect(lecteur.lire("../capture/bloc-16660.json")).to.equal(null);
    expect(lecteur.lire("bloc-16660.json")).to.not.equal(null);
  });

  it("verifierCapture refuse les reprises : index dont le journal est à un autre log_index, contrat différent, validator_set_hash différent, reçu manquant", function () {
    const dir = path.join(RACINE, "spec/vecteurs/ct-4/capture/periode-1");
    const index = JSON.parse(fs.readFileSync(path.join(dir, "capture-16660-0-ancre.json"), "utf8"));
    const base = R.verifierCapture({ fichiers: dir, index, jeux: JEUX_DEV, bftChainId: BFT });
    expect(base.premierEchec).to.equal(null);
    expect(R.verifierCapture({ fichiers: dir, index: { ...index, log_index: 1 }, jeux: JEUX_DEV, bftChainId: BFT }).premierEchec).to.deep.equal({ check: "CP-5", code: "capture_incomplete" });
    expect(R.verifierCapture({ fichiers: dir, index: { ...index, contract: CONSTANTES.contracts.period_registry }, jeux: JEUX_DEV, bftChainId: BFT }).premierEchec).to.deep.equal({ check: "CP-5", code: "capture_incomplete" });
    expect(R.verifierCapture({ fichiers: dir, index: { ...index, validator_set_hash: CONSTANTES.test_validators.valset_hash }, jeux: JEUX_DEV, bftChainId: BFT }).premierEchec).to.deep.equal({ check: "CP-4", code: "certificat_invalide" });
    expect(R.verifierCapture({ fichiers: dir, index: { ...index, files: { ...index.files, receipts: [] } }, jeux: JEUX_DEV, bftChainId: BFT }).premierEchec.check).to.equal("CP-3");
    expect(R.verifierCapture({ fichiers: dir, index, jeux: JEUX_DEV, bftChainId: "noortrace-2124-autre" }).premierEchec).to.deep.equal({ check: "CP-4", code: "certificat_invalide" });
    expect(R.verifierCapture({ fichiers: dir, index, jeux: { sets: [{ from_height: 20000, to_height: null, validators: JEUX_DEV.sets[0].validators, source: "x" }] }, bftChainId: BFT }).premierEchec).to.deep.equal({ check: "CP-4", code: "certificat_invalide" });
  });

  it("parties exportées éprouvées par le binaire Go de CT-6 : dossier valide-point-de-controle-complet avec registre.json, certificat-commit.json et validateurs.json reconstruits (R-1 à R-11, même verdict)", function () {
    const travail = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-registre-go-"));
    const binaire = construireVerificateur(travail);
    if (!binaire) {
      fs.rmSync(travail, { recursive: true, force: true });
      enAttente(this, "chaîne de compilation Go 1.27.3 introuvable (NOORTRACE_GO_BIN) pour construire noortrace-verifier");
      return;
    }
    const source = path.join(RACINE, "spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet");
    const attendu = lireJson("spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet/attendu.json");
    const dossier = path.join(travail, "dossier");
    fs.mkdirSync(dossier);
    for (const n of fs.readdirSync(source)) if (n !== "attendu.json") fs.copyFileSync(path.join(source, n), path.join(dossier, n));
    // Reconstruction des trois parties depuis les captures (période 1 et point 18928).
    const captures = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-registre-captures-"));
    for (const n of fs.readdirSync(path.join(RACINE, CAPTURE))) if (/^(bloc|recu|certificat)-/.test(n)) fs.copyFileSync(path.join(RACINE, CAPTURE, n), path.join(captures, n));
    const dir1 = path.join(RACINE, "spec/vecteurs/ct-4/capture/periode-1");
    const indexes = ["capture-16648-0-inscription.json", "capture-16652-0-inscription.json", "capture-16660-0-ancre.json", "capture-16668-0-cloture.json"].map((n) => JSON.parse(fs.readFileSync(path.join(dir1, n), "utf8")));
    const sha = (n) => sha256Hex(new Uint8Array(fs.readFileSync(path.join(captures, n))));
    const point = ATTENDU.checkpoint_anchor.transaction;
    const indexPoint = {
      version: 0, role: "ancre", evm_chain_id: 2124, bft_chain_id: BFT, contract: CONSTANTES.contracts.attestation_registry,
      transaction_hash: point.hash, block_number: 18928, block_hash: lireJson(`${CAPTURE}/bloc-18928.json`).result.hash, transaction_index: 0, log_index: 0,
      files: { block: { name: "bloc-18928.json", sha256: sha("bloc-18928.json") }, receipts: [{ name: `recu-${point.hash}.json`, sha256: sha(`recu-${point.hash}.json`) }], certificate: { name: "certificat-18928.json", sha256: sha("certificat-18928.json") } },
      node: { rpc: "http://127.0.0.1:8645", validator_id: "v1" }, validator_set_hash: ATTENDU.capture.valset_hash, captured_at: "2026-10-26T01:25:00.000Z", attempts: 1,
      checks: ["CP-1", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => ({ id, status: "reussi", detail: "" })), sending: null,
    };
    const registreDossier = lireJson("spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet/registre.json");
    const choix = R.choisirCaptures({
      repertoire: captures, indexes: [...indexes, indexPoint],
      periodHash: "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914", fingerprint: "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6",
      inscriptions: registreDossier.entries.filter((e) => e.role === "inscription").map((e) => ({ clePublique: "0x" + e.receipts[e.transaction_index].logs[e.log_index].data.slice(2, 66) })),
      empreintePoint: point.fingerprint,
    });
    const ex = R.exporterPartiesRegistre({ repertoire: captures, captures: choix, jeux: JEUX_DEV, source: registreDossier.source });
    // Les parties reconstruites égalent celles du dossier publié, membre pour membre.
    expect(ex.registre).to.deep.equal(registreDossier);
    expect(ex.certificatCommit).to.deep.equal(lireJson("spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet/certificat-commit.json"));
    expect(ex.validateurs).to.deep.equal(lireJson("spec/vecteurs/ct-6/dossiers/valide-point-de-controle-complet/validateurs.json"));
    // Le dossier reçoit les parties telles que ce module les sérialise ; l'index est réécrit avec leurs SHA-256.
    for (const [nom, octets] of [["registre.json", ex.octets.registre], ["certificat-commit.json", ex.octets.certificatCommit], ["validateurs.json", ex.octets.validateurs]]) fs.writeFileSync(path.join(dossier, nom), octets);
    const indexDossier = JSON.parse(fs.readFileSync(path.join(dossier, "dossier.json"), "utf8"));
    for (const p of indexDossier.parts) if (["registre.json", "certificat-commit.json", "validateurs.json"].includes(p.file)) p.sha256 = sha256Hex(new Uint8Array(fs.readFileSync(path.join(dossier, p.file))));
    fs.writeFileSync(path.join(dossier, "dossier.json"), JSON.stringify(indexDossier, null, 2) + "\n");
    const ancres = path.join(RACINE, "spec/vecteurs/ct-6/ancres/ancres-test.json");
    const entetes = path.join(RACINE, "spec/vecteurs/ct-6/ots/entetes/chaine-points.json");
    const r = spawnSync(binaire, [dossier, "--ancres", ancres, "--entetes-bitcoin", entetes, "--json"], { encoding: "utf8" });
    expect(r.status, r.stderr).to.equal(attendu.exit_code);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.verdict).to.equal(attendu.valid ? "valide" : "invalide");
    expect(rapport.exit_code).to.equal(attendu.exit_code);
    expect(rapport.controls.map((c) => c.status)).to.deep.equal(Object.values(attendu.control_statuses));
    expect(rapport.failed_checks).to.deep.equal(attendu.failed_checks);
    const statuts = Object.fromEntries(rapport.checks.map((c) => [c.id, c.status]));
    for (const id of ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "R-11", "K-8", "N-4"]) expect(statuts[id], id).to.equal("reussi");
    expect(rapport.facts.checkpoint.registry.inclusion).to.equal("prouvee");
    expect(rapport.facts.checkpoint.registry.fingerprint).to.equal(point.fingerprint);
    expect(rapport.warnings.map((w) => w.id)).to.deep.equal(attendu.warnings);
    // L'énoncé est celui du dossier publié : mêmes parties, même verdict.
    expect(rapport.statement.fr).to.equal(attendu.statement.fr);
    expect(rapport.statement.en).to.equal(attendu.statement.en);
    // Contre-épreuve : une entrée ancre_point_de_controle relabellisée en ancre de période fait échouer R-11 (CT-6 EX-11.24, règle 1).
    const registreAltere = JSON.parse(JSON.stringify(ex.registre));
    const entreePoint = registreAltere.entries.find((e) => e.role === "ancre_point_de_controle");
    entreePoint.receipts[entreePoint.transaction_index].logs[entreePoint.log_index].data = R.DOC_TYPE_PERIODE;
    fs.writeFileSync(path.join(dossier, "registre.json"), JSON.stringify(registreAltere, null, 2) + "\n");
    for (const p of indexDossier.parts) if (p.file === "registre.json") p.sha256 = sha256Hex(new Uint8Array(fs.readFileSync(path.join(dossier, p.file))));
    fs.writeFileSync(path.join(dossier, "dossier.json"), JSON.stringify(indexDossier, null, 2) + "\n");
    const r2 = spawnSync(binaire, [dossier, "--ancres", ancres, "--entetes-bitcoin", entetes, "--json"], { encoding: "utf8" });
    const rapport2 = JSON.parse(r2.stdout);
    expect(rapport2.verdict).to.equal("invalide");
    expect(rapport2.failed_checks).to.include("R-7");
    fs.rmSync(travail, { recursive: true, force: true });
    fs.rmSync(captures, { recursive: true, force: true });
  });
});
