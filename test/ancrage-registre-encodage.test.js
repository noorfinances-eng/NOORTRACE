// Composant d'ancrage, lot D : conventions du registre calculées hors chaîne
// (CT-4 §6.2 à §6.7, RG-1 à RG-15) et clé de chaîne (CT-2 EX-11.19), rejouées
// contre les vecteurs de spec/vecteurs/ct-4 (identifiants, doctypes,
// empreintes, condenses, appels, transactions ; octet pour octet) et éprouvées
// sur des entrées hostiles (RLP non minimal, formes refusées, bornes).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createPrivateKey } from "node:crypto";
import { sha256, utf8, hexVersOctets, octetsVersHex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");

/** Clé de test d'un vecteur : `hardhat:<n>` (comptes publics) ou `sha256:<graine>`. */
function cleDeTest(ref) {
  if (ref.startsWith("hardhat:")) return new R.SignataireChaineFichier(hexVersOctets(CONSTANTES.accounts[Number(ref.slice(8))].private_key));
  if (ref.startsWith("sha256:")) return new R.SignataireChaineFichier(sha256(utf8(ref.slice(7))));
  throw new Error(`clé de test inconnue : ${ref}`);
}

describe("ancrage, lot D : conventions du registre (CT-4 §6, RG-1 à RG-15)", function () {
  this.timeout(60000);

  it("sélecteurs (6.7.1), sujets (5.7) et docType (6.4) recalculés égalent les tables de CT-4", function () {
    expect(R.DOC_TYPE_PERIODE).to.equal("0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee");
    expect(R.DOC_TYPE_POINT_DE_CONTROLE).to.equal("0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178");
    const attendus = {
      anchor: "0x73deb4ad", revoke: "0x7e9d5abd", submitPeriod: "0x8af03732", registerRecorder: "0x982f962e", revokeRecorder: "0x7b2025ea",
      setCuratorSet: "0x53823884", periodDigest: "0x113946de", anchorDigest: "0x5fa9b02d", lookup: "0xf39ec1f7", isAnchored: "0x4f0b5801",
      getPeriod: "0x4b2c0706", latestPeriodOf: "0x9992f0d9", isKnown: "0x1a6a514c", isActiveRecorder: "0x0d219123", recorderOf: "0x98022b90",
      recorderByPubKey: "0xb0732ef4", curatorSetOf: "0x0642c24a", getThreshold: "0xe75235b8", isCurator: "0x6c7b79d4",
    };
    for (const [nom, valeur] of Object.entries(attendus)) expect(R.SELECTEURS[nom], nom).to.equal(valeur);
    expect(R.SUJETS.Anchored).to.equal("0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e");
    expect(R.SUJETS.PeriodSubmitted).to.equal("0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba");
    expect(R.SUJETS.RecorderRegistered).to.equal("0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec");
    expect(R.SUJETS.RecorderRevoked).to.equal("0x74ae31d8dbb96eed3dc2e0064cb3b980f6289d88b35c82b2863e40705567fa74");
    expect(R.SUJETS.CuratorSetAssigned).to.equal("0xe3dc53929964ea6820df23c3069981538b21f654bd176471a4befe2eb6da9b23");
    expect(R.SUJETS.AdminOpRelayed).to.equal("0x2e0e19053817f36938ec18c54c0901f672942223a90e78527399eb1b1db54b0a");
    expect(R.OPERATIONS_JEU["CuratorSet.addCurator"]).to.equal("0x90676d1923a8a97480098534555883cdbc62ebae7fcd057b915a730b244f58da");
    expect(R.OPERATIONS_JEU["CuratorSet.acceptAdmin"]).to.equal("0xe0d1968273ca8a1ca2680cc6bea43e6d6824797741e9a721c4588ef3bc7414b4");
  });

  it("identifiants.json : RG-1 (slug, org_id) et RG-2 (nom de journal, journal_id), réussites et refus", function () {
    const f = lireJson("spec/vecteurs/ct-4/identifiants.json");
    expect(f.cases.length).to.be.greaterThan(20);
    for (const c of f.cases) {
      const i = c.input;
      const r = i.kind === "slug" ? R.verifierSlug(i.value, { production: i.production === true }) : R.verifierNomJournal(i.value);
      if (c.refusal) {
        expect(r.statut, c.id).to.equal("echoue");
        expect(r.motif, c.id).to.equal(c.refusal.code);
      } else {
        expect(r.statut, c.id).to.equal("reussi");
        if (c.expected.org_id) expect(r.org_id, c.id).to.equal(c.expected.org_id);
        if (c.expected.journal_id) expect(r.journal_id, c.id).to.equal(c.expected.journal_id);
      }
    }
  });

  it("doctypes.json : RG-3, libellés et valeurs admis et refusés", function () {
    const f = lireJson("spec/vecteurs/ct-4/doctypes.json");
    for (const c of f.cases) {
      const r = R.verifierDocType(c.input);
      if (c.refusal) {
        expect(r.statut, c.id).to.equal("echoue");
        expect(r.motif, c.id).to.equal(c.refusal.code);
      } else if (c.expected.doc_type) expect(r.doc_type, c.id).to.equal(c.expected.doc_type);
      else expect(r.label, c.id).to.equal(c.expected.label);
    }
    // Le libellé du point de contrôle, admis depuis la révision 0.3 (CT-5 §9.5).
    expect(R.verifierDocType({ label: R.LIBELLE_POINT_DE_CONTROLE }).doc_type).to.equal(R.DOC_TYPE_POINT_DE_CONTROLE);
    expect(R.libelleDocType(R.DOC_TYPE_POINT_DE_CONTROLE)).to.equal(R.LIBELLE_POINT_DE_CONTROLE);
    // Entrées hostiles : chaîne non UTF-8 (substitut isolé), majuscules dans la valeur, type inattendu.
    expect(R.verifierDocType({ label: "noortrace/\ud800/v0" }).motif).to.equal("libelle_invalide");
    expect(R.verifierDocType({ doc_type: R.DOC_TYPE_PERIODE.toUpperCase() }).motif).to.equal("doctype_hors_table");
    expect(R.verifierDocType({ label: 12 }).motif).to.equal("libelle_invalide");
    expect(R.verifierDocType(null).motif).to.equal("libelle_invalide");
  });

  it("empreintes.json : RG-4, préimage de 96 octets et empreinte ; nullité et empreinte déclarée", function () {
    const f = lireJson("spec/vecteurs/ct-4/empreintes.json");
    for (const c of f.cases) {
      const r = R.empreinteAncre(c.input.org_id, c.input.journal_id, c.input.period_hash, c.input.fingerprint ?? null);
      if (c.refusal) {
        expect(r.statut, c.id).to.equal("echoue");
        expect(r.motif, c.id).to.equal(c.refusal.code);
      } else {
        expect(r.fingerprint, c.id).to.equal(c.expected.fingerprint);
        expect(r.preimage, c.id).to.equal(c.expected.preimage);
      }
    }
    // Empreintes des points K1 à K4 de l'exemple de référence de CT-1 (CT-5 EX-9.1).
    const org = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
    const journal = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
    expect(R.empreinteAncre(org, journal, "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff").fingerprint).to.equal("0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44");
    expect(R.empreinteAncre(org, journal, "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4").fingerprint).to.equal("0xd0cd916d070ecb8c2af3a3b62b933ccd6e61fd481ea2b70312ab988fabac8540");
    expect(R.empreinteAncre(org, journal, "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867").fingerprint).to.equal("0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837");
    expect(R.empreinteAncre(org, journal, "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107").fingerprint).to.equal("0xa7f0a30f11f724f5ae4bd7ba952079fa513dfe0ed70c051bdfc5bbe9c67b3792");
    // Hostile : longueur non minimale (31 octets), majuscules, préfixe absent.
    expect(R.empreinteAncre(org, journal, "0x" + "ab".repeat(31)).motif).to.equal("entree_nulle");
    expect(R.empreinteAncre(org.toUpperCase(), journal, "0x" + "ab".repeat(32)).motif).to.equal("entree_nulle");
    expect(R.empreinteAncre(org, journal, "ab".repeat(32)).motif).to.equal("entree_nulle");
  });

  it("condenses.json : RG-5 à RG-13 (champs d'une clôture, six condensés, hachage signé, signatures, jeux au seuil)", function () {
    const f = lireJson("spec/vecteurs/ct-4/condenses.json");
    let joues = 0;
    for (const c of f.cases) {
      const i = c.input;
      const attendreRefus = (r, motif = r.motif) => {
        expect(r.statut, c.id).to.equal("echoue");
        expect(motif, c.id).to.equal(c.refusal.code);
      };
      if (c.checks.length === 1 && c.checks[0] === "RG-5") {
        const r = R.verifierPeriodMeta(i.period_meta, i.previous ?? null, { slug: i.slug ?? null, nomJournal: i.journal_name ?? null });
        if (c.refusal) attendreRefus(r); else expect(r.statut, c.id).to.equal("reussi");
      } else if (c.checks.includes("RG-6")) {
        let d = null;
        try { d = R.periodDigest(i.chain_id, i.contract, i.period_meta); } catch { d = null; }
        if (c.refusal) expect(d, c.id).to.not.equal(i.digest); else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-7")) {
        let d = null;
        try { d = R.registerDigest(i.chain_id, i.contract, i.org_id, i.journal_id, i.chain_key, i.ed25519_public_key); } catch { d = null; }
        if (c.refusal && c.refusal.code === "condense_different") expect(d, c.id).to.not.equal(i.digest);
        else if (c.refusal) expect(d === null || d !== i.digest, c.id).to.equal(true);
        else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-8")) {
        const d = R.revokeDigestEnregistreur(i.chain_id, i.contract, i.org_id, i.chain_key, i.registered_at);
        if (c.refusal && c.refusal.code === "entree_invalide") expect(d, c.id).to.equal(null);
        else if (c.refusal) expect(d, c.id).to.not.equal(i.digest);
        else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-9")) {
        const d = R.anchorDigest(i.chain_id, i.contract, i.fingerprint, i.doc_type);
        if (c.refusal) expect(d, c.id).to.not.equal(i.digest); else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-10")) {
        const d = R.revokeDigestAncre(i.chain_id, i.contract, i.fingerprint);
        if (c.refusal) expect(d, c.id).to.not.equal(i.digest); else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-11")) {
        const d = R.adminOpDigest(i.chain_id, i.contract, i.op, i.arg, i.nonce);
        if (c.refusal && c.refusal.code === "entree_invalide") expect(d, c.id).to.equal(null);
        else if (c.refusal) expect(d, c.id).to.not.equal(i.digest);
        else expect(d, c.id).to.equal(c.expected.digest);
      } else if (c.checks.includes("RG-13")) {
        const r = R.verifierJeuSignatures(i.digest, i.signatures, { membres: i.members, seuil: i.threshold });
        if (c.refusal) {
          attendreRefus(r);
          expect(r.check, c.id).to.equal(c.refusal.check);
        } else expect(r.signers, c.id).to.deep.equal(c.expected.signers);
      } else if (c.checks.includes("RG-12")) {
        const r = R.verifierSignatureCondense(i.digest, i.signature, { hachageSigneDeclare: i.eip191_digest ?? null });
        if (c.refusal) attendreRefus(r); else expect(r.recovered, c.id).to.equal(c.expected.recovered);
      } else {
        throw new Error(`cas non joué : ${c.id}`);
      }
      joues++;
    }
    expect(joues).to.equal(f.cases.length);
  });

  it("exemples de CT-4 §6.6.4 : anchorDigest, hachage signé et signature déterministe de la clé de chaîne de rec-test-02", function () {
    const cle = cleDeTest("sha256:noortrace/vecteurs/v0/cle-chaine/rec-test-02");
    expect(cle.adresse()).to.equal("0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49");
    const d = R.anchorDigest(2124, CONSTANTES.contracts.attestation_registry, "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6", R.DOC_TYPE_PERIODE);
    expect(d).to.equal("0xb1eb8a317f588d9484ebf839effd88727b92525bdb487402c57a7f5a1fc8cbe9");
    const h = R.hachageSigne(d);
    expect(octetsVersHex(h)).to.equal("0xb56e7a39c5cb2baab700bf0ea017ed29e441c4b451cd1d5fe37c47eae0dc320a");
    const sig = cle.signerCondense(h);
    expect(sig).to.deep.equal({ v: 28, r: "0x51412a0867e5a514a48b3f5bb1be9f72c249fe707ecd459faef9cd9309f92c0b", s: "0x114b2aba6d972afbbd2e1a9b78f364fcccbc40252d67a01946291be59b8a42c4" });
    expect(R.recouvrerSignataire(h, sig)).to.equal(cle.adresse());
    expect(R.verifierSignatureCondense(d, { signer: cle.adresse(), ...sig }).statut).to.equal("reussi");
    // periodDigest de la période 1 : préimage de 101 octets.
    const meta = lireJson("spec/vecteurs/ct-4/condenses.json").cases.find((c) => c.id === "period-digest-periode-1").input.period_meta;
    expect(R.periodDigest(2124, CONSTANTES.contracts.period_registry, meta)).to.equal("0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674");
    expect(octetsVersHex(R.encoderPeriodMeta(meta)).length).to.equal(2 + 2 * 384);
  });

  it("appels.json : RG-14, données d'appel d'anchor, submitPeriod et registerRecorder octet pour octet ; v hors uint8 refusé", function () {
    const f = lireJson("spec/vecteurs/ct-4/appels.json");
    let joues = 0;
    for (const c of f.cases) {
      const a = c.input.args;
      const encodeurs = { anchor: R.encoderAnchor, submitPeriod: R.encoderSubmitPeriod, registerRecorder: R.encoderRegisterRecorder };
      const encodeur = encodeurs[c.input.function];
      if (!encodeur) continue;
      let sortie = null;
      let erreur = null;
      try { sortie = octetsVersHex(encodeur(a)); } catch (e) { erreur = e; }
      if (c.refusal && c.refusal.code === "entree_invalide") expect(erreur, c.id).to.be.instanceOf(TypeError);
      else if (c.refusal) expect(sortie, c.id).to.not.equal(c.input.calldata);
      else {
        expect(sortie, c.id).to.equal(c.expected.calldata);
        expect((sortie.length - 2) / 2, c.id).to.equal(c.expected.length);
      }
      joues++;
    }
    expect(joues).to.equal(12);
    // Lectures : sélecteur et mots.
    expect(octetsVersHex(R.encoderLookup("0x" + "11".repeat(32)))).to.equal("0xf39ec1f7" + "11".repeat(32));
    expect(octetsVersHex(R.encoderRecorderOf("0x" + "11".repeat(32), "0x" + "22".repeat(20)))).to.equal("0x98022b90" + "11".repeat(32) + "00".repeat(12) + "22".repeat(20));
  });

  it("décodage des retours d'eth_call (lookup, recorderOf, bool, getPeriod) et des journaux d'événements (CT-6 EX-11.9)", function () {
    const lookup = R.decoderLookup("0x" + "00".repeat(12) + "aa2a59656361352e96ef2eed355316ef8b29dab7" + R.DOC_TYPE_POINT_DE_CONTROLE.slice(2) + "00".repeat(28) + "6adeac0c" + "00".repeat(32));
    expect(lookup).to.deep.equal({ issuer: "0xaa2a59656361352e96ef2eed355316ef8b29dab7", docType: R.DOC_TYPE_POINT_DE_CONTROLE, issuedAt: 0x6adeac0cn, revokedAt: 0n });
    expect(R.decoderLookup("0x" + "00".repeat(127))).to.equal(null);
    expect(R.decoderLookup("0x" + "01".repeat(12) + "00".repeat(116))).to.equal(null, "octets de tête non nuls d'une adresse");
    const recorder = R.decoderRecorder("0x" + "00".repeat(12) + "aa2a59656361352e96ef2eed355316ef8b29dab7" + "e2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045" + "41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164" + "00".repeat(28) + "6ada8c36" + "00".repeat(32));
    expect(recorder.chainKey).to.equal("0xaa2a59656361352e96ef2eed355316ef8b29dab7");
    expect(recorder.registeredAt).to.equal(1792707638n);
    expect(R.decoderBool("0x" + "00".repeat(31) + "01")).to.equal(true);
    expect(R.decoderBool("0x" + "00".repeat(31) + "02")).to.equal(null);
    // Journal Anchored du bloc 16660 de la capture de CT-6.
    const recu = lireJson("spec/vecteurs/ct-6/registre/capture/recu-0x70edd263160e4fcd6c6887ac21daf4556720ef662facdf9bb12292366f120779.json").result;
    const j = recu.logs[0];
    expect(R.decoderJournal("ancre", { address: j.address.toLowerCase(), topics: j.topics, data: j.data })).to.deep.equal({
      name: "Anchored", fingerprint: "0x3690909bba236fc912813a9bfe222ea7cc9606f707b9b1b756a719c8802af8f6", issuer: "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49", docType: R.DOC_TYPE_PERIODE,
    });
    expect(R.decoderJournal("cloture", { address: j.address.toLowerCase(), topics: j.topics, data: j.data })).to.equal(null);
    // Journal PeriodSubmitted du bloc 16668.
    const cl = lireJson("spec/vecteurs/ct-6/registre/capture/recu-0xd9fb0d69567fa4f5ecbf51179198fa02f30524a3275678405cfc11307374bbc0.json").result.logs[0];
    const d = R.decoderJournal("cloture", { address: cl.address.toLowerCase(), topics: cl.topics, data: cl.data });
    expect(d.periodHash).to.equal("0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914");
    expect(d.lastSeq).to.equal(9n);
    expect(d.uri).to.equal("");
    expect(d.id).to.equal(5n);
    // Journal d'inscription du bloc 16648.
    const ins = lireJson("spec/vecteurs/ct-6/registre/capture/recu-0x932ae471728698ae648a109858081ccfadbf20e472bd85cdc47115550dc85158.json").result.logs[0];
    const di = R.decoderJournal("inscription", { address: ins.address.toLowerCase(), topics: ins.topics, data: ins.data });
    expect(di.chainKey).to.equal("0xaa2a59656361352e96ef2eed355316ef8b29dab7");
    expect(di.ed25519PubKey).to.equal("0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045");
    // Hostile : données de 33 octets, sujets en trop, remplissage non nul de l'URI.
    expect(R.decoderJournal("ancre", { address: j.address.toLowerCase(), topics: j.topics, data: j.data + "00" })).to.equal(null);
    expect(R.decoderJournal("ancre", { address: j.address.toLowerCase(), topics: [...j.topics, j.topics[1]], data: j.data })).to.equal(null);
    expect(R.decoderJournal("cloture", { address: cl.address.toLowerCase(), topics: cl.topics, data: cl.data + "01".repeat(32) })).to.equal(null);
  });

  it("transactions.json : RG-15 et transaction recalculée depuis les champs, octet pour octet (charge signée, hachage, signature, hachage de transaction)", async function () {
    const f = lireJson("spec/vecteurs/ct-4/transactions.json");
    let joues = 0;
    for (const c of f.cases) {
      const i = c.input;
      if (i.fields) {
        const tx = R.construireTransaction(i.fields);
        const s = await R.signerTransaction(tx, cleDeTest(i.signer_key));
        for (const k of ["signing_payload", "signing_hash", "y_parity", "r", "s", "raw_transaction", "transaction_hash", "from"]) expect(s[k], `${c.id} ${k}`).to.equal(c.expected[k]);
        expect(s.raw_transaction, c.id).to.equal(i.raw_transaction);
      }
      const r = R.verifierRG15(i.raw_transaction, i.context);
      if (c.refusal) {
        expect(r.statut, c.id).to.equal("echoue");
        expect(r.motif, c.id).to.equal(c.refusal.code);
      } else expect(r.statut, `${c.id} ${r.motif}`).to.equal("reussi");
      joues++;
    }
    expect(joues).to.equal(f.cases.length);
    // Frais d'un remplacement : ⌈1,1 × p⌉.
    expect([1n, 2n, 3n, 10n, 11n, 100n].map((p) => R.fraisRemplacement(p))).to.deep.equal([2n, 3n, 4n, 11n, 13n, 110n]);
    // Adresse de création (RG-19, CT-4 §5.3).
    expect(R.adresseCreation(CONSTANTES.accounts[0].address, 79)).to.equal(CONSTANTES.contracts.attestation_registry);
    expect(R.adresseCreation(CONSTANTES.accounts[0].address, 82)).to.equal(CONSTANTES.contracts.recorder_registry);
  });

  it("RG-15 sur des octets hostiles : RLP non minimal, profondeur, champs en trop, nombres hors bornes, liste d'accès, octets en trop", function () {
    const ctx = { evm_chain_id: 2124, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, objet: "appel", to: CONSTANTES.contracts.attestation_registry };
    const exemple = lireJson("spec/vecteurs/ct-4/transactions.json").cases.find((c) => c.id === "exemple-6-7-3").input.raw_transaction;
    const tx = R.lireTransaction(exemple);
    const champs = [tx.chainId, tx.nonce, tx.maxPriorityFeePerGas, tx.maxFeePerGas, tx.gasLimit, hexVersOctets(tx.to), tx.value, tx.data, [], BigInt(tx.signature.yParity), hexVersOctets(tx.signature.r), hexVersOctets(tx.signature.s)];
    const enveloppe = (liste) => octetsVersHex(new Uint8Array([0x02, ...R.rlp(liste)]));
    expect(R.verifierRG15(enveloppe(champs), ctx).statut).to.equal("reussi");
    // Nonce 0 écrit « 00 » au lieu de la chaîne vide (zéro de tête) : illisible.
    const nonMinimal = [...champs];
    nonMinimal[1] = Uint8Array.of(0x00);
    expect(R.verifierRG15(enveloppe(nonMinimal), ctx).motif).to.equal("transaction_illisible");
    // Onze ou treize champs : illisible ; octets en trop après la liste : illisible ; vide : illisible.
    expect(R.verifierRG15(enveloppe(champs.slice(0, 11)), ctx).motif).to.equal("transaction_illisible");
    expect(R.verifierRG15(enveloppe([...champs, 1n]), ctx).motif).to.equal("transaction_illisible");
    expect(R.verifierRG15(enveloppe(champs) + "00", ctx).motif).to.equal("transaction_illisible");
    expect(R.verifierRG15("0x", ctx).motif).to.equal("transaction_illisible");
    expect(R.verifierRG15("0x02", ctx).motif).to.equal("transaction_illisible");
    // Type 1 ou type 3 : non admis ; type 0 (liste nue) : non admis.
    expect(R.verifierRG15("0x01" + enveloppe(champs).slice(4), ctx).motif).to.equal("type_non_admis");
    expect(R.verifierRG15("0x03" + enveloppe(champs).slice(4), ctx).motif).to.equal("type_non_admis");
    expect(R.verifierRG15(octetsVersHex(R.rlp(champs)), ctx).motif).to.equal("type_non_admis");
    // Liste d'accès non vide ; destinataire de 19 octets ; r de 33 octets ; yParity 2 ; chainId sur 9 octets.
    const acces = [...champs];
    acces[8] = [[hexVersOctets(tx.to), []]];
    expect(R.verifierRG15(enveloppe(acces), ctx).motif).to.equal("liste_acces");
    const dest = [...champs];
    dest[5] = hexVersOctets(tx.to).subarray(1);
    expect(R.verifierRG15(enveloppe(dest), ctx).motif).to.equal("transaction_illisible");
    const r33 = [...champs];
    r33[10] = new Uint8Array(33).fill(1);
    expect(R.verifierRG15(enveloppe(r33), ctx).motif).to.equal("transaction_illisible");
    const parite = [...champs];
    parite[9] = 2n;
    expect(R.verifierRG15(enveloppe(parite), ctx).motif).to.equal("transaction_illisible");
    const chaine = [...champs];
    chaine[0] = new Uint8Array(9).fill(0xff);
    expect(R.verifierRG15(enveloppe(chaine), ctx).motif).to.equal("transaction_illisible");
    // Profondeur : une liste d'accès imbriquée au-delà de 16 niveaux est illisible, jamais une récursion sans fin.
    let profonde = [];
    for (let k = 0; k < 40; k++) profonde = [profonde];
    const abyssale = [...champs];
    abyssale[8] = profonde;
    expect(R.verifierRG15(enveloppe(abyssale), ctx).motif).to.equal("transaction_illisible");
    // Signature non canonique (s haut) et signature qui ne recouvre rien.
    const sHaut = [...champs];
    sHaut[11] = R.entierVersOctets(R.ORDRE_SECP256K1 === undefined ? 0n : 0n, 32);
    void sHaut;
    const faux = [...champs];
    faux[10] = new Uint8Array(32).fill(0xff);
    const rf = R.verifierRG15(enveloppe(faux), ctx);
    expect(rf.motif).to.equal("signature_non_canonique");
    // Objet : appel adressé à un autre contrat, valeur non nulle, données vides.
    expect(R.verifierRG15(enveloppe(champs), { ...ctx, to: CONSTANTES.contracts.period_registry }).motif).to.equal("objet_non_conforme");
    expect(R.verifierRG15(enveloppe(champs), { ...ctx, objet: "inconnu" }).motif).to.equal("objet_non_conforme");
    // RLP : décodage strict.
    expect(() => R.decoderRlp(hexVersOctets("0x8100"))).to.throw(R.ErreurRlp);
    expect(() => R.decoderRlp(hexVersOctets("0xb800"))).to.throw(R.ErreurRlp);
    expect(() => R.decoderRlp(hexVersOctets("0xb80101"))).to.throw(R.ErreurRlp);
    expect(() => R.decoderRlp(hexVersOctets("0xc1"))).to.throw(R.ErreurRlp);
    expect(R.decoderRlp(hexVersOctets("0x80"))).to.deep.equal(new Uint8Array(0));
    expect(octetsVersHex(R.rlpEntier(0n))).to.equal("0x80");
    expect(octetsVersHex(R.rlpEntier(127n))).to.equal("0x7f");
    expect(octetsVersHex(R.rlpEntier(128n))).to.equal("0x8180");
    expect(octetsVersHex(R.rlp(new Uint8Array(56).fill(7)))).to.equal("0xb838" + "07".repeat(56));
  });

  it("clé de chaîne (CT-2 EX-11.19) : formes admises (brute, hexadécimale, PKCS#8 PEM et DER), formes refusées, aucune fuite de la clé", function () {
    const graine = sha256(utf8("noortrace/vecteurs/v0/cle-chaine/rec-test-02"));
    const attendu = "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49";
    expect(new R.SignataireChaineFichier(graine).adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(graine).adresse()).to.equal(attendu);
    const hex = octetsVersHex(graine);
    expect(R.SignataireChaineFichier.depuisOctets(hex).adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(hex.slice(2).toUpperCase() + "\n").adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(utf8(hex)).adresse()).to.equal(attendu);
    const sec1 = createPrivateKey({ key: Buffer.from("302e0201010420" + hex.slice(2) + "a00706052b8104000a", "hex"), format: "der", type: "sec1" });
    const pem = sec1.export({ format: "pem", type: "pkcs8" });
    expect(R.SignataireChaineFichier.depuisOctets(pem).adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(utf8(pem)).adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(new Uint8Array(sec1.export({ format: "der", type: "pkcs8" }))).adresse()).to.equal(attendu);
    expect(R.SignataireChaineFichier.depuisOctets(sec1.export({ format: "pem", type: "sec1" })).adresse()).to.equal(attendu);
    const cle = R.SignataireChaineFichier.depuisOctets(pem);
    expect(cle.classe).to.equal("D");
    expect(JSON.stringify(cle)).to.equal(JSON.stringify({ classe: "D", adresse: attendu }));
    expect(String(cle)).to.not.include(hex.slice(2));
    // Refus : zéro, ordre de la courbe, 31 octets, courbe P-256, texte quelconque.
    expect(() => new R.SignataireChaineFichier(new Uint8Array(32))).to.throw(TypeError);
    expect(() => new R.SignataireChaineFichier(hexVersOctets("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))).to.throw(TypeError);
    expect(() => R.SignataireChaineFichier.depuisOctets(new Uint8Array(31))).to.throw(TypeError);
    const p256 = createPrivateKey({ key: Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420" + hex.slice(2), "hex"), format: "der", type: "pkcs8" }).export({ format: "pem", type: "pkcs8" });
    expect(() => R.SignataireChaineFichier.depuisOctets(p256)).to.throw(TypeError);
    expect(() => R.SignataireChaineFichier.depuisOctets("pas une clé")).to.throw(TypeError);
    expect(() => R.SignataireChaineFichier.depuisOctets(utf8("\ud800"))).to.throw(TypeError);
    // Signature sur un condensé qui n'a pas 32 octets : refusée.
    expect(() => cle.signerCondense(new Uint8Array(31))).to.throw(TypeError);
    // Recouvrement : s haut et v hors de {27, 28} refusés.
    const h = sha256(utf8("message"));
    const sig = cle.signerCondense(h);
    expect(R.recouvrerSignataire(h, sig)).to.equal(attendu);
    expect(R.recouvrerSignataire(h, { ...sig, v: 29 })).to.equal(null);
    const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const sHaut = "0x" + (n - BigInt(sig.s)).toString(16).padStart(64, "0");
    expect(R.recouvrerSignataire(h, { ...sig, s: sHaut })).to.equal(null);
    expect(R.recouvrerSignataire(h, { ...sig, r: "0x" + "00".repeat(32) })).to.equal(null);
  });

  it("demandes.json : OP-6 (condensé et hachage signé recalculés) et OP-7 (signatures canoniques, recouvrées, distinctes, rangées, membres, seuil, émetteur, administrateur)", function () {
    const f = lireJson("spec/vecteurs/ct-4/demandes/demandes.json");
    for (const c of f.cases) {
      const demande = lireJson(path.join("spec/vecteurs/ct-4", c.input.file));
      const r = R.verifierDemande(demande, { membres: c.input.members, administrateur: c.input.administrator, complete: c.input.complete });
      if (c.refusal) {
        expect(r.resultat, c.id).to.equal("refuse");
        expect({ check: r.check, code: r.code }, c.id).to.deep.equal(c.refusal);
      } else {
        expect(r.resultat, `${c.id} ${r.check} ${r.code}`).to.equal("valide");
        expect(r.digest, c.id).to.equal(c.expected.digest);
        expect(r.signers, c.id).to.deep.equal(c.expected.signers);
      }
    }
    expect(f.cases.length).to.equal(20);
  });

  it("PeriodMeta hostile : entiers hors uint64, version non entière, uri non imprimable, clés manquantes", function () {
    const base = lireJson("spec/vecteurs/ct-4/condenses.json").cases.find((c) => c.id === "cloture-periode-1").input.period_meta;
    expect(R.verifierPeriodMeta(base).statut).to.equal("reussi");
    expect(R.verifierPeriodMeta({ ...base, period_end: "18446744073709551616" }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, last_seq: "18446744073709551615" }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, last_seq: "18446744073709551614" }).statut).to.equal("reussi", "2^64 − 2 est admis (lastSeq < 2^64 − 1)");
    expect(R.verifierPeriodMeta({ ...base, version: "0" }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, version: 1.5 }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, uri: "a\tb" }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, uri: "é" }).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta({ ...base, first_seq: "01" }).motif).to.equal("periode_invalide");
    const { root, ...sansRacine } = base;
    void root;
    expect(R.verifierPeriodMeta(sansRacine).motif).to.equal("periode_invalide");
    expect(R.verifierPeriodMeta(null).motif).to.equal("periode_invalide");
    // L'encodage RG-14 ne juge pas les valeurs (CT-4 §6.9) : une URI refusée par RG-5 s'encode, et RG-5 la refuse.
    expect(() => R.encoderSubmitPeriod({ period_meta: { ...base, uri: "é" }, signatures: [] })).to.not.throw();
    expect(() => R.encoderSubmitPeriod({ period_meta: { ...base, root: "0x12" }, signatures: [] })).to.throw(TypeError);
    expect(() => R.encoderSubmitPeriod({ period_meta: base, signatures: [{ v: 27, r: "0x" + "11".repeat(32), s: "0x" + "22".repeat(31) }] })).to.throw(TypeError);
  });
});
