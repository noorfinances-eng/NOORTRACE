import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as H from "../scripts/lib/horodatage.mjs";
import * as G from "../scripts/vecteurs/ct6/rfc3161.mjs";
import { contextePointDeControle } from "../scripts/vecteurs/generer-ct6.mjs";

// CONTRÔLE 4 DE CT-6 (spec/CT-6-verificateur.md §9) : lecteur DER borné,
// TimeStampToken et TSTInfo, vérifications T-1 à T-11, statut du contrôle,
// faits et proposition de l'énoncé ; vecteurs spec/vecteurs/ct-6/rfc3161
// rejoués un par un, et leur génération déterministe. Les jetons de cas
// particuliers sont construits ici avec le constructeur DER du générateur.

const VECTEURS = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6", "rfc3161");
const ATTENDU = JSON.parse(fs.readFileSync(path.join(VECTEURS, "attendu.json"), "utf8"));
const MATERIEL = G.materielTest(G.chargerCles(path.join(VECTEURS, "cles")));
const FRAGMENTS = G.fragmentsAncres(MATERIEL);
const ANCRES = {
  "ancres-test": G.ancresHorodatage(FRAGMENTS.test),
  "ancres-qualification-declaree": G.ancresHorodatage(FRAGMENTS.qualification_declaree),
  "ancres-tsa-revoquee": G.ancresHorodatage(FRAGMENTS.tsa_revoquee),
  "ancres-unite-epinglee-revoquee": G.ancresHorodatage(FRAGMENTS.unite_epinglee_revoquee),
  "ancres-deux-autorites": G.ancresHorodatage(FRAGMENTS.deux_autorites),
};
const MANIFESTES = G.manifestesCT1();
const PH = MANIFESTES.map((m) => m.periodHash);
const jetonFichier = (nom) => fs.readFileSync(path.join(VECTEURS, "jetons", `${nom}.der`));
const statuts = (r) => Object.fromEntries(r.checks.map((c) => [c.id, c.reason ? `${c.status}:${c.reason}` : c.status]));
const echecs = (r) => r.checks.filter((c) => c.status === "echoue").map((c) => c.id);
const verifier = (octets, { periodHash = PH[0], ancres = ANCRES["ancres-test"], tsEvenement = null, langue = "fr" } = {}) => H.verifierJeton(octets, { periodHash, ancres, tsEvenement, langue });
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const NONCE = 0x0102030405060708n;

/** Jeton de base de la période 1, avec des options du constructeur. */
function jeton(options = {}) {
  return G.construireJeton({
    empreinte: Buffer.from(PH[0].slice(2), "hex"),
    genTime: "20261105100005Z",
    serie: 1,
    nonce: NONCE,
    tsaNom: MATERIEL.nomTsa,
    certificats: [MATERIEL.certs["tsa-test"]],
    signataire: MATERIEL.certs["tsa-test"],
    cle: MATERIEL.cles["tsa-test"],
    ...options,
  });
}
/** Fichier d'ancres d'horodatage : une autorité (certificat DER) et des CRL. */
function ancresAvec({ certificat = MATERIEL.certs["ac-test"], intermediaires = [], politiques = [G.POLITIQUE], qualified = null, crls = [MATERIEL.crls["crl-vide"]], statements = [], autres = [] } = {}) {
  return G.ancresHorodatage({
    tsa_authorities: [
      ...autres,
      { name: "AC de test CT-6", certificate: H.encoderPEM(certificat, "CERTIFICATE"), intermediates: intermediaires.map((c) => H.encoderPEM(c, "CERTIFICATE")), accepted_policies: politiques, qualified, source: "test" },
    ],
    revocation: { crls: crls.map((c) => H.encoderPEM(c, "X509 CRL")), statements },
  });
}
const pub = (k) => crypto.createPublicKey(k);
/** Certificat d'unité d'horodatage émis par l'AC de test pour une clé donnée. */
function certTsa(clePublique, { numero = 50, debut = "2026-06-01T00:00:00Z", fin = "2027-06-01T00:00:00Z", extensions = null, emetteur = G.nom(G.SUJETS.ac), cleEmetteur = MATERIEL.cles["ac-test"], sujet = G.nom(G.SUJETS.tsa) } = {}) {
  return G.construireCertificat({
    numero,
    emetteur,
    sujet,
    debut,
    fin,
    clePublique,
    cleEmetteur,
    extensions: extensions ?? [
      { oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0x80]), 7) },
      { oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping)) },
    ],
  });
}

describe("CT-6 contrôle 4 : lecteur DER borné (§9.3, EX-9.4)", function () {
  it("lit une structure conforme et refuse longueur indéfinie, longueur non minimale, étiquette ≥ 31, octet en trop", function () {
    const ok = H.lireDER(Buffer.from("3006020101010100", "hex"));
    expect(ok.enfants.map((e) => e.etiquette)).to.deep.equal([0x02, 0x01]);
    for (const [hexa, motif] of [
      ["3080020101" + "0000", /indéfinie/],
      ["30810302010" + "1", /non minimale/],
      ["3f2000", /≥ 31/],
      ["020101" + "00", /après la fin/],
      ["3003020101" + "ff", /après la fin/],
      ["3003020201", /au-delà/],
    ])
      expect(() => H.lireDER(Buffer.from(hexa, "hex")), hexa).to.throw(H.ErreurDER, motif);
  });

  it("BOOLEAN codé 00 ou ff seulement ; types universels de forme correcte ; NULL vide ; INTEGER non vide", function () {
    expect(() => H.lireDER(Buffer.from("010101", "hex"))).to.throw(H.ErreurDER, /BOOLEAN/);
    expect(() => H.lireDER(Buffer.from("0101ff", "hex"))).not.to.throw();
    expect(() => H.lireDER(Buffer.from("1000", "hex"))).to.throw(H.ErreurDER, /forme primitive/);
    expect(() => H.lireDER(Buffer.from("2400", "hex"))).to.throw(H.ErreurDER, /forme construite/);
    expect(() => H.lireDER(Buffer.from("050100", "hex"))).to.throw(H.ErreurDER, /NULL/);
    expect(() => H.lireDER(Buffer.from("0200", "hex"))).to.throw(H.ErreurDER, /INTEGER vide/);
  });

  it("profondeur d'imbrication : 32 acceptée, 33 refusée (EX-9.4, §15.1)", function () {
    const imbrique = (n) => {
      let b = Buffer.from("0500", "hex");
      for (let i = 0; i < n; i++) b = G.seq(b);
      return b;
    };
    expect(() => H.lireDER(imbrique(32))).not.to.throw();
    expect(() => H.lireDER(imbrique(33))).to.throw(H.ErreurDER, /profondeur/);
  });

  it("OID : notation pointée, sous-identifiant non minimal refusé ; aller-retour avec l'encodeur", function () {
    for (const o of [H.OID.tstInfo, H.OID.sha256, H.OID.p384, H.OID.qtstStatement1, "2.999.3"]) expect(H.oid(H.lireDER(G.oid(o)))).to.equal(o);
    expect(() => H.decoderOID(Buffer.from("2a8001", "hex"))).to.throw(H.ErreurDER, /non minimal/);
  });

  it("genTime : AAAAMMJJhhmmss[.f]Z, fraction sans zéro final, date existante (EX-9.15, règle 1) ; instants RFC 3339 (EX-6.11)", function () {
    expect(H.rfc3339(H.lireGenTime("20261105100005Z"))).to.equal("2026-11-05T10:00:05Z");
    expect(H.rfc3339(H.lireGenTime("20261105100005.25Z"))).to.equal("2026-11-05T10:00:05.25Z");
    for (const faux of ["20261105100005.250Z", "20260230100005Z", "202611051000Z", "20261105100005", "20261105240000Z", "20261105100005.Z"]) expect(H.lireGenTime(faux), faux).to.equal(null);
    expect(H.comparerInstants(H.lireGenTime("20261105100005.5Z"), H.instantDepuisRfc3339("2026-11-05T10:00:05.500Z"))).to.equal(0);
    expect(H.comparerInstants(H.lireGenTime("20261105100005Z"), H.lireGenTime("20261105100005.001Z"))).to.equal(-1);
  });
});

describe("CT-6 contrôle 4 : vecteurs spec/vecteurs/ct-6/rfc3161 (annexe A.3)", function () {
  it("les fichiers ont le SHA-256 de attendu.json ; les clés de test sont celles des graines documentées", function () {
    this.timeout(60_000);
    const hacher = (b) => "0x" + sha256(b).toString("hex");
    for (const [fichier, h] of Object.entries({ ...ATTENDU.keys.files, ...ATTENDU.crls })) {
      const brut = fs.readFileSync(path.join(VECTEURS, fichier));
      // Clés : SHA-256 du PKCS #8 DER ; certificats et CRL : SHA-256 du DER.
      const der = fichier.endsWith(".cle.pem") ? crypto.createPrivateKey(brut).export({ type: "pkcs8", format: "der" }) : H.decoderPEM(brut.toString("utf8"), fichier.startsWith("crl/") ? "X509 CRL" : "CERTIFICATE");
      expect(hacher(der), fichier).to.equal(h);
    }
    for (const j of ATTENDU.tokens) expect(hacher(fs.readFileSync(path.join(VECTEURS, j.file))), j.file).to.equal(j.sha256);
    for (const [id, graine] of Object.entries(G.GRAINES)) {
      const derivee = G.cleRsaDepuisGraine(graine).export({ type: "pkcs8", format: "pem" });
      expect(derivee, id).to.equal(fs.readFileSync(path.join(VECTEURS, "cles", `${id}.cle.pem`), "utf8"));
    }
  });

  it("chaque cas de attendu.json est rejoué : statuts T-1 à T-11, contrôle 4, avertissements et faits identiques", function () {
    expect(ATTENDU.cases.length).to.equal(24);
    for (const c of ATTENDU.cases) {
      const ancres = c.anchors ? ANCRES[path.basename(c.anchors, ".json")] : null;
      const r = H.verifierJeton(fs.readFileSync(path.join(VECTEURS, c.token)), { periodHash: c.dossier_period_hash, ancres });
      const etiquette = `${c.token} ${c.anchors}`;
      expect(r.checks.map((x) => ({ id: x.id, status: x.status, reason: x.reason })), etiquette).to.deep.equal(c.checks);
      expect([r.status, r.reason], etiquette).to.deep.equal([c.control_status, c.control_reason]);
      expect(r.warnings.map((w) => w.id), etiquette).to.deep.equal(c.warnings);
      expect(r.facts, etiquette).to.deep.equal(c.facts);
    }
  });

  it("une variante par vérification visée : la seule vérification en échec est la cible", function () {
    const cibles = ATTENDU.tokens.filter((j) => j.target);
    expect(cibles.map((j) => j.target)).to.deep.equal(["T-1", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-1", "T-1", "T-6"]);
    // Le jeton du point de contrôle (EX-A.13) se vérifie sur checkpoint_hash, non sur le period_hash de la période 1.
    for (const j of cibles) expect(echecs(verifier(fs.readFileSync(path.join(VECTEURS, j.file)), j.checkpoint ? { periodHash: j.checkpoint.checkpoint_hash } : {})), j.file).to.deep.equal([j.target]);
    expect(echecs(verifier(jetonFichier("periode-2")))).to.deep.equal(["T-2"]);
    expect(echecs(verifier(jetonFichier("periode-1"), { ancres: ANCRES["ancres-tsa-revoquee"] }))).to.deep.equal(["T-10"]);
  });

  it("jeton valide : faits de EX-9.19, résumé et proposition de EX-9.20 dans les deux langues", function () {
    const r = verifier(jetonFichier("periode-1"));
    expect(r.status).to.equal("reussi");
    expect(r.anchors_used).to.deep.equal(["/tsa_authorities/0", "/revocation/crls/0"]);
    expect(r.facts).to.include({ authority: "AC de test CT-6", tsu_subject_cn: "TSA de test CT-6", gen_time: "2026-11-05T10:00:05Z", upper_bound: "2026-11-05T10:00:06Z", policy: G.POLITIQUE, serial_number: "0x01", digest_algorithm: "sha256", signature_algorithm: "sha256WithRSAEncryption", key_bits: 3072, qualified_claim: false, qualified: null });
    expect(r.facts.tsu_certificate_sha256).to.equal("0x" + sha256(MATERIEL.certs["tsa-test"]).toString("hex"));
    expect(r.summary).to.equal("selon AC de test CT-6 (unité TSA de test CT-6), au plus tard 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré");
    expect(r.proposition.fr).to.equal(`selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte ${PH[0]} existait au plus tard le 2026-11-05T10:00:06Z UTC`);
    expect(r.proposition.en).to.equal(`according to AC de test CT-6 (unit TSA de test CT-6), the manifest with digest ${PH[0]} existed no later than 2026-11-05T10:00:06Z UTC`);
    const en = verifier(jetonFichier("periode-1"), { langue: "en" });
    expect(en.checks.map((c) => c.status)).to.deep.equal(r.checks.map((c) => c.status));
    expect(en.summary).to.equal("according to AC de test CT-6 (unit TSA de test CT-6), no later than 2026-11-05T10:00:06Z; no qualified status declared");
  });

  it("statut qualifié déclaré par le réviseur (T-11) : énoncé « horodatage qualifié eIDAS selon le réviseur »", function () {
    const r = verifier(jetonFichier("periode-1"), { ancres: ANCRES["ancres-qualification-declaree"] });
    expect(statuts(r)["T-11"]).to.equal("reussi");
    expect(r.facts.qualified).to.deep.equal({ framework: "eidas", source: "déclaration de test, sans valeur" });
    expect(r.proposition.fr).to.match(/ ; horodatage qualifié eIDAS selon le réviseur \(déclaration de test, sans valeur\)$/);
    expect(r.proposition.en).to.match(/; eIDAS qualified timestamp according to the reviewer \(déclaration de test, sans valeur\)$/);
    const hors = ancresAvec({ qualified: { framework: "zertes", valid_from: "2026-11-05T10:00:06.000Z", valid_to: null, source: "test" } });
    const r2 = verifier(jetonFichier("periode-1"), { ancres: hors });
    expect([statuts(r2)["T-11"], r2.status]).to.deep.equal(["non_execute:ancre_absente", "reussi"]);
  });

  it("sans fichier d'ancres : T-1 à T-6, T-8 et T-9 s'exécutent, T-7, T-10, T-11 non exécutées (ancre_absente)", function () {
    const r = verifier(jetonFichier("periode-1"), { ancres: null });
    expect(statuts(r)).to.deep.equal({ "T-1": "reussi", "T-2": "reussi", "T-3": "reussi", "T-4": "reussi", "T-5": "reussi", "T-6": "reussi", "T-7": "non_execute:ancre_absente", "T-8": "reussi", "T-9": "reussi", "T-10": "non_execute:ancre_absente", "T-11": "non_execute:ancre_absente" });
    expect([r.status, r.reason, r.facts, r.proposition]).to.deep.equal(["non_execute", "ancre_absente", null, null]);
    // Un jeton qui n'horodate pas ce manifeste échoue sans ancre (EX-5.3).
    expect(echecs(verifier(jetonFichier("periode-2"), { ancres: null }))).to.deep.equal(["T-2"]);
    expect(verifier(jetonFichier("periode-2"), { ancres: null }).status).to.equal("echoue");
  });

  it("periodHash non calculable : T-2 non exécutée (prerequis_en_echec), contrôle non exécuté (EX-5.4)", function () {
    const r = verifier(jetonFichier("periode-1"), { periodHash: null });
    expect(statuts(r)["T-2"]).to.equal("non_execute:prerequis_en_echec");
    expect([r.status, r.reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
  });
});

describe("CT-6 contrôle 4 : T-1, structure du jeton (EX-9.7)", function () {
  it("une réponse TimeStampResp n'est pas un jeton (EX-9.2)", function () {
    const reponse = G.seq(G.seq(G.entier(0)), jetonFichier("periode-1"));
    const r = verifier(reponse);
    expect(echecs(r)).to.deep.equal(["T-1"]);
    expect(r.checks[0].detail).to.match(/ContentInfo|contentType/);
  });

  it("fichier au-delà de 64 Kio, ordering codé à FALSE, eContent construit, deux SignerInfo : T-1 en échec", function () {
    expect(echecs(verifier(Buffer.concat([jetonFichier("periode-1"), Buffer.alloc(65536)])))).to.deep.equal(["T-1"]);
    // ordering encodé explicitement à FALSE (valeur DEFAULT) : refusé.
    const tst = H.lireDER(H.lireJeton(jetonFichier("periode-1")).eContent);
    expect(() => H.lireTSTInfo(G.seq(...tst.enfants.slice(0, 6).map((n) => n.octets()), G.bool(false)))).to.throw(H.ErreurDER, /ordering/);
    expect(() => H.lireTSTInfo(G.seq(...tst.enfants.slice(0, 6).map((n) => n.octets()), G.bool(true)))).not.to.throw();
    // eContent en OCTET STRING construite (24) : forme refusée.
    const j = jetonFichier("periode-1");
    const sd = H.lireDER(j).enfants[1].enfants[0];
    const eContent = sd.enfants[2].enfants[1].enfants[0];
    const construit = Buffer.from(j);
    construit[eContent.debut] = 0x24;
    expect(echecs(verifier(construit))).to.deep.equal(["T-1"]);
    // Deux SignerInfo (EX-9.7 : exactement un).
    const si = sd.enfants[sd.enfants.length - 1].enfants[0].octets();
    const deux = G.seq(G.oid(H.OID.signedData), G.explicite(0, G.seq(...sd.enfants.slice(0, -1).map((n) => n.octets()), G.set(si, si))));
    expect(verifier(deux).checks[0].detail).to.match(/2 SignerInfo/);
  });

  it("subjectKeyIdentifier comme sid (SignerInfo version 3) est accepté", function () {
    const r = verifier(jeton({ sid: "ski" }));
    expect(r.status).to.equal("reussi");
  });
});

describe("CT-6 contrôle 4 : T-2 à T-6", function () {
  it("T-2 : messageImprint d'un autre algorithme que SHA-256, ou autre empreinte", function () {
    expect(echecs(verifier(jeton({ algImprint: G.seq(G.oid(H.OID.sha384), G.nul()) })))).to.deep.equal(["T-2"]);
    expect(echecs(verifier(jeton({ empreinte: sha256(Buffer.from("autre")) })))).to.deep.equal(["T-2"]);
    expect(echecs(verifier(jeton({ algImprint: G.seq(G.oid(H.OID.sha256)) })))).to.deep.equal([]);
  });

  it("T-3 : identifiant ESS absent, attribut en double", function () {
    expect(echecs(verifier(jeton({ ess: "aucun" })))).to.deep.equal(["T-3"]);
    const double = G.seq(G.oid(H.OID.signingTime), G.set(G.temps("2026-11-05T10:00:05Z")));
    const r = verifier(jeton({ attributsEnPlus: [double, double] }));
    expect(echecs(r)).to.deep.equal(["T-3"]);
    expect(r.checks.find((c) => c.id === "T-3").detail).to.match(/deux fois/);
  });

  it("T-4 : signingCertificate (ESSCertID en SHA-1) seul, ou avec signingCertificateV2, est accepté ; certHash SHA-1 faux refusé", function () {
    expect(verifier(jeton({ ess: "v1" })).status).to.equal("reussi");
    expect(verifier(jeton({ ess: "les-deux" })).status).to.equal("reussi");
    expect(echecs(verifier(jeton({ ess: "v1", certHash: Buffer.alloc(20) })))).to.deep.equal(["T-4"]);
  });

  it("T-4 : certificat absent du jeton et des ancres → non exécutée (ancre_absente) ; fourni par les intermédiaires de l'ancre → réussie", function () {
    const sansCert = jeton({ certificats: [] });
    const r = verifier(sansCert);
    expect(statuts(r)["T-4"]).to.equal("non_execute:ancre_absente");
    expect(r.status).to.equal("non_execute");
    expect(r.reason).to.equal("ancre_absente");
    expect(verifier(sansCert, { ancres: ancresAvec({ intermediaires: [MATERIEL.certs["tsa-test"]] }) }).status).to.equal("reussi");
  });

  it("T-4 : deux certificats distincts désignés par le même sid → échec", function () {
    const jumeau = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 2, fin: "2027-06-02T00:00:00Z" });
    expect(echecs(verifier(jeton({ certificats: [MATERIEL.certs["tsa-test"], jumeau] })))).to.deep.equal(["T-4"]);
  });

  it("T-5 : ECDSA P-256 et RSASSA-PSS admis ; RSA 1024 refusé ; Ed25519 hors de la version 0", function () {
    const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const certEc = certTsa(ec.publicKey, { numero: 60 });
    const jEc = jeton({ certificats: [certEc], signataire: certEc, algSignature: G.seq(G.oid(H.OID.ecdsaWithSHA256)), signer: (d) => crypto.sign("sha256", d, ec.privateKey) });
    const rEc = verifier(jEc);
    expect(rEc.status).to.equal("reussi");
    expect([rEc.facts.signature_algorithm, rEc.facts.key_bits]).to.deep.equal(["ecdsa-with-SHA256", 256]);

    const pss = G.seq(G.oid(H.OID.rsassaPss), G.seq(G.explicite(0, G.seq(G.oid(H.OID.sha256))), G.explicite(1, G.seq(G.oid(H.OID.mgf1), G.seq(G.oid(H.OID.sha256)))), G.explicite(2, G.entier(32))));
    const jPss = jeton({ algSignature: pss, signer: (d) => crypto.sign("sha256", d, { key: MATERIEL.cles["tsa-test"], padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }) });
    expect(verifier(jPss).facts.signature_algorithm).to.equal("id-RSASSA-PSS");
    const pssSha1 = G.seq(G.oid(H.OID.rsassaPss), G.seq());
    expect(echecs(verifier(jeton({ algSignature: pssSha1, signer: (d) => crypto.sign("sha256", d, { key: MATERIEL.cles["tsa-test"], padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 20 }) })))).to.deep.equal(["T-5"]);

    const petit = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
    const certPetit = certTsa(petit.publicKey, { numero: 61 });
    const rPetit = verifier(jeton({ certificats: [certPetit], signataire: certPetit, cle: petit.privateKey }));
    expect(echecs(rPetit)).to.deep.equal(["T-5"]);
    expect(rPetit.checks.find((c) => c.id === "T-5").detail).to.match(/1024 bits/);

    const ed = crypto.generateKeyPairSync("ed25519");
    const certEd = certTsa(ed.publicKey, { numero: 62 });
    const rEd = verifier(jeton({ certificats: [certEd], signataire: certEd, algSignature: G.seq(G.oid(H.OID.ed25519)), signer: (d) => crypto.sign(null, d, ed.privateKey) }));
    expect(statuts(rEd)["T-5"]).to.equal("non_execute:hors_perimetre_version");
    expect([rEd.status, rEd.reason]).to.deep.equal(["non_execute", "hors_perimetre_version"]);
  });

  it("T-5 : signature dont la fonction diffère de digestAlgorithm, et rsaEncryption admis (EX-9.11)", function () {
    expect(echecs(verifier(jeton({ algSignature: G.seq(G.oid(H.OID.sha384WithRSAEncryption), G.nul()), signer: (d) => crypto.sign("sha384", d, MATERIEL.cles["tsa-test"]) })))).to.deep.equal(["T-5"]);
    const r = verifier(jeton({ algSignature: G.ALG.rsaEncryption }));
    expect(r.status).to.equal("reussi");
    expect(r.facts.signature_algorithm).to.equal("rsaEncryption");
  });

  it("T-6 : signature d'une autre clé, ou signature sur les attributs sous l'étiquette [0] au lieu de SET OF (EX-9.12)", function () {
    expect(echecs(verifier(jeton({ cle: MATERIEL.cles["ac-test"] })))).to.deep.equal(["T-6"]);
    const sousA0 = (d) => {
      const a0 = Buffer.from(d);
      a0[0] = 0xa0;
      return crypto.sign("sha256", a0, MATERIEL.cles["tsa-test"]);
    };
    expect(echecs(verifier(jeton({ signer: sousA0 })))).to.deep.equal(["T-6"]);
  });
});

describe("CT-6 contrôle 4 : T-7 à T-9", function () {
  const racine = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const inter = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const nomRacine = G.nom({ C: "CH", O: "Test", CN: "Racine de test" });
  const nomInter = G.nom({ C: "CH", O: "Test", CN: "Intermediaire de test" });
  const ca = (pathLen) => [{ oid: H.OID.basicConstraints, critique: true, valeur: G.seq(G.bool(true), ...(pathLen === undefined ? [] : [G.entier(pathLen)])) }, { oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0x06]), 1) }];
  const certRacine = G.construireCertificat({ numero: 1, emetteur: nomRacine, sujet: nomRacine, debut: "2026-01-01T00:00:00Z", fin: "2030-01-01T00:00:00Z", clePublique: racine.publicKey, cleEmetteur: racine.privateKey, extensions: ca() });
  const certInter = (pathLen, extensions) => G.construireCertificat({ numero: 2, emetteur: nomRacine, sujet: nomInter, debut: "2026-01-01T00:00:00Z", fin: "2030-01-01T00:00:00Z", clePublique: inter.publicKey, cleEmetteur: racine.privateKey, extensions: extensions ?? ca(pathLen) });
  const tsaSousInter = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 3, emetteur: nomInter, cleEmetteur: inter.privateKey });
  const jetonInter = (certs) => jeton({ certificats: certs, signataire: tsaSousInter });
  const crlInter = G.construireCRL({ emetteur: nomInter, thisUpdate: "2026-11-06T00:00:00Z", nextUpdate: "2026-12-06T00:00:00Z", numeroCrl: 1, skiEmetteur: Buffer.alloc(20), cleEmetteur: inter.privateKey });
  const crlRacine = G.construireCRL({ emetteur: nomRacine, thisUpdate: "2026-11-06T00:00:00Z", nextUpdate: "2026-12-06T00:00:00Z", numeroCrl: 1, skiEmetteur: Buffer.alloc(20), cleEmetteur: racine.privateKey });

  it("T-7 : chemin à deux niveaux (unité → intermédiaire du jeton → racine de l'ancre), T-10 par CRL de chaque émetteur", function () {
    const ancres = ancresAvec({ certificat: certRacine, crls: [crlInter, crlRacine] });
    const r = verifier(jetonInter([tsaSousInter, certInter()]), { ancres });
    expect(statuts(r)).to.include({ "T-7": "reussi", "T-10": "reussi" });
    expect(r.checks.find((c) => c.id === "T-7").detail).to.match(/« CN=TSA de test CT-6 » → « CN=Intermediaire de test » → « CN=Racine de test »/);
    expect(r.facts.revocation.map((x) => x.evidence)).to.deep.equal(["crl", "crl"]);
    // Intermédiaire fourni par l'ancre plutôt que par le jeton.
    expect(verifier(jetonInter([tsaSousInter]), { ancres: ancresAvec({ certificat: certRacine, intermediaires: [certInter()], crls: [crlInter, crlRacine] }) }).status).to.equal("reussi");
    // L'ancre peut être l'AC intermédiaire elle-même (identité de service, R1 F4.03).
    expect(statuts(verifier(jetonInter([tsaSousInter]), { ancres: ancresAvec({ certificat: certInter(), crls: [crlInter] }) }))["T-7"]).to.equal("reussi");
  });

  it("T-7 : intermédiaire sans basicConstraints critique, ou pathLenConstraint insuffisant → échec", function () {
    const ancres = ancresAvec({ certificat: certRacine, crls: [crlInter, crlRacine] });
    const sansBc = certInter(undefined, [{ oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0x06]), 1) }]);
    expect(echecs(verifier(jetonInter([tsaSousInter, sansBc]), { ancres }))).to.deep.equal(["T-7"]);
    expect(statuts(verifier(jetonInter([tsaSousInter, certInter(0)]), { ancres }))["T-7"]).to.equal("reussi");
  });

  it("T-7 : ancre égale au certificat de l'unité (n = 0) ; T-10 n'a rien à prouver", function () {
    const r = verifier(jetonFichier("periode-1"), { ancres: ancresAvec({ certificat: MATERIEL.certs["tsa-test"], crls: [] }) });
    expect(statuts(r)).to.include({ "T-7": "reussi", "T-10": "reussi" });
    expect(r.facts.revocation).to.deep.equal([]);
  });

  it("T-7 : autorité qui n'a pas émis l'unité, politique non admise, unité pas encore valide → échec", function () {
    expect(echecs(verifier(jetonFichier("periode-1"), { ancres: ancresAvec({ certificat: certRacine }) }))).to.deep.equal(["T-7"]);
    expect(echecs(verifier(jetonFichier("periode-1"), { ancres: ancresAvec({ politiques: ["1.2.3.4"] }) }))).to.deep.equal(["T-7"]);
    expect(verifier(jetonFichier("periode-1"), { ancres: ancresAvec({ politiques: null }) }).status).to.equal("reussi");
    const tard = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 70, debut: "2026-11-05T10:00:06Z" });
    expect(echecs(verifier(jeton({ certificats: [tard], signataire: tard })))).to.deep.equal(["T-7"]);
    // Bornes incluses : notAfter = genTime.
    const juste = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 71, fin: "2026-11-05T10:00:05Z" });
    expect(verifier(jeton({ certificats: [juste], signataire: juste })).status).to.equal("reussi");
    // Fichier d'ancres sans autorité : non exécutée.
    const vide = G.ancresHorodatage({ tsa_authorities: [], revocation: { crls: [], statements: [] } });
    expect(statuts(verifier(jetonFichier("periode-1"), { ancres: vide }))["T-7"]).to.equal("non_execute:ancre_absente");
  });

  it("T-8 : extendedKeyUsage absent, à deux valeurs ; keyUsage keyCertSign ; cA vrai → échec", function () {
    const k = pub(MATERIEL.cles["tsa-test"]);
    const cas = {
      "sans EKU": [{ oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0x80]), 7) }],
      "EKU à deux valeurs": [{ oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping), G.oid("1.3.6.1.5.5.7.3.1")) }],
      "keyUsage keyCertSign": [{ oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0x84]), 2) }, { oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping)) }],
      "cA vrai": [{ oid: H.OID.basicConstraints, critique: true, valeur: G.seq(G.bool(true)) }, { oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping)) }],
    };
    for (const [nom, extensions] of Object.entries(cas)) {
      const c = certTsa(k, { numero: 80, extensions });
      expect(echecs(verifier(jeton({ certificats: [c], signataire: c }))), nom).to.include("T-8");
    }
    const nonRep = certTsa(k, { numero: 81, extensions: [{ oid: H.OID.keyUsage, critique: true, valeur: G.bits(Buffer.from([0xc0]), 6) }, { oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping)) }] });
    expect(verifier(jeton({ certificats: [nonRep], signataire: nonRep })).status).to.equal("reussi");
  });

  it("T-9 : accuracy hors bornes, tsa différent du sujet, numéro de série de plus de 160 bits, fraction à zéro final → échec", function () {
    expect(echecs(verifier(jeton({ precisionBrute: G.seq(G.entier(1), G.implicite(0, Buffer.from([0]))) })))).to.deep.equal(["T-9"]);
    expect(echecs(verifier(jeton({ precisionBrute: G.seq(G.implicite(1, Buffer.from([0x03, 0xe8]))) })))).to.deep.equal(["T-9"]);
    expect(verifier(jeton({ precisionBrute: G.seq(G.implicite(0, Buffer.from([0x01, 0xf4]))) })).facts.upper_bound).to.equal("2026-11-05T10:00:05.5Z");
    expect(echecs(verifier(jeton({ tsaNom: G.nom({ C: "CH", CN: "Autre" }) })))).to.deep.equal(["T-9"]);
    expect(echecs(verifier(jeton({ serie: 1n << 160n })))).to.deep.equal(["T-9"]);
    expect(verifier(jeton({ serie: (1n << 160n) - 1n })).status).to.equal("reussi");
    expect(echecs(verifier(jeton({ genTime: "20261105100005.50Z" })))).to.deep.equal(["T-9"]);
  });

  it("T-9 : sans accuracy, la borne est genTime et l'énoncé renvoie à la politique (EX-9.20)", function () {
    const r = verifier(jeton({ precision: null }));
    expect(r.facts.accuracy).to.equal(null);
    expect(r.facts.upper_bound).to.equal(null);
    expect(r.proposition.fr).to.match(/existait au plus tard le 2026-11-05T10:00:05Z UTC, à la précision près de la politique 1\.3\.6\.1\.4\.1\.99999\.1\.1, que le jeton n'indique pas$/);
    expect(r.proposition.en).to.match(/no later than 2026-11-05T10:00:05Z UTC, within the accuracy of policy 1\.3\.6\.1\.4\.1\.99999\.1\.1, not stated in the token$/);
  });

  it("T-9 : genTime à fraction : upper_bound = genTime + accuracy à pleine précision", function () {
    const r = verifier(jeton({ genTime: "20261105100005.25Z" }));
    expect([r.facts.gen_time, r.facts.upper_bound]).to.deep.equal(["2026-11-05T10:00:05.25Z", "2026-11-05T10:00:06.25Z"]);
  });

  it("AV-T-1 : critical codé à FALSE dans une extension de TSTInfo, toléré ; qcStatements lu comme prétention (qualified_claim)", function () {
    const qc = G.seq(G.seq(G.oid(H.OID.qtstStatement1)));
    const extFalse = G.seq(G.oid(H.OID.qcStatements), G.bool(false), G.octets(qc));
    const r = verifier(jeton({ extensionsTstBrutes: [extFalse] }));
    expect(r.status).to.equal("reussi");
    expect(r.warnings.map((w) => w.id)).to.deep.equal(["AV-T-1"]);
    expect(r.facts.qualified_claim).to.equal(true);
    expect(r.facts.qualified).to.equal(null);
    const malforme = G.seq(G.oid(H.OID.qcStatements), G.octets(G.seq(G.entier(1))));
    expect(echecs(verifier(jeton({ extensionsTstBrutes: [malforme] })))).to.deep.equal(["T-9"]);
  });

  it("AV-T-2 : champ tsa sous une autre forme que directoryName, non comparé", function () {
    const r = verifier(jeton({ tsaGeneralName: G.tlv(0x86, Buffer.from("https://tsa.example", "latin1")) }));
    expect(r.status).to.equal("reussi");
    expect(r.warnings.map((w) => w.id)).to.deep.equal(["AV-T-2"]);
  });

  it("AV-T-4 : ts de l'événement postérieur à genTime + accuracy, avertissement seulement", function () {
    expect(verifier(jetonFichier("periode-1"), { tsEvenement: "2026-11-05T09:31:48.006Z" }).warnings).to.deep.equal([]);
    const r = verifier(jetonFichier("periode-1"), { tsEvenement: "2026-11-05T10:00:06.001Z" });
    expect(r.warnings.map((w) => w.id)).to.deep.equal(["AV-T-4"]);
    expect(r.status).to.equal("reussi");
  });
});

describe("CT-6 contrôle 4 : T-10, révocation (EX-9.16)", function () {
  const nomAc = G.nom(G.SUJETS.ac);
  const crl = (revoques, { thisUpdate = "2026-11-06T00:00:00Z", cle = MATERIEL.cles["ac-test"] } = {}) => G.construireCRL({ emetteur: nomAc, thisUpdate, nextUpdate: "2026-12-06T00:00:00Z", revoques, numeroCrl: 9, skiEmetteur: Buffer.alloc(20), cleEmetteur: cle });
  const t10 = (ancres, j = jetonFichier("periode-1")) => {
    const r = verifier(j, { ancres });
    return { statut: statuts(r)["T-10"], r };
  };

  it("révocation après genTime pour superseded, cessationOfOperation, affiliationChanged, unspecified : jeton valide", function () {
    for (const raison of [0, 3, 4, 5]) expect(t10(ancresAvec({ crls: [crl([{ numero: 2, date: "2026-11-05T12:00:00Z", raison }])] })).statut, String(raison)).to.equal("reussi");
  });

  it("keyCompromise, cACompromise, certificateHold, sans raison, ou révocation avant genTime : échec", function () {
    for (const raison of [1, 2, 6, null]) expect(t10(ancresAvec({ crls: [crl([{ numero: 2, date: "2026-11-05T12:00:00Z", raison }])] })).statut, String(raison)).to.equal("echoue");
    expect(t10(ancresAvec({ crls: [crl([{ numero: 2, date: "2026-11-05T10:00:05Z", raison: 4 }])] })).statut).to.equal("echoue");
  });

  it("CRL antérieure à genTime ou mal signée : écartée (AV-T-3), T-10 non exécutée faute de preuve", function () {
    const { statut, r } = t10(ancresAvec({ crls: [crl([], { thisUpdate: "2026-11-05T10:00:04Z" })] }));
    expect(statut).to.equal("non_execute:ancre_absente");
    expect(r.warnings.map((w) => w.id)).to.deep.equal(["AV-T-3"]);
    expect([r.status, r.reason]).to.deep.equal(["non_execute", "ancre_absente"]);
    const mal = t10(ancresAvec({ crls: [crl([], { cle: MATERIEL.cles["tsa-test"] })] }));
    expect([mal.statut, mal.r.warnings.map((w) => w.id)]).to.deep.equal(["non_execute:ancre_absente", ["AV-T-3"]]);
  });

  it("déclaration de non-révocation du réviseur postérieure à genTime ; antérieure, elle ne prouve rien", function () {
    const declaration = (quand) => ({ certificate_sha256: "0x" + sha256(MATERIEL.certs["tsa-test"]).toString("hex"), not_revoked_at: quand, method: "ocsp", source: "test" });
    const { statut, r } = t10(ancresAvec({ crls: [], statements: [declaration("2026-11-05T10:00:05.000Z")] }));
    expect(statut).to.equal("reussi");
    expect(r.facts.revocation).to.deep.equal([{ certificate_sha256: "0x" + sha256(MATERIEL.certs["tsa-test"]).toString("hex"), evidence: "declaration", issued_at: "2026-11-05T10:00:05Z" }]);
    expect(r.anchors_used).to.deep.equal(["/tsa_authorities/0", "/revocation/statements/0"]);
    expect(t10(ancresAvec({ crls: [], statements: [declaration("2026-11-05T10:00:04.999Z")] })).statut).to.equal("non_execute:ancre_absente");
  });

  it("CRL portée par le champ crls du jeton (R1 F2.04) ; une CRL illisible du jeton est écartée", function () {
    const j = jeton({ crls: [MATERIEL.crls["crl-vide"]] });
    expect(t10(ancresAvec({ crls: [] }), j).statut).to.equal("reussi");
    const revoque = jeton({ crls: [MATERIEL.crls["crl-tsa-revoquee"]] });
    expect(t10(ancresAvec({ crls: [] }), revoque).statut).to.equal("echoue");
  });
});

describe("CT-6 contrôle 4 : ancres d'horodatage (N-1, EX-12.2)", function () {
  it("controlerAncresTsa : ancres de test conformes ; PEM illisible, certificat v1, noms en double, dates inexistantes relevés", function () {
    for (const a of Object.values(ANCRES)) expect(H.controlerAncresTsa(a)).to.deep.equal([]);
    const base = ANCRES["ancres-test"];
    const pemFaux = { ...base, tsa_authorities: [{ ...base.tsa_authorities[0], certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }] };
    expect(H.controlerAncresTsa(pemFaux).length).to.equal(1);
    const double = { ...base, tsa_authorities: [base.tsa_authorities[0], base.tsa_authorities[0]] };
    expect(H.controlerAncresTsa(double)).to.deep.equal(["/tsa_authorities/1/name : nom d'autorité en double (AC de test CT-6)"]);
    const date = { ...base, revocation: { crls: [], statements: [{ certificate_sha256: "0x" + "00".repeat(32), not_revoked_at: "2026-02-30T00:00:00.000Z", method: "autre", source: "test" }] } };
    expect(H.controlerAncresTsa(date)).to.deep.equal(["/revocation/statements/0/not_revoked_at : date inexistante (2026-02-30T00:00:00.000Z)"]);
  });

  it("les fichiers d'ancres de test suivent le schéma ancres-confiance-v0 ; les faits du contrôle 4 suivent rapport-verification-v0", function () {
    const lire = (n) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", n), "utf8"));
    const ancresS = lire("ancres-confiance-v0.schema.json");
    const rapportS = lire("rapport-verification-v0.schema.json");
    const registre = J.registreSchemas([ancresS, rapportS]);
    for (const [nom, a] of Object.entries(ANCRES)) expect(J.validerSchema(a, ancresS, { registre }), nom).to.deep.equal([]);
    for (const c of ATTENDU.cases.filter((x) => x.facts)) expect(J.validerSchema(c.facts, rapportS, { registre, fragment: "#/$defs/faits/properties/timestamp" }), c.token).to.deep.equal([]);
    expect(J.validerSchema({ ...ATTENDU.cases[0].facts, key_bits: 0 }, rapportS, { registre, fragment: "#/$defs/faits/properties/timestamp" })).to.have.length(1);
  });

  it("les fragments d'ancres de test suivent le schéma ancres-confiance-v0 (forme des PEM)", function () {
    const schema = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", "ancres-confiance-v0.schema.json"), "utf8"));
    const motifCert = new RegExp(schema.$defs.pem_certificat.pattern);
    const motifCrl = new RegExp(schema.$defs.pem_crl.pattern);
    for (const f of Object.values(FRAGMENTS)) {
      for (const a of f.tsa_authorities) expect(a.certificate).to.match(motifCert);
      for (const c of f.revocation.crls) expect(c).to.match(motifCrl);
    }
  });
});

describe("CT-6 contrôle 4 : confrontation à openssl ts -verify (annexe A.3)", function () {
  const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" });
  before(function () {
    if (openssl.status !== 0) this.skip();
  });
  const verifierOpenssl = (jetonNom, empreinte, attime) => {
    const r = spawnSync("openssl", ["ts", "-verify", "-digest", empreinte.slice(2), "-in", path.join(VECTEURS, "jetons", `${jetonNom}.der`), "-token_in", "-CAfile", path.join(VECTEURS, "cles", "ac-test.pem"), "-attime", String(attime)], { encoding: "utf8" });
    return { code: r.status, sortie: r.stdout + r.stderr };
  };
  const GEN = [1793872805, 1793876405, 1793880005];

  it("les trois jetons valides : Verification: OK à genTime ; jeton de la période 2 contre periodHash de la période 1 : message imprint mismatch", function () {
    for (const n of [0, 1, 2]) {
      const r = verifierOpenssl(`periode-${n + 1}`, PH[n], GEN[n]);
      expect(r.sortie, `periode-${n + 1}`).to.match(/Verification: OK/);
      expect(r.code).to.equal(0);
    }
    expect(verifierOpenssl("periode-2", PH[0], GEN[1]).sortie).to.match(/message imprint mismatch/);
  });

  it("t7-tsa-expiree : certificate has expired ; t8-eku-non-critique : refusé (unsuitable certificate purpose)", function () {
    expect(verifierOpenssl("t7-tsa-expiree", PH[0], GEN[0]).sortie).to.match(/certificate has expired/);
    expect(verifierOpenssl("t8-eku-non-critique", PH[0], GEN[0]).sortie).to.match(/unsuitable certificate purpose/);
  });
});

describe("CT-6 contrôle 4 : génération déterministe des vecteurs rfc3161", function () {
  this.timeout(120_000);
  it("deux générations dans des répertoires vides (clés dérivées des graines) donnent les octets du dépôt", function () {
    const lister = (rep) => {
      const out = {};
      const parcourir = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) parcourir(p);
          else out[path.relative(rep, p)] = sha256(fs.readFileSync(p)).toString("hex");
        }
      };
      parcourir(rep);
      return out;
    };
    const a = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct6-rfc3161-"));
    const b = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct6-rfc3161-"));
    try {
      const point = contextePointDeControle();
      G.genererRfc3161({ racine: a, point });
      G.genererRfc3161({ racine: b, point });
      const la = lister(path.join(a, "rfc3161"));
      expect(la).to.deep.equal(lister(path.join(b, "rfc3161")));
      expect(la).to.deep.equal(lister(VECTEURS));
      expect(Object.keys(la).length).to.equal(28);
    } finally {
      fs.rmSync(a, { recursive: true, force: true });
      fs.rmSync(b, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Corrections de la revue de CT-6 : chaque règle corrigée a son test.
describe("CT-6 contrôle 4 : règles précisées par la revue", function () {
  const nomAc = G.nom(G.SUJETS.ac);
  const crlAc = (revoques) => G.construireCRL({ emetteur: nomAc, thisUpdate: "2026-11-06T00:00:00Z", nextUpdate: "2026-12-06T00:00:00Z", revoques, numeroCrl: 11, skiEmetteur: Buffer.alloc(20), cleEmetteur: MATERIEL.cles["ac-test"] });
  const pemUnite = H.encoderPEM(MATERIEL.certs["tsa-test"], "CERTIFICATE");
  const unite = (qualified = null) => ({ name: G.NOM_UNITE_EPINGLEE, certificate: pemUnite, intermediates: [], accepted_policies: [G.POLITIQUE], qualified, source: "test" });

  it("UTF8String invalide dans un nom : certificat illisible, T-1 en échec ou N-1, jamais une exception (EX-9.4, EX-15.2)", function () {
    const mauvais = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 60, sujet: G.NOM_CN_UTF8_INVALIDE });
    expect(() => H.lireCertificat(mauvais)).to.throw(H.ErreurDER, /UTF8String invalide/);
    // Certificat supplémentaire du jeton, qui ne sert pas : le jeton reste illisible (T-1).
    const r = verifier(jeton({ certificats: [MATERIEL.certs["tsa-test"], mauvais] }));
    expect(echecs(r)).to.deep.equal(["T-1"]);
    // Le même certificat en intermédiaire du fichier d'ancres : défaut N-1, pas une erreur interne.
    const ancres = ancresAvec({ intermediaires: [mauvais] });
    expect(H.controlerAncresTsa(ancres).join(" ")).to.match(/UTF8String invalide/);
    // BMPString de longueur impaire : même règle.
    const bmp = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 61, sujet: G.seq(G.set(G.seq(G.oid("2.5.4.3"), G.tlv(0x1e, Buffer.from([0x00, 0x41, 0x00]))))) });
    expect(() => H.lireCertificat(bmp)).to.throw(H.ErreurDER, /BMPString/);
  });

  it("CN d'un type de chaîne non lu (UniversalString) : tsu_subject_cn nul, le certificat reste lisible (EX-9.19)", function () {
    const ucs4 = Buffer.from([0, 0, 0, 0x54, 0, 0, 0, 0x53, 0, 0, 0, 0x41]);
    const sujet = G.seq(G.set(G.seq(G.oid("2.5.4.6"), G.imprimable("CH"))), G.set(G.seq(G.oid("2.5.4.3"), G.tlv(0x1c, ucs4))));
    const c = certTsa(pub(MATERIEL.cles["tsa-test"]), { numero: 62, sujet });
    expect(H.lireCertificat(c).cn).to.equal(null);
    const r = verifier(jeton({ certificats: [c], signataire: c, tsaNom: sujet }), { ancres: ancresAvec({ crls: [crlAc([])] }) });
    expect(r.status).to.equal("reussi");
    expect(r.facts.tsu_subject_cn).to.equal(null);
    expect(r.proposition.fr).to.include(`(unité ${r.facts.tsu_certificate_sha256})`);
  });

  it("fuzzing déterministe du jeton : evaluerJeton ne rend que des statuts, jamais une exception (EX-15.2)", function () {
    this.timeout(120_000);
    const base = jetonFichier("periode-1");
    let x = 0x9e3779b9;
    const alea = () => {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      return (x >>> 0) / 4294967296;
    };
    const ancres = ANCRES["ancres-test"];
    for (let k = 0; k < 1500; k++) {
      const m = Buffer.from(base);
      const n = 1 + Math.floor(alea() * 3);
      for (let i = 0; i < n; i++) m[Math.floor(alea() * m.length)] = Math.floor(alea() * 256);
      let r;
      expect(() => (r = H.evaluerJeton(m, { periodHash: PH[0], ancres })), `mutation ${k}`).to.not.throw();
      expect(["reussi", "echoue", "non_execute"]).to.include(r.status);
    }
  });

  it("valeurs DEFAULT encodées dans un certificat ou une CRL : critical, cA à FALSE, version v1 rendent l'objet illisible (EX-9.21)", function () {
    const cle = pub(MATERIEL.cles["tsa-test"]);
    const caFaux = certTsa(cle, { numero: 63, extensions: [{ oid: H.OID.basicConstraints, critique: true, valeur: G.seq(G.bool(false)) }, { oid: H.OID.extKeyUsage, critique: true, valeur: G.seq(G.oid(H.OID.idKpTimeStamping)) }] });
    expect(() => H.lireCertificat(caFaux)).to.throw(H.ErreurDER, /cA codé explicitement à FALSE/);
    expect(() => H.lireCertificat(MATERIEL.certs["tsa-critique-faux"])).to.throw(H.ErreurDER, /critical codé explicitement à FALSE/);
    // Version v1 encodée explicitement : a0 03 02 01 00 en tête de TBSCertificate.
    const lu = H.lireDER(MATERIEL.certs["tsa-test"]);
    const tbs = lu.enfants[0];
    const corps = Buffer.concat([G.explicite(0, G.entier(0)), ...tbs.enfants.slice(1, tbs.enfants.length - 1).map((e) => Buffer.from(e.octets()))]);
    const tbsV1 = G.seq(corps);
    const v1 = G.seq(tbsV1, G.ALG.sha256WithRSAEncryption, G.bits(crypto.sign("sha256", tbsV1, MATERIEL.cles["ac-test"])));
    expect(() => H.lireCertificat(v1)).to.throw(H.ErreurDER, /version v1 codée explicitement/);
    // CRL dont une extension encode critical à FALSE.
    const crl = H.lireDER(MATERIEL.crls["crl-vide"]);
    const crlBrute = Buffer.from(MATERIEL.crls["crl-vide"]).toString("hex");
    const ext = Buffer.from(H.lireDER(crl.enfants[0].enfants.at(-1).enfants[0].octets()).enfants[0].octets()).toString("hex");
    const extFaux = Buffer.from(G.seq(...H.lireDER(Buffer.from(ext, "hex")).enfants.map((e, i) => (i === 0 ? Buffer.concat([Buffer.from(e.octets()), G.bool(false)]) : Buffer.from(e.octets()))))).toString("hex");
    expect(crlBrute.includes(ext)).to.equal(true);
    expect(() => H.lireCRL(Buffer.from(crlBrute.replace(ext, extFaux), "hex"))).to.throw(H.ErreurDER);
  });

  it("hashAlgorithm SHA-256 encodé dans ESSCertIDv2 : toléré, AV-T-1 sur T-4 (EX-9.21)", function () {
    const s = H.lireCertificat(MATERIEL.certs["tsa-test"]);
    const issuerSerial = G.seq(G.seq(G.tlv(0xa4, s.emetteur)), G.entier(s.numero));
    const ess = G.seq(G.oid(H.OID.signingCertificateV2), G.set(G.seq(G.seq(G.seq(G.ALG.sha256, G.octets(sha256(MATERIEL.certs["tsa-test"])), issuerSerial)))));
    const r = verifier(jeton({ ess: "aucun", attributsEnPlus: [ess] }));
    expect(r.status).to.equal("reussi");
    expect(r.warnings.map((w) => [w.id, w.check])).to.deep.equal([["AV-T-1", "T-4"]]);
  });

  it("accuracy et genTime bornés : seconds au plus 86 400, entier énorme rejeté par T-9 et non par T-1, genTime + accuracy après l'an 9999 (EX-9.15)", function () {
    expect(statuts(verifier(jeton({ precision: 86400 })))["T-9"]).to.equal("reussi");
    expect(echecs(verifier(jeton({ precision: 86401 })))).to.deep.equal(["T-9"]);
    expect(echecs(verifier(jeton({ precisionBrute: G.seq(G.entier(2n ** 60n)) })))).to.deep.equal(["T-9"]);
    // genTime au dernier instant admis : la précision de 2 s déborde l'an 9999.
    const fin = verifier(jeton({ genTime: "99991231235959Z", precision: 2 }));
    expect(fin.checks.find((c) => c.id === "T-9").status).to.equal("echoue");
    expect(fin.checks.find((c) => c.id === "T-9").detail).to.match(/9999-12-31T23:59:59\.999999Z/);
    // Années 0000 à 0099 lues telles quelles (sans la correspondance 19xx de Date.UTC).
    expect(H.rfc3339(H.lireGenTime("00500101000000Z"))).to.equal("0050-01-01T00:00:00Z");
    expect(H.rfc3339(H.lireGenTime("99991231235959.999999Z"))).to.equal("9999-12-31T23:59:59.999999Z");
  });

  it("T-9, règle 3 : tsa nommé mais certificat signataire non établi → T-9 hérite de T-4 (EX-9.15)", function () {
    const r = verifier(jeton({ certificats: [] }), { ancres: ancresAvec({ crls: [] }) });
    expect(statuts(r)).to.include({ "T-4": "non_execute:ancre_absente", "T-9": "non_execute:ancre_absente", "T-7": "non_execute:ancre_absente" });
    const t4 = verifier(jetonFichier("t4-ess-autre-certificat"));
    expect(statuts(t4)).to.include({ "T-4": "echoue", "T-9": "non_execute:prerequis_en_echec" });
    // Sans champ tsa, la règle 3 n'a rien à comparer : T-9 réussit même sans S.
    expect(statuts(verifier(jeton({ certificats: [], tsaNom: null }), { ancres: ancresAvec({ crls: [] }) }))["T-9"]).to.equal("reussi");
  });

  it("T-7 et T-10 exigent T-6 : sans signature vérifiée, genTime n'est pas authentifié (EX-9.13)", function () {
    const r = verifier(jetonFichier("t6-signature"));
    expect(statuts(r)).to.include({ "T-6": "echoue", "T-7": "non_execute:prerequis_en_echec", "T-10": "non_execute:prerequis_en_echec", "T-11": "non_execute:prerequis_en_echec" });
  });

  it("T-7, choix déterministe : première autorité du fichier pour laquelle un chemin existe, identité d'abord (EX-9.13)", function () {
    const ac = ANCRES["ancres-test"].tsa_authorities[0];
    const avec = (autorites) => G.ancresHorodatage({ tsa_authorities: autorites, revocation: ANCRES["ancres-test"].revocation });
    const acPuisUnite = verifier(jetonFichier("periode-1"), { ancres: avec([ac, unite({ framework: "eidas", valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "test" })]) });
    expect([acPuisUnite.facts.authority, statuts(acPuisUnite)["T-11"], acPuisUnite.anchors_used[0]]).to.deep.equal(["AC de test CT-6", "non_execute:ancre_absente", "/tsa_authorities/0"]);
    const uniteSeule = verifier(jetonFichier("periode-1"), { ancres: avec([unite({ framework: "eidas", valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: "test" }), ac]) });
    expect([uniteSeule.facts.authority, statuts(uniteSeule)["T-11"], uniteSeule.facts.revocation]).to.deep.equal([G.NOM_UNITE_EPINGLEE, "reussi", []]);
  });

  it("T-10, certificat de l'autorité : une CRL du fichier d'ancres qui le révoque le disqualifie ; tolérée après genTime (EX-9.16)", function () {
    const avec = (crls) => G.ancresHorodatage({ tsa_authorities: [unite()], revocation: { crls: crls.map((c) => H.encoderPEM(c, "X509 CRL")), statements: [] } });
    const revoquee = verifier(jetonFichier("periode-1"), { ancres: avec([MATERIEL.crls["crl-tsa-revoquee"]]) });
    expect(echecs(revoquee)).to.deep.equal(["T-10"]);
    expect(revoquee.checks.find((c) => c.id === "T-10").detail).to.match(/certificat de l'autorité \/tsa_authorities\/0/);
    const toleree = verifier(jetonFichier("periode-1"), { ancres: avec([crlAc([{ numero: 2, date: "2026-11-05T12:00:00Z", raison: 4 }])]) });
    expect(toleree.status).to.equal("reussi");
    expect(toleree.anchors_used).to.deep.equal(["/tsa_authorities/0", "/revocation/crls/0"]);
    // Les CRL du jeton ne sont pas consultées pour le certificat de l'autorité.
    expect(verifier(jeton({ crls: [MATERIEL.crls["crl-tsa-revoquee"]] }), { ancres: avec([]) }).status).to.equal("reussi");
    // Une AC épinglée révoquée par sa racine, CRL de la racine dans le fichier d'ancres : T-10 échoue aussi.
    const ancreAc = verifier(jetonFichier("periode-1"), { ancres: ancresAvec({ crls: [MATERIEL.crls["crl-vide"], G.construireCRL({ emetteur: nomAc, thisUpdate: "2026-11-06T00:00:00Z", nextUpdate: "2026-12-06T00:00:00Z", revoques: [{ numero: 1, date: "2026-11-01T00:00:00Z", raison: 2 }], numeroCrl: 12, skiEmetteur: Buffer.alloc(20), cleEmetteur: MATERIEL.cles["ac-test"] })] }) });
    expect(echecs(ancreAc)).to.deep.equal(["T-10"]);
  });

  it("AV-T-3 : une CRL d'un autre émetteur n'est pas consultée et ne lève rien (EX-9.16, table 9.7)", function () {
    const crlTsa = G.construireCRL({ emetteur: G.nom(G.SUJETS.tsa), thisUpdate: "2026-11-06T00:00:00Z", nextUpdate: "2026-12-06T00:00:00Z", numeroCrl: 1, skiEmetteur: Buffer.alloc(20), cleEmetteur: MATERIEL.cles["tsa-test"] });
    const r = verifier(jeton({ crls: [crlTsa] }));
    expect(r.status).to.equal("reussi");
    expect(r.warnings).to.deep.equal([]);
  });
});
