// Réponses du serveur RFC 3161 interne (lot E, CT-5 §7) : les six requêtes
// de spec/vecteurs/ct-5/requetes jouées avec l'autorité de test de CT-6
// rendent, à série et horloge injectées, les six réponses `granted` de
// référence OCTET POUR OCTET (RSA PKCS#1 v1.5 est déterministe), que
// `openssl ts -verify -queryfile` accepte et que `openssl ts -reply -text`
// relit ; refus badAlg (AN-23), unacceptedPolicy (AN-29), badDataFormat,
// badRequest, unacceptedExtension, timeNotAvailable (AN-24), systemFailure ;
// nonce recopié (AN-25, « nonce mismatch » d'openssl sur une autre
// requête) ; série strictement croissante et durable, un seul émetteur par
// répertoire, épreuve de redémarrage en deux processus (AN-26) ; entrées
// hostiles (longueurs non minimales, profondeur, tailles, valeurs hors
// énumération).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { createHash, createPublicKey, verify, constants } from "node:crypto";
import { Autorite, repondre, reponseRejet, construireTstInfo, CompteurMemoire, Compteur, ErreurCompteur, lireRequeteTsa, RefusRequete, derEcriture as D, derLecture as L, OID_TSA } from "@noortrace/ancrage/serveur-interne";
import { RACINE, REQUETES, AUTORITE_TEST, POLITIQUE_TEST, lireRequete, cheminRequete, lireReponseReference, repertoireTemporaire, horlogeFixe, verifierOpenssl, relireReponse, openssl, opensslEssai, ecrire, hex } from "./fixtures/ancrage-tsa-interne/outils.mjs";

const EMETTRE = path.join(RACINE, "test", "fixtures", "ancrage-tsa-interne", "emettre.mjs");

function autoriteTest(options = {}) {
  return new Autorite({
    clePrivee: fs.readFileSync(AUTORITE_TEST.cleUnite),
    certificat: fs.readFileSync(AUTORITE_TEST.unite),
    politique: POLITIQUE_TEST,
    compteur: new CompteurMemoire(options.serie ?? 1n),
    ...options,
  });
}

/** Requête construite à la main (EX-5.1) pour les cas hors vecteurs. */
function requete({ algorithme = OID_TSA.sha256, condense = Buffer.alloc(32, 0xab), nul = true, politique = null, nonce = 0x74a6f4979421411en, certReq = true, extensions = false, version = 1, extra = null } = {}) {
  const parties = [D.entier(version), D.sequence(nul ? D.identifiantAlgorithme(algorithme, D.nul()) : D.identifiantAlgorithme(algorithme), D.chaineOctets(condense))];
  if (politique) parties.push(D.oid(politique));
  if (nonce !== null) parties.push(typeof nonce === "bigint" ? D.entier(nonce) : nonce);
  if (certReq) parties.push(D.booleen(true));
  if (extensions) parties.push(D.implicite(0, D.sequence(D.sequence(D.oid("1.3.6.1.5.5.7.1.1"), D.chaineOctets(Uint8Array.of(0x05, 0x00))))));
  if (extra) parties.push(extra);
  return D.sequence(...parties);
}

describe("ancrage lot E — réponses granted : six requêtes des vecteurs CT-5, autorité de test de CT-6", function () {
  this.timeout(60000);
  let rep;
  before(function () {
    rep = repertoireTemporaire();
  });
  after(function () {
    fs.rmSync(rep, { recursive: true, force: true });
  });

  for (const cas of REQUETES) {
    it(`${cas.nom} : réponse identique octet pour octet à ${cas.reference}.tsr, « Verification: OK » par openssl ts -verify`, function () {
      const r = repondre({ requete: lireRequete(cas.nom), autorite: autoriteTest({ serie: cas.serie }), horloge: horlogeFixe(cas.genTime.replace("Z", ".437Z")) });
      expect(r.statut).to.equal("granted");
      expect(r.serial).to.equal(cas.serie);
      expect(r.genTime).to.equal(cas.genTime);
      expect(r.echec).to.equal(null);
      const attendu = lireReponseReference(cas.reference);
      expect(hex(r.octets)).to.equal(hex(attendu));
      const chemin = ecrire(rep, `${cas.nom}.tsr`, r.octets);
      const v = verifierOpenssl({ requete: cheminRequete(cas.nom), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite });
      expect(v.code, v.stderr).to.equal(0);
      expect(v.stdout).to.include("Verification: OK");
      // Le jeton seul se vérifie aussi (-token_in), comme la partie jeton-rfc3161.der d'un dossier.
      const cheminJeton = ecrire(rep, `${cas.nom}.der`, r.jeton);
      const vj = verifierOpenssl({ requete: cheminRequete(cas.nom), reponse: cheminJeton, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite, jeton: true });
      expect(vj.stdout).to.include("Verification: OK");
    });
  }

  it("openssl ts -reply -text relit Status Granted, politique, SHA-256, l'empreinte, la série, genTime, Accuracy 0x01 seconds, Ordering no, le nonce et le TSA", function () {
    const cas = REQUETES[2];
    const r = repondre({ requete: lireRequete(cas.nom), autorite: autoriteTest({ serie: cas.serie }), horloge: horlogeFixe(cas.genTime) });
    const lu = relireReponse(ecrire(rep, "relecture.tsr", r.octets));
    expect(lu.statut).to.equal("Granted.");
    expect(lu.version).to.equal("1");
    expect(lu.politique).to.equal(POLITIQUE_TEST);
    expect(lu.algorithme).to.equal("sha256");
    expect(lu.condense).to.equal("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff");
    expect(lu.serie).to.equal("0x03EB");
    expect(lu.instant).to.equal("Nov  3 13:53:02 2026 GMT");
    expect(lu.precision).to.equal("0x01 seconds, unspecified millis, unspecified micros");
    expect(lu.ordering).to.equal("no");
    expect(lu.nonce).to.equal("0x018032FF0D74CFDA");
    expect(lu.tsa).to.equal("DirName:/C=CH/O=NOORTRACE vecteurs/CN=TSA de test CT-6");
  });

  it("structure (openssl asn1parse) : SignedData v3, digestAlgorithms SHA-256, eContent TSTInfo en OCTET STRING primitive, un certificat, SignerInfo v1 avec issuerAndSerialNumber, contentType, messageDigest, signingCertificateV2, sha256WithRSAEncryption", function () {
    const r = repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2026-11-03T13:53:02Z") });
    const sortie = openssl(["asn1parse", "-inform", "DER", "-i"], Buffer.from(r.octets));
    expect(sortie).to.include(":pkcs7-signedData");
    expect(sortie).to.match(/d=4 .*INTEGER\s+:03\n/);
    expect(sortie).to.include(":id-smime-ct-TSTInfo");
    expect(sortie).to.match(/d=6 .*prim:\s+OCTET STRING\s+\[HEX DUMP\]:3081/);
    expect(sortie).to.include(":contentType");
    expect(sortie).to.include(":messageDigest");
    expect(sortie).to.include(":id-smime-aa-signingCertificateV2");
    expect(sortie.match(/sha256WithRSAEncryption/g).length).to.be.at.least(3);
    // Aucune valeur DEFAULT encodée : pas de `ordering FALSE`, pas de hashAlgorithm dans ESSCertIDv2, pas de version v1.
    expect(sortie).to.not.match(/BOOLEAN\s+:0\n/);
    // Un seul certificat (l'unité), pas l'AC, par défaut.
    expect((sortie.match(/:X509v3 Extended Key Usage/g) ?? []).length).to.equal(1);
  });

  it("le message-digest signé est le SHA-256 des seuls octets de valeur de eContent (RFC 5652 §5.4) et la signature se vérifie sous la clé de l'unité sur le SET OF (EX-9.12)", function () {
    const r = repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2026-11-03T13:53:02Z") });
    const sha = createHash("sha256").update(Buffer.from(r.tstInfo)).digest("hex");
    expect(hex(r.jeton)).to.include(`0420${sha}`);
    // SignerInfo : dernier élément du SignedData ; signedAttrs = [0] IMPLICIT, signature = OCTET STRING final.
    const ci = L.lireSuite(L.lireUnique(r.jeton).contenu);
    const sd = L.lireSuite(L.lireSuite(ci[1].contenu)[0].contenu);
    const si = L.lireSuite(L.lireSuite(sd[sd.length - 1].contenu)[0].contenu);
    const attrs = Buffer.from(si[3].complet);
    attrs[0] = 0x31;
    const pub = createPublicKey(fs.readFileSync(AUTORITE_TEST.unite));
    expect(verify("sha256", attrs, { key: pub, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(si[5].contenu))).to.equal(true);
    // Altérer un octet de la signature la rend fausse.
    const faux = Buffer.from(si[5].contenu);
    faux[faux.length - 1] ^= 1;
    expect(verify("sha256", attrs, { key: pub, padding: constants.RSA_PKCS1_PADDING }, faux)).to.equal(false);
  });

  it("chaîne : avec `chaine: [AC]`, le jeton porte l'unité et l'AC (T-7 du client admet les deux) ; certReq absent : aucun champ certificates (RFC 3161 §2.4.1)", function () {
    const avec = repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest({ chaine: [fs.readFileSync(AUTORITE_TEST.ac)] }), horloge: horlogeFixe("2026-11-03T13:53:02Z") });
    const sortie = openssl(["asn1parse", "-inform", "DER", "-i"], Buffer.from(avec.octets));
    expect((sortie.match(/:X509v3 Subject Key Identifier/g) ?? []).length).to.equal(2);
    const chemin = ecrire(rep, "avec-ac.tsr", avec.octets);
    expect(verifierOpenssl({ requete: cheminRequete("point-k2-exemple"), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");

    const sans = repondre({ requete: requete({ certReq: false, condense: Buffer.from("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "hex") }), autorite: autoriteTest(), horloge: horlogeFixe("2026-11-03T13:53:02Z") });
    expect(sans.statut).to.equal("granted");
    expect(openssl(["asn1parse", "-inform", "DER", "-i"], Buffer.from(sans.octets))).to.not.include("X509v3");
    // Le client fournit alors lui-même l'unité : openssl vérifie avec -untrusted.
    const c2 = ecrire(rep, "sans-cert.tsr", sans.octets);
    const q2 = ecrire(rep, "sans-cert.tsq", requete({ certReq: false, condense: Buffer.from("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "hex") }));
    expect(verifierOpenssl({ requete: q2, reponse: c2, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
  });

  it("sans nonce dans la requête : aucun nonce dans le jeton ; nonce de 9 octets (bit haut) et nonce d'un octet recopiés à l'identique (AN-25)", function () {
    const h = horlogeFixe("2026-11-03T13:53:02Z");
    const sansNonce = repondre({ requete: requete({ nonce: null }), autorite: autoriteTest(), horloge: h });
    expect(sansNonce.statut).to.equal("granted");
    expect(relireReponse(ecrire(rep, "sans-nonce.tsr", sansNonce.octets)).nonce).to.equal("unspecified");
    for (const [nom, n, attendu] of [["haut", 0xf4a6f4979421411en, "0xF4A6F4979421411E"], ["un", 1n, "0x01"], ["max", 0xffffffffffffffffn, "0xFFFFFFFFFFFFFFFF"]]) {
      const q = requete({ nonce: n });
      const r = repondre({ requete: q, autorite: autoriteTest(), horloge: h });
      expect(r.statut, nom).to.equal("granted");
      expect(hex(r.tstInfo)).to.include(hex(D.entier(n)));
      const cq = ecrire(rep, `nonce-${nom}.tsq`, q);
      const cr = ecrire(rep, `nonce-${nom}.tsr`, r.octets);
      expect(relireReponse(cr).nonce).to.equal(attendu);
      expect(verifierOpenssl({ requete: cq, reponse: cr, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
    }
  });

  it("une requête à nonce différent de celui de la réponse : « nonce mismatch » (AN-25, annexe B.3)", function () {
    const r = repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2026-11-03T13:53:02Z") });
    const chemin = ecrire(rep, "nonce-mismatch.tsr", r.octets);
    const v = verifierOpenssl({ requete: cheminRequete("requete-point-k2"), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite });
    expect(v.code).to.not.equal(0);
    expect(v.stderr).to.include("nonce mismatch");
    // Et une autre empreinte : « message imprint mismatch ».
    const v2 = verifierOpenssl({ requete: cheminRequete("periode-1-reference"), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite });
    expect(v2.code).to.not.equal(0);
    expect(v2.stderr).to.match(/imprint mismatch|nonce mismatch/);
  });

  it("SHA-384 et SHA-512 sont servis (AN-23) : messageImprint recopié, openssl relit l'algorithme", function () {
    const h = horlogeFixe("2026-11-03T13:53:02Z");
    for (const [alg, nom, taille] of [[OID_TSA.sha384, "sha384", 48], [OID_TSA.sha512, "sha512", 64]]) {
      const q = requete({ algorithme: alg, condense: Buffer.alloc(taille, 0x5a), nul: false });
      const r = repondre({ requete: q, autorite: autoriteTest(), horloge: h });
      expect(r.statut, nom).to.equal("granted");
      const lu = relireReponse(ecrire(rep, `${nom}.tsr`, r.octets));
      expect(lu.algorithme).to.equal(nom);
      expect(lu.condense).to.equal("5a".repeat(taille));
      expect(verifierOpenssl({ requete: ecrire(rep, `${nom}.tsq`, q), reponse: path.join(rep, `${nom}.tsr`), ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
    }
  });

  it("tsa absent quand `tsaDansJeton` est faux ; genTime tronqué à la seconde ; accuracy 0 admise", function () {
    const r = repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest({ tsaDansJeton: false, precisionS: 0 }), horloge: horlogeFixe("2026-11-03T13:53:02.999Z") });
    const lu = relireReponse(ecrire(rep, "sans-tsa.tsr", r.octets));
    expect(lu.tsa).to.equal("unspecified");
    expect(lu.instant).to.equal("Nov  3 13:53:02 2026 GMT");
    expect(lu.precision).to.equal("0x0 seconds, unspecified millis, unspecified micros");
    expect(verifierOpenssl({ requete: cheminRequete("point-k2-exemple"), reponse: path.join(rep, "sans-tsa.tsr"), ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
  });
});

describe("ancrage lot E — refus (PKIStatus 2, failInfo nommé, aucun jeton)", function () {
  this.timeout(60000);
  let rep;
  const h = horlogeFixe("2026-11-03T13:53:02Z");
  before(function () {
    rep = repertoireTemporaire();
  });
  after(function () {
    fs.rmSync(rep, { recursive: true, force: true });
  });

  const relire = (nom, r) => relireReponse(ecrire(rep, `${nom}.tsr`, r.octets));

  it("badAlg pour SHA-1 (requête d'openssl ts -query -sha1) et MD5 (AN-23) ; openssl relit « unrecognized or unsupported algorithm identifier »", function () {
    const cheminSha1 = path.join(rep, "sha1.tsq");
    const q = opensslEssai(["ts", "-query", "-digest", "ab".repeat(20), "-sha1", "-cert", "-out", cheminSha1]);
    expect(q.code, q.stderr).to.equal(0);
    const sha1 = new Uint8Array(fs.readFileSync(cheminSha1));
    expect(openssl(["ts", "-query", "-in", cheminSha1, "-text"])).to.include("Hash Algorithm: sha1");
    for (const [nom, q] of [["sha1", sha1], ["md5", requete({ algorithme: OID_TSA.md5, condense: Buffer.alloc(16, 1) })]]) {
      const r = repondre({ requete: q, autorite: autoriteTest(), horloge: h });
      expect(r.statut, nom).to.equal("rejection");
      expect(r.echec).to.equal("badAlg");
      expect(r.jeton).to.equal(null);
      expect(r.serial).to.equal(null);
      const lu = relire(nom, r);
      expect(lu.statut).to.equal("Rejected.");
      expect(lu.echec).to.equal("unrecognized or unsupported algorithm identifier");
      expect(lu.texte).to.include("Not included.");
      // failInfo bit 0 : 03 02 07 80, comme rejet-badAlg.tsr de référence.
      expect(hex(r.octets)).to.match(/03020780$/);
    }
  });

  it("unacceptedPolicy pour une reqPolicy étrangère (AN-29) : bit 15 comme rejet-unacceptedPolicy.tsr ; la politique de l'autorité est servie", function () {
    const autre = autoriteTest({ politique: "1.3.6.1.4.1.99999.9.9" });
    const r = repondre({ requete: lireRequete("point-k2-exemple-politique-interne"), autorite: autre, horloge: h });
    expect(r.echec).to.equal("unacceptedPolicy");
    expect(hex(r.octets)).to.match(/0303000001$/);
    const lu = relire("politique", r);
    expect(lu.statut).to.equal("Rejected.");
    expect(lu.echec).to.equal("the requested TSA policy is not supported by the TSA");
    // Même bit que la réponse de référence, relu par openssl de la même façon.
    expect(relireReponse(path.join(RACINE, "spec", "vecteurs", "ct-5", "reponses", "rejet-unacceptedPolicy.tsr")).echec).to.equal(lu.echec);
    expect(repondre({ requete: lireRequete("point-k2-exemple-politique-interne"), autorite: autoriteTest(), horloge: h }).statut).to.equal("granted");
    // Sans reqPolicy, la politique de l'autorité s'applique, quelle qu'elle soit.
    expect(repondre({ requete: lireRequete("point-k2-exemple"), autorite: autre, horloge: h }).statut).to.equal("granted");
  });

  it("timeNotAvailable quand l'écart mesuré dépasse la précision (AN-24) : bit 14 comme rejet-timeNotAvailable.tsr ; 1000 ms admis, 1001 refusé, écart inconnu refusé", function () {
    const q = lireRequete("point-k2-exemple");
    expect(repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: h.murale, ecartMs: 1000 } }).statut).to.equal("granted");
    expect(repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: h.murale, ecartMs: -1000 } }).statut).to.equal("granted");
    expect(repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: h.murale, ecartMs: () => 250 } }).statut).to.equal("granted");
    for (const ecart of [1001, -1001, 1500, Number.NaN, Number.POSITIVE_INFINITY, "1", () => Number.NaN]) {
      const r = repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: h.murale, ecartMs: ecart } });
      expect(r.statut, String(ecart)).to.equal("rejection");
      expect(r.echec).to.equal("timeNotAvailable");
      expect(hex(r.octets)).to.match(/0303010002$/);
    }
    const lu = relire("time", repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: h.murale, ecartMs: 5000 } }));
    expect(lu.echec).to.equal("the TSA's time source is not available");
    expect(relireReponse(path.join(RACINE, "spec", "vecteurs", "ct-5", "reponses", "rejet-timeNotAvailable.tsr")).echec).to.equal(lu.echec);
    // Précision 0 : tout écart non nul fait cesser l'émission.
    expect(repondre({ requete: q, autorite: autoriteTest({ precisionS: 0 }), horloge: { murale: h.murale, ecartMs: 1 } }).echec).to.equal("timeNotAvailable");
    // Horloge murale illisible.
    expect(repondre({ requete: q, autorite: autoriteTest(), horloge: { murale: () => Number.NaN, ecartMs: 0 } }).echec).to.equal("timeNotAvailable");
  });

  it("unacceptedExtension pour toute extension ; badRequest pour une version autre que 1", function () {
    const ext = repondre({ requete: requete({ extensions: true }), autorite: autoriteTest(), horloge: h });
    expect(ext.echec).to.equal("unacceptedExtension");
    expect(relire("ext", ext).echec).to.equal("the requested extension is not supported by the TSA");
    const v2 = repondre({ requete: requete({ version: 2 }), autorite: autoriteTest(), horloge: h });
    expect(v2.echec).to.equal("badRequest");
    expect(relire("v2", v2).echec).to.equal("transaction not permitted or supported");
    expect(repondre({ requete: requete({ version: 0 }), autorite: autoriteTest(), horloge: h }).echec).to.equal("badRequest");
  });

  it("badDataFormat : requête vide, ordure, tronquée, octets en trop, longueur non minimale, nonce à zéro superflu (refusees.json), condensé de 31 octets, certReq FALSE encodé, BOOLEAN 01, paramètres non NULL, étiquette ≥ 31, profondeur, taille au-delà de 2048", function () {
    const cas = {
      vide: new Uint8Array(0),
      ordure: Uint8Array.of(1, 2, 3),
      tronquee: lireRequete("point-k2-exemple").subarray(0, 40),
      "octets en trop": Buffer.concat([lireRequete("point-k2-exemple"), Buffer.from([0])]),
      "longueur non minimale": Buffer.concat([Buffer.from([0x30, 0x81]), lireRequete("point-k2-exemple").subarray(1)]),
      "nonce zero superflu": D.sequence(D.entier(1), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.nul()), D.chaineOctets(Buffer.from("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "hex"))), D.tlv(0x02, Buffer.from("00018032ff0d74cfda", "hex")), D.booleen(true)),
      "condense 31 octets": requete({ condense: Buffer.alloc(31, 0xab) }),
      "condense 33 octets": requete({ condense: Buffer.alloc(33, 0xab) }),
      "sha384 avec 32 octets": requete({ algorithme: OID_TSA.sha384, condense: Buffer.alloc(32, 1) }),
      "certReq FALSE": D.sequence(D.entier(1), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.nul()), D.chaineOctets(Buffer.alloc(32, 1))), D.entier(5), D.booleen(false)),
      "BOOLEAN 01": D.sequence(D.entier(1), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.nul()), D.chaineOctets(Buffer.alloc(32, 1))), D.tlv(0x01, Uint8Array.of(1))),
      "parametres non NULL": D.sequence(D.entier(1), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.entier(0)), D.chaineOctets(Buffer.alloc(32, 1)))),
      "element inattendu": requete({ extra: D.utf8("x") }),
      "etiquette 31": Buffer.from("1f0100", "hex"),
      "pas une SEQUENCE": D.ensembleDe(D.entier(1)),
      "version non minimale": D.sequence(D.tlv(0x02, Uint8Array.of(0, 1)), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.nul()), D.chaineOctets(Buffer.alloc(32, 1)))),
      "longueur indefinie": Buffer.from("30800201010000", "hex"),
      "trop grande": D.sequence(D.entier(1), D.sequence(D.identifiantAlgorithme(OID_TSA.sha256, D.nul()), D.chaineOctets(Buffer.alloc(32, 1))), D.tlv(0x04, Buffer.alloc(2100, 7))),
    };
    let profond = D.entier(1);
    for (let i = 0; i < 40; i++) profond = D.sequence(profond);
    cas["profondeur 40"] = profond;
    for (const [nom, octets] of Object.entries(cas)) {
      const r = repondre({ requete: new Uint8Array(octets), autorite: autoriteTest(), horloge: h });
      expect(r.statut, nom).to.equal("rejection");
      expect(r.echec, nom).to.equal("badDataFormat");
      expect(r.jeton, nom).to.equal(null);
      expect(r.octets.length, nom).to.be.lessThan(260);
    }
    const lu = relire("format", repondre({ requete: cas.ordure, autorite: autoriteTest(), horloge: h }));
    expect(lu.echec).to.equal("the data submitted has the wrong format");
    expect(lu.texte).to.include("Not included.");
  });

  it("les requêtes refusées par la référence (refusees.json) qui sont encodables sont refusées ici aussi, à l'exception du nonce hors 64 bits, que le serveur sert (le nonce est au client)", function () {
    const refusees = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-5", "requetes", "refusees.json"), "utf8"));
    expect(refusees.cases.map((c) => c.id)).to.include.members(["condense-31-octets", "nonce-nul", "nonce-hors-64-bits", "certreq-faux", "nonce-zero-superflu"]);
    const zero = refusees.cases.find((c) => c.id === "nonce-zero-superflu");
    const octets = zero.input?.der ?? zero.expected?.der ?? null;
    if (octets) expect(repondre({ requete: D.depuisHex(octets), autorite: autoriteTest(), horloge: h }).echec).to.equal("badDataFormat");
    // nonce 0 : INTEGER minimal `02 01 00`, lisible ; le serveur le recopie (RFC 3161 §2.4.2) : c'est le client qui l'interdit (EX-5.3).
    const r0 = repondre({ requete: requete({ nonce: 0n }), autorite: autoriteTest(), horloge: h });
    expect(r0.statut).to.equal("granted");
    expect(hex(r0.tstInfo)).to.include("020100");
    const r64 = repondre({ requete: requete({ nonce: 1n << 64n }), autorite: autoriteTest(), horloge: h });
    expect(r64.statut).to.equal("granted");
  });

  it("systemFailure quand le compteur ne peut pas réserver de numéro ou que l'unité est hors de sa validité (T-7 échouerait)", function () {
    const casse = autoriteTest();
    casse.compteur = { suivant() { throw new Error("disque plein"); }, fermer() {} };
    const r = repondre({ requete: lireRequete("point-k2-exemple"), autorite: casse, horloge: h });
    expect(r.echec).to.equal("systemFailure");
    expect(r.erreur).to.be.instanceOf(Error);
    expect(relire("sys", r).echec).to.equal("the request cannot be handled due to system failure");
    // Unité de test valable du 2026-06-01 au 2027-06-01 : hors validité, aucune émission.
    expect(repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2027-06-02T00:00:00Z") }).echec).to.equal("systemFailure");
    expect(repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2026-05-31T23:59:59Z") }).echec).to.equal("systemFailure");
    expect(repondre({ requete: lireRequete("point-k2-exemple"), autorite: autoriteTest(), horloge: horlogeFixe("2026-06-01T00:00:00Z") }).statut).to.equal("granted");
  });

  it("reponseRejet : statusString facultatif, sans accent sur le réseau, bits de RFC 3161 §2.4.2 ; valeurs hors énumération refusées", function () {
    expect(hex(reponseRejet("badAlg"))).to.equal("3009300702010203020780");
    expect(hex(reponseRejet("unacceptedPolicy"))).to.equal("300a30080201020303000001");
    expect(hex(reponseRejet("timeNotAvailable"))).to.equal("300a30080201020303010002");
    // Même PKIStatusInfo que la référence sans statusString : rejet-timeNotAvailable.tsr (12 octets).
    expect(hex(reponseRejet("timeNotAvailable"))).to.equal(hex(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-5", "reponses", "rejet-timeNotAvailable.tsr"))));
    const avec = reponseRejet("badRequest", "requête refusée", 2);
    expect(Buffer.from(avec).toString("latin1")).to.include("requete refusee");
    expect(() => reponseRejet("badLuck")).to.throw(RangeError);
    expect(() => reponseRejet("badAlg", null, 0)).to.throw(RangeError);
    expect(() => reponseRejet("badAlg", null, 6)).to.throw(RangeError);
  });

  it("arguments : requête non Uint8Array, autorité absente, horloge sans murale() refusés", function () {
    expect(() => repondre({ requete: "abc", autorite: autoriteTest(), horloge: h })).to.throw(TypeError);
    expect(() => repondre({ requete: new Uint8Array(1), autorite: null, horloge: h })).to.throw(TypeError);
    expect(() => repondre({ requete: new Uint8Array(1), autorite: autoriteTest(), horloge: {} })).to.throw(TypeError);
  });
});

describe("ancrage lot E — lecture de la requête et TSTInfo", function () {
  it("lireRequeteTsa relit EX-5.1 : version, algorithme, empreinte, politique, nonce (octets reçus), certReq", function () {
    const q = lireRequeteTsa(lireRequete("point-k2-exemple-politique-interne"));
    expect(q.version).to.equal(1);
    expect(q.nomAlgorithme).to.equal("sha256");
    expect(hex(q.condense)).to.equal("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff");
    expect(q.reqPolicy).to.equal(POLITIQUE_TEST);
    expect(hex(q.nonce)).to.equal("018032ff0d74cfda");
    expect(q.certReq).to.equal(true);
    expect(hex(q.messageImprint)).to.equal("3031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff");
    const sans = lireRequeteTsa(lireRequete("requete-point-k2"));
    expect(sans.reqPolicy).to.equal(null);
    expect(hex(sans.nonce)).to.equal("74a6f4979421411e");
    expect(() => lireRequeteTsa("abc")).to.throw(TypeError);
    expect(() => lireRequeteTsa(new Uint8Array(0))).to.throw(RefusRequete);
  });

  it("construireTstInfo : forme attendue, refus d'une série non positive, d'un messageImprint absent, d'une précision hors 0..1, d'un nonce vide", function () {
    const imprint = lireRequeteTsa(lireRequete("requete-point-k2")).messageImprint;
    const t = construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: imprint, serie: 1001n, genTimeMs: Date.parse("2026-11-03T13:53:02Z"), precisionS: 1, nonce: Buffer.from("74a6f4979421411e", "hex"), tsa: null });
    expect(hex(t)).to.equal("3066020101060a2b06010401868d1f0101" + hex(imprint) + "020203e9" + "180f32303236313130333133353330325a" + "3003020101" + "020874a6f4979421411e");
    expect(() => construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: imprint, serie: 0n, genTimeMs: 0, precisionS: 1, nonce: null, tsa: null })).to.throw(RangeError);
    expect(() => construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: imprint, serie: 1, genTimeMs: 0, precisionS: 1, nonce: null, tsa: null })).to.throw(RangeError);
    expect(() => construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: new Uint8Array(0), serie: 1n, genTimeMs: 0, precisionS: 1, nonce: null, tsa: null })).to.throw(RangeError);
    expect(() => construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: imprint, serie: 1n, genTimeMs: 0, precisionS: 2, nonce: null, tsa: null })).to.throw(RangeError);
    expect(() => construireTstInfo({ politique: POLITIQUE_TEST, messageImprint: imprint, serie: 1n, genTimeMs: 0, precisionS: 1, nonce: new Uint8Array(0), tsa: null })).to.throw(RangeError);
  });
});

describe("ancrage lot E — numéros de série (AN-26) : croissance stricte, durabilité, émetteur unique", function () {
  this.timeout(60000);
  let rep;
  beforeEach(function () {
    rep = repertoireTemporaire();
  });
  afterEach(function () {
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("deux jetons successifs ont des séries strictement croissantes ; la série est écrite et synchronisée avant la réponse", function () {
    const compteur = Compteur.ouvrir({ repertoire: rep, debut: 1000 });
    const a = autoriteTest({ compteur });
    const h = horlogeFixe("2026-11-03T13:53:02Z");
    const r1 = repondre({ requete: lireRequete("point-k2-exemple"), autorite: a, horloge: h });
    expect(fs.readFileSync(path.join(rep, "serie"), "utf8")).to.equal("1000\n");
    const r2 = repondre({ requete: lireRequete("point-k2-exemple"), autorite: a, horloge: h });
    expect(r1.serial).to.equal(1000n);
    expect(r2.serial).to.equal(1001n);
    expect(fs.readFileSync(path.join(rep, "serie"), "utf8")).to.equal("1001\n");
    // Une réponse refusée ne consomme pas de numéro.
    repondre({ requete: new Uint8Array([1]), autorite: a, horloge: h });
    expect(fs.readFileSync(path.join(rep, "serie"), "utf8")).to.equal("1001\n");
    a.fermer();
    expect(fs.existsSync(path.join(rep, "serie.verrou"))).to.equal(false);
    expect(() => compteur.suivant()).to.throw(ErreurCompteur);
  });

  it("épreuve de redémarrage : deux processus successifs sur le même répertoire émettent des séries croissantes, et un troisième après eux aussi", function () {
    const series = [];
    for (let i = 0; i < 3; i++) {
      const r = spawnSync(process.execPath, [EMETTRE, rep, cheminRequete("point-k2-exemple"), path.join(rep, `r${i}.tsr`)], { encoding: "utf8", timeout: 30000 });
      expect(r.status, r.stderr).to.equal(0);
      const m = /^granted (\d+)$/m.exec(r.stdout);
      expect(m, r.stdout).to.not.equal(null);
      series.push(BigInt(m[1]));
      expect(fs.existsSync(path.join(rep, "serie.verrou")), "verrou rendu").to.equal(false);
    }
    expect(series).to.deep.equal([1n, 2n, 3n]);
    for (let i = 0; i < 3; i++) {
      expect(relireReponse(path.join(rep, `r${i}.tsr`)).serie).to.equal(`0x0${i + 1}`);
    }
  });

  it("un second processus émetteur sur le même répertoire est refusé tant que le premier tient le verrou (ErreurCompteur, code 3), puis admis après lui", async function () {
    const premier = spawn(process.execPath, [EMETTRE, rep, cheminRequete("point-k2-exemple"), path.join(rep, "a.tsr"), "--tenir", "1500"], { stdio: ["ignore", "pipe", "pipe"] });
    await new Promise((resoudre) => premier.stdout.once("data", resoudre));
    const second = spawnSync(process.execPath, [EMETTRE, rep, cheminRequete("point-k2-exemple"), path.join(rep, "b.tsr")], { encoding: "utf8", timeout: 30000 });
    expect(second.status, second.stdout + second.stderr).to.equal(3);
    expect(second.stdout).to.include("verrou refuse");
    const code = await new Promise((resoudre) => premier.once("exit", resoudre));
    expect(code).to.equal(0);
    const troisieme = spawnSync(process.execPath, [EMETTRE, rep, cheminRequete("point-k2-exemple"), path.join(rep, "c.tsr")], { encoding: "utf8", timeout: 30000 });
    expect(troisieme.status).to.equal(0);
    expect(troisieme.stdout).to.include("granted 2");
  });

  it("verrou périmé d'un processus disparu : repris ; verrou d'un processus vivant : refusé ; fichier de série corrompu : refusé", function () {
    fs.writeFileSync(path.join(rep, "serie.verrou"), "999999\n");
    const c = Compteur.ouvrir({ repertoire: rep, vivant: () => false });
    expect(c.suivant()).to.equal(1n);
    c.fermer();
    fs.writeFileSync(path.join(rep, "serie.verrou"), "424242\n");
    expect(() => Compteur.ouvrir({ repertoire: rep, vivant: () => true })).to.throw(ErreurCompteur, /verrou tenu/);
    fs.unlinkSync(path.join(rep, "serie.verrou"));
    fs.writeFileSync(path.join(rep, "serie"), "douze\n");
    expect(() => Compteur.ouvrir({ repertoire: rep })).to.throw(ErreurCompteur, /illisible/);
    expect(fs.existsSync(path.join(rep, "serie.verrou")), "verrou rendu sur échec").to.equal(false);
    expect(() => Compteur.ouvrir({ repertoire: rep, debut: 0 })).to.throw(RangeError);
    expect(() => Compteur.ouvrir({})).to.throw(TypeError);
  });

  it("CompteurMemoire : même interface, rien d'écrit", function () {
    const c = new CompteurMemoire(5n);
    expect(c.courant).to.equal(4n);
    expect(c.suivant()).to.equal(5n);
    expect(c.suivant()).to.equal(6n);
    expect(c.ouvert).to.equal(true);
    expect(fs.readdirSync(rep)).to.deep.equal([]);
  });
});
