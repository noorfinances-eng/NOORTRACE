// Encodeur et lecteur DER du serveur RFC 3161 interne (lot E,
// paquets/ancrage/src/serveur-interne/der-ecriture.mjs et der-lecture.mjs) :
// X.690 longueurs minimales, INTEGER minimal, BOOLEAN ff, GeneralizedTime
// sans fraction, SET OF trié, étiquettes contextuelles ; lecteur borné du
// profil de CT-6 §9.3 (EX-9.4, EX-9.21) : longueur non minimale ou
// indéfinie, étiquette ≥ 31, BOOLEAN autre que 00/ff, octets en trop,
// profondeur. Confrontation : `openssl asn1parse` relit chaque encodage.

import { expect } from "chai";
import { derEcriture as D, derLecture as L } from "@noortrace/ancrage/serveur-interne";
import { openssl, hex } from "./fixtures/ancrage-tsa-interne/outils.mjs";

const asn1 = (octets) => openssl(["asn1parse", "-inform", "DER", "-i"], Buffer.from(octets));

describe("ancrage lot E — encodeur DER (X.690)", function () {
  it("longueurs : forme courte sous 128, forme longue minimale au-delà", function () {
    expect(hex(D.longueur(0))).to.equal("00");
    expect(hex(D.longueur(127))).to.equal("7f");
    expect(hex(D.longueur(128))).to.equal("8180");
    expect(hex(D.longueur(255))).to.equal("81ff");
    expect(hex(D.longueur(256))).to.equal("820100");
    expect(hex(D.longueur(65535))).to.equal("82ffff");
    expect(hex(D.longueur(65536))).to.equal("83010000");
    expect(() => D.longueur(-1)).to.throw(RangeError);
  });

  it("INTEGER minimal : 00 de tête seulement si le bit haut vaut 1 ; négatifs en complément à deux", function () {
    expect(hex(D.entier(0))).to.equal("020100");
    expect(hex(D.entier(1))).to.equal("020101");
    expect(hex(D.entier(127))).to.equal("02017f");
    expect(hex(D.entier(128))).to.equal("02020080");
    expect(hex(D.entier(256))).to.equal("02020100");
    expect(hex(D.entier(1001n))).to.equal("020203e9");
    expect(hex(D.entier(0x74a6f4979421411en))).to.equal("020874a6f4979421411e");
    expect(hex(D.entier(0xf4a6f4979421411en))).to.equal("020900f4a6f4979421411e");
    expect(hex(D.entier(-1))).to.equal("0201ff");
    expect(hex(D.entier(-128))).to.equal("020180");
    expect(hex(D.entier(-129))).to.equal("0202ff7f");
    expect(() => D.entier(1.5)).to.throw(RangeError);
    expect(() => D.entier("1")).to.throw(TypeError);
  });

  it("INTEGER depuis des octets : zéros de tête retirés, 00 ajouté si nécessaire", function () {
    expect(hex(D.entierDepuisOctets(Uint8Array.of(0, 0, 0x03, 0xe9)))).to.equal("020203e9");
    expect(hex(D.entierDepuisOctets(Uint8Array.of(0x80)))).to.equal("02020080");
    expect(hex(D.entierDepuisOctets(new Uint8Array(0)))).to.equal("020100");
    expect(hex(D.entierDepuisOctets(Uint8Array.of(0, 0)))).to.equal("020100");
  });

  it("BOOLEAN ff/00, NULL, OCTET STRING, BIT STRING, bits nommés (zéros de fin retirés)", function () {
    expect(hex(D.booleen(true))).to.equal("0101ff");
    expect(hex(D.booleen(false))).to.equal("010100");
    expect(hex(D.nul())).to.equal("0500");
    expect(hex(D.chaineOctets(Uint8Array.of(1, 2)))).to.equal("04020102");
    expect(hex(D.chaineBits(Uint8Array.of(0xab)))).to.equal("030200ab");
    expect(hex(D.bitsNommes([0]))).to.equal("03020780"); // badAlg, keyUsage digitalSignature
    expect(hex(D.bitsNommes([5, 6]))).to.equal("03020106"); // keyCertSign, cRLSign
    expect(hex(D.bitsNommes([15]))).to.equal("0303000001"); // unacceptedPolicy (référence rejet-unacceptedPolicy.tsr)
    expect(hex(D.bitsNommes([14]))).to.equal("0303010002"); // timeNotAvailable (référence rejet-timeNotAvailable.tsr)
    expect(hex(D.bitsNommes([25]))).to.equal("03050600000040"); // systemFailure
    expect(hex(D.bitsNommes([]))).to.equal("030100");
  });

  it("OBJECT IDENTIFIER : arcs multi-octets, confronté aux octets d'EX-5.1 et de CT-6 §9.4", function () {
    expect(hex(D.oid("2.16.840.1.101.3.4.2.1"))).to.equal("0609608648016503040201");
    expect(hex(D.oid("1.3.6.1.4.1.99999.1.1"))).to.equal("060a2b06010401868d1f0101");
    expect(hex(D.oid("1.2.840.113549.1.9.16.2.47"))).to.equal("060b2a864886f70d010910022f");
    expect(hex(D.oid("1.3.6.1.5.5.7.3.8"))).to.equal("06082b06010505070308");
    expect(hex(D.oid("1.2.840.10045.3.1.7"))).to.equal("06082a8648ce3d030107");
    expect(hex(D.oid("1.3.132.0.34"))).to.equal("06052b81040022");
    expect(() => D.oid("3.1")).to.throw(RangeError);
    expect(() => D.oid("0.40")).to.throw(RangeError);
    expect(() => D.oid("1")).to.throw(RangeError);
    expect(() => D.oid("1.a")).to.throw(RangeError);
  });

  it("GeneralizedTime à la seconde sans fraction ; UTCTime 1950–2049 ; `Time` de RFC 5280 bascule en 2050", function () {
    expect(Buffer.from(D.tempsGeneralise(Date.parse("2026-11-03T13:53:02.999Z"))).toString("latin1")).to.equal("\x18\x0f20261103135302Z");
    expect(Buffer.from(D.tempsUtc(Date.parse("2026-06-01T00:00:00Z"))).toString("latin1")).to.equal("\x17\x0d260601000000Z");
    expect(D.temps(Date.parse("2049-12-31T23:59:59Z"))[0]).to.equal(0x17);
    expect(D.temps(Date.parse("2050-01-01T00:00:00Z"))[0]).to.equal(0x18);
    expect(() => D.tempsUtc(Date.parse("2050-01-01T00:00:00Z"))).to.throw(RangeError);
    expect(() => D.tempsGeneralise(Number.NaN)).to.throw(RangeError);
  });

  it("SET OF trié par les octets des encodages (X.690 §11.6), SEQUENCE dans l'ordre donné", function () {
    const a = D.entier(3);
    const b = D.chaineOctets(Uint8Array.of(1));
    const c = D.entier(1);
    expect(hex(D.ensembleDe(b, a, c))).to.equal("3109" + "020101" + "020103" + "040101");
    expect(hex(D.sequence(b, a, c))).to.equal("3009" + "040101" + "020103" + "020101");
    expect(D.comparerOctets(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).to.equal(0);
    expect(D.comparerOctets(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 1))).to.equal(-1);
  });

  it("étiquettes contextuelles : EXPLICIT enveloppe, IMPLICIT réétiquette en gardant la forme", function () {
    expect(hex(D.explicite(0, D.entier(1)))).to.equal("a003020101");
    expect(hex(D.implicite(0, D.chaineOctets(Uint8Array.of(9))))).to.equal("800109");
    expect(hex(D.implicite(6, D.ia5("a")))).to.equal("860161");
    expect(hex(D.implicite(0, D.ensembleDe(D.entier(1))))).to.equal("a003020101");
    expect(() => D.explicite(31, D.nul())).to.throw(RangeError);
    expect(() => D.tlv(0x1f, new Uint8Array(0))).to.throw(RangeError);
  });

  it("chaînes : UTF8String, PrintableString (jeu restreint), IA5String (ASCII)", function () {
    expect(hex(D.utf8("é"))).to.equal("0c02c3a9");
    expect(hex(D.imprimable("CH"))).to.equal("13024348");
    expect(() => D.imprimable("é")).to.throw(RangeError);
    expect(() => D.imprimable("a&b")).to.throw(RangeError);
    expect(() => D.ia5("é")).to.throw(RangeError);
  });

  it("PEM aller-retour et hexadécimal préfixé", function () {
    const der = D.sequence(D.entier(1));
    const texte = D.pem("CERTIFICATE", der);
    expect(texte).to.match(/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=]+\n-----END CERTIFICATE-----\n$/);
    expect(hex(D.depuisPem(texte, "CERTIFICATE"))).to.equal(hex(der));
    expect(() => D.depuisPem(texte, "X509 CRL")).to.throw(RangeError);
    expect(D.versHex(der)).to.equal("0x3003020101");
    expect(hex(D.depuisHex("0x3003020101"))).to.equal(hex(der));
    expect(() => D.depuisHex("3003")).to.throw(RangeError);
    expect(() => D.depuisHex("0xABCD")).to.throw(RangeError);
  });

  it("openssl asn1parse relit un composé (SEQUENCE { INTEGER, SET OF, [0] EXPLICIT, GeneralizedTime, OID })", function () {
    const octets = D.sequence(D.entier(1001n), D.ensembleDe(D.oid("2.16.840.1.101.3.4.2.1")), D.explicite(0, D.booleen(true)), D.tempsGeneralise(Date.parse("2026-11-03T13:53:02Z")), D.oid("1.3.6.1.4.1.99999.1.1"));
    const sortie = asn1(octets);
    expect(sortie).to.include("INTEGER           :03E9");
    expect(sortie).to.include("OBJECT            :sha256");
    expect(sortie).to.include("BOOLEAN           :255");
    expect(sortie).to.include("GENERALIZEDTIME   :20261103135302Z");
    expect(sortie).to.include("1.3.6.1.4.1.99999.1.1");
  });
});

describe("ancrage lot E — lecteur DER borné (CT-6 §9.3)", function () {
  const lit = (h) => L.lireUnique(Buffer.from(h, "hex"));

  it("relit un élément, son contenu et ses octets complets", function () {
    const e = lit("020203e9");
    expect(e.etiquette).to.equal(2);
    expect(e.construit).to.equal(false);
    expect(hex(e.contenu)).to.equal("03e9");
    expect(hex(e.complet)).to.equal("020203e9");
    expect(L.valeurEntier(e)).to.equal(1001n);
    expect(L.valeurEntier(lit("0201ff"))).to.equal(-1n);
    expect(L.valeurEntier(lit("02020080"))).to.equal(128n);
  });

  it("refuse les longueurs non minimales, indéfinies ou tronquées (EX-9.4)", function () {
    expect(() => lit("028103e9")).to.throw(L.ErreurDer, /non minimale/);
    expect(() => lit("0282000101")).to.throw(L.ErreurDer, /non minimale/);
    expect(() => lit("308000")).to.throw(L.ErreurDer, /indéfinie/);
    expect(() => lit("020301")).to.throw(L.ErreurDer, /tronqué/);
    expect(() => lit("02")).to.throw(L.ErreurDer, /prématurée/);
    expect(() => lit("")).to.throw(L.ErreurDer);
    expect(() => lit("0285010000000001")).to.throw(L.ErreurDer, /quatre octets/);
  });

  it("refuse une étiquette ≥ 31, des octets après la structure, un BOOLEAN autre que 00/ff, un INTEGER non minimal", function () {
    expect(() => lit("1f0100")).to.throw(L.ErreurDer, /31/);
    expect(() => lit("02010100")).to.throw(L.ErreurDer, /après la fin/);
    expect(() => L.valeurBooleen(lit("010101"))).to.throw(L.ErreurDer, /00 ou ff/);
    expect(() => L.valeurBooleen(lit("01020000"))).to.throw(L.ErreurDer);
    expect(L.valeurBooleen(lit("0101ff"))).to.equal(true);
    expect(() => L.contenuEntier(lit("02020001"))).to.throw(L.ErreurDer, /non minimal/);
    expect(() => L.contenuEntier(lit("0202ff80"))).to.throw(L.ErreurDer, /non minimal/);
    expect(() => L.contenuEntier(lit("0200"))).to.throw(L.ErreurDer, /vide/);
  });

  it("borne la profondeur d'imbrication à 32", function () {
    let octets = Buffer.from("020101", "hex");
    for (let i = 0; i < 40; i++) octets = Buffer.from(D.sequence(octets));
    const descendre = (e, p) => {
      for (const f of L.lireSuite(e.contenu, p)) if (f.construit) descendre(f, p + 1);
    };
    expect(() => descendre(L.lireUnique(octets), 1)).to.throw(L.ErreurDer, /profondeur/);
    let peu = Buffer.from("020101", "hex");
    for (let i = 0; i < 10; i++) peu = Buffer.from(D.sequence(peu));
    expect(() => descendre(L.lireUnique(peu), 1)).to.not.throw();
  });

  it("OID : relecture de la forme pointée, refus d'un sous-identifiant non minimal ou tronqué", function () {
    expect(L.valeurOid(lit("0609608648016503040201"))).to.equal("2.16.840.1.101.3.4.2.1");
    expect(L.valeurOid(lit("060a2b06010401868d1f0101"))).to.equal("1.3.6.1.4.1.99999.1.1");
    expect(L.valeurOid(lit("06052b81040022"))).to.equal("1.3.132.0.34");
    expect(() => L.valeurOid(lit("06028001"))).to.throw(L.ErreurDer, /non minimal/);
    expect(() => L.valeurOid(lit("06022b81"))).to.throw(L.ErreurDer, /tronqué/);
    expect(() => L.valeurOid(lit("0600"))).to.throw(L.ErreurDer, /vide/);
  });

  it("Time : UTCTime lu 20AA sous 50 et 19AA sinon ; GeneralizedTime avec fraction sans zéro final", function () {
    expect(L.valeurTemps(lit("170d3236303630313030303030305a"))).to.equal(Date.parse("2026-06-01T00:00:00Z"));
    expect(L.valeurTemps(lit("170d3939303130313030303030305a"))).to.equal(Date.parse("1999-01-01T00:00:00Z"));
    expect(L.valeurTemps(lit("180f32303236313130333133353330325a"))).to.equal(Date.parse("2026-11-03T13:53:02Z"));
    expect(L.valeurTemps(L.lireUnique(D.tlv(0x18, Buffer.from("20261103135302.5Z"))))).to.equal(Date.parse("2026-11-03T13:53:02.500Z"));
    expect(() => L.valeurTemps(L.lireUnique(D.tlv(0x18, Buffer.from("20261103135302.50Z"))))).to.throw(L.ErreurDer);
    expect(() => L.valeurTemps(L.lireUnique(D.tlv(0x18, Buffer.from("20261103135302+0100"))))).to.throw(L.ErreurDer);
    expect(() => L.valeurTemps(L.lireUnique(D.tlv(0x18, Buffer.from([0xff, 0xfe]))))).to.throw(L.ErreurDer, /illisible/);
  });

  it("AlgorithmIdentifier : paramètres absents ou NULL admis, autre forme refusée par le profil", function () {
    const a = L.lireIdentifiantAlgorithme(lit("300d0609608648016503040201" + "0500"));
    expect(a.algorithme).to.equal("2.16.840.1.101.3.4.2.1");
    expect(L.parametresAbsentsOuNuls(a.parametres)).to.equal(true);
    const b = L.lireIdentifiantAlgorithme(lit("300b0609608648016503040201"));
    expect(L.parametresAbsentsOuNuls(b.parametres)).to.equal(true);
    const c = L.lireIdentifiantAlgorithme(lit("300e0609608648016503040201" + "020100"));
    expect(L.parametresAbsentsOuNuls(c.parametres)).to.equal(false);
    expect(() => L.lireIdentifiantAlgorithme(lit("3000"))).to.throw(L.ErreurDer);
  });
});
