// Lot A du composant d'ancrage : chaque exigence EX- et chaque vérification
// AN- des sections CT-5 §5 (EX-5.1 à EX-5.15, AN-5 à AN-15), §10.2 (EX-10.6,
// AN-54), §11 (EX-11.4, AN-57) et les règles de CT-6 §9.3 (EX-9.4, EX-9.5,
// EX-9.21), §9.5 (T-1 à T-10), §15.1, §15.4 réutilisées à l'acquisition,
// éprouvées en réussite et en échec, avec des entrées hostiles (longueurs non
// minimales, profondeur, tailles au-delà des bornes, valeurs hors
// énumération, chaînes non UTF-8, nombres hors bornes), un serveur
// d'horodatage local factice (HTTP sur 127.0.0.1 et TLS) et le dépôt d'ancres
// dans un répertoire temporaire.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { RegistreSchemas, jcs, analyserJson } from "@noortrace/noyau";
import {
  construireRequete, relireRequete, tirerNonce, ErreurRequete, NONCE_MAX,
  lireReponse, lireJeton, ErreurReponse, TAILLE_MAX_JETON,
  verifierJeton, normaliserAncres, ErreurAncres, VERIFICATIONS_ACQUISITION,
  verifierRevocation, capturerCrls,
  classerErreur, lireRetryAfter, attenteReprise, RETRY_DEFAUT,
  acquerir, identifiantTentative, identifiantDemande, FRAICHEUR_DEFAUT,
  DepotAncres, ErreurDepot, choisirPromu, nomPeriode, nomObjet,
  construireFiche, verifierFiche, epreuveAcceptation, nomFiche, MENTION_NON_QUALIFIE,
  transportHttps, controlerUrl, entetesRequete, autorisationBasic, ErreurTransport, CORPS_MAX,
  lireCertificatPem, lireCertificat, lireCrl, decoderPem,
  ErreurDer, PROFONDEUR_MAX, lireTlv, lireUnique, enfants, lireEntier, lireOid, lireBooleen, lireChaine, lireGeneralizedTime, encoderTlv, encoderEntierNonNegatif, encoderOid,
} from "@noortrace/ancrage/rfc3161";
import {
  SPEC, CT5, CT6, CLES, JETONS, octets, texte, json, sha256Hex, prestataireTest, horlogeFixe, aleaFixe, transportFactice, reponse200,
  certificatsTls, serveurTsa, enAttente, repertoireTemporaire, AC_TEST_PEM, TSA_TEST_PEM, opensslDisponible,
} from "./fixtures/ancrage-rfc3161/outils.mjs";

const hex = (s) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const K2 = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
const NONCE_K2 = 0x74a6f4979421411en;
const GRANTED_K2 = octets(path.join(CT5, "reponses", "granted-point-k2-exemple.tsr"));
const JETON_K2 = octets(path.join(CT5, "reponses", "granted-point-k2-exemple.der"));
const REQUETE_K2_EXEMPLE = octets(path.join(CT5, "requetes", "point-k2-exemple.tsq"));
const NONCE_K2_EXEMPLE = 0x018032ff0d74cfdan;
const SENT = Date.parse("2026-11-03T13:53:00.000Z");
const ANCRES_TEST = json(path.join(CT6, "ancres", "ancres-test.json"));
const PERIODE_1 = octets(path.join(JETONS, "periode-1.der"));
const PERIOD_HASH_1 = "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914";
const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
const JOURNAL = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";

let dir;
before(function () {
  dir = repertoireTemporaire();
});
after(function () {
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

describe("ancrage rfc3161 : lecteur DER borné (CT-6 EX-9.4, EX-9.21, §15.1)", function () {
  it("lit les formes minimales et refuse la forme longue d'une longueur courte, la forme indéfinie et l'octet de tête nul", function () {
    expect(lireUnique(hex("30 03 02 01 05")).longueur).to.equal(3);
    expect(() => lireUnique(hex("30 81 03 02 01 05"))).to.throw(ErreurDer, /non minimale/);
    expect(() => lireUnique(hex("30 80 02 01 05 00 00"))).to.throw(ErreurDer, /indéfinie/);
    expect(() => lireUnique(hex("30 82 00 03 02 01 05"))).to.throw(ErreurDer, /non minimale/);
    expect(() => lireUnique(hex("30 85 01 00 00 00 00"))).to.throw(ErreurDer, /quatre octets/);
    const long = encoderTlv(0x04, new Uint8Array(200));
    expect(long[1]).to.equal(0x81);
    expect(lireUnique(long).longueur).to.equal(200);
  });
  it("refuse un numéro d'étiquette ≥ 31, une structure tronquée et des octets après la fin", function () {
    expect(() => lireUnique(hex("1f 01 00"))).to.throw(ErreurDer, /31/);
    expect(() => lireUnique(hex("30 05 02 01 05"))).to.throw(ErreurDer, /tronqué/);
    expect(() => lireUnique(hex("30 03 02 01 05 00"))).to.throw(ErreurDer, /après la fin/);
    expect(() => lireTlv(hex("30"), 0)).to.throw(ErreurDer);
  });
  it("BOOLEAN : 00 et ff seulement", function () {
    expect(lireBooleen(lireUnique(hex("01 01 ff")))).to.equal(true);
    expect(lireBooleen(lireUnique(hex("01 01 00")))).to.equal(false);
    expect(() => lireBooleen(lireUnique(hex("01 01 01")))).to.throw(ErreurDer, /00 ou ff/);
    expect(() => lireBooleen(lireUnique(hex("01 02 00 00")))).to.throw(ErreurDer);
  });
  it("profondeur d'imbrication : 32 admise, 33 refusée", function () {
    const imbriquer = (n) => {
      let o = hex("05 00");
      for (let i = 0; i < n; i++) o = encoderTlv(0x30, o);
      return o;
    };
    let t = lireUnique(imbriquer(PROFONDEUR_MAX - 1));
    while (t.construit) t = enfants(t)[0];
    expect(t.profondeur).to.equal(PROFONDEUR_MAX);
    expect(() => {
      let u = lireUnique(imbriquer(PROFONDEUR_MAX));
      while (u.construit) u = enfants(u)[0];
    }).to.throw(ErreurDer, /profondeur/);
  });
  it("UTF8String en UTF-8 valide, BMPString de longueur paire ; INTEGER, OID, GeneralizedTime", function () {
    expect(lireChaine(lireUnique(hex("0c 03 e2 82 ac"))).texte).to.equal("€");
    expect(() => lireChaine(lireUnique(hex("0c 02 ff fe")))).to.throw(ErreurDer, /UTF-8/);
    expect(() => lireChaine(lireUnique(hex("0c 03 ed a0 80")))).to.throw(ErreurDer, /UTF-8/); // substitut encodé
    expect(lireChaine(lireUnique(hex("1e 02 00 41"))).texte).to.equal("A");
    expect(() => lireChaine(lireUnique(hex("1e 03 00 41 00")))).to.throw(ErreurDer, /impaire/);
    expect(lireEntier(lireUnique(hex("02 02 03 e9")))).to.equal(1001n);
    expect(lireEntier(lireUnique(hex("02 01 ff")))).to.equal(-1n);
    expect(() => lireEntier(lireUnique(hex("02 00")))).to.throw(ErreurDer, /vide/);
    expect(() => lireEntier(lireUnique(hex("02 02 00 01")), { minimal: true })).to.throw(ErreurDer, /minimal/);
    expect(lireOid(lireUnique(hex("06 09 60 86 48 01 65 03 04 02 01")))).to.equal("2.16.840.1.101.3.4.2.1");
    expect(() => lireOid(lireUnique(hex("06 02 80 01")))).to.throw(ErreurDer, /minimal/);
    expect(() => lireOid(lireUnique(hex("06 01 81")))).to.throw(ErreurDer, /tronqué/);
    expect(Buffer.from(encoderOid("1.3.6.1.4.1.99999.1.1")).toString("hex")).to.equal("060a2b06010401868d1f0101");
    const gt = lireGeneralizedTime(lireUnique(Buffer.concat([Buffer.from([0x18, 15]), Buffer.from("20261103135302Z")])));
    expect(gt.ms).to.equal(Date.parse("2026-11-03T13:53:02Z"));
    expect(lireGeneralizedTime(lireUnique(Buffer.concat([Buffer.from([0x18, 17]), Buffer.from("20261103135302.0Z")]))).ms).to.equal(null, "fraction à zéro final");
    expect(lireGeneralizedTime(lireUnique(Buffer.concat([Buffer.from([0x18, 15]), Buffer.from("20260230120000Z")]))).ms).to.equal(null, "date inexistante");
    expect(lireGeneralizedTime(lireUnique(Buffer.concat([Buffer.from([0x18, 17]), Buffer.from("20260228120000.5Z")]))).ms).to.equal(Date.parse("2026-02-28T12:00:00.500Z"));
  });
  it("INTEGER DER minimal d'un entier non négatif (nonce)", function () {
    expect(Buffer.from(encoderEntierNonNegatif(0x74a6f4979421411en)).toString("hex")).to.equal("020874a6f4979421411e");
    expect(Buffer.from(encoderEntierNonNegatif(0xf4a6f4979421411en)).toString("hex")).to.equal("020900f4a6f4979421411e");
    expect(Buffer.from(encoderEntierNonNegatif(1n)).toString("hex")).to.equal("020101");
    expect(Buffer.from(encoderEntierNonNegatif(0n)).toString("hex")).to.equal("020100");
  });
  it("certificats : un critical encodé à FALSE (tsa-critique-faux.pem) et un CN en UTF-8 invalide rendent le certificat illisible ; les autres clés de test se lisent", function () {
    expect(() => lireCertificatPem(texte(path.join(CLES, "tsa-critique-faux.pem")))).to.throw(ErreurDer, /DEFAULT/);
    expect(() => lireCertificatPem(texte(path.join(CLES, "tsa-cn-utf8-invalide.pem")))).to.throw(ErreurDer, /UTF-8/);
    for (const f of ["ac-test", "tsa-test", "tsa-sans-cn", "tsa-expiree", "tsa-eku-non-critique", "tsa-8192", "tsa-8200", "tsa-exposant", "intermediaire-8200", "tsa-par-intermediaire-8200", "tsa-ed25519", "tsa-ed25519-auto-signe"]) {
      const c = lireCertificatPem(texte(path.join(CLES, `${f}.pem`)));
      expect(c.version).to.equal(3);
      expect(c.sha256).to.match(/^0x[0-9a-f]{64}$/);
    }
    const sansCn = lireCertificatPem(texte(path.join(CLES, "tsa-sans-cn.pem")));
    expect(sansCn.sujet.cn).to.equal(null);
    const tsa = lireCertificatPem(TSA_TEST_PEM);
    expect(tsa.sujet.cn).to.equal("TSA de test CT-6");
    expect(tsa.clePublique).to.include({ type: "rsa", bits: 3072, admise: true });
    expect(tsa.usagesEtendus.critique).to.equal(true);
    expect(tsa.notBefore).to.equal(Date.parse("2026-06-01T00:00:00Z"));
    expect(lireCertificatPem(texte(path.join(CLES, "tsa-8200.pem"))).clePublique).to.include({ admise: false, bits: 8200 });
    expect(lireCertificatPem(texte(path.join(CLES, "tsa-exposant.pem"))).clePublique.admise).to.equal(false);
    expect(lireCertificatPem(texte(path.join(CLES, "tsa-ed25519.pem"))).clePublique).to.include({ type: "autre", admise: false });
  });
  it("version encodée à v1 et cA encodé à FALSE refusés (valeurs DEFAULT encodées, EX-9.21)", function () {
    const tsa = lireCertificat(decoderPem(TSA_TEST_PEM, "CERTIFICATE"));
    // La version [0] { INTEGER 2 } des certificats de test est aux octets 4..8 du TBS (30 82 l l 30 82 l l a0 03 02 01 02) : forcée à 0.
    const v1 = new Uint8Array(tsa.octets);
    const pos = Buffer.from(v1).indexOf(Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]));
    expect(pos).to.be.greaterThan(0);
    v1[pos + 4] = 0x00;
    expect(() => lireCertificat(v1)).to.throw(ErreurDer, /v1/);
    // basicConstraints { cA FALSE } : dans l'AC de test, la valeur 30 03 01 01 ff de l'extension critique devient 30 03 01 01 00.
    const ac = new Uint8Array(decoderPem(AC_TEST_PEM, "CERTIFICATE"));
    const bc = Buffer.from(ac).indexOf(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff]));
    expect(bc).to.be.greaterThan(0);
    ac[bc + 14] = 0x00;
    expect(() => lireCertificat(ac)).to.throw(ErreurDer, /cA encodé à FALSE/);
    expect(() => lireCertificat(hex("30 03 02 01 05"))).to.throw(ErreurDer);
  });
  it("PEM : un seul bloc, base64 canonique", function () {
    expect(() => decoderPem(AC_TEST_PEM + TSA_TEST_PEM, "CERTIFICATE")).to.throw(ErreurDer, /un seul bloc/);
    expect(() => decoderPem(AC_TEST_PEM.replace("-----END CERTIFICATE-----", "QQ==\n-----END CERTIFICATE-----"), "CERTIFICATE")).to.throw(ErreurDer);
    expect(() => decoderPem("-----BEGIN CERTIFICATE-----\nQR==\n-----END CERTIFICATE-----\n", "CERTIFICATE")).to.throw(ErreurDer, /canonique/);
    expect(() => lireCertificatPem(12)).to.throw(ErreurDer);
  });
  it("CRL : lecture des deux CRL de test, entrées de révocation, raison, complétude", function () {
    const vide = lireCrl(texte(path.join(CT6, "rfc3161", "crl", "crl-vide.pem")));
    expect(vide.revoques).to.deep.equal([]);
    expect(vide.thisUpdate).to.equal(Date.parse("2026-11-06T00:00:00Z"));
    expect(vide.complete).to.equal(true);
    const rev = lireCrl(octets(path.join(CT6, "rfc3161", "crl", "crl-tsa-revoquee.pem")));
    expect(rev.revoques).to.have.length(1);
    expect(rev.revoques[0]).to.include({ numeroSerieHex: "0x02", raison: 1 });
    expect(rev.revoques[0].date).to.equal(Date.parse("2026-11-05T12:00:00Z"));
    expect(() => lireCrl(hex("30 03 02 01 05"))).to.throw(ErreurDer);
    expect(() => lireCrl(42)).to.throw(ErreurDer);
  });
});

describe("ancrage rfc3161 : requête TimeStampReq (EX-5.1 à EX-5.4, AN-5, AN-6)", function () {
  it("EX-5.1 : l'exemple de la spécification, 69 octets, puis 70 avec un nonce à bit haut et 81 avec reqPolicy", function () {
    const r = construireRequete({ imprint: K2, nonce: NONCE_K2, policy_oid: null });
    expect(Buffer.from(r.octets).toString("hex")).to.equal("30430201013031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff020874a6f4979421411e0101ff");
    expect(r.taille).to.equal(69);
    const haut = construireRequete({ imprint: K2, nonce: 0xf4a6f4979421411en });
    expect(haut.taille).to.equal(70);
    expect(Buffer.from(haut.octets).toString("hex")).to.include("020900f4a6f4979421411e");
    const pol = construireRequete({ imprint: K2, nonce: NONCE_K2, policy_oid: "1.3.6.1.4.1.99999.1.1" });
    expect(pol.taille).to.equal(81);
    expect(Buffer.from(pol.octets).toString("hex")).to.include("060a2b06010401868d1f0101");
    expect(construireRequete({ imprint: K2, nonce: 1n }).taille).to.equal(62);
    expect(construireRequete({ imprint: K2, nonce: "0x74a6f4979421411e" }).sha256).to.equal(r.sha256);
  });
  it("EX-5.2, EX-5.4, AN-5 : refus de sha384, d'une empreinte de 31 ou 33 octets, d'un certReq faux, d'un OID mal formé, d'un hexadécimal non minuscule", function () {
    expect(() => construireRequete({ imprint: K2, nonce: 1n, hash: "sha384" })).to.throw(ErreurRequete, /sha256/);
    expect(() => construireRequete({ imprint: "0x" + "ab".repeat(31), nonce: 1n })).to.throw(ErreurRequete, /32 octets/);
    expect(() => construireRequete({ imprint: "0x" + "ab".repeat(33), nonce: 1n })).to.throw(ErreurRequete, /32 octets/);
    expect(() => construireRequete({ imprint: K2, nonce: 1n, certReq: false })).to.throw(ErreurRequete, /certReq/);
    expect(() => construireRequete({ imprint: K2, nonce: 1n, policy_oid: "1.3.6.01" })).to.throw(ErreurRequete, /OID/);
    expect(() => construireRequete({ imprint: K2, nonce: 1n, policy_oid: 5 })).to.throw(ErreurRequete, /OID/);
    expect(() => construireRequete({ imprint: "zz", nonce: 1n })).to.throw(ErreurRequete);
  });
  it("EX-5.3, AN-6 : nonce dans [1, 2^64 − 1], encodage minimal, tirage nul rejoué", function () {
    expect(() => construireRequete({ imprint: K2, nonce: 0n })).to.throw(ErreurRequete, /hors de/);
    expect(() => construireRequete({ imprint: K2, nonce: NONCE_MAX + 1n })).to.throw(ErreurRequete, /hors de/);
    expect(() => construireRequete({ imprint: K2, nonce: -1n })).to.throw(ErreurRequete);
    expect(() => construireRequete({ imprint: K2, nonce: "12" })).to.throw(ErreurRequete, /hexadécimal/);
    expect(construireRequete({ imprint: K2, nonce: NONCE_MAX }).taille).to.equal(70);
    const zero = new Uint8Array(8);
    const un = Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1);
    expect(tirerNonce(aleaFixe(zero, zero, un))).to.equal(1n);
    expect(tirerNonce(aleaFixe(Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)))).to.equal(NONCE_MAX);
    expect(() => tirerNonce(aleaFixe(zero))).to.throw(ErreurRequete, /zéro/);
    expect(() => tirerNonce(() => new Uint8Array(4))).to.throw(ErreurRequete, /huit octets/);
  });
  it("AN-5 : la relecture refuse un champ en trop, une longueur non minimale, un BOOLEAN 01, une version 2, un hashAlgorithm sans NULL, une empreinte de 31 octets, un zéro de tête superflu", function () {
    const base = construireRequete({ imprint: K2, nonce: NONCE_K2 }).octets;
    const mutations = [
      ["champ en trop", (o) => encoderTlv(0x30, Buffer.concat([Buffer.from(o.subarray(2)), Buffer.from([0x05, 0x00])]))],
      ["longueur non minimale", (o) => Buffer.concat([Buffer.from([0x30, 0x81, o[1]]), Buffer.from(o.subarray(2))])],
      ["BOOLEAN 01", (o) => { const m = Buffer.from(o); m[m.length - 1] = 0x01; return m; }],
      ["version 2", (o) => { const m = Buffer.from(o); m[4] = 0x02; return m; }],
      ["hashAlgorithm sans NULL", (o) => encoderTlv(0x30, Buffer.concat([Buffer.from(o.subarray(2, 5)), encoderTlv(0x30, Buffer.concat([hex("30 0b 06 09 60 86 48 01 65 03 04 02 01"), Buffer.from(o.subarray(22, 56))])), Buffer.from(o.subarray(56))]))],
      ["empreinte de 31 octets", (o) => encoderTlv(0x30, Buffer.concat([Buffer.from(o.subarray(2, 5)), encoderTlv(0x30, Buffer.concat([Buffer.from(o.subarray(7, 22)), encoderTlv(0x04, Buffer.from(o.subarray(24, 55)))])), Buffer.from(o.subarray(56))]))],
      ["zéro de tête superflu", () => hex("30440201013031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff020900018032ff0d74cfda0101ff")],
      ["nonce nul", (o) => encoderTlv(0x30, Buffer.concat([Buffer.from(o.subarray(2, 56)), hex("02 01 00 01 01 ff")]))],
      ["sans certReq", (o) => encoderTlv(0x30, Buffer.from(o.subarray(2, o.length - 3)))],
    ];
    for (const [nom, muter] of mutations) {
      const m = new Uint8Array(muter(base));
      expect(() => relireRequete(m), nom).to.throw(ErreurRequete);
    }
    expect(relireRequete(base).nonceBigint).to.equal(NONCE_K2);
  });
});

describe("ancrage rfc3161 : lecture d'une TimeStampResp (EX-5.10 étape 2, AN-8)", function () {
  it("statut 0 avec jeton ; 2 à 5 sans jeton ; PKIFailureInfo nommé ou autre", function () {
    const r = lireReponse(GRANTED_K2);
    expect(r.status).to.equal(0);
    expect(r.token).to.have.length(2104);
    expect(Buffer.from(r.token).equals(Buffer.from(JETON_K2))).to.equal(true);
    expect(lireReponse(hex("30 05 30 03 02 01 03"))).to.include({ status: 3, failureInfo: null, token: null });
    expect(lireReponse(hex("30 0a 30 08 02 01 02 03 03 01 00 02")).failureInfo).to.equal("timeNotAvailable");
    expect(lireReponse(hex("30 09 30 07 02 01 02 03 02 07 80")).failureInfo).to.equal("badAlg");
    expect(lireReponse(hex("30 09 30 07 02 01 02 03 02 06 c0")).failureInfo).to.equal("autre", "deux bits levés");
    expect(lireReponse(hex("30 0a 30 08 02 01 02 03 03 00 00 01")).failureInfo).to.equal("unacceptedPolicy");
    expect(lireReponse(hex("30 0e 30 0c 02 01 02 03 07 00 00 00 00 00 00 40")).failureInfo).to.equal("autre", "bit 49 hors de la RFC");
  });
  it("refus : statut 6, statut 1 sans jeton, rejet avec jeton, corps vide, octets en trop, longueur non minimale", function () {
    expect(() => lireReponse(hex("30 05 30 03 02 01 06"))).to.throw(ErreurReponse, /hors de 0 à 5/);
    expect(() => lireReponse(hex("30 05 30 03 02 01 01"))).to.throw(ErreurReponse, /sans TimeStampToken/);
    const rejetAvecJeton = encoderTlv(0x30, Buffer.concat([hex("30 03 02 01 02"), Buffer.from(JETON_K2)]));
    expect(() => lireReponse(rejetAvecJeton)).to.throw(ErreurReponse, /rejet avec/);
    expect(() => lireReponse(new Uint8Array(0))).to.throw(ErreurReponse);
    expect(() => lireReponse(Buffer.concat([Buffer.from(GRANTED_K2), Buffer.from([0])]))).to.throw(ErreurReponse, /après la fin/);
    expect(() => lireReponse(hex("30 81 05 30 03 02 01 03"))).to.throw(ErreurReponse, /non minimale/);
    expect(() => lireReponse(hex("30 05 30 03 02 01 ff"))).to.throw(ErreurReponse);
    expect(() => lireReponse("texte")).to.throw();
  });
});

describe("ancrage rfc3161 : vérification T-1 à T-9 (CT-6 §9.5) et entrées hostiles (§15.1)", function () {
  const ancres = { certificatsPem: [AC_TEST_PEM], politiquesAdmises: ["1.3.6.1.4.1.99999.1.1"] };
  it("jeton valide : T-1 à T-9 réussies, tstInfo et faits renseignés, chemin vers l'AC de test", function () {
    const r = verifierJeton({ octets: JETON_K2, imprintAttendue: K2, ancres });
    expect(VERIFICATIONS_ACQUISITION.map((id) => r.checks[id])).to.deep.equal(Array(9).fill("reussi"));
    expect(r.tstInfo).to.include({ genTimeTexte: "2026-11-03T13:53:02Z", accuracyMs: 1000, upperBound: "2026-11-03T13:53:03Z", policy: "1.3.6.1.4.1.99999.1.1" });
    expect(r.tstInfo.nonce).to.equal(NONCE_K2_EXEMPLE);
    expect(r.chemin).to.have.length(1);
    expect(r.autorite.nom).to.equal("AC de test CT-6");
    expect(r.faits).to.include({ tsu_subject_cn: "TSA de test CT-6", signature_algorithm: "sha256WithRSAEncryption", key_bits: 3072, qualified_claim: false });
  });
  it("T-1 : jeton de plus de 64 Kio, octet en trop, TimeStampResp à la place du jeton, profondeur excessive, deux SignerInfo", function () {
    expect(verifierJeton({ octets: new Uint8Array(TAILLE_MAX_JETON + 1), imprintAttendue: K2, ancres }).checks["T-1"]).to.equal("echoue");
    expect(verifierJeton({ octets: Buffer.concat([Buffer.from(JETON_K2), Buffer.from([0])]), imprintAttendue: K2, ancres }).checks["T-1"]).to.equal("echoue");
    const r = verifierJeton({ octets: GRANTED_K2, imprintAttendue: K2, ancres });
    expect(r.checks["T-1"]).to.equal("echoue");
    expect(r.details["T-1"]).to.match(/OBJECT IDENTIFIER attendu/);
    for (const id of VERIFICATIONS_ACQUISITION.slice(1)) expect(r.raisons[id]).to.equal("prerequis_en_echec");
    let profond = hex("05 00");
    for (let i = 0; i < 40; i++) profond = encoderTlv(0x30, profond);
    expect(() => lireJeton(profond)).to.throw(ErreurDer);
    expect(() => lireJeton("pas des octets")).to.throw(ErreurDer);
  });
  it("T-2 : empreinte attendue différente ou absente", function () {
    expect(verifierJeton({ octets: JETON_K2, imprintAttendue: PERIOD_HASH_1, ancres }).checks["T-2"]).to.equal("echoue");
    const sans = verifierJeton({ octets: JETON_K2, imprintAttendue: null, ancres });
    expect(sans.checks["T-2"]).to.equal("non_execute");
    expect(sans.checks["T-6"]).to.equal("reussi");
  });
  it("T-4 : forme réduite d'un prestataire et fichier d'ancres rendent le même certificat signataire ; ancres illisibles (N-1) refusées d'avance", function () {
    const a = verifierJeton({ octets: PERIODE_1, imprintAttendue: PERIOD_HASH_1, ancres });
    const b = verifierJeton({ octets: PERIODE_1, imprintAttendue: PERIOD_HASH_1, ancres: ANCRES_TEST });
    expect(a.certificatSignataire.sha256).to.equal(b.certificatSignataire.sha256);
    expect(a.checks).to.deep.equal(b.checks);
    expect(() => normaliserAncres({ certificatsPem: ["-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"] })).to.throw(ErreurAncres);
    expect(() => normaliserAncres({ certificatsPem: [texte(path.join(CLES, "tsa-critique-faux.pem"))] })).to.throw(ErreurAncres, /DEFAULT/);
    expect(() => normaliserAncres({ autre: 1 })).to.throw(ErreurAncres, /forme/);
    expect(normaliserAncres(null).autorites).to.deep.equal([]);
    expect(normaliserAncres({ autorites: [{ nom: "AC", certificatPem: AC_TEST_PEM, politiquesAdmises: null }] }).autorites[0].nom).to.equal("AC");
  });
  it("T-7 : politique hors accepted_policies de l'ancre (règle 7), ancre absente, unité épinglée (identité)", function () {
    const refus = verifierJeton({ octets: JETON_K2, imprintAttendue: K2, ancres: { certificatsPem: [AC_TEST_PEM], politiquesAdmises: ["1.3.6.1.4.1.99999.1.2"] } });
    expect(refus.checks["T-7"]).to.equal("echoue");
    const sans = verifierJeton({ octets: JETON_K2, imprintAttendue: K2, ancres: null });
    expect(sans.checks["T-7"]).to.equal("non_execute");
    expect(sans.raisons["T-7"]).to.equal("ancre_absente");
    const epinglee = verifierJeton({ octets: JETON_K2, imprintAttendue: K2, ancres: { certificatsPem: [TSA_TEST_PEM], politiquesAdmises: null } });
    expect(epinglee.checks["T-7"]).to.equal("reussi");
    expect(epinglee.identite).to.equal(true);
    expect(epinglee.chemin).to.have.length(1);
  });
  it("aGenTime doit être vrai (T-7 à genTime, EX-9.13)", function () {
    expect(() => verifierJeton({ octets: JETON_K2, imprintAttendue: K2, ancres, aGenTime: false })).to.throw(TypeError);
  });
  it("T-10 : preuve par CRL d'ancre, révocation non tolérée, révocation tolérée (superseded après genTime), déclaration, CRL écartée (AV-T-3), instant inconnu", function () {
    const r = verifierJeton({ octets: PERIODE_1, imprintAttendue: PERIOD_HASH_1, ancres: ANCRES_TEST });
    const auto = { nom: r.autorite.nom, certificat: r.autorite.certificat, identite: r.identite };
    const vide = texte(path.join(CT6, "rfc3161", "crl", "crl-vide.pem"));
    const revoquee = texte(path.join(CT6, "rfc3161", "crl", "crl-tsa-revoquee.pem"));
    const ok = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [vide], aInstant: r.tstInfo.genTime });
    expect(ok.statut).to.equal("reussi");
    expect(ok.preuves[0]).to.include({ evidence: "crl", issued_at: "2026-11-06T00:00:00Z" });
    const ko = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [revoquee], aInstant: r.tstInfo.genTime });
    expect(ko.statut).to.equal("echoue");
    expect(ko.revocations[0]).to.include({ raison: 1, toleree: false });
    // Même CRL, mais genTime postérieur à la révocation : une raison keyCompromise n'est jamais tolérée.
    expect(verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [revoquee], aInstant: Date.parse("2026-11-05T13:00:00Z") }).statut).to.equal("echoue");
    // CRL dont thisUpdate précède genTime : écartée, AV-T-3, aucune preuve.
    const tard = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [vide], aInstant: Date.parse("2026-11-07T00:00:00Z") });
    expect(tard.statut).to.equal("non_execute");
    expect(tard.raison).to.equal("ancre_absente");
    expect(tard.avertissements.map((a) => a.id)).to.include("AV-T-3");
    // Déclaration du réviseur.
    const decl = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [], declarations: [{ certificate_sha256: r.certificatSignataire.sha256, not_revoked_at: "2026-11-06T00:00:00.000Z", method: "ocsp", source: "test" }], aInstant: r.tstInfo.genTime });
    expect(decl.statut).to.equal("reussi");
    expect(decl.preuves[0].evidence).to.equal("declaration");
    // CRL illisible : écartée.
    const illisible = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [new Uint8Array([0x30, 0x00])], aInstant: r.tstInfo.genTime });
    expect(illisible.statut).to.equal("non_execute");
    expect(illisible.avertissements.some((a) => a.id === "AV-T-3")).to.equal(true);
    expect(verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [vide], aInstant: NaN }).statut).to.equal("non_execute");
  });
  it("T-10 : révocation tolérée quand la raison est superseded et la date postérieure à genTime (CRL produite par openssl avec la clé de test publiée)", function () {
    if (!opensslDisponible()) return enAttente(this, "openssl absent de la machine");
    const d = path.join(dir, "crl-superseded");
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, "index.txt"), `R\t270601000000Z\t261105120000Z,superseded\t02\tunknown\t/C=CH/O=NOORTRACE vecteurs/CN=TSA de test CT-6\n`);
    fs.writeFileSync(path.join(d, "crlnumber"), "03\n");
    fs.writeFileSync(path.join(d, "ca.cnf"), `[ca]\ndefault_ca = c\n[c]\ndatabase = ${path.join(d, "index.txt")}\ncrlnumber = ${path.join(d, "crlnumber")}\ndefault_md = sha256\ndefault_crl_days = 30\n`);
    const crlPem = execFileSync("openssl", ["ca", "-config", path.join(d, "ca.cnf"), "-gencrl", "-keyfile", path.join(CLES, "ac-test.cle.pem"), "-cert", path.join(CLES, "ac-test.pem"), "-crl_lastupdate", "20261106000000Z", "-crl_nextupdate", "20261206000000Z"], { stdio: "pipe" }).toString();
    const crl = lireCrl(crlPem);
    expect(crl.revoques[0]).to.include({ numeroSerieHex: "0x02", raison: 4 });
    const r = verifierJeton({ octets: PERIODE_1, imprintAttendue: PERIOD_HASH_1, ancres: ANCRES_TEST });
    const auto = { nom: r.autorite.nom, certificat: r.autorite.certificat, identite: r.identite };
    const toleree = verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [crlPem], aInstant: r.tstInfo.genTime });
    expect(toleree.statut).to.equal("reussi");
    expect(toleree.revocations[0].toleree).to.equal(true);
    // Le même jeton « émis » après la révocation (genTime postérieur) échoue : la date n'est plus strictement postérieure.
    expect(verifierRevocation({ chemin: r.chemin, autorite: auto, crls: [crlPem], aInstant: Date.parse("2026-11-05T12:00:00Z") }).statut).to.equal("echoue");
  });
  it("capture différée des CRL (EX-5.10 étape 10, EX-13.12) : point de distribution lu dans le certificat, CRL lue par le lecteur borné, crl_indisponible réessayable", async function () {
    const r = verifierJeton({ octets: PERIODE_1, imprintAttendue: PERIOD_HASH_1, ancres: ANCRES_TEST });
    const vide = octets(path.join(CT6, "rfc3161", "crl", "crl-vide.pem"));
    const horloge = horlogeFixe(Date.parse("2026-11-06T01:00:00Z"));
    const sansPoint = await capturerCrls({ chemin: r.chemin, transport: transportFactice({ status: 200, corps: vide }), horloge, apresInstant: r.tstInfo.genTime });
    expect(sansPoint[0].erreur).to.match(/point de distribution/, "les certificats de test n'ont pas de cRLDistributionPoints");
    const avecPoint = { ...r.chemin[0], extensions: [...r.chemin[0].extensions] };
    // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames { uniformResourceIdentifier [6] } } }.
    const uri = encoderTlv(0x86, new TextEncoder().encode("http://crl.example/ac.crl"));
    const cdp = encoderTlv(0x30, encoderTlv(0x30, encoderTlv(0xa0, encoderTlv(0xa0, uri))));
    const faux = { octets: r.chemin[0].octets, sha256: r.chemin[0].sha256, sujet: r.chemin[0].sujet, extensions: [{ oid: "2.5.29.31", critique: false, valeur: cdp, tlv: { profondeur: 1 } }] };
    void avecPoint;
    const t = transportFactice({ status: 200, corps: vide });
    const c = await capturerCrls({ chemin: [faux], transport: t, horloge, apresInstant: r.tstInfo.genTime });
    expect(c[0].sources).to.deep.equal(["http://crl.example/ac.crl"]);
    expect(c[0].crl).to.not.equal(null);
    expect(c[0].pem).to.include("BEGIN X509 CRL");
    const indispo = await capturerCrls({ chemin: [faux], transport: transportFactice({ status: 404, corps: new Uint8Array(0) }), horloge });
    expect(indispo[0]).to.include({ crl: null, erreur: "http_404" });
    const trop = await capturerCrls({ chemin: [faux], transport: transportFactice({ status: 200, corps: vide }), horloge, apresInstant: Date.parse("2026-12-01T00:00:00Z") });
    expect(trop[0].erreur).to.match(/thisUpdate/);
    const illisible = await capturerCrls({ chemin: [faux], transport: transportFactice({ status: 200, corps: hex("30 00") }), horloge });
    expect(illisible[0].erreur).to.match(/illisible/);
  });
});

describe("ancrage rfc3161 : classement des erreurs et attente de reprise (EX-5.12, EX-8.9, AN-11)", function () {
  const retry = { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 };
  it("table d'EX-5.12 : transitoires", function () {
    for (const code of ["erreur_transport", "delai", "http_500", "http_502", "http_504", "echec_timeNotAvailable", "echec_systemFailure", "statut_3", "reponse_tardive", "ecriture"]) {
      const c = classerErreur({ code, retry, k: 1 });
      expect(c.classe, code).to.equal("transitoire");
      expect(c.attenteMs, code).to.equal(5000);
      expect(c.alerte, code).to.equal("aucune");
    }
  });
  it("table d'EX-5.12 : permanentes, alerte ; PKIStatus 4 et 5 critiques", function () {
    for (const code of ["http_400", "http_401", "http_403", "http_404", "http_418", "http_501", "http_505", "type_contenu", "taille", "reponse_illisible", "echec_badAlg", "echec_badRequest", "echec_badDataFormat", "echec_unacceptedPolicy", "echec_unacceptedExtension", "echec_addInfoNotAvailable", "empreinte_differente", "nonce_absent", "nonce_different", "politique_differente", "politique_refusee", "verification_T-1", "verification_T-6", "verification_T-9", "statut_2", "code_inconnu"]) {
      const c = classerErreur({ code, retry });
      expect(c.classe, code).to.equal("permanente");
      expect(c.attenteMs, code).to.equal(null);
      expect(c.alerte, code).to.equal("alerte");
    }
    for (const code of ["statut_4", "statut_5"]) expect(classerErreur({ code })).to.include({ classe: "permanente", alerte: "critique" });
  });
  it("408 : immédiat une fois, puis attente ; 429 et 503 : Retry-After en secondes ou date RFC 1123, sinon attente", function () {
    expect(classerErreur({ code: "http_408", retry, k: 1 })).to.include({ classe: "transitoire", attenteMs: 0, raisonAttente: "immediat", immediat: true });
    expect(classerErreur({ code: "http_408", retry, k: 2 })).to.include({ attenteMs: 10000, raisonAttente: "backoff" });
    expect(classerErreur({ code: "http_408", retry, k: 1, premier408: false })).to.include({ attenteMs: 5000 });
    expect(classerErreur({ code: "http_503", retryAfter: 30, retry })).to.include({ attenteMs: 30000, raisonAttente: "retry_after" });
    expect(classerErreur({ code: "http_429", retryAfter: "7", retry })).to.include({ attenteMs: 7000, raisonAttente: "retry_after" });
    const maintenant = Date.parse("2026-11-03T13:53:03Z");
    expect(classerErreur({ code: "http_503", retryAfter: "Tue, 03 Nov 2026 13:54:03 GMT", maintenantMs: maintenant, retry })).to.include({ attenteMs: 60000, raisonAttente: "retry_after" });
    // EX-8.9 révisée (R-C-1, R-C-3) : un Retry-After passé ou nul vaut le plancher retry.initial_ms, jamais une reprise immédiate.
    expect(classerErreur({ code: "http_503", retryAfter: "Tue, 03 Nov 2026 13:50:03 GMT", maintenantMs: maintenant, retry })).to.include({ attenteMs: 5000, raisonAttente: "retry_after" });
    expect(classerErreur({ code: "http_503", retryAfter: "demain", retry })).to.include({ attenteMs: 5000, raisonAttente: "backoff" });
    expect(classerErreur({ code: "http_500", retryAfter: 30, retry })).to.include({ attenteMs: 5000, raisonAttente: "backoff" }, "Retry-After n'est suivi que sur 429 et 503 (EX-8.9)");
    expect(lireRetryAfter("  12 ", 0)).to.equal(12);
    expect(lireRetryAfter("1e3", 0)).to.equal(null);
    expect(lireRetryAfter(null, 0)).to.equal(null);
  });
  it("suite des attentes : 5 s, 10 s, 20 s, …, plafond 300 s ; sans code : classe nulle", function () {
    expect([1, 2, 3, 4, 5, 6, 7, 8, 9, 50].map((k) => attenteReprise(retry, k))).to.deep.equal([5000, 10000, 20000, 40000, 80000, 160000, 300000, 300000, 300000, 300000]);
    expect(attenteReprise({ ...retry, factor: 1 }, 10)).to.equal(5000);
    expect(attenteReprise(undefined, 2)).to.equal(RETRY_DEFAUT.initial_ms * 2);
    expect(classerErreur({})).to.include({ classe: null, attenteMs: null });
    expect(classerErreur({ httpStatus: 503 }).classe).to.equal("transitoire");
    expect(classerErreur({ httpStatus: 200, pkiStatus: 2, failureInfo: "badAlg" }).code).to.equal("echec_badAlg");
    expect(classerErreur({ httpStatus: 200, pkiStatus: 2, failureInfo: "autre" })).to.include({ code: "statut_2", classe: "permanente" });
  });
});

describe("ancrage rfc3161 : transport (EX-5.5, AN-7) sur un serveur local", function () {
  this.timeout(30000);
  let tlsCerts = null;
  const serveurs = [];
  before(function () {
    tlsCerts = certificatsTls(path.join(dir, "tls"));
  });
  after(async function () {
    for (const s of serveurs) await s.fermer();
  });
  const demarrer = async (o) => {
    const s = await serveurTsa(o);
    serveurs.push(s);
    return s;
  };
  const prestatairePour = (s, o = {}) => prestataireTest({ url: s.url, policy_oid: null, accepted_policies: null, correlation_header: "X-Request-ID", request_timeout_ms: 2000, ...o });
  const horloge = () => horlogeFixe(SENT, 1500);
  const alea = () => aleaFixe(Uint8Array.of(0x01, 0x80, 0x32, 0xff, 0x0d, 0x74, 0xcf, 0xda));

  it("controlerUrl : https admis ; http pour le seul rôle interne vers 127.0.0.1, ::1, localhost ; autres schémas refusés", function () {
    expect(controlerUrl("https://tsa.example/x", "principal").protocol).to.equal("https:");
    expect(controlerUrl("http://127.0.0.1:2020/", "interne").hostname).to.equal("127.0.0.1");
    expect(controlerUrl("http://localhost:2020/", "interne").hostname).to.equal("localhost");
    expect(controlerUrl("http://[::1]:2020/", "interne").hostname).to.equal("[::1]");
    expect(() => controlerUrl("http://127.0.0.1:2020/", "principal")).to.throw(ErreurTransport, /interne/);
    expect(() => controlerUrl("http://tsa.example/", "interne")).to.throw(ErreurTransport, /interne/);
    expect(() => controlerUrl("ftp://tsa.example/", "interne")).to.throw(ErreurTransport, /refusé/);
    expect(() => controlerUrl("pas une url", "interne")).to.throw(ErreurTransport, /illisible/);
    expect(entetesRequete({ taille: 69, correlationHeader: "X-Request-ID", attemptId: "point:abcd:1" })).to.deep.equal({ "Content-Type": "application/timestamp-query", Accept: "application/timestamp-reply, application/timestamp-response", "Content-Length": "69", "X-Request-ID": "point:abcd:1" });
    expect(autorisationBasic(new TextEncoder().encode("test:test"))).to.equal("Basic dGVzdDp0ZXN0");
    expect(() => autorisationBasic(new Uint8Array(0))).to.throw(ErreurTransport);
  });

  it("http vers 127.0.0.1 pour le rôle interne : POST, en-têtes exacts, corps DER, corrélation ; réponse lue et jeton vérifié ; refus du même point d'accès pour un principal", async function () {
    const s = await demarrer({ repondre: () => ({ status: 200, entetes: { "Content-Type": "application/timestamp-reply" }, corps: GRANTED_K2 }) });
    const p = prestatairePour(s, { role: "interne" });
    const r = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attemptId: "point:6a8e035ab9b90937:1", periodStart: 1793710800, horloge: horloge(), aleatoire: null, depot: null, transport: transportHttps() });
    expect(r.outcome).to.equal("obtenue");
    expect(s.requetes).to.have.length(1);
    const q = s.requetes[0];
    expect(q.method).to.equal("POST");
    expect(q.headers["content-type"]).to.equal("application/timestamp-query");
    expect(q.headers.accept).to.equal("application/timestamp-reply, application/timestamp-response");
    expect(q.headers["content-length"]).to.equal("69");
    expect(q.headers["x-request-id"]).to.equal("point:6a8e035ab9b90937:1");
    expect(q.headers.authorization).to.equal(undefined);
    expect(q.corps.equals(Buffer.from(REQUETE_K2_EXEMPLE))).to.equal(true, "le DER de la requête pour seul corps");
    expect(r.data.transport).to.equal("reponse");
    let refus = null;
    try {
      await acquerir({ prestataire: prestatairePour(s, { role: "principal" }), imprint: K2, objet: "point", nonce: 1n, periodStart: 1793710800, horloge: horloge(), transport: transportHttps() });
    } catch (e) {
      refus = e;
    }
    expect(refus).to.be.instanceOf(ErreurTransport);
    let basic = null;
    try {
      await acquerir({ prestataire: prestatairePour(s, { role: "interne", auth: { method: "basic", secret: new TextEncoder().encode("a:b") } }), imprint: K2, objet: "point", nonce: 1n, periodStart: 1793710800, horloge: horloge(), transport: transportHttps() });
    } catch (e) {
      basic = e;
    }
    expect(basic, "basic sur TLS seulement").to.be.instanceOf(ErreurTransport);
  });

  it("TLS : certificat du serveur vérifié (refus sans l'AC), TLS 1.2 au moins, Basic porté, 503 avec Retry-After, type de contenu refusé, corps au-delà de 128 Kio coupé (taille), délai", async function () {
    if (!tlsCerts) return enAttente(this, "openssl absent : aucun certificat TLS de test");
    let mode = "ok";
    const s = await demarrer({
      tls: { cert: tlsCerts.cert, key: tlsCerts.key },
      repondre: () => {
        if (mode === "ok") return { status: 200, entetes: { "Content-Type": "application/timestamp-reply; charset=binary" }, corps: GRANTED_K2 };
        if (mode === "503") return { status: 503, entetes: { "Retry-After": "30", "Content-Type": "text/plain" }, corps: Buffer.from("plus tard") };
        if (mode === "html") return { status: 200, entetes: { "Content-Type": "text/html" }, corps: Buffer.from("<html></html>") };
        if (mode === "gros") return { status: 200, entetes: { "Content-Type": "application/timestamp-reply" }, corps: new Uint8Array(CORPS_MAX + 4096) };
        if (mode === "lent") return null;
        return { status: 500, entetes: {}, corps: Buffer.alloc(0) };
      },
    });
    const transport = transportHttps({ ca: tlsCerts.caPem });
    const base = prestatairePour(s, { role: "second_rang", auth: { method: "basic", secret: new TextEncoder().encode("test:test") } });
    // Sans l'AC : la vérification du certificat du serveur refuse la connexion (erreur de transport, transitoire).
    const sansAc = await acquerir({ prestataire: base, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horloge(), transport: transportHttps() });
    expect(sansAc.outcome).to.equal("echec_transitoire");
    expect(sansAc.code).to.equal("erreur_transport");
    expect(sansAc.data.transport).to.equal("erreur_transport");
    expect(sansAc.data.http_status).to.equal(null);
    // Avec l'AC : jeton obtenu, Basic porté, paramètres du Content-Type ignorés.
    const ok = await acquerir({ prestataire: base, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horloge(), transport });
    expect(ok.outcome).to.equal("obtenue");
    expect(s.requetes.at(-1).headers.authorization).to.equal("Basic dGVzdDp0ZXN0");
    expect(ok.enregistrement).to.not.include.keys("secret");
    expect(JSON.stringify(ok.enregistrement)).to.not.include("dGVzdDp0ZXN0");
    mode = "503";
    const r503 = await acquerir({ prestataire: base, imprint: K2, objet: "point", nonce: 7n, periodStart: 1793710800, horloge: horloge(), transport });
    expect(r503).to.include({ outcome: "echec_transitoire", code: "http_503" });
    expect(r503.classement).to.include({ attenteMs: 30000, raisonAttente: "retry_after" });
    expect(r503.data).to.include({ http_status: 503, retry_after_s: 30, transport: "reponse" });
    mode = "html";
    const html = await acquerir({ prestataire: base, imprint: K2, objet: "point", nonce: 8n, periodStart: 1793710800, horloge: horloge(), transport });
    expect(html).to.include({ outcome: "echec_permanente", code: "type_contenu" });
    mode = "gros";
    const gros = await acquerir({ prestataire: base, imprint: K2, objet: "point", nonce: 9n, periodStart: 1793710800, horloge: horloge(), transport });
    expect(gros).to.include({ outcome: "echec_permanente", code: "taille" });
    expect(gros.data.body_size).to.equal(CORPS_MAX + 1);
    expect(gros.reponse.length).to.equal(CORPS_MAX, "lu jusqu'à 128 Kio puis coupé");
    mode = "lent";
    const lent = await acquerir({ prestataire: { ...base, request_timeout_ms: 1000 }, imprint: K2, objet: "point", nonce: 10n, periodStart: 1793710800, horloge: horloge(), transport });
    expect(lent).to.include({ outcome: "echec_transitoire", code: "delai" });
    expect(lent.data.transport).to.equal("delai");
  });

  it("TLS : un serveur limité à TLS 1.1 est refusé, un serveur en TLS 1.3 seul est accepté (minVersion TLSv1.2)", async function () {
    if (!tlsCerts) return enAttente(this, "openssl absent : aucun certificat TLS de test");
    const transport = transportHttps({ ca: tlsCerts.caPem });
    const s13 = await demarrer({ tls: { cert: tlsCerts.cert, key: tlsCerts.key, minVersion: "TLSv1.3" }, repondre: () => ({ status: 200, entetes: { "Content-Type": "application/timestamp-reply" }, corps: GRANTED_K2 }) });
    const ok = await acquerir({ prestataire: prestatairePour(s13), imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horloge(), transport });
    expect(ok.outcome).to.equal("obtenue");
    let s11;
    try {
      s11 = await demarrer({ tls: { cert: tlsCerts.cert, key: tlsCerts.key, minVersion: "TLSv1", maxVersion: "TLSv1.1" }, repondre: () => ({ status: 200, entetes: {}, corps: GRANTED_K2 }) });
    } catch {
      return enAttente(this, "la bibliothèque TLS de la machine ne sert plus TLS 1.1");
    }
    const ko = await acquerir({ prestataire: prestatairePour(s11), imprint: K2, objet: "point", nonce: 11n, periodStart: 1793710800, horloge: horloge(), transport });
    expect(ko.outcome).to.equal("echec_transitoire");
    expect(ko.code).to.equal("erreur_transport");
  });
});

describe("ancrage rfc3161 : acquisition, enregistrement et dépôt (EX-5.10 à EX-5.14, AN-9, AN-10, AN-13, AN-14, AN-15)", function () {
  const schema = json(path.join(SPEC, "schemas", "planificateur-ancrage-v0.schema.json"));
  const registre = new RegistreSchemas([schema]);
  const validerData = (data) => registre.valider(`${schema.$id}#/$defs/evenement_entree`, { t: "2026-11-03T13:53:03.000Z", type: "reponse_rfc3161", data });
  const depotPour = (nom) => DepotAncres.ouvrir({ racine: path.join(dir, nom), orgId: ORG, journalId: JOURNAL });

  it("data d'une entrée reponse_rfc3161 conforme au schéma pour un jeton obtenu, un rejet, une erreur HTTP et une erreur de transport ; un champ hors schéma est refusé", async function () {
    const p = prestataireTest();
    const cas = [
      ["obtenue", reponse200(GRANTED_K2)],
      ["rejet", reponse200(octets(path.join(CT5, "reponses", "rejet-badAlg.tsr")))],
      ["http", { status: 503, entetes: { "content-type": "text/plain", "retry-after": "30" }, corps: new Uint8Array(3), tronque: false }],
      ["transport", new ErreurTransport("connexion", "refusée")],
      ["illisible", reponse200(hex("30 00"))],
    ];
    for (const [nom, rep] of cas) {
      const r = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 3000), aleatoire: null, depot: null, transport: transportFactice(rep) });
      const v = validerData(r.data);
      expect(v.erreurs, nom).to.deep.equal([]);
      expect(r.data.request_id).to.equal(`jeton_point:${K2}`);
    }
    const r = await acquerir({ prestataire: p, imprint: K2, objet: "manifeste", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 3000), transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(r.data.request_id).to.equal(`jeton_periode:${K2}`);
    // Le schéma ne ferme pas `data` : le client n'y met que les champs qu'il nomme (règle 1 d'INTERFACES.md).
    const proprietes = Object.keys(schema.$defs.evenement_entree.allOf.find((b) => b.if.properties.type.const === "reponse_rfc3161").then.properties.data.properties);
    for (const k of Object.keys(r.data)) expect(proprietes, k).to.include(k);
    expect(validerData({ ...r.data, transport: "autre" }).valide).to.equal(false);
    expect(validerData({ ...r.data, attempt: 0 }).valide).to.equal(false);
    expect(identifiantTentative("point", K2, 3)).to.equal("point:6a8e035ab9b90937:3");
    expect(identifiantDemande("manifeste", K2)).to.equal(`jeton_periode:${K2}`);
  });

  it("entrées refusées : prestataire hors énumération, secret non résolu, empreinte mal formée, objet inconnu, attempt hors bornes, horloge absente", async function () {
    const p = prestataireTest();
    const t = transportFactice(reponse200(GRANTED_K2));
    const base = { imprint: K2, objet: "point", nonce: 1n, periodStart: 1793710800, horloge: horlogeFixe(SENT), transport: t };
    for (const [nom, args] of [
      ["rôle", { ...base, prestataire: { ...p, role: "autre" } }],
      ["hash", { ...base, prestataire: { ...p, hash: "sha384" } }],
      ["secret", { ...base, prestataire: { ...p, auth: { method: "basic", secret: { env: "X" } } } }],
      ["ancres vides", { ...base, prestataire: { ...p, anchor_certificates: [] } }],
      ["empreinte", { ...base, prestataire: p, imprint: "0x12" }],
      ["objet", { ...base, prestataire: p, objet: "racine" }],
      ["attempt", { ...base, prestataire: p, attempt: 0 }],
      ["attempt max", { ...base, prestataire: p, attempt: 100001 }],
      ["horloge", { ...base, prestataire: p, horloge: null }],
      ["transport", { ...base, prestataire: p, transport: {} }],
      ["nonce", { ...base, prestataire: p, nonce: 0n }],
    ]) {
      let err = null;
      try {
        await acquerir(args);
      } catch (e) {
        err = e;
      }
      expect(err, nom).to.not.equal(null);
    }
  });

  it("EX-5.14 : noms exacts des fichiers, octets identiques, acquisitions.ndjson en JCS intégral, aucun secret, promoted ; EX-5.3 : nonce réemployé refusé, nonce tiré évite le journal", async function () {
    const depot = depotPour("depot-1");
    const p = prestataireTest({ id: "tsa-test" });
    const horloge = horlogeFixe(SENT, 3000);
    const r = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attempt: 1, periodStart: 1793710800, deadlineIndex: 2, horloge, aleatoire: null, depot, transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(r.outcome).to.equal("obtenue");
    const rep = path.join(dir, "depot-1", ORG.slice(2), JOURNAL.slice(2), "ancres", "periode-1793710800");
    expect(nomPeriode(1793710800)).to.equal("periode-1793710800");
    expect(nomPeriode(5)).to.equal("periode-0000000005");
    expect(nomObjet("point", K2)).to.equal(`point-${K2.slice(2)}`);
    expect(nomObjet("manifeste", K2)).to.equal("manifeste");
    const base = `point-${K2.slice(2)}-tsa-test-point:6a8e035ab9b90937:1`;
    expect(r.fichiers).to.deep.equal({ request: `rfc3161/${base}.tsq`, response: `rfc3161/${base}.tsr`, token: `rfc3161/${base}.der`, crls: [], acquisitions: "acquisitions.ndjson" });
    expect(fs.readFileSync(path.join(rep, r.fichiers.request)).equals(Buffer.from(REQUETE_K2_EXEMPLE))).to.equal(true);
    expect(fs.readFileSync(path.join(rep, r.fichiers.response)).equals(Buffer.from(GRANTED_K2))).to.equal(true);
    expect(fs.readFileSync(path.join(rep, r.fichiers.token)).equals(Buffer.from(JETON_K2))).to.equal(true);
    const lignes = fs.readFileSync(path.join(rep, "acquisitions.ndjson"), "utf8").split("\n");
    expect(lignes).to.have.length(2);
    expect(lignes[1]).to.equal("");
    const e = analyserJson(lignes[0]);
    expect(jcs(e)).to.equal(lignes[0], "JCS intégral");
    expect(e).to.include({ attempt_id: "point:6a8e035ab9b90937:1", org_id: ORG, journal_id: JOURNAL, period_start: 1793710800, object: "point", imprint: K2, hash_algorithm: "sha256", deadline_index: 2, provider_id: "tsa-test", provider_role: "second_rang", qualified: null, nonce: "0x018032ff0d74cfda", sent_at: "2026-11-03T13:53:00.000Z", received_at: "2026-11-03T13:53:03.000Z", http_status: 200, pki_status: 0, pki_failure_info: null, outcome: "obtenue", error_code: null, token_size: 2104, gen_time: "2026-11-03T13:53:02Z", upper_bound: "2026-11-03T13:53:03.000Z", serial_number: "0x03ea", policy: "1.3.6.1.4.1.99999.1.1", freshness: "nonce", promoted: true });
    expect(e.request_sha256).to.equal(sha256Hex(REQUETE_K2_EXEMPLE));
    expect(e.token_sha256).to.equal(sha256Hex(JETON_K2));
    expect(e.checks).to.deep.equal({ "T-1": "reussi", "T-2": "reussi", "T-3": "reussi", "T-4": "reussi", "T-5": "reussi", "T-6": "reussi", "T-7": "reussi", "T-8": "reussi", "T-9": "reussi", "T-10": "non_execute" });
    expect(e.files).to.deep.equal({ request: r.fichiers.request, response: r.fichiers.response, token: r.fichiers.token, crls: [] });
    expect(e.tsu_subject_cn).to.equal("TSA de test CT-6");
    for (const k of Object.keys(e)) expect(["auth", "secret", "password", "account", "price"]).to.not.include(k);
    expect(depot.nonceConnu(NONCE_K2_EXEMPLE)).to.equal(true);
    expect(depot.nonceConnu("0x018032ff0d74cfda")).to.equal(true);
    expect(depot.nonceConnu(1n)).to.equal(false);
    let reemploi = null;
    try {
      await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attempt: 2, periodStart: 1793710800, horloge, depot, transport: transportFactice(reponse200(GRANTED_K2)) });
    } catch (err) {
      reemploi = err;
    }
    expect(reemploi).to.be.instanceOf(ErreurRequete);
    expect(reemploi.message).to.match(/nonce_reemploye/);
    // Un nonce tiré qui tombe sur une valeur connue est rejoué.
    const alea = aleaFixe(Uint8Array.of(0x01, 0x80, 0x32, 0xff, 0x0d, 0x74, 0xcf, 0xda), Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0x2a));
    const r2 = await acquerir({ prestataire: p, imprint: K2, objet: "point", attempt: 2, periodStart: 1793710800, horloge, aleatoire: alea, depot, transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(r2.enregistrement.nonce).to.equal("0x000000000000002a");
    expect(r2.enregistrement.outcome).to.equal("echec_permanente", "le jeton rejoué porte l'ancien nonce : nonce_different");
    expect(r2.enregistrement.error_code).to.equal("nonce_different");
    expect(r2.fichiers.token).to.equal(`rfc3161/point-${K2.slice(2)}-tsa-test-point:6a8e035ab9b90937:2.der`, "la réponse est conservée comme pièce");
    expect(depot.lireAcquisitions(1793710800).enregistrements).to.have.length(2);
    // Le jeton promu est le premier obtenu (EX-5.8, choix fait une fois) ; une seconde réponse valable n'est pas promue.
    const r3 = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attempt: 3, attemptId: "point:6a8e035ab9b90937:3", periodStart: 1793710800, horloge, depot: depotPour("depot-2"), transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(r3.enregistrement.promoted).to.equal(true);
    const promu = depot.promu("point", 1793710800, K2);
    expect(promu.attempt_id).to.equal("point:6a8e035ab9b90937:1");
    expect(depot.promu("manifeste", 1793710800)).to.equal(null);
    expect(depot.periodes()).to.deep.equal([1793710800]);
  });

  it("jamais de réécriture (CT-4 EX-9.3) : un fichier existant lève ErreurDepot ; une ligne tronquée est signalée ; identifiants hors motif refusés", function () {
    const depot = depotPour("depot-3");
    depot.ecrirePiece(1793710800, "rfc3161", "a.tsq", new Uint8Array([1]));
    expect(() => depot.ecrirePiece(1793710800, "rfc3161", "a.tsq", new Uint8Array([2]))).to.throw(ErreurDepot, /jamais réécrit/);
    expect(fs.readFileSync(path.join(dir, "depot-3", ORG.slice(2), JOURNAL.slice(2), "ancres", "periode-1793710800", "rfc3161", "a.tsq"))[0]).to.equal(1);
    depot.ajouterAcquisition(1793710800, { a: 1 });
    fs.appendFileSync(path.join(dir, "depot-3", ORG.slice(2), JOURNAL.slice(2), "ancres", "periode-1793710800", "acquisitions.ndjson"), '{"b":2');
    const lu = depot.lireAcquisitions(1793710800);
    expect(lu.tronquee).to.equal(true);
    expect(lu.enregistrements).to.deep.equal([{ a: 1 }]);
    expect(() => depot.nomPiece({ objet: "point", imprint: K2, providerId: "../x", attemptId: "1" })).to.throw(TypeError);
    expect(() => depot.nomPiece({ objet: "point", imprint: "0x12", providerId: "p", attemptId: "1" })).to.throw(TypeError);
    expect(() => DepotAncres.ouvrir({ racine: dir, orgId: "0x12", journalId: JOURNAL })).to.throw(TypeError);
    expect(() => nomPeriode(10000000000)).to.throw(TypeError);
    expect(depot.lireAcquisitions(1793714400).enregistrements).to.deep.equal([]);
  });

  it("EX-5.8, AN-13 : parmi plusieurs jetons valables, le qualifié au plus petit genTime + précision, sinon le plus petit", function () {
    const e = (id, qualified, upper) => ({ attempt_id: id, outcome: "obtenue", qualified, upper_bound: upper });
    expect(choisirPromu([e("a", null, "2026-11-03T13:53:03.000Z"), e("b", { framework: "eidas" }, "2026-11-03T13:53:09.000Z"), e("c", { framework: "eidas" }, "2026-11-03T13:53:05.000Z")]).attempt_id).to.equal("c");
    expect(choisirPromu([e("a", null, "2026-11-03T13:53:03.000Z"), e("b", null, "2026-11-03T13:53:02.000Z")]).attempt_id).to.equal("b");
    expect(choisirPromu([{ attempt_id: "x", outcome: "reponse_tardive", qualified: null, upper_bound: "2026-11-03T13:53:02.000Z" }])).to.equal(null);
    expect(choisirPromu([])).to.equal(null);
  });

  it("EX-5.11, AN-10 : fraîcheur et horloge ; la troisième réponse tardive est promue avec avertissement ; horloge_suspecte promue et marquée", async function () {
    const p = prestataireTest();
    const t = () => transportFactice(reponse200(GRANTED_K2));
    const tard = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 61000), transport: t(), tardivesAvant: 0 });
    expect(tard).to.include({ outcome: "reponse_tardive", code: "reponse_tardive" });
    expect(tard.enregistrement.freshness).to.equal("reponse_tardive");
    expect(tard.classement.classe).to.equal("transitoire");
    const limite = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 60000), transport: t() });
    expect(limite.outcome).to.equal("obtenue", "60 s exactement : admis");
    const troisieme = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 61000), transport: t(), tardivesAvant: 2 });
    expect(troisieme.outcome).to.equal("obtenue");
    expect(troisieme.warnings).to.deep.equal(["reponse_tardive"]);
    const suspect = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT - 121000, 2000), transport: t() });
    expect(suspect.outcome).to.equal("obtenue");
    expect(suspect.warnings).to.deep.equal(["horloge_suspecte"]);
    const juste = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT - 118000, 2000), transport: t(), fraicheur: FRAICHEUR_DEFAUT });
    expect(juste.warnings).to.deep.equal([]);
    const strict = await acquerir({ prestataire: p, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, periodStart: 1793710800, horloge: horlogeFixe(SENT, 2000), transport: t(), fraicheur: { max_response_delay_s: 1, clock_tolerance_s: 1 } });
    expect(strict.outcome).to.equal("reponse_tardive");
  });

  it("EX-5.10 étapes 3 à 6 : un jeton valable sur une autre empreinte, sans nonce, de politique différente ou refusée, de signature altérée est conservé et non promu", async function () {
    const depot = depotPour("depot-4");
    const p = prestataireTest({ policy_oid: "1.3.6.1.4.1.99999.1.1" });
    const cas = [
      ["granted-autre-empreinte", "empreinte_differente", "point-k2-exemple"],
      ["granted-sans-nonce", "nonce_absent", "point-k2-exemple"],
      ["granted-politique-differente", "politique_differente", "point-k2-exemple-politique-interne"],
      ["t6-signature", "verification_T-6", "point-k2-exemple"],
    ];
    let n = 0;
    for (const [fichier, code, requete] of cas) {
      const relue = relireRequete(octets(path.join(CT5, "requetes", `${requete}.tsq`)));
      // Un dépôt par cas : les réponses rejouées portent toutes le même nonce, qu'un même journal refuserait (AN-6).
      const r = await acquerir({ prestataire: { ...p, policy_oid: relue.policy_oid ?? "1.3.6.1.4.1.99999.1.1" }, imprint: relue.imprint, objet: "point", nonce: relue.nonceBigint, attempt: ++n, periodStart: 1793710800, horloge: horlogeFixe(SENT, 3000), depot: depotPour(`depot-4-${n}`), transport: transportFactice(reponse200(octets(path.join(CT5, "reponses", `${fichier}.tsr`)))) });
      expect(r.outcome, fichier).to.equal("echec_permanente");
      expect(r.code, fichier).to.equal(code);
      expect(r.enregistrement.promoted).to.equal(false);
      expect(r.fichiers.token).to.match(/\.der$/);
    }
    const refusee = await acquerir({ prestataire: { ...p, policy_oid: null, accepted_policies: ["1.3.6.1.4.1.99999.1.9"] }, imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attempt: 9, periodStart: 1793710800, horloge: horlogeFixe(SENT, 3000), depot, transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(refusee).to.include({ code: "politique_refusee" });
    expect(refusee.data.policy_check).to.equal("politique_refusee");
    expect(refusee.data.checks_passed).to.not.include("T-7", "la politique hors de l'ancre fait aussi échouer T-7 (règle 7)");
    expect(depot.promu("point", 1793710800, K2)).to.equal(null);
    // Écriture impossible (étape 9) : transitoire, code ecriture.
    const bloque = depotPour("depot-5");
    bloque.ecrirePiece(1793710800, "rfc3161", `point-${K2.slice(2)}-tsa-test-point:6a8e035ab9b90937:1.tsq`, new Uint8Array(1));
    const ecr = await acquerir({ prestataire: prestataireTest(), imprint: K2, objet: "point", nonce: NONCE_K2_EXEMPLE, attempt: 1, periodStart: 1793710800, horloge: horlogeFixe(SENT, 3000), depot: bloque, transport: transportFactice(reponse200(GRANTED_K2)) });
    expect(ecr).to.include({ outcome: "echec_transitoire", code: "ecriture" });
    expect(ecr.erreurEcriture).to.be.instanceOf(ErreurDepot);
    expect(ecr.jeton).to.not.equal(null, "la réponse reçue est rendue pour rejouer l'écriture sans la renvoyer");
  });

  it("EX-5.10 étape 6 : clé de l'unité hors de la version 0 (Ed25519) rattachée à l'ancre : T-5 hors_perimetre_version, le jeton n'est pas promu (verification_T-5)", async function () {
    const tok = octets(path.join(JETONS, "t5-cle-ed25519.der"));
    const reponse = encoderTlv(0x30, Buffer.concat([hex("30 03 02 01 00"), Buffer.from(tok)]));
    const r = await acquerir({ prestataire: prestataireTest({ accepted_policies: null }), imprint: PERIOD_HASH_1, objet: "manifeste", nonce: 1n, periodStart: 1793710800, horloge: horlogeFixe(Date.parse("2026-11-05T10:00:04Z"), 1000), transport: transportFactice(reponse200(reponse)) });
    expect(r.code).to.equal("nonce_different", "le jeton de CT-6 porte son propre nonce");
    expect(r.verification.raisons["T-5"]).to.equal("hors_perimetre_version");
    const nonce = r.verification.tstInfo.nonce;
    const r2 = await acquerir({ prestataire: prestataireTest({ accepted_policies: null }), imprint: PERIOD_HASH_1, objet: "manifeste", nonce, periodStart: 1793710800, horloge: horlogeFixe(Date.parse("2026-11-05T10:00:04Z"), 1000), transport: transportFactice(reponse200(reponse)) });
    expect(r2.code).to.equal("verification_T-5");
    expect(r2.outcome).to.equal("echec_permanente");
  });
});

describe("ancrage rfc3161 : fiche de prestataire et épreuve d'acceptation (EX-10.6, AN-54, EX-11.4, AN-57)", function () {
  const exemple = () => {
    const spec = texte(path.join(SPEC, "CT-5-ancrage.md"));
    const debut = spec.indexOf("<!-- schema: ancrage -->");
    const bloc = spec.slice(spec.indexOf("```json", debut) + 7, spec.indexOf("```", spec.indexOf("```json", debut) + 7));
    return JSON.parse(bloc);
  };
  it("construireFiche : forme de providers[] privée d'auth, SHA-256 des certificats, instantané qualified, mention non qualifié pour le rôle interne ; verifierFiche l'accepte", function () {
    const cfg = exemple();
    const principal = cfg.rfc3161.providers.find((p) => p.role === "principal");
    const interne = cfg.rfc3161.providers.find((p) => p.role === "interne");
    const f = construireFiche(principal);
    expect(f).to.not.have.property("auth");
    expect(f.id).to.equal("qtsa-principal");
    expect(f.anchor_certificates_sha256).to.deep.equal([lireCertificatPem(AC_TEST_PEM).sha256]);
    expect(f.qualified.framework).to.equal("eidas");
    expect(f.qualified_notice).to.equal(null);
    expect(f.acceptance_test).to.equal(null);
    expect(nomFiche(f)).to.equal("prestataire-qtsa-principal.json");
    expect(verifierFiche(f)).to.deep.equal({ conforme: true, ecarts: [] });
    const fi = construireFiche(interne);
    expect(fi.qualified).to.equal(null);
    expect(fi.qualified_notice).to.equal(MENTION_NON_QUALIFIE);
    expect(verifierFiche(fi).conforme).to.equal(true);
    expect(JSON.stringify(f)).to.not.match(/NOORTRACE_TSA_PRINCIPAL|secret|password|price/);
  });
  it("verifierFiche (AN-54) : clé interdite à tout niveau, SHA-256 différent, PEM illisible, interne qualifié, mention absente, épreuve mal datée", function () {
    const f = construireFiche(exemple().rfc3161.providers[0]);
    expect(verifierFiche({ ...f, auth: { method: "basic" } }).ecarts).to.include("clé interdite auth");
    expect(verifierFiche({ ...f, qualified: { ...f.qualified, trusted_list: { ...f.qualified.trusted_list, Password: "x" } } }).ecarts.some((e) => e.includes("qualified.trusted_list.Password"))).to.equal(true);
    expect(verifierFiche({ ...f, anchor_certificates_sha256: ["0x" + "00".repeat(32)] }).ecarts[0]).to.match(/SHA-256/);
    expect(verifierFiche({ ...f, anchor_certificates: ["-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"] }).ecarts[0]).to.match(/illisible/);
    expect(verifierFiche({ ...f, role: "interne" }).ecarts[0]).to.match(/jamais qualifié/);
    expect(verifierFiche({ ...f, qualified: null, qualified_notice: null }).ecarts[0]).to.match(/non qualifié/);
    expect(verifierFiche({ ...f, acceptance_test: { tested_at: "hier", outcome: "obtenue" } }).ecarts.length).to.be.at.least(2);
    expect(verifierFiche({ ...f, acceptance_test: { tested_at: "2026-11-03T13:53:00.000Z", outcome: "gagne" } }).ecarts[0]).to.match(/outcome/);
    expect(verifierFiche({ ...f, role: "roi" }).ecarts[0]).to.match(/role/);
    expect(verifierFiche(null).conforme).to.equal(false);
    expect(verifierFiche([]).conforme).to.equal(false);
    const { source, ...sans } = f;
    void source;
    expect(verifierFiche(sans).ecarts).to.include("clé source absente");
  });
  it("epreuveAcceptation : requête sur une empreinte de test, réponse vérifiée, résultat daté dans la fiche (AN-57) ; un rejet est rapporté tel quel", async function () {
    const p = prestataireTest({ policy_oid: null, accepted_policies: null });
    const horloge = horlogeFixe(SENT, 2000);
    // La réponse rejouée porte l'empreinte K2 : l'épreuve exige l'empreinte de test, donc `imprint` est fixée à K2 et le nonce de la réponse est imposé par l'aléa.
    const t = transportFactice(reponse200(GRANTED_K2));
    const e = await epreuveAcceptation({ prestataire: p, transport: t, horloge, aleatoire: aleaFixe(Uint8Array.of(0x01, 0x80, 0x32, 0xff, 0x0d, 0x74, 0xcf, 0xda)), imprint: K2 });
    expect(e.tested_at).to.equal("2026-11-03T13:53:00.000Z");
    expect(e.outcome).to.equal("obtenue");
    expect(e.tsu_certificate_sha256).to.equal(lireCertificatPem(TSA_TEST_PEM).sha256);
    expect(e.checks["T-10"]).to.equal("non_execute");
    expect(t.appels[0].entetes["X-Request-ID"]).to.match(/^epreuve:6a8e035ab9b90937:1$/);
    const fiche = construireFiche(p, { epreuve: e });
    expect(verifierFiche(fiche).conforme).to.equal(true);
    expect(fiche.acceptance_test.tested_at).to.equal("2026-11-03T13:53:00.000Z");
    const rejet = await epreuveAcceptation({ prestataire: p, transport: transportFactice(reponse200(octets(path.join(CT5, "reponses", "rejet-badAlg.tsr")))), horloge, aleatoire: aleaFixe(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)) });
    expect(rejet).to.include({ outcome: "echec_permanente", error_code: "echec_badAlg" });
    expect(rejet.imprint).to.match(/^0x[0-9a-f]{64}$/);
    expect(verifierFiche(construireFiche(p, { epreuve: rejet })).conforme).to.equal(true);
  });
});
