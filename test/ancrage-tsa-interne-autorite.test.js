// Autorité du serveur RFC 3161 interne (lot E) : `initialiserAutorite`
// (AN-22, AN-31 : AC auto-signée, unité à EKU critique `id-kp-timeStamping`
// seul, CA:FALSE, validité ≤ 3 ans, point de distribution de CRL, CRL vide
// signée ; RSA 3072 et P-256), `publierCrl`, `chargerAutorite`, et les
// refus de la classe `Autorite` (clé faible ou hors bornes, clé qui ne
// correspond pas au certificat, EKU non critique, certificat d'AC, validité
// trop longue, politique ou précision hors profil). Juges : `openssl x509
// -text`, `openssl crl -text`, `openssl verify -crl_check`, `openssl ts
// -verify` sur une réponse de chaque autorité générée.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { Autorite, ErreurAutorite, CompteurMemoire, repondre, initialiserAutorite, publierCrl, chargerAutorite, FICHIERS_AUTORITE, emettreCertificat, emettreCrl, construireNom, extensionsUnite, extensionsAc, lireCertificatX509, defautsUnite, decrireCle, lireClePrivee, derEcriture as D } from "@noortrace/ancrage/serveur-interne";
import { CLES_CT6, AUTORITE_TEST, POLITIQUE_TEST, lireRequete, cheminRequete, repertoireTemporaire, horlogeFixe, aleatoireFixe, openssl, opensslEssai, verifierOpenssl, relireReponse, ecrire, hex } from "./fixtures/ancrage-tsa-interne/outils.mjs";

const H = horlogeFixe("2026-11-03T13:53:02Z");
const cle = (nom) => fs.readFileSync(path.join(CLES_CT6, nom));

// Nom de l'AC tel qu'openssl -text l'imprime : « O = …, CN = … » jusqu'à OpenSSL 3.0, sans espaces autour de « = » ensuite.
const NOM_AC = /Issuer: ?O ?= ?NOORTRACE developpement, ?CN ?= ?AC interne de developpement\n/;

describe("ancrage lot E — initialiserAutorite (AN-22, AN-31) : RSA 3072 et P-256", function () {
  this.timeout(120000);
  let rep;
  before(function () {
    rep = repertoireTemporaire();
  });
  after(function () {
    fs.rmSync(rep, { recursive: true, force: true });
  });

  for (const algorithme of ["rsa-3072", "p-256"]) {
    describe(algorithme, function () {
      let r;
      let dir;
      before(function () {
        dir = path.join(rep, algorithme);
        r = initialiserAutorite({ repertoire: dir, algorithme, politique: "1.3.6.1.4.1.99999.2.1", crlUrl: "http://127.0.0.1:8080/crl.pem", validiteJours: 1095, horloge: H, aleatoire: aleatoireFixe(3) });
      });

      it("écrit clés PKCS#8 (mode 600), certificats et CRL en PEM, le descripteur autorite.json sans secret", function () {
        for (const [k, f] of Object.entries(FICHIERS_AUTORITE)) {
          if (k === "compteur") continue;
          expect(fs.existsSync(path.join(dir, f)), f).to.equal(true);
        }
        expect(fs.statSync(r.fichiers.acCle).mode & 0o777).to.equal(0o600);
        expect(fs.statSync(r.fichiers.uniteCle).mode & 0o777).to.equal(0o600);
        expect(fs.readFileSync(r.fichiers.uniteCle, "utf8")).to.match(/^-----BEGIN PRIVATE KEY-----\n/);
        expect(openssl(["pkey", "-in", r.fichiers.uniteCle, "-noout", "-text"])).to.include(algorithme === "rsa-3072" ? "Private-Key: (3072 bit" : "Private-Key: (256 bit)");
        const d = JSON.parse(fs.readFileSync(r.fichiers.descripteur, "utf8"));
        expect(d).to.include({ version: 0, role: "interne", qualified: null, algorithm: algorithme, policy_oid: "1.3.6.1.4.1.99999.2.1", accuracy_s: 1, crl_url: "http://127.0.0.1:8080/crl.pem", created_at: "2026-11-03T13:53:02.000Z" });
        expect(d.unit_certificate_sha256).to.match(/^0x[0-9a-f]{64}$/);
        expect(JSON.stringify(d)).to.not.include("PRIVATE");
      });

      it("unité (openssl x509 -text) : EKU critique Time Stamping seul, CA:FALSE, Digital Signature critique, SKI, AKI, URI de CRL, validité ≤ 3 ans, clé admise", function () {
        const t = openssl(["x509", "-in", r.fichiers.unite, "-noout", "-text"]);
        expect(t).to.match(/X509v3 Extended Key Usage: critical\s*\n\s*Time Stamping\s*\n/);
        expect(t).to.include("CA:FALSE");
        expect(t).to.match(/X509v3 Key Usage: critical\s*\n\s*Digital Signature\s*\n/);
        expect(t).to.include("X509v3 Subject Key Identifier");
        expect(t).to.include("X509v3 Authority Key Identifier");
        expect(t).to.include("URI:http://127.0.0.1:8080/crl.pem");
        expect(t).to.include("Not Before: Nov  3 13:53:02 2026 GMT");
        expect(t).to.include("Not After : Nov  2 13:53:02 2029 GMT");
        expect(t).to.include(algorithme === "rsa-3072" ? "Public-Key: (3072 bit)" : "Public-Key: (256 bit)");
        expect(t).to.include(algorithme === "rsa-3072" ? "Signature Algorithm: sha256WithRSAEncryption" : "Signature Algorithm: ecdsa-with-SHA256");
        expect(t).to.include("Version: 3 (0x2)");
        expect(t).to.match(NOM_AC, "émetteur : l'AC");
        expect(t).to.match(/Subject: O ?= ?NOORTRACE developpement, ?CN ?= ?TSA interne non qualifiee\n/);
        const c = lireCertificatX509(fs.readFileSync(r.fichiers.unite));
        expect(defautsUnite(c)).to.deep.equal([]);
        expect(c.extensions.map((e) => e.oid)).to.deep.equal(["2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.14", "2.5.29.35", "2.5.29.31"]);
        // Aucune valeur DEFAULT encodée : pas de `critical FALSE`, pas de `cA FALSE`, pas de `version v1`.
        expect(hex(c.der)).to.not.include("010100");
      });

      it("AC auto-signée : CA:TRUE critique, Certificate Sign et CRL Sign, SKI égal à l'AKI de l'unité ; openssl verify accepte l'unité", function () {
        const t = openssl(["x509", "-in", r.fichiers.ac, "-noout", "-text"]);
        expect(t).to.match(/X509v3 Basic Constraints: critical\s*\n\s*CA:TRUE\s*\n/);
        expect(t).to.match(/X509v3 Key Usage: critical\s*\n\s*Certificate Sign, CRL Sign\s*\n/);
        const ski = /Subject Key Identifier:\s*\n\s*([0-9A-F:]+)/.exec(t)[1];
        const tu = openssl(["x509", "-in", r.fichiers.unite, "-noout", "-text"]);
        expect(/Authority Key Identifier:\s*\n\s*([0-9A-F:]+)/.exec(tu)[1]).to.equal(ski);
        expect(openssl(["verify", "-CAfile", r.fichiers.ac, r.fichiers.unite])).to.include(": OK");
        expect(openssl(["verify", "-CAfile", r.fichiers.ac, r.fichiers.ac])).to.include(": OK");
      });

      it("CRL vide signée (openssl crl -text) : v2, émetteur l'AC, thisUpdate et nextUpdate, numéro 1, aucun certificat révoqué ; openssl verify -crl_check accepte l'unité", function () {
        const t = openssl(["crl", "-in", r.fichiers.crl, "-noout", "-text"]);
        expect(t).to.include("Version 2 (0x1)");
        expect(t).to.match(NOM_AC, "émetteur : l'AC");
        expect(t).to.include("Last Update: Nov  3 13:53:02 2026 GMT");
        expect(t).to.include("Next Update: Dec  3 13:53:02 2026 GMT");
        expect(t).to.match(/X509v3 CRL Number:\s*\n\s*1\s*\n/);
        expect(t).to.include("No Revoked Certificates.");
        expect(openssl(["crl", "-in", r.fichiers.crl, "-noout", "-verify", "-CAfile", r.fichiers.ac], undefined)).to.equal("");
        expect(openssl(["verify", "-crl_check", "-CAfile", r.fichiers.ac, "-CRLfile", r.fichiers.crl, r.fichiers.unite])).to.include(": OK");
      });

      it("une réponse granted de cette autorité : Verification: OK par openssl ts -verify ; politique et algorithme relus ; nonce différent → nonce mismatch", function () {
        const a = chargerAutorite({ repertoire: dir, compteur: new CompteurMemoire(1n) });
        expect(a.algorithme).to.equal(algorithme === "rsa-3072" ? "rsa" : "p-256");
        expect(a.politique).to.equal("1.3.6.1.4.1.99999.2.1");
        const rr = repondre({ requete: lireRequete("point-k2-exemple"), autorite: a, horloge: H });
        expect(rr.statut).to.equal("granted");
        const chemin = ecrire(dir, "r.tsr", rr.octets);
        const v = verifierOpenssl({ requete: cheminRequete("point-k2-exemple"), reponse: chemin, ac: r.fichiers.ac, unite: r.fichiers.unite });
        expect(v.code, v.stderr).to.equal(0);
        expect(v.stdout).to.include("Verification: OK");
        const lu = relireReponse(chemin);
        expect(lu.politique).to.equal("1.3.6.1.4.1.99999.2.1");
        expect(lu.tsa).to.equal("DirName:/O=NOORTRACE developpement/CN=TSA interne non qualifiee");
        expect(lu.precision).to.include("0x01 seconds");
        const mauvais = verifierOpenssl({ requete: cheminRequete("requete-point-k2"), reponse: chemin, ac: r.fichiers.ac, unite: r.fichiers.unite });
        expect(mauvais.stderr).to.include("nonce mismatch");
        // Signature ECDSA : SignerInfo ecdsa-with-SHA256 sans paramètres ; RSA : sha256WithRSAEncryption avec NULL.
        const asn = openssl(["asn1parse", "-inform", "DER", "-i"], Buffer.from(rr.octets));
        expect(asn).to.include(algorithme === "rsa-3072" ? "sha256WithRSAEncryption" : "ecdsa-with-SHA256");
        // Avec l'AC incluse, openssl vérifie aussi.
        const a2 = chargerAutorite({ repertoire: dir, compteur: new CompteurMemoire(2n), inclureAc: true });
        const r2 = ecrire(dir, "r2.tsr", repondre({ requete: lireRequete("point-k2-exemple"), autorite: a2, horloge: H }).octets);
        expect(verifierOpenssl({ requete: cheminRequete("point-k2-exemple"), reponse: r2, ac: r.fichiers.ac, unite: r.fichiers.unite }).stdout).to.include("Verification: OK");
      });

      it("publierCrl : numéro incrémenté, nouvelle date, entrée révoquée avec raison ; la CRL se vérifie sous l'AC", function () {
        const u = lireCertificatX509(fs.readFileSync(r.fichiers.unite));
        const p = publierCrl({ repertoire: dir, horloge: horlogeFixe("2026-12-01T00:00:00Z"), validiteCrlJours: 7 });
        expect(p.numero).to.equal(2n);
        expect(p.thisUpdate).to.equal("2026-12-01T00:00:00.000Z");
        expect(p.nextUpdate).to.equal("2026-12-08T00:00:00.000Z");
        const t = openssl(["crl", "-in", p.chemin, "-noout", "-text"]);
        expect(t).to.match(/X509v3 CRL Number:\s*\n\s*2\s*\n/);
        expect(t).to.include("Last Update: Dec  1 00:00:00 2026 GMT");
        expect(openssl(["crl", "-in", p.chemin, "-noout", "-verify", "-CAfile", r.fichiers.ac])).to.equal("");
        const serieUnite = BigInt(`0x${hex(u.serie.subarray(2))}`);
        const p3 = publierCrl({ repertoire: dir, horloge: horlogeFixe("2026-12-02T00:00:00Z"), revoques: [{ serie: serieUnite, date: Date.parse("2026-12-02T00:00:00Z"), raison: 4 }] });
        expect(p3.numero).to.equal(3n);
        const t3 = openssl(["crl", "-in", p3.chemin, "-noout", "-text"]);
        expect(t3).to.include("Revoked Certificates:");
        expect(t3).to.include("Superseded");
        const v = opensslEssai(["verify", "-crl_check", "-CAfile", r.fichiers.ac, "-CRLfile", p3.chemin, r.fichiers.unite]);
        expect(v.code).to.not.equal(0);
        expect(v.stderr + v.stdout).to.include("certificate revoked");
        expect(fs.readFileSync(path.join(dir, FICHIERS_AUTORITE.crlNumero), "utf8")).to.equal("3\n");
      });

      it("rien n'est écrasé : une seconde initialisation dans le même répertoire est refusée", function () {
        expect(() => initialiserAutorite({ repertoire: dir, algorithme, politique: "1.2.3", crlUrl: "http://127.0.0.1/crl", horloge: H, aleatoire: aleatoireFixe() })).to.throw(ErreurAutorite, /existe déjà/);
      });
    });
  }

  it("bornes : validiteJours hors 1..1095, algorithme inconnu, politique non OID, crlUrl non http(s), horloge ou aléa absents", function () {
    const base = { repertoire: path.join(rep, "bornes"), algorithme: "rsa-3072", politique: "1.3.6.1.4.1.99999.2.1", crlUrl: "http://127.0.0.1/crl.pem", horloge: H, aleatoire: aleatoireFixe() };
    expect(() => initialiserAutorite({ ...base, validiteJours: 1096 })).to.throw(ErreurAutorite, /1095/);
    expect(() => initialiserAutorite({ ...base, validiteJours: 0 })).to.throw(ErreurAutorite);
    expect(() => initialiserAutorite({ ...base, validiteJours: 1.5 })).to.throw(ErreurAutorite);
    expect(() => initialiserAutorite({ ...base, algorithme: "rsa-2048" })).to.throw(ErreurAutorite, /rsa-3072 ou p-256/);
    expect(() => initialiserAutorite({ ...base, algorithme: "ed25519" })).to.throw(ErreurAutorite);
    expect(() => initialiserAutorite({ ...base, politique: "politique" })).to.throw(ErreurAutorite, /OID/);
    expect(() => initialiserAutorite({ ...base, crlUrl: "ldap://x" })).to.throw(ErreurAutorite, /http/);
    expect(() => initialiserAutorite({ ...base, horloge: null })).to.throw(TypeError);
    expect(() => initialiserAutorite({ ...base, aleatoire: null })).to.throw(TypeError);
    expect(() => initialiserAutorite({ ...base, validiteAcJours: 10 })).to.throw(ErreurAutorite, /validiteAcJours/);
    expect(fs.existsSync(path.join(rep, "bornes", "ac.cle.pem"))).to.equal(false);
  });

  it("chargerAutorite sur un répertoire sans descripteur ni politique : refus ; avec politique donnée : chargé", function () {
    const dir = path.join(rep, "sans-descripteur");
    initialiserAutorite({ repertoire: dir, algorithme: "p-256", politique: "1.2.3.4", crlUrl: "http://127.0.0.1/crl.pem", horloge: H, aleatoire: aleatoireFixe(9) });
    fs.unlinkSync(path.join(dir, FICHIERS_AUTORITE.descripteur));
    expect(() => chargerAutorite({ repertoire: dir, compteur: new CompteurMemoire() })).to.throw(ErreurAutorite, /politique absente/);
    const a = chargerAutorite({ repertoire: dir, politique: "1.2.3.4", compteur: new CompteurMemoire() });
    expect(a.politique).to.equal("1.2.3.4");
    // Sans compteur fourni : compteur durable du sous-répertoire compteur/, verrou rendu à la fermeture.
    const b = chargerAutorite({ repertoire: dir, politique: "1.2.3.4" });
    expect(fs.existsSync(path.join(dir, "compteur", "serie.verrou"))).to.equal(true);
    b.fermer();
    expect(fs.existsSync(path.join(dir, "compteur", "serie.verrou"))).to.equal(false);
  });
});

describe("ancrage lot E — classe Autorite : contrôles à la construction (AN-22, AN-30, AN-31 ; CT-6 EX-9.23)", function () {
  this.timeout(60000);
  const base = () => ({ clePrivee: cle("tsa-test.cle.pem"), certificat: cle("tsa-test.pem"), politique: POLITIQUE_TEST, compteur: new CompteurMemoire() });

  it("l'autorité de test de CT-6 est admise : RSA 3072, EKU critique timeStamping, pas d'AC, validité d'un an", function () {
    const a = new Autorite(base());
    expect(a.algorithme).to.equal("rsa");
    expect(a.cle.bits).to.equal(3072);
    expect(a.precisionS).to.equal(1);
    expect(hex(a.identifiantCleSujet)).to.equal("42e0e8a680c207fd2fb1b1542c509f1cd9f28a93");
    expect(a.dansValidite(Date.parse("2026-06-01T00:00:00Z"))).to.equal(true);
    expect(a.dansValidite(Date.parse("2027-06-01T00:00:01Z"))).to.equal(false);
    // DER ou PEM pour la clé et le certificat.
    const derCle = D.depuisPem(cle("tsa-test.cle.pem").toString(), "PRIVATE KEY");
    const derCert = D.depuisPem(cle("tsa-test.pem").toString(), "CERTIFICATE");
    expect(new Autorite({ ...base(), clePrivee: derCle, certificat: derCert }).algorithme).to.equal("rsa");
  });

  it("clé qui ne correspond pas au certificat : refus (clé de l'AC avec le certificat de l'unité)", function () {
    expect(() => new Autorite({ ...base(), clePrivee: cle("ac-test.cle.pem") })).to.throw(ErreurAutorite, /ne correspond pas/);
  });

  it("clés hors profil : RSA 2048 (trop courte), RSA 8200 (au-delà de 8192), exposant 2^31 + 1, Ed25519, P-384 (AN-31, EX-9.23)", function () {
    const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    expect(() => decrireCle(rsa2048)).to.throw(ErreurAutorite, /3072 au moins/);
    expect(() => decrireCle(lireClePrivee(cle("tsa-8200.cle.pem")))).to.throw(ErreurAutorite, /8192 au plus/);
    expect(() => decrireCle(lireClePrivee(cle("tsa-exposant.cle.pem")))).to.throw(ErreurAutorite, /exposant/);
    expect(() => decrireCle(lireClePrivee(cle("tsa-ed25519.cle.pem")))).to.throw(ErreurAutorite, /RSA ou ECDSA P-256/);
    expect(() => decrireCle(generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey)).to.throw(ErreurAutorite, /P-256 seule/);
    expect(decrireCle(lireClePrivee(cle("tsa-8192.cle.pem"))).bits).to.equal(8192);
    expect(() => new Autorite({ ...base(), clePrivee: cle("tsa-8200.cle.pem"), certificat: cle("tsa-8200.pem") })).to.throw(ErreurAutorite, /8192/);
    expect(() => lireClePrivee(Buffer.from("pas une cle"))).to.throw(ErreurAutorite, /illisible/);
  });

  it("certificats d'unité hors profil : EKU non critique (tsa-eku-non-critique.pem), certificat d'AC (ac-test.pem), validité trop longue", function () {
    const eku = lireCertificatX509(cle("tsa-eku-non-critique.pem"));
    expect(defautsUnite(eku)).to.deep.equal(["extKeyUsage non critique (AN-22)"]);
    const ac = lireCertificatX509(cle("ac-test.pem"));
    expect(defautsUnite(ac)).to.include("extKeyUsage absent (AN-22)");
    expect(defautsUnite(ac)).to.include("certificat d'AC (AN-22)");
    expect(defautsUnite(ac).some((d) => /au-delà de trois ans/.test(d))).to.equal(true);
    expect(() => new Autorite({ ...base(), certificat: cle("tsa-eku-non-critique.pem") })).to.throw(ErreurAutorite, /non critique/);
    expect(() => new Autorite({ ...base(), clePrivee: cle("ac-test.cle.pem"), certificat: cle("ac-test.pem") })).to.throw(ErreurAutorite, /AC/);
    // Certificat à `critical FALSE` encodé : illisible (EX-9.21).
    expect(() => lireCertificatX509(cle("tsa-critique-faux.pem"))).to.throw(/critical FALSE/);
    // Unité expirée : admise à la construction, mais aucune émission hors validité (systemFailure, essai des réponses).
    const expiree = lireCertificatX509(cle("tsa-expiree.pem"));
    expect(defautsUnite(expiree)).to.deep.equal([]);
  });

  it("une unité émise pour plus de trois ans est refusée ; 1096 jours (trois ans bissextiles) admis", function () {
    const cleAc = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const cleU = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const nom = construireNom({ CN: "AC" });
    const spki = (k) => new Uint8Array(createPublicKey(k).export({ type: "spki", format: "der" }));
    const spkiAc = spki(cleAc);
    const spkiU = spki(cleU);
    const emettre = (jours) =>
      emettreCertificat({ cleEmetteur: cleAc, emetteur: nom, sujet: construireNom({ CN: "U" }), spki: spkiU, serie: 7n, notBefore: H.murale(), notAfter: H.murale() + jours * 86400000, extensions: extensionsUnite(spkiU, new Uint8Array(20), "http://127.0.0.1/crl") });
    expect(defautsUnite(lireCertificatX509(emettre(1096)))).to.deep.equal([]);
    expect(defautsUnite(lireCertificatX509(emettre(1097)))).to.deep.equal(["validité de 1097 jours, au-delà de trois ans (AN-31)"]);
    expect(() => emettreCertificat({ cleEmetteur: cleAc, emetteur: nom, sujet: nom, spki: spkiAc, serie: 0n, notBefore: 0, notAfter: 1, extensions: extensionsAc(spkiU) })).to.throw(ErreurAutorite, /positif/);
    expect(() => emettreCertificat({ cleEmetteur: cleAc, emetteur: nom, sujet: nom, spki: spkiU, serie: 1n, notBefore: 5, notAfter: 5, extensions: [] })).to.throw(ErreurAutorite, /notBefore/);
    expect(() => emettreCrl({ cleEmetteur: cleAc, emetteur: nom, identifiantCleEmetteur: null, thisUpdate: 10, nextUpdate: 10, numero: 1n })).to.throw(ErreurAutorite);
    expect(() => emettreCrl({ cleEmetteur: cleAc, emetteur: nom, identifiantCleEmetteur: null, thisUpdate: 1, nextUpdate: 10, numero: -1n })).to.throw(ErreurAutorite);
  });

  it("politique non OID, précision hors 0..1, compteur absent, options absentes, signataire mal formé : refus ; signataire injecté (classe A à C) admis", function () {
    expect(() => new Autorite({ ...base(), politique: "interne" })).to.throw(ErreurAutorite, /OID/);
    expect(() => new Autorite({ ...base(), politique: "3.1.1" })).to.throw(RangeError);
    expect(() => new Autorite({ ...base(), precisionS: 2 })).to.throw(ErreurAutorite, /au plus 1/);
    expect(() => new Autorite({ ...base(), precisionS: 0.5 })).to.throw(ErreurAutorite);
    expect(() => new Autorite({ ...base(), compteur: null })).to.throw(ErreurAutorite, /compteur/);
    expect(() => new Autorite()).to.throw(TypeError);
    expect(() => new Autorite({ certificat: cle("tsa-test.pem"), politique: POLITIQUE_TEST, compteur: new CompteurMemoire() })).to.throw(ErreurAutorite, /clePrivee ou signataire/);
    expect(() => new Autorite({ certificat: cle("tsa-test.pem"), politique: POLITIQUE_TEST, compteur: new CompteurMemoire(), signataire: { type: "p-256", signer: () => new Uint8Array(1) } })).to.throw(ErreurAutorite, /type de clé différent/);
    expect(() => new Autorite({ certificat: cle("tsa-test.pem"), politique: POLITIQUE_TEST, compteur: new CompteurMemoire(), signataire: { type: "dsa", signer: () => new Uint8Array(1) } })).to.throw(ErreurAutorite, /signataire/);
    // Signataire externe qui délègue à la clé de test : même jeton qu'avec la clé.
    const d = decrireCle(lireClePrivee(cle("tsa-test.cle.pem")));
    let appels = 0;
    const a = new Autorite({ certificat: cle("tsa-test.pem"), politique: POLITIQUE_TEST, compteur: new CompteurMemoire(1001n), signataire: { type: "rsa", signer: (o) => { appels++; return d.signer(o); } } });
    const r = repondre({ requete: lireRequete("requete-point-k2"), autorite: a, horloge: H });
    expect(appels).to.equal(1);
    expect(hex(r.octets)).to.equal(hex(fs.readFileSync(path.join(AUTORITE_TEST.ac, "..", "..", "..", "..", "ct-5", "reponses", "granted-requete-point-k2.tsr"))));
  });
});
