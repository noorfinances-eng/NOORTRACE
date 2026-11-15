// Revue de sécurité interne de l'étape 8 : client RFC 3161. Bornes de
// temps et d'adresses (causes S-1, S-7) : CT-6 EX-9.13 (recherche du
// chemin avec mémoire des signatures : 16 × 17 vérifications au plus par
// autorité), CT-5 EX-5.5 (délai total d'une requête), (capture
// des CRL : plafond, dédoublonnage, adresses locales et privées refusées en
// production, liste d'hôtes par prestataire), EX-4.8 (url à
// identifiants refusée par AN-1, le transport et la fiche), EX-4.9 (interne
// jamais qualifié), (serveur interne : champs de certificat
// contrôlés, délais du frontal posés).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifierJeton, construireRequete, controlerUrl, transportHttps, construireFiche, verifierFiche, capturerCrls, ErreurTransport, controlerUrlCrl } from "@noortrace/ancrage/rfc3161";
import { validerConfiguration } from "@noortrace/ancrage/planificateur";
import { Autorite, CompteurMemoire, repondre, emettreCertificat, construireNom, derEcriture as W, lireCertificatX509, demarrerServeur } from "@noortrace/ancrage/serveur-interne";
import { extensionX509, spkiDe, identifiantCle, sha256 } from "../paquets/ancrage/src/serveur-interne/autorite.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const exempleCt5 = () => {
  const texte = fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8");
  const m = /<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(texte);
  return JSON.parse(m[1]);
};
const T = Date.UTC(2026, 10, 5, 10, 0, 5);
const JOUR = 86400000;
const ec = () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const nom = (cn) => construireNom({ O: "essai revue de sécurité", CN: cn });
let serie = 5000n;
const extAc = (k) => [extensionX509("2.5.29.19", true, W.sequence(W.booleen(true))), extensionX509("2.5.29.15", true, W.bitsNommes([5, 6])), extensionX509("2.5.29.14", false, W.chaineOctets(identifiantCle(spkiDe(k))))];
const cert = (ek, en, sn, sk, ext) => emettreCertificat({ cleEmetteur: ek, emetteur: en, sujet: sn, spki: spkiDe(sk), serie: ++serie, notBefore: T - 30 * JOUR, notAfter: T + 300 * JOUR, extensions: ext });

describe("ancrage, revue de sécurité de l'étape 8 : recherche du chemin de certification avec mémoire (CT-6 EX-9.13, EX-9.23)", function () {
  this.timeout(120000);
  it("quinze certificats d'AC de même nom qui se signent tous : la recherche les essaie tous et T-7 échoue en moins de 300 vérifications de signature (était des dizaines de milliers, 5 à 48 s) ; un seizième de même nom, émis par une ancre et placé après eux, est trouvé", function () {
    const K = ec();
    const n = nom("meme nom");
    const chaine = [];
    for (let j = 0; j < 15; j++) chaine.push(cert(K, n, n, K, extAc(K)));
    const uCle = ec();
    const uNom = nom("unite essai");
    const extU = [extensionX509("2.5.29.15", true, W.bitsNommes([0])), extensionX509("2.5.29.37", true, W.sequence(W.oid("1.3.6.1.5.5.7.3.8")))];
    const bonne = (() => { const a = ec(); const an = nom("AC bonne"); return cert(a, an, uNom, uCle, extU); })();
    const hostile = cert(K, n, uNom, uCle, extU);
    const autorite = new Autorite({ clePrivee: uCle.export({ type: "pkcs8", format: "pem" }), certificat: bonne, politique: "1.3.6.1.4.1.99999.1.1", compteur: new CompteurMemoire() });
    autorite.certificat = lireCertificatX509(hostile);
    autorite.certHash = sha256(hostile);
    autorite.chaine = chaine.map((d) => lireCertificatX509(d));
    const imprint = "0x" + "ab".repeat(32);
    const r = repondre({ requete: construireRequete({ imprint, nonce: 77n }).octets, autorite, horloge: { murale: () => T } });
    const ancres = { tsa_authorities: [] };
    for (let j = 0; j < 8; j++) {
      const a = ec();
      const an = nom(`ancre ${j}`);
      ancres.tsa_authorities.push({ name: `ancre ${j}`, certificate: W.pem("CERTIFICATE", cert(a, an, an, a, extAc(a))), intermediates: [], accepted_policies: null, qualified: null });
    }
    const statistiques = { signatures: 0 };
    const debut = performance.now();
    const v = verifierJeton({ octets: r.jeton, imprintAttendue: imprint, ancres, aGenTime: true, statistiques });
    const duree = performance.now() - debut;
    expect(v.checks["T-1"]).to.equal("reussi");
    expect(v.checks["T-7"]).to.equal("echoue");
    expect(statistiques.signatures, `vérifications de signature de la recherche de chemin : ${statistiques.signatures}`).to.be.at.most(300);
    // La recherche a bien essayé les candidats : S est vérifié sous chacun des quinze certificats de même nom
    // (au moins 15 vérifications). Une recherche qui n'essaie aucun candidat, ou s'arrête au premier, en fait moins.
    expect(statistiques.signatures, "S essayé sous chacun des quinze candidats de même nom").to.be.at.least(15);
    expect(duree, `durée ${Math.round(duree)} ms`).to.be.below(3000);

    // Même jeton, un seizième certificat de même nom et de même clé, émis par une ancre : il est porté par les
    // intermédiaires de cette ancre, donc placé dans les candidats après les quinze du jeton (EX-9.13 : ordre des
    // candidats, puis des autorités), et cette ancre vient après les huit autres. Le seul chemin valide passe par lui.
    const cleBonne = ec();
    const nomBonne = nom("ancre bonne");
    const ancreBonne = cert(cleBonne, nomBonne, nomBonne, cleBonne, extAc(cleBonne));
    const intermediaire = cert(cleBonne, nomBonne, n, K, extAc(K));
    const ancres2 = { tsa_authorities: [...ancres.tsa_authorities, { name: "ancre bonne", certificate: W.pem("CERTIFICATE", ancreBonne), intermediates: [W.pem("CERTIFICATE", intermediaire)], accepted_policies: null, qualified: null }] };
    const stat2 = { signatures: 0 };
    const v2 = verifierJeton({ octets: r.jeton, imprintAttendue: imprint, ancres: ancres2, aGenTime: true, statistiques: stat2 });
    expect(v2.checks["T-7"], v2.raisons?.["T-7"]).to.equal("reussi");
    expect(v2.chemin.length, "chemin S, intermédiaire").to.equal(2);
    expect(Buffer.from(v2.chemin[1].octets).equals(Buffer.from(intermediaire)), "le chemin passe par le seizième certificat, non par l'un des quinze premiers").to.equal(true);
    for (const d of chaine) expect(Buffer.from(v2.chemin[1].octets).equals(Buffer.from(d))).to.equal(false);
    expect(Buffer.from(v2.autorite.certificat.octets).equals(Buffer.from(ancreBonne)), "autorité retenue : la neuvième ancre").to.equal(true);
    expect(stat2.signatures, "les quinze candidats placés avant le bon ont été essayés").to.be.at.least(16);
    expect(stat2.signatures).to.be.at.most(300);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : transport RFC 3161, délai total d'une requête (CT-5 EX-5.5)", function () {
  this.timeout(30000);
  it("une réponse au goutte-à-goutte (un octet toutes les 150 ms) est coupée au délai total : erreur delai, requête close en moins de 2 s pour delaiMs = 400", async function () {
    const serveur = http.createServer((req, rep) => {
      req.resume();
      rep.writeHead(200, { "Content-Type": "application/timestamp-reply" });
      let k = 0;
      const t = setInterval(() => { rep.write(Buffer.from([0x30])); if (++k >= 40) { clearInterval(t); rep.end(); } }, 150);
      rep.on("close", () => clearInterval(t));
    });
    await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${serveur.address().port}/`;
      const t0 = performance.now();
      let erreur = null;
      try {
        await transportHttps().envoyer({ url, octets: new Uint8Array(70), entetes: { "Content-Type": "application/timestamp-query" }, delaiMs: 400, auth: null, tls: null, role: "interne", serveurInterne: false });
      } catch (e) {
        erreur = e;
      }
      const duree = performance.now() - t0;
      expect(erreur, "la requête ne rend pas une réponse 200 après six secondes").to.be.instanceOf(ErreurTransport);
      expect(erreur.code).to.equal("delai");
      expect(duree, `durée ${Math.round(duree)} ms`).to.be.below(2000);
      // Même borne pour la capture d'une CRL (obtenir).
      const t1 = performance.now();
      let e2 = null;
      try {
        await transportHttps().obtenir(url, 400);
      } catch (e) {
        e2 = e;
      }
      expect(e2?.code).to.equal("delai");
      expect(performance.now() - t1).to.be.below(2000);
    } finally {
      serveur.closeAllConnections?.();
      await new Promise((r) => serveur.close(r));
    }
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : capture des CRL, adresses bornées (CT-5 EX-5.10 étape 10, AN-1)", function () {
  it("controlerUrlCrl : https ou http ; en production, adresses locales et privées refusées et liste d'hôtes du prestataire appliquée ; hors production, la boucle locale reste admise (serveur de CRL d'essai)", function () {
    const prod = { production: true };
    expect(controlerUrlCrl("http://127.0.0.1:8080/crl.pem", prod)).to.match(/locale|privée/);
    expect(controlerUrlCrl("http://10.1.2.3/crl.pem", prod)).to.match(/privée/);
    expect(controlerUrlCrl("http://172.16.0.9/crl.pem", prod)).to.match(/privée/);
    expect(controlerUrlCrl("http://192.168.1.1/crl.pem", prod)).to.match(/privée/);
    expect(controlerUrlCrl("http://169.254.169.254/latest/meta-data", prod)).to.match(/privée|locale/);
    expect(controlerUrlCrl("http://[::1]/crl.pem", prod)).to.match(/locale/);
    expect(controlerUrlCrl("http://[fd00::1]/crl.pem", prod)).to.match(/privée/);
    expect(controlerUrlCrl("http://localhost/crl.pem", prod)).to.match(/locale/);
    expect(controlerUrlCrl("ldap://crl.example/x", prod)).to.match(/schéma/);
    expect(controlerUrlCrl("http://u:p@crl.example/x", prod)).to.match(/identifiant/);
    expect(controlerUrlCrl("http://crl.example/x", prod)).to.equal(null);
    expect(controlerUrlCrl("http://crl.example/x", { production: true, hotesAdmis: ["crl.autre.example"] })).to.match(/hôte/);
    expect(controlerUrlCrl("http://crl.example/x", { production: true, hotesAdmis: ["crl.example"] })).to.equal(null);
    expect(controlerUrlCrl("http://127.0.0.1:8080/crl.pem", { production: false })).to.equal(null);
    expect(controlerUrlCrl("http://10.1.2.3/crl.pem", { production: false })).to.match(/privée/);
  });

  it("capturerCrls : au plus huit adresses distinctes par certificat (500 déclarées), chacune contrôlée avant la requête ; les adresses refusées sont consignées sans requête", async function () {
    // Certificat qui porte 500 points de distribution http://127.0.0.1:<port>/x (comme l'essai x509-crl du relecteur), plus un doublon.
    const K = ec();
    const n = nom("AC crl");
    const uris = [];
    for (let p = 1024; p < 1524; p++) uris.push(`http://127.0.0.1:${p}/x`);
    uris.push("http://127.0.0.1:1024/x");
    const dp = W.sequence(...uris.map((u) => W.sequence(W.explicite(0, W.explicite(0, W.implicite(6, W.ia5(u)))))));
    const c = cert(K, n, nom("unite crl"), ec(), [extensionX509("2.5.29.31", false, dp), extensionX509("2.5.29.37", true, W.sequence(W.oid("1.3.6.1.5.5.7.3.8")))]);
    const demandees = [];
    const transport = { obtenir: async (url) => { demandees.push(url); return { status: 404, corps: new Uint8Array(0) }; } };
    const horloge = { murale: () => T };
    const r = await capturerCrls({ chemin: [c], transport, horloge, politique: { production: false } });
    expect(r).to.have.length(1);
    expect(r[0].sources.length).to.equal(501);
    expect(demandees.length, "plafond de huit adresses par certificat, dédoublonnées").to.equal(8);
    expect(new Set(demandees).size).to.equal(8);
    expect(r[0].erreur).to.equal("http_404");
    // En production, les 500 adresses de la boucle locale sont toutes refusées sans requête.
    demandees.length = 0;
    const r2 = await capturerCrls({ chemin: [c], transport, horloge, politique: { production: true } });
    expect(demandees).to.deep.equal([]);
    expect(r2[0].crl).to.equal(null);
    expect(r2[0].erreur).to.match(/refusée|locale/);
    expect(r2[0].refusees).to.be.at.least(1);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : adresse d'un prestataire sans identifiant (CT-5 EX-4.8, AN-54) et prestataire interne jamais qualifié (EX-5.6 ; EX-4.9)", function () {
  it("une url à identifiant et mot de passe est refusée par AN-1 (motif du schéma ancrage-v0 depuis CT-5 0.10, la règle 4 restant en défense), par controlerUrl et par verifierFiche", function () {
    const doc = exempleCt5();
    expect(validerConfiguration(doc, { profil: "production", checkpointIntervalEnregistreur: doc.checkpoint_interval_s }).valide).to.equal(true);
    doc.rfc3161.providers[0].url = "https://compte-4242:MotDePasseTsa@horodatage-principal.example/tsa";
    const v = validerConfiguration(doc, { profil: "production", checkpointIntervalEnregistreur: doc.checkpoint_interval_s });
    expect(v.valide).to.equal(false);
    // CT-5 0.10 (EX-4.8, AN-54) : le motif de `url` du schéma exclut toute partie d'autorité à identifiant ; le
    // document est refusé dès le schéma (copie embarquée alignée, revue de sécurité de l'étape 8), sans écho du secret.
    expect(v.erreurs.map((e) => e.regle)).to.deep.equal(["schema"]);
    expect(v.erreurs[0].message).to.not.include("MotDePasseTsa");
    expect(() => controlerUrl(doc.rfc3161.providers[0].url, "principal")).to.throw(ErreurTransport, /identifiant/);
    const fiche = construireFiche(doc.rfc3161.providers[0]);
    const f = verifierFiche(fiche);
    expect(f.conforme).to.equal(false);
    expect(f.ecarts.some((e) => /identifiant/.test(e))).to.equal(true);
  });

  it("un prestataire de rôle interne déclaré qualified est refusé par AN-1 dans tout profil (règle 4) ; en production, headers_source null est refusé (CT-5 EX-6.6)", function () {
    const doc = exempleCt5();
    const interne = doc.rfc3161.providers.find((p) => p.role === "interne");
    const principal = doc.rfc3161.providers.find((p) => p.role === "principal");
    const d = structuredClone(doc);
    d.rfc3161.providers.find((p) => p.role === "interne").qualified = structuredClone(principal.qualified);
    for (const profil of ["developpement", "test", "production"]) {
      const v = validerConfiguration(d, { profil, checkpointIntervalEnregistreur: d.checkpoint_interval_s });
      expect(v.valide, profil).to.equal(false);
      expect(v.erreurs.map((e) => e.regle), profil).to.deep.equal(["4"]);
      expect(v.erreurs[0].message).to.include(interne.id);
    }
    const sansSource = structuredClone(doc);
    sansSource.opentimestamps.headers_source = null;
    expect(validerConfiguration(sansSource, { profil: "developpement", checkpointIntervalEnregistreur: doc.checkpoint_interval_s }).valide).to.equal(true);
    const prod = validerConfiguration(sansSource, { profil: "production", checkpointIntervalEnregistreur: doc.checkpoint_interval_s });
    expect(prod.valide).to.equal(false);
    expect(prod.erreurs.map((e) => [e.regle, /headers_source/.test(e.message)])).to.deep.equal([["4", true]]);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : serveur RFC 3161 interne, robustesse", function () {
  it("un TBSCertificate court lève une ErreurDer nommée, jamais une TypeError", function () {
    const K = ec();
    const bon = cert(K, nom("AC"), nom("AC"), K, extAc(K));
    const { ErreurDer, lireUnique, lireSuite } = W.__proto__ ? {} : {};
    void ErreurDer;
    void lireUnique;
    void lireSuite;
    // Certificate dont le TBS n'a que trois éléments : version, série, algorithme.
    const racine = W.sequence(W.sequence(W.explicite(0, W.entier(2n)), W.entier(5n), W.identifiantAlgorithme("1.2.840.10045.4.3.2")), W.identifiantAlgorithme("1.2.840.10045.4.3.2"), W.chaineBits(new Uint8Array(8)));
    expect(() => lireCertificatX509(bon)).to.not.throw();
    let erreur = null;
    try {
      lireCertificatX509(racine);
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.not.equal(null);
    expect(erreur.name).to.equal("ErreurDer");
    expect(erreur.message).to.match(/TBSCertificate/);
  });

  it("le frontal HTTP pose des délais d'en-têtes et de requête et une borne de connexions", async function () {
    const K = ec();
    const uCle = ec();
    const ac = cert(K, nom("AC frontal"), nom("AC frontal"), K, extAc(K));
    const unite = cert(K, nom("AC frontal"), nom("unite frontal"), uCle, [extensionX509("2.5.29.15", true, W.bitsNommes([0])), extensionX509("2.5.29.37", true, W.sequence(W.oid("1.3.6.1.5.5.7.3.8")))]);
    void ac;
    const autorite = new Autorite({ clePrivee: uCle.export({ type: "pkcs8", format: "pem" }), certificat: unite, politique: "1.3.6.1.4.1.99999.1.1", compteur: new CompteurMemoire() });
    const s = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port: 0 }, horloge: { murale: () => T } });
    try {
      expect(s.serveur.headersTimeout).to.be.at.most(15000);
      expect(s.serveur.requestTimeout).to.be.at.most(30000);
      expect(s.serveur.maxConnections).to.be.a("number").and.to.be.at.most(1024);
      expect(s.serveur.keepAliveTimeout).to.be.at.most(10000);
    } finally {
      await s.fermer();
    }
  });
});
