// Frontal HTTP du serveur RFC 3161 interne (lot E, AN-27, AN-28) et binaire
// `bin/noortrace-tsa-interne` : écoute en clair sur 127.0.0.1 seulement,
// `POST` avec `Content-Type: application/timestamp-query`, corps borné,
// réponse `application/timestamp-reply` (y compris pour un refus RFC 3161) ;
// TLS avec authentification du client par certificat (client sans
// certificat ou sous une autre AC refusé) ; journal injecté sans jeton ;
// `init`, `servir`, `crl`, codes de retour. Les certificats TLS d'essai sont
// produits par `openssl req` (boîte noire). L'écoute sur ::1 est en attente
// quand la machine n'a pas d'IPv6.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { spawn } from "node:child_process";
import { Autorite, CompteurMemoire, demarrerServeur, ErreurServeur, TYPE_REQUETE, TYPE_REPONSE, lancerTsaInterne, USAGE_TSA_INTERNE } from "@noortrace/ancrage/serveur-interne";
import { RACINE, AUTORITE_TEST, POLITIQUE_TEST, lireRequete, cheminRequete, repertoireTemporaire, horlogeFixe, openssl, verifierOpenssl, relireReponse, ecrire, enAttente, bin, BIN_TSA } from "./fixtures/ancrage-tsa-interne/outils.mjs";

const H = horlogeFixe("2026-11-03T13:53:02Z");

function autoriteTest(serie = 1n) {
  return new Autorite({ clePrivee: fs.readFileSync(AUTORITE_TEST.cleUnite), certificat: fs.readFileSync(AUTORITE_TEST.unite), politique: POLITIQUE_TEST, compteur: new CompteurMemoire(serie) });
}

/** Requête HTTP(S) brute : `{ status, entetes, corps }`. */
function requeteHttp(url, { methode = "POST", entetes = {}, corps = null, tls = {} } = {}) {
  return new Promise((resoudre, rejeter) => {
    const u = new URL(url);
    const module = u.protocol === "https:" ? https : http;
    const req = module.request(u, { method: methode, headers: entetes, ...tls }, (rep) => {
      const morceaux = [];
      rep.on("data", (m) => morceaux.push(m));
      rep.on("end", () => resoudre({ status: rep.statusCode, entetes: rep.headers, corps: Buffer.concat(morceaux) }));
    });
    req.on("error", rejeter);
    if (corps) req.write(corps);
    req.end();
  });
}

function journalMemoire() {
  const lignes = [];
  return { lignes, consigner: (niveau, evenement, data = {}) => lignes.push({ niveau, evenement, data }) };
}

const ipv6Disponible = () =>
  new Promise((resoudre) => {
    const s = net.createServer();
    s.once("error", () => resoudre(false));
    s.listen(0, "::1", () => s.close(() => resoudre(true)));
  });

describe("ancrage lot E — serveur HTTP en clair sur une adresse locale (AN-27)", function () {
  this.timeout(60000);
  let rep;
  let serveur;
  let journal;
  before(async function () {
    rep = repertoireTemporaire();
    journal = journalMemoire();
    serveur = await demarrerServeur({ autorite: autoriteTest(1001n), ecoute: { hote: "127.0.0.1", port: 0 }, horloge: H, journal });
  });
  after(async function () {
    await serveur?.fermer();
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("démarre sur 127.0.0.1 à un port libre, rend l'adresse et consigne tsa_demarrage avec l'écart d'horloge (AN-24), sans secret", function () {
    expect(serveur.adresse.hote).to.equal("127.0.0.1");
    expect(serveur.adresse.port).to.be.greaterThan(0);
    expect(serveur.adresse.url).to.equal(`http://127.0.0.1:${serveur.adresse.port}/`);
    expect(serveur.adresse.tls).to.equal(false);
    expect(journal.lignes[0]).to.deep.equal({ niveau: "info", evenement: "tsa_demarrage", data: { address: "127.0.0.1", port: serveur.adresse.port, tls: false, policy_oid: POLITIQUE_TEST, accuracy_s: 1, tsa_clock_offset_ms: 0 } });
  });

  it("POST application/timestamp-query → 200 application/timestamp-reply, réponse identique à la référence, vérifiée par openssl ; rien du jeton n'est journalisé (AN-28)", async function () {
    const avant = journal.lignes.length;
    const r = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE, "Content-Length": 69 }, corps: Buffer.from(lireRequete("requete-point-k2")) });
    expect(r.status).to.equal(200);
    expect(r.entetes["content-type"]).to.equal(TYPE_REPONSE);
    expect(Number(r.entetes["content-length"])).to.equal(r.corps.length);
    expect(r.corps.equals(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-5", "reponses", "granted-requete-point-k2.tsr")))).to.equal(true);
    const chemin = ecrire(rep, "http.tsr", r.corps);
    expect(verifierOpenssl({ requete: cheminRequete("requete-point-k2"), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
    expect(journal.lignes.length, "aucune ligne pour un jeton émis").to.equal(avant);
    // Content-Type avec paramètre : admis.
    const r2 = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": `${TYPE_REQUETE}; charset=binary` }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
    expect(r2.status).to.equal(200);
    expect(relireReponse(ecrire(rep, "http2.tsr", r2.corps)).serie).to.equal("0x03EA");
  });

  it("un refus RFC 3161 voyage en 200 application/timestamp-reply (badAlg, unacceptedPolicy, badDataFormat) et est consigné sans empreinte ni nonce", async function () {
    const avant = journal.lignes.length;
    const r = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from([0x30, 0x00]) });
    expect(r.status).to.equal(200);
    expect(r.entetes["content-type"]).to.equal(TYPE_REPONSE);
    const lu = relireReponse(ecrire(rep, "refus.tsr", r.corps));
    expect(lu.statut).to.equal("Rejected.");
    expect(lu.echec).to.equal("the data submitted has the wrong format");
    expect(journal.lignes.slice(avant)).to.deep.equal([{ niveau: "warning", evenement: "tsa_refus", data: { fail_info: "badDataFormat", reason: journal.lignes[avant].data.reason } }]);
    expect(JSON.stringify(journal.lignes)).to.not.include("6a8e035a");
  });

  it("GET → 405 avec Allow: POST ; autre Content-Type → 415 ; corps annoncé ou réel au-delà de la borne → 413 ; chemin exigé → 404 ailleurs", async function () {
    const g = await requeteHttp(serveur.adresse.url, { methode: "GET" });
    expect(g.status).to.equal(405);
    expect(g.entetes.allow).to.equal("POST");
    const t = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": "application/octet-stream" }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
    expect(t.status).to.equal(415);
    const sans = await requeteHttp(serveur.adresse.url, { corps: Buffer.from(lireRequete("point-k2-exemple")) });
    expect(sans.status).to.equal(415);
    const annonce = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE, "Content-Length": 5000 }, corps: Buffer.alloc(5000) });
    expect(annonce.status).to.equal(413);
    const reel = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE, "Transfer-Encoding": "chunked" }, corps: Buffer.alloc(4097) });
    expect(reel.status).to.equal(413);
    const borne = await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.alloc(4096) });
    expect(borne.status, "4096 octets admis, lus, refusés par la TSA").to.equal(200);
    expect(journal.lignes.filter((l) => l.evenement === "tsa_http_refus").map((l) => l.data.status)).to.include.members([405, 415, 413]);

    const avecChemin = await demarrerServeur({ autorite: autoriteTest(), ecoute: { hote: "localhost", port: 0 }, horloge: H, chemin: "/tsa" });
    try {
      expect((await requeteHttp(`${avecChemin.adresse.url}autre`, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) })).status).to.equal(404);
      expect((await requeteHttp(`${avecChemin.adresse.url}tsa`, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) })).status).to.equal(200);
    } finally {
      await avecChemin.fermer();
    }
  });

  it("timeNotAvailable quand l'écart injecté dépasse la précision : consigné avec tsa_clock_offset_ms (AN-24)", async function () {
    const j = journalMemoire();
    const s = await demarrerServeur({ autorite: autoriteTest(), ecoute: { hote: "127.0.0.1", port: 0 }, horloge: { murale: H.murale, ecartMs: () => 2500 }, journal: j });
    try {
      const r = await requeteHttp(s.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
      expect(r.status).to.equal(200);
      expect(relireReponse(ecrire(rep, "time.tsr", r.corps)).echec).to.equal("the TSA's time source is not available");
      expect(j.lignes[0].data.tsa_clock_offset_ms).to.equal(2500);
      expect(j.lignes[1]).to.deep.include({ niveau: "warning", evenement: "tsa_refus" });
      expect(j.lignes[1].data).to.deep.include({ fail_info: "timeNotAvailable", tsa_clock_offset_ms: 2500 });
    } finally {
      await s.fermer();
    }
  });

  it("refuse d'écouter en clair ailleurs que sur 127.0.0.1, ::1 ou localhost (192.0.2.1, 0.0.0.0, nom d'hôte) ; options mal formées refusées", async function () {
    for (const hote of ["192.0.2.1", "0.0.0.0", "198.51.100.7", "2001:db8::1", "tsa.example", "", undefined]) {
      let erreur = null;
      try {
        await demarrerServeur({ autorite: autoriteTest(), ecoute: { hote, port: 0 }, horloge: H });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, String(hote)).to.be.instanceOf(ErreurServeur);
      expect(erreur.message).to.include("AN-27");
    }
    for (const o of [{ ecoute: null }, { ecoute: { hote: "127.0.0.1", port: 70000 } }, { ecoute: { hote: "127.0.0.1", port: 0 }, tailleMaxCorps: 10 }, { horloge: {} }, { autorite: null }]) {
      let erreur = null;
      try {
        await demarrerServeur({ autorite: autoriteTest(), ecoute: { hote: "127.0.0.1", port: 0 }, horloge: H, ...o });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, JSON.stringify(o)).to.be.an("error");
    }
    // TLS sans AC de clients : refusé (AN-27 : authentification du client obligatoire).
    let e2 = null;
    try {
      await demarrerServeur({ autorite: autoriteTest(), ecoute: { tls: { cle: "x", certificat: "y", port: 0 } }, horloge: H });
    } catch (e) {
      e2 = e;
    }
    expect(e2).to.be.instanceOf(ErreurServeur);
  });

  it("écoute sur ::1 (adresse locale admise par AN-27)", async function () {
    if (!(await ipv6Disponible())) return enAttente(this, "la machine n'offre pas d'IPv6 (::1 injoignable)");
    const s = await demarrerServeur({ autorite: autoriteTest(), ecoute: { hote: "::1", port: 0 }, horloge: H });
    try {
      expect(s.adresse.url).to.match(/^http:\/\/\[::1\]:\d+\/$/);
      const r = await requeteHttp(s.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
      expect(r.status).to.equal(200);
    } finally {
      await s.fermer();
    }
  });
});

describe("ancrage lot E — serveur TLS avec authentification du client (AN-27)", function () {
  this.timeout(120000);
  let rep;
  let pki;
  let serveur;
  let journal;

  /** AC, serveur et deux clients (l'un sous l'AC des clients, l'autre sous une AC étrangère), par openssl req. */
  function fabriquerPki(dir) {
    const f = (n) => path.join(dir, n);
    const req = (nom, sujet, ext, ca) => {
      openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f(`${nom}.cle.pem`), "-out", f(`${nom}.pem`), "-subj", sujet, "-days", "2", "-addext", ext, ...(ca ? ["-CA", f(`${ca}.pem`), "-CAkey", f(`${ca}.cle.pem`)] : [])]);
    };
    req("ac-clients", "/CN=AC clients TSA interne", "basicConstraints=critical,CA:TRUE");
    req("ac-etrangere", "/CN=AC etrangere", "basicConstraints=critical,CA:TRUE");
    req("serveur", "/CN=127.0.0.1", "subjectAltName=IP:127.0.0.1", "ac-clients");
    req("client", "/CN=enregistreur", "extendedKeyUsage=clientAuth", "ac-clients");
    req("intrus", "/CN=intrus", "extendedKeyUsage=clientAuth", "ac-etrangere");
    return { acClients: f("ac-clients.pem"), serveurCle: f("serveur.cle.pem"), serveurCert: f("serveur.pem"), clientCle: f("client.cle.pem"), clientCert: f("client.pem"), intrusCle: f("intrus.cle.pem"), intrusCert: f("intrus.pem") };
  }

  before(async function () {
    rep = repertoireTemporaire();
    pki = fabriquerPki(rep);
    journal = journalMemoire();
    serveur = await demarrerServeur({
      autorite: autoriteTest(1001n),
      ecoute: { tls: { cle: fs.readFileSync(pki.serveurCle), certificat: fs.readFileSync(pki.serveurCert), acClients: fs.readFileSync(pki.acClients), hote: "127.0.0.1", port: 0 } },
      horloge: H,
      journal,
    });
  });
  after(async function () {
    await serveur?.fermer();
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("un client authentifié par un certificat de l'AC des clients obtient une réponse vérifiée par openssl", async function () {
    expect(serveur.adresse.tls).to.equal(true);
    expect(serveur.adresse.url).to.match(/^https:\/\/127\.0\.0\.1:\d+\/$/);
    const r = await requeteHttp(serveur.adresse.url, {
      entetes: { "Content-Type": TYPE_REQUETE },
      corps: Buffer.from(lireRequete("requete-point-k2")),
      tls: { ca: fs.readFileSync(pki.acClients), key: fs.readFileSync(pki.clientCle), cert: fs.readFileSync(pki.clientCert) },
    });
    expect(r.status).to.equal(200);
    expect(r.entetes["content-type"]).to.equal(TYPE_REPONSE);
    const chemin = ecrire(rep, "tls.tsr", r.corps);
    expect(verifierOpenssl({ requete: cheminRequete("requete-point-k2"), reponse: chemin, ac: AUTORITE_TEST.ac, unite: AUTORITE_TEST.unite }).stdout).to.include("Verification: OK");
  });

  it("une tentative anonyme (sans certificat client) est refusée à la poignée de main, et consignée", async function () {
    let erreur = null;
    try {
      await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")), tls: { ca: fs.readFileSync(pki.acClients) } });
    } catch (e) {
      erreur = e;
    }
    expect(erreur, "refus attendu").to.be.an("error");
    expect(journal.lignes.some((l) => l.evenement === "tsa_tls_refus")).to.equal(true);
  });

  it("un certificat client d'une AC étrangère est refusé", async function () {
    let erreur = null;
    try {
      await requeteHttp(serveur.adresse.url, {
        entetes: { "Content-Type": TYPE_REQUETE },
        corps: Buffer.from(lireRequete("point-k2-exemple")),
        tls: { ca: fs.readFileSync(pki.acClients), key: fs.readFileSync(pki.intrusCle), cert: fs.readFileSync(pki.intrusCert) },
      });
    } catch (e) {
      erreur = e;
    }
    expect(erreur, "refus attendu").to.be.an("error");
  });

  it("le serveur TLS n'accepte pas TLS 1.1 ni une connexion en clair", async function () {
    let erreur = null;
    try {
      await requeteHttp(serveur.adresse.url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")), tls: { ca: fs.readFileSync(pki.acClients), key: fs.readFileSync(pki.clientCle), cert: fs.readFileSync(pki.clientCert), maxVersion: "TLSv1.1", minVersion: "TLSv1.1" } });
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.be.an("error");
    let e2 = null;
    try {
      await requeteHttp(serveur.adresse.url.replace("https:", "http:"), { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
    } catch (e) {
      e2 = e;
    }
    expect(e2).to.be.an("error");
  });
});

describe("ancrage lot E — binaire noortrace-tsa-interne (init, servir, crl)", function () {
  this.timeout(120000);
  let rep;
  before(function () {
    rep = repertoireTemporaire();
  });
  after(function () {
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("sans commande : usage et code 2 ; aide : code 0 ; commande inconnue : code 2 ; init sans option requise : code 2", function () {
    const sans = bin([]);
    expect(sans.status).to.equal(2);
    expect(sans.stdout).to.include("noortrace-tsa-interne");
    expect(bin(["aide"]).status).to.equal(0);
    expect(bin(["aide"]).stdout).to.equal(USAGE_TSA_INTERNE);
    const inconnue = bin(["danser"]);
    expect(inconnue.status).to.equal(2);
    expect(inconnue.stderr).to.include("commande inconnue");
    const manque = bin(["init", "--repertoire", path.join(rep, "x")]);
    expect(manque.status).to.equal(2);
    expect(manque.stderr).to.include("--politique requis");
    expect(bin(["init", "--repertoire", path.join(rep, "x"), "--politique", "1.2.3", "--crl-url", "http://127.0.0.1/crl", "--algorithme", "rsa-2048"]).status).to.equal(2);
    expect(bin(["init", "--repertoire", path.join(rep, "x"), "--politique", "1.2.3", "--crl-url", "http://127.0.0.1/crl", "--validite-jours", "1096"]).status).to.equal(1);
    expect(fs.existsSync(path.join(rep, "x", "ac.cle.pem"))).to.equal(false);
  });

  it("init (p-256) écrit l'autorité, crl la republie (numéro 2), init à nouveau refuse d'écraser (code 1)", function () {
    const dir = path.join(rep, "autorite");
    const i = bin(["init", "--repertoire", dir, "--algorithme", "p-256", "--politique", "1.3.6.1.4.1.99999.3.1", "--crl-url", "http://127.0.0.1:8080/crl.pem", "--validite-jours", "365"]);
    expect(i.status, i.stderr).to.equal(0);
    expect(i.stdout).to.include("autorité créée");
    expect(i.stdout).to.include("politique : 1.3.6.1.4.1.99999.3.1");
    expect(openssl(["x509", "-in", path.join(dir, "unite.pem"), "-noout", "-text"])).to.match(/Extended Key Usage: critical\s*\n\s*Time Stamping/);
    const c = bin(["crl", "--repertoire", dir]);
    expect(c.status, c.stderr).to.equal(0);
    expect(c.stdout).to.include("CRL numéro 2 publiée");
    expect(openssl(["crl", "-in", path.join(dir, "crl.pem"), "-noout", "-crlnumber"])).to.equal("crlNumber=0x02\n");
    const encore = bin(["init", "--repertoire", dir, "--politique", "1.2.3", "--crl-url", "http://127.0.0.1/crl"]);
    expect(encore.status).to.equal(1);
    expect(encore.stderr).to.include("existe déjà");
  });

  it("servir --repertoire : écoute 127.0.0.1, imprime l'URL, répond (openssl ts -verify OK), journal NDJSON sur la sortie d'erreur sans jeton, arrêt propre sur SIGTERM et verrou rendu", async function () {
    const dir = path.join(rep, "autorite");
    const p = spawn(process.execPath, [BIN_TSA, "servir", "--repertoire", dir, "--port", "0", "--ecart-ms", "120"], { stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    p.stderr.on("data", (m) => (err += m));
    const url = await new Promise((resoudre, rejeter) => {
      let out = "";
      p.stdout.on("data", (m) => {
        out += m;
        const l = out.split("\n")[0];
        if (l.startsWith("http://")) resoudre(l.trim());
      });
      p.once("exit", (code) => rejeter(new Error(`arrêt prématuré ${code}: ${err}`)));
    });
    expect(url).to.match(/^http:\/\/127\.0\.0\.1:\d+\/$/);
    expect(fs.existsSync(path.join(dir, "compteur", "serie.verrou"))).to.equal(true);
    const r = await requeteHttp(url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("point-k2-exemple")) });
    expect(r.status).to.equal(200);
    const chemin = ecrire(rep, "bin.tsr", r.corps);
    const v = verifierOpenssl({ requete: cheminRequete("point-k2-exemple"), reponse: chemin, ac: path.join(dir, "ac.pem"), unite: path.join(dir, "unite.pem") });
    expect(v.stdout, v.stderr).to.include("Verification: OK");
    expect(relireReponse(chemin).politique).to.equal("1.3.6.1.4.1.99999.3.1");
    const refus = await requeteHttp(url, { methode: "GET" });
    expect(refus.status).to.equal(405);
    p.kill("SIGTERM");
    const code = await new Promise((resoudre) => p.once("exit", resoudre));
    expect(code).to.equal(0);
    const lignes = err.trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.map((l) => l.event)).to.deep.equal(["tsa_demarrage", "tsa_http_refus", "tsa_arret"]);
    expect(lignes[0]).to.include({ level: "info", component: "tsa_interne" });
    expect(lignes[0].data).to.include({ tsa_clock_offset_ms: 120, policy_oid: "1.3.6.1.4.1.99999.3.1" });
    expect(err).to.not.include("6a8e035a");
    expect(fs.existsSync(path.join(dir, "compteur", "serie.verrou")), "verrou rendu").to.equal(false);
    expect(fs.readFileSync(path.join(dir, "compteur", "serie"), "utf8")).to.equal("1\n");
  });

  it("servir --cle/--certificat avec l'autorité de test de CT-6 et un compteur à part ; un second serveur sur le même compteur est refusé (AN-26) ; écoute hors adresse locale refusée (AN-27)", async function () {
    const compteur = path.join(rep, "compteur-test");
    const lancerServir = (args) => {
      const p = spawn(process.execPath, [BIN_TSA, "servir", "--cle", AUTORITE_TEST.cleUnite, "--certificat", AUTORITE_TEST.unite, "--politique", POLITIQUE_TEST, "--compteur", compteur, "--port", "0", ...args], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (m) => (out += m));
      p.stderr.on("data", (m) => (err += m));
      // `fin` est créée à la naissance du processus : un `once("exit")` posé après coup manquerait une sortie déjà survenue.
      const fin = new Promise((resoudre) => p.once("exit", resoudre));
      const url = new Promise((resoudre) => {
        p.stdout.on("data", () => {
          const l = out.split("\n")[0];
          if (l.startsWith("http")) resoudre(l.trim());
        });
        fin.then(() => resoudre(null));
      });
      return { p, url, fin, sortie: () => ({ out, err }) };
    };
    const premier = lancerServir([]);
    const url = await premier.url;
    expect(url, premier.sortie().err).to.match(/^http:\/\/127\.0\.0\.1:\d+\/$/);
    const r = await requeteHttp(url, { entetes: { "Content-Type": TYPE_REQUETE }, corps: Buffer.from(lireRequete("requete-point-k2")) });
    expect(relireReponse(ecrire(rep, "bin2.tsr", r.corps)).serie).to.equal("0x01");

    const second = lancerServir([]);
    expect(await second.url).to.equal(null);
    expect(await second.fin).to.equal(1);
    expect(second.sortie().err).to.include("verrou tenu");
    expect(second.sortie().err, "erreur rattrapée, pas une exception non gérée").to.not.include("at Compteur.ouvrir");

    premier.p.kill("SIGTERM");
    expect(await premier.fin).to.equal(0);

    const distant = lancerServir(["--hote", "192.0.2.1"]);
    expect(await distant.url).to.equal(null);
    expect(await distant.fin).to.equal(1);
    expect(distant.sortie().err).to.include("AN-27");
    expect(distant.sortie().err).to.match(/^erreur : /m);
    expect(fs.existsSync(path.join(compteur, "serie.verrou")), "verrou rendu après le refus").to.equal(false);
  });

  it("lancer() avec flux et horloge injectés : aide sur la sortie, code 0", async function () {
    let out = "";
    const code = await lancerTsaInterne({ argv: ["aide"], horloge: H, aleatoire: () => new Uint8Array(16), sortie: { write: (s) => (out += s) }, erreur: { write: () => {} } });
    expect(code).to.equal(0);
    expect(out).to.equal(USAGE_TSA_INTERNE);
  });
});
