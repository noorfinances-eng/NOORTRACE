// Revue de sécurité interne de l'étape 8 (enregistreur) : secrets et
// canaux en clair, règles de production (cause structurante S-7), et arrêt
// du démon. Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ; chaque essai échoue
// sur le code d'avant la correction et passe après.
//
//   CT-2 EX-15.4   jeton statique vide ou court refusé au pas 4 ; ligne de jeton vide refusée sur les prises
//     le rapport de validation n'imprime jamais un secret écrit littéralement
//     route de modèle en http:// hors boucle locale : erreur en production
//    magasin de bail : sslmode verify-full exigé en production, etcd en https
//     mTLS des prises TCP : avertissement au démarrage (CT-2 EX-4.39)
//    pieces_days sans effet : avertissement
//     avertissement EX-18.7 au démarrage ; secrets résolus effacés à l'arrêt
//   EX-18.1  une connexion muette au port de santé ne retient pas l'arrêt
//   CT-2 EX-18.4   l'auxiliaire du verrou du bail ne reçoit pas l'environnement du démon

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import * as N from "@noortrace/noyau";
import * as E from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, configurationExemple, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const { Coeur, HorlogeReglable, validerConfiguration, resoudreSecrets, ligneRapport, ServeurConnecteurs, ServeurSdk, MagasinBailFichier } = E;
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

/** Configuration de production : l'exemple de 15.3 (environment production). */
function configurationProduction() {
  const c = configurationExemple();
  c.recorder.environment = "production";
  return c;
}

describe("enregistreur, revue (étape 8) : secrets, canaux en clair et règles de production (S-7), arrêt du démon", function () {
  this.timeout(60000);

  describe("CT-2 EX-15.4 : jetons statiques vides ou courts", function () {
    it("pas 4 : un jeton statique résolu à zéro octet ou à moins de 16 octets est une erreur secrète (pointeur, jamais la valeur) ; 16 octets passent", function () {
      const c = configurationExemple();
      c.mcp.http.static_tokens = [{ id: "vide", token: { env: "J_VIDE" } }, { id: "court", token: { env: "J_COURT" } }, { id: "juste", token: { env: "J_JUSTE" } }];
      c.model.static_tokens = [{ id: "modele-court", token: { env: "J_COURT2" } }];
      const env = { J_VIDE: "", J_COURT: "abcd", J_JUSTE: "0123456789abcdef", J_COURT2: "x".repeat(15) };
      for (const [k, v] of Object.entries(process.env)) if (/^NOORTRACE_|^VAULT_|^AWS_/.test(k)) env[k] = v;
      const r = resoudreSecrets(c, { env: { ...process.env, ...env } });
      const fautifs = r.erreurs.filter((e) => /static_tokens/.test(e.pointeur) && /octets/.test(e.regle));
      expect(fautifs.map((e) => e.pointeur).sort()).to.deep.equal(["/mcp/http/static_tokens/0/token", "/mcp/http/static_tokens/1/token", "/model/static_tokens/0/token"]);
      for (const e of fautifs) {
        expect(e.secret).to.equal(true);
        expect(e.regle).to.match(/16 octets/);
        expect(ligneRapport(e)).to.not.include("abcd");
      }
      expect(E.JETON_STATIQUE_MIN_OCTETS).to.equal(16);
    });

    it("prises TCP des connecteurs et du SDK : une ligne {\"noortrace_token\":\"\"} est refusée (auth_failed jeton) même quand un jeton résolu est vide", async function () {
      const lignes = [];
      const hote = { id: "hote-a", match: { static_token: "jeton-a" } };
      const frontal = {
        journal: { consigner: (...a) => lignes.push({ event: a[2], data: a[3] }), abonner: () => () => {} },
        monotone: () => Number(process.hrtime.bigint() / 1000000n),
        hotePour: (m) => (m.static_token === "jeton-a" ? hote : null),
        config: { limits: { line_max_bytes: 65536 } },
        ouvrirSession: () => ({}), fermerSession: () => {}, compterRecus: () => {},
        ouvrirConnexion: () => ({}), fermerConnexion: async () => {},
      };
      for (const Classe of [ServeurConnecteurs, ServeurSdk]) {
        const s = new Classe({ frontal, tcp: { listen: "127.0.0.1:0", client_auth: "jeton", tls: null }, jetons: new Map([["jeton-a", new Uint8Array(0)]]) });
        await s.ecouter();
        const { port } = s.adresseTcp();
        const rep = await new Promise((res) => {
          const c = net.createConnection(port, "127.0.0.1", () => c.write('{"noortrace_token":""}\n'));
          let t = "";
          c.on("data", (d) => { t += d; });
          c.on("close", () => res(t.trim()));
          setTimeout(() => c.destroy(), 1500);
        });
        expect(rep, Classe.name).to.not.include("acceptee");
        await s.fermer();
      }
      expect(lignes.filter((l) => l.event === "auth_failed" && l.data.reason === "jeton")).to.have.length(2);
      expect(lignes.some((l) => l.event === "host_connected" || l.event === "sdk_connected")).to.equal(false);
    });
  });

  describe("le rapport de validation n'imprime pas un secret écrit en clair", function () {
    it("une chaîne littérale à la place d'une référence de secret (relay_mac_key, jeton statique, secret de route) donne une erreur secrète au pas 2 ; aucune ligne du rapport ne porte la valeur", function () {
      const SECRET = "SECRET-LITTERAL-0123456789abcdef0123456789abcdef";
      const c = configurationExemple();
      c.storage.relay_mac_key = SECRET;
      c.mcp.http.static_tokens[0].token = SECRET + "-jeton";
      c.policy.model.routes[0].secret = SECRET + "-route";
      const r = validerConfiguration(enc(c));
      expect(r.pas).to.equal(2);
      const touchees = r.erreurs.filter((e) => ["/storage/relay_mac_key", "/mcp/http/static_tokens/0/token", "/policy/model/routes/0/secret"].includes(e.pointeur));
      expect(touchees.length).to.be.at.least(3);
      for (const e of touchees) expect(e.secret, e.pointeur).to.equal(true);
      const rapport = r.erreurs.map(ligneRapport).join("\n");
      expect(rapport).to.not.include(SECRET);
    });

    it("une erreur dont la valeur fautive est un objet (membre requis absent dans l'objet qui porte le jeton littéral) ne recopie pas l'objet : sorte et taille seulement", function () {
      const SECRET = "SECRET-LITTERAL-objet-0123456789abcdef";
      const c = configurationExemple();
      c.mcp.http.static_tokens[0] = { token: SECRET };
      const r = validerConfiguration(enc(c));
      expect(r.pas).to.equal(2);
      const rapport = r.erreurs.map(ligneRapport).join("\n");
      expect(rapport).to.not.include(SECRET);
      expect(rapport).to.match(/required : id/);
    });
  });

  describe("CT-2 EX-15.4, CT-2 §21 : règles de production et avertissements du pas 3", function () {
    it("CT-2 EX-15.4 : une route de modèle en http:// hors de la boucle locale est une erreur en production et un avertissement en développement ; un serveur d'outils en http:// est un avertissement", function () {
      const prod = configurationProduction();
      prod.policy.model.routes[0].upstream = "http://modele.interne.example:8080";
      const rp = validerConfiguration(enc(prod));
      const e = rp.erreurs.find((x) => x.pointeur === "/policy/model/routes/0/upstream");
      expect(e, JSON.stringify(rp.erreurs)).to.be.an("object");
      expect(e.regle).to.match(/https:\/\/ exigé/);
      const dev = configurationExemple();
      dev.recorder.environment = "developpement";
      dev.policy.model.routes[0].upstream = "http://modele.interne.example:8080";
      dev.policy.servers[Object.keys(dev.policy.servers)[0]].transport = { type: "http", url: "http://outils.interne.example:9000/mcp", headers: { Authorization: { env: "X_OUTIL" } }, oauth: null, tls: null };
      const rd = validerConfiguration(enc(dev));
      expect(rd.erreurs.filter((x) => /upstream|transport\/url/.test(x.pointeur))).to.deep.equal([]);
      expect(rd.avertissements.some((a) => a.pointeur === "/policy/model/routes/0/upstream" && /en clair/.test(a.regle))).to.equal(true);
      expect(rd.avertissements.some((a) => /transport\/url$/.test(a.pointeur) && /identifiants compris/.test(a.regle))).to.equal(true);
      // Boucle locale : rien.
      const local = configurationProduction();
      local.policy.model.routes[0].upstream = "http://127.0.0.1:8080";
      expect(validerConfiguration(enc(local)).erreurs.filter((x) => /upstream/.test(x.pointeur))).to.deep.equal([]);
    });

    it("CT-2 EX-15.4 : en production, un DSN PostgreSQL sans sslmode verify-full (ou verify-ca avec sslrootcert) est refusé au pas 4 sans que la valeur paraisse ; des points etcd en http:// sont refusés au pas 3", function () {
      const c = configurationProduction();
      c.lease = { store: { type: "postgresql", dsn: { env: "DSN_BAIL" }, table: "noortrace_lease" }, ttl_ms: 10000, renew_ms: 3000, acquire_wait_ms: 1000, fencing: "detachement" };
      const essai = (dsn) => resoudreSecrets(c, { env: { ...process.env, DSN_BAIL: dsn } }).erreurs.filter((e) => e.pointeur === "/lease/store/dsn");
      for (const mauvais of ["postgresql://noortrace:MOT-DE-PASSE@bail.interne.example/bail", "postgresql://noortrace:MOT-DE-PASSE@bail.interne.example/bail?sslmode=require", "postgresql://noortrace:MOT-DE-PASSE@bail.interne.example/bail?sslmode=verify-ca"]) {
        const e = essai(mauvais);
        expect(e, mauvais).to.have.length(1);
        expect(e[0].secret).to.equal(true);
        expect(e[0].regle).to.match(/verify-full/);
        expect(ligneRapport(e[0])).to.not.include("MOT-DE-PASSE");
      }
      expect(essai("postgresql://noortrace:MOT-DE-PASSE@bail.interne.example/bail?sslmode=verify-full")).to.deep.equal([]);
      expect(essai("postgresql://noortrace:MOT-DE-PASSE@bail.interne.example/bail?sslmode=verify-ca&sslrootcert=/run/secrets/ca.pem")).to.deep.equal([]);
      // Hors production, aucune règle.
      c.recorder.environment = "developpement";
      expect(essai("postgresql://noortrace:MOT-DE-PASSE@127.0.0.1/bail")).to.deep.equal([]);
      // etcd en production.
      const e2 = configurationProduction();
      e2.lease = { store: { type: "etcd", endpoints: ["https://etcd-1.interne.example:2379", "http://etcd-2.interne.example:2379"], prefix: "/noortrace/", tls: null }, ttl_ms: 10000, renew_ms: 3000, acquire_wait_ms: 1000, fencing: "detachement" };
      const r2 = validerConfiguration(enc(e2));
      expect(r2.erreurs.map((x) => x.pointeur)).to.include("/lease/store/endpoints/1");
      expect(r2.erreurs.map((x) => x.pointeur)).to.not.include("/lease/store/endpoints/0");
    });

    it("CT-2 EX-4.39, CT-2 §21 : avertissements pour une prise TCP en mTLS (autorité des clients tirée de cert_file) et pour pieces_days non nul (purge non codée)", function () {
      const c = configurationExemple();
      c.mcp.connector_tcp = { listen: "127.0.0.1:8611", client_auth: "mtls", tls: { cert_file: "/run/secrets/prise.pem", key_file: "/run/secrets/prise.key" } };
      c.storage.retention.pieces_days = 365;
      const r = validerConfiguration(enc(c));
      expect(r.erreurs, JSON.stringify(r.erreurs)).to.deep.equal([]);
      expect(r.avertissements.some((a) => a.pointeur === "/mcp/connector_tcp/tls/cert_file" && /nom commun/.test(a.regle))).to.equal(true);
      expect(r.avertissements.some((a) => a.pointeur === "/storage/retention/pieces_days" && /non codée/.test(a.regle))).to.equal(true);
    });
  });

  describe("CT-2 EX-18.7, EX-18.1, EX-18.4 : démarrage et arrêt du démon", function () {
    it("le démarrage consigne memory_protection_unavailable (EX-18.7 : mlockall et prctl non faits) ; l'arrêt efface tous les secrets résolus (tampons mis à zéro, table vidée)", async function () {
      const dir = repertoireTemporaire("noortrace-revue-secrets-");
      try {
        const { config } = configurationDev(dir);
        const v = validerConfiguration(enc(config));
        expect(v.erreurs).to.deep.equal([]);
        const secrets = secretsDev();
        secrets.set("/policy/model/routes/0/secret", new Uint8Array(Buffer.from("cle-du-fournisseur-0123456789abcdef")));
        const coeur = await Coeur.demarrer({ config: v.config, secrets, horloge: new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:20:00.000Z")), service: new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }) });
        const avert = coeur.journal.trouver("memory_protection_unavailable");
        expect(avert).to.have.length(1);
        expect(avert[0].level).to.equal("warning");
        expect(avert[0].data).to.include({ mlockall: false, dumpable_cleared: false });
        // Les tampons tenus par le démon (sa table, copie ou non de celle de l'appelant).
        const tampons = [...coeur.secrets.values()].filter((x) => x instanceof Uint8Array);
        expect(tampons.length).to.be.at.least(2);
        expect(tampons.some((x) => x.some((o) => o !== 0))).to.equal(true);
        await coeur.arreter();
        expect(coeur.secrets.size).to.equal(0);
        expect(tampons.every((x) => x.every((o) => o === 0)), "tampons écrasés de zéros").to.equal(true);
        expect(coeur.journal.trouver("shutdown")).to.have.length(1);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("CT-2 EX-18.1 : une connexion qui envoie la première ligne d'une requête au port de santé puis se tait ne retient pas l'arrêt : arreter() rend en moins de trois secondes, bail rendu et ligne shutdown écrite", async function () {
      const dir = repertoireTemporaire("noortrace-revue-sante-");
      try {
        const { config } = configurationDev(dir);
        const v = validerConfiguration(enc(config));
        const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:20:00.000Z")), service: new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }), supervision: true });
        const port = coeur.serveur.address().port;
        const sante = await new Promise((res, rej) => http.get({ host: "127.0.0.1", port, path: "/healthz" }, (r) => { r.resume(); res(r.statusCode); }).on("error", rej));
        expect(sante).to.equal(200);
        const muette = net.connect(port, "127.0.0.1");
        await new Promise((r) => muette.once("connect", r));
        muette.write("GET /healthz HTTP/1.1\r\n");
        await new Promise((r) => setTimeout(r, 200));
        const t0 = Date.now();
        const issue = await Promise.race([coeur.arreter().then(() => "arrete"), new Promise((r) => setTimeout(() => r("retenu"), 12000))]);
        expect(issue).to.equal("arrete");
        expect(Date.now() - t0).to.be.below(3000);
        expect(coeur.bailDetenu).to.equal(false);
        expect(coeur.journal.trouver("shutdown")).to.have.length(1);
        muette.destroy();
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("CT-2 EX-18.4 : l'auxiliaire flock(1) du verrou du bail ne reçoit que PATH, jamais les variables du démon (références { env } comprises)", async function () {
      const dir = repertoireTemporaire("noortrace-revue-bail-");
      process.env.NOORTRACE_REVUE_SECRET_TEMOIN = "valeur-secrete-du-demon-0123456789";
      try {
        const bail = new MagasinBailFichier(path.join(dir, "verrou"));
        await bail.acquerir();
        const pid = bail.auxiliaire?.pid;
        expect(pid, "auxiliaire lancé").to.be.a("number");
        const environ = fs.readFileSync(`/proc/${pid}/environ`, "latin1").split("\0").filter(Boolean);
        expect(environ.some((x) => x.startsWith("NOORTRACE_REVUE_SECRET_TEMOIN="))).to.equal(false);
        expect(environ.filter((x) => !x.startsWith("PATH=")), "aucune autre variable que PATH").to.deep.equal([]);
        await bail.liberer();
      } finally {
        delete process.env.NOORTRACE_REVUE_SECRET_TEMOIN;
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
