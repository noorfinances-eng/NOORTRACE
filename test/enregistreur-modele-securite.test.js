// Passerelle du frontal modèle : quotas de la connexion d'hôte (EX-4.47 ;
// 14.2, ligne « Mémoire », colonne M), jeton OAuth d'une connexion d'hôte
// (EX-5.8 point 2) et TLS de `model.tls` (EX-5.2), en réussite et en échec.
// Certificats et clés générés à l'exécution (openssl, node:crypto), sans
// valeur.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import https from "node:https";
import tls from "node:tls";
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { PasserelleModele, lireEvenements, controleModele, uriPasserelle } from "@noortrace/enregistreur";
import { BIN_NOORTRACE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule, evenementsFlux } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import { genererCertificats, opensslDisponible } from "./fixtures/enregistreur-modele/certificats.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const MSG = { model: "modele-securite", max_tokens: 16, system: "Agent.", messages: [{ role: "user", content: "Statut ?" }] };
const BASE = { "content-type": "application/json", "x-noortrace-token": JETON_MODELE };
const b64url = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

async function portLibre() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
}

describe("enregistreur, frontal modèle : quotas, jeton OAuth, TLS de la passerelle", function () {
  this.timeout(60000);
  let dir;
  let fournisseur;
  let coeur;
  let config;
  let secrets;
  const ouvertes = [];
  let obs = [];

  async function ouvrir(sur = () => {}, o = {}) {
    const c = structuredClone(config);
    sur(c);
    const p = new PasserelleModele({ coeur, secrets, config: c, chargerJwks: o.chargerJwks, observateur: { echange: (x) => obs.push(x) } });
    await p.ecouter();
    ouvertes.push(p);
    return p;
  }

  async function envoyer(p, o = {}) {
    obs = [];
    const r = await fetch(`http://127.0.0.1:${p.adresse().port}${o.chemin ?? "/v1/messages"}`, { method: "POST", headers: o.entetes ?? BASE, body: o.corps ?? JSON.stringify(MSG) });
    const texte = await r.text();
    if (r.status < 400 || o.attendre) for (let i = 0; i < 200 && !obs.length; i++) await pause(10);
    return { statut: r.status, texte, echange: obs[0] ?? null };
  }

  const ops = () => fs.readFileSync(config.supervision.ops_log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const derniere = (ev) => ops().filter((l) => l.event === ev).pop();

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-securite-");
    fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
    const c = configurationModele(dir, fournisseur.url);
    ({ config, secrets } = valider(c.config, c.env));
    ({ coeur } = await demarrerCoeur(config, secrets));
  });

  after(async function () {
    for (const p of ouvertes) await p.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  describe("EX-4.47 : quotas de la connexion d'hôte sur la passerelle", function () {
    const quota = (q) => (c) => Object.assign(c.model.hosts[0].quota, q);
    const bloque = '{"type":"error","error":{"type":"noortrace_degrade","message":"noortrace: echange bloque, enregistreur en mode degrade"}}';

    it("requêtes en cours (max_concurrent) : la seconde, pendant un flux, est bloquée (503) ; l'échange suivant passe", async function () {
      const p = await ouvrir(quota({ max_concurrent: 1 }));
      fournisseur.prochaine({ statut: 200, entetes: { "content-type": "text/event-stream" }, morceaux: evenementsFlux("anthropic-messages", MSG, 1), pauseMs: 80 });
      const lent = fetch(`http://127.0.0.1:${p.adresse().port}/v1/messages`, { method: "POST", headers: BASE, body: JSON.stringify({ ...MSG, stream: true }) }).then((r) => r.text());
      await pause(100);
      const b = await envoyer(p);
      expect([b.statut, b.texte]).to.deep.equal([503, bloque]);
      expect(derniere("call_blocked").data).to.deep.equal({ code: 503, reason: "quota", class: "modele", limit_requests: 1 });
      await lent;
      await pause(200);
      expect((await envoyer(p)).statut).to.equal(200);
    });

    it("octets reçus par minute, requêtes refusées comprises ; octets de pièces ; temps de capture : bloquants une fois atteints", async function () {
      const gros = JSON.stringify({ ...MSG, messages: [{ role: "user", content: "x".repeat(1500) }] });
      const a = await ouvrir(quota({ received_bytes_per_minute: 2500 }));
      expect((await envoyer(a, { corps: gros })).statut).to.equal(200);
      expect((await envoyer(a, { corps: gros })).statut).to.equal(503);
      expect(derniere("call_blocked").data).to.include({ reason: "quota", limit_bytes: 2500 });
      const b = await ouvrir(quota({ piece_bytes_per_minute: 1200 }));
      expect((await envoyer(b, { corps: gros })).statut).to.equal(200);
      expect((await envoyer(b)).statut).to.equal(503);
      expect(derniere("call_blocked").data).to.include({ limit_bytes: 1200 });
      const c = await ouvrir(quota({ redaction_ms_per_minute: 1 }));
      const enorme = JSON.stringify({ ...MSG, messages: Array.from({ length: 400 }, (_, k) => ({ role: "user", content: `ecrire a agent${k}@exemple.ch, ${"y".repeat(400)}` })) });
      expect((await envoyer(c, { corps: enorme })).statut).to.equal(200);
      expect((await envoyer(c)).statut).to.equal(503);
      expect(derniere("call_blocked").data).to.include({ limit_ms: 1 });
      expect(coeur.metriques.valeur("noortrace_calls_blocked_total", { code: "503", reason: "quota", class: "modele" })).to.be.greaterThan(3);
    });

    it("mode observation (EX-14.16) : un quota atteint ne bloque pas, observation_would_block est consigné", async function () {
      const p = await ouvrir((c) => {
        quota({ received_bytes_per_minute: 1024 })(c);
        c.policy.approval.mode = "observation";
      });
      const gros = JSON.stringify({ ...MSG, messages: [{ role: "user", content: "x".repeat(1500) }] });
      expect((await envoyer(p, { corps: gros })).statut).to.equal(200);
      expect(derniere("observation_would_block").data).to.include({ would: "quota", reason: "quota", class: "modele" });
    });
  });

  describe("EX-5.8 point 2 : jeton OAuth d'audience l'URI de la passerelle", function () {
    let cles;
    let port;
    const jwks = () => Promise.resolve({ keys: [{ ...cles.publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256", use: "sig" }] });
    const jeton = (charge, o = {}) => {
      const tete = b64url({ alg: "ES256", kid: o.kid ?? "k1", typ: "JWT" });
      const corps = b64url({ iss: "https://as.exemple.test", aud: `http://127.0.0.1:${port}`, sub: "agent-oauth-sub", scope: "modele lecture", exp: Math.floor(Date.now() / 1000) + 600, ...charge });
      const sig = sign("sha256", Buffer.from(`${tete}.${corps}`), { key: (o.cle ?? cles).privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
      return `${tete}.${corps}.${sig}`;
    };
    let p;

    before(async function () {
      cles = generateKeyPairSync("ec", { namedCurve: "P-256" });
      port = await portLibre();
      p = await ouvrir(
        (c) => {
          c.model.listen = `127.0.0.1:${port}`;
          c.mcp.http = { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, static_tokens: [], oauth: { resource: "https://mcp.exemple.test/mcp", authorization_servers: ["https://as.exemple.test"], jwks_uri: "https://as.exemple.test/jwks", required_scopes: ["modele"] } };
          c.model.hosts.push({ ...c.model.hosts[0], id: "agent-oauth", match: { oauth_subject: "agent-oauth-sub" }, launched_by: "${oauth_subject}", host_group: "agent-oauth" });
        },
        { chargerJwks: jwks },
      );
    });

    it("jeton valide (X-Noortrace-Token, ou Authorization en mode propre) : connexion d'hôte du sujet, launched_by = sujet du jeton", async function () {
      expect(uriPasserelle(p.config)).to.equal(`http://127.0.0.1:${port}`);
      const a = await envoyer(p, { entetes: { "content-type": "application/json", "x-noortrace-token": jeton({}) } });
      expect(a.statut).to.equal(200);
      expect(a.echange.evenement.delegation.launched_by).to.equal("agent-oauth-sub");
      const b = await envoyer(p, { entetes: { "content-type": "application/json", authorization: `Bearer ${jeton({})}` }, chemin: "/v1/responses", corps: JSON.stringify({ model: "m", input: "x" }) });
      expect(b.statut).to.equal(200);
      expect(fournisseur.requetes.at(-1).entetes.authorization).to.equal("Bearer cle-fournisseur-fictive-de-test");
    });

    it("refusés (401, aucun relais) : autre audience, expiré, autre émetteur, portée insuffisante, signature d'une autre clé, sujet sans entrée", async function () {
      const avant = fournisseur.requetes.length;
      const autre = generateKeyPairSync("ec", { namedCurve: "P-256" });
      for (const [quoi, j] of [
        ["audience", jeton({ aud: "https://mcp.exemple.test/mcp" })],
        ["expire", jeton({ exp: Math.floor(Date.now() / 1000) - 10 })],
        ["emetteur", jeton({ iss: "https://autre.exemple.test" })],
        ["portee", jeton({ scope: "lecture" })],
        ["signature", jeton({}, { cle: autre })],
        ["sujet", jeton({ sub: "inconnu" })],
      ]) {
        const r = await envoyer(p, { entetes: { "content-type": "application/json", "x-noortrace-token": j } });
        expect(r.statut, quoi).to.equal(401);
      }
      expect(fournisseur.requetes.length).to.equal(avant);
      expect(ops().filter((l) => l.event === "auth_failed").map((l) => l.data.reason)).to.include.members(["oauth_audience", "oauth_expire", "oauth_emetteur", "oauth_portee", "oauth_signature"]);
    });

    it("configuration : oauth_subject sans mcp.http.oauth, ou hors du mode passerelle, est refusée ; le démon ne démarre pas (code 2)", async function () {
      const c = structuredClone(config);
      c.model.hosts.push({ ...c.model.hosts[0], id: "agent-oauth", match: { oauth_subject: "s" }, launched_by: "${oauth_subject}" });
      expect(controleModele(c).erreurs.map((e) => e.regle)).to.include("un jeton OAuth de la passerelle exige mcp.http.oauth (serveur d'autorisation, JWKS, portées ; EX-5.8)");
      c.model.mode = "icap";
      c.model.icap = { listen: "127.0.0.1:0", tls_listen: null, client_ca: null, allowed_sources: [], client_address_header: null };
      expect(controleModele(c).erreurs.map((e) => e.regle)).to.include("oauth_subject seulement en mode passerelle (EX-5.8)");
      const d = repertoireTemporaire("noortrace-modele-oauth-");
      const x = configurationModele(d, fournisseur.url);
      x.config.model.hosts.push({ ...x.config.model.hosts[0], id: "agent-oauth", match: { oauth_subject: "s" }, launched_by: "${oauth_subject}" });
      const chemin = path.join(d, "c.json");
      fs.writeFileSync(chemin, JSON.stringify(x.config));
      const r = spawnSync(process.execPath, [BIN_NOORTRACE, "--config", chemin], { encoding: "utf8", env: { ...process.env, ...x.env }, timeout: 30000 });
      expect(r.status).to.equal(2);
      expect(r.stderr).to.match(/^config_invalid : \/model\/hosts\/1\/match\/oauth_subject : un jeton OAuth de la passerelle exige mcp\.http\.oauth/m);
      const v = spawnSync(process.execPath, [BIN_NOORTRACE, "validate-config", chemin], { encoding: "utf8", env: { ...process.env, ...x.env }, timeout: 30000 });
      expect(v.status).to.equal(2);
    });
  });

  describe("TLS de model.tls (EX-5.2 : TLS par le client)", function () {
    let certs;
    before(function () {
      if (!opensslDisponible()) this.skip();
      certs = genererCertificats(path.join(dir, "certs"));
    });

    function requete(port, o) {
      return new Promise((res) => {
        const q = https.request({ host: "127.0.0.1", port, path: "/v1/messages", method: "POST", headers: BASE, ...o }, (r) => {
          const protocole = r.socket?.getProtocol?.() ?? null;
          r.resume();
          r.on("end", () => res({ statut: r.statusCode, protocole }));
        });
        q.on("error", (e) => res({ erreur: e.code ?? e.message }));
        q.end(JSON.stringify(MSG));
      });
    }

    it("poignée de main réussie avec l'autorité du client : échange scellé ; protocole TLS 1.2 ou plus", async function () {
      const p = await ouvrir((c) => {
        c.model.tls = { cert_file: certs.serveurCert, key_file: certs.serveurCle };
      });
      obs = [];
      const r = await requete(p.adresse().port, { ca: fs.readFileSync(certs.ca) });
      expect(r.statut).to.equal(200);
      expect(["TLSv1.2", "TLSv1.3"]).to.include(r.protocole);
      for (let i = 0; i < 100 && !obs.length; i++) await pause(10);
      expect(obs[0].evenement.execution.tool).to.equal("noortrace.modele.echange");
    });

    it("certificat refusé par le client : autorité inconnue, ou nom qui ne correspond pas ; version antérieure à TLS 1.2 refusée", async function () {
      const p = await ouvrir((c) => {
        c.model.tls = { cert_file: certs.serveurCert, key_file: certs.serveurCle };
      });
      const echanges = async () => (await lireEvenements(coeur.repertoire)).filter((e) => e.execution?.tool === "noortrace.modele.echange").length;
      await pause(100);
      const n = await echanges();
      expect((await requete(p.adresse().port, {})).erreur).to.match(/UNABLE_TO_VERIFY|SELF_SIGNED|unable to verify/i);
      expect((await requete(p.adresse().port, { ca: fs.readFileSync(certs.etrangeCa) })).erreur).to.match(/UNABLE_TO_VERIFY|SELF_SIGNED|unable to verify/i);
      const q = await ouvrir((c) => {
        c.model.tls = { cert_file: certs.autreServeurCert, key_file: certs.autreServeurCle };
      });
      expect((await requete(q.adresse().port, { ca: fs.readFileSync(certs.ca) })).erreur).to.equal("ERR_TLS_CERT_ALTNAME_INVALID");
      // Client limité à TLS 1.1 (openssl s_client) : un serveur témoin qui
      // l'admet l'accepte (le client sait donc le parler) ; la passerelle le refuse.
      const ancien = (port) =>
        new Promise((res) => {
          const c = spawn("openssl", ["s_client", "-connect", `127.0.0.1:${port}`, "-tls1_1", "-cipher", "ALL:@SECLEVEL=0"], { stdio: ["pipe", "pipe", "pipe"] });
          let sortie = "";
          c.stdout.on("data", (z) => (sortie += z));
          c.stderr.on("data", (z) => (sortie += z));
          c.stdin.end();
          const garde = setTimeout(() => c.kill("SIGKILL"), 10000);
          c.on("close", () => {
            clearTimeout(garde);
            // s_client écrit « Protocol : TLSv1.1 » même après un échec : la
            // poignée de main n'a réussi que si une suite a été négociée.
            const reussie = /Cipher is (?!\(NONE\))/.test(sortie) && /Protocol\s*:\s*TLSv1\.1/.test(sortie);
            res(reussie ? "TLSv1.1" : sortie);
          });
        });
      const temoin = tls.createServer({ cert: fs.readFileSync(certs.serveurCert), key: fs.readFileSync(certs.serveurCle), minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" }, (x) => x.end());
      await new Promise((r) => temoin.listen(0, "127.0.0.1", r));
      const versionTemoin = await ancien(temoin.address().port);
      temoin.close();
      expect(versionTemoin).to.equal("TLSv1.1");
      const refus = await ancien(p.adresse().port);
      expect(refus).to.not.equal("TLSv1.1");
      expect(refus).to.match(/alert|unsupported protocol|no protocols available|errno/i);
      await pause(100);
      expect(await echanges()).to.equal(n);
    });

    it("certificat illisible : le démon ne démarre pas (frontal_modele, code 2)", async function () {
      const d = repertoireTemporaire("noortrace-modele-tls-");
      const x = configurationModele(d, fournisseur.url);
      x.config.model.tls = { cert_file: path.join(d, "absent.pem"), key_file: certs.serveurCle };
      const chemin = path.join(d, "c.json");
      fs.writeFileSync(chemin, JSON.stringify(x.config));
      const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...x.env }, stdio: ["ignore", "pipe", "pipe"] });
      let err = "";
      p.stderr.on("data", (z) => (err += z));
      const code = await new Promise((r) => p.on("exit", r));
      expect(code).to.equal(2);
      expect(err).to.match(/^demarrage_refuse : frontal_modele : /m);
    });
  });
});
