// Configuration, démarrage et refus du cœur (CT-2 §15, §11, §7.4, §14, §17) :
// commande `noortrace validate-config` et démarrage du démon `bin/noortrace`
// (codes et messages d'EX-15.4 : rapport sur stderr, une ligne par erreur,
// code 2) ; classe D refusée en production (EX-11.8) ; horloge qui recule ou
// saute en avant (EX-7.9, EX-7.13, mode dégradé « horloge ») ; rechargement
// (EX-15.5) ; ensemble de politique changé sans nouvelle version (EX-10.21) ;
// schémas embarqués identiques à spec/schemas.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, MagasinBailFichier, SignataireFichier, ErreurEnregistreur, validerConfiguration, resoudreSecrets, empreintePolitique,
  pieceJson, FICHIERS_SCHEMAS, ADRESSES_DE_TEST, AVERTISSEMENT_OBSERVATION,
} from "@noortrace/enregistreur";
import {
  BIN_NOORTRACE, SPEC, configurationDev, configurationExemple, graine, repertoireTemporaire, secretsDev,
} from "./fixtures/enregistreur-coeur/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);
const enc = (o) => new TextEncoder().encode(typeof o === "string" ? o : JSON.stringify(o));

function ecrire(dir, nom, contenu) {
  const p = path.join(dir, nom);
  fs.writeFileSync(p, typeof contenu === "string" ? contenu : JSON.stringify(contenu, null, 2));
  return p;
}

function noortrace(args, env = {}) {
  return spawnSync(process.execPath, [BIN_NOORTRACE, ...args], { encoding: "utf8", env: { ...process.env, ...env }, timeout: 30000 });
}

function getJson(adresse, chemin) {
  return new Promise((resoudre, rejeter) => {
    http.get(`http://${adresse}${chemin}`, (res) => {
      let t = "";
      res.on("data", (d) => (t += d));
      res.on("end", () => resoudre({ statut: res.statusCode, corps: t ? JSON.parse(t) : null }));
    }).on("error", rejeter);
  });
}

describe("enregistreur, cœur : configuration, démarrage et refus", function () {
  this.timeout(60000);

  describe("schémas et listes embarqués", function () {
    it("les schémas de paquets/enregistreur/schemas sont identiques à spec/schemas", function () {
      for (const f of FICHIERS_SCHEMAS) {
        const a = fs.readFileSync(path.join(SPEC, "..", "paquets", "enregistreur", "schemas", f));
        expect(Buffer.compare(a, fs.readFileSync(path.join(SPEC, "schemas", f))), f).to.equal(0);
      }
    });

    it("la liste des adresses de test est celle de spec/vecteurs/ct-7/cles-de-test.json (EX-15.8)", function () {
      const d = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-7", "cles-de-test.json"), "utf8"));
      expect([...ADRESSES_DE_TEST].sort()).to.deep.equal([...new Set(d.keys.map((k) => k.address).filter(Boolean))].sort());
    });
  });

  describe("validation (EX-15.4 pas 1 à 3, EX-15.7)", function () {
    it("l'exemple de 15.3 valide ; son ensemble de politique fait 6533 octets, policy_sha256 de EX-10.21", function () {
      const c = configurationExemple();
      const v = validerConfiguration(enc(c));
      expect(v.erreurs).to.deep.equal([]);
      expect(empreintePolitique(c.policy)).to.deep.equal({ policy_version: "2026-11-01", policy_sha256: "0xd68bb713d14538549a347529a1f927a13ceffd444b351fe1b644242b2574e75c", length: 6533 });
      const dir = repertoireTemporaire();
      const r = noortrace(["validate-config", ecrire(dir, "exemple.json", c)]);
      expect(r.status).to.equal(0);
      expect(r.stdout).to.not.match(/^erreur/m);
    });

    it("JSON non strict (clé en double) : code 2, une ligne au pointeur racine", function () {
      const dir = repertoireTemporaire();
      const r = noortrace(["validate-config", ecrire(dir, "c.json", '{"config_version":0,"config_version":0}')]);
      expect(r.status).to.equal(2);
      expect(r.stdout).to.match(/^erreur : \/ : JSON strict : clé en double/m);
    });

    it("schéma : toutes les erreurs, une ligne chacune (pointeur, règle, valeur)", function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      config.inconnu = true;
      config.lease.ttl_ms = 10;
      const r = noortrace(["validate-config", ecrire(dir, "c.json", config)]);
      expect(r.status).to.equal(2);
      const lignes = r.stdout.trim().split("\n");
      expect(lignes).to.include("erreur : /inconnu : additionalProperties : membre inconnu");
      expect(lignes).to.include("erreur : /lease/ttl_ms : minimum : 1000 ; valeur : 10");
    });

    it("règles hors schéma : cadence, bail, signataire, observation (EX-12.24, EX-13.3, EX-15.4, EX-15.8)", function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      config.checkpoint_interval_s = 11;
      config.lease.renew_ms = 6000;
      config.signer.backend = { type: "pkcs11", module: "/opt/x.so", token_label: "t", key_label: "k", pin: { env: "PIN_TEST" }, mechanism: "CKM_EDDSA" };
      const v = validerConfiguration(enc(config));
      expect(v.pas).to.equal(3);
      const regles = v.erreurs.map((e) => `${e.pointeur} ${e.regle}`);
      expect(regles).to.include("/checkpoint_interval_s diviseur de 3600 entre 10 et 3600 attendu (EX-12.24)");
      expect(regles).to.include("/lease/renew_ms lease.renew_ms < lease.ttl_ms / 2 attendu");
      expect(regles).to.include("/signer/backend/type incohérent avec la classe D (EX-15.4 pas 3)");
      const { config: c2 } = configurationDev(dir);
      c2.policy.approval.mode = "observation";
      const v2 = validerConfiguration(enc(c2));
      expect(v2.erreurs.map((e) => e.regle)).to.include("version_observation_sans_suffixe (EX-15.8)");
      expect(v2.avertissements.map((e) => e.regle)).to.include(AVERTISSEMENT_OBSERVATION);
    });

    it("classe D refusée en production (EX-11.8), à la validation et par le signataire lui-même", function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir, { environment: "production" });
      const v = validerConfiguration(enc(config));
      expect(v.erreurs.map((e) => `${e.pointeur} ${e.regle}`)).to.include("/signer/class classe D refusée en production (EX-11.8)");
      expect(() => new SignataireFichier({ environment: "production", cles: new Map([["k", graine("rec-test-01")]]) })).to.throw(ErreurEnregistreur, /classe D refusee en production/);
    });

    it("secrets (pas 4) : variable absente et clé du MAC trop courte, sans la valeur", function () {
      const dir = repertoireTemporaire();
      const { config, env } = configurationDev(dir);
      const v = validerConfiguration(enc(config));
      const r1 = resoudreSecrets(v.config, { env: {} });
      expect(r1.erreurs.find((e) => e.pointeur === "/storage/relay_mac_key").regle).to.equal("variable d'environnement NOORTRACE_TEST_CLE_MAC absente");
      const r2 = resoudreSecrets(v.config, { env: { ...env, NOORTRACE_TEST_CLE_MAC: "0x0102" } });
      expect(r2.erreurs).to.deep.equal([{ pointeur: "/storage/relay_mac_key", regle: "au moins 32 octets après décodage (EX-7.22)", secret: true }]);
    });
  });

  describe("démon bin/noortrace", function () {
    it("refuse une configuration invalide : code 2, rapport sur stderr, rien n'est ouvert", function () {
      const dir = repertoireTemporaire();
      const { config, env } = configurationDev(dir, { environment: "production" });
      const r = noortrace(["--config", ecrire(dir, "c.json", config)], env);
      expect(r.status).to.equal(2);
      expect(r.stderr).to.match(/^config_invalid : \/signer\/class : classe D refusée en production \(EX-11\.8\) ; valeur : "D"$/m);
      expect(fs.existsSync(config.storage.root)).to.equal(false);
      const r2 = noortrace(["--config", ecrire(dir, "c2.json", configurationDev(dir).config)], {});
      expect(r2.status).to.equal(2);
      expect(r2.stderr).to.match(/^config_invalid : \/storage\/relay_mac_key : variable d'environnement NOORTRACE_TEST_CLE_MAC absente$/m);
      expect(noortrace([]).status).to.equal(2);
    });

    it("démarre sur une configuration valide, sert /healthz, s'arrête proprement sur SIGTERM", async function () {
      const dir = repertoireTemporaire();
      const { config, env } = configurationDev(dir);
      const chemin = ecrire(dir, "c.json", config);
      const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      let sortie = "";
      let erreurs = "";
      p.stderr.on("data", (d) => (erreurs += d));
      const adresse = await new Promise((resoudre, rejeter) => {
        p.stdout.on("data", (d) => {
          sortie += d;
          const m = /supervision ([0-9.]+:[0-9]+)/.exec(sortie);
          if (m) resoudre(m[1]);
        });
        p.on("exit", (code) => rejeter(new Error(`arrêt (${code}) : ${erreurs}`)));
      });
      const h = await getJson(adresse, "/healthz");
      expect(h).to.deep.equal({ statut: 200, corps: { status: "ok" } });
      expect((await getJson(adresse, "/readyz")).statut).to.equal(200);
      const code = await new Promise((r) => {
        p.removeAllListeners("exit");
        p.on("exit", (c) => r(c));
        p.kill("SIGTERM");
      });
      expect(code).to.equal(0);
      const ops = fs.readFileSync(path.join(dir, "exploitation.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(ops.map((l) => l.event)).to.include.members(["lease_acquired", "policy_announced", "startup", "shutdown"]);
      const startup = ops.find((l) => l.event === "startup");
      expect(startup.data.config_sha256).to.equal(N.sha256Hex(new Uint8Array(fs.readFileSync(chemin))));
      expect(startup.data.class).to.equal("D");
      expect(Object.keys(startup)).to.deep.equal(["ts", "level", "component", "event", "org_id", "journal_id", "seq", "host", "request_id", "data"]);
      expect(fs.readFileSync(`${config.lease.store.path}.epoch`, "utf8").trim()).to.equal("1");
      // Verrou du bail libéré par l'arrêt (flock(2), 13.2) : une nouvelle acquisition réussit.
      // Le fichier verrou reste en place : il n'est jamais supprimé (deux verrous sur deux fichiers).
      const b = new MagasinBailFichier(config.lease.store.path);
      expect(await b.acquerir(), "verrou du bail libéré").to.equal(2);
      await b.liberer();
    });
  });

  describe("horloge (EX-7.9, EX-7.13, 14.2)", function () {
    let coeur;
    let horloge;
    const p = pieceJson({ x: 1 });
    const echange = () =>
      coeur.scellerEchange({ delegation: { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null }, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 1, is_error: false });

    before(async function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.000Z"));
      coeur = await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev(), horloge });
      await coeur.ecrirePiece(p);
    });

    after(async function () {
      await coeur.arreter();
    });

    it("un recul sous le seuil garde ts non décroissant ; au-delà de max_backstep_ms, mode dégradé « horloge », bloquant", async function () {
      horloge.aller(ms("2026-11-10T10:14:10.000Z"));
      const e1 = await echange();
      horloge.placerMurale(ms("2026-11-10T10:14:08.000Z"));
      const e2 = await echange();
      expect(e2.ts, "ts = max(lu, précédent)").to.equal(e1.ts);
      expect(coeur.journal.trouver("clock_skew")).to.have.length(1);
      horloge.placerMurale(ms("2026-11-10T10:14:04.000Z"));
      let err;
      try {
        await echange();
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.raison).to.equal("horloge");
      expect(coeur.journal.trouver("clock_backstep")).to.have.length(1);
      expect(coeur.sante().corps).to.include({ status: "degraded" });
      expect(coeur.sante().corps.reasons).to.deep.equal(["horloge"]);
      expect(coeur.metriques.valeur("noortrace_degraded", { reason: "horloge" })).to.equal(1);
      // L'horloge a rejoint le ts précédent : sortie du mode.
      horloge.placerMurale(ms("2026-11-10T10:14:11.000Z"));
      const e3 = await echange();
      expect(e3.seq).to.equal(e2.seq + 1);
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
    });

    it("un saut en avant au-delà de l'avance monotone + max_forward_ms bloque, jusqu'à confirmation de l'exploitant", async function () {
      horloge.placerMurale(horloge.murale() + 5 * 60 * 1000);
      let err;
      try {
        await echange();
      } catch (e) {
        err = e;
      }
      expect(err?.raison).to.equal("horloge");
      expect(coeur.journal.trouver("clock_forward_jump")).to.have.length(1);
      coeur.horloge.accepter();
      const e = await echange();
      expect(N.decoderHorodatage(e.ts)).to.equal(horloge.murale());
    });
  });

  describe("politique : rechargement (EX-15.5) et changement sans nouvelle version (EX-10.21)", function () {
    it("rechargement : version inchangée refusée, membre hors policy refusé, nouvelle version scellée", async function () {
      const dir = repertoireTemporaire();
      const { config, env } = configurationDev(dir);
      const coeur = await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev() });
      try {
        const c2 = structuredClone(config);
        c2.policy.failure.lecture = "bloquant";
        expect((await coeur.recharger(enc(c2), { env })).raison).to.equal("version_inchangee");
        const c3 = structuredClone(config);
        c3.clock.warn_skew_ms = 2000;
        expect(await coeur.recharger(enc(c3), { env })).to.deep.include({ accepte: false, raison: "redemarrage_requis", pointeurs: ["/clock"] });
        c2.policy.version = "2026-11-02";
        const r = await coeur.recharger(enc(c2), { env });
        expect(r.accepte).to.equal(true);
        expect(r.evenement.execution.arguments.value).to.deep.equal({ policy_version: "2026-11-02", policy_sha256: empreintePolitique(c2.policy).policy_sha256 });
        expect(coeur.versionPolitique).to.equal("2026-11-02");
      } finally {
        await coeur.arreter();
      }
    });

    it("démarrage refusé si l'ensemble de politique a changé pendant l'arrêt sans changer policy.version", async function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      const c1 = await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev() });
      await c1.arreter();
      config.policy.failure.lecture = "bloquant";
      let err;
      try {
        await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev() });
      } catch (e) {
        err = e;
      }
      expect(err).to.be.instanceOf(ErreurEnregistreur);
      expect(err.message).to.match(/EX-10\.21/);
    });
  });
});

// Défauts démontrés par la relecture adversariale A : configuration (R-A-7,
// R-A-8, soupçon `worm.credentials`), horloge au tic (R-A-2), commandes
// `noortrace-ctl reload` et `noortrace-ctl clock --accept` (R-A-10).
describe("enregistreur, cœur : non-régression de la relecture A (configuration, horloge, noortrace-ctl)", function () {
  this.timeout(60000);
  const BIN_CTL = path.join(path.dirname(BIN_NOORTRACE), "noortrace-ctl");
  const valider = (c) => {
    const dir = repertoireTemporaire();
    const r = noortrace(["validate-config", ecrire(dir, "c.json", c)]);
    return { code: r.status, sortie: r.stdout + r.stderr };
  };

  describe("validate-config, production (EX-15.4 pas 3)", function () {
    it("R-A-8, EX-3.5 : serveur stdio sans user ni integrity, ou sous l'utilisateur du démon, ou commande sans le paquet épinglé → refus", function () {
      const base = configurationExemple();
      expect(valider(base).code, "exemple de 15.3").to.equal(0);
      const c1 = structuredClone(base);
      c1.policy.servers.fichiers.transport.user = null;
      c1.policy.servers.fichiers.transport.integrity = null;
      const r1 = valider(c1);
      expect(r1.code).to.equal(2);
      expect(r1.sortie).to.match(/^erreur : \/policy\/servers\/fichiers\/transport\/user : utilisateur distinct de celui du démon obligatoire en production \(EX-3\.5\)/m);
      expect(r1.sortie).to.match(/^erreur : \/policy\/servers\/fichiers\/transport\/integrity : épinglage de la commande obligatoire en production \(EX-3\.5\)/m);
      const c2 = structuredClone(base);
      c2.policy.servers.fichiers.transport.user = os.userInfo().username;
      expect(valider(c2).sortie).to.match(/transport\/user : utilisateur du démon refusé \(EX-3\.5\)/);
      const c3 = structuredClone(base);
      c3.policy.servers.fichiers.transport.integrity = { package: "@modelcontextprotocol/server-filesystem@2025.8.21" };
      expect(valider(c3).sortie).to.match(/transport\/command : la commande ne contient pas tel quel le paquet épinglé \(EX-3\.5\)/);
    });

    it("R-A-7, EX-18.8 : service d'approbation en HTTP sans jeton (aucun mTLS en v0), prise Unix sans peer_user ni jeton, HTTP sans TLS hors de la boucle locale → refus, en production comme en développement", function () {
      const base = configurationExemple();
      const c1 = structuredClone(base);
      c1.policy.approval.service = { url: "http://approbation.interne.example:8080", socket: null, token: null, peer_user: null };
      const r1 = valider(c1);
      expect(r1.code).to.equal(2);
      expect(r1.sortie).to.match(/^erreur : \/policy\/approval\/service\/token : jeton nul admis seulement sur une prise Unix dont le pair est vérifié/m);
      expect(r1.sortie).to.match(/^erreur : \/policy\/approval\/service\/url : TLS exigé hors de la boucle locale/m);
      const c2 = structuredClone(base);
      c2.policy.approval.service = { url: "http://127.0.0.1:9", socket: null, token: null, peer_user: null };
      expect(valider(c2).code, "service HTTP local sans jeton").to.equal(2);
      const c3 = structuredClone(base);
      c3.policy.approval.service = { url: null, socket: "/run/noortrace/approbation.sock", token: null, peer_user: null };
      expect(valider(c3).sortie).to.match(/^erreur : \/policy\/approval\/service\/peer_user : prise Unix sans peer_user/m);
      const c4 = structuredClone(base);
      c4.policy.approval.service = { url: "https://approbation.interne.example:8600", socket: null, token: { file: "/run/secrets/jeton-approbation" }, peer_user: null };
      expect(valider(c4).code, "HTTPS avec jeton").to.equal(0);
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      config.policy.approval.service = { url: "http://127.0.0.1:9", socket: null, token: null, peer_user: null };
      const r5 = valider(config);
      expect(r5.code, r5.sortie).to.equal(2);
      expect(r5.sortie).to.match(/^erreur : \/policy\/approval\/service\/token : jeton nul admis seulement/m);
    });

    it("soupçon (EX-15.4) : worm.credentials qui désigne le même fichier que relay_mac_key (encoding différent) → avertissement", function () {
      const c = configurationExemple();
      c.storage.seal.worm.credentials = { file: c.storage.relay_mac_key.file };
      const r = valider(c);
      expect(r.sortie).to.match(/^avertissement : \/storage\/seal\/worm\/credentials : même référence que \/storage\/relay_mac_key/m);
    });
  });

  describe("horloge au tic (R-A-2, EX-7.13, EX-12.24)", function () {
    const p = pieceJson({ x: 2 });
    const echange = (coeur) => coeur.scellerEchange({ delegation: { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null }, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 1, is_error: false });
    async function demarrer() {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      const horloge = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
      const coeur = await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev(), horloge });
      await coeur.ecrirePiece(p);
      return { coeur, horloge };
    }
    const manifestes = (coeur) => fs.readdirSync(path.join(coeur.repertoire, "manifestes")).filter((n) => n.endsWith(".json"));
    const points = (coeur) => fs.readdirSync(path.join(coeur.repertoire, "points"));

    it("saut en avant pendant un tic, après un scellement refusé : rien n'est clos ni pointé ; l'horloge revenue, le prochain événement est daté à l'heure vraie", async function () {
      const { coeur, horloge } = await demarrer();
      try {
        const e1 = await echange(coeur);
        horloge.avancer(1000);
        const pointsAvant = points(coeur).map((n) => fs.readFileSync(path.join(coeur.repertoire, "points", n), "utf8")).join("");
        horloge.placerMurale(ms("2026-11-13T10:15:01.000Z"));
        let err;
        try {
          await echange(coeur);
        } catch (e) {
          err = e;
        }
        expect(err?.raison).to.equal("horloge");
        await coeur.tic();
        expect(manifestes(coeur), "aucune période future close").to.deep.equal([]);
        expect(points(coeur).map((n) => fs.readFileSync(path.join(coeur.repertoire, "points", n), "utf8")).join(""), "aucun point").to.equal(pointsAvant);
        horloge.placerMurale(ms("2026-11-10T10:14:01.500Z"));
        await coeur.tic();
        expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
        const e3 = await echange(coeur);
        expect(e3.ts).to.equal("2026-11-10T10:14:01.500Z");
        expect(e3.seq).to.equal(e1.seq + 1);
      } finally {
        await coeur.arreter();
      }
    });

    it("saut en avant détecté par le tic lui-même (aucun scellement entre-temps) : mode dégradé « horloge », clock_forward_jump, rien n'est clos", async function () {
      const { coeur, horloge } = await demarrer();
      try {
        await echange(coeur);
        horloge.avancer(1000);
        horloge.placerMurale(ms("2026-11-12T00:00:00.500Z"));
        await coeur.tic();
        expect(manifestes(coeur)).to.deep.equal([]);
        expect(coeur.sante().corps.reasons).to.deep.equal(["horloge"]);
        expect(coeur.journal.trouver("clock_forward_jump")).to.have.length(1);
      } finally {
        await coeur.arreter();
      }
    });
  });

  describe("noortrace-ctl reload et clock --accept (R-A-10, EX-15.5, EX-7.13)", function () {
    function ctl(args) {
      return new Promise((r) => {
        const x = spawn(process.execPath, [BIN_CTL, ...args], { stdio: ["ignore", "pipe", "pipe"] });
        let sortie = "";
        let erreur = "";
        x.stdout.on("data", (d) => (sortie += d));
        x.stderr.on("data", (d) => (erreur += d));
        x.on("exit", (code) => r({ code, sortie, erreur }));
      });
    }

    it("contre le démon bin/noortrace réel : reload scelle la nouvelle politique (code 0), version inchangée refusée (code 1) ; clock --accept hors mode horloge refusé et consigné (code 1) ; sans démon, code 4", async function () {
      const dir = repertoireTemporaire();
      const { config, env } = configurationDev(dir);
      const chemin = ecrire(dir, "c.json", config);
      expect((await ctl(["reload", "--configuration", chemin, "--delai-ms", "500"])).code, "aucun démon").to.equal(4);
      const p = spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      try {
        await new Promise((resoudre, rejeter) => {
          let s = "";
          p.stdout.on("data", (d) => {
            s += d;
            if (/supervision /.test(s)) resoudre();
          });
          p.on("exit", (code) => rejeter(new Error(`arrêt ${code}`)));
        });
        const c2 = structuredClone(config);
        c2.policy.version = "2026-11-02";
        ecrire(dir, "c.json", c2);
        const r1 = await ctl(["reload", "--configuration", chemin]);
        expect(r1.code, r1.sortie + r1.erreur).to.equal(0);
        expect(JSON.parse(r1.sortie.trim()).event).to.equal("config_reloaded");
        const r2 = await ctl(["reload", "--configuration", chemin]);
        expect(r2.code).to.equal(1);
        expect(JSON.parse(r2.sortie.trim()).data.raison).to.equal("version_inchangee");
        const r3 = await ctl(["clock", "--accept", "--configuration", chemin]);
        expect(r3.code).to.equal(1);
        expect(JSON.parse(r3.sortie.trim())).to.deep.include({ event: "clock_accept_refused", data: { raison: "hors_mode_horloge" } });
        expect((await ctl(["clock", "--configuration", chemin])).code, "--accept exigé").to.equal(2);
      } finally {
        p.kill("SIGTERM");
        await new Promise((r) => p.on("exit", r));
      }
      const ops = fs.readFileSync(path.join(dir, "exploitation.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(ops.filter((l) => l.event === "policy_announced").map((l) => l.data.policy_version)).to.deep.equal(["2026-11-01", "2026-11-02"]);
    });

    it("accepterHorloge (signal de clock --accept) : lève le mode « horloge » d'un saut en avant (clock_accepted) ; refusé après un recul", async function () {
      const dir = repertoireTemporaire();
      const { config } = configurationDev(dir);
      const horloge = new HorlogeReglable(ms("2026-11-10T10:14:00.000Z"));
      const coeur = await Coeur.demarrer({ config: validerConfiguration(enc(config)).config, secrets: secretsDev(), horloge });
      const p = pieceJson({ x: 3 });
      await coeur.ecrirePiece(p);
      const echange = () => coeur.scellerEchange({ delegation: { launched_by: "x", on_behalf_of: null, scope: "s", run_id: null }, code: { model: null, prompt_version: null }, intent: null, requete: p.reference, reponse: p.reference, duration_ms: 1, is_error: false });
      try {
        await echange();
        horloge.placerMurale(horloge.murale() + 10 * 60 * 1000);
        await echange().catch(() => {});
        expect(coeur.sante().corps.reasons).to.deep.equal(["horloge"]);
        expect(coeur.accepterHorloge()).to.deep.equal({ accepte: true });
        expect(coeur.journal.trouver("clock_accepted")).to.have.length(1);
        expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
        const e = await echange();
        expect(N.decoderHorodatage(e.ts)).to.equal(horloge.murale());
        horloge.placerMurale(horloge.murale() - 60 * 1000);
        await echange().catch(() => {});
        expect(coeur.accepterHorloge()).to.deep.equal({ accepte: false, raison: "recul" });
        expect(coeur.sante().corps.reasons).to.deep.equal(["horloge"]);
      } finally {
        await coeur.arreter();
      }
    });
  });
});
