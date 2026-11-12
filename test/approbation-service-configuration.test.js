// Configuration du service d'approbation de la révision 0.5 (CT-3 EX-10.12,
// EX-12.12 ; CT-7 EX-3.10) : document `configuration-approbation-v0`,
// commande `noortrace-approbation valider-configuration` (rapport, tri, codes
// de retour), chaque règle de la table d'EX-10.12 à son pointeur, secrets
// résolus au démarrage et nommés par pointeur seulement, jetons comparés par
// valeur, écoute d'état, `GET /v0/etat` authentifié sur le canal de la
// console, sonde du conteneur. TA-51 (réponse retirée : règle
// `rpc_non_declare`) avec son mutant, copié hors du dépôt et détruit après.
// Révision 0.6 : boucle locale écrite exactement, règle
// `origine_port_par_defaut`, refus au démarrage en une ligne
// `$defs/rapport_validation` (EX-10.14 : `reference_illisible`,
// `jetons_egaux`, `ecoute_impossible`), jetons et clé du webhook sans espace
// intérieure, sonde d'EX-12.22.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawnSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as A from "@noortrace/approbation";
import { BIN_APPROBATION, RACINE, SESSIONS, messageCharger, politiqueParcours, repertoireTemporaire } from "./fixtures/approbation-service/outils.mjs";
import { configurationEtape6, serviceEtape6, etatHttp, journalService } from "./fixtures/approbation-service/etape6.mjs";

const CT3 = fs.readFileSync(path.join(RACINE, "spec", "CT-3-approbations.md"), "utf8");
/** Bloc JSON qui suit un marqueur `<!-- exemple: … -->` de CT-3. */
function exemple(marqueur) {
  const k = CT3.indexOf(`<!-- exemple: ${marqueur} -->`);
  const debut = CT3.indexOf("```json\n", k) + 8;
  return JSON.parse(CT3.slice(debut, CT3.indexOf("```", debut)));
}
const EXEMPLE = exemple("configuration-approbation");
const RAPPORT_EXEMPLE = exemple("configuration-approbation/rapport_validation");

const cloner = (o) => JSON.parse(JSON.stringify(o));
/** Variante de l'exemple : `f` modifie la copie. */
const variante = (f) => {
  const c = cloner(EXEMPLE);
  f(c);
  return c;
};

/** `noortrace-approbation <args>` ; rend { code, sortie, erreur }. */
function commande(args, env = {}) {
  const r = spawnSync(process.execPath, [BIN_APPROBATION, ...args], { encoding: "utf8", env: { ...process.env, ...env }, timeout: 30000 });
  return { code: r.status, sortie: r.stdout, erreur: r.stderr };
}

/** Écrit un document et le valide par la commande ; rend le rapport et le code. */
function valider(doc, dir = repertoireTemporaire("noortrace-config-")) {
  const f = path.join(dir, "approbation.json");
  fs.writeFileSync(f, typeof doc === "string" ? doc : JSON.stringify(doc));
  const r = commande(["valider-configuration", f]);
  const lignes = r.sortie.split("\n").filter(Boolean);
  expect(lignes, r.erreur).to.have.length(1);
  const rapport = JSON.parse(lignes[0]);
  expect(A.registreSchemas().valider(`${A.IDS.configuration}#/$defs/rapport_validation`, rapport).valide, lignes[0]).to.equal(true);
  return { rapport, code: r.code };
}

const refus = (code, pointer) => ({ valide: false, errors: [{ code, pointer }] });

describe("service d'approbation : configuration de la révision 0.5 (EX-10.12)", function () {
  this.timeout(120000);

  describe("valider-configuration", function () {
    it("l'exemple d'EX-10.12 est accepté (code 0) ; avec validator developpement, le rapport de l'exemple (code 1)", function () {
      expect(valider(EXEMPLE)).to.deep.equal({ rapport: { valide: true, errors: [] }, code: 0 });
      const r = valider(variante((c) => (c.rpc.validator = "developpement")));
      expect(r).to.deep.equal({ rapport: RAPPORT_EXEMPLE, code: 1 });
      // la commande ne lit aucun secret : l'exemple désigne /run/secrets/…, absents ici
      expect(fs.existsSync("/run/secrets/cle-stockage-approbation")).to.equal(false);
    });

    it("chaque code de la table d'EX-10.12 à son pointeur", function () {
      const cas = [
        ["rpc_non_declare /rpc (nul)", (c) => (c.rpc = null), refus("rpc_non_declare", "/rpc")],
        ["rpc_non_declare /rpc (absent)", (c) => delete c.rpc, refus("rpc_non_declare", "/rpc")],
        ["rpc_non_declare /rpc/validator", (c) => (c.rpc.validator = "developpement"), refus("rpc_non_declare", "/rpc/validator")],
        ["rpc_tls http hors boucle locale", (c) => (c.rpc.url = "http://rpc.assureur-demo.example"), refus("rpc_tls", "/rpc/url")],
        ["rpc_tls http vers la boucle locale en production", (c) => (c.rpc.url = "http://127.0.0.1:8545"), refus("rpc_tls", "/rpc/url")],
        ["tls_exige /console", (c) => (c.console.tls = null), refus("tls_exige", "/console")],
        ["tls_exige /noyau", (c) => Object.assign(c.noyau, { socket: null, tcp: { host: "192.0.2.10", port: 8500 } }), refus("tls_exige", "/noyau")],
        ["authentification_exigee /noyau (tcp sans jeton ni mTLS)", (c) => Object.assign(c.noyau, { socket: null, tcp: { host: "127.0.0.1", port: 8500 }, token: null }), refus("authentification_exigee", "/noyau")],
        ["authentification_exigee /console", (c) => (c.console.token = null), refus("authentification_exigee", "/console")],
        ["jeton_exige_production /noyau", (c) => (c.noyau.token = null), refus("jeton_exige_production", "/noyau")],
        ["jetons_egaux /console/token (même référence)", (c) => (c.console.token = { file: "/run/secrets/jeton-noyau-vers-service" }), refus("jetons_egaux", "/console/token")],
        ["escalade_non_croissante, première étape fautive", (c) => (c.escalation = [{ after_ms: 900000, notify: "jeu" }, { after_ms: 900000, notify: "jeu" }, { after_ms: 10, notify: "jeu" }]), refus("escalade_non_croissante", "/escalation/1/after_ms")],
        ["webhook_http", (c) => (c.notifications.url = "http://relais.assureur-demo.example/n"), refus("webhook_http", "/notifications/url")],
        ["webhook_http vers la boucle locale en production", (c) => (c.notifications.url = "http://[::1]:9000/n"), refus("webhook_http", "/notifications/url")],
      ];
      for (const [nom, f, attendu] of cas) expect(valider(variante(f)), nom).to.deep.equal({ rapport: attendu, code: 1 });
    });

    it("règles hors production : http vers 127.0.0.1, ::1 ou localhost admis ; socket sans jeton admise ; jetons de deux références", function () {
      const dev = (f) => variante((c) => {
        c.environment = "developpement";
        f(c);
      });
      for (const h of ["127.0.0.1", "[::1]", "localhost"]) {
        expect(valider(dev((c) => (c.rpc.url = `http://${h}:8545`))).code, h).to.equal(0);
        expect(valider(dev((c) => (c.notifications.url = `http://${h}:9000/n`))).code, h).to.equal(0);
      }
      expect(valider(dev((c) => (c.noyau.token = null))).code).to.equal(0);
      expect(valider(dev((c) => (c.rpc = null))).code).to.equal(0);
      // jetons_egaux par référence : le même fichier écrit relatif et absolu
      const d = repertoireTemporaire("noortrace-config-");
      const r = valider(dev((c) => {
        c.noyau.token = { file: "jetons/noyau" };
        c.console.token = { file: path.join(d, "jetons", "noyau") };
      }), d);
      expect(r).to.deep.equal({ rapport: refus("jetons_egaux", "/console/token"), code: 1 });
    });

    it("révision 0.6 : boucle locale écrite exactement (127.0.0.1, [::1], localhost, en minuscules, avant normalisation) ; 127.1, LOCALHOST, 127.000.000.001 n'en sont pas", function () {
      const dev = (f) => variante((c) => {
        c.environment = "developpement";
        f(c);
      });
      for (const h of ["127.1", "LOCALHOST", "Localhost", "127.000.000.001", "0x7f.1", "[0:0:0:0:0:0:0:1]"]) {
        expect(valider(dev((c) => (c.notifications.url = `http://${h}:9000/n`))), `webhook ${h}`).to.deep.equal({ rapport: refus("webhook_http", "/notifications/url"), code: 1 });
        expect(valider(dev((c) => (c.rpc.url = `http://${h}:8545`))), `rpc ${h}`).to.deep.equal({ rapport: refus("rpc_tls", "/rpc/url"), code: 1 });
      }
      for (const h of ["LOCALHOST", "127.1"]) {
        const r = valider(dev((c) => Object.assign(c.noyau, { socket: null, tcp: { host: h, port: 8500 } })));
        expect(r, `noyau ${h}`).to.deep.equal({ rapport: refus("tls_exige", "/noyau"), code: 1 });
      }
      expect(valider(dev((c) => Object.assign(c.noyau, { socket: null, tcp: { host: "localhost", port: 8500 } }))).code).to.equal(0);
    });

    it("révision 0.6 : origine_port_par_defaut, console_origin au port 443 écrit en clair ; un autre port, ou aucun, admis", function () {
      expect(valider(variante((c) => (c.console_origin = "https://console.assureur-demo.example:443")))).to.deep.equal({ rapport: refus("origine_port_par_defaut", "/console_origin"), code: 1 });
      expect(valider(variante((c) => (c.console_origin = "https://console.assureur-demo.example:8700"))).code).to.equal(0);
      expect(valider(variante((c) => (c.console_origin = "https://console.assureur-demo.example"))).code).to.equal(0);
    });

    it("erreurs triées par pointeur puis par code (unités UTF-16)", function () {
      const r = valider(variante((c) => {
        c.console.tls = null;
        c.console.token = null;
        c.rpc = null;
        c.noyau.token = null;
      }));
      expect(r.rapport.errors).to.deep.equal([
        { code: "authentification_exigee", pointer: "/console" },
        { code: "tls_exige", pointer: "/console" },
        { code: "jeton_exige_production", pointer: "/noyau" },
        { code: "rpc_non_declare", pointer: "/rpc" },
      ]);
    });

    it("json : fichier illisible ou hors JSON strict, seule erreur { json, \"\" }", function () {
      const json = { rapport: refus("json", ""), code: 1 };
      expect(valider('{"version":0,"version":0}')).to.deep.equal(json);
      expect(valider('{"org":"\\ud800"}')).to.deep.equal(json);
      expect(valider("{")).to.deep.equal(json);
      const r = commande(["valider-configuration", path.join(repertoireTemporaire(), "absent.json")]);
      expect(r.code).to.equal(1);
      expect(JSON.parse(r.sortie)).to.deep.equal(refus("json", ""));
    });

    it("schema : erreurs aux pointeurs des membres fautifs, règles alors non évaluées", function () {
      const r = valider(variante((c) => {
        delete c.org;
        c.rpc = null; // rpc_non_declare n'est pas évaluée
        c.max_open_tickets = 0;
        c.inconnu = 1;
        c.console.tcp.port = 70000;
      }));
      expect(r.code).to.equal(1);
      expect(r.rapport.errors).to.deep.equal([
        { code: "schema", pointer: "/console/tcp/port" },
        { code: "schema", pointer: "/inconnu" },
        { code: "schema", pointer: "/max_open_tickets" },
        { code: "schema", pointer: "/org" },
      ]);
      // bornes et formes du schéma : administrators de 1 à 64 identités canoniques distinctes, socket_mode, org
      const adm = (l) => valider(variante((c) => (c.administrators = l))).rapport.errors;
      expect(adm([])).to.deep.equal([{ code: "schema", pointer: "/administrators" }]);
      expect(adm([SESSIONS.admin, SESSIONS.admin])).to.deep.equal([{ code: "schema", pointer: "/administrators" }]);
      expect(adm(["u.martin@assureur-demo.example"])).to.deep.equal([{ code: "schema", pointer: "/administrators/0" }]);
      expect(adm(Array.from({ length: 65 }, (_, k) => `utilisateur local admin-${k}`))).to.deep.equal([{ code: "schema", pointer: "/administrators" }]);
      expect(valider(variante((c) => (c.administrators = Array.from({ length: 64 }, (_, k) => `utilisateur local admin-${k}`)))).code).to.equal(0);
      expect(valider(variante((c) => (c.noyau.socket_mode = "0666"))).rapport.errors).to.deep.equal([{ code: "schema", pointer: "/noyau/socket_mode" }]);
    });

    it("usage incorrect : code 2 ; --config reste la seule option du service", function () {
      expect(commande(["valider-configuration"]).code).to.equal(2);
      expect(commande([]).code).to.equal(2);
      expect(commande(["--config", "x.json", "--autre"]).code).to.equal(2);
    });

    it("membres facultatifs absents : défauts des descriptions du schéma", function () {
      const min = { version: 0, environment: "developpement", org: "assureur-demo", org_id: EXEMPLE.org_id, journal_id: EXEMPLE.journal_id, state_dir: "/var/lib/x", storage_key: { env: "X" }, noyau: { socket: "/run/x.sock" }, administrators: [SESSIONS.admin], console_origin: EXEMPLE.console_origin };
      expect(A.validerConfiguration(min)).to.deep.equal({ valide: true, errors: [] });
      const c = A.completer(min);
      expect(c).to.deep.include({
        console: null, etat: null, tickets: { epoch: null }, max_open_tickets: 20, escalation: [], set_poll_interval_ms: 10000,
        registration_ttl_ms: 600000, rpc: null, notifications: null, remise_representation_ms: 30000, body_max_bytes: 16777216,
      });
      expect(c.noyau).to.deep.equal({ socket: "/run/x.sock", socket_mode: "0660", tcp: null, tls: null, token: null });
      const r = A.completer({ ...min, rpc: { url: "https://r.example", validator: "client" }, notifications: { url: "https://n.example", key: { env: "K" } } });
      expect(r.rpc).to.deep.equal({ url: "https://r.example", validator: "client", token: null, timeout_ms: 5000, logs_from_block: 0 });
      expect(r.notifications).to.deep.equal({ url: "https://n.example", key: { env: "K" }, ca: null, timeout_ms: 10000 });
    });
  });

  describe("TA-51 : point RPC déclaré en production (CT-7 EX-3.10)", function () {
    let mutant = null;
    after(function () {
      if (mutant) fs.rmSync(mutant, { recursive: true, force: true });
    });

    it("TA-51 : production avec rpc nul ou developpement refusée (rpc_non_declare, code 1), client et partenaire acceptés (code 0) ; mutant sans la règle : la configuration sans point RPC déclaré passe (tué)", async function () {
      const production = (f) => variante(f);
      expect(valider(production((c) => (c.rpc = null)))).to.deep.equal({ rapport: refus("rpc_non_declare", "/rpc"), code: 1 });
      expect(valider(production((c) => (c.rpc.validator = "developpement")))).to.deep.equal({ rapport: refus("rpc_non_declare", "/rpc/validator"), code: 1 });
      expect(valider(production((c) => (c.rpc.validator = "client")))).to.deep.equal({ rapport: { valide: true, errors: [] }, code: 0 });
      expect(valider(production((c) => (c.rpc.validator = "partenaire")))).to.deep.equal({ rapport: { valide: true, errors: [] }, code: 0 });
      // la règle ne vaut qu'en production
      expect(valider(variante((c) => Object.assign(c, { environment: "developpement", rpc: null }))).code).to.equal(0);
      // mutant : copie du paquet sans la règle rpc_non_declare
      const base = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "noortrace-ta51-"));
      mutant = base;
      fs.cpSync(path.join(RACINE, "paquets", "approbation"), path.join(base, "approbation"), { recursive: true });
      fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(base, "node_modules"));
      const f = path.join(base, "approbation", "src", "configuration.mjs");
      const texte = fs.readFileSync(f, "utf8");
      const regle = /  if \(prod\) \{\n    if \(c\.rpc === undefined[\s\S]*?\n  \}\n/;
      expect(regle.test(texte), "règle trouvée dans la copie").to.equal(true);
      fs.writeFileSync(f, texte.replace(regle, ""));
      const M = await import(path.join(base, "approbation", "src", "configuration.mjs"));
      const sansRpc = production((c) => (c.rpc = null));
      expect(A.validerConfiguration(sansRpc).valide).to.equal(false);
      expect(M.validerConfiguration(sansRpc), "mutant : la réponse retirée, le refus disparaît").to.deep.equal({ valide: true, errors: [] });
    });
  });

  describe("secrets résolus au démarrage", function () {
    /** Configuration de développement écrite sous un répertoire neuf, secrets en fichiers. */
    const preparer = () => {
      const dir = repertoireTemporaire("noortrace-secrets-");
      const cfg = configurationEtape6(dir, { webhook: { url: "http://127.0.0.1:9/n" } });
      return { dir, cfg };
    };
    const refusDemarrage = (chemin) => {
      try {
        A.chargerConfiguration(chemin);
      } catch (e) {
        expect(e).to.be.instanceOf(A.ErreurConfiguration);
        return e.erreurs;
      }
      throw new Error("configuration acceptée");
    };

    it("storage_key : 32 octets bruts pris tels quels (espaces de tête et de fin compris), sinon 64 chiffres hexadécimaux après retrait des espaces", function () {
      const { dir, cfg } = preparer();
      const brute = Buffer.concat([Buffer.from(" "), randomBytes(30), Buffer.from("\n")]);
      fs.writeFileSync(path.join(dir, "cle-stockage"), brute);
      expect(Buffer.from(A.chargerConfiguration(cfg.chemin).secrets.cle).equals(brute)).to.equal(true);
      const hex = randomBytes(32).toString("hex");
      fs.writeFileSync(path.join(dir, "cle-stockage"), `  0x${hex}\n`);
      expect(Buffer.from(A.chargerConfiguration(cfg.chemin).secrets.cle).toString("hex")).to.equal(hex);
      fs.writeFileSync(path.join(dir, "cle-stockage"), hex.slice(2));
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/storage_key" }]);
    });

    it("jetons de 16 à 1 024 caractères ASCII imprimables, clé du webhook de 32 à 1 024 ; secrets illisibles nommés par pointeur, jamais par valeur", function () {
      const { dir, cfg } = preparer();
      fs.writeFileSync(path.join(dir, "jeton-noyau"), "court-15-carac.");
      fs.writeFileSync(path.join(dir, "cle-webhook"), "a".repeat(31));
      fs.rmSync(path.join(dir, "jeton-console"));
      const erreurs = refusDemarrage(cfg.chemin);
      expect(erreurs).to.deep.equal([
        { code: "reference_illisible", pointer: "/console/token" },
        { code: "reference_illisible", pointer: "/notifications/key" },
        { code: "reference_illisible", pointer: "/noyau/token" },
      ]);
      // la commande du service : code 1, pointeurs sur la sortie d'erreur, aucune valeur, aucune écoute
      fs.writeFileSync(path.join(dir, "cle-webhook"), "secret-de-webhook-tres-confidentiel-31");
      const r = commande(["--config", cfg.chemin]);
      expect(r.code).to.equal(1);
      expect(r.erreur).to.contain("/noyau/token").and.contain("/console/token");
      expect(r.erreur).to.not.contain("court-15-carac.");
      expect(r.erreur).to.not.contain("secret-de-webhook");
      expect(r.sortie).to.equal("");
      expect(fs.existsSync(cfg.doc.state_dir)).to.equal(false);
      // bornes exactes
      fs.writeFileSync(path.join(dir, "jeton-noyau"), "x".repeat(16));
      fs.writeFileSync(path.join(dir, "jeton-console"), `  ${"y".repeat(1024)}\n`);
      fs.writeFileSync(path.join(dir, "cle-webhook"), "k".repeat(32));
      const s = A.chargerConfiguration(cfg.chemin).secrets;
      expect([s.jetonNoyau.length, s.jetonConsole.length, s.cleWebhook.length]).to.deep.equal([16, 1024, 32]);
      fs.writeFileSync(path.join(dir, "jeton-console"), "y".repeat(1025));
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/console/token" }]);
      fs.writeFileSync(path.join(dir, "jeton-console"), "jeton avec espace");
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/console/token" }]);
      // révision 0.6 d'EX-10.12 : de U+0021 à U+007E, sans espace intérieure, notifications.key comprise
      fs.writeFileSync(path.join(dir, "jeton-console"), "y".repeat(16));
      fs.writeFileSync(path.join(dir, "cle-webhook"), ` ${"k".repeat(20)} ${"k".repeat(20)}\n`);
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/notifications/key" }]);
      fs.writeFileSync(path.join(dir, "cle-webhook"), ` ${"k".repeat(41)}\n`);
      expect(A.chargerConfiguration(cfg.chemin).secrets.cleWebhook).to.equal("k".repeat(41));
    });

    it("variable d'environnement absente ou vide : secret illisible, nommé par pointeur", function () {
      const { dir, cfg } = preparer();
      const doc = { ...cfg.doc, storage_key: { env: "NOORTRACE_ESSAI_CLE_ABSENTE" } };
      fs.writeFileSync(cfg.chemin, JSON.stringify(doc));
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/storage_key" }]);
      void dir;
    });

    it("jetons_egaux par valeur au démarrage : deux fichiers de même contenu refusés ; code 1, rapport sur la sortie d'erreur", function () {
      const { dir, cfg } = preparer();
      fs.writeFileSync(path.join(dir, "jeton-console"), fs.readFileSync(path.join(dir, "jeton-noyau")));
      expect(A.validerConfiguration(cfg.doc, { base: dir }).valide, "références distinctes").to.equal(true);
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "jetons_egaux", pointer: "/console/token" }]);
      const r = commande(["--config", cfg.chemin]);
      expect(r.code).to.equal(1);
      expect(JSON.parse(r.erreur.trim())).to.deep.equal(refus("jetons_egaux", "/console/token"));
      expect(r.erreur).to.not.contain(cfg.jetonNoyau);
    });

    it("au démarrage, un document refusé arrête le service avant toute écoute : code 1, mêmes erreurs sur la sortie d'erreur", function () {
      const { cfg } = preparer();
      const doc = { ...cfg.doc, environment: "production", console: { ...cfg.doc.console, tls: null } };
      fs.writeFileSync(cfg.chemin, JSON.stringify(doc));
      const v = commande(["valider-configuration", cfg.chemin]);
      const r = commande(["--config", cfg.chemin]);
      expect(r.code).to.equal(1);
      expect(r.sortie).to.equal("");
      expect(r.erreur).to.equal(v.sortie);
      // rpc nul, webhook http vers la boucle locale : deux règles de production
      expect(JSON.parse(r.erreur).errors).to.deep.equal([{ code: "webhook_http", pointer: "/notifications/url" }, { code: "rpc_non_declare", pointer: "/rpc" }]);
      expect(fs.existsSync(cfg.doc.state_dir)).to.equal(false);
    });

    it("EX-10.14 : refus au démarrage en une ligne $defs/rapport_validation sur la sortie d'erreur, code 1, sans valeur de secret : reference_illisible", function () {
      const { dir, cfg } = preparer();
      fs.writeFileSync(path.join(dir, "jeton-console"), "");
      fs.writeFileSync(path.join(dir, "jeton-noyau"), "jeton du noyau, mal formé");
      const r = commande(["--config", cfg.chemin]);
      expect(r.code).to.equal(1);
      expect(r.sortie).to.equal("");
      const lignes = r.erreur.split("\n").filter(Boolean);
      expect(lignes, r.erreur).to.have.length(1);
      const rapport = JSON.parse(lignes[0]);
      expect(A.registreSchemas().valider(`${A.IDS.configuration}#/$defs/rapport_validation`, rapport).valide, lignes[0]).to.equal(true);
      expect(rapport).to.deep.equal({ valide: false, errors: [{ code: "reference_illisible", pointer: "/console/token" }, { code: "reference_illisible", pointer: "/noyau/token" }] });
      expect(r.erreur).to.not.contain("jeton du noyau");
      expect(fs.existsSync(cfg.doc.state_dir)).to.equal(false);
    });

    it("EX-10.14 : écoute impossible (adresse déjà prise) : ecoute_impossible au pointeur de l'écoute, code 1, une ligne", async function () {
      const occupe = http.createServer();
      await new Promise((ok) => occupe.listen(0, "127.0.0.1", ok));
      const port = occupe.address().port;
      try {
        for (const ecoute of ["noyau", "console", "etat"]) {
          const { dir, cfg } = preparer();
          const doc = cloner(cfg.doc);
          if (ecoute === "etat") doc.etat = { host: "127.0.0.1", port };
          else doc[ecoute].tcp = { host: "127.0.0.1", port };
          fs.writeFileSync(cfg.chemin, JSON.stringify(doc));
          const r = commande(["--config", cfg.chemin]);
          expect(r.code, ecoute).to.equal(1);
          expect(r.sortie, ecoute).to.equal("");
          const lignes = r.erreur.split("\n").filter(Boolean);
          expect(lignes, r.erreur).to.have.length(1);
          const rapport = JSON.parse(lignes[0]);
          expect(A.registreSchemas().valider(`${A.IDS.configuration}#/$defs/rapport_validation`, rapport).valide).to.equal(true);
          expect(rapport, ecoute).to.deep.equal(refus("ecoute_impossible", `/${ecoute}`));
          void dir;
        }
      } finally {
        await new Promise((ok) => occupe.close(ok));
      }
    });

    it("TLS en PEM par référence : certificat du serveur en tête, clé privée ; PEM mal formé nommé par pointeur", function () {
      const { dir, cfg } = preparer();
      const doc = { ...cfg.doc, console: { ...cfg.doc.console, tls: { cert: { file: "tls.pem" }, key: { file: "tls.pem" }, client_ca: null } } };
      fs.writeFileSync(cfg.chemin, JSON.stringify(doc));
      fs.writeFileSync(path.join(dir, "tls.pem"), "pas un PEM");
      expect(refusDemarrage(cfg.chemin)).to.deep.equal([{ code: "reference_illisible", pointer: "/console/tls/cert" }, { code: "reference_illisible", pointer: "/console/tls/key" }]);
    });
  });

  describe("écoute d'état et GET /v0/etat (EX-10.12, EX-12.12)", function () {
    let s;
    before(async function () {
      s = await serviceEtape6({ etat: true });
    });
    after(async function () {
      await s?.arreter();
    });

    it("écoute etat : GET /v0/etat sans authentification, forme d'EX-12.12, aucune donnée de ticket", async function () {
      const r = await etatHttp(s.inst.etat);
      expect(r.statut).to.equal(200);
      expect(r.corps).to.deep.equal({ ready: false, set_read_at: null, open_tickets: 0 });
      expect(A.formeEtat(r.corps)).to.equal(true);
    });

    it("écoute etat : toute autre requête reçoit 404 et requete_invalide", async function () {
      const base = `http://127.0.0.1:${s.inst.etat.port}`;
      for (const [m, chemin] of [["POST", "/v0/etat"], ["GET", "/v0/tickets"], ["POST", "/v0/evaluer"], ["GET", "/"], ["PUT", "/v0/etat"]]) {
        const r = await fetch(base + chemin, { method: m, body: m === "GET" ? undefined : "{}", headers: { "content-type": "application/json" } });
        expect(r.status, `${m} ${chemin}`).to.equal(404);
        expect((await r.json()).error.code).to.equal("requete_invalide");
      }
    });

    it("canal de la console : GET /v0/etat authentifié comme les autres méthodes (401 sans le jeton, 200 avec)", async function () {
      expect((await etatHttp(s.inst.console)).statut).to.equal(401);
      expect((await etatHttp(s.inst.console, s.cfg.jetonNoyau)).statut).to.equal(401);
      const r = await etatHttp(s.inst.console, s.cfg.jetonConsole);
      expect(r).to.deep.equal({ statut: 200, corps: { ready: false, set_read_at: null, open_tickets: 0 } });
    });
  });

  it("escalation : une étape dont after_ms n'est pas inférieur à l'expire_after_ms d'une version chargée est signalée au chargement (EX-10.10)", async function () {
    const s = await serviceEtape6({ escalation: [{ after_ms: 60000, notify: "jeu" }, { after_ms: 3600000, notify: "administrateur" }] });
    try {
      await s.client.charger(messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() }));
      await s.service.supervision.vider();
      const l = journalService(s.cfg.doc.state_dir).filter((x) => x.kind === "escalade_apres_echeance");
      expect(l.map((x) => [x.expire_after_ms, x.after_ms])).to.deep.equal([[3600000, [3600000]]]);
    } finally {
      await s.arreter();
    }
  });

  describe("sonde --url (proposition PD-17)", function () {
    /** Lance la sonde en processus ; rend { code, sortie, erreur, duree }. */
    const sonde = (url, args = ["sonde", "--url", url]) => new Promise((ok) => {
      const debut = Date.now();
      const p = spawn(process.execPath, [BIN_APPROBATION, ...args], { stdio: ["ignore", "pipe", "pipe"] });
      let sortie = "";
      let erreur = "";
      p.stdout.on("data", (x) => (sortie += x));
      p.stderr.on("data", (x) => (erreur += x));
      p.on("exit", (code) => ok({ code, sortie, erreur, duree: Date.now() - debut }));
    });
    const serveur = (gestion) => new Promise((ok) => {
      const srv = http.createServer(gestion);
      srv.listen(0, "127.0.0.1", () => ok({ url: `http://127.0.0.1:${srv.address().port}/v0/etat`, fermer: () => new Promise((f) => { srv.closeAllConnections(); srv.close(f); }) }));
    });

    it("code 0 sur la réponse de l'écoute d'état, ready faux compris ; le corps sur une ligne de la sortie standard", async function () {
      const s = await serviceEtape6({ etat: true });
      try {
        const r = await sonde(`http://127.0.0.1:${s.inst.etat.port}/v0/etat`);
        expect(r.code, r.erreur).to.equal(0);
        expect(r.sortie).to.equal('{"open_tickets":0,"ready":false,"set_read_at":null}\n');
        expect(r.erreur).to.equal("");
      } finally {
        await s.arreter();
      }
    });

    it("code 1 : autre statut, corps hors forme, connexion refusée, délai de 2 500 ms écoulé, URL non http ; la raison sur la sortie d'erreur", async function () {
      const cas = [
        [(q, r) => r.writeHead(503).end('{"ready":true,"set_read_at":null,"open_tickets":0}'), /statut 503/],
        [(q, r) => r.writeHead(200).end('{"ready":true,"set_read_at":null}'), /forme/],
        [(q, r) => r.writeHead(200).end('{"ready":"oui","set_read_at":null,"open_tickets":0}'), /forme/],
        [(q, r) => r.writeHead(200).end("pas du JSON"), /illisible/],
      ];
      for (const [g, raison] of cas) {
        const srv = await serveur(g);
        const r = await sonde(srv.url);
        await srv.fermer();
        expect(r.code).to.equal(1);
        expect(r.sortie).to.equal("");
        expect(r.erreur).to.match(raison);
      }
      const muet = await serveur(() => {});
      const r = await sonde(muet.url);
      await muet.fermer();
      expect(r.code).to.equal(1);
      expect(r.erreur).to.match(/délai/);
      expect(r.duree).to.be.within(2400, 6000);
      const ferme = await serveur(() => {});
      const url = ferme.url;
      await ferme.fermer();
      expect((await sonde(url)).code).to.equal(1);
      expect((await sonde("https://127.0.0.1:1/v0/etat")).code).to.equal(1);
      expect(commande(["sonde"]).code).to.equal(1);
    });

    it("EX-12.22 : forme fermée de reponse_etat_service (membre en trop, horodatage mal formé, open_tickets négatif : 1 ; ready vrai : 0), redirection non suivie (1), usage incorrect : 1, jamais 2", async function () {
      const cas = [
        ['{"ready":true,"set_read_at":"2026-11-10T08:00:00.000Z","open_tickets":3}', 0],
        ['{"ready":false,"set_read_at":null,"open_tickets":0,"version":0}', 1],
        ['{"ready":false,"set_read_at":"2026-11-10 08:00:00","open_tickets":0}', 1],
        ['{"ready":false,"set_read_at":null,"open_tickets":-1}', 1],
        ['{"ready":false,"set_read_at":null,"open_tickets":0.5}', 1],
        ['{"ready":false,"ready":false,"set_read_at":null,"open_tickets":0}', 1],
      ];
      for (const [corps, code] of cas) {
        const srv = await serveur((q, r) => r.writeHead(200, { "content-type": "application/json" }).end(corps));
        const r = await sonde(srv.url);
        await srv.fermer();
        expect(r.code, corps).to.equal(code);
        expect(r.sortie, corps).to.equal(code === 0 ? `${corps}\n` : "");
      }
      // redirection vers une écoute conforme : non suivie
      let suivie = false;
      const cible = await serveur((q, r) => {
        suivie = true;
        r.writeHead(200).end('{"ready":true,"set_read_at":null,"open_tickets":0}');
      });
      const redir = await serveur((q, r) => r.writeHead(302, { location: cible.url }).end());
      const r = await sonde(redir.url);
      await redir.fermer();
      await cible.fermer();
      expect(r.code).to.equal(1);
      expect(suivie).to.equal(false);
      // usage incorrect : --url répétée, argument inconnu, --url sans valeur, valeur vide
      const ok = await serveur((q, rep) => rep.writeHead(200).end('{"ready":true,"set_read_at":null,"open_tickets":0}'));
      try {
        expect((await sonde(ok.url)).code).to.equal(0);
        for (const args of [["sonde", "--url", ok.url, "--url", ok.url], ["sonde", "--url", ok.url, "--verbeux"], ["sonde", "--verbeux", "--url", ok.url], ["sonde", "--url"], ["sonde", "--url", ""], ["sonde", ok.url]]) {
          const x = await sonde(null, args);
          expect(x.code, args.join(" ")).to.equal(1);
          expect(x.sortie, args.join(" ")).to.equal("");
        }
      } finally {
        await ok.fermer();
      }
    });
  });
});
