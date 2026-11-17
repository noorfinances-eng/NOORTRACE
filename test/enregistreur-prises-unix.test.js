// Longueur des chemins de prise Unix du démon et de ses processus (CT-2
// EX-18.1, EX-6.10 ; complément du 2026-11-16) et lignes de commande de
// `noortrace-miroir`, `noortrace-connecteur` et `noortrace validate-config`.
//
// Node.js tronque le chemin d'une prise Unix à `sizeof(sun_path) - 1` (107
// octets sous Linux, 103 sous macOS ; R12-F50) : un démon dont la prise
// configurée était plus longue écoutait sous un nom tronqué, souvent dans le
// répertoire PARENT de celui configuré, hors du répertoire dont EX-4.39 et
// EX-18.1 fixent le propriétaire et le mode. Tout chemin de prise configuré
// fait donc au plus 103 octets (`CHEMIN_PRISE_MAX_OCTETS`, même borne que le
// SDK) : la validation le refuse (`chemin_prise_trop_long`), le démarrage
// aussi (code 2), la mise en écoute aussi, et `noortrace-miroir --socket`,
// `noortrace-connecteur --socket` de même (code 2).
//
// Une option inconnue, en double ou sans sa valeur, rend l'usage et le code
// 2 : une faute de frappe sur une option de sécurité (`--source` pour
// `--sources`) ne passe plus en silence.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import * as E from "@noortrace/enregistreur";
import { RACINE, BIN_NOORTRACE, repertoireTemporaire, configurationDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMiroir } from "./fixtures/enregistreur-modele/outils.mjs";

const BIN_MIROIR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-miroir");
const BIN_CONNECTEUR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-connecteur");

/** Chemin de `n` octets exactement : `<dir>/p…p.sock`. */
function cheminDe(dir, n) {
  const reste = n - Buffer.byteLength(dir) - "/".length - ".sock".length;
  if (reste < 1) throw new Error(`répertoire trop long pour un chemin de ${n} octets : ${dir}`);
  const c = `${dir}/${"p".repeat(reste)}.sock`;
  expect(Buffer.byteLength(c)).to.equal(n);
  return c;
}

/**
 * Prise dans un sous-répertoire au nom long de `parent` : le chemin dépasse
 * 107 octets et sa troncature tomberait dans `parent` (constat reproduit).
 */
function priseSousNomLong(parent) {
  const sous = path.join(parent, `noortrace-modele-demon-miroir-${"x".repeat(90)}`);
  const c = path.join(sous, "miroir.sock");
  expect(Buffer.byteLength(parent) + 1).to.be.below(107);
  expect(Buffer.byteLength(c)).to.be.above(107);
  return c;
}

const lances = new Set();
function suivre(p) {
  lances.add(p);
  return p;
}
async function arreterRestants() {
  const vivants = [...lances].filter((p) => p.exitCode === null && p.signalCode === null);
  lances.clear();
  await Promise.all(vivants.map((p) => new Promise((res) => {
    p.once("exit", res);
    p.kill("SIGKILL");
  })));
}

/** Lance le démon ; rend son code de sortie, ou "demarre" (le démon est alors arrêté). */
async function lancerDemon(dir, c, delaiMs = 30000) {
  const chemin = path.join(dir, "configuration.json");
  fs.writeFileSync(chemin, JSON.stringify(c.config, null, 2));
  const p = suivre(spawn(process.execPath, [BIN_NOORTRACE, "--config", chemin], { env: { ...process.env, ...c.env }, stdio: ["ignore", "pipe", "pipe"] }));
  let sortie = "";
  let erreurs = "";
  p.stderr.on("data", (d) => (erreurs += d));
  const issue = await new Promise((res) => {
    const t = setTimeout(() => res("delai"), delaiMs);
    p.stdout.on("data", (d) => {
      sortie += d;
      if (/demon demarre/.test(sortie)) {
        clearTimeout(t);
        res("demarre");
      }
    });
    p.on("exit", (code) => {
      clearTimeout(t);
      res(code);
    });
  });
  if (issue === "demarre" || issue === "delai") {
    await new Promise((res) => {
      if (p.exitCode !== null || p.signalCode !== null) return res();
      p.once("exit", res);
      p.kill("SIGTERM");
    });
  }
  return { issue, erreurs };
}

describe("enregistreur : longueur des chemins de prise Unix (CT-2 EX-18.1, EX-6.10, complément du 2026-11-16)", function () {
  this.timeout(120000);
  let dir;

  before(function () {
    dir = repertoireTemporaire("noortrace-prises-");
  });

  afterEach(arreterRestants);
  after(arreterRestants);

  it("la borne est celle du SDK : 103 octets", function () {
    expect(E.CHEMIN_PRISE_MAX_OCTETS).to.equal(103);
  });

  it("validation : chaque membre de prise refusé à 104 octets (chemin_prise_trop_long), admis à 103", function () {
    const base = repertoireTemporaire("noortrace-prises-v-");
    const membres = [
      ["/mcp/socket", (c, p) => (c.mcp.socket = p)],
      ["/sdk/socket", (c, p) => (c.sdk = { enabled: false, socket: p, tcp_listen: null, hosts: [] })],
      ["/model/mirror/socket", (c, p) => (c.model.mirror = { socket: p })],
      ["/policy/approval/service/socket", (c, p) => (c.policy.approval.service = { url: null, socket: p, token: null, peer_user: "noortrace-approbation" })],
    ];
    for (const [pointeur, poser] of membres) {
      for (const n of [103, 104]) {
        const { config } = configurationDev(base);
        poser(config, cheminDe(base, n));
        const v = E.validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
        const e = v.erreurs.filter((x) => x.pointeur === pointeur);
        if (n === 103) {
          expect(e, `${pointeur} à 103 octets : ${JSON.stringify(v.erreurs)}`).to.deep.equal([]);
        } else {
          expect(e.length, `${pointeur} à 104 octets : ${JSON.stringify(v.erreurs)}`).to.equal(1);
          expect(e[0].regle).to.match(/^chemin_prise_trop_long : 104 octets, au plus 103 \(EX-18\.1, EX-6\.10\)$/);
          expect(v.pas).to.equal(3);
        }
      }
    }
  });

  it("validation : la borne est en octets UTF-8, non en caractères", function () {
    const base = repertoireTemporaire("noortrace-prises-u-");
    const { config } = configurationDev(base);
    // 100 caractères, plus de 103 octets : « é » en fait deux.
    const nom = "é".repeat(100 - Buffer.byteLength(base) - "/.sock".length);
    config.mcp.socket = `${base}/${nom}.sock`;
    expect(config.mcp.socket.length).to.be.at.most(103);
    expect(Buffer.byteLength(config.mcp.socket)).to.be.above(103);
    const v = E.validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
    expect(v.erreurs.map((x) => x.pointeur)).to.include("/mcp/socket");
  });

  it("démarrage refusé (code 2) pour une prise de 104 octets, avant toute écoute", async function () {
    const d = repertoireTemporaire("noortrace-prises-d-");
    const c = configurationMiroir(d, "http://127.0.0.1:9");
    fs.mkdirSync(path.join(d, "prise"), { recursive: true });
    c.config.model.mirror.socket = cheminDe(path.join(d, "prise"), 104);
    const r = await lancerDemon(d, c);
    expect(r.issue, r.erreurs).to.equal(2);
    expect(r.erreurs).to.match(/config_invalid : \/model\/mirror\/socket : chemin_prise_trop_long : 104 octets/);
    expect(fs.readdirSync(path.join(d, "prise"))).to.deep.equal([]);
  });

  it("démarrage refusé (code 2) pour une prise de plus de 107 octets : aucune prise créée dans le répertoire parent", async function () {
    const d = repertoireTemporaire("noortrace-prises-p-");
    const c = configurationMiroir(d, "http://127.0.0.1:9");
    const parent = path.join(d, "parent");
    fs.mkdirSync(parent);
    c.config.model.mirror.socket = priseSousNomLong(parent);
    const r = await lancerDemon(d, c);
    expect(r.issue, r.erreurs).to.equal(2);
    expect(r.erreurs).to.match(/chemin_prise_trop_long/);
    expect(fs.readdirSync(parent)).to.deep.equal([]);
  });

  it("mise en écoute (ecouterPriseUnix) refusée au-delà de 103 octets : aucune prise créée, ni à ce chemin ni dans le répertoire parent", async function () {
    const parent = path.join(dir, "ecoute");
    fs.mkdirSync(parent);
    for (const chemin of [cheminDe(parent, 104), priseSousNomLong(parent)]) {
      fs.mkdirSync(path.dirname(chemin), { recursive: true });
      const s = net.createServer();
      let erreur = null;
      try {
        await E.ecouterPriseUnix(s, chemin);
      } catch (e) {
        erreur = e;
      } finally {
        await new Promise((r) => (s.listening ? s.close(() => r()) : r()));
      }
      expect(erreur?.code, String(erreur)).to.equal("chemin_prise_trop_long");
      const restes = [];
      for (const n of fs.readdirSync(parent, { recursive: true })) if (fs.lstatSync(path.join(parent, n)).isSocket()) restes.push(n);
      expect(restes).to.deep.equal([]);
    }
  });

  it("adaptateur du miroir : prise du démon de 104 octets refusée avant toute connexion (chemin_prise_trop_long)", async function () {
    let erreur = null;
    try {
      const x = await E.lancerAdaptateur({ socket: cheminDe(dir, 104), ecoute: "127.0.0.1:0" });
      await x.arreter();
    } catch (e) {
      erreur = e;
    }
    expect(erreur?.code, String(erreur)).to.equal("chemin_prise_trop_long");
  });

  it("noortrace-miroir --socket de 104 octets, ou --config dont model.mirror.socket en fait 104 : refusé (code 2)", function () {
    const r = spawnSync(process.execPath, [BIN_MIROIR, "--socket", cheminDe(dir, 104), "--ecoute", "127.0.0.1:0"], { encoding: "utf8", timeout: 10000 });
    expect(r.status, r.stderr).to.equal(2);
    expect(r.stderr).to.match(/chemin_prise_trop_long/);
    const d = repertoireTemporaire("noortrace-prises-m-");
    const c = configurationMiroir(d, "http://127.0.0.1:9");
    c.config.model.mirror.socket = cheminDe(d, 104);
    const f = path.join(d, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(c.config));
    const r2 = spawnSync(process.execPath, [BIN_MIROIR, "--config", f], { encoding: "utf8", timeout: 10000 });
    expect(r2.status, r2.stderr).to.equal(2);
    expect(r2.stderr).to.match(/chemin_prise_trop_long/);
  });

  it("noortrace-connecteur --socket de 104 octets : refusé (code 2)", function () {
    const r = spawnSync(process.execPath, [BIN_CONNECTEUR, "--socket", cheminDe(dir, 104)], { encoding: "utf8", input: "", timeout: 10000 });
    expect(r.status, r.stderr).to.equal(2);
    expect(r.stderr).to.match(/chemin_prise_trop_long/);
  });
});

describe("enregistreur : lignes de commande strictes de noortrace-miroir, noortrace-connecteur et noortrace validate-config (complément du 2026-11-16)", function () {
  this.timeout(60000);
  let dir;
  let prise;
  let serveur;

  before(async function () {
    dir = repertoireTemporaire("noortrace-prises-l-");
    // Une vraie prise joignable : sans la règle, l'adaptateur démarrerait et écouterait.
    prise = path.join(dir, "demon.sock");
    serveur = net.createServer((s) => s.on("error", () => {}));
    await new Promise((r) => serveur.listen(prise, r));
  });

  after(async function () {
    await new Promise((r) => serveur.close(() => r()));
  });

  /** Lance l'adaptateur ; un adaptateur qui démarre au lieu de refuser est arrêté au délai (status null). */
  const miroir = (args) => spawnSync(process.execPath, [BIN_MIROIR, ...args], { encoding: "utf8", timeout: 4000, killSignal: "SIGKILL" });

  it("noortrace-miroir : option inconnue refusée (code 2, usage), au lieu d'écouter sur l'adresse par défaut", function () {
    for (const args of [
      ["--socket", prise, "--ecoute-mutant", "127.0.0.1:0"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "--source", "192.0.2.0/24"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "--tls_ca", "x.pem"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "superflu"],
    ]) {
      const r = miroir(args);
      expect(r.status, `${args.join(" ")} : ${r.stderr}`).to.equal(2);
      expect(r.stderr).to.match(/^usage : noortrace-miroir /m);
    }
  });

  it("noortrace-miroir : option à valeur sans valeur, option en double, --config avec une autre option : refusés (code 2, usage)", function () {
    for (const args of [
      ["--socket", prise, "--ecoute"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "--sources"],
      ["--socket", prise, "--sources", "--ecoute", "127.0.0.1:0"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "--ecoute", "192.0.2.10:0"],
      ["--socket", prise, "--ecoute", "127.0.0.1:0", "--preuve", "--preuve"],
      ["--config", path.join(dir, "absente.json"), "--sources", "192.0.2.0/24"],
    ]) {
      const r = miroir(args);
      expect(r.status, `${args.join(" ")} : ${r.stderr}`).to.equal(2);
      expect(r.stderr).to.match(/^usage : noortrace-miroir /m);
    }
  });

  it("noortrace-connecteur : option inconnue, en double ou sans valeur refusée (code 2, usage)", function () {
    for (const args of [
      ["--socket", prise, "--jeton", "x"],
      ["--socket", prise, "--socket", prise],
      ["--socket"],
      ["--socket", prise, "--tcp", "127.0.0.1:9"],
      ["--sockett", prise],
    ]) {
      const r = spawnSync(process.execPath, [BIN_CONNECTEUR, ...args], { encoding: "utf8", input: "", timeout: 4000, killSignal: "SIGKILL" });
      expect(r.status, `${args.join(" ")} : ${r.stderr}`).to.equal(2);
      expect(r.stderr).to.match(/usage : noortrace-connecteur /);
    }
  });

  it("noortrace validate-config : argument en trop refusé (code 2, usage)", function () {
    const d = repertoireTemporaire("noortrace-prises-c-");
    const { config } = configurationDev(d);
    const f = path.join(d, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(config));
    const ok = spawnSync(process.execPath, [BIN_NOORTRACE, "validate-config", f], { encoding: "utf8", timeout: 20000 });
    expect(ok.status, ok.stdout + ok.stderr).to.equal(0);
    const r = spawnSync(process.execPath, [BIN_NOORTRACE, "validate-config", f, "--strict"], { encoding: "utf8", timeout: 20000 });
    expect(r.status, r.stdout + r.stderr).to.equal(2);
    expect(r.stderr).to.match(/^usage : noortrace /m);
  });
});
