// Longueur des chemins de prise Unix du service d'approbation (CT-3 EX-12.2,
// EX-10.12 ; CT-2 EX-6.10, EX-18.1 ; complément du 2026-11-16) et ligne de
// commande de `noortrace-approbation`.
//
// Node.js tronque le chemin d'une prise Unix à la taille de `sun_path` : une
// écoute `socket` du noyau ou de la console plus longue serait créée sous un
// autre nom, souvent dans le répertoire parent de celui configuré, hors du
// répertoire dont EX-12.2 fixe les droits. Tout chemin de prise du service
// fait donc au plus 103 octets (`CHEMIN_PRISE_MAX_OCTETS`, borne du SDK et du
// démon) : la validation le refuse (`chemin_prise_trop_long`, au pointeur du
// membre), le démarrage aussi (code 1 et rapport d'EX-10.14, comme toute
// configuration refusée du service), la mise en écoute aussi, avant toute
// liaison. Un chemin admis dont le chemin provisoire (`.p-XXXXXX/s` du même
// répertoire) dépasserait la borne est écouté directement à son chemin.
//
// Une option inconnue, en double ou sans sa valeur, ou un argument en trop,
// rend l'usage et le code 2 (la sonde garde le code 1 d'EX-12.22).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import * as A from "@noortrace/approbation";
import { BIN_APPROBATION, RACINE, ecrireConfiguration, repertoireTemporaire, politiqueParcours } from "./fixtures/approbation-service/outils.mjs";

const CT3 = fs.readFileSync(path.join(RACINE, "spec", "CT-3-approbations.md"), "utf8");
function exemple(marqueur) {
  const k = CT3.indexOf(`<!-- exemple: ${marqueur} -->`);
  const debut = CT3.indexOf("```json\n", k) + 8;
  return JSON.parse(CT3.slice(debut, CT3.indexOf("```", debut)));
}
const EXEMPLE = exemple("configuration-approbation");
const cloner = (o) => JSON.parse(JSON.stringify(o));

/** Chemin de `n` octets exactement : `<dir>/p…p.sock`. */
function cheminDe(dir, n) {
  const reste = n - Buffer.byteLength(dir) - "/".length - ".sock".length;
  if (reste < 1) throw new Error(`répertoire trop long pour un chemin de ${n} octets : ${dir}`);
  const c = `${dir}/${"p".repeat(reste)}.sock`;
  expect(Buffer.byteLength(c)).to.equal(n);
  return c;
}

function commande(args) {
  const r = spawnSync(process.execPath, [BIN_APPROBATION, ...args], { encoding: "utf8", timeout: 30000 });
  return { code: r.status, sortie: r.stdout, erreur: r.stderr };
}

/** Rapport de `valider-configuration` sur un document ; vérifie sa forme. */
function valider(doc) {
  const dir = repertoireTemporaire("noortrace-prises-ap-v-");
  const f = path.join(dir, "approbation.json");
  fs.writeFileSync(f, JSON.stringify(doc));
  const r = commande(["valider-configuration", f]);
  const lignes = r.sortie.split("\n").filter(Boolean);
  expect(lignes, r.erreur).to.have.length(1);
  const rapport = JSON.parse(lignes[0]);
  expect(A.registreSchemas().valider(`${A.IDS.configuration}#/$defs/rapport_validation`, rapport).valide, lignes[0]).to.equal(true);
  return { rapport, code: r.code };
}

/** Configuration de service écrite sous `dir`, dont la prise du noyau est `socket`. */
function configurationAvecPrise(dir, socket) {
  const cfg = ecrireConfiguration(dir);
  const doc = JSON.parse(fs.readFileSync(cfg.chemin, "utf8"));
  doc.noyau.socket = socket;
  fs.writeFileSync(cfg.chemin, JSON.stringify(doc, null, 2));
  return { chemin: cfg.chemin, doc };
}

const lances = new Set();
/** Lance le service ; rend { issue: code | "pret" | "delai", sortie, erreur } ; le service prêt reste vivant (arrêté par arreterRestants). */
function lancer(chemin, delaiMs = 30000) {
  const p = spawn(process.execPath, [BIN_APPROBATION, "--config", chemin], { stdio: ["ignore", "pipe", "pipe"] });
  lances.add(p);
  let sortie = "";
  let erreur = "";
  p.stderr.on("data", (d) => (erreur += d));
  return new Promise((res) => {
    const t = setTimeout(() => res({ issue: "delai", sortie, erreur, p }), delaiMs);
    p.stdout.on("data", (d) => {
      sortie += d;
      if (sortie.includes("\n")) {
        clearTimeout(t);
        res({ issue: "pret", sortie, erreur, p });
      }
    });
    p.on("exit", (code) => {
      clearTimeout(t);
      res({ issue: code, sortie, erreur, p });
    });
  });
}
async function arreterRestants() {
  const vivants = [...lances].filter((p) => p.exitCode === null && p.signalCode === null);
  lances.clear();
  await Promise.all(vivants.map((p) => new Promise((res) => {
    p.once("exit", res);
    p.kill("SIGTERM");
  })));
}

describe("service d'approbation : longueur des chemins de prise Unix (CT-3 EX-12.2, EX-10.12 ; CT-2 EX-6.10 ; complément du 2026-11-16)", function () {
  this.timeout(120000);
  afterEach(arreterRestants);
  after(arreterRestants);

  it("la borne est celle du SDK et du démon : 103 octets", function () {
    expect(A.CHEMIN_PRISE_MAX_OCTETS).to.equal(103);
    expect(A.CODES_CONFIGURATION).to.include("chemin_prise_trop_long");
  });

  it("validation : socket du noyau ou de la console refusée à 104 octets (chemin_prise_trop_long au pointeur du membre, code 1), admise à 103", function () {
    for (const canal of ["noyau", "console"]) {
      const doc = cloner(EXEMPLE);
      doc[canal] = { ...doc[canal], socket: cheminDe("/run/noortrace", 104), tcp: null, tls: null };
      const r = valider(doc);
      expect(r.code, canal).to.equal(1);
      expect(r.rapport, canal).to.deep.equal({ valide: false, errors: [{ code: "chemin_prise_trop_long", pointer: `/${canal}/socket` }] });
      doc[canal].socket = cheminDe("/run/noortrace", 103);
      const ok = valider(doc);
      expect(ok.rapport, canal).to.deep.equal({ valide: true, errors: [] });
      expect(ok.code, canal).to.equal(0);
    }
  });

  it("validation : la borne est en octets UTF-8 (49 « é » : 108 octets, 59 caractères)", function () {
    const doc = cloner(EXEMPLE);
    const c = `/run/${"é".repeat(49)}/sock`;
    expect(c.length).to.equal(59);
    expect(Buffer.byteLength(c)).to.equal(108);
    doc.noyau.socket = c;
    expect(valider(doc).rapport.errors).to.deep.equal([{ code: "chemin_prise_trop_long", pointer: "/noyau/socket" }]);
  });

  it("démarrage refusé à 104 octets : code 1, rapport d'EX-10.14 sur la sortie d'erreur, aucune prise, aucun état", async function () {
    const dir = repertoireTemporaire("noortrace-prises-ap-d-");
    const socket = cheminDe(dir, 104);
    const { chemin, doc } = configurationAvecPrise(dir, socket);
    const r = await lancer(chemin);
    expect(r.issue, r.sortie + r.erreur).to.equal(1);
    expect(r.sortie).to.equal("");
    expect(JSON.parse(r.erreur.trim())).to.deep.equal({ valide: false, errors: [{ code: "chemin_prise_trop_long", pointer: "/noyau/socket" }] });
    expect(fs.existsSync(socket)).to.equal(false);
    expect(fs.existsSync(doc.state_dir)).to.equal(false);
  });

  it("démarrage refusé au-delà de 107 octets : aucune prise créée, ni au chemin ni dans le répertoire parent", async function () {
    const dir = repertoireTemporaire("noortrace-prises-ap-l-");
    const sous = path.join(dir, `noortrace-approbation-${"x".repeat(90)}`);
    fs.mkdirSync(sous, { mode: 0o750 });
    const socket = path.join(sous, "approbation.sock");
    expect(Buffer.byteLength(socket)).to.be.above(107);
    const { chemin } = configurationAvecPrise(dir, socket);
    const avant = fs.readdirSync(dir).sort();
    const r = await lancer(chemin);
    expect(r.issue, r.sortie + r.erreur).to.equal(1);
    expect(JSON.parse(r.erreur.trim()).errors).to.deep.equal([{ code: "chemin_prise_trop_long", pointer: "/noyau/socket" }]);
    expect(fs.readdirSync(dir).sort()).to.deep.equal(avant);
    expect(fs.readdirSync(sous)).to.deep.equal([]);
  });

  it("chemin de 103 octets dans un répertoire au nom long (chemin provisoire au-delà de la borne) : prise écoutée à son chemin exact, mode 0660, rien d'autre dans le répertoire", async function () {
    const base = repertoireTemporaire("noortrace-prises-ap-c-");
    const dir = path.join(base, "d".repeat(101 - Buffer.byteLength(base) - 1));
    fs.mkdirSync(dir, { mode: 0o750 });
    const socket = path.join(dir, "a");
    expect(Buffer.byteLength(socket)).to.equal(103);
    const { chemin } = configurationAvecPrise(base, socket);
    const r = await lancer(chemin);
    expect(r.issue, r.sortie + r.erreur).to.equal("pret");
    expect(JSON.parse(r.sortie.split("\n")[0]).noyau).to.deep.equal({ socket });
    const st = fs.lstatSync(socket);
    expect(st.isSocket()).to.equal(true);
    expect(st.mode & 0o777).to.equal(0o660);
    expect(fs.readdirSync(dir)).to.deep.equal(["a"]);
    await arreterRestants();
  });

  it("mise en écoute (Ecoute.demarrer) : refus chemin_prise_trop_long avant toute liaison, aucune prise ni au chemin ni dans le parent", async function () {
    const dir = repertoireTemporaire("noortrace-prises-ap-e-");
    for (const socket of [cheminDe(dir, 104), path.join(dir, `${"y".repeat(120)}.sock`)]) {
      const e = new A.Ecoute({ canal: "noyau", service: {}, config: { socket, socket_mode: "0660", tcp: null }, jeton: "jeton-de-seize-caracteres", bodyMax: 1024 });
      let erreur = null;
      try {
        await e.demarrer();
      } catch (x) {
        erreur = x;
      } finally {
        await e.arreter().catch(() => {});
      }
      expect(erreur?.code, String(erreur)).to.equal("chemin_prise_trop_long");
      expect(fs.readdirSync(dir)).to.deep.equal([]);
    }
  });

  it("démarrage programmatique (demarrerService) d'une configuration non validée : refus chemin_prise_trop_long au pointeur du membre, sans écoute", async function () {
    const dir = repertoireTemporaire("noortrace-prises-ap-p-");
    const cfg = ecrireConfiguration(dir);
    const { config, secrets, base } = A.chargerConfiguration(cfg.chemin);
    const socket = cheminDe(dir, 104);
    config.noyau.socket = socket;
    let erreur = null;
    let instance = null;
    try {
      instance = await A.demarrerService({ config, secrets, base, essais: { minuterie: false } });
    } catch (x) {
      erreur = x;
    } finally {
      await instance?.arreter();
    }
    expect(erreur, "le service a démarré").to.be.instanceOf(A.ErreurConfiguration);
    expect(erreur.erreurs).to.deep.equal([{ code: "chemin_prise_trop_long", pointer: "/noyau/socket" }]);
    expect(fs.existsSync(socket)).to.equal(false);
  });
});

describe("noortrace-approbation : ligne de commande stricte (CT-3 EX-10.12 ; complément du 2026-11-16)", function () {
  this.timeout(60000);
  let f;
  let politique;
  before(function () {
    const dir = repertoireTemporaire("noortrace-prises-ap-o-");
    f = ecrireConfiguration(dir).chemin;
    politique = path.join(dir, "politique.json");
    fs.writeFileSync(politique, JSON.stringify(politiqueParcours()));
  });

  const usage = (r, quoi) => {
    expect(r.code, `${quoi} : ${r.sortie}${r.erreur}`).to.equal(2);
    expect(r.erreur, quoi).to.match(/usage/);
    expect(r.sortie, quoi).to.equal("");
  };

  it("--version seul ; avec une autre option ou un argument : usage, code 2", function () {
    expect(commande(["--version"]).code).to.equal(0);
    usage(commande(["--version", "--inconnue"]), "--version --inconnue");
    usage(commande(["--config", f, "--version"]), "--config f --version");
    usage(commande(["valider-configuration", f, "--version"]), "valider-configuration f --version");
  });

  it("--config et valider-configuration sans valeur (option à la place du fichier) : usage, code 2", function () {
    usage(commande(["--config", "--inconnue"]), "--config --inconnue");
    usage(commande(["valider-configuration", "--inconnue"]), "valider-configuration --inconnue");
  });

  it("déjà refusés : --config avec une option en plus, en double, sans fichier ; valider-configuration sans fichier ou avec un argument en trop", function () {
    usage(commande(["--config", f, "--autre"]), "--config f --autre");
    usage(commande(["--config", f, "--config", f]), "--config en double");
    usage(commande(["--config"]), "--config seul");
    usage(commande(["valider-configuration"]), "valider-configuration seul");
    usage(commande(["valider-configuration", f, f]), "valider-configuration f f");
  });

  it("valider-politique : forme admise rendue (code 0) ; option inconnue, en double, sans valeur, argument en trop : usage, code 2", function () {
    const ok = commande(["valider-politique", politique, "--environment", "developpement", "--expire-after-ms", "3600000"]);
    expect(ok.code, ok.sortie + ok.erreur).to.equal(0);
    expect(commande(["valider-politique", politique]).code).to.equal(0);
    usage(commande(["valider-politique", politique, "--environement", "production"]), "option inconnue");
    usage(commande(["valider-politique", politique, "--environment", "production", "--environment", "developpement"]), "--environment en double");
    usage(commande(["valider-politique", politique, "--environment"]), "--environment sans valeur");
    usage(commande(["valider-politique", politique, "--expire-after-ms", "--environment", "production"]), "--expire-after-ms sans valeur");
    usage(commande(["valider-politique", politique, politique]), "argument en trop");
    usage(commande(["valider-politique", "--environment", "production"]), "sans fichier");
  });

  it("sonde : usage incorrect rend 1, jamais 2 (EX-12.22, inchangé)", function () {
    expect(commande(["sonde", "--url", "http://127.0.0.1:1/v0/etat", "--inconnue"]).code).to.equal(1);
    expect(commande(["sonde", "--url"]).code).to.equal(1);
    expect(commande(["sonde", "--url", "http://127.0.0.1:1/v0/etat", "--url", "http://127.0.0.1:1/v0/etat"]).code).to.equal(1);
  });
});
