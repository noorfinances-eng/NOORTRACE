// Revue de sécurité interne de l'étape 8 : outils de supervision
// (scripts/deploiement/sonde.mjs, extraire-journaux.mjs,
// deploiement/taches/superviser.sh), constats EX-10.7.
//
// - : `sonde.mjs releve` rend le code de la relecture (CT-8 EX-10.9),
//   1 pour une commande tuée par un signal ;
// - EX-10.7 : témoin de vie en mode --intervalle : la sonde et
//   l'extracteur écrivent l'instant de leur dernière passe réussie
//   (noortrace_sonde_derniere_passe_s, noortrace_extracteur_derniere_passe_s) ;
//   une passe unique n'écrit pas ce témoin ; mutants : la ligne retirée de
//   chaque outil, l'oracle échoue ;
// - CT-8 EX-10.7 : un procès-verbal daté dans le futur n'est pas lu par
//   l'extracteur, qui le signale ;
// - : superviser.sh construit la commande des services
//   noortrace-extracteur et noortrace-sonde depuis les réglages, et lance
//   l'extracteur, qui écrit son exposition et son témoin.
// Les règles d'alerte sur ces témoins relèvent du générateur de
// scripts/lib/supervision.mjs. Aucun réseau hors 127.0.0.1 ; fichiers sous NOORTRACE_TMP
// (ou os.tmpdir()).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { TEMOIN_SONDE, TEMOIN_EXTRACTEUR, expositionTemoin } from "../scripts/deploiement/sonde.mjs";
import { ExtracteurFichiers, TOLERANCE_FUTUR_MS } from "../scripts/deploiement/extraire-journaux.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTILS = path.join(RACINE, "scripts", "deploiement");
const TACHES = path.join(RACINE, "deploiement", "taches");
const VECT = path.join(RACINE, "spec", "vecteurs", "ct-8", "supervision");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-observabilite-revue-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

const outil = (fichier, args, o = {}) => spawnSync(process.execPath, [fichier, ...args], { encoding: "utf8", cwd: RACINE, env: o.env ?? process.env, maxBuffer: 16 * 1024 * 1024 });
const bash = (script, args, o = {}) => spawnSync("/bin/bash", [script, ...args], { encoding: "utf8", cwd: RACINE, env: o.env ?? process.env });

/** Lance un outil en mode --intervalle, attend que `fichier` contienne `motif` (ou l'échéance), puis l'arrête par SIGTERM. */
async function passeEnBoucle(fichierOutil, args, fichier, motif, delaiMs = 8000) {
  const p = spawn(process.execPath, [fichierOutil, ...args], { cwd: RACINE, stdio: ["ignore", "pipe", "pipe"] });
  const err = [];
  p.stderr.on("data", (d) => err.push(d));
  const debut = Date.now();
  let texte = null;
  try {
    while (Date.now() - debut < delaiMs) {
      if (fs.existsSync(fichier)) {
        const t = fs.readFileSync(fichier, "utf8");
        if (t.includes(motif)) {
          texte = t;
          break;
        }
      }
      await attendre(100);
    }
    if (texte === null && fs.existsSync(fichier)) texte = fs.readFileSync(fichier, "utf8");
  } finally {
    p.kill("SIGTERM");
    await new Promise((r) => p.once("exit", r));
  }
  return { texte, stderr: Buffer.concat(err).toString("utf8") };
}

/**
 * Copie mutée d'un outil de scripts/deploiement/ sous TRAVAIL (NOORTRACE_TMP) :
 * même arborescence, scripts/lib lié au dépôt, `remplacement` appliqué une fois.
 */
function mutant(nom, de, par, autres = []) {
  const base = path.join(TRAVAIL, `mutant-${nom}`);
  fs.mkdirSync(path.join(base, "scripts", "deploiement"), { recursive: true });
  fs.symlinkSync(path.join(RACINE, "scripts", "lib"), path.join(base, "scripts", "lib"));
  fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(base, "node_modules"));
  for (const f of autres) fs.copyFileSync(path.join(OUTILS, f), path.join(base, "scripts", "deploiement", f));
  const source = fs.readFileSync(path.join(OUTILS, `${nom}.mjs`), "utf8");
  expect(source.split(de), `motif unique dans ${nom}.mjs`).to.have.length(2);
  fs.writeFileSync(path.join(base, "scripts", "deploiement", `${nom}.mjs`), source.replace(de, par));
  return { fichier: path.join(base, "scripts", "deploiement", `${nom}.mjs`), detruire: () => fs.rmSync(base, { recursive: true, force: true }) };
}

describe("Revue de sécurité de l'étape 8, CT-8 EX-10.9 : code rendu par sonde.mjs releve", function () {
  it("CT-8 EX-10.9 : la relecture rend 3 → releve rend 3 après avoir écrit la jauge à 0 ; relecture tuée par un signal → 1 ; relecture réussie → 0 et jauge à 1", function () {
    const f = path.join(TRAVAIL, "releve-code.prom");
    const sonde = path.join(OUTILS, "sonde.mjs");
    let r = outil(sonde, ["releve", "--check", "registre_gels", "--sortie", f, "--", process.execPath, "-e", "process.exit(3)"]);
    expect(r.status, r.stderr).to.equal(3);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 0');
    r = outil(sonde, ["releve", "--check", "registre_gels", "--sortie", f, "--", "/bin/bash", "-c", "kill -9 $$"]);
    expect(r.status).to.equal(1);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 0');
    r = outil(sonde, ["releve", "--check", "registre_gels", "--sortie", f, "--", process.execPath, "-e", "process.exit(0)"]);
    expect(r.status).to.equal(0);
    expect(fs.readFileSync(f, "utf8")).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 1');
  });
});

describe("Revue de sécurité de l'étape 8, témoins de vie des outils de supervision (CT-8 EX-10.7)", function () {
  this.timeout(60000);

  it("expositionTemoin : HELP, TYPE gauge, valeur en secondes UNIX à la milliseconde", function () {
    expect(expositionTemoin(TEMOIN_SONDE, 1793872800123)).to.equal(`# HELP ${TEMOIN_SONDE} Instant de la derniere passe reussie de l'outil, en secondes UNIX (temoin de vie, CT-8 EX-10.3).\n# TYPE ${TEMOIN_SONDE} gauge\n${TEMOIN_SONDE} 1793872800.123\n`);
    expect(TEMOIN_SONDE).to.equal("noortrace_sonde_derniere_passe_s");
    expect(TEMOIN_EXTRACTEUR).to.equal("noortrace_extracteur_derniere_passe_s");
  });

  it("sonde.mjs --intervalle 1 --sortie : l'exposition porte noortrace_sonde_derniere_passe_s, qui avance à la passe suivante ; une passe unique ne la porte pas ; mutant (témoin retiré) : la jauge manque, l'oracle échoue", async function () {
    const sonde = path.join(OUTILS, "sonde.mjs");
    const f = path.join(TRAVAIL, "sonde.prom");
    const args = ["--approbation", "http://127.0.0.1:9", "--delai", "200", "--sortie", f, "--intervalle", "1"];
    const une = await passeEnBoucle(sonde, args, f, TEMOIN_SONDE);
    expect(une.texte, une.stderr).to.match(new RegExp(`^${TEMOIN_SONDE} [0-9]{10}(\\.[0-9]{1,3})?$`, "m"));
    expect(une.texte).to.contain("noortrace_approbation_pret 0\n");
    const v1 = Number(/^noortrace_sonde_derniere_passe_s ([0-9.]+)$/m.exec(une.texte)[1]);
    fs.rmSync(f);
    const deux = await passeEnBoucle(sonde, args, f, TEMOIN_SONDE);
    const v2 = Number(/^noortrace_sonde_derniere_passe_s ([0-9.]+)$/m.exec(deux.texte)[1]);
    expect(v2).to.be.greaterThan(v1);
    const unique = outil(sonde, ["--approbation", "http://127.0.0.1:9", "--delai", "200"]);
    expect(unique.status).to.equal(0);
    expect(unique.stdout).to.not.contain(TEMOIN_SONDE);
    const m = mutant("sonde", '(o.intervalle !== undefined ? expositionTemoin(TEMOIN_SONDE, Date.now()) : "")', '""');
    try {
      const fm = path.join(TRAVAIL, "sonde-mutant.prom");
      const mu = await passeEnBoucle(m.fichier, ["--approbation", "http://127.0.0.1:9", "--delai", "200", "--sortie", fm, "--intervalle", "1"], fm, "noortrace_approbation_pret", 6000);
      expect(mu.texte, "le mutant écrit bien son exposition").to.contain("noortrace_approbation_pret 0\n");
      expect(mu.texte, "mutant : témoin absent (oracle qui tue le mutant)").to.not.contain(TEMOIN_SONDE);
    } finally {
      m.detruire();
    }
  });

  it("extraire-journaux.mjs --intervalle 1 --sortie : l'exposition porte noortrace_extracteur_derniere_passe_s ; la passe unique (SV-5, attendu.prom) ne la porte pas ; mutant (témoin retiré) : la jauge manque, l'oracle échoue", async function () {
    const extracteur = path.join(OUTILS, "extraire-journaux.mjs");
    const d = path.join(TRAVAIL, "journaux");
    fs.mkdirSync(path.join(d, "exploitation"), { recursive: true });
    fs.writeFileSync(path.join(d, "exploitation", "exploitation.ndjson"), `${JSON.stringify({ ts: "2026-11-05T08:00:00.000Z", level: "error", component: "noyau", event: "journal_fork", data: {} })}\n`);
    const f = path.join(TRAVAIL, "extracteur.prom");
    const r = await passeEnBoucle(extracteur, ["--exploitation", path.join(d, "exploitation"), "--sortie", f, "--intervalle", "1"], f, TEMOIN_EXTRACTEUR);
    expect(r.texte, r.stderr).to.match(new RegExp(`^${TEMOIN_EXTRACTEUR} [0-9]{10}(\\.[0-9]{1,3})?$`, "m"));
    expect(r.texte).to.contain('event="journal_fork",level="error",detail=""} 1');
    const unique = outil(extracteur, ["--repertoire", path.join(VECT, "journaux")]);
    expect(unique.status, unique.stderr).to.equal(0);
    expect(unique.stdout).to.equal(fs.readFileSync(path.join(VECT, "attendu.prom"), "utf8"));
    expect(unique.stdout).to.not.contain(TEMOIN_EXTRACTEUR);
    const m = mutant("extraire-journaux", '(o.intervalle !== undefined ? expositionTemoin(TEMOIN_EXTRACTEUR, Date.now()) : "")', '""', ["sonde.mjs"]);
    try {
      const fm = path.join(TRAVAIL, "extracteur-mutant.prom");
      const mu = await passeEnBoucle(m.fichier, ["--exploitation", path.join(d, "exploitation"), "--sortie", fm, "--intervalle", "1"], fm, "journal_fork", 6000);
      expect(mu.texte, "le mutant écrit bien son exposition").to.contain('event="journal_fork"');
      expect(mu.texte, "mutant : témoin absent (oracle qui tue le mutant)").to.not.contain(TEMOIN_EXTRACTEUR);
    } finally {
      m.detruire();
    }
  });
});

describe("Revue de sécurité de l'étape 8, extracteur : procès-verbal daté dans le futur (CT-8 EX-10.7)", function () {
  it("un procès-verbal dont finished_at dépasse l'heure de la passe de plus de TOLERANCE_FUTUR_MS n'est pas lu (jauge absente) et est signalé une fois ; il est lu dès que l'heure de la passe l'atteint", function () {
    const pv = path.join(VECT, "journaux", "proces-verbaux");
    const avertissements = [];
    // Horloge de la passe au 1er janvier 2026 : les procès-verbaux des vecteurs (novembre 2026) sont « futurs ».
    let horloge = Date.parse("2026-01-01T00:00:00.000Z");
    const x = new ExtracteurFichiers({ "proces-verbaux": [pv] }, { maintenant: () => horloge, avertir: (m) => avertissements.push(m) });
    let e = x.passe();
    expect(e).to.not.contain("noortrace_proces_verbal_dernier_s{");
    expect(avertissements.length).to.be.greaterThan(0);
    expect(avertissements[0]).to.match(/^Avertissement : procès-verbal écarté, finished_at dans le futur \(2026-/);
    const n = avertissements.length;
    e = x.passe();
    expect(avertissements.length, "signalé une seule fois par fichier").to.equal(n);
    expect(e).to.not.contain("noortrace_proces_verbal_dernier_s{");
    // L'heure de la passe atteint la date : le procès-verbal est lu (même valeur que SV-5).
    horloge = Date.parse("2026-11-13T00:00:00.000Z");
    e = x.passe();
    expect(e).to.contain('noortrace_proces_verbal_dernier_s{kind="sauvegarde"} 1793919761');
    expect(TOLERANCE_FUTUR_MS).to.equal(300000);
    // Témoin : l'horloge réelle lit les procès-verbaux des vecteurs sans avertissement.
    const reel = [];
    const y = new ExtracteurFichiers({ "proces-verbaux": [pv] }, { avertir: (m) => reel.push(m) });
    expect(y.passe()).to.contain('noortrace_proces_verbal_dernier_s{kind="sauvegarde"} 1793919761');
    expect(reel).to.deep.equal([]);
  });
});

describe("Revue de sécurité de l'étape 8, services de supervision (CT-8 EX-10.7) : superviser.sh", function () {
  this.timeout(30000);

  it("superviser.sh --afficher : commande de l'extracteur depuis les réglages (volumes du projet, procès-verbaux, chemins supplémentaires qui existent, --sortie et --intervalle) et de la sonde (approbation, console, points RPC, manifeste) ; usage et réglages manquants → 2", function () {
    const rep = path.join(TRAVAIL, "superviser");
    const volumes = path.join(rep, "volumes");
    fs.mkdirSync(path.join(volumes, "noortrace_exploitation", "_data"), { recursive: true });
    fs.mkdirSync(path.join(volumes, "noortrace_approbation-etat", "_data"), { recursive: true });
    fs.writeFileSync(path.join(volumes, "noortrace_approbation-etat", "_data", "journal-service.ndjson"), "");
    const sauvegardes = path.join(rep, "sauvegardes");
    fs.mkdirSync(sauvegardes);
    const gel = path.join(rep, "gel.ndjson");
    fs.writeFileSync(gel, "");
    const env = {
      ...process.env, NOORTRACE_RACINE: RACINE, NOORTRACE_SUPERVISION: path.join(rep, "collecteur"), NOORTRACE_SUPERVISION_INTERVALLE: "7",
      NOORTRACE_PROJET: "noortrace", NOORTRACE_VOLUMES: volumes, NOORTRACE_SAUVEGARDES: sauvegardes, NOORTRACE_EXPLOITATION: path.join(rep, "exploitation"),
      NOORTRACE_EXTRACTEUR_GEL: `${gel} ${path.join(rep, "absent.ndjson")}`, NOORTRACE_SONDE_CONSOLE: "https://console.interne.example", NOORTRACE_SONDE_RPC: "validateur-1=https://rpc-1.interne.example validateur-2=https://rpc-2.interne.example",
    };
    const sup = path.join(TACHES, "superviser.sh");
    const e = bash(sup, ["extracteur", "--afficher"], { env });
    expect(e.status, e.stderr).to.equal(0);
    expect(e.stdout.split("\n").filter(Boolean)).to.deep.equal([
      "node", path.join(OUTILS, "extraire-journaux.mjs"),
      "--exploitation", path.join(volumes, "noortrace_exploitation", "_data"),
      "--approbation", path.join(volumes, "noortrace_approbation-etat", "_data", "journal-service.ndjson"),
      "--proces-verbaux", sauvegardes,
      "--gel", gel,
      "--sortie", path.join(rep, "collecteur", "extracteur.prom"), "--intervalle", "7",
    ]);
    const s = bash(sup, ["sonde", "--afficher"], { env });
    expect(s.status, s.stderr).to.equal(0);
    expect(s.stdout.split("\n").filter(Boolean)).to.deep.equal([
      "node", path.join(OUTILS, "sonde.mjs"), "--approbation", "http://127.0.0.1:8601", "--console", "https://console.interne.example",
      "--rpc", "validateur-1=https://rpc-1.interne.example", "--rpc", "validateur-2=https://rpc-2.interne.example",
      "--sortie", path.join(rep, "collecteur", "sonde.prom"), "--intervalle", "7",
    ]);
    expect(bash(sup, ["autre"], { env }).status).to.equal(2);
    expect(bash(sup, [], { env }).status).to.equal(2);
    const sansRacine = bash(sup, ["sonde", "--afficher"], { env: { ...env, NOORTRACE_RACINE: "" } });
    expect(sansRacine.status).to.equal(2);
    expect(sansRacine.stderr).to.contain("NOORTRACE_RACINE");
    expect(bash(sup, ["extracteur", "--afficher"], { env: { ...env, NOORTRACE_SUPERVISION_INTERVALLE: "0" } }).status).to.equal(2);
    const rien = bash(sup, ["extracteur", "--afficher"], { env: { ...env, NOORTRACE_VOLUMES: path.join(rep, "nulle-part"), NOORTRACE_SAUVEGARDES: path.join(rep, "nulle-part"), NOORTRACE_EXTRACTEUR_GEL: "" } });
    expect(rien.status).to.equal(2);
    expect(rien.stderr).to.contain("aucun journal à lire");
  });

  it("superviser.sh extracteur (réglages d'essai, intervalle 1 s) lance l'extracteur, qui écrit <supervision>/extracteur.prom avec les lignes lues et son témoin de vie", async function () {
    const rep = path.join(TRAVAIL, "superviser-run");
    const volumes = path.join(rep, "volumes");
    fs.mkdirSync(path.join(volumes, "noortrace_exploitation", "_data"), { recursive: true });
    fs.writeFileSync(path.join(volumes, "noortrace_exploitation", "_data", "exploitation.ndjson"), `${JSON.stringify({ ts: "2026-11-05T08:00:00.000Z", level: "error", component: "noyau", event: "disk_low", data: {} })}\n`);
    const collecteur = path.join(rep, "collecteur");
    fs.mkdirSync(collecteur);
    const env = { ...process.env, NOORTRACE_RACINE: RACINE, NOORTRACE_SUPERVISION: collecteur, NOORTRACE_SUPERVISION_INTERVALLE: "1", NOORTRACE_PROJET: "noortrace", NOORTRACE_VOLUMES: volumes, NOORTRACE_SAUVEGARDES: path.join(rep, "aucune"), NOORTRACE_EXPLOITATION: path.join(rep, "aucune") };
    const p = spawn("/bin/bash", [path.join(TACHES, "superviser.sh"), "extracteur"], { cwd: RACINE, env, stdio: ["ignore", "pipe", "pipe"] });
    const err = [];
    p.stderr.on("data", (d) => err.push(d));
    const f = path.join(collecteur, "extracteur.prom");
    let texte = null;
    const debut = Date.now();
    try {
      while (Date.now() - debut < 8000) {
        if (fs.existsSync(f) && fs.readFileSync(f, "utf8").includes(TEMOIN_EXTRACTEUR)) {
          texte = fs.readFileSync(f, "utf8");
          break;
        }
        await attendre(100);
      }
    } finally {
      p.kill("SIGTERM");
      await new Promise((r) => p.once("exit", r));
    }
    expect(texte, Buffer.concat(err).toString("utf8")).to.not.equal(null);
    expect(texte).to.contain('noortrace_journal_lignes_total{source="exploitation",event="disk_low",level="error",detail=""} 1');
    expect(texte).to.match(new RegExp(`^${TEMOIN_EXTRACTEUR} [0-9]{10}(\\.[0-9]{1,3})?$`, "m"));
  });
});
