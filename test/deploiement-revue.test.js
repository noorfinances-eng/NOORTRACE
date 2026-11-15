// Revue de sécurité interne de l'étape 8 : fichiers de déploiement
// (deploiement/taches/, deploiement/hote/, deploiement/config/modele-production/,
// scripts/deploiement/archiver-journal-exploitation.mjs, configurer-rapide.mjs,
// banc-client-fictif.mjs). Constats : CT-8 EX-10.9 (tâches enveloppées par
// sonde.mjs releve, jauges des tâches), EX-5.3 (TLS des frontaux du modèle),
// IC-16 (propriété de la racine des tâches), IC-2 (preparer-hote.sh :
// archive copiée avant contrôle, version de Node.js exigée, procès-verbal
// sans lien suivi), CT-8 CO-8 (daemon.json), EX-10.7 (unités des
// services de supervision), EX-11.23 (archivage : index chaîné, reprise,
// liens, taille), IC-14 (modèle de politique), IC-15 et
// (banc : projet propre, installation de référence intouchée),
// (avertissement de configurer-rapide). Les commandes système sont
// simulées ; aucun réseau ; fichiers sous NOORTRACE_TMP (ou os.tmpdir()).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validerConfiguration } from "@noortrace/enregistreur";
import * as J from "../scripts/lib/journal.mjs";
import { valeur as valeurCondition } from "../paquets/approbation/src/evaluation.mjs";
import { archiver, relireSerie, lireIndex, lireFichierTourne, principal as archiverPrincipal, OCTETS_MAX_DEFAUT, PREMIERE_EMPREINTE } from "../scripts/deploiement/archiver-journal-exploitation.mjs";
import { installationPresente, preparerRepertoireOutils, nettoyerRepertoireOutils, PROJET_BANC } from "../scripts/deploiement/banc-client-fictif.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEP = path.join(RACINE, "deploiement");
const TACHES = path.join(DEP, "taches");
const PREPARER = path.join(DEP, "hote", "preparer-hote.sh");
const OUTILS = path.join(RACINE, "scripts", "deploiement");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const sha = (o) => "0x" + crypto.createHash("sha256").update(o).digest("hex");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const commande = (c) => spawnSync("/bin/sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).status === 0;
const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-deploiement-revue-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

const bash = (script, args, o = {}) => spawnSync("/bin/bash", [script, ...args], { encoding: "utf8", cwd: o.cwd ?? RACINE, env: o.env ?? process.env });
const outil = (nom, args, o = {}) => spawnSync(process.execPath, [path.join(OUTILS, nom), ...args], { encoding: "utf8", cwd: RACINE, env: o.env ?? process.env });

/** Copie mutée d'un script shell sous TRAVAIL : `de` remplacé une fois par `par`. */
function mutantShell(source, de, par) {
  const texte = fs.readFileSync(source, "utf8");
  expect(texte.split(de), `motif unique dans ${path.basename(source)}`).to.have.length(2);
  const f = path.join(TRAVAIL, `mutant-${path.basename(source)}`);
  fs.writeFileSync(f, texte.replace(de, par), { mode: 0o755 });
  return f;
}

// ---------------------------------------------------------------------------
// Tâches planifiées (CT-8 EX-10.9, CT-8 IC-16, CT-8 EX-10.7)
// ---------------------------------------------------------------------------

/** Moteur simulé : `docker volume inspect` rend `volume` ; `docker compose … run …` rend le code du fichier `code` et consigne ses arguments. */
function moteurSimule(rep, { volume = rep, code = 0 } = {}) {
  const bin = path.join(rep, "bin");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(rep, "code"), String(code));
  fs.writeFileSync(path.join(bin, "docker"), `#!/bin/sh\necho "docker $*" >> "${rep}/appels"\nif [ "$1 $2" = "volume inspect" ]; then echo "${volume}"; exit 0; fi\nexit "$(cat "${rep}/code")"\n`, { mode: 0o755 });
  return { bin, appels: () => (fs.existsSync(path.join(rep, "appels")) ? fs.readFileSync(path.join(rep, "appels"), "utf8").split("\n").filter(Boolean) : []), code: (c) => fs.writeFileSync(path.join(rep, "code"), String(c)) };
}

describe("Revue de sécurité de l'étape 8, CT-8 EX-8.6, EX-10.9 : tâches enveloppées par sonde.mjs releve et jauges des tâches", function () {
  this.timeout(60000);

  it("CT-8 EX-10.9, CT-2 EX-12.36 : avec NOORTRACE_SUPERVISION, TP-4 passe par sonde.mjs releve --check registre_gels : releve-registre_gels.prom (ok 1 quand worm gel liste et chaque gel listé rendent 0, sinon ok 0 et code de la tâche égal à celui de la relecture) et tache-TP-4.prom ; sans NOORTRACE_SUPERVISION, aucune jauge ; mutant (enveloppe retirée) : aucune jauge de relecture, l'oracle échoue", function () {
    const rep = path.join(TRAVAIL, "tp4");
    const m = moteurSimule(rep);
    const sup = path.join(rep, "collecteur");
    const env = { ...process.env, PATH: `${m.bin}:${process.env.PATH}`, NOORTRACE_RACINE: RACINE, NOORTRACE_EXPLOITATION: path.join(rep, "exploitation"), NOORTRACE_SUPERVISION: sup, NOORTRACE_TP4_IDENTIFIANTS: path.join(rep, "lecteur"), NOORTRACE_TP4_GELS: "gel-a gel-b" };
    const executer = path.join(TACHES, "executer-tache.sh");
    let r = bash(executer, ["TP-4"], { env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    const releve = fs.readFileSync(path.join(sup, "releve-registre_gels.prom"), "utf8");
    expect(releve).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 1');
    expect(releve).to.match(/^noortrace_releve_externe_dernier_s\{check="registre_gels"\} [0-9]+(\.[0-9]+)?$/m);
    // CT-2 EX-12.36 : tout le registre est relu (worm gel liste, sans --gel), puis chaque gel listé par ses réglages (worm gel etat --gel).
    const liste = m.appels().filter((a) => a.includes("worm gel liste"));
    expect(liste, "relecture de tout le registre des gels (worm gel liste)").to.have.length(1);
    expect(liste[0]).to.match(/worm gel liste --configuration \/etc\/noortrace\/configuration\.json --identifiants \{"file":"\/run\/noortrace-lecteur\/identifiants"\}$/);
    expect(liste[0]).to.not.contain("--gel");
    expect(m.appels().filter((a) => a.includes("worm gel etat"))).to.have.length(2);
    const tache = fs.readFileSync(path.join(sup, "tache-TP-4.prom"), "utf8");
    expect(tache).to.contain('noortrace_tache_code{task="TP-4"} 0');
    expect(tache).to.match(/^noortrace_tache_derniere_s\{task="TP-4"\} [0-9]{10}$/m);
    // Relecture en échec : le code de la relecture est celui de la tâche (EX-10.9) et la jauge vaut 0.
    m.code(4);
    r = bash(executer, ["TP-4"], { env });
    expect(r.status).to.equal(4);
    expect(fs.readFileSync(path.join(sup, "releve-registre_gels.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 0');
    expect(fs.readFileSync(path.join(sup, "tache-TP-4.prom"), "utf8")).to.contain('noortrace_tache_code{task="TP-4"} 4');
    const lignes = fs.readFileSync(path.join(rep, "exploitation", "taches", "taches.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.map((l) => [l.task, l.exit_code])).to.deep.equal([["TP-4", 0], ["TP-4", 4]]);
    // CT-2 EX-12.36 : NOORTRACE_TP4_GELS est facultatif : sans lui, la seule relecture est celle de tout le registre.
    const rep4 = path.join(TRAVAIL, "tp4-liste-seule");
    const m4 = moteurSimule(rep4);
    r = bash(executer, ["TP-4"], { env: { ...env, PATH: `${m4.bin}:${process.env.PATH}`, NOORTRACE_EXPLOITATION: rep4, NOORTRACE_SUPERVISION: path.join(rep4, "collecteur"), NOORTRACE_TP4_GELS: "" } });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(m4.appels().filter((a) => a.includes("worm gel liste"))).to.have.length(1);
    expect(m4.appels().filter((a) => a.includes("worm gel etat"))).to.deep.equal([]);
    expect(fs.readFileSync(path.join(rep4, "collecteur", "releve-registre_gels.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="registre_gels"} 1');
    // Mutant CT-2 EX-12.36 : la relecture de tout le registre retirée (seuls les gels listés sont relus) : l'oracle échoue.
    const mutantListe = mutantShell(executer, "  noortrace_ctl_lecteur liste || code=$?\n", "");
    const rep5 = path.join(TRAVAIL, "tp4-mutant-liste");
    const m5 = moteurSimule(rep5);
    r = bash(mutantListe, ["TP-4"], { env: { ...env, PATH: `${m5.bin}:${process.env.PATH}`, NOORTRACE_EXPLOITATION: rep5, NOORTRACE_SUPERVISION: path.join(rep5, "collecteur") } });
    expect(r.status).to.equal(0);
    expect(m5.appels().filter((a) => a.includes("worm gel etat"))).to.have.length(2);
    expect(m5.appels().filter((a) => a.includes("worm gel liste")), "mutant : tout le registre n'est pas relu (oracle qui tue le mutant)").to.deep.equal([]);
    fs.rmSync(mutantListe);
    // Sans supervision réglée : même code, aucune jauge.
    const rep2 = path.join(TRAVAIL, "tp4-sans");
    const m2 = moteurSimule(rep2, { code: 4 });
    r = bash(executer, ["TP-4"], { env: { ...env, PATH: `${m2.bin}:${process.env.PATH}`, NOORTRACE_EXPLOITATION: rep2, NOORTRACE_SUPERVISION: "" } });
    expect(r.status).to.equal(4);
    expect(fs.existsSync(path.join(sup, "tache-TP-4.prom"))).to.equal(true);
    expect(fs.readdirSync(rep2).filter((n) => n.endsWith(".prom"))).to.deep.equal([]);
    // Mutant : l'enveloppe de relecture retirée.
    const mutant = mutantShell(executer, 'if [ -n "$supervision" ] && [ "$relecture" -eq 0 ]; then', "if false; then");
    const supM = path.join(TRAVAIL, "tp4-mutant", "collecteur");
    const m3 = moteurSimule(path.join(TRAVAIL, "tp4-mutant"));
    r = bash(mutant, ["TP-4"], { env: { ...env, PATH: `${m3.bin}:${process.env.PATH}`, NOORTRACE_EXPLOITATION: path.join(TRAVAIL, "tp4-mutant", "exploitation"), NOORTRACE_SUPERVISION: supM } });
    expect(r.status).to.equal(0);
    expect(fs.existsSync(path.join(supM, "releve-registre_gels.prom")), "mutant : jauge de relecture absente (oracle qui tue le mutant)").to.equal(false);
  });

  it("CT-8 EX-10.9 : TP-5 (commande du client) passe par releve --check console ; TP-6 copie puis relit par releve --check copie_exploitation ; une relecture de TP-6 en échec donne le code 1 à la tâche", function () {
    const rep = path.join(TRAVAIL, "tp5-tp6");
    const volume = path.join(rep, "volume-exploitation");
    fs.mkdirSync(volume, { recursive: true });
    const ligne = (ts, event) => `${JSON.stringify({ ts, level: "info", component: "noyau", event, data: {} })}\n`;
    fs.writeFileSync(path.join(volume, "exploitation.ndjson"), ligne("2026-11-13T04:00:00.000Z", "courant"));
    fs.writeFileSync(path.join(volume, "exploitation.ndjson.1"), ligne("2026-11-13T03:00:00.000Z", "a") + ligne("2026-11-13T03:59:00.000Z", "b"));
    const m = moteurSimule(rep, { volume });
    const sup = path.join(rep, "collecteur");
    const env = { ...process.env, PATH: `${m.bin}:${process.env.PATH}`, NOORTRACE_RACINE: RACINE, NOORTRACE_EXPLOITATION: path.join(rep, "exploitation"), NOORTRACE_SUPERVISION: sup, NOORTRACE_INSTANCE: "enregistreur-1", NOORTRACE_TP5_COMMANDE: "echo empreintes comparees; exit 0" };
    const executer = path.join(TACHES, "executer-tache.sh");
    let r = bash(executer, ["TP-5"], { env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(r.stdout).to.contain("empreintes comparees");
    expect(fs.readFileSync(path.join(sup, "releve-console.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="console"} 1');
    r = bash(executer, ["TP-5"], { env: { ...env, NOORTRACE_TP5_COMMANDE: "exit 7" } });
    expect(r.status).to.equal(7);
    expect(fs.readFileSync(path.join(sup, "releve-console.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="console"} 0');
    expect(bash(executer, ["TP-5"], { env: { ...env, NOORTRACE_TP5_COMMANDE: "" } }).status, "sans commande du client : 3").to.equal(3);
    r = bash(executer, ["TP-6"], { env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(fs.readFileSync(path.join(sup, "releve-copie_exploitation.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="copie_exploitation"} 1');
    const archive = path.join(rep, "exploitation", "journal-exploitation", "enregistreur-1");
    expect(fs.readFileSync(path.join(archive, "index.ndjson"), "utf8").trim().split("\n")).to.have.length(1);
    // Série altérée après la copie : la relecture échoue, la tâche rend 1 et la jauge vaut 0.
    const idx = lireJSON(path.join(archive, "index.ndjson"));
    fs.appendFileSync(path.join(archive, idx.file), "{}\n");
    r = bash(executer, ["TP-6"], { env });
    expect(r.status).to.equal(1);
    expect(fs.readFileSync(path.join(sup, "releve-copie_exploitation.prom"), "utf8")).to.contain('noortrace_releve_externe_ok{check="copie_exploitation"} 0');
  });
});

describe("Revue de sécurité de l'étape 8, CT-8 IC-16 : poser-taches.sh, propriété de la racine et services de supervision (EX-10.7)", function () {
  this.timeout(60000);

  it("CT-8 IC-16 : une racine dont un composant est inscriptible par le groupe ou dont un script n'appartient pas au compte attendu est refusée (code 2, rien d'écrit) ; une racine saine sous un répertoire à bit collant est admise", function () {
    const base = path.join(TRAVAIL, "racines");
    fs.mkdirSync(base, { mode: 0o700 });
    const saine = path.join(base, "saine");
    fs.mkdirSync(path.join(saine, "deploiement", "taches"), { recursive: true });
    fs.mkdirSync(path.join(saine, "scripts", "deploiement"), { recursive: true });
    for (const f of ["executer-tache.sh", "superviser.sh"]) fs.copyFileSync(path.join(TACHES, f), path.join(saine, "deploiement", "taches", f));
    fs.copyFileSync(path.join(OUTILS, "sonde.mjs"), path.join(saine, "scripts", "deploiement", "sonde.mjs"));
    const poser = path.join(TACHES, "poser-taches.sh");
    const args = (racine, suffixe) => ["--racine", racine, "--taches", "TP-7", "--sortie", path.join(TRAVAIL, `unites-${suffixe}`), "--environnement", path.join(TRAVAIL, `env-${suffixe}`), "--sans-activation"];
    const ok = bash(poser, args(saine, "saine"));
    expect(ok.status, ok.stdout + ok.stderr).to.equal(0);
    // Composant inscriptible par le groupe.
    fs.chmodSync(path.join(saine, "deploiement"), 0o775);
    const g = bash(poser, args(saine, "groupe"));
    expect(g.status).to.equal(2);
    expect(g.stderr).to.match(/^Erreur : --racine : .*\/deploiement inscriptible par le groupe ou les autres \(mode 775\)/);
    expect(fs.existsSync(path.join(TRAVAIL, "unites-groupe"))).to.equal(false);
    fs.chmodSync(path.join(saine, "deploiement"), 0o755);
    // Script exécuté par le superutilisateur, inscriptible par les autres.
    fs.chmodSync(path.join(saine, "scripts", "deploiement", "sonde.mjs"), 0o646);
    const o = bash(poser, args(saine, "autres"));
    expect(o.status).to.equal(2);
    expect(o.stderr).to.contain("sonde.mjs inscriptible par le groupe ou les autres (mode 646)");
    fs.chmodSync(path.join(saine, "scripts", "deploiement", "sonde.mjs"), 0o644);
    // Autre propriétaire (seulement quand l'essai tourne en superutilisateur : il peut alors changer le propriétaire).
    if (process.getuid() === 0) {
      fs.chownSync(path.join(saine, "deploiement", "taches", "executer-tache.sh"), 65534, 65534);
      const p = bash(poser, args(saine, "proprietaire"));
      expect(p.status).to.equal(2);
      expect(p.stderr).to.contain("executer-tache.sh appartient au compte 65534, non au compte 0");
      fs.chownSync(path.join(saine, "deploiement", "taches", "executer-tache.sh"), 0, 0);
    }
    // Racine sous un répertoire à bit collant (comme /tmp) : admise.
    const collant = path.join(TRAVAIL, "collant");
    fs.mkdirSync(collant, { mode: 0o1777 });
    fs.chmodSync(collant, 0o1777);
    const sous = path.join(collant, "racine");
    fs.cpSync(saine, sous, { recursive: true });
    const c = bash(poser, args(sous, "collant"));
    expect(c.status, c.stderr).to.equal(0);
  });

  it("CT-8 EX-10.7 : --supervision pose noortrace-extracteur.service et noortrace-sonde.service (compte noortrace-supervision, superviser.sh, répertoire du collecteur substitué) et règle NOORTRACE_SUPERVISION ; sans --supervision, seules les unités des tâches ; valeur refusée → 2", function () {
    const rep = path.join(TRAVAIL, "pose-supervision");
    const unites = path.join(rep, "unites");
    const env = path.join(rep, "taches.env");
    const collecteur = path.join(rep, "collecteur");
    const poser = path.join(TACHES, "poser-taches.sh");
    const r = bash(poser, ["--racine", RACINE, "--taches", "TP-6", "--sortie", unites, "--environnement", env, "--supervision", collecteur, "--sans-activation"]);
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(fs.readdirSync(unites).sort()).to.deep.equal(["noortrace-extracteur.service", "noortrace-sonde.service", "noortrace-tache@.service", "noortrace-tp6.timer"]);
    const extracteur = fs.readFileSync(path.join(unites, "noortrace-extracteur.service"), "utf8");
    expect(extracteur).to.include("User=noortrace-supervision\n");
    expect(extracteur).to.include(`ExecStart=/bin/bash ${RACINE}/deploiement/taches/superviser.sh extracteur\n`);
    expect(extracteur).to.include(`ReadWritePaths=${collecteur}\n`);
    expect(extracteur).to.include("AmbientCapabilities=CAP_DAC_READ_SEARCH\n");
    expect(extracteur).to.include(`InaccessiblePaths=-${RACINE}/deploiement/secrets\n`);
    expect(extracteur).to.not.include("@");
    const sonde = fs.readFileSync(path.join(unites, "noortrace-sonde.service"), "utf8");
    expect(sonde).to.include("User=noortrace-supervision\n");
    expect(sonde).to.include(`ExecStart=/bin/bash ${RACINE}/deploiement/taches/superviser.sh sonde\n`);
    expect(sonde).to.not.include("CAP_DAC_READ_SEARCH");
    expect(sonde).to.not.include("@");
    expect(fs.readFileSync(env, "utf8")).to.include(`NOORTRACE_SUPERVISION=${collecteur}\n`);
    const sans = bash(poser, ["--racine", RACINE, "--taches", "TP-6", "--sortie", path.join(rep, "unites-sans"), "--environnement", path.join(rep, "env-sans"), "--sans-activation"]);
    expect(sans.status, sans.stderr).to.equal(0);
    expect(fs.readdirSync(path.join(rep, "unites-sans")).sort()).to.deep.equal(["noortrace-tache@.service", "noortrace-tp6.timer"]);
    expect(fs.readFileSync(path.join(rep, "env-sans"), "utf8")).to.include("NOORTRACE_SUPERVISION=/var/lib/noortrace-supervision\n");
    expect(bash(poser, ["--racine", RACINE, "--sortie", path.join(rep, "u3"), "--environnement", path.join(rep, "e3"), "--supervision", "relatif/collecteur", "--sans-activation"]).status).to.equal(2);
  });

  it("CT-8 EX-10.7 : systemd-analyze verify accepte les deux services de supervision", function () {
    if (!commande("systemd-analyze")) {
      enAttente(this, "systemd-analyze absent (systemd du système de référence)");
      return;
    }
    const unites = path.join(TRAVAIL, "pose-supervision", "unites");
    const v = spawnSync("systemd-analyze", ["verify", "--recursive-errors=no", "--man=no", "noortrace-extracteur.service", "noortrace-sonde.service"], { encoding: "utf8", cwd: unites, env: { ...process.env, SYSTEMD_UNIT_PATH: `${unites}:` } });
    const notres = v.stderr.split("\n").filter((l) => /noortrace-(extracteur|sonde)/.test(l));
    expect(v.status, v.stderr).to.equal(0);
    expect(notres, v.stderr).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
// Préparation de l'hôte (CT-8 IC-2, CT-8 CO-8)
// ---------------------------------------------------------------------------

/** Commandes système simulées (même principe que test/deploiement-installation.test.js) ; `node` : version rendue, ou null. */
function hoteSimule(rep, { node = "v22.23.4", uid = 0 } = {}) {
  const bin = path.join(rep, "bin");
  const etat = path.join(rep, "etat");
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(path.join(etat, "services"), { recursive: true });
  for (const s of ["docker", "chrony"]) fs.writeFileSync(path.join(etat, "services", s), "");
  const appels = path.join(rep, "appels");
  const ecrire = (nom, corps) => fs.writeFileSync(path.join(bin, nom), `#!/bin/bash\necho "${nom} $*" >> "${appels}"\n${corps}\n`, { mode: 0o755 });
  ecrire("dpkg-query", `if [ "$1" = "-W" ] && [ "$2" = "-f=\\\${db:Status-Status}" ]; then printf installed; exit 0; fi; for q in "\${@:3}"; do echo "$q 1.0-simule"; done`);
  ecrire("apt-get", "exit 0");
  ecrire("systemctl", `case "$1" in is-enabled|is-active) [ -e "${etat}/services/\${@: -1}" ] ;; *) exit 0 ;; esac`);
  ecrire("chronyc", `if [ "$1" = "-c" ]; then echo "C0A80001,ntp.simule,3,1700000000.0,0.000001,0.000001,0.000001,-1.0,0.0,0.01,0.001,0.001,64.0,Normal"; else echo "Leap status     : Normal"; fi`);
  ecrire("docker", `echo "docker simulé $*"`);
  ecrire("id", `if [ "$1" = "-u" ]; then echo ${uid}; else exit 0; fi`);
  ecrire("findmnt", "echo ext4");
  ecrire("usermod", "exit 0");
  if (node) ecrire("node", `echo ${node}`);
  const osRelease = path.join(rep, "os-release");
  fs.writeFileSync(osRelease, 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n');
  const sysbin = path.join(rep, "sysbin");
  fs.mkdirSync(sysbin, { recursive: true });
  for (const c of ["bash", "sed", "awk", "tr", "cut", "grep", "sha256sum", "tar", "xz", "install", "ln", "uname", "cat", "printf", "date", "dirname", "mkdir", "rm", "env", "sh", "mktemp", "cp", "mv", "chmod", "stat", "readlink"]) {
    const r = spawnSync("/bin/sh", ["-c", `command -v ${c}`], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim().startsWith("/")) fs.symlinkSync(r.stdout.trim(), path.join(sysbin, c));
  }
  return { bin, osRelease, env: { PATH: `${bin}:${sysbin}`, LC_ALL: "C" }, lireAppels: () => (fs.existsSync(appels) ? fs.readFileSync(appels, "utf8").split("\n").filter(Boolean) : []) };
}

describe("Revue de sécurité de l'étape 8, CT-8 IC-2 : preparer-hote.sh (CO-8)", function () {
  this.timeout(60000);

  it("CT-8 IC-2 : un Node.js 22 d'une autre version n'est pas « déjà fait » : simulation « à faire » qui nomme l'écart et la version livrée ; installation sans archive : échec qui nomme l'écart ; v22.23.4 reste « déjà fait »", function () {
    const h = hoteSimule(path.join(TRAVAIL, "ic2-autre-node"), { node: "v22.1.0" });
    const commun = ["--os-release", h.osRelease, "--daemon-json", path.join(TRAVAIL, "ic2-autre-node", "daemon.json"), "--prefixe", path.join(TRAVAIL, "ic2-autre-node", "prefixe")];
    const sim = bash(PREPARER, ["--simulation", ...commun], { env: h.env });
    expect(sim.status, sim.stdout + sim.stderr).to.equal(4);
    expect(sim.stdout).to.match(/^IC-2 node +à faire : Node\.js v22\.1\.0 présent, version livrée v22\.23\.4 absente : --archive-node node-v22\.23\.4-linux-x64\.tar\.xz$/m);
    const r = bash(PREPARER, commun, { env: h.env });
    expect(r.status).to.equal(1);
    expect(r.stdout).to.match(/^IC-2 node +échec : Node\.js v22\.1\.0 présent, version livrée v22\.23\.4 absente ; donner --archive-node/m);
    const exact = hoteSimule(path.join(TRAVAIL, "ic2-node-exact"));
    const e = bash(PREPARER, ["--simulation", "--os-release", exact.osRelease, "--daemon-json", path.join(TRAVAIL, "ic2-node-exact", "daemon.json"), "--prefixe", path.join(TRAVAIL, "ic2-node-exact", "prefixe")], { env: exact.env });
    expect(e.stdout).to.match(/^IC-2 node +déjà fait \(v22\.23\.4\)$/m);
  });

  it("CT-8 IC-2 : l'archive de Node.js est copiée dans un répertoire privé avant son contrôle ; une archive au mauvais SHA-256 est refusée sans rien installer et sans être modifiée ; le répertoire temporaire est retiré", function () {
    const rep = path.join(TRAVAIL, "ic2-archive-copie");
    const h = hoteSimule(rep, { node: null });
    const tmpdir = path.join(rep, "tmp");
    fs.mkdirSync(tmpdir);
    const faux = path.join(rep, "node-v22.23.4-linux-x64.tar.xz");
    fs.writeFileSync(faux, "pas une archive de Node.js");
    const avant = fs.readFileSync(faux);
    const r = bash(PREPARER, ["--os-release", h.osRelease, "--daemon-json", path.join(rep, "daemon.json"), "--prefixe", path.join(rep, "prefixe"), "--archive-node", faux], { env: { ...h.env, TMPDIR: tmpdir } });
    expect(r.status).to.equal(1);
    expect(r.stdout).to.include("archive refusée, rien n'est installé");
    expect(fs.readFileSync(faux).equals(avant)).to.equal(true);
    expect(fs.existsSync(path.join(rep, "prefixe"))).to.equal(false);
    expect(fs.readdirSync(tmpdir), "répertoire privé de la copie retiré").to.deep.equal([]);
    // Le texte du script : la somme et l'extraction portent sur la copie, jamais sur le chemin donné.
    const t = fs.readFileSync(PREPARER, "utf8");
    expect(t).to.include('sha256sum "$copie_node/${NOM_NODE}.tar.xz"');
    expect(t).to.include('tar -xJf "$copie_node/${NOM_NODE}.tar.xz"');
    expect(t).to.not.match(/sha256sum "\$archive_node"/);
    expect(t).to.not.match(/tar -xJf "\$archive_node"/);
  });

  it("un lien symbolique posé dans le répertoire du procès-verbal à la place d'IC-2-docker-version.txt n'est pas suivi : la cible reste intacte, le fichier du procès-verbal est un fichier ordinaire", function () {
    const rep = path.join(TRAVAIL, "ic2-pv-lien");
    const h = hoteSimule(rep);
    const pv = path.join(rep, "pv");
    fs.mkdirSync(pv);
    const cible = path.join(rep, "cible-a-proteger.txt");
    fs.writeFileSync(cible, "intact\n");
    fs.symlinkSync(cible, path.join(pv, "IC-2-docker-version.txt"));
    const r = bash(PREPARER, ["--os-release", h.osRelease, "--daemon-json", path.join(rep, "daemon.json"), "--prefixe", path.join(rep, "prefixe"), "--pv", pv], { env: h.env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(fs.readFileSync(cible, "utf8"), "cible du lien").to.equal("intact\n");
    expect(fs.lstatSync(path.join(pv, "IC-2-docker-version.txt")).isSymbolicLink()).to.equal(false);
    expect(fs.readFileSync(path.join(pv, "IC-2-docker-version.txt"), "utf8")).to.equal("docker simulé version\n");
  });

  it("CT-8 CO-8 : pas moteur : simulation « à faire » ; installation : /etc/docker/daemon.json (ici --daemon-json) écrit avec log-driver json-file et log-opts max-size, max-file, puis systemctl restart docker ; second passage « déjà fait » ; fichier existant sans rotation : échec qui nomme les clés ; mutant (pas retiré) : rien d'écrit, l'oracle échoue", function () {
    const rep = path.join(TRAVAIL, "ic2-moteur");
    const h = hoteSimule(rep);
    const dj = path.join(rep, "docker", "daemon.json");
    const args = ["--os-release", h.osRelease, "--daemon-json", dj, "--prefixe", path.join(rep, "prefixe")];
    const sim = bash(PREPARER, ["--simulation", ...args], { env: h.env });
    expect(sim.status).to.equal(4);
    expect(sim.stdout).to.match(/^IC-2 moteur +à faire : écrire la rotation des journaux dans .*daemon\.json puis relancer docker$/m);
    expect(fs.existsSync(dj)).to.equal(false);
    const r = bash(PREPARER, args, { env: h.env });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(lireJSON(dj)).to.deep.equal({ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "5" } });
    expect(fs.statSync(dj).mode & 0o777).to.equal(0o644);
    expect(h.lireAppels()).to.include("systemctl restart docker");
    expect(r.stdout).to.match(/^IC-2 moteur +fait \(rotation des journaux dans .*, moteur relancé\)$/m);
    const r2 = bash(PREPARER, args, { env: h.env });
    expect(r2.status).to.equal(0);
    expect(r2.stdout).to.match(/^IC-2 moteur +déjà fait/m);
    expect(h.lireAppels().filter((a) => a === "systemctl restart docker")).to.have.length(1);
    // Fichier existant du client, sans rotation : rien n'est réécrit.
    fs.writeFileSync(dj, '{"storage-driver": "overlay2"}\n');
    const e = bash(PREPARER, args, { env: h.env });
    expect(e.status).to.equal(1);
    expect(e.stdout).to.match(/^IC-2 moteur +échec : .*existe sans rotation des journaux : y ajouter "log-driver": "json-file" et "log-opts"/m);
    expect(fs.readFileSync(dj, "utf8")).to.equal('{"storage-driver": "overlay2"}\n');
    // Mutant : le pas moteur ne fait rien (déclare « déjà fait »).
    const mutant = mutantShell(PREPARER, "if journaux_moteur_poses; then", "if true; then");
    fs.rmSync(dj);
    const m = bash(mutant, args, { env: h.env });
    expect(m.status).to.equal(0);
    expect(fs.existsSync(dj), "mutant : daemon.json non écrit (oracle qui tue le mutant)").to.equal(false);
  });
});

// ---------------------------------------------------------------------------
// Modèle de production (IC-14)
// ---------------------------------------------------------------------------

/** Frontaux du modèle qui écoutent hors de la boucle locale avec un jeton (statique ou OAuth) : chacun doit avoir TLS (CT-8 EX-5.3, révision demandée). */
function frontauxEnClair(c) {
  const horsBoucle = (l) => typeof l === "string" && !/^(127\.0\.0\.1|localhost|\[::1\]):/.test(l);
  const sorties = [];
  if (c.mcp?.http && horsBoucle(c.mcp.http.listen) && ((c.mcp.http.static_tokens ?? []).length > 0 || c.mcp.http.oauth !== null) && c.mcp.http.tls === null) sorties.push("mcp.http");
  if (c.model && horsBoucle(c.model.listen) && ((c.model.static_tokens ?? []).length > 0 || (c.model.hosts ?? []).length > 0) && c.model.tls === null) sorties.push("model");
  if (c.otel?.enabled && horsBoucle(c.otel.listen) && c.otel.tls === null) sorties.push("otel");
  return sorties;
}

describe("Revue de sécurité de l'étape 8, CT-8 §8 (IC-14), EX-5.3 : modèle de production", function () {
  const MODELE = path.join(DEP, "config", "modele-production", "configuration.json");
  const SCHEMAS = ["configuration-enregistreur", "politique-redaction", "politique-approbation"].map((n) => lireJSON(path.join(RACINE, "spec", "schemas", `${n}-v0.schema.json`)));

  it("CT-8 EX-5.3 : aucun frontal du modèle n'écoute hors de la boucle locale avec un jeton sans TLS : mcp.http.tls et model.tls désignent les deux secrets TLS déjà montés par production.yaml ; le modèle reste valide pour le démon (validate-config) ; copie altérée (tls nul) : l'oracle la refuse", function () {
    const c = lireJSON(MODELE);
    expect(frontauxEnClair(c)).to.deep.equal([]);
    const tls = { cert_file: "/run/secrets/tls-enregistreur-certificat", key_file: "/run/secrets/tls-enregistreur-cle" };
    expect(c.mcp.http.tls).to.deep.equal(tls);
    expect(c.model.tls).to.deep.equal(tls);
    expect(c.otel.tls).to.deep.equal(tls);
    const compose = fs.readFileSync(path.join(DEP, "compose", "production.yaml"), "utf8");
    for (const s of ["tls-enregistreur-certificat", "tls-enregistreur-cle"]) expect(compose).to.include(`      - ${s}\n`);
    expect(J.validerSchema(c, SCHEMAS[0], { registre: J.registreSchemas(SCHEMAS) })).to.deep.equal([]);
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(c)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    const altere = structuredClone(c);
    altere.mcp.http.tls = null;
    expect(frontauxEnClair(altere)).to.deep.equal(["mcp.http"]);
    altere.model.tls = null;
    expect(frontauxEnClair(altere)).to.deep.equal(["mcp.http", "model"]);
  });

  it("CT-8 IC-14 : la règle « paiement <= 5000 CHF » exige un montant de 0 à 5 000 (un montant négatif ne satisfait aucune règle : règle par défaut) et ouvre une fenêtre (24 h, 10 appels, même bénéficiaire) au lieu d'autoriser d'office ; le modèle reste valide ; mutant (borne retirée) : −250 000 satisfait la règle", function () {
    const c = lireJSON(MODELE);
    const regles = c.policy.approval.rules.rules.filter((r) => r.tools.includes("sap__payments.create"));
    const petit = regles.find((r) => r.name === "paiement <= 5000 CHF");
    expect(petit.level).to.equal("fenetre");
    expect(petit.decision).to.equal(null);
    expect(petit.window).to.deep.equal({ duration_ms: 86400000, max_calls: 10, same_arguments: ["/arguments/beneficiary_iban"] });
    expect(petit.contest_ms).to.equal(0);
    expect(c.policy.approval.rules.default.level).to.equal("revue");
    const vraies = (montant) => regles.filter((r) => valeurCondition(r.when, { arguments: { currency: "CHF", amount: montant } }) === "VRAI").map((r) => `${r.name} (${r.level}${r.decision ? "/" + r.decision : ""})`);
    expect(vraies("100")).to.deep.equal(["paiement <= 5000 CHF (fenetre)"]);
    expect(vraies("5000")).to.deep.equal(["paiement <= 5000 CHF (fenetre)"]);
    expect(vraies("0")).to.deep.equal(["paiement <= 5000 CHF (fenetre)"]);
    expect(vraies("5000.01")).to.deep.equal(["paiement > 5000 CHF (revue)"]);
    for (const m of ["-250000", -250000, "-0.01"]) expect(vraies(m), String(m)).to.deep.equal([]);
    expect(vraies("abc")).to.deep.equal([]);
    expect(J.validerSchema(c, SCHEMAS[0], { registre: J.registreSchemas(SCHEMAS) })).to.deep.equal([]);
    const mutant = structuredClone(c);
    const r = mutant.policy.approval.rules.rules.find((x) => x.name === "paiement <= 5000 CHF");
    r.when.all = r.when.all.filter((p) => p.op !== "superieur_ou_egal");
    expect(valeurCondition(r.when, { arguments: { currency: "CHF", amount: "-250000" } }), "mutant sans borne inférieure : règle satisfaite (oracle qui tue le mutant)").to.equal("VRAI");
  });
});

// ---------------------------------------------------------------------------
// Archivage du journal d'exploitation
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8, CT-8 EX-11.22, EX-11.23 : archiver-journal-exploitation.mjs", function () {
  const ligne = (ts, event) => `${JSON.stringify({ ts, level: "info", event })}\n`;
  function journalTourne(nom, fichiers) {
    const j = path.join(TRAVAIL, nom, "journal");
    fs.mkdirSync(j, { recursive: true });
    const jr = path.join(j, "exploitation.ndjson");
    fs.writeFileSync(jr, ligne("2026-11-13T04:00:00.000Z", "courant"));
    fichiers.forEach((contenu, i) => fs.writeFileSync(`${jr}.${fichiers.length - i}`, contenu));
    return { jr, vers: path.join(TRAVAIL, nom, "archive") };
  }
  const trois = [ligne("2026-11-13T01:00:00.000Z", "startup") + ligne("2026-11-13T01:59:00.000Z", "a"), ligne("2026-11-13T02:00:00.000Z", "config_reloaded") + ligne("2026-11-13T02:59:00.000Z", "b"), ligne("2026-11-13T03:00:00.000Z", "c") + ligne("2026-11-13T03:59:00.000Z", "d")];

  it("(a) index chaîné : chaque ligne porte version 1, son rang et le SHA-256 de la ligne précédente (0x00… pour la première) ; un fichier du milieu retiré avec sa ligne d'index est une discontinuité (rang et empreinte) ; mutant (chaîne non contrôlée) : la relecture dit continu", function () {
    const { jr, vers } = journalTourne("journal-a", trois);
    const r = archiver({ journal: jr, instance: "i1", vers, maintenant: () => "2026-11-13T04:05:00.000Z" });
    expect(r.errors).to.deep.equal([]);
    const rep = path.join(vers, "i1");
    const textes = fs.readFileSync(path.join(rep, "index.ndjson"), "utf8").trim().split("\n");
    const lignes = textes.map((t) => JSON.parse(t));
    expect(lignes.map((l) => [l.version, l.rank])).to.deep.equal([[1, 1], [1, 2], [1, 3]]);
    expect(lignes[0].prev_sha256).to.equal(PREMIERE_EMPREINTE);
    expect(lignes[1].prev_sha256).to.equal(sha(Buffer.from(textes[0], "utf8")));
    expect(lignes[2].prev_sha256).to.equal(sha(Buffer.from(textes[1], "utf8")));
    expect(Object.keys(lignes[0])).to.deep.equal(["version", "rank", "prev_sha256", "file", "sha256", "length", "first_ts", "last_ts", "source", "archived_at"]);
    expect(relireSerie(rep)).to.deep.equal([]);
    fs.rmSync(path.join(rep, lignes[1].file));
    fs.writeFileSync(path.join(rep, "index.ndjson"), `${textes[0]}\n${textes[2]}\n`);
    const ecarts = relireSerie(rep);
    expect(ecarts).to.have.length(2);
    expect(ecarts[0]).to.equal("index.ndjson, ligne 2 : rang 3 au lieu de 2 (ligne retirée ou déplacée)");
    expect(ecarts[1]).to.match(/^index\.ndjson, ligne 2 : empreinte de la ligne précédente 0x[0-9a-f]{64} au lieu de 0x[0-9a-f]{64}$/);
    const v = outil("archiver-journal-exploitation.mjs", ["--verifier", "--instance", "i1", "--vers", vers]);
    expect(v.status).to.equal(1);
    expect(v.stdout).to.include("relecture : discontinu");
    // Mutant : relecture qui ne contrôle pas la chaîne (lignes du même index relues sans rang) → continu.
    const sansChaine = textes.filter((_, i) => i !== 1).map((t) => JSON.stringify({ ...JSON.parse(t), version: 0, rank: undefined, prev_sha256: undefined }));
    fs.writeFileSync(path.join(rep, "index.ndjson"), `${sansChaine.join("\n")}\n`);
    const e0 = relireSerie(rep);
    expect(e0.every((e) => e.includes("sans rang ni empreinte")), "lignes de version 0 : chaîne non vérifiable, signalé (le trou de date ne se voit pas)").to.equal(true);
    expect(e0).to.have.length(2);
  });

  it("(b) reprise après panne : fichier copié sans ligne d'index → adopté au passage suivant (code 1, note « adopté »), puis 0 ; dernière ligne d'index incomplète → écartée, retirée et signalée (code 1), puis 0", function () {
    const { jr, vers } = journalTourne("journal-b", trois);
    const rep = path.join(vers, "i1");
    const fi = path.join(rep, "index.ndjson");
    expect(archiver({ journal: jr, instance: "i1", vers, maintenant: () => "2026-11-13T04:05:00.000Z" }).errors).to.deep.equal([]);
    const textes = fs.readFileSync(fi, "utf8").trim().split("\n");
    // Panne simulée : le troisième fichier est copié, sa ligne d'index n'a pas été écrite.
    fs.writeFileSync(fi, `${textes[0]}\n${textes[1]}\n`);
    let r = outil("archiver-journal-exploitation.mjs", ["--journal", jr, "--instance", "i1", "--vers", vers, "--date", "2026-11-13T04:20:00.000Z"]);
    expect(r.status, r.stderr).to.equal(1);
    expect(r.stdout).to.match(/fichier déjà présent, de mêmes octets, sans ligne d'index : adopté \(reprise après panne\)/);
    const relues = fs.readFileSync(fi, "utf8").trim().split("\n").map((t) => JSON.parse(t));
    expect(relues.map((l) => l.rank)).to.deep.equal([1, 2, 3]);
    expect(relues[2].file).to.equal(JSON.parse(textes[2]).file);
    r = outil("archiver-journal-exploitation.mjs", ["--journal", jr, "--instance", "i1", "--vers", vers, "--date", "2026-11-13T04:35:00.000Z"]);
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(fs.readdirSync(rep).filter((n) => n.startsWith("exploitation-"))).to.have.length(3);
    // Ligne d'index tronquée (panne pendant l'ajout) : écartée et retirée, puis le passage suivant est sain.
    fs.writeFileSync(fi, `${textes[0]}\n${textes[1]}\n${textes[2].slice(0, 40)}`);
    r = outil("archiver-journal-exploitation.mjs", ["--journal", jr, "--instance", "i1", "--vers", vers, "--date", "2026-11-13T04:50:00.000Z"]);
    expect(r.status).to.equal(1);
    expect(r.stdout).to.include("index.ndjson : dernière ligne incomplète (40 caractères) écartée et retirée (reprise après panne)");
    expect(fs.readFileSync(fi, "utf8").trim().split("\n").map((t) => JSON.parse(t).rank)).to.deep.equal([1, 2, 3]);
    r = outil("archiver-journal-exploitation.mjs", ["--journal", jr, "--instance", "i1", "--vers", vers, "--date", "2026-11-13T05:05:00.000Z"]);
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(lireIndex(fi).incomplet).to.equal(null);
  });

  it("(c) un fichier tourné qui est un lien symbolique n'est pas suivi (signalé, non archivé) ; un fichier plus grand que --octets-max est refusé ; un tube nommé est refusé ; un fichier présent au nom calculé avec d'autres octets est signalé", function () {
    const { jr, vers } = journalTourne("journal-c", [ligne("2026-11-13T03:00:00.000Z", "c")]);
    const ailleurs = path.join(TRAVAIL, "journal-c", "ailleurs.ndjson");
    fs.writeFileSync(ailleurs, ligne("2026-11-13T01:00:00.000Z", "contenu_d_un_autre_fichier_de_l_hote"));
    fs.symlinkSync(ailleurs, `${jr}.2`);
    let r = archiver({ journal: jr, instance: "i1", vers, maintenant: () => "2026-11-13T04:05:00.000Z" });
    expect(r.archived).to.have.length(1);
    expect(r.errors).to.deep.equal(["exploitation.ndjson.2 : lien symbolique refusé (jamais suivi), non archivé"]);
    expect(fs.readdirSync(path.join(vers, "i1")).filter((n) => n.startsWith("exploitation-"))).to.have.length(1);
    expect(() => lireFichierTourne(`${jr}.2`)).to.throw(/lien symbolique refusé/);
    expect(() => lireFichierTourne(`${jr}.1`, 10)).to.throw(/plus que --octets-max \(10\), refusé/);
    expect(OCTETS_MAX_DEFAUT).to.equal(1073741824);
    const t = outil("archiver-journal-exploitation.mjs", ["--journal", jr, "--instance", "i2", "--vers", vers, "--octets-max", "10"]);
    expect(t.status).to.equal(1);
    expect(t.stdout).to.match(/exploitation\.ndjson\.1 : [0-9]+ octets, plus que --octets-max \(10\), refusé, non archivé/);
    if (commande("mkfifo")) {
      fs.rmSync(`${jr}.2`);
      expect(spawnSync("mkfifo", [`${jr}.2`]).status).to.equal(0);
      r = archiver({ journal: jr, instance: "i1", vers, maintenant: () => "2026-11-13T04:10:00.000Z" });
      expect(r.errors).to.deep.equal(["exploitation.ndjson.2 : pas un fichier ordinaire (tube, périphérique ou répertoire), refusé, non archivé"]);
      fs.rmSync(`${jr}.2`);
    }
    // Fichier déjà présent au nom calculé, d'autres octets : altération signalée, non adoptée.
    const { jr: jr3, vers: vers3 } = journalTourne("journal-c3", [ligne("2026-11-13T03:00:00.000Z", "c")]);
    const r3 = archiver({ journal: jr3, instance: "i1", vers: vers3, maintenant: () => "2026-11-13T04:05:00.000Z" });
    const nom = r3.archived[0].file;
    fs.writeFileSync(path.join(vers3, "i1", "index.ndjson"), "");
    fs.writeFileSync(path.join(vers3, "i1", nom), "autre contenu\n");
    const r4 = archiver({ journal: jr3, instance: "i1", vers: vers3, maintenant: () => "2026-11-13T04:20:00.000Z" });
    expect(r4.archived).to.deep.equal([]);
    expect(r4.errors[0]).to.equal(`${nom} : déjà présent avec d'autres octets (ou pas un fichier ordinaire), non archivé`);
    expect(archiverPrincipal(["--verifier", "--instance", "i1", "--vers", vers3, "--octets-max", "5"], { stdout: { write() {} }, stderr: { write() {} } })).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// Banc client fictif (CT-8 IC-15), configurer-rapide
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8, banc client fictif et configurer-rapide", function () {
  it("le banc tourne dans son projet Compose noortrace-banc ; installationPresente relève un conteneur, un volume ou un réseau du projet noortrace (moteur simulé) et rien sinon", function () {
    expect(PROJET_BANC).to.equal("noortrace-banc");
    const src = fs.readFileSync(path.join(OUTILS, "banc-client-fictif.mjs"), "utf8");
    expect(src).to.include('"compose", "-p", PROJET_BANC');
    expect(src).to.not.match(/"noortrace_(journal|exports|exploitation)"/);
    const rep = path.join(TRAVAIL, "banc-docker");
    fs.mkdirSync(rep);
    const docker = path.join(rep, "docker");
    fs.writeFileSync(docker, `#!/bin/sh\ncase "$*" in *"label=com.docker.compose.project=noortrace") [ "$1" = volume ] && echo v0lume ;; esac\nexit 0\n`, { mode: 0o755 });
    const avec = spawnSync(process.execPath, ["--input-type=module", "-e", `import { installationPresente } from ${JSON.stringify(path.join(OUTILS, "banc-client-fictif.mjs"))}; console.log(JSON.stringify(installationPresente("noortrace")), JSON.stringify(installationPresente("noortrace-banc")));`], { encoding: "utf8", env: { ...process.env, PATH: `${rep}:${process.env.PATH}` }, cwd: RACINE });
    expect(avec.stdout.trim(), avec.stderr).to.equal('["volume"] []');
    expect(installationPresente("projet-qui-n-existe-pas-l14")).to.deep.equal([]);
  });

  it("le répertoire servi par le pont : créé par le banc, il est retiré au nettoyage (fichiers/, puis le parent seulement s'il l'a créé et qu'il est vide) ; préexistant, il n'est ni retiré ni changé", function () {
    const racine = path.join(TRAVAIL, "srv", "noortrace-outils");
    const B = {};
    if (process.getuid() !== 0) {
      enAttente(this, "superutilisateur requis : préparation du répertoire du pont (chown 10101)");
      return;
    }
    preparerRepertoireOutils(B, racine);
    expect(B).to.deep.equal({ srvParentCree: true, srvCree: true });
    expect(fs.statSync(path.join(racine, "fichiers")).uid).to.equal(10101);
    nettoyerRepertoireOutils(B, racine);
    expect(fs.existsSync(path.dirname(racine))).to.equal(true);
    expect(fs.existsSync(racine)).to.equal(false);
    // Parent préexistant avec un autre outil : seul fichiers/ est retiré.
    fs.mkdirSync(path.join(racine, "autre-outil"), { recursive: true });
    const B2 = {};
    preparerRepertoireOutils(B2, racine);
    expect(B2).to.deep.equal({ srvCree: true });
    nettoyerRepertoireOutils(B2, racine);
    expect(fs.readdirSync(racine)).to.deep.equal(["autre-outil"]);
    // fichiers/ préexistant d'un autre compte : refusé sans chown ; du bon compte : gardé, non retiré.
    fs.mkdirSync(path.join(racine, "fichiers"));
    fs.chownSync(path.join(racine, "fichiers"), 65534, 65534);
    expect(() => preparerRepertoireOutils({}, racine)).to.throw(/appartient au compte 65534, non à 10101/);
    expect(fs.statSync(path.join(racine, "fichiers")).uid).to.equal(65534);
    fs.chownSync(path.join(racine, "fichiers"), 10101, 10101);
    fs.chmodSync(path.join(racine, "fichiers"), 0o700);
    const B3 = {};
    preparerRepertoireOutils(B3, racine);
    expect(B3).to.deep.equal({});
    expect(fs.statSync(path.join(racine, "fichiers")).mode & 0o777, "mode préexistant gardé").to.equal(0o700);
    nettoyerRepertoireOutils(B3, racine);
    expect(fs.existsSync(path.join(racine, "fichiers"))).to.equal(true);
  });

  it("configurer-rapide.mjs sans --ac-horodatage avertit que le document d'ancrage monté reste celui du dépôt (AC de test des vecteurs) ; avec l'AC, aucun avertissement ; codes et fichiers inchangés", function () {
    const sortie = path.join(TRAVAIL, "rapide-configuration.json");
    const r = outil("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", sortie]);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stderr).to.match(/^Avertissement : sans --ac-horodatage et --sortie-ancrage, le document d'ancrage monté par rapide\.yaml reste celui du dépôt, dont le certificat est l'AC de test des vecteurs CT-6 \(clé privée publique\)/);
    expect(fs.readFileSync(sortie, "utf8")).to.equal(fs.readFileSync(path.join(DEP, "config", "rapide", "configuration.json"), "utf8"));
    const ancrage = path.join(TRAVAIL, "rapide-ancrage.json");
    const a = outil("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", `${sortie}.2`, "--ac-horodatage", path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles", "ac-test.pem"), "--sortie-ancrage", ancrage]);
    expect(a.status, a.stderr).to.equal(0);
    expect(a.stderr).to.equal("");
    expect(fs.existsSync(ancrage)).to.equal(true);
  });
});
