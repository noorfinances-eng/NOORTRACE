// Outils des essais de la page de vérification (CT-6 §18) : chaîne Go
// go1.27.3, constructions (artefact, binaire natif, page), exécution du
// binaire natif dans un répertoire /entrees (EX-18.10), dossiers des
// vecteurs, mise en attente.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const VERSION = "0.1.0";
export const ANCRES = path.join(RACINE, "spec", "vecteurs", "ct-6", "ancres", "ancres-test.json");
export const CHAINE = path.join(RACINE, "spec", "vecteurs", "ct-6", "ots", "entetes", "chaine.json");
export const CONSTRUIRE_PAGE = path.join(RACINE, "paquets", "verification-web", "src", "construire.mjs");

/** Marque l'essai courant en attente avec sa condition dans le titre. */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Répertoire temporaire propre aux essais, à détruire par l'appelant. */
export function repertoireTemporaire(prefixe) {
  const base = process.env.NOORTRACE_TMP ?? os.tmpdir();
  return fs.mkdtempSync(path.join(base, `${prefixe}-`));
}

/**
 * Environnement où `go` est go1.27.3 (répertoire NOORTRACE_GO_BIN, à défaut
 * le PATH), ou null. GOFLAGS est retiré : les scripts posent la recette.
 */
export function environnementGo() {
  const env = { ...process.env, GOTOOLCHAIN: "local" };
  delete env.GOFLAGS;
  if (process.env.NOORTRACE_GO_BIN) env.PATH = `${process.env.NOORTRACE_GO_BIN}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["env", "GOVERSION"], { env: { ...env, GOENV: "off" }, encoding: "utf8" });
  if (v.status !== 0 || v.stdout.trim() !== "go1.27.3") return null;
  return env;
}

/** construire-wasm.sh du dépôt (ou d'une copie du module `verificateur`). */
export function construireArtefact(sortie, env, module = path.join(RACINE, "verificateur")) {
  return execFileSync(path.join(module, "scripts", "construire-wasm.sh"), ["-v", VERSION, "-o", sortie], { env, cwd: module, encoding: "utf8", stdio: "pipe" });
}

/** Binaire natif linux/amd64 de la même construction (EX-14.6). */
export function construireNatif(sortie, env) {
  const module = path.join(RACINE, "verificateur");
  execFileSync(path.join(module, "scripts", "construire.sh"), ["-v", VERSION, "-o", sortie], { env, cwd: module, stdio: "pipe" });
  return sortie;
}

/** construire.mjs : fichiers de la page dans `sortie`. */
export function construirePage(wasm, sortie, script = CONSTRUIRE_PAGE) {
  return execFileSync(process.execPath, [script, "--wasm", wasm, "--version", VERSION, "--sortie", sortie], { encoding: "utf8", stdio: "pipe" });
}

/** Artefact, page et binaire natif construits une fois dans `dir`. */
export function construireTout(dir, env) {
  const wasm = path.join(dir, "wasm");
  const page = path.join(dir, "page");
  construireArtefact(wasm, env);
  construirePage(wasm, page);
  const natif = construireNatif(path.join(dir, "noortrace-verifier"), env);
  return { wasm, page, natif };
}

export const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

/** Les dossiers de spec/vecteurs/ct-1/dossiers et ct-6/dossiers, triés. */
export function dossiersVecteurs() {
  const r = [];
  for (const ct of ["ct-1", "ct-6"]) {
    const base = path.join(RACINE, "spec", "vecteurs", ct, "dossiers");
    for (const n of fs.readdirSync(base).sort()) {
      const p = path.join(base, n);
      if (fs.statSync(p).isDirectory()) r.push({ nom: `${ct}/${n}`, chemin: p });
    }
  }
  return r;
}

/** Fichiers d'un répertoire, chemins relatifs avec « / », triés. */
export function fichiersDe(rep) {
  const r = [];
  const parcourir = (d, rel) => {
    for (const n of fs.readdirSync(d).sort()) {
      const p = path.join(d, n);
      const st = fs.lstatSync(p);
      if (st.isDirectory()) parcourir(p, `${rel}${n}/`);
      else if (st.isFile()) r.push({ chemin: `${rel}${n}`, octets: fs.readFileSync(p) });
      else throw new Error(`entrée qui n'est ni fichier ni répertoire : ${p}`);
    }
  };
  parcourir(rep, "");
  return r;
}

/** Arguments d'EX-18.8, dans l'ordre, sans --json. */
export function argumentsVerification({ ancres, entetes, exiger, langue, detail }) {
  const a = ["dossier"];
  if (ancres) a.push("--ancres", "ancres.json");
  if (entetes) a.push("--entetes-bitcoin", "entetes-bitcoin.json");
  if (exiger) a.push("--exiger", exiger);
  a.push("--langue", langue);
  if (detail) a.push("--detail");
  return a;
}

/**
 * Exécution du binaire natif dans un répertoire /entrees (EX-18.10) : une
 * racine `racine` qui contient le binaire et entrees/, montée comme racine
 * du processus par `unshare --root` (superutilisateur, ou espace de noms
 * d'utilisateur), répertoire de travail /entrees, environnement vide.
 */
export class RacineNatif {
  constructor(racine, binaire) {
    this.racine = racine;
    fs.mkdirSync(path.join(racine, "entrees", "dossier"), { recursive: true });
    fs.copyFileSync(binaire, path.join(racine, "noortrace-verifier"));
    fs.chmodSync(path.join(racine, "noortrace-verifier"), 0o755);
    this.unshare = RacineNatif.commandeUnshare();
  }

  static commandeUnshare() {
    for (const c of ["/usr/bin/unshare", "/bin/unshare"]) {
      if (fs.existsSync(c)) return process.getuid && process.getuid() === 0 ? [c] : [c, "--map-root-user"];
    }
    return null;
  }

  /** Installe le dossier et les fichiers d'option de la configuration. */
  installer(dossier, { ancres, entetes }) {
    const d = path.join(this.racine, "entrees", "dossier");
    fs.rmSync(d, { recursive: true, force: true });
    fs.mkdirSync(d);
    for (const f of fichiersDe(dossier)) {
      fs.mkdirSync(path.dirname(path.join(d, f.chemin)), { recursive: true });
      fs.writeFileSync(path.join(d, f.chemin), f.octets);
    }
    this.option("ancres.json", ancres ? ANCRES : null);
    this.option("entetes-bitcoin.json", entetes ? CHAINE : null);
  }

  /** Installe des fichiers donnés : [{ chemin relatif à /entrees, octets }], répertoires vides compris. */
  installerFichiers(fichiers, repertoires = []) {
    const e = path.join(this.racine, "entrees");
    fs.rmSync(e, { recursive: true, force: true });
    fs.mkdirSync(path.join(e, "dossier"), { recursive: true });
    for (const r of repertoires) fs.mkdirSync(path.join(e, r), { recursive: true });
    for (const f of fichiers) {
      fs.mkdirSync(path.dirname(path.join(e, f.chemin)), { recursive: true });
      fs.writeFileSync(path.join(e, f.chemin), f.octets);
    }
  }

  option(nom, source) {
    const p = path.join(this.racine, "entrees", nom);
    fs.rmSync(p, { force: true });
    if (source) fs.copyFileSync(source, p);
  }

  /** Exécute `noortrace-verifier <args>` ; rend { code, sortie, erreur } (Buffer). */
  executer(args) {
    const r = spawnSync(this.unshare[0], [...this.unshare.slice(1), `--root=${this.racine}`, "--wd=/entrees", "/noortrace-verifier", ...args], {
      env: {},
      maxBuffer: 256 * 1024 * 1024,
    });
    if (r.error) throw r.error;
    return { code: r.status, signal: r.signal, sortie: r.stdout, erreur: r.stderr };
  }
}

/**
 * Le binaire natif s'exécute-t-il dans une racine /entrees ? Rend null, ou la
 * raison de l'échec.
 */
export function essaiRacineNatif(binaire) {
  if (RacineNatif.commandeUnshare() === null) return "unshare absent";
  const dir = repertoireTemporaire("noortrace-racine-essai");
  try {
    const r = new RacineNatif(path.join(dir, "r"), binaire).executer(["--version"]);
    if (r.code !== 0) return `unshare --root : code ${r.code}, ${r.erreur.toString("utf8").trim()}`;
    return null;
  } catch (e) {
    return `unshare --root : ${e.message}`;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
