// Outils des essais de la démonstration de référence (CT-2 §19) :
// test/demonstration.test.js, test/demonstration-composition.test.js et les
// essais TA- qui se jouent sur la démonstration (TA-1, TA-14, TA-18, TA-22).
// La composition est lancée sous un nom de projet propre à l'essai, sur un
// port de santé libre, et démontée avec ses volumes à la fin.

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RACINE = process.env.NOORTRACE_RACINE ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const DEMO = path.join(RACINE, "demo");
export const COMPOSE = path.join(DEMO, "compose.yaml");
export const VERSION = "0.1.0";
/** Images que la composition emploie : six de la démonstration, deux de CT-8. */
export const IMAGES = Object.freeze(["outils-demo", "modele-demo", "agent-demo", "approbateur-demo", "registre-dev", "verificateur-demo", "enregistreur", "approbation"].map((n) => `noortrace/${n}:${VERSION}`));
/** Image qui sert aux essais pour lire un volume (Node.js seul, aucun réseau). */
export const IMAGE_OUTIL = `noortrace/enregistreur:${VERSION}`;

export const pause = (ms) => new Promise((r) => setTimeout(r, ms));

export function docker(args, o = {}) {
  return spawnSync("docker", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: o.timeout ?? 300000, env: { ...process.env, ...(o.env ?? {}) }, input: o.input });
}

/** Marque un essai « en attente » en nommant sa condition (CT-9 EX-3.11). */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/**
 * Dit si la démonstration peut être lancée ici : démon Docker joignable,
 * Compose présent, les huit images dans le magasin local. Rend `{ ok }` ou
 * `{ ok: false, condition }`. Les images se construisent par
 * `node scripts/deploiement/construire-images.mjs` et
 * `node demo/construire-images.mjs`, jamais par un essai.
 */
export function etatDocker() {
  const info = docker(["info", "--format", "{{.ServerVersion}}"], { timeout: 20000 });
  if (info.status !== 0) return { ok: false, condition: "démon Docker injoignable (docker info)" };
  if (docker(["compose", "version", "--short"], { timeout: 20000 }).status !== 0) return { ok: false, condition: "Docker Compose absent" };
  const manquantes = IMAGES.filter((i) => docker(["image", "inspect", "--format", "{{.Id}}", i], { timeout: 20000 }).status !== 0);
  if (manquantes.length) return { ok: false, condition: `image(s) absente(s) du magasin local : ${manquantes.join(", ")} (node scripts/deploiement/construire-images.mjs ; node demo/construire-images.mjs)` };
  return { ok: true, version: info.stdout.trim() };
}

/** Port TCP libre de la boucle locale. */
export function portLibre() {
  return new Promise((resoudre, rejeter) => {
    const s = net.createServer();
    s.once("error", rejeter);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resoudre(port));
    });
  });
}

/** Répertoire temporaire de l'essai (mode 0700), sous NOORTRACE_TMP ou le répertoire temporaire du système. */
export function repertoireTemporaire(prefixe = "noortrace-demonstration-") {
  const base = process.env.NOORTRACE_TMP ?? os.tmpdir();
  fs.mkdirSync(base, { recursive: true });
  const d = fs.mkdtempSync(path.join(base, prefixe));
  fs.chmodSync(d, 0o700);
  return d;
}

/** Un projet Compose de la démonstration, propre à l'essai. */
export class Composition {
  /**
   * @param {{nom: string, port: number, fichier?: string}} o `fichier` : un autre fichier Compose que celui de la
   *   démonstration (mutant), lu avec `demo/` pour répertoire de projet, pour que ses chemins relatifs se résolvent de même.
   */
  constructor(o) {
    this.nom = o.nom;
    this.port = o.port;
    this.fichier = o.fichier ?? COMPOSE;
  }

  /** Arguments communs : projet, répertoire du projet (demo/), fichier. */
  base(fichier = this.fichier) {
    return ["compose", "-p", this.nom, "--project-directory", DEMO, "-f", fichier];
  }

  dc(args, o = {}) {
    return docker([...this.base(o.fichier), ...args], { ...o, env: { NOORTRACE_DEMO_PORT_SANTE: String(this.port), ...(o.env ?? {}) } });
  }

  /** `up --detach` de toute la composition, ou des services nommés. */
  lancer(services = []) {
    const r = this.dc(["up", "--detach", "--quiet-pull", ...services], { timeout: 420000 });
    if (r.status !== 0) throw new Error(`docker compose up en échec (code ${r.status}) :\n${r.stderr.split("\n").slice(-25).join("\n")}`);
    return r;
  }

  /** `docker compose wait <service>` : code de retour du conteneur, ou null si le délai est passé. */
  attendre(service, timeout = 240000) {
    const r = this.dc(["wait", service], { timeout });
    if (r.error || r.status === null) return null;
    // « container "…" exited with status code <n> », et <n> est aussi le code de la commande.
    const m = /exited with status code ([0-9]+)/.exec(r.stdout);
    return m ? Number(m[1]) : r.status;
  }

  /** Sortie standard et d'erreur d'un service, sans préfixe. */
  journal(service) {
    const r = this.dc(["logs", "--no-log-prefix", "--no-color", service], { timeout: 60000 });
    return `${r.stdout}${r.stderr}`;
  }

  /** Identifiant du conteneur d'un service (arrêté compris). */
  conteneur(service) {
    return this.dc(["ps", "--all", "-q", service], { timeout: 60000 }).stdout.trim().split("\n")[0] ?? "";
  }

  /** `docker inspect` du conteneur d'un service. */
  inspecter(service) {
    return JSON.parse(docker(["inspect", this.conteneur(service)]).stdout)[0];
  }

  /** Attend qu'un service soit sain (`healthy`), dans le délai. */
  async sain(service, delaiMs = 180000) {
    const fin = Date.now() + delaiMs;
    for (;;) {
      const id = this.conteneur(service);
      const etat = id ? docker(["inspect", "--format", "{{.State.Health.Status}}", id], { timeout: 20000 }).stdout.trim() : "";
      if (etat === "healthy") return true;
      if (Date.now() > fin) throw new Error(`${service} n'est pas sain après ${delaiMs} ms (état ${etat || "inconnu"}) :\n${this.journal(service).split("\n").slice(-15).join("\n")}`);
      await pause(1000);
    }
  }

  /**
   * Lance un programme Node.js dans un conteneur éphémère d'un service (mêmes image, compte, réseaux et volumes que le
   * service, sans ses dépendances) : `docker compose run --rm --no-deps --entrypoint node <service> -e <script>`.
   * Rend `{ code, stdout, stderr }`.
   */
  executer(service, script, o = {}) {
    const r = this.dc(["run", "--rm", "--no-deps", "-T", "--entrypoint", "/usr/local/bin/node", service, "-e", script], { timeout: o.timeout ?? 120000, fichier: o.fichier });
    return { code: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  /** Nom d'un volume ou d'un réseau du projet. */
  ressource(nom) {
    return `${this.nom}_${nom}`;
  }

  /** Lit un volume du projet par un programme Node.js lancé sous le compte 0, sans réseau, volume en lecture seule sous /v. */
  lireVolume(volume, script, montages = []) {
    const args = ["run", "--rm", "--network", "none", "--user", "0:0", "-v", `${this.ressource(volume)}:/v:ro`];
    for (const [source, cible] of montages) args.push("-v", `${source}:${cible}`);
    const r = docker([...args, "--entrypoint", "/usr/local/bin/node", IMAGE_OUTIL, "-e", script]);
    if (r.status !== 0) throw new Error(`lecture du volume ${volume} en échec : ${r.stderr}`);
    return r.stdout;
  }

  /** Copie un sous-répertoire d'un volume vers un répertoire de l'hôte, rendu au compte de l'essai. */
  extraire(volume, sousRepertoire, destination) {
    fs.mkdirSync(destination, { recursive: true });
    const uid = process.getuid?.() ?? 0;
    const gid = process.getgid?.() ?? 0;
    this.lireVolume(volume, `const fs=require("fs"),p=require("path");fs.cpSync(p.join("/v",${JSON.stringify(sousRepertoire)}),"/c",{recursive:true});const f=(x)=>{fs.chownSync(x,${uid},${gid});if(fs.statSync(x).isDirectory()){fs.chmodSync(x,0o700);for(const n of fs.readdirSync(x))f(p.join(x,n))}};f("/c")`, [[destination, "/c"]]);
    return destination;
  }

  /** Lignes du journal d'exploitation du démon (volume `exploitation`). */
  journalExploitation() {
    const texte = this.lireVolume("exploitation", 'const fs=require("fs");for(const f of fs.readdirSync("/v").filter((n)=>n.endsWith(".ndjson")))process.stdout.write(fs.readFileSync("/v/"+f,"utf8"))');
    return texte.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }

  /** Événements du journal de la démonstration, lus dans les segments (volume `journal`), dans l'ordre. */
  evenements(config) {
    const rep = `${config.recorder.org_id.slice(2)}/${config.recorder.journal_id.slice(2)}/segments`;
    const texte = this.lireVolume("journal", `const fs=require("fs");const d="/v/${rep}";for(const f of fs.readdirSync(d).sort()){const l=fs.readFileSync(d+"/"+f,"utf8").split("\\n").filter(Boolean);for(const x of l.slice(1))console.log(x)}`);
    return texte.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }

  /** `down --volumes` : conteneurs, réseaux et volumes du projet. */
  demonter() {
    return this.dc(["down", "--volumes", "--remove-orphans", "--timeout", "5"], { timeout: 180000 });
  }
}

/** Bloc de code de CT-2 §19.4 (la sortie attendue), ligne par ligne. */
export function sortieDeLaSpecification() {
  const ct2 = fs.readFileSync(path.join(RACINE, "spec", "CT-2-enregistreur.md"), "utf8");
  const bloc = /```text\n([\s\S]*?)```/.exec(ct2.slice(ct2.indexOf("### 19.4 Sortie attendue")));
  return bloc[1].replace(/\n$/, "").split("\n");
}

/** Remplace les valeurs variables d'une ligne de la sortie par un jalon, pour comparer le texte fixe mot pour mot (CT-9 TE-3). */
export function normaliser(ligne) {
  return ligne
    .replace(/: [0-9]+\.[0-9]+\.[0-9]+, clé [a-z0-9-]+ \(classe [A-D]/, ": <version>, clé <clé> (classe <classe>")
    .replace(/bail [a-z]+, époque [0-9]+/, "bail <bail>, époque <n>")
    .replace(/[0-9]+ événements, période [0-9T:Z-]+ → [0-9:Z]+/, "<n> événements, période <début> → <fin>")
    .replace(/bloc certifié par [0-9]+ validateurs/, "bloc certifié par <n> validateurs")
    .replace(/dossiers\/seq-[0-9]+\//, "dossiers/seq-<n>/")
    .replace(/par 0x[0-9a-f]{4}…[0-9a-f]{4} et 0x[0-9a-f]{4}…[0-9a-f]{4}, seuil [0-9]+ sur [0-9]+/, "par <a> et <b>, seuil <k> sur <n>")
    .replace(/[0-9]+ contrôles \[ok\], [0-9]+ non exécutés/, "<n> contrôles [ok], <m> non exécutés")
    .replace(/effacer seq [0-9]+ /, "effacer seq <n> ")
    .replace(/Durée totale : [0-9]+(,[0-9]{3})? s/, "Durée totale : <durée> s");
}

/** Durée imprimée par le vérificateur, en secondes (nombre), ou null. */
export function dureeImprimee(sortie) {
  const m = /^ {2}Durée totale : ([0-9]+),([0-9]{3}) s$/m.exec(sortie);
  return m ? Number(`${m[1]}.${m[2]}`) : null;
}

/** Vérificateur Go de CT-6 (`NOORTRACE_VERIFIER_BIN`, ou `verificateur/dist/`), ou null. */
export function binaireGo() {
  for (const c of [process.env.NOORTRACE_VERIFIER_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")]) if (c && fs.existsSync(c)) return c;
  return null;
}

/** Rapport JSON du vérificateur JavaScript de référence (boîte noire). */
export function verifierJs(dossier, ancres) {
  const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), dossier, "--json", "--ancres", ancres], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

/** Rapport JSON du binaire Go de CT-6 (boîte noire), ou null sans binaire. */
export function verifierGo(dossier, ancres, bin = binaireGo()) {
  if (!bin) return null;
  const r = spawnSync(bin, [dossier, "--json", "--ancres", ancres], { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

/**
 * Copie d'un fichier de `demo/` où un remplacement exact et unique est
 * appliqué (mutant de la composition ou de l'outil de rapprochement, CT-9
 * EX-10.5, EX-10.6) ; lève si la chaîne retirée n'apparaît pas exactement une
 * fois. Rend le chemin de la copie.
 */
export function mutantDeDemo(repertoire, fichier, ancien, nouveau) {
  const texte = fs.readFileSync(path.join(DEMO, fichier), "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant de demo/${fichier} : « ${ancien} » trouvé ${n} fois`);
  const cible = path.join(repertoire, `mutant-${path.basename(fichier)}`);
  fs.writeFileSync(cible, texte.replace(ancien, () => nouveau));
  return cible;
}

/** Empreinte publique d'une clé de fournisseur : 16 premiers chiffres hexadécimaux de son SHA-256 (relevé d'usage du simulateur). */
export const empreinteCle = (valeur) => createHash("sha256").update(valeur).digest("hex").slice(0, 16);

export { spawn };
