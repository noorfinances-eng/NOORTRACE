// Outils des essais des cas de démonstration (CT-9 TE-1 « assurance », TE-2
// « administration ») : la composition de la démonstration de référence avec
// la surcharge demo/cas/compose.cas.yaml, le serveur de console réel de CT-3
// branché sur la prise du canal de la console du service d'approbation (volume
// prise-console du projet), les gestes de préparation (demo/cas/preparer.mjs),
// la vérification hors ligne des dossiers par les deux vérificateurs de CT-6
// dans un espace de noms réseau vide (`unshare -n`), la signature d'une
// attestation de périmètre par les comptes de test, et le paquet réviseur de
// CT-8 §13 (construction, vérification en une commande).
//
// Les personnes dans Chromium, le portefeuille EIP-1193 simulé et le
// fournisseur OIDC simulé sont ceux des essais de la console de l'étape 6
// (test/fixtures/exploitation-console/).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { Composition, DEMO, RACINE, docker, enAttente, etatDocker, pause, portLibre, repertoireTemporaire } from "../demonstration/outils.mjs";

export { DEMO, RACINE, docker, enAttente, pause, portLibre, repertoireTemporaire };

export const CAS_DIR = path.join(DEMO, "cas");
export const CAS = Object.freeze(["assurance", "administration"]);
/** Image de plus que la démonstration de référence : le serveur RFC 3161 interne (CT-8 §7). */
export const IMAGE_TSA = "noortrace/tsa-interne:0.1.0";
export const BIN_CONSOLE = path.join(RACINE, "paquets", "console", "bin", "noortrace-console");
export const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
export const CONSTRUIRE_PAQUET = path.join(RACINE, "scripts", "paquet-reviseur", "construire.mjs");
export const VERIFIER_PAQUET = path.join(RACINE, "scripts", "paquet-reviseur", "verifier.mjs");
export const ATTESTATION = path.join(RACINE, "scripts", "conformite", "attestation.mjs");
export const CLIENT_OIDC = "console-demonstration";

export const sha256 = (octets) => crypto.createHash("sha256").update(octets).digest("hex");

/** Configuration de l'enregistreur du cas. */
export const configurationCas = (cas) => JSON.parse(fs.readFileSync(path.join(CAS_DIR, cas, "configuration-cas.json"), "utf8"));

/** Variables de `cas.env`. */
export function envCas(cas) {
  const env = {};
  for (const l of fs.readFileSync(path.join(CAS_DIR, cas, "cas.env"), "utf8").split("\n")) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(l);
    if (m) env[m[1]] = m[2];
  }
  return env;
}

/** Peut-on jouer un cas ici ? Démon Docker, Compose, les neuf images, openssl ; rend `{ ok }` ou `{ ok: false, condition }`. */
export function etatCas() {
  const e = etatDocker();
  if (!e.ok) return e;
  if (docker(["image", "inspect", "--format", "{{.Id}}", IMAGE_TSA], { timeout: 20000 }).status !== 0) return { ok: false, condition: `image absente du magasin local : ${IMAGE_TSA} (node scripts/deploiement/construire-images.mjs --images tsa-interne)` };
  if (spawnSync("openssl", ["version"], { stdio: "pipe" }).status !== 0) return { ok: false, condition: "openssl absent (matériel TLS de la console et du fournisseur OIDC simulé)" };
  return { ok: true, version: e.version };
}

/** La composition d'un cas : la démonstration de référence avec la surcharge et le fichier de variables du cas. */
export class CompositionCas extends Composition {
  /** @param {{cas: string, nom: string, port: number, travail: string}} o */
  constructor(o) {
    super({ nom: o.nom, port: o.port });
    this.cas = o.cas;
    this.travail = o.travail;
  }

  base(fichier = this.fichier) {
    return ["compose", "-p", this.nom, "--project-directory", DEMO, "--env-file", path.join(CAS_DIR, this.cas, "cas.env"), "-f", fichier, "-f", path.join(CAS_DIR, "compose.cas.yaml")];
  }

  dc(args, o = {}) {
    return super.dc(args, { ...o, env: { NOORTRACE_CAS_TRAVAIL: this.travail, ...(o.env ?? {}) } });
  }

  /** Chemin, sur l'hôte, de la prise du canal de la console du service d'approbation (volume prise-console). */
  priseConsole() {
    const r = docker(["volume", "inspect", "--format", "{{.Mountpoint}}", this.ressource("prise-console")], { timeout: 20000 });
    if (r.status !== 0) throw new Error(`volume prise-console introuvable : ${r.stderr}`);
    return path.join(r.stdout.trim(), "console.sock");
  }

  /** Contexte `cas.json` écrit par l'exploitation dans le volume des exports. */
  contexte() {
    return JSON.parse(this.lireVolume("exports", 'process.stdout.write(require("fs").readFileSync("/v/cas.json","utf8"))'));
  }
}

/** `node demo/cas/preparer.mjs <commande> …` ; rend la ligne JSON. */
export function preparer(commande, { cas, travail, projet, origineConsole = null, issuer = null, port = null }) {
  const args = [path.join(CAS_DIR, "preparer.mjs"), commande, "--cas", cas, "--travail", travail, "--projet", projet];
  if (origineConsole) args.push("--origine-console", origineConsole);
  if (issuer) args.push("--issuer", issuer);
  if (port) args.push("--port-sante", String(port));
  const r = spawnSync(process.execPath, args, { cwd: RACINE, encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 300000 });
  if (r.status !== 0) throw new Error(`preparer.mjs ${commande} : code ${r.status}\n${r.stderr}`);
  return JSON.parse(r.stdout.trim().split("\n").at(-1));
}

/** Lignes JSON d'un texte. */
function lignesJson(texte) {
  const r = [];
  for (const l of texte.split("\n")) {
    if (!l.startsWith("{")) continue;
    try {
      r.push(JSON.parse(l));
    } catch {
      // ligne coupée
    }
  }
  return r;
}

/**
 * Serveur de console réel (`bin/noortrace-console --config`), processus
 * séparé, relié au service d'approbation par la prise de son canal de la
 * console (`service.socket`), identité par le fournisseur OIDC simulé. Rend
 * quand la ligne `pret` est écrite. Même forme que le banc de l'étape 6.
 */
export async function lancerConsoleSurPrise({ dir, port, tls, prise, jeton, issuer, secretClient, reglages = {} }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, "tls-console"), Buffer.concat([tls.cert, tls.key]), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "jeton-service"), `${jeton}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "secret-oidc"), `${secretClient}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "ca.pem"), tls.ca);
  const origine = `https://127.0.0.1:${port}`;
  const config = {
    version: 0,
    environment: "developpement",
    console_origin: origine,
    listen: { host: "127.0.0.1", port },
    tls: { cert: { file: "tls-console" }, key: { file: "tls-console" } },
    service: { url: null, socket: prise, token: { file: "jeton-service" }, ca: null, client_cert: null, client_key: null },
    identity: { kind: "oidc", issuer, client_id: CLIENT_OIDC, client_secret: { file: "secret-oidc" }, id_token_signing_alg_values: ["RS256"] },
    ...reglages,
  };
  const chemin = path.join(dir, "configuration.json");
  fs.writeFileSync(chemin, JSON.stringify(config, null, 2));
  const validation = spawnSync(process.execPath, [BIN_CONSOLE, "valider-configuration", chemin], { encoding: "utf8" });
  if (validation.status !== 0) throw new Error(`configuration de la console refusée : ${validation.stdout}${validation.stderr}`);
  fs.mkdirSync(path.join(dir, "autorites"), { recursive: true });
  const env = { ...process.env, SSL_CERT_FILE: path.join(dir, "ca.pem"), SSL_CERT_DIR: path.join(dir, "autorites") };
  delete env.NODE_EXTRA_CA_CERTS;
  const p = spawn(process.execPath, [BIN_CONSOLE, "--config", chemin], { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"] });
  const c = { processus: p, origine, port, chemin, config, validation, sortie: "", journal: "" };
  p.stdout.on("data", (d) => (c.sortie += d));
  p.stderr.on("data", (d) => (c.journal += d));
  c.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
  const limite = Date.now() + 30000;
  while (!c.sortie.includes('{"pret":true') && p.exitCode === null) {
    if (Date.now() > limite) throw new Error(`serveur de console : pas prêt en 30 s : ${c.journal.slice(-1500)}`);
    await pause(100);
  }
  if (p.exitCode !== null) throw new Error(`serveur de console arrêté au démarrage (code ${p.exitCode}) : ${c.journal.slice(-1500)}`);
  c.pret = JSON.parse(c.sortie.split("\n").find((l) => l.startsWith('{"pret":true')));
  c.lignes = () => lignesJson(c.journal);
  c.arreter = async () => {
    if (p.exitCode === null && p.signalCode === null) p.kill("SIGTERM");
    return c.fin;
  };
  return c;
}

/** Attend qu'une condition (éventuellement asynchrone) rende une valeur vraie, ou lève après `delaiMs`. */
export async function attendre(cond, delaiMs = 30000, description = "condition", pas = 500) {
  const limite = Date.now() + delaiMs;
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() > limite) throw new Error(`${description} : non atteinte en ${delaiMs} ms`);
    await pause(pas);
  }
}

/** `unshare -n` est-il utilisable ici (espace de noms réseau vide pour la vérification hors ligne) ? */
export function sansReseauDisponible() {
  return spawnSync("unshare", ["-n", "true"], { stdio: "pipe" }).status === 0;
}

/**
 * Lance une commande dans un espace de noms réseau vide quand `unshare -n`
 * est disponible, telle quelle sinon ; rend `{ code, stdout, stderr, sans_reseau }`.
 */
export function executerSansReseau(commande, args, o = {}) {
  const sansReseau = sansReseauDisponible();
  const r = sansReseau
    ? spawnSync("unshare", ["-n", commande, ...args], { cwd: o.cwd ?? RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: o.timeout ?? 300000 })
    : spawnSync(commande, args, { cwd: o.cwd ?? RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: o.timeout ?? 300000 });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, sans_reseau: sansReseau };
}

/** Binaire Go de CT-6 (`NOORTRACE_VERIFIER_BIN`), ou null. */
export function binaireGo() {
  const b = process.env.NOORTRACE_VERIFIER_BIN;
  return b && fs.existsSync(b) ? b : null;
}

/**
 * Les deux vérificateurs de CT-6 sur un dossier, sans réseau, lisible et
 * `--json` : `{ js: { lisible, json, rapport }, go: … | null }`.
 */
export function verifierDeuxSansReseau(dossier, { ancres, exiger = null }) {
  const options = ["--ancres", ancres, ...(exiger ? ["--exiger", exiger] : [])];
  const un = (commande, base) => {
    const lisible = executerSansReseau(commande, [...base, dossier, ...options]);
    const json = executerSansReseau(commande, [...base, dossier, ...options, "--json"]);
    return { lisible, json, rapport: json.stdout ? JSON.parse(json.stdout) : null };
  };
  const bin = binaireGo();
  return { js: un(process.execPath, [VERIFICATEUR_JS]), go: bin ? un(bin, []) : null };
}

/** Statut de chaque contrôle (1 à 8) d'un rapport JSON. */
export const controles = (rapport) => Object.fromEntries(rapport.controls.map((c) => [c.number, c.status]));
/** Statut de chaque vérification d'un rapport JSON. */
export const verifications = (rapport) => Object.fromEntries(rapport.checks.map((c) => [c.id, c.status]));
/** Raison d'une vérification ou d'un contrôle. */
export const raison = (rapport, id) => (rapport.checks.find((c) => c.id === id) ?? rapport.controls.find((c) => c.number === id))?.reason ?? null;

/**
 * Attestation de périmètre du cas signée par les comptes de test 1 et 2
 * (`scripts/conformite/attestation.mjs signer` puis `assembler`, boîte noire),
 * et le jeu d'approbateurs qui la vérifie (CT-7 §7.8, CT-8 PR-12). Les clés
 * ne vivent que le temps de la signature, dans des fichiers 0600 du
 * répertoire de travail, puis sont effacées.
 * @param {{attestation: string, cles: Uint8Array[], jeu: object, dir: string}} o
 * @returns {{signee: string, jeu: string}}
 */
export function signerAttestation({ attestation, cles, jeu, dir }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const signatures = [];
  cles.forEach((cle, i) => {
    const fichierCle = path.join(dir, `cle-${i}.hex`);
    fs.writeFileSync(fichierCle, `0x${Buffer.from(cle).toString("hex")}\n`, { mode: 0o600 });
    const r = spawnSync(process.execPath, [ATTESTATION, "signer", attestation, "--cle", `fichier:${fichierCle}`, "--oui"], { cwd: RACINE, encoding: "utf8" });
    fs.rmSync(fichierCle, { force: true });
    if (r.status !== 0) throw new Error(`attestation signer : code ${r.status}\n${r.stdout}\n${r.stderr}`);
    const json = r.stdout.slice(r.stdout.lastIndexOf("\n{"));
    const sig = path.join(dir, `signature-${i}.json`);
    fs.writeFileSync(sig, json.trim() + "\n");
    signatures.push(sig);
  });
  const a = spawnSync(process.execPath, [ATTESTATION, "assembler", attestation, ...signatures], { cwd: RACINE, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (a.status !== 0) throw new Error(`attestation assembler : code ${a.status}\n${a.stdout}\n${a.stderr}`);
  const signee = path.join(dir, "attestation-signee.json");
  fs.writeFileSync(signee, a.stdout.slice(a.stdout.indexOf("{")));
  const fichierJeu = path.join(dir, "jeu-approbateurs.json");
  fs.writeFileSync(fichierJeu, `${JSON.stringify(jeu, null, 2)}\n`);
  return { signee, jeu: fichierJeu };
}

/** `scripts/conformite/attestation.mjs verifier <signée> --jeu <jeu>` : code et sortie. */
export function verifierAttestation(signee, jeu) {
  const r = spawnSync(process.execPath, [ATTESTATION, "verifier", signee, "--jeu", jeu], { cwd: RACINE, encoding: "utf8" });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Construit un paquet réviseur (`construire.mjs`) depuis une description écrite dans `dir` ; rend `{ code, stdout, stderr, paquet, sha256 }`. */
export function construirePaquet({ dir, description, nom = "paquet.tar" }) {
  const fichier = path.join(dir, "description.json");
  fs.writeFileSync(fichier, `${JSON.stringify(description, null, 2)}\n`);
  const paquet = path.join(dir, nom);
  const r = spawnSync(process.execPath, [CONSTRUIRE_PAQUET, "--description", fichier, "--sortie", paquet], { cwd: RACINE, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, paquet, sha256: r.status === 0 ? sha256(fs.readFileSync(paquet)) : null };
}

/** Vérifie un paquet en une commande, sans réseau (`verifier.mjs`), lisible puis `--json` ; rend `{ lisible, json, rapport }`. */
export function verifierPaquetSansReseau(paquet, { ancres = null, empreinte = null, conserver = null, exiger = null }) {
  const options = [...(ancres ? ["--ancres", ancres] : []), ...(empreinte ? ["--empreinte", empreinte] : []), ...(exiger ? ["--exiger", exiger] : [])];
  const lisible = executerSansReseau(process.execPath, [VERIFIER_PAQUET, paquet, ...options, ...(conserver ? ["--conserver", conserver] : [])]);
  const json = executerSansReseau(process.execPath, [VERIFIER_PAQUET, paquet, ...options, "--json"]);
  return { lisible, json, rapport: json.stdout ? JSON.parse(json.stdout) : null };
}

/** Appel d'une méthode du canal de la console du service, sur sa prise (jeton porteur) ; `{ statut, corps }`. */
export function appelCanalConsole(prise, jeton, methode, corps) {
  return new Promise((resoudre, rejeter) => {
    import("node:http").then((http) => {
      const octets = Buffer.from(JSON.stringify(corps), "utf8");
      const req = http.request({ socketPath: prise, method: "POST", path: `/v0/${methode}`, headers: { "content-type": "application/json", "content-length": octets.length, authorization: `Bearer ${jeton}` } }, (rep) => {
        const m = [];
        rep.on("data", (x) => m.push(x));
        rep.on("end", () => {
          try {
            resoudre({ statut: rep.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8")) });
          } catch (e) {
            rejeter(e);
          }
        });
      });
      req.setTimeout(10000, () => req.destroy(new Error("délai du canal de la console")));
      req.on("error", rejeter);
      req.end(octets);
    });
  });
}

/** Mots et formes interdits dans les fichiers des cas (règles de contenu des cas, CT-2 EX-19.1 : rien qui se paie, aucune devise). Chaque motif est nommé sans l'employer. */
export const INTERDITS = Object.freeze([
  { nom: "code de devise ISO", motif: /\b(CHF|EUR|USD|GBP|JPY)\b/ },
  { nom: "symbole monétaire", motif: /[€£¥]|\$\s?[0-9]|[0-9]\s?\$(?!\{)/ },
  { nom: "nombre à deux décimales", motif: /(?<![-.0-9A-Za-z])[0-9]+\.[0-9]{2}(?![0-9.])/ },
  { nom: "mot désignant une somme à payer", motif: /\b(prix|tarif|tarifs|tarification|prime|primes|premium|montant|montants)\b/i },
  { nom: "membre amount ou currency non nul", motif: /"(amount|currency)"\s*:\s*"[^"]/ },
]);
/** Chemins de machine (répertoire personnel, répertoire temporaire de session), nommés par morceaux pour ne pas s'y trouver. */
export const CHEMINS_DE_MACHINE = new RegExp(["/tmp/cl" + "aude", "/home/[a-z]+/", "scr" + "atchpad"].join("|"));
/** Nom d'hôte inventé hors .example/.invalid : précédé d'un séparateur, suivi de rien qui en fasse un identifiant. */
export const DOMAINE_HORS_EXAMPLE = /(?<=["'/@ (])([a-z0-9-]+\.)+(com|net|org|ch|fr|de|io|eu|dev|app)\b(?![.\w]|\s*=)/gi;
/** Adresse IPv4 (hors OID). */
export const ADRESSE_IPV4 = /(?<![0-9.])\b([0-9]{1,3}\.){3}[0-9]{1,3}\b(?![0-9.])/g;

/** Fichiers des cas : tout fichier sous demo/cas/, récursivement. */
export function fichiersDesCas() {
  const out = [];
  const marcher = (d) => {
    for (const n of fs.readdirSync(d).sort()) {
      const p = path.join(d, n);
      if (fs.statSync(p).isDirectory()) marcher(p);
      else out.push(p);
    }
  };
  marcher(CAS_DIR);
  return out;
}
