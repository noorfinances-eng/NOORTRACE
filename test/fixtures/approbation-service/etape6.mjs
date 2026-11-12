// Outils des essais du service d'approbation de l'étape 6 (CT-3 révision
// 0.5) : clés des comptes de CT-3 A.2 dérivées au moment de l'essai du
// mnémonique public (`m/44'/60'/0'/0/i`), aucune clé écrite dans le dépôt ;
// configuration `configuration-approbation-v0` et ses secrets tirés au hasard
// dans un répertoire temporaire ; service en processus (`demarrerService`)
// sous une horloge réglable ; récepteur de webhook tiers (Python, bibliothèque
// standard) ; appels HTTP des canaux.

import fs from "node:fs";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { HDNodeWallet } from "ethers";
import * as N from "@noortrace/noyau";
import { chargerConfiguration, demarrerService } from "@noortrace/approbation";
import { ClientServiceApprobation } from "@noortrace/enregistreur";
import { CONSTANTES, ORG_ID, JOURNAL_ID, SESSIONS, VECTEURS_CT3, repertoireTemporaire } from "./outils.mjs";

export const ORIGINE = "https://console.assureur-demo.example";
export const ORG = "assureur-demo";
export const RECEPTEUR = path.join(path.dirname(new URL(import.meta.url).pathname), "recepteur_webhook.py");

const portefeuilles = new Map();

/** Portefeuille du compte i de CT-3 A.2, dérivé du mnémonique public au moment de l'essai. */
export function portefeuille(i) {
  if (!portefeuilles.has(i)) {
    const w = HDNodeWallet.fromPhrase(CONSTANTES.mnemonic, undefined, `m/44'/60'/0'/0/${i}`);
    if (w.address.toLowerCase() !== CONSTANTES.accounts[i - 1].address) throw new Error(`compte ${i} : dérivation différente de CT-3 A.2`);
    portefeuilles.set(i, w);
  }
  return portefeuilles.get(i);
}

/** Adresse du compte i. */
export const adresseDe = (i) => portefeuille(i).address.toLowerCase();

/** Vote EIP-191 du compte i sur D_A (CT-1 §6.3). */
export function signerVoteDerive(i, { decision, ticket, request_hash }) {
  return N.signerApprobation(N.hexVersOctets(portefeuille(i).privateKey, 32), { decision, journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash, ticket });
}

/** Signature `personal_sign` du compte i sur le texte d'un message d'inscription (EX-13.12). */
export function signerTexte(i, texte) {
  return portefeuille(i).signMessageSync(texte).toLowerCase();
}

/** Lit un fichier JSON des vecteurs de CT-3. */
export const vecteur = (rel) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT3, rel), "utf8"));

/** Horloge réglable du service. */
export function horlogeReglable(depart = "2026-11-10T08:00:00.000Z") {
  const h = { t: Date.parse(depart) };
  h.lire = () => h.t;
  h.regler = (iso) => {
    h.t = Date.parse(iso);
  };
  h.avancer = (ms) => {
    h.t += ms;
  };
  return h;
}

/**
 * Écrit une configuration v0.5 et ses secrets (tirés au hasard) sous `dir`.
 * @param {string} dir
 * @param {object} [o] membres remplacés ou ajoutés ; `annuaire` : amorce (chemin) ;
 *   `webhook` : `{ url, ca?, timeout_ms? }` ; `cleWebhook` : clé HMAC imposée ; `etat` : true
 *   pour une écoute d'état
 */
export function configurationEtape6(dir, o = {}) {
  const jetonNoyau = "noyau-" + randomBytes(16).toString("hex");
  const jetonConsole = "console-" + randomBytes(16).toString("hex");
  const cleWebhook = o.cleWebhook ?? randomBytes(32).toString("hex");
  fs.writeFileSync(path.join(dir, "cle-stockage"), randomBytes(32), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "jeton-noyau"), jetonNoyau + "\n", { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "jeton-console"), jetonConsole + "\n", { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "cle-webhook"), cleWebhook + "\n", { mode: 0o600 });
  const doc = {
    version: 0,
    environment: "developpement",
    org: ORG,
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    state_dir: path.join(dir, "service"),
    storage_key: { file: "cle-stockage" },
    noyau: { socket: null, tcp: { host: "127.0.0.1", port: 0 }, tls: null, token: { file: "jeton-noyau" } },
    console: { socket: null, tcp: { host: "127.0.0.1", port: 0 }, tls: null, token: { file: "jeton-console" }, annuaire: o.annuaire ?? null },
    etat: o.etat ? { host: "127.0.0.1", port: 0 } : null,
    tickets: { epoch: o.epoch ?? null },
    max_open_tickets: o.max_open_tickets ?? 20,
    escalation: o.escalation ?? [],
    set_poll_interval_ms: o.set_poll_interval_ms ?? 10000,
    administrators: o.administrators ?? [SESSIONS.admin],
    console_origin: ORIGINE,
    registration_ttl_ms: o.registration_ttl_ms ?? 600000,
    rpc: o.rpc ?? null,
    notifications: o.webhook ? { url: o.webhook.url, key: { file: "cle-webhook" }, ca: o.webhook.ca ? { file: o.webhook.ca } : null, timeout_ms: o.webhook.timeout_ms ?? 2000 } : null,
  };
  const chemin = path.join(dir, "approbation.json");
  fs.writeFileSync(chemin, JSON.stringify(doc, null, 2));
  return { chemin, doc, jetonNoyau, jetonConsole, cleWebhook };
}

/**
 * Service en processus sur une configuration v0.5 (fichier relu par
 * `chargerConfiguration`), horloge réglable.
 * @param {object} [o] options de `configurationEtape6`, plus `dir`, `horloge`, `essais`, `appelRpc`, `garder` (ne pas réécrire la configuration)
 */
export async function serviceEtape6(o = {}) {
  const dir = o.dir ?? repertoireTemporaire("noortrace-etape6-");
  const cfg = o.garder ?? configurationEtape6(dir, o);
  const h = o.horloge ?? horlogeReglable();
  const charge = chargerConfiguration(cfg.chemin);
  const inst = await demarrerService({
    config: charge.config, secrets: charge.secrets, base: charge.base, horloge: h.lire, appelRpc: o.appelRpc,
    essais: { minuterie: false, ...(o.essais ?? {}) },
  });
  const client = new ClientServiceApprobation({ url: `http://127.0.0.1:${inst.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
  const appel = (methode, corps, jeton = cfg.jetonConsole) => appelHttp(inst.console, methode, corps, jeton);
  return { dir, cfg, charge, inst, service: inst.service, client, appel, h, arreter: () => inst.arreter() };
}

/** `POST /v0/<méthode>` d'un canal, jeton porteur ; rend `{ statut, corps }`. */
export async function appelHttp(ecoute, methode, corps, jeton) {
  const r = await fetch(`http://${ecoute.host}:${ecoute.port}/v0/${methode}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(jeton ? { authorization: `Bearer ${jeton}` } : {}) },
    body: typeof corps === "string" ? corps : JSON.stringify(corps),
  });
  return { statut: r.status, corps: await r.json() };
}

/** `GET /v0/etat` d'une écoute. */
export async function etatHttp(ecoute, jeton = null) {
  const r = await fetch(`http://${ecoute.host}:${ecoute.port}/v0/etat`, { headers: jeton ? { authorization: `Bearer ${jeton}` } : {} });
  return { statut: r.status, corps: await r.json() };
}

/** Python 3 est-il disponible ? */
export function pythonDisponible() {
  try {
    execFileSync("python3", ["--version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Lance le récepteur de webhook tiers.
 * @param {{dir: string, cle: string, scenario?: (number|"silence")[], cert?: string, key?: string}} p
 * @returns {Promise<{url: string, port: number, requetes: () => object[], arreter: () => Promise<void>}>}
 */
export function lancerRecepteur(p) {
  const sortie = path.join(p.dir, `recepteur-${randomBytes(4).toString("hex")}.ndjson`);
  const cle = path.join(p.dir, `cle-recepteur-${randomBytes(4).toString("hex")}`);
  fs.writeFileSync(cle, p.cle, { mode: 0o600 });
  const args = ["-I", RECEPTEUR, "--cle", cle, "--sortie", sortie];
  if (p.scenario) {
    const f = path.join(p.dir, `scenario-${randomBytes(4).toString("hex")}.json`);
    fs.writeFileSync(f, JSON.stringify(p.scenario));
    args.push("--scenario", f);
  }
  if (p.cert) args.push("--cert", p.cert, "--key", p.key);
  return new Promise((resoudre, rejeter) => {
    const proc = spawn("python3", args, { stdio: ["ignore", "pipe", "pipe"] });
    let tampon = "";
    let erreurs = "";
    proc.stderr.on("data", (x) => (erreurs += x));
    proc.on("exit", (code) => rejeter(new Error(`récepteur arrêté (${code}) : ${erreurs}`)));
    proc.stdout.on("data", (x) => {
      tampon += x;
      const l = tampon.split("\n")[0];
      if (!l.startsWith("{")) return;
      const { port } = JSON.parse(l);
      resoudre({
        port,
        url: `${p.cert ? "https" : "http"}://127.0.0.1:${port}/noortrace/notifications`,
        requetes: () => (fs.existsSync(sortie) ? fs.readFileSync(sortie, "utf8").split("\n").filter(Boolean).map((y) => JSON.parse(y)) : []),
        arreter: () => new Promise((ok) => {
          proc.removeAllListeners("exit");
          proc.once("exit", () => ok());
          proc.kill("SIGTERM");
        }),
      });
    });
  });
}

/** Lignes du journal du service. */
export function journalService(stateDir) {
  const f = path.join(stateDir, "journal-service.ndjson");
  return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
}

/** Lignes de la boîte d'envoi. */
export function boite(stateDir, suffixe = "") {
  const f = path.join(stateDir, `notifications.ndjson${suffixe}`);
  return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean) : [];
}
