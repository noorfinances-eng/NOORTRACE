// Outils des essais de l'export du dossier et des demandes du démon (CT-2
// révision 0.8, §15.7 : EX-15.9 à EX-15.14 ; étape 6) :
//
// - `construireJournal` : journal de test bâti par le cœur réel, en cours de
//   processus, à l'horloge réglable, avec le service d'approbation factice
//   (servi aussi en HTTP pour le démon qui reprend ce journal) : une période
//   close et une ouverte ; un appel approuvé par ticket et relayé, suivi de
//   sa continuation (second événement `executee` qui hérite de
//   l'approbation, EX-4.21) ; des tickets refusé, expiré, approuvé sans
//   relais, non décidé ; un ticket approuvé et relayé dont le jeu
//   d'approbateurs est retiré des fichiers des approbations ;
// - `DemonEssai` : le démon réel (`principal` et `superviserProcessus` de
//   `src/cli.mjs`) dans un processus enfant, à l'horloge réglable
//   (`test/fixtures/enregistreur-ancrage/demon.mjs`), ou le binaire
//   `bin/noortrace` d'un paquet (le dépôt, ou un mutant) à l'horloge du
//   système ;
// - `ctl` : `bin/noortrace-ctl` lancé comme processus (codes de sortie,
//   sorties standard et d'erreur).
//
// Tout fichier va sous `NOORTRACE_TMP` (ou `os.tmpdir()`), jamais dans le
// dépôt ; les clés d'essai sont celles des outils du cœur (graines
// documentées, sans valeur).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Coeur, HorlogeReglable, validerConfiguration, resoudreSecrets, pieceJson } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, RACINE } from "../enregistreur-coeur/outils.mjs";

export { RACINE };
export const PAQUET = path.join(RACINE, "paquets", "enregistreur");
export const BIN_CTL = path.join(PAQUET, "bin", "noortrace-ctl");
export const DEMON_HORLOGE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "enregistreur-ancrage", "demon.mjs");
export const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
export const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();

const DELEGATION = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null };
const JETON_SERVICE = "jeton-approbation-de-test";

/** Répertoire temporaire neuf (préfixe de l'étape 6). */
export function repertoireTemporaire(prefixe = "noortrace-export-") {
  return fs.mkdtempSync(path.join(TMP, prefixe));
}

/** Pause en temps réel. */
export const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/** Attend qu'une condition (éventuellement asynchrone) soit vraie, ou lève après `delaiMs`. */
export async function attendre(cond, delaiMs = 30000, description = "condition") {
  const limite = Date.now() + delaiMs;
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() > limite) throw new Error(`${description} non atteinte en ${delaiMs} ms`);
    await pause(50);
  }
}

/** Lignes du journal d'exploitation (fichier courant et fichiers tournés). */
export function lignesJournal(chemin) {
  const fichiers = [];
  for (let k = 50; k >= 1; k--) if (fs.existsSync(`${chemin}.${k}`)) fichiers.push(`${chemin}.${k}`);
  if (fs.existsSync(chemin)) fichiers.push(chemin);
  return fichiers.flatMap((f) => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
}

/**
 * `bin/noortrace-ctl` comme processus.
 * @returns {Promise<{code: number, stdout: string, stderr: string, ligne: object|null}>}
 */
export function ctl(args, o = {}) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [o.bin ?? BIN_CTL, ...args], { cwd: o.cwd ?? TMP, env: { ...process.env, ...(o.env ?? {}) }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("exit", (code) => {
      let ligne = null;
      try {
        ligne = stdout.trim() ? JSON.parse(stdout.trim().split("\n")[0]) : null;
      } catch {
        ligne = null;
      }
      res({ code, stdout, stderr, ligne });
    });
  });
}

async function echange(coeur, n) {
  const req = pieceJson({ n, messages: [{ role: "user", content: `requete ${n}` }] });
  const rep = pieceJson({ n, content: [{ type: "text", text: `reponse ${n}` }] });
  await coeur.ecrirePiece(req);
  await coeur.ecrirePiece(rep);
  return coeur.scellerEchange({ delegation: DELEGATION, code: { model: "fournisseur/modele-test", prompt_version: null }, intent: null, requete: req.reference, reponse: rep.reference, duration_ms: 10, is_error: false });
}

/**
 * Outil de paiement soumis à revue, tel que le nomme la politique de
 * l'exemple de configuration (CT-2 §15.3, règle « paiement > 5000 CHF ») :
 * nom annoncé, nom d'origine et alias du serveur lus dans cette donnée.
 */
function outilPaiement(config) {
  const annonce = config.policy.approval.rules.rules.find((r) => r.name === "paiement > 5000 CHF").tools[0];
  const [alias, ...reste] = annonce.split("__");
  return { tool_announced: annonce, tool_original: reste.join("__"), server_alias: alias };
}

async function retenue(coeur, outil, claim, montant = "7400.00") {
  const args = { claim_id: claim, amount: montant, currency: "CHF" };
  const p = pieceJson(args);
  await coeur.ecrirePiece(p);
  const capture = { host: { id: "agent-sinistres-stdio" }, delegation: DELEGATION, tool_announced: outil.tool_announced, tool_original: outil.tool_original, server_alias: outil.server_alias, class: "ecriture", arguments: p.reference, context: [], intent: null, code: {} };
  const requete = { tool_announced: outil.tool_announced, tool_original: outil.tool_original, server_alias: outil.server_alias, arguments: args, class: "ecriture", delegation: DELEGATION, intent: null, code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [] };
  const reponse = await coeur.evaluer(requete);
  const r = await coeur.scellerRetenue(capture, reponse, args);
  await pause(20);
  return { ticket: reponse.ticket, evenement: r.evenement, args, capture, requete };
}

async function decider(coeur, service, ticket, o = {}) {
  const acq = await coeur.traiterRemise(service.decider_ticket(ticket, o));
  if (acq.result !== "scelle") throw new Error(`décision non scellée : ${JSON.stringify(acq)}`);
  return acq;
}

async function relayer(coeur, x, claim) {
  const reponse = await coeur.evaluer(x.requete);
  if (reponse.ticket_state !== "approuve") throw new Error(`ticket non approuvé : ${JSON.stringify(reponse)}`);
  const relais = await coeur.preparerRelais(x.capture, { reponse, argumentsEnClair: x.args, upstream_id: `amont-${claim}` });
  const resultat = () => pieceJson({ content: [{ type: "text", text: `ok ${claim}` }], isError: false });
  const executee = await coeur.terminerRelais(relais, { resultat: resultat(), resultatRedige: { content: [{ type: "text", text: `ok ${claim}` }], isError: false }, argumentsRediges: x.args, duration_ms: 3, is_error: false });
  return { relais, executee, resultat };
}

/**
 * Journal de test (voir l'en-tête). La période close est `P` (secondes UNIX,
 * environ trois heures avant l'heure réelle, pour que le démon qui reprend le
 * journal ait une horloge murale en deçà de l'heure réelle : les demandes de
 * `noortrace-ctl` ne sont alors pas périmées) ; l'ouverte, `P + 3600`.
 * @param {string} dir
 * @param {{production?: boolean}} [o]
 */
export async function construireJournal(dir, o = {}) {
  const { config: brut, env: envDev } = configurationDev(dir);
  const outil = outilPaiement(brut);
  brut.exports_dir = path.join(dir, "exports");
  fs.mkdirSync(brut.exports_dir, { recursive: true, mode: 0o750 });
  const P = Math.floor((Date.now() - 3 * 3600000) / 3600000) * 3600;
  const service = new ServiceApprobationFactice({ org_id: brut.recorder.org_id, journal_id: brut.recorder.journal_id, decider: () => ({ decision: "a_approuver", rule: "paiement > 5000 CHF" }) });
  const serveur = await service.servir(0);
  brut.policy.approval.service = { url: `http://127.0.0.1:${serveur.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
  const env = { ...envDev, NOORTRACE_TEST_JETON_APPROBATION: JETON_SERVICE };
  const cheminConfig = path.join(dir, "configuration.json");
  const octets = new TextEncoder().encode(JSON.stringify(brut, null, 2));
  fs.writeFileSync(cheminConfig, octets);
  const v = validerConfiguration(octets);
  if (v.erreurs.length) throw new Error(`configuration de l'essai invalide : ${JSON.stringify(v.erreurs)}`);
  const s = resoudreSecrets(v.config, { env });
  if (s.erreurs.length) throw new Error(`secrets de l'essai : ${JSON.stringify(s.erreurs)}`);
  const horloge = new HorlogeReglable(P * 1000 + 60000);
  const coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, horloge, service });
  const t = {};
  const seqs = {};
  try {
    seqs.echange1 = (await echange(coeur, 1)).seq;
    horloge.avancer(1000);
    // Appel approuvé par ticket, relayé, puis sa continuation (EX-4.21 : même policy et même approval, sans consommer).
    const a = await retenue(coeur, outil, "2026-A");
    t.approuve = a.ticket;
    seqs.retenueApprouve = a.evenement.seq;
    seqs.decisionApprouve = (await decider(coeur, service, a.ticket)).seq;
    horloge.avancer(1000);
    const ra = await relayer(coeur, a, "2026-A");
    seqs.executeApprouve = ra.executee.seq;
    horloge.avancer(1000);
    const continuation = await coeur.terminerRelais({ ...ra.relais, intention: null, ticket: null }, { resultat: ra.resultat(), resultatRedige: { content: [{ type: "text", text: "ok 2026-A" }], isError: false }, argumentsRediges: a.args, duration_ms: 2, is_error: false });
    seqs.continuation = continuation.seq;
    horloge.avancer(1000);
    // Ticket refusé par les approbateurs.
    const b = await retenue(coeur, outil, "2026-B");
    t.refuse = b.ticket;
    seqs.decisionRefuse = (await decider(coeur, service, b.ticket, { decision: "refuse", reason: "montant non justifié" })).seq;
    horloge.avancer(1000);
    // Ticket expiré.
    const c = await retenue(coeur, outil, "2026-C");
    t.expire = c.ticket;
    seqs.decisionExpire = (await decider(coeur, service, c.ticket, { decision: "expire", reason: "echeance atteinte sans decision" })).seq;
    horloge.avancer(1000);
    // Ticket approuvé, jamais relayé.
    const e = await retenue(coeur, outil, "2026-E");
    t.approuveSansRelais = e.ticket;
    await decider(coeur, service, e.ticket);
    horloge.avancer(1000);
    // Ticket approuvé et relayé, dont le jeu d'approbateurs sera retiré des fichiers des approbations.
    const f = await retenue(coeur, outil, "2026-F");
    t.sansJeu = f.ticket;
    await decider(coeur, service, f.ticket);
    seqs.executeSansJeu = (await relayer(coeur, f, "2026-F")).executee.seq;
    horloge.avancer(1000);
    seqs.echange2 = (await echange(coeur, 2)).seq;
    // Clôture de la période P.
    horloge.aller((P + 3600) * 1000 + 300);
    await coeur.tic();
    if (!fs.existsSync(path.join(coeur.repertoire, "manifestes", `periode-${String(P).padStart(10, "0")}.json`))) throw new Error("période P non close");
    // Période ouverte : un ticket non décidé, un appel approuvé et relayé, un échange.
    const d = await retenue(coeur, outil, "2026-D");
    t.nonDecide = d.ticket;
    horloge.avancer(1000);
    const g = await retenue(coeur, outil, "2026-G");
    t.approuveOuvert = g.ticket;
    await decider(coeur, service, g.ticket);
    seqs.executeOuvert = (await relayer(coeur, g, "2026-G")).executee.seq;
    horloge.avancer(1000);
    seqs.echange3 = (await echange(coeur, 3)).seq;
    seqs.dernierClos = seqs.echange2;
  } finally {
    await coeur.arreter();
  }
  // Les remises fabriquées ont été remises au cœur ici ; le démon qui reprend le journal n'en reçoit aucune.
  service.fileRemises.length = 0;
  const repertoire = coeur.repertoire;
  // Jeu d'approbateurs du ticket « sansJeu » retiré (EX-12.23 : remises et décision).
  const dirA = path.join(repertoire, "approbations");
  for (const nom of fs.readdirSync(dirA).filter((n) => n.startsWith("approbations-"))) {
    const f = path.join(dirA, nom);
    const lignes = fs.readFileSync(f, "utf8").split("\n").filter(Boolean);
    const gardees = lignes.filter((l) => {
      const x = JSON.parse(l);
      return !(x.ticket === t.sansJeu && (x.kind === "remise" || x.kind === "decision"));
    });
    fs.writeFileSync(f, gardees.map((l) => `${l}\n`).join(""));
  }
  return {
    dir, config: v.config, env, cheminConfig, repertoire, service, serveur, P, tickets: t, seqs,
    exports: brut.exports_dir, journal: v.config.supervision.ops_log.path, finMs: horloge.murale(),
    fermer: () => new Promise((r) => serveur.close(() => r())),
  };
}

/**
 * Démon réel dans un processus enfant. `horloge` : instant de départ de
 * l'horloge réglable (`demon.mjs`) ; sans lui, `bin/noortrace` du paquet
 * donné (le dépôt par défaut, ou un mutant) à l'horloge du système.
 */
export class DemonEssai {
  constructor({ cheminConfig, env, journal, horloge = null, paquet = PAQUET }) {
    this.cheminConfig = cheminConfig;
    this.env = env;
    this.journal = journal;
    this.horloge = horloge;
    this.paquet = paquet;
    this.sortie = "";
    this.attentes = [];
    this.compteur = 0;
  }

  async demarrer() {
    const args = this.horloge === null ? [path.join(this.paquet, "bin", "noortrace"), "--config", this.cheminConfig] : [DEMON_HORLOGE, "noortrace", "--config", this.cheminConfig];
    const env = { ...process.env, ...this.env, ...(this.horloge === null ? {} : { NOORTRACE_TEST_HORLOGE_BASE_MS: String(this.horloge) }) };
    this.p = spawn(process.execPath, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    this.pid = this.p.pid;
    this.fin = new Promise((r) => this.p.on("exit", (code, signal) => r({ code, signal })));
    this.p.stderr.on("data", (d) => (this.sortie += d));
    let reste = "";
    this.p.stdout.on("data", (d) => {
      this.sortie += this.horloge === null ? d : "";
      if (this.horloge === null) return;
      reste += d;
      let k;
      while ((k = reste.indexOf("\n")) >= 0) {
        const ligne = reste.slice(0, k);
        reste = reste.slice(k + 1);
        try {
          this.attentes.shift()?.(JSON.parse(ligne));
        } catch {
          // ligne non JSON
        }
      }
    });
    if (this.horloge !== null) {
      const premiere = await Promise.race([new Promise((r) => this.attentes.push(r)), this.fin.then((f) => ({ started: false, ...f }))]);
      if (!premiere.started) throw new Error(`démon non démarré : ${JSON.stringify(premiere)}\n${this.sortie}`);
    }
    else await attendre(() => this.p.exitCode === null && /bail acquis/.test(this.sortie), 60000, `démarrage du démon\n${this.sortie}`);
    return this;
  }

  /** Commande du démon à horloge réglable. */
  commande(c, delaiMs = 60000) {
    if (this.horloge === null) throw new Error("commande : démon sans horloge réglable");
    const id = ++this.compteur;
    return new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error(`commande ${c.cmd} sans réponse\n${this.sortie.slice(-2000)}`)), delaiMs);
      this.attentes.push((o) => {
        clearTimeout(t);
        if (o.ok === false) rej(new Error(`commande ${c.cmd} refusée : ${o.erreur}`));
        else res(o);
      });
      this.p.stdin.write(`${JSON.stringify({ ...c, id })}\n`);
    });
  }

  lignes() {
    return lignesJournal(this.journal);
  }

  de(evenement) {
    return this.lignes().filter((l) => l.event === evenement);
  }

  /** Attend une ligne qui satisfait `predicat`. */
  attendreLigne(predicat, delaiMs = 30000, description = "ligne") {
    return attendre(() => this.lignes().find(predicat), delaiMs, `${description}\n${this.sortie.slice(-1500)}`);
  }

  /** Arrêt propre (SIGTERM). */
  async arreter() {
    if (!this.p || this.p.exitCode !== null || this.p.signalCode !== null) return this.fin;
    this.p.kill("SIGTERM");
    const r = await Promise.race([this.fin, pause(30000).then(() => null)]);
    if (r === null) {
      this.p.kill("SIGKILL");
      return this.fin;
    }
    return r;
  }

  /** Arrêt brutal (SIGKILL). */
  async tuer() {
    if (!this.p || this.p.exitCode !== null) return this.fin;
    this.p.kill("SIGKILL");
    return this.fin;
  }
}

/** Écrit un fichier de demande (octets ou objet) comme le ferait une commande, puis envoie SIGURG au démon. */
export function deposerEtSignaler(journal, pid, contenu) {
  const f = `${journal}.rotation-urgence`;
  fs.writeFileSync(f, typeof contenu === "string" || contenu instanceof Uint8Array ? contenu : `${JSON.stringify(contenu)}\n`, { mode: 0o600 });
  process.kill(pid, "SIGURG");
  return f;
}

/** Demande `dossier` complète (EX-15.10, pas 3). */
export function demandeDossier(o) {
  return {
    demande: "dossier",
    selection: o.selection ?? "seq",
    seq: o.seq ?? null,
    ticket: o.ticket ?? null,
    destination: o.destination,
    request_id: o.request_id ?? Buffer.from(Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))).toString("hex"),
    pid: o.pid ?? process.pid,
    at: o.at,
  };
}
