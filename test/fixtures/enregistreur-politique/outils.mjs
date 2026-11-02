// Outils des tests du moteur de politique (test/enregistreur-politique-*.test.js) :
// service d'approbation simulé d'après CT-3 §12 (versions chargées,
// `politique_inconnue`, mode observation sans ticket, `held`, échéance,
// attente longue de `decisions`, canal HTTP à jeton porteur, pannes
// provoquées), horloge décalée (temps réel plus un décalage que le test fait
// avancer, murale et monotone ensemble), configuration d'un banc (cœur et
// frontal MCP dans le processus, vrai serveur d'outils stdio) et requêtes
// d'un hôte moderne.
//
// Le service simulé n'évalue pas les règles de CT-3 §6 : la décision d'une
// demande sans ticket connu est fixée par une fonction du test (comme le
// service factice du cœur, dont il hérite) ; le reste suit les formes et les
// transitions de CT-3 §7 et §12 que le noyau observe.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { decoderHorodatage, utf8, adresseDepuisClePrivee, hexVersOctets, signerApprobation } from "@noortrace/noyau";
import {
  Coeur, FrontalMcp, ErreurServiceApprobation, analyserJsonIntegral, jcsIntegral, validerConfiguration, controlePolitiqueApprobation, lireEvenements,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice, CLES_HARDHAT } from "@noortrace/enregistreur/factice";
import { configurationMcp, hoteDemo, serveurStdio, reglageOutil, RedacteurTest } from "../enregistreur-mcp/outils.mjs";
import { RACINE, SPEC, repertoireTemporaire, secretsDev } from "../enregistreur-coeur/outils.mjs";

export { hoteDemo, serveurStdio, reglageOutil, RedacteurTest };

export const SERVEUR_OUTILS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "enregistreur-mcp", "serveur-outils.mjs");

/** Membres d'un jeu statique de test : comptes Hardhat 1 à 3 (CT-1 §13), triés. */
export const MEMBRES_TEST = Object.freeze([
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
  "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
]);

/** Politique d'approbation de test, conforme à `politique-approbation-v0` (CT-3 §4). */
export function politiqueApprobationTest(o = {}) {
  return {
    version: 0,
    default: { name: "defaut : autorise", description: null, level: "automatique", decision: "autorise", contest_ms: null },
    rules: [
      {
        name: "paiement hors CHF",
        description: "Les paiements se font en francs suisses.",
        tools: ["demo__payments.create"],
        when: { none: [{ path: "/arguments/currency", op: "egal", value: "CHF" }] },
        level: "automatique",
        decision: "refuse",
        window: null,
        contest_ms: null,
      },
      {
        name: "paiement > 5000 CHF",
        description: "Chaque paiement est approuve au seuil du jeu.",
        tools: ["demo__payments.create"],
        when: { all: [{ path: "/arguments/currency", op: "egal", value: "CHF" }, { path: "/arguments/amount", op: "strictement_superieur", value: "5000" }] },
        level: "revue",
        decision: null,
        window: null,
        contest_ms: 0,
      },
    ],
    approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [...MEMBRES_TEST], threshold: { required: 2, size: 3 } },
    separation: { self_approval: o.self_approval ?? "permise", identities: o.identities ?? [] },
  };
}

/**
 * Décision de test, lue sur les arguments comme la politique ci-dessus :
 * paiement hors CHF refusé, paiement CHF au-delà de 5000 à approuver,
 * autre appel autorisé.
 */
export function deciderTest(r) {
  if (r.tool_announced !== "demo__payments.create") return { decision: "autorise", rule: "defaut : autorise" };
  const a = r.arguments ?? {};
  if (a.currency === undefined) return { decision: "a_approuver", rule: "paiement > 5000 CHF" };
  if (a.currency !== "CHF") return { decision: "refuse", rule: "paiement hors CHF" };
  if (Number(a.amount) > 5000) return { decision: "a_approuver", rule: "paiement > 5000 CHF" };
  return { decision: "autorise", rule: "defaut : autorise" };
}

/**
 * Service d'approbation simulé d'après CT-3 §12 (voir l'en-tête).
 */
export class ServiceSimule extends ServiceApprobationFactice {
  /**
   * @param {{org_id: string, journal_id: string, decider?: Function, jeton?: string|null, nommer?: (n: number) => string}} p
   */
  constructor(p) {
    super({ decider: deciderTest, ...p });
    this.jeton = p.jeton ?? null;
    /** policy_version → membre approval reçu par `charger` (12.2). */
    this.versions = new Map();
    /** Comportements provoqués : `muet` (aucune réponse), `illisible` (HTTP), `reponseForcee` (evaluer). */
    this.muet = false;
    this.illisible = false;
    this.reponseForcee = null;
    this.nommer = p.nommer ?? null;
    /** Re-présentation d'une remise non acquittée (CT-3 T12 : au plus tôt timeout_ms plus tard). */
    this.delaiRepresentation = p.delaiRepresentation ?? 2000;
    this.presentees = new WeakMap();
    this.attentes = [];
  }

  _panne(methode) {
    if (this.muet === true || (Array.isArray(this.muet) && this.muet.includes(methode))) return new Promise(() => {});
    return null;
  }

  async charger(r) {
    const p = this._panne("charger");
    if (p) return p;
    const x = await super.charger(r);
    this.versions.set(r.policy_version, r.approval);
    return x;
  }

  async evaluer(r) {
    const p = this._panne("evaluer");
    if (p) return p;
    if (this.reponseForcee) {
      this.enregistrer("evaluer", r);
      return this.reponseForcee(r);
    }
    // 12.8 : version non chargée.
    if (!this.versions.has(r.code?.policy_version)) {
      this.enregistrer("evaluer", r);
      throw new ErreurServiceApprobation("politique_inconnue");
    }
    // 11.7, EX-12.20 : en observation, aucun ticket, aucun rapprochement.
    if (this.versions.get(r.code.policy_version)?.mode === "observation") {
      this.enregistrer("evaluer", r);
      const d = this.decider(r);
      return { rule: d.rule ?? "defaut : autorise", decision: d.decision, ticket: null, ticket_state: null, approval: null, approver_set: null };
    }
    const cle = `${r.tool_announced}\u0000${jcsIntegral(r.arguments)}`;
    const ticket = this.parDemande.get(cle);
    const t = ticket ? this.tickets.get(ticket) : null;
    // CT-3 EX-11.4 : approbation servie à une requête retenue (held) ; une autre ré-émission attend.
    if (t && t.etat === "approuve" && t.held) {
      this.enregistrer("evaluer", r);
      return { rule: t.rule, decision: "a_approuver", ticket, ticket_state: "en_attente", approval: null, approver_set: null };
    }
    // Après consommation : comme un premier appel (11.3).
    if (t && t.etat === "consomme") this.parDemande.delete(cle);
    return this._nommerNouveau(await super.evaluer(r));
  }

  /**
   * Identifiant d'un ticket nouveau (CT-3 EX-7.1) : `nommer(n)` s'il est
   * donné (rejeu des vecteurs), sinon celui du service factice.
   */
  async _nommerNouveau(x) {
    if (x.ticket_state !== "nouveau" || !this.nommer) return x;
    const id = this.nommer(this.compteur);
    const t = this.tickets.get(x.ticket);
    this.tickets.delete(x.ticket);
    this.tickets.set(id, t);
    for (const [k, v] of this.parDemande) if (v === x.ticket) this.parDemande.set(k, id);
    return { ...x, ticket: id };
  }

  async ouvrir(r) {
    const p = this._panne("ouvrir");
    if (p) return p;
    const x = await super.ouvrir(r);
    const E = this.versions.get(r.request_event?.code?.policy_version)?.expire_after_ms ?? null;
    // EX-7.10 : échéance request_ts + E.
    return { ...x, deadline: E === null ? null : new Date(decoderHorodatage(r.request_ts) + E).toISOString() };
  }

  decider_ticket(ticket, o = {}) {
    const r = super.decider_ticket(ticket, o);
    for (const a of this.attentes.splice(0)) a();
    return r;
  }

  /** Remises présentables : jamais présentées, ou présentées sans acquittement final depuis `delaiRepresentation`. */
  _pretes() {
    return this.fileRemises.filter((x) => this.presentees.get(x) === undefined || Date.now() - this.presentees.get(x) >= this.delaiRepresentation);
  }

  async decisions(r) {
    const p = this._panne("decisions");
    if (p) return p;
    // Attente longue (EX-12.8) : réponse dès qu'une remise est prête (ou
    // redevient présentable), ou au terme de wait_ms.
    const fin = Date.now() + (r.wait_ms ?? 0);
    while (!this._pretes().length && Date.now() < fin) {
      const prochaine = Math.min(fin, ...this.fileRemises.map((x) => (this.presentees.get(x) ?? 0) + this.delaiRepresentation));
      await new Promise((res) => {
        const t = setTimeout(res, Math.max(1, prochaine - Date.now()));
        t.unref?.();
        this.attentes.push(() => {
          clearTimeout(t);
          res();
        });
      });
    }
    // Une remise reste due jusqu'à son acquittement scelle ou refuse ; temporaire,
    // ou perdue avec la connexion, elle est re-présentée (CT-3 T12).
    this.enregistrer("decisions", r);
    const remises = this._pretes();
    for (const x of remises) this.presentees.set(x, Date.now());
    return { remises };
  }

  async acquitter(r) {
    if (r.result === "scelle" || r.result === "refuse") {
      const k = this.fileRemises.findIndex((x) => x.remise_id === r.remise_id);
      if (k >= 0) this.fileRemises.splice(k, 1);
    }
    const x = await super.acquitter(r);
    const t = this.tickets.get(r.ticket);
    if (t && r.result === "scelle") t.held = r.held === true;
    return x;
  }

  /** Relâche les attentes longues (fin de test). */
  liberer() {
    for (const a of this.attentes.splice(0)) a();
  }

  /**
   * Canal HTTP (CT-3 §12.1, CT-2 EX-7.14, EX-18.8) sur 127.0.0.1 : `POST
   * /v0/<méthode>`, JSON strict, jeton porteur exigé s'il est fixé, erreurs
   * de 12.8 ; `illisible` rend un corps qui n'est pas du JSON.
   * @returns {Promise<http.Server>}
   */
  servirHttp(port = 0) {
    const serveur = http.createServer((req, res) => {
      const morceaux = [];
      req.on("data", (m) => morceaux.push(m));
      req.on("end", async () => {
        this.entetes = req.headers;
        const erreur = (statut, code) => res.writeHead(statut, { "content-type": "application/json" }).end(jcsIntegral({ error: { code, message: code, data: {} } }));
        if (this.jeton && req.headers.authorization !== `Bearer ${this.jeton}`) return erreur(401, "requete_invalide");
        if (this.illisible) return res.writeHead(200, { "content-type": "application/json" }).end("{reponse illisible");
        const methode = (req.url ?? "").replace(/^\/v0\//, "");
        if (!["charger", "evaluer", "ouvrir", "decisions", "acquitter", "consommer", "expiration"].includes(methode)) return erreur(404, "requete_invalide");
        try {
          const corps = analyserJsonIntegral(new Uint8Array(Buffer.concat(morceaux)));
          const r = await this[methode](corps);
          res.writeHead(200, { "content-type": "application/json" }).end(jcsIntegral(r));
        } catch (e) {
          erreur(400, e instanceof ErreurServiceApprobation ? e.code : "requete_invalide");
        }
      });
    });
    this.serveurHttp = serveur;
    return new Promise((r) => serveur.listen(port, "127.0.0.1", () => r(serveur)));
  }
}

/**
 * Horloge réelle décalée : murale et monotone avancent avec le temps réel ;
 * `avancer(ms)` les décale ensemble (pas de saut d'EX-7.13) ;
 * `reculerMurale(ms)` recule la murale seule (recul d'EX-7.9).
 */
export class HorlogeDecalee {
  constructor(debut = Date.now()) {
    this.d = debut - Date.now();
    this.dm = 0;
  }

  murale() {
    return Date.now() + this.d;
  }

  monotone() {
    return performance.now() + this.dm + 1_000_000;
  }

  avancer(ms) {
    this.d += ms;
    this.dm += ms;
  }

  reculerMurale(ms) {
    this.d -= ms;
  }
}

/**
 * Configuration d'un banc : celle du frontal MCP des tests (15.3 adaptée),
 * serveur `demo` = vrai serveur d'outils stdio de test, politique
 * d'approbation conforme, mode d'attente choisi.
 * @param {string} dir
 * @param {{mode?: string, version?: string, hold_timeout_ms?: number, expire_after_ms?: number, timeout_ms?: number,
 *   serviceConfig?: object, lectureService?: "passant"|"bloquant", hosts?: object[], tools?: object, limits?: object, socket?: string}} [o]
 */
export function configurationPolitique(dir, o = {}) {
  const outils = {
    "claims.get": reglageOutil({ class: "lecture" }),
    "claims.search": reglageOutil({ class: "lecture" }),
    "payments.create": reglageOutil({
      class: "ecriture",
      timeout_ms: 5000,
      effects: [{ system: "demo", action: "ecriture", object: "/result/structuredContent/payment_id", extract: null, amount: "/arguments/amount", currency: "/arguments/currency" }],
    }),
  };
  const { config, env } = configurationMcp(dir, {
    servers: { demo: serveurStdio([process.execPath, SERVEUR_OUTILS], { tools: outils }) },
    mode: o.mode ?? "erreur",
    hosts: o.hosts,
    limits: o.limits,
    tools: o.tools,
    socket: o.socket,
  });
  const mode = o.mode ?? "erreur";
  config.policy.version = o.version ?? (mode === "observation" ? "test-1-observation" : "test-1");
  config.policy.approval.rules = politiqueApprobationTest();
  config.policy.approval.hold_timeout_ms = o.hold_timeout_ms ?? 1500;
  config.policy.approval.expire_after_ms = o.expire_after_ms ?? 60000;
  config.policy.approval.timeout_ms = o.timeout_ms ?? 500;
  config.policy.approval.service = o.serviceConfig ?? { url: null, socket: null, token: null, peer_user: null };
  config.policy.failure.approval_service = { ecriture: "bloquant", lecture: o.lectureService ?? "passant" };
  config.supervision.ops_log.level = "debug";
  // Passerelle de modèle désactivée : ce banc n'en a pas l'usage, et son port fixe
  // (exemple de 15.3) peut être pris par un autre test en cours.
  config.model.mode = "desactive";
  return { config, env };
}

/** Métadonnées d'une requête moderne (EX-4.4). */
export function meta(extra = {}) {
  return {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": { name: "hote-test", version: "0.1.0" },
    ...extra,
  };
}

/** Ligne `tools/call` d'un hôte moderne. */
export function ligneAppel(id, nom, args, extraMeta = {}) {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, _meta: meta(extraMeta) } });
}

/** Ligne `tools/list` d'un hôte moderne. */
export function ligneListe(id) {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list", params: { _meta: meta() } });
}

/** Lignes du journal d'exploitation d'un nom d'événement. */
export function lignesExploitation(coeur, evenement) {
  return coeur.journal.trouver(evenement);
}

/** Attend qu'une condition soit vraie (au plus `ms`). */
export async function attendre(condition, ms = 5000, pas = 20) {
  const fin = Date.now() + ms;
  for (;;) {
    const v = await condition();
    if (v) return v;
    if (Date.now() > fin) throw new Error("condition non atteinte");
    await new Promise((r) => setTimeout(r, pas));
  }
}

/**
 * Banc d'essai : cœur et frontal MCP dans le processus (horloge décalée,
 * service simulé), vrai serveur d'outils stdio, une session d'hôte moderne
 * qui a reçu la liste servie.
 * @param {object} [o] options de `configurationPolitique`, plus `ajuster(config)`,
 *   `service` (null : aucun service), `horloge`, `minuteurs`, `redacteur`, `correlateur`
 */
export async function monterBanc(o = {}) {
  const dir = o.dir ?? repertoireTemporaire("noortrace-politique-");
  const { config: brut, env } = configurationPolitique(dir, o);
  o.ajuster?.(brut);
  const v = validerConfiguration(utf8(JSON.stringify(brut)), { reglesSupplementaires: [controlePolitiqueApprobation] });
  if (v.erreurs.length) throw new Error(`configuration du banc invalide : ${JSON.stringify(v.erreurs)}`);
  const config = v.config;
  const horloge = o.horloge ?? new HorlogeDecalee();
  const service = o.service === null ? null : (o.service ?? new ServiceSimule({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }));
  const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service, minuteurs: o.minuteurs === true, reglesSupplementaires: [controlePolitiqueApprobation] });
  const frontal = new FrontalMcp({ coeur, redacteur: o.redacteur ?? new RedacteurTest(), correlateur: o.correlateur ?? null });
  await frontal.demarrer();
  if (service && !service.muet) await attendre(() => coeur.candidats !== null);
  const session = frontal.ouvrirSession({ hote: config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio" });
  await frontal.recevoir(session, ligneListe("liste-1"));
  let n = 0;
  const banc = {
    dir,
    env,
    config,
    coeur,
    frontal,
    session,
    service,
    horloge,
    /** Appel `tools/call` ; rend la réponse analysée (null si aucune). */
    async appeler(nom, args, x = {}) {
      const texte = await frontal.recevoir(session, ligneAppel(x.id ?? `h-${++n}`, nom, args, x.meta));
      return texte === null ? null : JSON.parse(texte);
    },
    /** Envoie un appel sans attendre la réponse (rétention). */
    lancer(nom, args, x = {}) {
      const id = x.id ?? `h-${++n}`;
      return { id, reponse: frontal.recevoir(session, ligneAppel(id, nom, args, x.meta)).then((t) => (t === null ? null : JSON.parse(t))) };
    },
    evenements: () => lireEvenements(coeur.repertoire),
    lignes: (e) => coeur.journal.trouver(e),
    async arreter() {
      service?.liberer?.();
      await frontal.arreter().catch(() => {});
      await coeur.arreter().catch(() => {});
      service?.serveurHttp?.close();
    },
  };
  return banc;
}

/** Texte du signal d'approbation (EX-4.49). */
export const texteSignal = (ticket, state) => `noortrace: appel soumis a approbation ; ticket=${ticket} ; state=${state}`;

// ------------------------------------------------------------------------
// Vrai service d'approbation (paquets/approbation, CT-3), lancé comme processus.

export const BIN_APPROBATION = path.join(RACINE, "paquets", "approbation", "bin", "noortrace-approbation");

/** Annuaire de référence des vecteurs de CT-3 (approbateur-1 : compte Hardhat 1, approbateur-2 : compte 2, u.martin : compte 3). */
export const ANNUAIRE_REFERENCE = path.join(SPEC, "vecteurs", "ct-3", "annuaire", "annuaires", "reference.json");

/**
 * Lance `noortrace-approbation --config` (CT-3 §12) : canal du noyau et canal
 * de la console en TCP sur 127.0.0.1, jetons distincts, état chiffré sous
 * `dir`, annuaire de référence de CT-3. Rend quand la ligne `pret` est écrite.
 * @param {string} dir
 * @param {{org_id: string, journal_id: string, remise_representation_ms?: number}} o
 */
export async function lancerServiceApprobation(dir, o) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const env = {
    NOORTRACE_TEST_CLE_APPROBATION: randomBytes(32).toString("hex"),
    NOORTRACE_TEST_JETON_NOYAU: `jeton-noyau-${randomBytes(12).toString("hex")}`,
    NOORTRACE_TEST_JETON_CONSOLE: `jeton-console-${randomBytes(12).toString("hex")}`,
  };
  const annuaire = path.join(dir, "annuaire.json");
  fs.copyFileSync(ANNUAIRE_REFERENCE, annuaire);
  const config = {
    version: 0,
    environment: "developpement",
    org_id: o.org_id,
    journal_id: o.journal_id,
    state_dir: path.join(dir, "etat-service"),
    storage_key: { env: "NOORTRACE_TEST_CLE_APPROBATION" },
    noyau: { tcp: { host: "127.0.0.1", port: 0 }, token: { env: "NOORTRACE_TEST_JETON_NOYAU" } },
    console: { tcp: { host: "127.0.0.1", port: 0 }, token: { env: "NOORTRACE_TEST_JETON_CONSOLE" }, annuaire },
    tickets: { epoch: null },
    remise_representation_ms: o.remise_representation_ms ?? 2000,
  };
  const fichier = path.join(dir, "approbation.json");
  fs.writeFileSync(fichier, JSON.stringify(config, null, 2));
  const p = spawn(process.execPath, [BIN_APPROBATION, "--config", fichier], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  p.sortie = "";
  p.stdout.on("data", (c) => (p.sortie += c));
  p.stderr.on("data", (c) => (p.sortie += c));
  p.fin = new Promise((r) => p.on("exit", (code, signal) => r({ code, signal })));
  const ligne = await attendre(() => p.sortie.split("\n").find((l) => l.startsWith('{"pret":true')), 30000, 50).catch(() => {
    p.kill("SIGKILL");
    throw new Error(`service d'approbation non démarré : ${p.sortie}`);
  });
  const pret = JSON.parse(ligne);
  const annuaireDoc = JSON.parse(fs.readFileSync(annuaire, "utf8"));
  return {
    processus: p,
    jetonNoyau: env.NOORTRACE_TEST_JETON_NOYAU,
    url: `http://127.0.0.1:${pret.noyau.port}`,
    console: `http://127.0.0.1:${pret.console.port}`,
    jetonConsole: env.NOORTRACE_TEST_JETON_CONSOLE,
    org_id: o.org_id,
    journal_id: o.journal_id,
    /** Identité de session dont l'adresse active est `adresse` (annuaire). */
    identite(adresse) {
      const e = annuaireDoc.entries.find((x) => x.active && x.addresses.some((a) => a.state === "active" && a.address === adresse));
      return e?.session_identity ?? null;
    },
    /**
     * Vote d'un approbateur par le canal de la console (CT-3 7.4, 12.9) :
     * signature EIP-191 de l'objet A (CT-1 §6.3) par la clé de test du compte
     * Hardhat `k + 1` (CT-1 §13).
     * @param {{ticket: string, request_hash: string, decision: "approuve"|"refuse", k: number, reason?: string|null}} v
     */
    async voter(v) {
      const cle = hexVersOctets(CLES_HARDHAT[v.k], 32);
      const approver = adresseDepuisClePrivee(cle);
      const A = { decision: v.decision, journal_id: o.journal_id, org_id: o.org_id, request_hash: v.request_hash, ticket: v.ticket };
      const corps = { ticket: v.ticket, approver, decision: v.decision, signature: signerApprobation(cle, A), reason: v.reason ?? null, session_identity: this.identite(approver) };
      return posterJson(`${this.console}/v0/voter`, corps, env.NOORTRACE_TEST_JETON_CONSOLE);
    },
    async arreter() {
      if (p.exitCode === null && p.signalCode === null) p.kill("SIGTERM");
      await p.fin;
    },
  };
}

/** POST JSON avec jeton porteur ; rend { statut, corps }. */
export function posterJson(url, corps, jeton) {
  const u = new URL(url);
  const texte = Buffer.from(JSON.stringify(corps), "utf8");
  return new Promise((resoudre, rejeter) => {
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": texte.length, authorization: `Bearer ${jeton}` } },
      (res) => {
        const m = [];
        res.on("data", (c) => m.push(c));
        res.on("end", () => resoudre({ statut: res.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8") || "null") }));
      },
    );
    req.on("error", rejeter);
    req.end(texte);
  });
}
