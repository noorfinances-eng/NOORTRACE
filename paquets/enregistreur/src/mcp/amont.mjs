// Connexions du frontal MCP vers les serveurs d'outils (CT-2 §4.2, §4.4,
// §4.7) : le frontal est le client MCP de chaque serveur. Il détermine l'ère
// du serveur à la première connexion (EX-4.6 : sonde `server/discover`, repli
// `initialize`, ou ère épinglée), lui envoie des requêtes d'identifiant propre
// (`e-` suivi de douze chiffres, unique par connexion), lit ses réponses dans
// le cadrage de son transport (une ligne par message en stdio, EX-4.31 ;
// corps JSON ou flux SSE en Streamable HTTP, EX-4.36), borne leur taille
// (`limits.response_max_bytes`, 4.4 pas 11), et signale toute perte
// (fin de fichier, fin du processus, connexion coupée : EX-4.33, EX-4.48).
//
// Un serveur stdio est lancé par le démon (EX-3.4), sous l'utilisateur de sa
// configuration (EX-3.5), avec son bac à sable, son environnement (secrets
// résolus) et, si elle est épinglée, la vérification de son exécutable. Sa
// sortie d'erreur n'est pas une erreur ; elle est consignée par empreinte
// (EX-4.32). Les en-têtes envoyés à un serveur HTTP sont construits par le
// frontal, jamais recopiés de l'hôte (EX-4.35, EX-4.41).

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { EventEmitter } from "node:events";
import { sha256Hex } from "@noortrace/noyau";
import { analyserTexte, decoderUtf8Strict, membre, valeurDe, ErreurTexteJson } from "./json-texte.mjs";
import { IDENTITE_TEXTE, VERSION_MODERNE, VERSIONS_HERITEES, notification, requete } from "./messages.mjs";

/** Codes d'erreur reconnus comme modernes (EX-4.6 point 1). */
const ERREURS_MODERNES = new Set([-32020, -32021, -32022]);

/** Erreur : connexion au serveur d'outils impossible (4.4 pas 7, -31014 sans événement). */
export class ErreurConnexionAmont extends Error {
  constructor(alias, raison) {
    super(`serveur d'outils ${alias} injoignable (${raison})`);
    this.name = "ErreurConnexionAmont";
    this.alias = alias;
    this.raison = raison;
  }
}

/**
 * Lit /etc/passwd : utilisateur → { uid, gid }, uid → nom (EX-3.5, EX-4.39).
 * @returns {{parNom: Map<string, {uid: number, gid: number}>, parUid: Map<number, string>}}
 */
export function lireComptes() {
  const parNom = new Map();
  const parUid = new Map();
  try {
    for (const l of fs.readFileSync("/etc/passwd", "utf8").split("\n")) {
      const c = l.split(":");
      if (c.length < 4) continue;
      const uid = Number(c[2]);
      const gid = Number(c[3]);
      if (!Number.isInteger(uid)) continue;
      parNom.set(c[0], { uid, gid });
      if (!parUid.has(uid)) parUid.set(uid, c[0]);
    }
  } catch {
    // système sans /etc/passwd lisible : aucun compte connu
  }
  return { parNom, parUid };
}

/**
 * Objet `_meta` des requêtes du frontal vers un serveur (EX-4.7) : version
 * négociée avec ce serveur, capacités déclarées, identité de l'enregistreur.
 * @param {string} version
 * @param {string} capacitesTexte texte JSON des capacités
 * @param {"discover"|"normal"} [ordre]
 */
export function metaClient(version, capacitesTexte, ordre = "normal") {
  const v = `"io.modelcontextprotocol/protocolVersion":${JSON.stringify(version)}`;
  const c = `"io.modelcontextprotocol/clientCapabilities":${capacitesTexte}`;
  const i = `"io.modelcontextprotocol/clientInfo":${IDENTITE_TEXTE}`;
  return ordre === "discover" ? `{${v},${i},${c}}` : `{${v},${c},${i}}`;
}

/**
 * Connexion à un serveur d'outils : état d'ère, compteur d'identifiants,
 * appels en vol. Les sous-classes fournissent le transport.
 */
export class ConnexionAmont extends EventEmitter {
  /**
   * @param {{alias: string, serveur: object, frontal: object}} p
   */
  constructor(p) {
    super();
    this.alias = p.alias;
    this.serveur = p.serveur;
    this.frontal = p.frontal;
    this.ere = null;
    this.version = null;
    this.connectee = false;
    this.compteur = p.compteurInitial ?? 0;
    /** id amont → { resoudre, surNotification } */
    this.enVol = new Map();
    this.capacitesTexte = "{}";
  }

  get journal() {
    return this.frontal.journal;
  }

  /** Identifiant amont suivant (4.4 pas 9). */
  prochainId() {
    this.compteur++;
    return `e-${String(this.compteur).padStart(12, "0")}`;
  }

  /** `_meta` sortant pour cette connexion. */
  meta(capacitesTexte, ordre) {
    return metaClient(this.version ?? VERSION_MODERNE, capacitesTexte ?? this.capacitesTexte, ordre);
  }

  /** Instant monotone. */
  maintenant() {
    return this.frontal.monotone();
  }

  /**
   * Détermine l'ère (EX-4.6) d'une connexion qui vient de s'établir.
   * @param {string} capacitesTexte capacités de la première requête d'hôte (EX-4.7)
   */
  async _negocier(capacitesTexte) {
    this.capacitesTexte = capacitesTexte;
    const protocole = this.serveur.protocol ?? "auto";
    if (protocole === VERSION_MODERNE) {
      this.ere = "moderne";
      this.version = VERSION_MODERNE;
      this._ecouter();
      return;
    }
    if (protocole === "auto") {
      const id = this.prochainId();
      const r = await this.requeteInterne(id, requete(id, "server/discover", `{"_meta":${metaClient(VERSION_MODERNE, capacitesTexte, "discover")}}`), this.frontal.config.mcp.discover_timeout_ms);
      const res = r?.objet?.result;
      if (res && Array.isArray(res.supportedVersions)) {
        if (!res.supportedVersions.includes(VERSION_MODERNE)) throw new ErreurConnexionAmont(this.alias, "version_moderne_non_prise_en_charge");
        this.ere = "moderne";
        this.version = VERSION_MODERNE;
        this._ecouter();
        return;
      }
      const code = r?.objet?.error?.code;
      if (r && ERREURS_MODERNES.has(code)) throw new ErreurConnexionAmont(this.alias, "erreur_moderne_a_la_sonde");
      // Toute autre erreur, ou aucune réponse dans le délai : ère héritée.
    }
    await this._initialiser(capacitesTexte);
  }

  async _initialiser(capacitesTexte) {
    const id = this.prochainId();
    const r = await this.requeteInterne(
      id,
      requete(id, "initialize", `{"protocolVersion":${JSON.stringify(VERSIONS_HERITEES[0])},"capabilities":${capacitesTexte},"clientInfo":${IDENTITE_TEXTE}}`),
      this.frontal.config.mcp.discover_timeout_ms,
    );
    const v = r?.objet?.result?.protocolVersion;
    if (!VERSIONS_HERITEES.includes(v)) throw new ErreurConnexionAmont(this.alias, "initialize_refuse");
    this.ere = "heritee";
    this.version = v;
    this.envoyerNotification(notification("notifications/initialized", null));
  }

  /** `subscriptions/listen` vers un serveur moderne (EX-4.15). */
  _ecouter() {
    const id = this.prochainId();
    this.idEcoute = id;
    this.envoyerNotification(requete(id, "subscriptions/listen", `{"toolsListChanged":true,"_meta":${this.meta()}}`));
  }

  /**
   * Réponse amont arrivée pour un id connu, ou notification, ou requête.
   * @param {string} texte ligne ou données SSE
   * @param {object} noeud
   * @param {number} t instant monotone
   */
  _message(texte, noeud, t) {
    const objet = valeurDe(noeud);
    const id = membre(noeud, "id");
    const methode = membre(noeud, "method");
    if (id && (membre(noeud, "result") || membre(noeud, "error")) && !methode) {
      const cle = id.t === "chaine" ? id.valeur : texte.slice(id.d, id.f);
      const a = this.enVol.get(cle);
      if (a) {
        this.enVol.delete(cle);
        a.resoudre({ issue: "reponse", texte, noeud, objet, t });
      } else {
        this.journal.consigner("info", "frontal_mcp", "late_response", { server: this.alias, sha256: sha256Hex(new TextEncoder().encode(texte)) });
      }
      return;
    }
    if (methode?.t === "chaine" && id) {
      // Requête du serveur vers le client (ère héritée, 4.6) : non relayée.
      this.journal.consigner("warning", "frontal_mcp", "server_request_refused", { server: this.alias, method: methode.valeur });
      this.envoyerNotification(`{"jsonrpc":"2.0","id":${texte.slice(id.d, id.f)},"error":{"code":-32601,"message":"Method not found"}}`);
      return;
    }
    if (methode?.t === "chaine") {
      this.emit("notification", { methode: methode.valeur, texte, noeud, objet, t });
    }
  }

  /** Ligne amont invalide (EX-4.43, 4.4 pas 11) : ignorée et consignée. */
  _ligneInvalide(raison) {
    this.journal.consigner("warning", "frontal_mcp", "invalid_line", { server: this.alias, reason: raison });
  }

  /** Toutes les attentes en vol finissent par une perte (EX-4.33). */
  _perte(raison) {
    const t = this.maintenant();
    this.connectee = false;
    this.ere = this.serveur.protocol === "auto" ? null : this.ere;
    const enVol = [...this.enVol.values()];
    this.enVol.clear();
    for (const a of enVol) a.resoudre({ issue: "perte", t });
    this.emit("perte", { raison, t });
  }

  /**
   * Attend la réponse d'un id (ou une perte, une taille dépassée).
   * @param {string} id
   * @returns {Promise<object>}
   */
  attendre(id) {
    return new Promise((resoudre) => this.enVol.set(id, { resoudre }));
  }

  /** Abandonne l'attente d'un id (délai, annulation). */
  oublier(id) {
    this.enVol.delete(id);
  }

  /** Requête interne (sonde, poignée de main, liste) avec délai. */
  async requeteInterne(id, texte, delai) {
    const attente = this.attendre(id);
    this.envoyerRequete(texte, { id });
    let minuteur;
    const r = await Promise.race([attente, new Promise((res) => (minuteur = this.frontal.planifier(delai, () => res(null))))]);
    this.frontal.annulerMinuteur(minuteur);
    if (r === null) this.oublier(id);
    if (r?.issue !== "reponse") return null;
    return r;
  }

  /**
   * Liste complète des outils du serveur (EX-4.13) : toutes les pages, dans
   * les bornes `tools_list_max_pages` et `tools_list_max_items`.
   * @returns {Promise<{tools: object[], ttlMs: number|null, cacheScope: string|null}>}
   */
  async lister() {
    const lim = this.frontal.config.limits;
    const outils = [];
    let curseur = null;
    let ttlMs = null;
    let cacheScope = null;
    for (let page = 0; ; page++) {
      if (page >= lim.tools_list_max_pages) throw new ErreurConnexionAmont(this.alias, "liste_trop_longue");
      const id = this.prochainId();
      const params = this.ere === "moderne"
        ? `{${curseur === null ? "" : `"cursor":${JSON.stringify(curseur)},`}"_meta":${this.meta()}}`
        : curseur === null ? "{}" : `{"cursor":${JSON.stringify(curseur)}}`;
      const r = await this.requeteInterne(id, requete(id, "tools/list", params), this.frontal.delaiOutil(this.alias, null));
      const res = r?.objet?.result;
      if (!res || !Array.isArray(res.tools)) throw new ErreurConnexionAmont(this.alias, "liste_illisible");
      outils.push(...res.tools.filter((x) => x !== null && typeof x === "object" && !Array.isArray(x)));
      if (outils.length > lim.tools_list_max_items) throw new ErreurConnexionAmont(this.alias, "liste_trop_longue");
      if (typeof res.ttlMs === "number") ttlMs = ttlMs === null ? res.ttlMs : Math.min(ttlMs, res.ttlMs);
      if (res.cacheScope === "private") cacheScope = "private";
      else if (cacheScope === null && typeof res.cacheScope === "string") cacheScope = res.cacheScope;
      if (typeof res.nextCursor !== "string") break;
      curseur = res.nextCursor;
    }
    return { tools: outils, ttlMs, cacheScope };
  }
}

/**
 * Lanceur par défaut d'un serveur stdio : `spawn` sans shell, sous
 * l'utilisateur configuré (EX-3.5 ; le démon doit pouvoir changer
 * d'utilisateur), bac à sable antéposé à la commande.
 * @param {{commande: string[], cwd: string|null, env: object, uid?: number, gid?: number}} p
 */
export function lanceurSysteme(p) {
  const options = { cwd: p.cwd ?? undefined, env: p.env, stdio: ["pipe", "pipe", "pipe"], shell: false };
  if (p.uid !== undefined) {
    options.uid = p.uid;
    options.gid = p.gid;
  }
  return spawn(p.commande[0], p.commande.slice(1), options);
}

/** Serveur d'outils lancé par le démon, cadrage stdio (EX-4.31). */
export class ConnexionStdio extends ConnexionAmont {
  constructor(p) {
    super(p);
    this.lanceur = p.lanceur ?? lanceurSysteme;
    this.tentatives = 0;
    this.prochainLancement = 0;
    this.stderrFenetre = { debut: 0, n: 0, comptees: 0 };
  }

  /** Commande complète (bac à sable antéposé), pour EX-3.4. */
  commande() {
    const t = this.serveur.transport;
    return [...(t.sandbox ?? []), ...t.command];
  }

  /**
   * Établit la connexion si elle ne l'est pas (4.4 pas 7) : lancement,
   * négociation d'ère. Lève ErreurConnexionAmont.
   * @param {string} capacitesTexte
   */
  async assurer(capacitesTexte = "{}") {
    if (this.connectee) return;
    if (!this.enCours) {
      this.enCours = this._lancer(capacitesTexte).finally(() => {
        this.enCours = null;
      });
    }
    await this.enCours;
  }

  async _lancer(capacitesTexte) {
    const t = this.serveur.transport;
    const maintenant = this.frontal.murale();
    const restart = this.frontal.config.restart;
    if (this.tentatives > 0) {
      if (this.tentatives > restart.max_attempts) throw new ErreurConnexionAmont(this.alias, "relances_epuisees");
      if (maintenant < this.prochainLancement) throw new ErreurConnexionAmont(this.alias, "relance_differee");
    }
    // Épinglage de la commande (EX-3.5) : sha256 de l'exécutable, ou paquet exact.
    if (t.integrity?.sha256) {
      let h = null;
      try {
        h = sha256Hex(new Uint8Array(fs.readFileSync(t.command[0])));
      } catch {
        h = null;
      }
      if (h !== t.integrity.sha256) {
        this.journal.consigner("error", "frontal_mcp", "integrity_mismatch", { server: this.alias });
        throw new ErreurConnexionAmont(this.alias, "integrite");
      }
    }
    if (t.integrity?.package && !t.command.includes(t.integrity.package)) throw new ErreurConnexionAmont(this.alias, "integrite");
    let ids = {};
    if (t.user) {
      const c = lireComptes().parNom.get(t.user);
      if (!c) throw new ErreurConnexionAmont(this.alias, "utilisateur_inconnu");
      if (typeof process.getuid === "function" && process.getuid() !== c.uid) ids = { uid: c.uid, gid: c.gid };
    }
    const env = this.frontal.environnementServeur(this.alias);
    let enfant;
    try {
      enfant = this.lanceur({ commande: this.commande(), cwd: t.cwd, env, ...ids, alias: this.alias });
    } catch (e) {
      this.tentatives++;
      this.prochainLancement = maintenant + restart.backoff_ms;
      throw new ErreurConnexionAmont(this.alias, `lancement:${e?.code ?? "erreur"}`);
    }
    this.enfant = enfant;
    this.tampon = [];
    this.tailleTampon = 0;
    this.sauterJusquaFinDeLigne = false;
    const echec = new Promise((_, rej) => {
      enfant.once?.("error", (e) => rej(new ErreurConnexionAmont(this.alias, `lancement:${e?.code ?? "erreur"}`)));
    });
    echec.catch(() => {});
    enfant.stdout.on("data", (c) => this._lire(c));
    enfant.stdout.on("end", () => this._fin("eof"));
    enfant.stderr?.on("data", (c) => this._stderr(c));
    enfant.on?.("exit", (code, signal) => {
      this.journal.consigner("warning", "frontal_mcp", "child_exited", { server: this.alias, code: code ?? null, signal: signal ?? null });
      this._fin("exit");
    });
    enfant.stdin.on?.("error", () => this._fin("stdin"));
    this.vivant = true;
    this.connectee = true;
    this.journal.consigner("info", "frontal_mcp", "child_started", { server: this.alias, pid: enfant.pid ?? null });
    try {
      await Promise.race([this._negocier(capacitesTexte), echec]);
    } catch (e) {
      this.tentatives++;
      this.prochainLancement = maintenant + restart.backoff_ms;
      this.arreterEnfant();
      throw e instanceof ErreurConnexionAmont ? e : new ErreurConnexionAmont(this.alias, "negociation");
    }
    this.tentatives = 0;
  }

  _fin(raison) {
    if (!this.vivant) return;
    this.vivant = false;
    this.tentatives = Math.max(this.tentatives, 1);
    this.prochainLancement = this.frontal.murale() + this.frontal.config.restart.backoff_ms;
    this._perte(raison);
  }

  _stderr(c) {
    // EX-4.32 : longueur et sha256 par défaut, débit borné.
    const ops = this.frontal.config.supervision.ops_log;
    const max = ops.child_stderr_lines_per_second ?? 20;
    const s = this.stderrFenetre;
    const t = this.frontal.monotone();
    if (t - s.debut >= 1000) {
      if (s.comptees) this.journal.consigner("info", "frontal_mcp", "child_stderr_dropped", { server: this.alias, lines: s.comptees });
      s.debut = t;
      s.n = 0;
      s.comptees = 0;
    }
    for (const l of String(c).split("\n").filter((x) => x.length)) {
      if (s.n >= max) {
        s.comptees++;
        continue;
      }
      s.n++;
      this.journal.consigner("info", "frontal_mcp", "child_stderr", { server: this.alias, length: Buffer.byteLength(l), sha256: sha256Hex(new TextEncoder().encode(l)) });
    }
  }

  /** Lecture de la sortie standard, découpée sur LF seulement (EX-4.31). */
  _lire(c) {
    const borne = this.frontal.config.limits.response_max_bytes;
    let debut = 0;
    const octets = c instanceof Uint8Array ? c : Buffer.from(c);
    while (debut < octets.length) {
      const k = octets.indexOf(10, debut);
      const fin = k < 0 ? octets.length : k;
      const morceau = octets.subarray(debut, fin);
      if (!this.sauterJusquaFinDeLigne) {
        this.tampon.push(morceau);
        this.tailleTampon += morceau.length;
        if (this.tailleTampon > borne) this._tailleDepassee(borne);
      }
      if (k < 0) break;
      if (!this.sauterJusquaFinDeLigne) {
        const ligne = Buffer.concat(this.tampon);
        this._ligne(ligne);
      }
      this.tampon = [];
      this.tailleTampon = 0;
      this.sauterJusquaFinDeLigne = false;
      debut = k + 1;
    }
  }

  /**
   * Réponse au-delà de la borne (4.4 pas 11) : l'appel concerné finit par
   * `taille` à cet instant ; le reste de la ligne est lu sans être gardé.
   */
  _tailleDepassee(borne) {
    const t = this.maintenant();
    const debut = Buffer.concat(this.tampon).subarray(0, 256).toString("latin1");
    const m = /"id"\s*:\s*"(e-[0-9]{12})"/.exec(debut);
    let cle = m ? m[1] : null;
    if (!cle && this.enVol.size === 1) cle = [...this.enVol.keys()][0];
    const a = cle ? this.enVol.get(cle) : null;
    if (a) {
      this.enVol.delete(cle);
      a.resoudre({ issue: "taille", t, limite: borne });
    } else {
      this._ligneInvalide("taille");
    }
    this.tampon = [];
    this.tailleTampon = 0;
    this.sauterJusquaFinDeLigne = true;
  }

  _ligne(octets) {
    const t = this.maintenant();
    if (octets.includes(13)) return this._ligneInvalide("cr");
    let texte;
    let noeud;
    try {
      texte = decoderUtf8Strict(octets);
      noeud = analyserTexte(texte, { profondeurMax: this.frontal.config.limits.json_max_depth, membresMax: this.frontal.config.limits.json_max_members });
    } catch (e) {
      if (e instanceof ErreurTexteJson) return this._ligneInvalide(e.raison);
      throw e;
    }
    if (noeud.t === "tableau") return this._ligneInvalide("lot");
    if (noeud.t !== "objet") return this._ligneInvalide("non_objet");
    this._message(texte, noeud, t);
  }

  envoyerRequete(texte) {
    this._ecrire(texte);
  }

  envoyerNotification(texte) {
    this._ecrire(texte);
  }

  _ecrire(texte) {
    if (!this.vivant) return;
    try {
      this.enfant.stdin.write(texte + "\n");
    } catch {
      this._fin("stdin");
    }
  }

  /** Annulation amont (EX-4.22, EX-4.23) : `notifications/cancelled`. */
  annuler(id, raison) {
    this.oublier(id);
    this.envoyerNotification(notification("notifications/cancelled", JSON.stringify({ requestId: id, reason: raison })));
  }

  /** Fin d'un appel : rien à fermer en stdio. */
  terminerAppel() {}

  /**
   * Arrêt (4.2, « Arrêt ») : fermeture de l'entrée standard, attente, SIGTERM
   * après `child_exit_timeout_ms`, SIGKILL après le même délai.
   */
  async fermer() {
    const e = this.enfant;
    if (!e || !this.vivant) return;
    const delai = this.frontal.config.mcp.child_exit_timeout_ms;
    const fini = new Promise((r) => {
      if (e.exitCode !== null && e.exitCode !== undefined) return r();
      e.once?.("exit", r);
      e.stdout?.once?.("end", r);
    });
    try {
      e.stdin.end();
    } catch {
      // déjà fermée
    }
    const attendre = (ms) => new Promise((r) => setTimeout(r, ms).unref?.());
    if (await Promise.race([fini.then(() => true), attendre(delai).then(() => false)])) return;
    e.kill?.("SIGTERM");
    if (await Promise.race([fini.then(() => true), attendre(delai).then(() => false)])) return;
    e.kill?.("SIGKILL");
  }

  arreterEnfant() {
    try {
      this.enfant?.kill?.("SIGKILL");
    } catch {
      // déjà arrêté
    }
  }
}

// ------------------------------------------------------------------ HTTP

/**
 * Lecteur d'un flux SSE (EX-4.36) : rend chaque champ `data` complet.
 */
export class LecteurSse {
  constructor(surDonnees) {
    this.surDonnees = surDonnees;
    this.reste = "";
    this.donnees = [];
  }

  pousser(texte) {
    this.reste += texte;
    let k;
    while ((k = this.reste.search(/\r\n|\n|\r/)) >= 0) {
      const l = this.reste.slice(0, k);
      const sep = this.reste[k] === "\r" && this.reste[k + 1] === "\n" ? 2 : 1;
      this.reste = this.reste.slice(k + sep);
      this._ligne(l);
    }
  }

  _ligne(l) {
    if (l === "") {
      if (this.donnees.length) this.surDonnees(this.donnees.join("\n"));
      this.donnees = [];
      return;
    }
    if (l.startsWith(":")) return;
    const k = l.indexOf(":");
    const champ = k < 0 ? l : l.slice(0, k);
    let v = k < 0 ? "" : l.slice(k + 1);
    if (v.startsWith(" ")) v = v.slice(1);
    if (champ === "data") this.donnees.push(v);
  }

  finir() {
    if (this.reste) this._ligne(this.reste);
    this.reste = "";
    if (this.donnees.length) this.surDonnees(this.donnees.join("\n"));
    this.donnees = [];
  }
}

/**
 * Valeur d'un en-tête `Mcp-Param-*` (EX-4.35) : texte ASCII visible tel
 * quel, sinon la sentinelle `=?base64?…?=`.
 * @param {unknown} v
 * @returns {string|null}
 */
export function valeurEnteteParametre(v) {
  if (v === null || typeof v === "object") return null;
  const s = String(v);
  if (/^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/.test(s) && !s.startsWith("=?")) return s;
  return `=?base64?${Buffer.from(s, "utf8").toString("base64")}?=`;
}

/** Serveur d'outils en Streamable HTTP (EX-4.6 point 2, EX-4.35, EX-4.38, EX-4.40). */
export class ConnexionHttp extends ConnexionAmont {
  constructor(p) {
    super(p);
    this.url = new URL(this.serveur.transport.url);
    this.session = null;
    this.requetes = new Map();
    const tls = this.serveur.transport.tls;
    const options = { keepAlive: true };
    if (tls) {
      options.ca = fs.readFileSync(tls.ca_file);
      if (tls.cert_file) options.cert = fs.readFileSync(tls.cert_file);
      if (tls.key_file) options.key = fs.readFileSync(tls.key_file);
    }
    this.agent = this.url.protocol === "https:" ? new https.Agent(options) : new http.Agent({ keepAlive: true });
  }

  async assurer(capacitesTexte = "{}") {
    if (this.connectee) return;
    if (this.serveur.transport.oauth) throw new ErreurConnexionAmont(this.alias, "oauth_non_pris_en_charge");
    if (!this.enCours) {
      this.enCours = (async () => {
        this.connectee = true;
        try {
          await this._negocier(capacitesTexte);
        } catch (e) {
          this.connectee = false;
          throw e instanceof ErreurConnexionAmont ? e : new ErreurConnexionAmont(this.alias, "negociation");
        }
      })().finally(() => {
        this.enCours = null;
      });
    }
    await this.enCours;
  }

  /** En-têtes construits par le frontal (EX-4.35, EX-4.41). */
  entetes(o = {}) {
    const h = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    for (const [nom, valeur] of Object.entries(this.frontal.entetesServeur(this.alias))) h[nom.toLowerCase()] = valeur;
    if (this.version && (this.ere === "moderne" || this.version !== "2025-03-26")) h["mcp-protocol-version"] = this.version;
    if (this.session) h["mcp-session-id"] = this.session;
    if (this.ere === "moderne" && o.methode) {
      h["mcp-method"] = o.methode;
      if (o.nom) h["mcp-name"] = o.nom;
      for (const [nom, v] of Object.entries(o.parametres ?? {})) h[`mcp-param-${nom.toLowerCase()}`] = v;
    }
    return h;
  }

  _poster(texte, o = {}) {
    const limite = this.frontal.config.limits.response_max_bytes;
    const req = (this.url.protocol === "https:" ? https : http).request(this.url, { method: "POST", agent: this.agent, headers: this.entetes(o) });
    let recu = 0;
    const id = o.id ?? null;
    const resoudreId = (r) => {
      if (id === null) return;
      const a = this.enVol.get(id);
      if (a) {
        this.enVol.delete(id);
        a.resoudre(r);
      }
    };
    req.on("response", (res) => {
      const s = res.headers["mcp-session-id"];
      if (typeof s === "string" && o.methode === "initialize") this.session = s;
      const type = String(res.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
      if (res.statusCode === 202 || id === null) {
        res.resume();
        return;
      }
      if (res.statusCode === 404 && this.session) {
        // Session amont terminée (EX-4.38) : réinitialiser à la prochaine connexion.
        this.session = null;
        this.connectee = false;
      }
      const morceaux = [];
      const sse = type === "text/event-stream";
      const lecteur = sse ? new LecteurSse((d) => this._donnees(d)) : null;
      const decodeur = new TextDecoder("utf-8");
      res.on("data", (c) => {
        recu += c.length;
        if (recu > limite) {
          resoudreId({ issue: "taille", t: this.maintenant(), limite });
          req.destroy();
          return;
        }
        if (sse) lecteur.pousser(decodeur.decode(c, { stream: true }));
        else morceaux.push(c);
      });
      res.on("end", () => {
        if (sse) {
          lecteur.pousser(decodeur.decode());
          lecteur.finir();
        } else if (res.statusCode >= 200 && res.statusCode < 300 && type === "application/json") {
          this._donnees(Buffer.concat(morceaux));
        } else if (res.statusCode === 400 && o.sonde) {
          this._donnees(Buffer.concat(morceaux));
        }
        resoudreId({ issue: "perte", t: this.maintenant(), statut: res.statusCode });
      });
      res.on("error", () => resoudreId({ issue: "perte", t: this.maintenant() }));
    });
    req.on("error", () => resoudreId({ issue: "perte", t: this.maintenant() }));
    req.end(texte);
    if (id !== null) this.requetes.set(id, req);
    return req;
  }

  _donnees(d) {
    let texte;
    let noeud;
    try {
      texte = typeof d === "string" ? d : decoderUtf8Strict(d);
      noeud = analyserTexte(texte, { profondeurMax: this.frontal.config.limits.json_max_depth, membresMax: this.frontal.config.limits.json_max_members });
    } catch (e) {
      if (e instanceof ErreurTexteJson) return this._ligneInvalide(e.raison);
      throw e;
    }
    if (noeud.t !== "objet") return this._ligneInvalide(noeud.t === "tableau" ? "lot" : "non_objet");
    this._message(texte, noeud, this.maintenant());
  }

  envoyerRequete(texte, o = {}) {
    let methode = null;
    try {
      methode = JSON.parse(texte).method ?? null;
    } catch {
      methode = null;
    }
    this._poster(texte, { ...o, methode, sonde: methode === "server/discover" });
  }

  envoyerNotification(texte) {
    let methode = null;
    try {
      methode = JSON.parse(texte).method ?? null;
    } catch {
      methode = null;
    }
    this._poster(texte, { methode });
  }

  /**
   * Envoi d'un `tools/call` (4.4 pas 9) avec ses en-têtes construits.
   * @param {string} id
   * @param {string} texte
   * @param {{nom: string, parametres: object}} o
   */
  envoyerAppel(id, texte, o) {
    this._poster(texte, { id, methode: "tools/call", nom: o.nom, parametres: o.parametres });
  }

  annuler(id, raison) {
    this.oublier(id);
    if (this.ere === "heritee") this.envoyerNotification(notification("notifications/cancelled", JSON.stringify({ requestId: id, reason: raison })));
    this.terminerAppel(id);
  }

  /** Ferme le flux de réponse d'un appel (annulation en ère moderne, EX-4.22). */
  terminerAppel(id) {
    const r = this.requetes.get(id);
    this.requetes.delete(id);
    try {
      r?.destroy();
    } catch {
      // déjà fermé
    }
  }

  async fermer() {
    for (const id of [...this.requetes.keys()]) this.terminerAppel(id);
    if (this.ere === "heritee" && this.session) {
      await new Promise((r) => {
        const req = (this.url.protocol === "https:" ? https : http).request(this.url, { method: "DELETE", agent: this.agent, headers: this.entetes() }, (res) => {
          res.resume();
          res.on("end", r);
        });
        req.on("error", r);
        req.end();
      });
    }
    this.agent.destroy();
  }
}
