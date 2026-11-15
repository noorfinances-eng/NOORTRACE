// Côté démon du transport stdio des hôtes (CT-2 §4.7.1, EX-4.39) : le
// connecteur stdio, lancé par l'hôte, joint la prise locale `mcp.socket` (ou
// la prise TCP `mcp.connector_tcp`) et y relaie ses lignes JSON-RPC. Cadrage :
// un message par ligne, LF seul (EX-4.31) ; une ligne avec un CR est rejetée
// par -32700 (EX-4.43) ; une ligne au-delà de `limits.line_max_bytes` est
// refusée par -31013 et la lecture reprend après le LF suivant ; un cadrage
// `Content-Length` est refusé et consigné.
//
// Identité de la connexion d'hôte (EX-4.39) :
//   - prise de domaine Unix : l'utilisateur système du processus connecteur.
//     Node.js n'expose pas SO_PEERCRED ; le démon le lit par une preuve de
//     propriété de fichier (LISEZMOI, lectures 31 et 157) : il envoie un
//     défi aléatoire, le connecteur crée en exclusion
//     `<répertoire de la prise>/.noortrace-defi-<défi>`, le démon lit le
//     propriétaire de ce fichier (lstat : fichier ordinaire, un seul lien,
//     créé après le défi) et le supprime. Un processus ne peut créer qu'un
//     fichier qui lui appartient ; la preuve n'est pas transférable parce que
//     le répertoire de la prise et ses parents ne sont inscriptibles par
//     d'autres que le démon (ou root) qu'avec le bit collant, qui interdit à
//     un pair de renommer le fichier d'un autre : vérifié au démarrage et à
//     chaque preuve ;
//   - prise TCP, `client_auth: "jeton"` : la première ligne
//     `{"noortrace_token": "<jeton>"}`, comparée en temps constant aux jetons
//     statiques, puis retirée ; sur TLS si `connector_tcp.tls` est posé ;
//   - prise TCP, `client_auth: "mtls"` : certificat client vérifié contre
//     l'autorité qui suit le certificat du démon dans `tls.cert_file`, et
//     rattaché à l'entrée de `mcp.hosts` dont `match.peer_user` est son nom
//     commun ; pas de ligne de jeton (LISEZMOI, lecture 134, même lecture que
//     la 113 du SDK ; serveur commun `./prise-tcp.mjs`).
// Une connexion sans entrée de `mcp.hosts` est refusée (EX-7.3). Les échecs
// de jeton de la prise TCP sont limités par identifiant de jeton présenté
// (EX-18.3). Les octets reçus d'un connecteur sont comptés au quota de sa
// connexion d'hôte dès leur lecture, ligne trop longue comprise (4.4 pas 1,
// EX-4.47). Les lignes `warning` et `error` du journal d'exploitation qui
// concernent la connexion d'un connecteur lui sont envoyées pour sa sortie
// d'erreur (EX-9.7, lecture 158).

import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { lireComptes } from "./amont.mjs";
import { reponseErreur } from "./messages.mjs";
import { ecouterPriseTcp, identiteCertificat } from "./prise-tcp.mjs";
import { LimiteurEchecs } from "../sdk/limiteur.mjs";
import { DELAI_IDENTIFICATION_MS, CONNEXIONS_NON_IDENTIFIEES_MAX } from "../bornes.mjs";

/** Préfixe des fichiers de preuve d'identité. */
export const PREFIXE_DEFI = ".noortrace-defi-";

/**
 * Préfixe d'une ligne du démon vers le connecteur qui porte une ligne du
 * journal d'exploitation pour la sortie d'erreur du connecteur (EX-9.7) ; une
 * réponse JSON-RPC du démon commence toujours par `{"jsonrpc"`.
 */
export const PREFIXE_JOURNAL = '{"noortrace_journal":';

/** Mode d'une prise locale (EX-18.1) et d'un répertoire de prise créé par le démon (lecture 157). */
export const MODE_PRISE = 0o660;
export const MODE_REPERTOIRE_PRISE = 0o1770;

/** Marge admise entre l'horloge des fichiers et celle du démon pour l'instant de création d'une preuve. */
const MARGE_CREATION_MS = 1000;

/** Connexion d'hôte dont une ligne du journal d'exploitation est consignée (EX-9.7). */
export const CONTEXTE_CONNEXION = new AsyncLocalStorage();

/**
 * Met une prise de domaine Unix en écoute avec son mode dès la liaison : le
 * masque du processus est posé le temps de l'appel synchrone qui crée le
 * fichier, de sorte qu'il n'existe jamais avec un mode plus ouvert (EX-18.1).
 * @param {net.Server} serveur
 * @param {string} chemin
 * @param {number} [mode]
 */
export async function ecouterPriseUnix(serveur, chemin, mode = MODE_PRISE) {
  const pret = new Promise((res, rej) => {
    serveur.once("error", rej);
    serveur.once("listening", res);
  });
  const ancien = process.umask(0o777 & ~mode);
  try {
    serveur.listen(chemin);
  } finally {
    process.umask(ancien);
  }
  await pret;
  if ((fs.statSync(chemin).mode & 0o777) !== mode) {
    serveur.close();
    throw new Error(`prise ${chemin} : mode ${(fs.statSync(chemin).mode & 0o777).toString(8)} au lieu de ${mode.toString(8)} (EX-18.1)`);
  }
}

/**
 * Le répertoire d'une prise et ses parents ne laissent-ils renommer un
 * fichier de preuve que par son propriétaire (lecture 157) ? Chaque
 * répertoire appartient au démon ou à root, et n'est inscriptible par le
 * groupe ou les autres qu'avec le bit collant.
 * @param {string} dir
 * @returns {string|null} raison du refus, ou null
 */
export function controlerRepertoirePrise(dir) {
  if (typeof process.getuid !== "function") return null;
  const uid = process.getuid();
  let d;
  try {
    d = fs.realpathSync(dir);
  } catch {
    return "repertoire_absent";
  }
  for (;;) {
    let st;
    try {
      st = fs.lstatSync(d);
    } catch {
      return "repertoire_absent";
    }
    if (!st.isDirectory()) return "repertoire_non_dossier";
    if (st.uid !== uid && st.uid !== 0) return "repertoire_proprietaire";
    if ((st.mode & 0o022) !== 0 && (st.mode & 0o1000) === 0) return "repertoire_inscriptible";
    const parent = path.dirname(d);
    if (parent === d) return null;
    d = parent;
  }
}

/**
 * Prépare le répertoire d'une prise au démarrage : créé avec le mode 1770 s'il
 * n'existe pas ; refus de démarrer s'il laisse un pair renommer la preuve
 * d'un autre (lecture 157).
 * @param {string} socket chemin de la prise
 */
export function preparerRepertoirePrise(socket) {
  const dir = path.dirname(socket);
  if (fs.mkdirSync(dir, { recursive: true }) !== undefined) fs.chmodSync(dir, MODE_REPERTOIRE_PRISE);
  const raison = controlerRepertoirePrise(dir);
  if (raison) throw new Error(`répertoire de la prise ${dir} : ${raison} (inscriptible par d'autres que le démon sans bit collant, ou d'un autre propriétaire ; EX-4.39, lecture 157)`);
}

/**
 * Le chemin d'une prise est tenu par un fichier d'un autre compte (étape 8) :
 * un membre du groupe des prises y a lié sa propre prise ; le démon
 * refuse de démarrer avec cette erreur nommée, jamais une erreur avalée.
 */
export class ErreurPriseTenue extends Error {
  constructor(chemin, uid) {
    super(`prise ${chemin} : chemin tenu par un fichier du compte ${uid} (usurpation possible) ; le démon ne le remplace pas`);
    this.code = "prise_tenue_par_autre_compte";
    this.chemin = chemin;
    this.uid = uid;
  }
}

/**
 * Libère le chemin d'une prise avant l'écoute (étape 8) : la prise que
 * ce démon a laissée à son arrêt précédent (même compte, ou compte 0) est
 * supprimée ; un fichier d'un autre compte n'est jamais supprimé ni remplacé :
 * `ErreurPriseTenue`. À l'arrêt, la prise n'est plus supprimée : dans un
 * répertoire à bit collant, un autre compte ne peut ni la retirer ni lier la
 * sienne au même chemin tant qu'elle y est.
 * @param {string} chemin
 */
export function libererCheminPrise(chemin) {
  let st;
  try {
    st = fs.lstatSync(chemin);
  } catch (e) {
    if (e?.code === "ENOENT") return;
    throw e;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && st.uid !== uid && st.uid !== 0) throw new ErreurPriseTenue(chemin, st.uid);
  fs.rmSync(chemin, { force: true });
}

/**
 * Tient le chemin d'une prise après l'arrêt (étape 8) : Node.js
 * supprime le fichier de la prise à la fermeture du serveur ; un fichier
 * ordinaire du démon (mode 0600) est remis à sa place, qu'un autre compte ne
 * peut ni retirer ni remplacer dans un répertoire à bit collant, et qui fait
 * échouer tout `bind` au même chemin ; un client y lit `prise_non_prise`
 * (démon arrêté). Le démon le retire au démarrage suivant (`libererCheminPrise`).
 * @param {string} chemin
 */
export function tenirCheminPrise(chemin) {
  try {
    fs.closeSync(fs.openSync(chemin, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600));
  } catch {
    // chemin déjà tenu (par ce démon ou par un autre : le démarrage suivant tranche)
  }
}

/**
 * Compte attendu du démon pour une prise jointe par un client (connecteur,
 * SDK ; étape 8) : un uid (nombre ou chaîne décimale), un nom de
 * compte de `/etc/passwd`, ou rien. Sans compte attendu, la prise doit
 * appartenir au compte du client ou au compte 0 : une prise d'un autre compte
 * non privilégié est tenue pour une usurpation.
 * @param {string} chemin chemin de la prise
 * @param {string|number|null|undefined} attendu
 * @returns {string|null} raison du refus (`prise_absente`, `prise_non_prise`,
 *   `prise_autre_compte`, `proprietaire_inconnu`), ou null
 */
export function controlerProprietairePrise(chemin, attendu) {
  if (typeof process.getuid !== "function") return null;
  let st;
  try {
    st = fs.lstatSync(chemin);
  } catch {
    return "prise_absente";
  }
  if (!st.isSocket()) return "prise_non_prise";
  if (attendu === null || attendu === undefined || attendu === "") {
    return st.uid === process.getuid() || st.uid === 0 ? null : "prise_autre_compte";
  }
  let uid;
  if (typeof attendu === "number") uid = attendu;
  else if (/^[0-9]{1,10}$/.test(String(attendu))) uid = Number(attendu);
  else uid = lireComptes().parNom.get(String(attendu))?.uid;
  if (!Number.isInteger(uid)) return "proprietaire_inconnu";
  return st.uid === uid ? null : "prise_autre_compte";
}

/**
 * Le système de fichiers du répertoire d'une prise rend-il l'instant de
 * création des fichiers (`birthtime`) ? Sans lui, la preuve par fichier perd
 * son contrôle d'antériorité et est refusée (étape 8) : le démon le
 * consigne au démarrage.
 * @param {string} dir
 * @returns {boolean}
 */
export function instantCreationDisponible(dir) {
  const f = path.join(dir, `.noortrace-sonde-${randomBytes(8).toString("hex")}`);
  try {
    fs.closeSync(fs.openSync(f, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600));
    return fs.lstatSync(f).birthtimeMs > 0;
  } catch {
    return false;
  } finally {
    fs.rmSync(f, { force: true });
  }
}

/**
 * Délai d'identification et borne des connexions non identifiées d'une
 * prise (étape 8 ; EX-18.3 : un processus local ne bloque pas les
 * hôtes légitimes) : une connexion qui n'a pas remis sa preuve ou son jeton
 * dans `delaiMs` est détruite (`auth_failed`, `delai_identification`) ; au
 * plus `max` connexions non identifiées à la fois, les suivantes refusées
 * (`connexions_non_identifiees`).
 */
export class GardeIdentification {
  /** @param {{delaiMs?: number, max?: number}} [o] */
  constructor(o = {}) {
    this.delaiMs = o.delaiMs ?? DELAI_IDENTIFICATION_MS;
    this.max = o.max ?? CONNEXIONS_NON_IDENTIFIEES_MAX;
    /** @type {Map<object, NodeJS.Timeout>} */
    this.enCours = new Map();
  }

  /**
   * Admet une connexion non identifiée ; faux (et `surRefus` appelé) au-delà de la borne.
   * @param {import("node:net").Socket} c
   * @param {(raison: string) => void} surRefus consigne et détruit la connexion
   */
  admettre(c, surRefus) {
    if (this.enCours.size >= this.max) {
      surRefus("connexions_non_identifiees");
      return false;
    }
    const t = setTimeout(() => {
      if (!this.enCours.has(c)) return;
      this.enCours.delete(c);
      surRefus("delai_identification");
    }, this.delaiMs);
    t.unref?.();
    this.enCours.set(c, t);
    c.once("close", () => this.identifiee(c));
    return true;
  }

  /** La connexion est identifiée (ou fermée) : plus de délai, plus comptée. */
  identifiee(c) {
    const t = this.enCours.get(c);
    if (t === undefined) return;
    clearTimeout(t);
    this.enCours.delete(c);
  }
}

/**
 * Vérifie la preuve par fichier d'un pair (lectures 31 et 157).
 * @param {string} socket chemin de la prise
 * @param {string} defi défi envoyé
 * @param {number} instantDefi instant d'envoi du défi (ms UNIX)
 * @param {{lstat?: (chemin: string) => fs.Stats}} [o] `lstat` : lecture des attributs (essais)
 * @returns {{utilisateur: string|null}|{refus: string, detail?: string}}
 */
export function verifierPreuveFichier(socket, defi, instantDefi, o = {}) {
  const dir = path.dirname(socket);
  const fichier = path.join(dir, PREFIXE_DEFI + defi);
  const r = controlerRepertoirePrise(dir);
  if (r) {
    fs.rmSync(fichier, { force: true });
    return { refus: "repertoire_prise", detail: r };
  }
  let st;
  try {
    st = (o.lstat ?? fs.lstatSync)(fichier);
    fs.rmSync(fichier, { force: true });
  } catch {
    return { refus: "preuve" };
  }
  if (!st.isFile() || st.nlink !== 1) return { refus: "preuve" };
  // Étape 8 : sans instant de création, le contrôle d'antériorité ne
  // peut pas être fait ; la preuve est refusée, jamais admise sans lui.
  if (!(st.birthtimeMs > 0)) return { refus: "preuve", detail: "instant_creation_indisponible" };
  // Un fichier antérieur au défi (renommé depuis un autre répertoire) ne prouve rien.
  if (st.birthtimeMs < instantDefi - MARGE_CREATION_MS) return { refus: "preuve" };
  return { utilisateur: lireComptes().parUid.get(st.uid) ?? null };
}

/**
 * Compare deux jetons en temps constant (EX-4.39).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
export function egauxTempsConstant(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) {
    timingSafeEqual(x, x);
    return false;
  }
  return timingSafeEqual(x, y);
}

/**
 * Découpe un flux en lignes (LF seul), avec borne de longueur.
 */
export class DecoupeurLignes {
  /**
   * @param {number} borne octets
   * @param {(ligne: Buffer) => void} surLigne
   * @param {(taille: number) => void} surTrop
   */
  constructor(borne, surLigne, surTrop) {
    this.borne = borne;
    this.surLigne = surLigne;
    this.surTrop = surTrop;
    this.morceaux = [];
    this.taille = 0;
    this.sauter = false;
  }

  pousser(c) {
    let debut = 0;
    while (debut < c.length) {
      const k = c.indexOf(10, debut);
      const fin = k < 0 ? c.length : k;
      if (!this.sauter) {
        this.morceaux.push(c.subarray(debut, fin));
        this.taille += fin - debut;
        if (this.taille > this.borne) {
          this.surTrop(this.taille);
          this.morceaux = [];
          this.taille = 0;
          this.sauter = true;
        }
      }
      if (k < 0) break;
      if (!this.sauter) this.surLigne(Buffer.concat(this.morceaux));
      this.morceaux = [];
      this.taille = 0;
      this.sauter = false;
      debut = k + 1;
    }
  }
}

export class ServeurConnecteurs {
  /**
   * @param {{frontal: import("./frontal.mjs").FrontalMcp, socket?: string|null, tcp?: {listen: string, client_auth: string, tls: object|null}|null,
   *   jetons?: Map<string, Uint8Array>}} p `jetons` : identifiant → jeton statique résolu
   */
  constructor(p) {
    this.frontal = p.frontal;
    this.socket = p.socket ?? null;
    this.tcp = p.tcp ?? null;
    this.jetons = p.jetons ?? new Map();
    this.serveurs = [];
    this.connexions = new Set();
    this.limiteur = new LimiteurEchecs({ monotone: () => this.frontal.monotone() });
    /** Délai d'identification et borne des connexions non identifiées (CT-2 EX-18.3). */
    this.garde = new GardeIdentification(p.identification ?? {});
  }

  get journal() {
    return this.frontal.journal;
  }

  async ecouter() {
    if (this.socket) {
      preparerRepertoirePrise(this.socket);
      // la prise laissée par ce démon est retirée ; un chemin tenu par un autre compte est refusé (ErreurPriseTenue).
      libererCheminPrise(this.socket);
      if (!instantCreationDisponible(path.dirname(this.socket))) {
        this.journal.consigner("warning", "frontal_mcp", "proof_birthtime_unavailable", { socket: this.socket, reason: "le système de fichiers ne rend pas l'instant de création : toute preuve par fichier sera refusée" });
      }
      const s = net.createServer((c) => this._connexionUnix(c));
      await ecouterPriseUnix(s, this.socket);
      this.serveurs.push(s);
    }
    if (this.tcp) {
      const s = await ecouterPriseTcp(this.tcp, {
        nom: "prise TCP des connecteurs",
        pointeur: "mcp.connector_tcp",
        connexions: this.connexions,
        delaiIdentificationMs: this.garde.delaiMs,
        surJeton: (c) => this._connexionTcp(c),
        surMtls: (c) => this._connexionMtls(c),
        surEchecTls: (raison) => this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "stdio", tls: true, reason: raison }),
      });
      this.serveurs.push(s);
    }
  }

  /** Adresse TCP effective (tests : port 0). */
  adresseTcp() {
    const s = this.serveurs.find((x) => typeof x.address() === "object");
    return s ? s.address() : null;
  }

  async fermer() {
    for (const c of this.connexions) c.destroy();
    await Promise.all(this.serveurs.map((s) => new Promise((r) => s.close(() => r()))));
    // le chemin de la prise reste tenu par le démon après l'arrêt.
    if (this.socket) tenirCheminPrise(this.socket);
  }

  _refuser(c, raison, detail = null) {
    this.garde.identifiee(c);
    this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "stdio", ...(c.encrypted ? { tls: true } : {}), reason: raison, ...(detail ? { detail } : {}) });
    c.destroy();
  }

  _connexionMtls(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
    if (!this.garde.admettre(c, (r) => this._refuser(c, r))) return;
    // Certificat absent, expiré ou d'une autre autorité : refus avant toute
    // lecture ; sinon rattachement à l'entrée d'hôte de son nom commun.
    const id = identiteCertificat(c);
    if (id.refus) return this._refuser(c, id.refus);
    const hote = this.frontal.hotePour({ peer_user: id.cn });
    if (!hote) return this._refuser(c, "hote_inconnu");
    this.garde.identifiee(c);
    c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
    this._servir(c, hote, { peer_user: id.cn, certificat: id.empreinte });
  }

  _connexionUnix(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
    if (!this.garde.admettre(c, (r) => this._refuser(c, r))) return;
    const defi = randomBytes(16).toString("hex");
    const instantDefi = Date.now();
    c.write(JSON.stringify({ noortrace_defi: defi }) + "\n");
    let fini = false;
    const d = new DecoupeurLignes(4096, (l) => {
      if (fini) return;
      fini = true;
      c.removeAllListeners("data");
      let preuve = null;
      try {
        preuve = JSON.parse(l.toString("utf8")).noortrace_preuve;
      } catch {
        preuve = null;
      }
      if (preuve !== defi) return this._refuser(c, "preuve");
      const v = verifierPreuveFichier(this.socket, defi, instantDefi);
      if (v.refus) return this._refuser(c, v.refus, v.detail);
      const utilisateur = v.utilisateur;
      const hote = utilisateur === null ? null : this.frontal.hotePour({ peer_user: utilisateur });
      if (!hote) return this._refuser(c, "hote_inconnu");
      this.garde.identifiee(c);
      c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
      this._servir(c, hote, { peer_user: utilisateur });
    }, () => this._refuser(c, "preuve"));
    c.on("data", (x) => d.pousser(x));
  }

  _connexionTcp(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
    if (!this.garde.admettre(c, (r) => this._refuser(c, r))) return;
    let fini = false;
    const d = new DecoupeurLignes(4096, (l) => {
      if (fini) return;
      fini = true;
      c.removeAllListeners("data");
      let jeton = null;
      try {
        jeton = JSON.parse(l.toString("utf8")).noortrace_token;
      } catch {
        jeton = null;
      }
      // Une ligne de jeton vide est refusée avant toute comparaison (CT-2 EX-15.4).
      if (typeof jeton !== "string" || jeton.length === 0) return this._refuser(c, "jeton");
      const recu = Buffer.from(jeton, "utf8");
      // EX-18.3 : un identifiant de jeton qui a trop échoué est refusé 60 s,
      // jamais une adresse source (une connexion ne porte qu'une tentative ; lecture 163).
      const cle = this.limiteur.cleJeton(recu);
      if (this.limiteur.bloque(cle)) return this._refuser(c, "jeton_limite");
      let id = null;
      for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
      const hote = id === null ? null : this.frontal.hotePour({ static_token: id });
      if (!hote) {
        this.limiteur.echec(cle);
        return this._refuser(c, "jeton");
      }
      this.garde.identifiee(c);
      c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
      this._servir(c, hote, { jeton: id });
    }, () => this._refuser(c, "jeton"));
    c.on("data", (x) => d.pousser(x));
  }

  _servir(c, hote, identite) {
    const f = this.frontal;
    const ecrire = (texte) => {
      if (!c.destroyed && texte !== null && texte !== undefined && texte !== "") c.write(texte + "\n");
    };
    const session = f.ouvrirSession({ hote, identite, transport: "stdio", emettre: ecrire });
    // EX-9.7 : les lignes warning et error consignées pour cette connexion
    // (son hôte, dans le traitement de ses lignes) partent vers la sortie
    // d'erreur du connecteur ; celles d'un autre hôte, d'un autre connecteur,
    // d'un serveur d'outils ou du démon jamais.
    const desabonner = f.journal.abonner?.((l) => {
      if ((l.level === "warning" || l.level === "error") && l.host === hote.id && CONTEXTE_CONNEXION.getStore() === session && !c.destroyed) {
        c.write(PREFIXE_JOURNAL + JSON.stringify(l) + "}\n");
      }
    });
    f.journal.consigner("info", "frontal_mcp", "host_connected", { transport: "stdio" }, { host: hote.id });
    const borne = f.config.limits.line_max_bytes;
    const d = new DecoupeurLignes(
      borne,
      (ligne) => {
        if (/^Content-Length:/i.test(ligne.subarray(0, 32).toString("latin1"))) {
          f.journal.consigner("warning", "frontal_mcp", "framing_refused", { framing: "content-length" }, { host: hote.id });
          ecrire(reponseErreur(null, -32700, { reason: "cadrage_non_admis" }));
          return;
        }
        if (ligne.length === 0) return;
        f.recevoir(session, new Uint8Array(ligne), { cadre: "ligne", compte: true }).then(ecrire, (e) => {
          f.journal.consigner("error", "frontal_mcp", "internal_error", { message: String(e?.message ?? e).slice(0, 200) }, { host: hote.id });
          ecrire(reponseErreur(null, -32603));
        });
      },
      (taille) => {
        f.journal.consigner("warning", "frontal_mcp", "request_too_large", { length: taille }, { host: hote.id });
        ecrire(reponseErreur(null, -31013, { limit_bytes: borne, direction: "requete" }));
      },
    );
    c.on("data", (x) => {
      // 4.4 pas 1, EX-4.47 : octets comptés dès leur lecture, avant toute
      // analyse, ligne refusée ou trop longue comprise.
      f.compterRecus(hote, x.length);
      CONTEXTE_CONNEXION.run(session, () => d.pousser(x));
    });
    c.on("close", () => {
      desabonner?.();
      f.fermerSession(session);
    });
  }
}
