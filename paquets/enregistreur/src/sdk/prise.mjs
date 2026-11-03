// Prise du point d'entrée SDK (CT-2 EX-6.1, EX-6.10, EX-4.39, EX-18.1) :
// prise de domaine Unix `sdk.socket` (mode 0660) ou prise TCP locale
// `sdk.tcp_listen`, cadrage de 4.7.1 (une ligne JSON-RPC 2.0 par message, LF
// seul ; au-delà de `limits.line_max_bytes`, -31013 et lecture reprise après
// le LF suivant).
//
// Identité de la connexion (EX-6.1) :
//   - prise Unix : l'utilisateur système du processus pair, lu comme pour le
//     connecteur stdio du frontal MCP (LISEZMOI, lectures 31 et 157 : défi
//     aléatoire, fichier créé en exclusion dans le répertoire de la prise par
//     le pair après le défi, propriétaire relu par `lstat` ; répertoire de la
//     prise et parents qu'aucun pair ne peut employer pour renommer la preuve
//     d'un autre, vérifiés au démarrage et à chaque preuve) ;
//   - prise TCP, `client_auth: "jeton"` : la première ligne
//     `{"noortrace_token": "<jeton>"}`, comparée en temps constant aux jetons
//     statiques (EX-4.39, EX-6.10), puis retirée ; sur TLS si `tls` est posé ;
//   - prise TCP, `client_auth: "mtls"` : TLS (`tls.cert_file`, `tls.key_file`)
//     avec certificat client obligatoire, vérifié contre l'autorité de la
//     chaîne de `tls.cert_file` (les certificats qui suivent celui du démon),
//     et rattaché à l'entrée de `sdk.hosts` dont `match.peer_user` est le
//     nom commun (CN) du sujet du certificat ; pas de ligne de jeton (EX-6.10,
//     « sauf en mTLS ») (LISEZMOI, lecture 113 : le schéma n'a ni autorité
//     cliente pour cette prise ni forme de `match` pour un certificat) ;
//     serveur TCP, TLS et mTLS communs avec la prise des connecteurs
//     (`../mcp/prise-tcp.mjs`).
// L'identité acceptée est confirmée par `{"noortrace_identite":"acceptee"}` ;
// une connexion sans entrée de `sdk.hosts` est refusée et consignée
// (`auth_failed`, EX-7.3), et les échecs de jeton sont limités comme en EX-18.3.
// Les octets reçus sont comptés au quota de la connexion d'hôte dès leur
// lecture, ligne trop longue comprise (4.4 pas 1, EX-4.47).

import net from "node:net";
import fs from "node:fs";
import { randomBytes } from "node:crypto";
import { DecoupeurLignes, egauxTempsConstant, preparerRepertoirePrise, ecouterPriseUnix, verifierPreuveFichier } from "../mcp/hote-stdio.mjs";
import { reponseErreur } from "../mcp/messages.mjs";
import { LimiteurEchecs } from "./limiteur.mjs";
import { ecouterPriseTcp, identiteCertificat } from "../mcp/prise-tcp.mjs";

export class ServeurSdk {
  /**
   * @param {{frontal: import("./frontal.mjs").FrontalSdk, socket?: string|null,
   *   tcp?: {listen: string, client_auth: string, tls: object|null}|null, jetons?: Map<string, Uint8Array>}} p
   *   `jetons` : identifiant → jeton statique résolu
   */
  constructor(p) {
    this.frontal = p.frontal;
    this.socket = p.socket ?? null;
    this.tcp = p.tcp ?? null;
    this.jetons = p.jetons ?? new Map();
    this.serveurs = [];
    this.connexions = new Set();
    this.limiteur = new LimiteurEchecs({ monotone: () => this.frontal.monotone() });
  }

  get journal() {
    return this.frontal.journal;
  }

  async ecouter() {
    if (this.socket) {
      preparerRepertoirePrise(this.socket);
      fs.rmSync(this.socket, { force: true });
      const s = net.createServer((c) => this._connexionUnix(c));
      // EX-18.1 : propriétaire = utilisateur du démon, mode 0660 dès la création.
      await ecouterPriseUnix(s, this.socket);
      this.serveurs.push(s);
    }
    if (this.tcp) {
      const s = await ecouterPriseTcp(this.tcp, {
        nom: "prise TCP du SDK",
        pointeur: "sdk.tcp_listen",
        connexions: this.connexions,
        surJeton: (c) => this._connexionTcp(c),
        surMtls: (c) => this._connexionMtls(c),
        surEchecTls: (raison) => this.journal.consigner("warning", "sdk", "auth_failed", { transport: "tls", reason: raison }),
      });
      this.serveurs.push(s);
    }
  }

  /** Adresse TCP effective (port 0 dans les essais). */
  adresseTcp() {
    const s = this.serveurs.find((x) => typeof x.address() === "object" && x.address() !== null);
    return s ? s.address() : null;
  }

  async fermer() {
    for (const c of this.connexions) c.destroy();
    await Promise.all(this.serveurs.map((s) => new Promise((r) => s.close(() => r()))));
    if (this.socket) fs.rmSync(this.socket, { force: true });
  }

  _refuser(c, raison, cle = null, detail = null) {
    if (cle) this.limiteur.echec(cle);
    this.journal.consigner("warning", "sdk", "auth_failed", { transport: c.encrypted ? "tls" : this.socket && !c.remoteAddress ? "unix" : "tcp", reason: raison, ...(detail ? { detail } : {}) });
    c.destroy();
  }

  _connexionUnix(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
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
      if (v.refus) return this._refuser(c, v.refus, null, v.detail);
      const utilisateur = v.utilisateur;
      const hote = utilisateur === null ? null : this.frontal.hotePour({ peer_user: utilisateur });
      if (!hote) return this._refuser(c, "hote_inconnu");
      c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
      this._servir(c, hote, { peer_user: utilisateur, transport: "unix" });
    }, () => this._refuser(c, "preuve"));
    c.on("data", (x) => d.pousser(x));
  }

  _connexionTcp(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
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
      if (typeof jeton !== "string") return this._refuser(c, "jeton");
      const recu = Buffer.from(jeton, "utf8");
      const cle = this.limiteur.cleJeton(recu);
      // EX-18.3 : un identifiant de jeton qui a trop échoué est refusé 60 s, jamais une adresse source.
      if (this.limiteur.bloque(cle)) return this._refuser(c, "jeton_limite");
      let id = null;
      for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
      const hote = id === null ? null : this.frontal.hotePour({ static_token: id });
      if (!hote) return this._refuser(c, "jeton", cle);
      c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
      this._servir(c, hote, { jeton: id, transport: c.encrypted ? "tls" : "tcp" });
    }, () => this._refuser(c, "jeton"));
    c.on("data", (x) => d.pousser(x));
  }

  _connexionMtls(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
    // Certificat absent, expiré ou d'une autre autorité : refus avant toute
    // lecture ; sinon rattachement à l'entrée d'hôte de son nom commun.
    const id = identiteCertificat(c);
    if (id.refus) return this._refuser(c, id.refus);
    const hote = this.frontal.hotePour({ peer_user: id.cn });
    if (!hote) return this._refuser(c, "hote_inconnu");
    c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
    this._servir(c, hote, { peer_user: id.cn, transport: "mtls", certificat: id.empreinte });
  }

  _servir(c, hote, identite) {
    const f = this.frontal;
    const cx = f.ouvrirConnexion({ hote, identite });
    const ecrire = (texte) => {
      if (!c.destroyed && texte !== null && texte !== undefined && texte !== "") c.write(texte + "\n");
    };
    const borne = f.config.limits.line_max_bytes;
    const d = new DecoupeurLignes(
      borne,
      (ligne) => {
        if (ligne.length === 0) return;
        if (/^Content-Length:/i.test(ligne.subarray(0, 32).toString("latin1"))) {
          f.journal.consigner("warning", "sdk", "framing_refused", { framing: "content-length" }, { host: hote.id });
          ecrire(reponseErreur(null, -32700, { reason: "cadrage_non_admis" }));
          return;
        }
        f.recevoir(cx, new Uint8Array(ligne), { compte: true }).then(ecrire, (e) => {
          f.journal.consigner("error", "sdk", "internal_error", { message: String(e?.message ?? e).slice(0, 200) }, { host: hote.id });
          ecrire(reponseErreur(null, -32603));
        });
      },
      (taille) => {
        f.journal.consigner("warning", "sdk", "request_too_large", { length: taille }, { host: hote.id });
        ecrire(reponseErreur(null, -31013, { limit_bytes: borne, direction: "requete" }));
      },
    );
    c.on("data", (x) => {
      // 4.4 pas 1, EX-4.47 : octets comptés dès leur lecture, ligne refusée ou trop longue comprise.
      f.compterRecus(hote, x.length);
      d.pousser(x);
    });
    c.on("close", () => {
      f.journal.consigner("info", "sdk", "sdk_disconnected", {}, { host: hote.id });
      f.fermerConnexion(cx).catch(() => {});
    });
  }
}

