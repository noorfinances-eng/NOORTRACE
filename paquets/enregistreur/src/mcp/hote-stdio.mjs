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
//     propriété de fichier (lecture consignée au LISEZMOI) : il envoie un
//     défi aléatoire, le connecteur crée en exclusion
//     `<répertoire de la prise>/.noortrace-defi-<défi>`, le démon lit le
//     propriétaire de ce fichier (lstat : fichier ordinaire, un seul lien) et
//     le supprime. Un processus ne peut créer qu'un fichier qui lui appartient ;
//   - prise TCP, `client_auth: "jeton"` : la première ligne
//     `{"noortrace_token": "<jeton>"}`, comparée en temps constant aux jetons
//     statiques, puis retirée ; sur TLS si `connector_tcp.tls` est posé ;
//   - prise TCP, `client_auth: "mtls"` : certificat client vérifié contre
//     l'autorité qui suit le certificat du démon dans `tls.cert_file`, et
//     rattaché à l'entrée de `mcp.hosts` dont `match.peer_user` est son nom
//     commun ; pas de ligne de jeton (LISEZMOI, lecture 134, même lecture que
//     la 113 du SDK ; serveur commun `./prise-tcp.mjs`).
// Une connexion sans entrée de `mcp.hosts` est refusée (EX-7.3).

import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { lireComptes } from "./amont.mjs";
import { reponseErreur } from "./messages.mjs";
import { ecouterPriseTcp, identiteCertificat } from "./prise-tcp.mjs";

/** Préfixe des fichiers de preuve d'identité. */
export const PREFIXE_DEFI = ".noortrace-defi-";

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
  }

  get journal() {
    return this.frontal.journal;
  }

  async ecouter() {
    if (this.socket) {
      fs.mkdirSync(path.dirname(this.socket), { recursive: true });
      try {
        fs.rmSync(this.socket, { force: true });
      } catch {
        // prise absente
      }
      const s = net.createServer((c) => this._connexionUnix(c));
      await new Promise((res, rej) => {
        s.once("error", rej);
        s.listen(this.socket, res);
      });
      this.serveurs.push(s);
    }
    if (this.tcp) {
      const s = await ecouterPriseTcp(this.tcp, {
        nom: "prise TCP des connecteurs",
        pointeur: "mcp.connector_tcp",
        connexions: this.connexions,
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
    if (this.socket) fs.rmSync(this.socket, { force: true });
  }

  _refuser(c, raison) {
    this.journal.consigner("warning", "frontal_mcp", "auth_failed", { transport: "stdio", ...(c.encrypted ? { tls: true } : {}), reason: raison });
    c.destroy();
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
    this._servir(c, hote, { peer_user: id.cn, certificat: id.empreinte });
  }

  _connexionUnix(c) {
    this.connexions.add(c);
    c.on("close", () => this.connexions.delete(c));
    c.on("error", () => {});
    const defi = randomBytes(16).toString("hex");
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
      const fichier = path.join(path.dirname(this.socket), PREFIXE_DEFI + defi);
      let st;
      try {
        st = fs.lstatSync(fichier);
        fs.rmSync(fichier, { force: true });
      } catch {
        return this._refuser(c, "preuve");
      }
      if (!st.isFile() || st.nlink !== 1) return this._refuser(c, "preuve");
      const utilisateur = lireComptes().parUid.get(st.uid) ?? null;
      const hote = utilisateur === null ? null : this.frontal.hotePour({ peer_user: utilisateur });
      if (!hote) return this._refuser(c, "hote_inconnu");
      c.write(JSON.stringify({ noortrace_identite: "acceptee" }) + "\n");
      this._servir(c, hote, { peer_user: utilisateur });
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
      let id = null;
      for (const [k, v] of this.jetons) if (egauxTempsConstant(recu, v)) id = k;
      const hote = id === null ? null : this.frontal.hotePour({ static_token: id });
      if (!hote) return this._refuser(c, "jeton");
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
        f.recevoir(session, new Uint8Array(ligne), { cadre: "ligne" }).then(ecrire, (e) => {
          f.journal.consigner("error", "frontal_mcp", "internal_error", { message: String(e?.message ?? e).slice(0, 200) }, { host: hote.id });
          ecrire(reponseErreur(null, -32603));
        });
      },
      (taille) => {
        f.journal.consigner("warning", "frontal_mcp", "request_too_large", { length: taille }, { host: hote.id });
        ecrire(reponseErreur(null, -31013, { limit_bytes: borne, direction: "requete" }));
      },
    );
    c.on("data", (x) => d.pousser(x));
    c.on("close", () => f.fermerSession(session));
  }
}
