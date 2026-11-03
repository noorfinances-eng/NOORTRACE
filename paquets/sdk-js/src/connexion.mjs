// Connexion du SDK au démon (CT-2 EX-6.1, EX-6.10) : prise de domaine Unix ou
// prise TCP locale (jeton statique en première ligne, ou mTLS), cadrage de
// 4.7.1 (une ligne JSON-RPC 2.0 par message, `\n` final), `id` entiers
// croissants à partir de 1 sur chaque connexion. Le SDK n'y reçoit jamais de
// requête du démon : il lit les réponses à ses requêtes, et, à l'ouverture,
// les deux lignes de la preuve d'identité (prise Unix : défi du démon, fichier
// créé en exclusion dans le répertoire de la prise par le processus du SDK,
// dont le démon lit le propriétaire ; puis l'acceptation).

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import { ErreurNoortraceIndisponible, erreurDepuisReponse } from "./erreurs.mjs";

/** Préfixe du fichier de preuve d'identité, celui du connecteur stdio du démon. */
export const PREFIXE_DEFI = ".noortrace-defi-";

export class Connexion {
  /**
   * @param {{socket?: string|null, tcp?: {hote: string, port: number}|null, jeton?: string|null,
   *   tls?: {ca: Buffer, cert: Buffer, key: Buffer}|null}} o
   */
  constructor(o) {
    this.o = o;
    this.prochainId = 1;
    /** @type {Map<number, {resoudre: Function, rejeter: Function, minuteur: any}>} */
    this.attentes = new Map();
    this.perdue = false;
    this.surPerte = null;
    this.tampon = Buffer.alloc(0);
  }

  /**
   * Établit la connexion et la preuve d'identité (EX-6.10).
   * @param {number} delaiMs
   * @returns {Promise<void>}
   */
  ouvrir(delaiMs) {
    return new Promise((resoudre, rejeter) => {
      let fini = false;
      const echec = (raison) => {
        if (fini) return;
        fini = true;
        clearTimeout(minuteur);
        this.prise?.destroy();
        rejeter(new ErreurNoortraceIndisponible(`noortrace: enregistreur injoignable (${raison})`, false));
      };
      const minuteur = setTimeout(() => echec("delai"), delaiMs);
      const o = this.o;
      let c;
      if (o.socket) c = net.createConnection(o.socket);
      else if (o.tls) c = tls.connect({ host: o.tcp.hote, port: o.tcp.port, ca: o.tls.ca, cert: o.tls.cert, key: o.tls.key, servername: net.isIP(o.tcp.hote) ? undefined : o.tcp.hote });
      else c = net.createConnection(o.tcp.port, o.tcp.hote);
      this.prise = c;
      let identifie = false;
      c.on("error", (e) => {
        if (!identifie) echec(e.code ?? "erreur");
        else this._perdre();
      });
      c.on("close", () => {
        if (!identifie) echec("fermee");
        else this._perdre();
      });
      c.on(o.tls && !o.socket ? "secureConnect" : "connect", () => {
        // Prise TCP : première ligne {"noortrace_token": …}, sauf en mTLS (EX-6.10, EX-4.39).
        if (o.tcp && !o.tls) c.write(JSON.stringify({ noortrace_token: o.jeton ?? "" }) + "\n");
      });
      c.on("data", (x) => {
        this.tampon = this.tampon.length ? Buffer.concat([this.tampon, x]) : x;
        let k;
        while ((k = this.tampon.indexOf(10)) >= 0) {
          const ligne = this.tampon.subarray(0, k);
          this.tampon = this.tampon.subarray(k + 1);
          if (identifie) {
            this._ligne(ligne);
            continue;
          }
          let m = null;
          try {
            m = JSON.parse(ligne.toString("utf8"));
          } catch {
            m = null;
          }
          if (m && typeof m.noortrace_defi === "string" && /^[0-9a-f]{32}$/.test(m.noortrace_defi) && o.socket) {
            const f = path.join(path.dirname(o.socket), PREFIXE_DEFI + m.noortrace_defi);
            try {
              fs.closeSync(fs.openSync(f, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600));
            } catch (e) {
              return echec(`preuve_${e.code ?? "impossible"}`);
            }
            c.write(JSON.stringify({ noortrace_preuve: m.noortrace_defi }) + "\n");
            continue;
          }
          if (m && m.noortrace_identite === "acceptee") {
            identifie = true;
            fini = true;
            clearTimeout(minuteur);
            this._libre();
            resoudre();
            continue;
          }
          return echec("reponse_inattendue");
        }
      });
    });
  }

  _ligne(ligne) {
    let m;
    try {
      m = JSON.parse(ligne.toString("utf8"));
    } catch {
      return;
    }
    if (!m || typeof m.id !== "number") return;
    const a = this.attentes.get(m.id);
    if (!a) return;
    this.attentes.delete(m.id);
    clearTimeout(a.minuteur);
    this._libre();
    if (m.error) a.rejeter(erreurDepuisReponse(m.error));
    else a.resoudre(m.result);
  }

  /** Une prise sans requête en cours ne retient pas le processus (EX-6.11 (4)). */
  _libre() {
    if (this.attentes.size === 0) this.prise?.unref?.();
    else this.prise?.ref?.();
  }

  _perdre() {
    if (this.perdue) return;
    this.perdue = true;
    for (const [, a] of this.attentes) {
      clearTimeout(a.minuteur);
      a.rejeter(new ErreurNoortraceIndisponible("noortrace: connexion perdue", true));
    }
    this.attentes.clear();
    this.prise?.destroy();
    this.surPerte?.();
  }

  /**
   * Envoie une requête et attend sa réponse, au plus `delaiMs` (EX-6.11 (1)).
   * @param {string} methode nom complet `noortrace/sdk/<…>`
   * @param {object} params
   * @param {number} delaiMs
   * @returns {Promise<unknown>}
   */
  appeler(methode, params, delaiMs) {
    if (this.perdue) return Promise.reject(new ErreurNoortraceIndisponible("noortrace: connexion perdue", false));
    const id = this.prochainId++;
    const ligne = JSON.stringify({ jsonrpc: "2.0", id, method: methode, params }) + "\n";
    return new Promise((resoudre, rejeter) => {
      const minuteur = setTimeout(() => {
        if (!this.attentes.has(id)) return;
        this.attentes.delete(id);
        this._libre();
        rejeter(new ErreurNoortraceIndisponible("noortrace: delai ecoule", true));
      }, delaiMs);
      this.attentes.set(id, { resoudre, rejeter, minuteur });
      this._libre();
      // La requête est écrite : elle ne sera jamais renvoyée (EX-6.13).
      this.prise.write(ligne);
    });
  }

  fermer() {
    this.perdue = true;
    for (const [, a] of this.attentes) clearTimeout(a.minuteur);
    this.attentes.clear();
    this.prise?.destroy();
  }
}
