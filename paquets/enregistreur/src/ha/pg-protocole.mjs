// Client minimal du protocole de PostgreSQL (version 3 du protocole « frontend/
// backend »), écrit sur node:net et node:tls, sans bibliothèque : démarrage,
// authentification (confiance, mot de passe en clair ou MD5, SCRAM-SHA-256 de
// la RFC 7677), TLS sur demande (`SSLRequest`), requête étendue à paramètres
// texte (`Parse`, `Bind`, `Describe`, `Execute`, `Sync`) pour que les valeurs
// ne soient jamais interpolées dans le texte SQL. Il ne sert qu'au magasin de
// bail de CT-2 §13.2 : une connexion, une requête à la fois.

import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

/** Erreur rendue par le serveur (`ErrorResponse`) ou de protocole. */
export class ErreurPg extends Error {
  constructor(message, champs = {}) {
    super(message);
    this.name = "ErreurPg";
    this.champs = champs;
    this.sqlstate = champs.C ?? null;
  }
}

/**
 * Analyse un DSN URI (`postgresql://utilisateur:motdepasse@hote:port/base?sslmode=…`).
 * `sslmode` : `disable` (défaut), `require`, `verify-ca`, `verify-full`.
 * @param {string} dsn
 * @returns {{hote: string, port: number, utilisateur: string, motDePasse: string|null, base: string, sslmode: string, sslrootcert: string|null}}
 */
export function analyserDsn(dsn) {
  let u;
  try {
    u = new URL(dsn);
  } catch {
    throw new ErreurPg("DSN illisible (forme URI postgresql:// attendue)");
  }
  if (u.protocol !== "postgresql:" && u.protocol !== "postgres:") throw new ErreurPg("DSN : schéma postgresql:// attendu");
  const sslmode = u.searchParams.get("sslmode") ?? "disable";
  if (!["disable", "require", "verify-ca", "verify-full"].includes(sslmode)) throw new ErreurPg(`DSN : sslmode ${sslmode} non pris en charge`);
  return {
    hote: u.hostname.replace(/^\[|\]$/g, "") || "127.0.0.1",
    port: u.port ? Number(u.port) : 5432,
    utilisateur: decodeURIComponent(u.username),
    motDePasse: u.password ? decodeURIComponent(u.password) : null,
    base: decodeURIComponent(u.pathname.replace(/^\//, "")) || decodeURIComponent(u.username),
    sslmode,
    sslrootcert: u.searchParams.get("sslrootcert"),
  };
}

function message(type, corps) {
  const b = Buffer.alloc(5 + corps.length);
  b.write(type, 0, "latin1");
  b.writeInt32BE(4 + corps.length, 1);
  corps.copy(b, 5);
  return b;
}

const cstr = (s) => Buffer.concat([Buffer.from(s, "utf8"), Buffer.from([0])]);
const i16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeInt16BE(n);
  return b;
};
const i32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n);
  return b;
};

function champsErreur(corps) {
  const champs = {};
  let i = 0;
  while (i < corps.length && corps[i] !== 0) {
    const t = String.fromCharCode(corps[i]);
    const f = corps.indexOf(0, i + 1);
    champs[t] = corps.subarray(i + 1, f).toString("utf8");
    i = f + 1;
  }
  return champs;
}

const hmac = (k, d) => createHmac("sha256", k).update(d).digest();
const h256 = (d) => createHash("sha256").update(d).digest();
const xor = (a, b) => Buffer.from(a.map((x, k) => x ^ b[k]));

/** Une connexion au serveur. */
export class ConnexionPg {
  /**
   * @param {ReturnType<typeof analyserDsn>} dsn
   * @param {{delaiMs?: number}} [o]
   */
  constructor(dsn, o = {}) {
    this.dsn = dsn;
    this.delaiMs = o.delaiMs ?? 10000;
    this.tampon = Buffer.alloc(0);
    this.attente = null;
    this.ferme = false;
  }

  _lier(socket) {
    this.socket = socket;
    socket.on("data", (d) => {
      this.tampon = Buffer.concat([this.tampon, d]);
      this._reveiller();
    });
    const fin = (e) => {
      this.ferme = true;
      this.erreur = this.erreur ?? new ErreurPg(`connexion perdue${e?.message ? ` : ${e.message}` : ""}`);
      this._reveiller();
    };
    socket.on("error", fin);
    socket.on("close", fin);
  }

  _reveiller() {
    const a = this.attente;
    if (a) {
      this.attente = null;
      a();
    }
  }

  /** Prochain message `{ type, corps }` ; lève à la fermeture ou au délai. */
  async _lire(delaiMs = this.delaiMs) {
    const limite = Date.now() + delaiMs;
    for (;;) {
      if (this.tampon.length >= 5) {
        const n = this.tampon.readInt32BE(1);
        if (this.tampon.length >= 1 + n) {
          const type = String.fromCharCode(this.tampon[0]);
          const corps = this.tampon.subarray(5, 1 + n);
          this.tampon = this.tampon.subarray(1 + n);
          return { type, corps: Buffer.from(corps) };
        }
      }
      if (this.ferme) throw this.erreur;
      const reste = limite - Date.now();
      if (reste <= 0) {
        this.detruire();
        throw new ErreurPg(`délai de ${delaiMs} ms dépassé`);
      }
      await new Promise((r) => {
        const t = setTimeout(r, reste);
        this.attente = () => {
          clearTimeout(t);
          r();
        };
      });
    }
  }

  _ecrire(b) {
    this.socket.write(b);
  }

  /** Ouvre la connexion et s'authentifie. */
  async ouvrir() {
    const d = this.dsn;
    let socket = await new Promise((res, rej) => {
      const s = net.connect({ host: d.hote, port: d.port });
      const t = setTimeout(() => {
        s.destroy();
        rej(new ErreurPg("magasin injoignable (délai de connexion)"));
      }, this.delaiMs);
      s.once("connect", () => {
        clearTimeout(t);
        res(s);
      });
      s.once("error", (e) => {
        clearTimeout(t);
        rej(new ErreurPg(`magasin injoignable : ${e.code ?? e.message}`));
      });
    });
    if (d.sslmode !== "disable") {
      socket.write(Buffer.concat([i32(8), i32(80877103)]));
      const r = await new Promise((res, rej) => {
        socket.once("data", (b) => res(b));
        socket.once("error", rej);
      });
      if (r[0] !== 0x53) {
        socket.destroy();
        throw new ErreurPg("le serveur refuse TLS (sslmode exige TLS)");
      }
      const ca = d.sslrootcert ? fs.readFileSync(d.sslrootcert) : undefined;
      socket = await new Promise((res, rej) => {
        const s = tls.connect({
          socket,
          servername: net.isIP(d.hote) ? undefined : d.hote,
          ca,
          rejectUnauthorized: d.sslmode !== "require",
          checkServerIdentity: d.sslmode === "verify-full" ? tls.checkServerIdentity : () => undefined,
        });
        s.once("secureConnect", () => res(s));
        s.once("error", rej);
      });
    }
    this._lier(socket);
    const params = Buffer.concat([cstr("user"), cstr(d.utilisateur), cstr("database"), cstr(d.base), cstr("client_encoding"), cstr("UTF8"), Buffer.from([0])]);
    const corps = Buffer.concat([i32(196608), params]);
    this._ecrire(Buffer.concat([i32(4 + corps.length), corps]));
    await this._authentifier();
    for (;;) {
      const m = await this._lire();
      if (m.type === "Z") return;
      if (m.type === "E") throw new ErreurPg(champsErreur(m.corps).M ?? "erreur", champsErreur(m.corps));
    }
  }

  async _authentifier() {
    let scram = null;
    for (;;) {
      const m = await this._lire();
      if (m.type === "E") throw new ErreurPg(champsErreur(m.corps).M ?? "authentification refusée", champsErreur(m.corps));
      if (m.type !== "R") throw new ErreurPg(`message inattendu à l'authentification : ${m.type}`);
      const code = m.corps.readInt32BE(0);
      if (code === 0) return;
      const mdp = this.dsn.motDePasse;
      if (code === 3) {
        if (mdp === null) throw new ErreurPg("mot de passe exigé par le serveur");
        this._ecrire(message("p", cstr(mdp)));
      } else if (code === 5) {
        if (mdp === null) throw new ErreurPg("mot de passe exigé par le serveur");
        const sel = m.corps.subarray(4, 8);
        const a = createHash("md5").update(mdp + this.dsn.utilisateur).digest("hex");
        const b = createHash("md5").update(Buffer.concat([Buffer.from(a), sel])).digest("hex");
        this._ecrire(message("p", cstr(`md5${b}`)));
      } else if (code === 10) {
        const mecas = m.corps.subarray(4).toString("utf8").split("\0").filter(Boolean);
        if (!mecas.includes("SCRAM-SHA-256")) throw new ErreurPg("mécanisme SASL non pris en charge");
        if (mdp === null) throw new ErreurPg("mot de passe exigé par le serveur");
        const nonce = randomBytes(18).toString("base64");
        const premierNu = `n=,r=${nonce}`;
        scram = { nonce, premierNu };
        const initial = Buffer.from(`n,,${premierNu}`, "utf8");
        this._ecrire(message("p", Buffer.concat([cstr("SCRAM-SHA-256"), i32(initial.length), initial])));
      } else if (code === 11) {
        const serveurPremier = m.corps.subarray(4).toString("utf8");
        const attrs = Object.fromEntries(serveurPremier.split(",").map((x) => [x[0], x.slice(2)]));
        if (!attrs.r?.startsWith(scram.nonce)) throw new ErreurPg("SCRAM : nonce du serveur invalide");
        const sel = Buffer.from(attrs.s, "base64");
        const iter = Number(attrs.i);
        const sale = pbkdf2Sync(Buffer.from(mdp.normalize("NFKC"), "utf8"), sel, iter, 32, "sha256");
        const cleClient = hmac(sale, "Client Key");
        const sansPreuve = `c=biws,r=${attrs.r}`;
        const auth = `${scram.premierNu},${serveurPremier},${sansPreuve}`;
        const preuve = xor(cleClient, hmac(h256(cleClient), auth));
        scram.signatureServeur = hmac(hmac(sale, "Server Key"), auth);
        this._ecrire(message("p", Buffer.from(`${sansPreuve},p=${preuve.toString("base64")}`, "utf8")));
      } else if (code === 12) {
        const v = m.corps.subarray(4).toString("utf8");
        const recu = Buffer.from(v.replace(/^v=/, ""), "base64");
        if (!v.startsWith("v=") || recu.length !== 32 || !timingSafeEqual(recu, scram.signatureServeur)) throw new ErreurPg("SCRAM : signature du serveur invalide");
      } else {
        throw new ErreurPg(`méthode d'authentification ${code} non prise en charge`);
      }
    }
  }

  /**
   * Requête étendue : paramètres texte (ou null), résultats texte.
   * @param {string} sql
   * @param {(string|null)[]} [params]
   * @returns {Promise<{lignes: (string|null)[][], colonnes: string[], commande: string|null}>}
   */
  async requete(sql, params = []) {
    if (this.ferme) throw this.erreur ?? new ErreurPg("connexion fermée");
    const bind = [cstr(""), cstr(""), i16(0), i16(params.length)];
    for (const p of params) {
      if (p === null) bind.push(i32(-1));
      else {
        const b = Buffer.from(String(p), "utf8");
        bind.push(i32(b.length), b);
      }
    }
    bind.push(i16(0));
    this._ecrire(
      Buffer.concat([
        message("P", Buffer.concat([cstr(""), cstr(sql), i16(0)])),
        message("B", Buffer.concat(bind)),
        message("D", Buffer.concat([Buffer.from("P"), cstr("")])),
        message("E", Buffer.concat([cstr(""), i32(0)])),
        message("S", Buffer.alloc(0)),
      ]),
    );
    const lignes = [];
    let colonnes = [];
    let commande = null;
    let erreur = null;
    for (;;) {
      const m = await this._lire();
      if (m.type === "T") {
        const n = m.corps.readInt16BE(0);
        let i = 2;
        colonnes = [];
        for (let k = 0; k < n; k++) {
          const f = m.corps.indexOf(0, i);
          colonnes.push(m.corps.subarray(i, f).toString("utf8"));
          i = f + 1 + 18;
        }
      } else if (m.type === "D") {
        const n = m.corps.readInt16BE(0);
        let i = 2;
        const l = [];
        for (let k = 0; k < n; k++) {
          const len = m.corps.readInt32BE(i);
          i += 4;
          if (len < 0) l.push(null);
          else {
            l.push(m.corps.subarray(i, i + len).toString("utf8"));
            i += len;
          }
        }
        lignes.push(l);
      } else if (m.type === "C") {
        commande = m.corps.subarray(0, m.corps.length - 1).toString("utf8");
      } else if (m.type === "E") {
        erreur = new ErreurPg(champsErreur(m.corps).M ?? "erreur", champsErreur(m.corps));
      } else if (m.type === "Z") {
        if (erreur) throw erreur;
        return { lignes, colonnes, commande };
      }
    }
  }

  /** Coupe la connexion sans politesse. */
  detruire() {
    this.ferme = true;
    this.erreur = this.erreur ?? new ErreurPg("connexion fermée");
    this.socket?.destroy();
  }

  /** Ferme proprement (`Terminate`). */
  fermer() {
    if (!this.ferme && this.socket) {
      try {
        this._ecrire(message("X", Buffer.alloc(0)));
      } catch {
        // déjà fermée
      }
    }
    this.detruire();
  }
}
