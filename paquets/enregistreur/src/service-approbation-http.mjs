// Canal du noyau vers le service d'approbation (CT-2 EX-7.14, CT-3 §12.1) :
// requête HTTP/1.1 `POST <base>/v0/<méthode>`, corps et réponse objets JSON,
// `<base>` = `policy.approval.service.url`, ou la prise Unix
// `policy.approval.service.socket` avec la base `http://localhost`. La
// réponse est analysée en JSON strict ; une réponse illisible vaut une erreur
// du service. Jeton porteur facultatif (EX-18.8). Chaque message a son délai.
//
// Authentification du service (EX-18.8, CT-3 EX-12.2) sur la prise Unix :
// « par l'identifiant d'utilisateur attendu du pair (peer_user) et un
// répertoire de prise non inscriptible par les hôtes ni par les agents ».
// Node.js ne donne pas l'identité du pair d'une connexion (SO_PEERCRED) sans
// module natif : avant chaque message, le client vérifie que la prise est
// une prise dont le propriétaire (le processus qui l'a créée par bind) est
// `peer_user`, et que son répertoire appartient au compte 0 ou à `peer_user`
// et n'est inscriptible ni par le groupe ni par les autres ; nul autre ne peut
// alors substituer une autre prise sous ce nom (lecture du LISEZMOI). Un
// écart vaut indisponibilité du service (code `pair_non_verifie`), jamais une
// réponse acceptée. Le corps de réponse est borné (`tailleMax`).

import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import { analyserJsonIntegral, jcsIntegral } from "./jcs-integral.mjs";
import { ErreurServiceApprobation, ServiceApprobation } from "./approbations.mjs";
import { lireComptes } from "./mcp/amont.mjs";

/** Borne du corps d'une réponse du service (octets) : au-delà, réponse illisible. */
export const TAILLE_MAX_REPONSE_APPROBATION = 16 * 1024 * 1024;

export class ClientServiceApprobation extends ServiceApprobation {
  /**
   * @param {{url?: string|null, socket?: string|null, jeton?: string|null, timeout_ms?: number,
   *   peer_user?: string|null, tailleMax?: number}} p `peer_user` : utilisateur système attendu du
   *   pair sur la prise (EX-18.8) ; `tailleMax` : borne du corps de réponse
   */
  constructor(p) {
    super();
    this.url = p.url ? new URL(p.url) : null;
    this.socket = p.socket ?? null;
    this.jeton = p.jeton ?? null;
    this.delai = p.timeout_ms ?? 2000;
    this.peerUser = p.peer_user ?? null;
    this.tailleMax = p.tailleMax ?? TAILLE_MAX_REPONSE_APPROBATION;
    if (!this.url && !this.socket) throw new TypeError("url ou socket du service d'approbation attendu");
  }

  /**
   * Vérifie le pair d'une prise Unix (EX-18.8) : rend null, ou la raison du refus.
   * @returns {Promise<string|null>}
   */
  async verifierPair() {
    if (this.url || this.peerUser === null) return null;
    const compte = lireComptes().parNom.get(this.peerUser);
    if (!compte) return "peer_user_inconnu";
    let st;
    let rep;
    try {
      st = await fs.lstat(this.socket);
      rep = await fs.stat(path.dirname(path.resolve(this.socket)));
    } catch {
      return "prise_absente";
    }
    if (!st.isSocket()) return "prise_absente";
    if (st.uid !== compte.uid) return "proprietaire_prise";
    if ((rep.mode & 0o022) !== 0 || (rep.uid !== 0 && rep.uid !== compte.uid)) return "repertoire_inscriptible";
    return null;
  }

  /**
   * @param {string} methode
   * @param {object} corps
   * @param {number} [delai]
   * @returns {Promise<object>}
   */
  async appeler(methode, corps, delai = this.delai) {
    const refus = await this.verifierPair();
    if (refus) throw new ErreurServiceApprobation("pair_non_verifie", { raison: refus });
    return this._envoyer(methode, corps, delai);
  }

  _envoyer(methode, corps, delai) {
    const texte = Buffer.from(jcsIntegral(corps), "utf8");
    const base = this.url ? this.url.pathname.replace(/\/$/, "") : "";
    const options = {
      method: "POST",
      path: `${base}/v0/${methode}`,
      headers: { "content-type": "application/json", "content-length": texte.length, ...(this.jeton ? { authorization: `Bearer ${this.jeton}` } : {}) },
    };
    if (this.url) {
      options.hostname = this.url.hostname;
      options.port = this.url.port || (this.url.protocol === "https:" ? 443 : 80);
    } else {
      options.socketPath = this.socket;
      options.headers.host = "localhost";
    }
    const module = this.url?.protocol === "https:" ? https : http;
    return new Promise((resoudre0, rejeter0) => {
      // Délai du message (EX-7.14) : durée totale de l'échange, pas seulement
      // l'inactivité du flux ; au terme, la connexion est coupée (indisponible).
      let minuteur = null;
      const resoudre = (x) => {
        clearTimeout(minuteur);
        resoudre0(x);
      };
      const rejeter = (e) => {
        clearTimeout(minuteur);
        rejeter0(e);
      };
      const req = module.request(options, (res) => {
        const morceaux = [];
        let taille = 0;
        let coupe = false;
        res.on("data", (m) => {
          taille += m.length;
          if (taille > this.tailleMax) {
            // Corps au-delà de la borne : la connexion est coupée, réponse illisible.
            coupe = true;
            req.destroy();
            rejeter(new ErreurServiceApprobation("reponse_illisible", { raison: "trop_grande" }));
            return;
          }
          morceaux.push(m);
        });
        res.on("end", () => {
          if (coupe) return;
          let objet;
          try {
            objet = analyserJsonIntegral(new Uint8Array(Buffer.concat(morceaux)));
          } catch {
            rejeter(new ErreurServiceApprobation("reponse_illisible"));
            return;
          }
          if (res.statusCode >= 400) {
            const e = objet?.error;
            const code = typeof e?.code === "string" ? e.code : "erreur_http";
            // 401 (canal non authentifié, CT-3 EX-12.2) et 5xx `requete_invalide` (erreur
            // interne du service, dont un échec d'écriture de son état) ne répondent pas
            // au message : indisponibilité, réessayée, jamais une réponse finale (EX-7.20).
            if (res.statusCode === 401 || (res.statusCode >= 500 && code === "requete_invalide")) {
              rejeter(new ErreurServiceApprobation("indisponible", { statut: res.statusCode, code }));
              return;
            }
            rejeter(new ErreurServiceApprobation(code, e?.data ?? {}));
            return;
          }
          if (objet === null || typeof objet !== "object" || Array.isArray(objet)) {
            rejeter(new ErreurServiceApprobation("reponse_illisible"));
            return;
          }
          resoudre(objet);
        });
      });
      req.setTimeout(delai, () => req.destroy(new Error("délai")));
      minuteur = setTimeout(() => {
        req.destroy();
        rejeter(new ErreurServiceApprobation("indisponible", { raison: "delai" }));
      }, delai);
      minuteur.unref?.();
      req.on("error", () => rejeter(new ErreurServiceApprobation("indisponible")));
      req.end(texte);
    });
  }

  charger(r) {
    return this.appeler("charger", r);
  }
  evaluer(r) {
    return this.appeler("evaluer", r);
  }
  ouvrir(r) {
    return this.appeler("ouvrir", r);
  }
  decisions(r) {
    return this.appeler("decisions", r, (r.wait_ms ?? 25000) + this.delai);
  }
  acquitter(r) {
    return this.appeler("acquitter", r);
  }
  consommer(r) {
    return this.appeler("consommer", r);
  }
  expiration(r) {
    return this.appeler("expiration", r);
  }
}
