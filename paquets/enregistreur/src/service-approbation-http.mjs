// Canal du noyau vers le service d'approbation (CT-2 EX-7.14, CT-3 §12.1) :
// requête HTTP/1.1 `POST <base>/v0/<méthode>`, corps et réponse objets JSON,
// `<base>` = `policy.approval.service.url`, ou la prise Unix
// `policy.approval.service.socket` avec la base `http://localhost`. La
// réponse est analysée en JSON strict ; une réponse illisible vaut une erreur
// du service. Jeton porteur facultatif (EX-18.8). Chaque message a son délai.

import http from "node:http";
import https from "node:https";
import { analyserJsonIntegral, jcsIntegral } from "./jcs-integral.mjs";
import { ErreurServiceApprobation, ServiceApprobation } from "./approbations.mjs";

export class ClientServiceApprobation extends ServiceApprobation {
  /**
   * @param {{url?: string|null, socket?: string|null, jeton?: string|null, timeout_ms?: number}} p
   */
  constructor(p) {
    super();
    this.url = p.url ? new URL(p.url) : null;
    this.socket = p.socket ?? null;
    this.jeton = p.jeton ?? null;
    this.delai = p.timeout_ms ?? 2000;
    if (!this.url && !this.socket) throw new TypeError("url ou socket du service d'approbation attendu");
  }

  /**
   * @param {string} methode
   * @param {object} corps
   * @param {number} [delai]
   * @returns {Promise<object>}
   */
  appeler(methode, corps, delai = this.delai) {
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
    return new Promise((resoudre, rejeter) => {
      const req = module.request(options, (res) => {
        const morceaux = [];
        res.on("data", (m) => morceaux.push(m));
        res.on("end", () => {
          let objet;
          try {
            objet = analyserJsonIntegral(new Uint8Array(Buffer.concat(morceaux)));
          } catch {
            rejeter(new ErreurServiceApprobation("reponse_illisible"));
            return;
          }
          if (res.statusCode >= 400) {
            const e = objet?.error;
            rejeter(new ErreurServiceApprobation(typeof e?.code === "string" ? e.code : "erreur_http", e?.data ?? {}));
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
