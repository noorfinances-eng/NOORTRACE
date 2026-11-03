// Couche d'accès des supports `azure-immutable-blob` et
// `gcs-object-retention` : requêtes d'EX-12.39 envoyées en HTTPS avec un
// jeton porteur (`Authorization: Bearer`, Entra ID pour Azure, OAuth 2.0 pour
// Google Cloud Storage). La signature à clé partagée d'Azure et l'obtention
// du jeton sont laissées aux outils du support (section 21) : la référence de
// secret porte un jeton déjà obtenu, objet JSON `{ "bearer_token": "…" }`.

import http from "node:http";
import https from "node:https";
import { ErreurTransport } from "./s3.mjs";

/**
 * Identifiants porteurs, lus depuis les octets d'une référence de secret.
 * @param {Uint8Array} octets
 * @returns {{bearer_token: string}}
 */
export function identifiantsBearer(octets) {
  let o;
  try {
    o = JSON.parse(Buffer.from(octets).toString("utf8"));
  } catch {
    throw new Error("identifiants illisibles (objet JSON attendu)");
  }
  if (typeof o?.bearer_token !== "string" || !o.bearer_token) throw new Error("identifiants : bearer_token attendu");
  return { bearer_token: o.bearer_token };
}

export class AccesBearer {
  /**
   * @param {{origine: string, jeton: string, tls?: {ca?: string|Buffer}, delaiMs?: number}} o
   */
  constructor(o) {
    this.origine = new URL(o.origine);
    this.jeton = o.jeton;
    this.tls = o.tls ?? {};
    this.delaiMs = o.delaiMs ?? 10000;
  }

  /**
   * @param {{method: string, target: string, headers: string[][], body: Uint8Array|null}} r
   * @returns {Promise<{statut: number, entetes: Record<string, string>, corps: Buffer}>}
   */
  envoyer(r) {
    const entetes = { host: this.origine.host, authorization: `Bearer ${this.jeton}` };
    for (const [n, v] of r.headers) entetes[n.toLowerCase()] = v;
    const module = this.origine.protocol === "http:" ? http : https;
    return new Promise((resolve, reject) => {
      const req = module.request(
        {
          hostname: this.origine.hostname.replace(/^\[|\]$/g, ""),
          port: this.origine.port || (this.origine.protocol === "http:" ? 80 : 443),
          method: r.method,
          path: r.target,
          headers: entetes,
          ca: this.tls.ca,
          agent: false,
        },
        (res) => {
          const m = [];
          res.on("data", (c) => m.push(c));
          res.on("end", () => {
            clearTimeout(t);
            const h = {};
            for (const [k, v] of Object.entries(res.headers)) h[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
            resolve({ statut: res.statusCode, entetes: h, corps: Buffer.concat(m) });
          });
        },
      );
      const t = setTimeout(() => req.destroy(new ErreurTransport(`délai de ${this.delaiMs} ms dépassé`)), this.delaiMs);
      req.on("error", (e) => {
        clearTimeout(t);
        reject(e instanceof ErreurTransport ? e : new ErreurTransport("support injoignable", e));
      });
      req.end(r.body ? Buffer.from(r.body) : undefined);
    });
  }
}
