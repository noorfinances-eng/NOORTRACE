// Magasin de bail `etcd` (v3, CT-2 §13.2), par la passerelle JSON de l'API
// gRPC d'etcd (`POST /v3/...` sur chaque point de `lease.store.endpoints`) :
// acquisition par `LeaseGrant(ttl)` puis la transaction atomique
// `If(Version(key) == 0) Then(Put(key, instance, WithLease(lease)))` ; la clé
// `<prefix><org_id>/<journal_id>` disparaît à l'expiration du bail etcd ;
// l'époque est la `mod_revision` de la clé écrite par le `Put` (révision du
// magasin, compteur de 64 bits de toute la grappe, strictement croissant) ;
// renouvellement par `LeaseKeepAlive` et une transaction qui vérifie que la
// clé porte encore l'instance et l'époque ; vérification après écriture par
// la même transaction (EX-13.10 (2)). Un TTL en millisecondes est arrondi à
// la seconde supérieure (etcd compte en secondes).

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { MagasinBailReseau, ErreurMagasin } from "./bail-reseau.mjs";

const b64 = (t) => Buffer.from(t, "utf8").toString("base64");

/** Client minimal de la passerelle JSON d'etcd v3. */
export class ClientEtcd {
  /**
   * @param {string[]} points `lease.store.endpoints`
   * @param {{ca_file: string, cert_file: string|null, key_file: string|null}|null} tls
   * @param {number} [delaiMs]
   */
  constructor(points, tls, delaiMs = 5000) {
    this.points = points.map((p) => new URL(p));
    this.courant = 0;
    this.delaiMs = delaiMs;
    this.tls = tls
      ? { ca: fs.readFileSync(tls.ca_file), cert: tls.cert_file ? fs.readFileSync(tls.cert_file) : undefined, key: tls.key_file ? fs.readFileSync(tls.key_file) : undefined }
      : {};
  }

  _poster(u, chemin, corps, flux = false) {
    const module = u.protocol === "https:" ? https : http;
    const octets = Buffer.from(JSON.stringify(corps), "utf8");
    return new Promise((resolve, reject) => {
      const req = module.request(
        {
          hostname: u.hostname.replace(/^\[|\]$/g, ""),
          port: u.port || (u.protocol === "https:" ? 443 : 80),
          method: "POST",
          path: chemin,
          headers: { "content-type": "application/json", "content-length": octets.length },
          agent: false,
          ...this.tls,
        },
        (res) => {
          const m = [];
          const finir = () => {
            clearTimeout(t);
            const texte = Buffer.concat(m).toString("utf8");
            let o;
            try {
              o = JSON.parse(flux ? texte.split("\n")[0] : texte);
            } catch {
              reject(new ErreurMagasin("etcd : réponse illisible"));
              return;
            }
            if (res.statusCode !== 200) reject(new ErreurMagasin(`etcd : statut ${res.statusCode} ${o?.message ?? ""}`));
            else resolve(o);
          };
          res.on("data", (c) => {
            m.push(c);
            // Flux de LeaseKeepAlive : la première réponse suffit.
            if (flux && Buffer.concat(m).includes(0x0a)) {
              res.destroy();
              finir();
            }
          });
          res.on("end", finir);
          res.on("error", () => {});
        },
      );
      const t = setTimeout(() => req.destroy(new Error("délai")), this.delaiMs);
      req.on("error", (e) => {
        clearTimeout(t);
        reject(new ErreurMagasin(`etcd injoignable : ${e.code ?? e.message}`, e));
      });
      req.end(octets);
    });
  }

  /** Envoie au point courant, puis aux autres en cas d'échec de connexion. */
  async appeler(chemin, corps, flux = false) {
    let derniere;
    for (let k = 0; k < this.points.length; k++) {
      const i = (this.courant + k) % this.points.length;
      try {
        const r = await this._poster(this.points[i], chemin, corps, flux);
        this.courant = i;
        return r;
      } catch (e) {
        derniere = e;
        if (!/injoignable/.test(e.message)) throw e;
      }
    }
    throw derniere;
  }
}

export class MagasinBailEtcd extends MagasinBailReseau {
  /**
   * @param {object} o options de MagasinBailReseau, et :
   * @param {string[]} o.endpoints
   * @param {string} o.prefix `lease.store.prefix`
   * @param {object|null} o.tls `lease.store.tls`
   */
  constructor(o) {
    super(o);
    this.client = new ClientEtcd(o.endpoints, o.tls ?? null, Math.max(1000, Math.min(o.ttl_ms, 10000)));
    this.cle = `${o.prefix}${o.org_id}/${o.journal_id}`;
    this.bailEtcd = null;
  }

  get type() {
    return "etcd";
  }

  async _acquerir() {
    const g = await this.client.appeler("/v3/lease/grant", { TTL: String(Math.ceil(this.ttl / 1000)) });
    if (!g?.ID) throw new ErreurMagasin("etcd : LeaseGrant sans identifiant");
    const r = await this.client.appeler("/v3/kv/txn", {
      compare: [{ key: b64(this.cle), target: "VERSION", result: "EQUAL", version: "0" }],
      success: [{ request_put: { key: b64(this.cle), value: b64(this.instance), lease: g.ID } }],
      failure: [],
    });
    if (!r.succeeded) {
      await this.client.appeler("/v3/lease/revoke", { ID: g.ID }).catch(() => {});
      return null;
    }
    this.bailEtcd = g.ID;
    const rev = Number(r.responses?.[0]?.response_put?.header?.revision ?? r.header?.revision);
    if (!Number.isSafeInteger(rev)) throw new ErreurMagasin("etcd : révision illisible");
    return rev;
  }

  /** Transaction qui vérifie que la clé porte encore l'instance et l'époque. */
  async _comparer() {
    const r = await this.client.appeler("/v3/kv/txn", {
      compare: [
        { key: b64(this.cle), target: "MOD", result: "EQUAL", mod_revision: String(this.epoque) },
        { key: b64(this.cle), target: "VALUE", result: "EQUAL", value: b64(this.instance) },
      ],
      success: [],
      failure: [],
    });
    return r.succeeded === true;
  }

  async _renouveler() {
    const k = await this.client.appeler("/v3/lease/keepalive", { ID: this.bailEtcd }, true);
    const ttl = Number(k?.result?.TTL ?? 0);
    if (!(ttl > 0)) return false;
    return this._comparer();
  }

  async _verifier() {
    return this._comparer();
  }

  async _liberer() {
    if (this.bailEtcd) await this.client.appeler("/v3/lease/revoke", { ID: this.bailEtcd });
  }
}
