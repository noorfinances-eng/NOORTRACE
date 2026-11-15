// Couche d'accès d'un support `s3-object-lock` (Amazon S3 et services
// compatibles) : adresse, signature AWS SigV4 (écrite ici sur node:crypto,
// sans bibliothèque), envoi HTTPS, délai par requête. Les requêtes elles-mêmes
// (cible, en-têtes fixés par NOORTRACE, corps) viennent de requetes.mjs
// (EX-12.39) ; cette couche n'ajoute que `Host`, `x-amz-date`,
// `x-amz-content-sha256`, `x-amz-security-token` et `Authorization`.
//
// Adresse : `endpoint` nul → Amazon S3, style « virtual-hosted »
// (`https://<bucket>.s3.<region>.amazonaws.com<cible>`) ; `endpoint` donné
// (service compatible) → style « path » (`<endpoint>/<bucket><cible>`), le
// seul que tous les services compatibles servent sans DNS propre (lecture
// consignée au LISEZMOI).

import http from "node:http";
import https from "node:https";
import { createHash, createHmac } from "node:crypto";
import { analyserXml, enfant, enfants, texteDe } from "./xml.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const sha256 = (b) => createHash("sha256").update(b).digest();
const hmac = (k, d) => createHmac("sha256", k).update(d).digest();

/**
 * Identifiants d'un rôle sur un support S3, lus depuis les octets d'une
 * référence de secret (15.2) : objet JSON `{ "access_key_id",
 * "secret_access_key", "session_token"? }`.
 * @param {Uint8Array} octets
 * @returns {{access_key_id: string, secret_access_key: string, session_token: string|null}}
 */
export function identifiantsS3(octets) {
  let o;
  try {
    o = JSON.parse(Buffer.from(octets).toString("utf8"));
  } catch {
    throw new Error("identifiants S3 illisibles (objet JSON attendu)");
  }
  if (typeof o?.access_key_id !== "string" || typeof o?.secret_access_key !== "string" || !o.access_key_id || !o.secret_access_key) {
    throw new Error("identifiants S3 : access_key_id et secret_access_key attendus");
  }
  return { access_key_id: o.access_key_id, secret_access_key: o.secret_access_key, session_token: typeof o.session_token === "string" ? o.session_token : null };
}

function dateAmz(ms) {
  const d = new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.[0-9]{3}/, "");
  return { amz: d, jour: d.slice(0, 8) };
}

function encoderSigv4(t) {
  return encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Requête canonique de la requête (paramètres décodés puis réencodés, triés). */
function requeteCanonique(chemin, requete) {
  const params = requete === ""
    ? []
    : requete.split("&").map((p) => {
        const k = p.indexOf("=");
        const nom = decodeURIComponent(k < 0 ? p : p.slice(0, k));
        const val = k < 0 ? "" : decodeURIComponent(p.slice(k + 1));
        return [encoderSigv4(nom), encoderSigv4(val)];
      });
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return { chemin, requete: params.map(([n, v]) => `${n}=${v}`).join("&") };
}

/**
 * Signature SigV4 (en-têtes ajoutés à la requête).
 * @param {object} p
 * @returns {Record<string, string>} en-têtes complets à envoyer
 */
export function signerSigv4(p) {
  const { amz, jour } = dateAmz(p.instant);
  const corps = p.corps ?? Buffer.alloc(0);
  const empreinteCorps = hex(sha256(corps));
  const entetes = { host: p.hote, "x-amz-date": amz, "x-amz-content-sha256": empreinteCorps };
  if (p.identifiants.session_token) entetes["x-amz-security-token"] = p.identifiants.session_token;
  for (const [n, v] of p.entetes) entetes[n.toLowerCase()] = v;
  const noms = Object.keys(entetes).sort();
  const canon = requeteCanonique(p.chemin, p.requete);
  const creq = [p.methode, canon.chemin, canon.requete, noms.map((n) => `${n}:${String(entetes[n]).trim()}\n`).join(""), noms.join(";"), empreinteCorps].join("\n");
  const portee = `${jour}/${p.region}/s3/aws4_request`;
  const aSigner = ["AWS4-HMAC-SHA256", amz, portee, hex(sha256(creq))].join("\n");
  let k = hmac(`AWS4${p.identifiants.secret_access_key}`, jour);
  k = hmac(k, p.region);
  k = hmac(k, "s3");
  k = hmac(k, "aws4_request");
  const sig = hex(hmac(k, aSigner));
  entetes.authorization = `AWS4-HMAC-SHA256 Credential=${p.identifiants.access_key_id}/${portee}, SignedHeaders=${noms.join(";")}, Signature=${sig}`;
  return entetes;
}

/** Erreur de transport (injoignable, délai). */
export class ErreurTransport extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = "ErreurTransport";
  }
}

/**
 * Réponse du support refusée (étape 8) : corps plus grand que la
 * borne. Elle n'est pas réessayée (ce n'est pas une ErreurTransport).
 */
export class ErreurReponse extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurReponse";
  }
}

/** Borne du corps d'une réponse gardée en mémoire (listes, états, erreurs) : 16 Mio. */
export const LIMITE_REPONSE_OCTETS = 16 * 1024 * 1024;
/** Borne du corps d'un objet relu (segment, manifeste, pièce) : 256 Mio. */
export const LIMITE_OBJET_OCTETS = 256 * 1024 * 1024;

/**
 * Accès à un bucket S3.
 */
export class AccesS3 {
  /**
   * @param {object} o
   * @param {string|null} o.endpoint origine HTTPS (`storage.seal.worm.endpoint`) ou null (Amazon S3)
   * @param {string|null} o.region région ; à défaut `us-east-1`
   * @param {string} o.bucket
   * @param {{access_key_id: string, secret_access_key: string, session_token: string|null}} o.identifiants
   * @param {number} [o.delaiMs] délai par requête (10 s, EX-12.40)
   * @param {() => number} [o.murale] horloge de la signature
   * @param {{ca?: string|Buffer}} [o.tls] autorité de confiance supplémentaire (tests)
   */
  constructor(o) {
    this.bucket = o.bucket;
    this.region = o.region ?? "us-east-1";
    this.identifiants = o.identifiants;
    this.delaiMs = o.delaiMs ?? 10000;
    this.murale = o.murale ?? (() => Date.now());
    this.tls = o.tls ?? {};
    if (o.endpoint) {
      const u = new URL(o.endpoint);
      this.origine = u;
      this.stylePath = true;
    } else {
      this.origine = new URL(this.region === "us-east-1" ? `https://${o.bucket}.s3.amazonaws.com` : `https://${o.bucket}.s3.${this.region}.amazonaws.com`);
      this.stylePath = false;
    }
  }

  /** Chemin et requête réels d'une cible relative au service. */
  _adresse(cible) {
    const q = cible.indexOf("?");
    let chemin = q < 0 ? cible : cible.slice(0, q);
    const requete = q < 0 ? "" : cible.slice(q + 1);
    if (this.stylePath) chemin = chemin === "/" ? `/${this.bucket}` : `/${this.bucket}${chemin}`;
    return { chemin, requete };
  }

  /**
   * Envoie une requête de requetes.mjs ; rend le statut, les en-têtes (noms en
   * minuscules) et le corps. Une erreur de réseau ou un délai dépassé lèvent
   * ErreurTransport.
   * @param {{method: string, target: string, headers: string[][], body: Uint8Array|null}} r
   * @param {{hacher?: boolean, maxOctets?: number}} [o] `hacher` : le corps d'une réponse 200 n'est pas gardé ;
   *   son SHA-256 (`0x…`) et sa longueur sont calculés au fil de l'eau ; `maxOctets` : borne du corps gardé
   *   (défaut `LIMITE_REPONSE_OCTETS`) ; au-delà, la réponse est abandonnée et ErreurReponse levée
   * @returns {Promise<{statut: number, entetes: Record<string, string>, corps: Buffer, sha256?: string, longueur?: number}>}
   */
  envoyer(r, o = {}) {
    const maxOctets = o.maxOctets ?? LIMITE_REPONSE_OCTETS;
    const { chemin, requete } = this._adresse(r.target);
    const hote = this.origine.host;
    const entetes = signerSigv4({
      methode: r.method,
      hote,
      chemin,
      requete,
      entetes: r.headers,
      corps: r.body,
      region: this.region,
      identifiants: this.identifiants,
      instant: this.murale(),
    });
    if (!r.body && r.method !== "GET" && r.method !== "HEAD" && entetes["content-length"] === undefined) entetes["content-length"] = "0";
    const module = this.origine.protocol === "http:" ? http : https;
    return new Promise((resolve, reject) => {
      const req = module.request(
        {
          protocol: this.origine.protocol,
          hostname: this.origine.hostname.replace(/^\[|\]$/g, ""),
          port: this.origine.port || (this.origine.protocol === "http:" ? 80 : 443),
          method: r.method,
          path: requete ? `${chemin}?${requete}` : chemin,
          headers: entetes,
          ca: this.tls.ca,
          agent: false,
        },
        (res) => {
          const m = [];
          const empreinte = o.hacher && res.statusCode === 200 ? createHash("sha256") : null;
          let longueur = 0;
          let fini = false;
          res.on("data", (c) => {
            if (fini) return;
            longueur += c.length;
            if (empreinte) {
              empreinte.update(c);
              return;
            }
            if (longueur > maxOctets) {
              // Corps au-delà de la borne : rien de plus n'est gardé, la connexion est fermée.
              fini = true;
              m.length = 0;
              clearTimeout(minuteur);
              res.destroy();
              req.destroy();
              reject(new ErreurReponse(`réponse du support plus grande que la borne de ${maxOctets} octets`));
              return;
            }
            m.push(c);
          });
          res.on("end", () => {
            if (fini) return;
            fini = true;
            clearTimeout(minuteur);
            const h = {};
            for (const [k, v] of Object.entries(res.headers)) h[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
            const x = { statut: res.statusCode, entetes: h, corps: Buffer.concat(m) };
            if (empreinte) Object.assign(x, { sha256: `0x${empreinte.digest("hex")}`, longueur });
            resolve(x);
          });
          res.on("error", (e) => {
            if (fini) return;
            fini = true;
            clearTimeout(minuteur);
            reject(new ErreurTransport("réponse interrompue", e));
          });
        },
      );
      const minuteur = setTimeout(() => req.destroy(new ErreurTransport(`délai de ${this.delaiMs} ms dépassé`)), this.delaiMs);
      req.on("error", (e) => {
        clearTimeout(minuteur);
        if (e instanceof ErreurReponse) return reject(e);
        reject(e instanceof ErreurTransport ? e : new ErreurTransport("support injoignable", e));
      });
      if (r.body) req.end(Buffer.from(r.body));
      else req.end();
    });
  }
}

/**
 * Code d'erreur d'une réponse S3 (`<Error><Code>`), ou null.
 * @param {Buffer} corps
 */
export function codeErreurS3(corps) {
  try {
    const x = analyserXml(corps.toString("utf8"));
    return texteDe(enfant(x, "Error"), "Code");
  } catch {
    return null;
  }
}

/**
 * Lit une page de `ListObjectVersions`.
 * @param {Buffer} corps
 * @returns {{versions: {key: string, version_id: string, is_latest: boolean, delete_marker: boolean, last_modified: string|null}[],
 *   tronquee: boolean, keyMarker: string|null, versionIdMarker: string|null}}
 */
export function lirePageVersions(corps) {
  const x = enfant(analyserXml(corps.toString("utf8")), "ListVersionsResult");
  if (!x) throw new Error("réponse ListObjectVersions illisible");
  const versions = [];
  for (const e of x.enfants) {
    if (e.nom !== "Version" && e.nom !== "DeleteMarker") continue;
    const key = texteDe(e, "Key");
    const version_id = texteDe(e, "VersionId");
    // Une version sans clé ni identifiant n'est pas une version : la page entière est refusée.
    if (typeof key !== "string" || key === "" || typeof version_id !== "string" || version_id === "") throw new Error("réponse ListObjectVersions illisible : Key ou VersionId absent");
    versions.push({
      key,
      version_id,
      is_latest: texteDe(e, "IsLatest") === "true",
      delete_marker: e.nom === "DeleteMarker",
      last_modified: texteDe(e, "LastModified"),
    });
  }
  return {
    versions,
    tronquee: texteDe(x, "IsTruncated") === "true",
    keyMarker: texteDe(x, "NextKeyMarker"),
    versionIdMarker: texteDe(x, "NextVersionIdMarker"),
  };
}

/**
 * Lit la réponse de `GetObjectLegalHold` : `ON`, `OFF`, ou la valeur brute.
 * @param {Buffer} corps
 * @returns {string|null}
 */
export function lireStatutGel(corps) {
  try {
    return texteDe(enfant(analyserXml(corps.toString("utf8")), "LegalHold"), "Status");
  } catch {
    return null;
  }
}

/**
 * Lit la configuration de verrouillage d'un bucket (`GetObjectLockConfiguration`).
 * @param {Buffer} corps
 * @returns {{enabled: string|null, mode: string|null, days: number|null, years: number|null}}
 */
export function lireConfigurationVerrou(corps) {
  const x = enfant(analyserXml(corps.toString("utf8")), "ObjectLockConfiguration");
  if (!x) throw new Error("configuration de verrouillage illisible");
  const d = enfant(enfant(x, "Rule"), "DefaultRetention");
  const n = (t) => (t !== null && /^[0-9]{1,9}$/.test(t) ? Number(t) : null);
  return { enabled: texteDe(x, "ObjectLockEnabled"), mode: texteDe(d, "Mode"), days: n(texteDe(d, "Days")), years: n(texteDe(d, "Years")) };
}

export { enfants };
