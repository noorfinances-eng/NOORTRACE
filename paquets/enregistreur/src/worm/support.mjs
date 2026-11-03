// Opérations d'un support WORM (CT-2 §12.6, §12.11), au-dessus des requêtes
// exactes d'EX-12.39 et de la couche d'accès de chaque type :
//   - `s3-object-lock` (Amazon S3, MinIO, Exoscale SOS, cloudscale.ch) : toutes
//     les opérations (copie, état d'une version, liste des versions, lecture
//     et écriture conditionnelle d'un objet, gel, configuration de
//     verrouillage) ;
//   - `azure-immutable-blob`, `gcs-object-retention` : les opérations que le
//     texte fixe (gel d'une version, lecture de l'état, EX-12.39). La copie,
//     la liste des versions, la lecture et l'écriture d'un objet ne sont pas
//     fixées par CT-2 0.5 pour ces supports (12.6 : en-têtes de la réponse à
//     l'écriture « fixés en phase 2 » ; EX-12.35 : liste « non relue » ;
//     section 21 : copie GCS en version 1) : elles lèvent
//     `ErreurNonFixe` au lieu d'inventer une requête.
// Politique d'essais d'EX-12.40 : support injoignable, délai de 10 s dépassé,
// `500`, `502`, `503`, `504` → trois essais de la même requête, après 1 s,
// 2 s puis 4 s.

import * as R from "./requetes.mjs";
import { AccesS3, ErreurTransport, identifiantsS3, lirePageVersions, lireStatutGel, lireConfigurationVerrou, codeErreurS3 } from "./s3.mjs";
import { AccesBearer, identifiantsBearer } from "./bearer.mjs";

/** Délais des nouveaux essais d'EX-12.40, ms. */
export const DELAIS_ESSAIS = Object.freeze([1000, 2000, 4000]);
const STATUTS_TRANSITOIRES = new Set([500, 502, 503, 504]);

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

/** Opération que CT-2 0.5 ne fixe pas pour ce type de support. */
export class ErreurNonFixe extends Error {
  constructor(operation, type) {
    super(`${operation} non fixée par CT-2 0.5 pour ${type} (12.6, EX-12.35, section 21)`);
    this.name = "ErreurNonFixe";
    this.operation = operation;
  }
}

/**
 * Exécute une requête avec les essais d'EX-12.40 : rend la dernière réponse
 * (statut quelconque), ou lève la dernière ErreurTransport.
 * @param {() => Promise<{statut: number}>} f
 * @param {{delais?: number[], aussi?: number[]}} [o] `aussi` : statuts réessayés en plus (409 à la copie)
 */
export async function avecEssais(f, o = {}) {
  const delais = o.delais ?? DELAIS_ESSAIS;
  const aussi = new Set(o.aussi ?? []);
  let derniere;
  for (let k = 0; k <= delais.length; k++) {
    if (k > 0) await dormir(delais[k - 1]);
    try {
      const r = await f();
      if (!STATUTS_TRANSITOIRES.has(r.statut) && !aussi.has(r.statut)) return r;
      derniere = r;
    } catch (e) {
      if (!(e instanceof ErreurTransport)) throw e;
      derniere = e;
    }
  }
  if (derniere instanceof Error) throw derniere;
  return derniere;
}

/**
 * Opérations d'un support `s3-object-lock`.
 */
export class OperationsS3 {
  /**
   * @param {object} o
   * @param {object} o.worm membre `storage.seal.worm`
   * @param {{access_key_id: string, secret_access_key: string, session_token: string|null}} o.identifiants
   * @param {{ca?: string|Buffer}} [o.tls]
   * @param {number[]} [o.delais] délais des essais (EX-12.40)
   * @param {() => number} [o.murale]
   */
  constructor(o) {
    this.type = "s3-object-lock";
    this.worm = o.worm;
    this.prefix = o.worm.prefix;
    this.delais = o.delais ?? DELAIS_ESSAIS;
    this.acces = new AccesS3({ endpoint: o.worm.endpoint ?? null, region: o.worm.region ?? null, bucket: o.worm.bucket, identifiants: o.identifiants, tls: o.tls, murale: o.murale });
  }

  _envoyer(r, o = {}) {
    return avecEssais(() => this.acces.envoyer(r, o), { delais: this.delais, aussi: o.aussi });
  }

  /**
   * Copie conditionnelle à l'absence (EX-12.16, EX-12.31) ; `409` réessayé.
   * @returns {Promise<{statut: number, version_id: string|null, code: string|null}>}
   */
  async copier(cle, octets, gelAEcriture = false) {
    const r = await this._envoyer(R.requeteS3Copie(cle, octets, gelAEcriture), { aussi: [409] });
    return { statut: r.statut, version_id: r.entetes["x-amz-version-id"] ?? null, code: r.statut === 200 ? null : codeErreurS3(r.corps) };
  }

  /** Écriture conditionnelle d'un objet du registre des gels (EX-12.37). */
  async ecrireConditionnel(cle, octets) {
    const r = await this._envoyer(R.requeteS3EcritureConditionnelle(cle, octets));
    return { statut: r.statut, version_id: r.entetes["x-amz-version-id"] ?? null, code: r.statut === 200 ? null : codeErreurS3(r.corps) };
  }

  /** État d'une version (`HEAD` avec `versionId`, EX-12.33). */
  async etat(cle, versionId) {
    const r = await this._envoyer(R.requeteS3Etat(cle, versionId));
    return { statut: r.statut, entetes: r.entetes, json: null };
  }

  /** Lecture du gel d'une version (`GET ?legal-hold`) : `ON`, `OFF`, valeur brute, ou `null` sans gel. */
  async lireGel(cle, versionId) {
    const r = await this._envoyer(R.requeteS3LireGel(cle, versionId));
    if (r.statut !== 200) return { statut: r.statut, valeur: null, code: codeErreurS3(r.corps) };
    return { statut: 200, valeur: lireStatutGel(r.corps), code: null };
  }

  /** État de gel d'une version : `on`, `off`, `jamais`, `illisible` (table d'EX-12.33). */
  etatGel(lu) {
    if (lu.valeur === null) return "jamais";
    return lu.valeur === "ON" ? "on" : lu.valeur === "OFF" ? "off" : "illisible";
  }

  /** Pose ou levée du gel d'une version (`PutObjectLegalHold`). */
  async poserGel(cle, versionId, pose) {
    const r = await this._envoyer(R.requeteS3Gel(cle, versionId, pose));
    return { statut: r.statut, code: r.statut === 200 ? null : codeErreurS3(r.corps) };
  }

  /**
   * Liste de toutes les versions sous un préfixe (`ListObjectVersions`
   * paginé, EX-12.35 pas 1) ; `premierStatut` dit si la première requête a
   * abouti (EX-12.40 : code `4`).
   */
  async listerVersions(prefixe) {
    const versions = [];
    let keyMarker = null;
    let versionIdMarker = null;
    for (let page = 0; ; page++) {
      const r = await this._envoyer(R.requeteS3Liste({ prefix: prefixe, keyMarker, versionIdMarker }));
      if (r.statut !== 200) return { statut: r.statut, page, versions, code: codeErreurS3(r.corps) };
      const p = lirePageVersions(r.corps);
      versions.push(...p.versions);
      if (!p.tronquee) return { statut: 200, page, versions, code: null };
      keyMarker = p.keyMarker;
      versionIdMarker = p.versionIdMarker;
    }
  }

  /** Lit un objet (une version, ou la version courante). */
  async lire(cle, versionId = null) {
    const r = await this._envoyer(R.requeteS3Lire(cle, versionId));
    return { statut: r.statut, corps: r.corps, version_id: r.entetes["x-amz-version-id"] ?? null, last_modified: r.entetes["last-modified"] ?? null };
  }

  /** SHA-256 et longueur d'une version, sans garder le corps (EX-12.17). */
  async empreinte(cle, versionId = null) {
    const r = await this._envoyer(R.requeteS3Lire(cle, versionId), { hacher: true });
    return { statut: r.statut, sha256: r.sha256 ?? null, longueur: r.longueur ?? null, version_id: r.entetes["x-amz-version-id"] ?? null, last_modified: r.entetes["last-modified"] ?? null };
  }

  /** Configuration de verrouillage du bucket (EX-17.5). */
  async configurationVerrou() {
    const r = await this._envoyer(R.requeteS3LireConfiguration());
    if (r.statut !== 200) return { statut: r.statut, config: null, code: codeErreurS3(r.corps) };
    return { statut: 200, config: lireConfigurationVerrou(r.corps), code: null };
  }
}

/**
 * Opérations d'un support `azure-immutable-blob` : gel et état d'une version
 * (EX-12.39) ; le reste n'est pas fixé par CT-2 0.5.
 */
export class OperationsAzure {
  constructor(o) {
    this.type = "azure-immutable-blob";
    this.worm = o.worm;
    this.prefix = o.worm.prefix;
    this.delais = o.delais ?? DELAIS_ESSAIS;
    this.acces = new AccesBearer({ origine: o.worm.endpoint, jeton: o.identifiants.bearer_token, tls: o.tls });
  }

  _envoyer(r) {
    return avecEssais(() => this.acces.envoyer(r), { delais: this.delais });
  }

  async etat(cle, versionId) {
    const r = await this._envoyer(R.requeteAzureEtat(this.worm.bucket, cle, versionId));
    return { statut: r.statut, entetes: r.entetes, json: null };
  }

  /** Lecture du gel : `HEAD`, en-tête `x-ms-legal-hold` (EX-12.40 pas 5). */
  async lireGel(cle, versionId) {
    const r = await this.etat(cle, versionId);
    return { statut: r.statut, valeur: r.statut === 200 ? (r.entetes["x-ms-legal-hold"] ?? null) : null, code: null };
  }

  etatGel(lu) {
    if (lu.valeur === null) return "jamais";
    return lu.valeur === "true" ? "on" : lu.valeur === "false" ? "off" : "illisible";
  }

  async poserGel(cle, versionId, pose) {
    const r = await this._envoyer(R.requeteAzureGel(this.worm.bucket, cle, versionId, pose));
    return { statut: r.statut, code: r.entetes["x-ms-error-code"] ?? null };
  }

  async copier() { throw new ErreurNonFixe("copie", this.type); }
  async ecrireConditionnel() { throw new ErreurNonFixe("écriture du registre des gels", this.type); }
  async listerVersions() { throw new ErreurNonFixe("liste des versions", this.type); }
  async lire() { throw new ErreurNonFixe("lecture d'un objet", this.type); }
  async empreinte() { throw new ErreurNonFixe("lecture d'un objet", this.type); }
  async configurationVerrou() { throw new ErreurNonFixe("lecture de la politique de niveau version", this.type); }
}

/**
 * Opérations d'un support `gcs-object-retention` (hors production en
 * version 0) : gel (`temporaryHold`) et état d'une génération (EX-12.39).
 */
export class OperationsGcs {
  constructor(o) {
    this.type = "gcs-object-retention";
    this.worm = o.worm;
    this.prefix = o.worm.prefix;
    this.delais = o.delais ?? DELAIS_ESSAIS;
    this.acces = new AccesBearer({ origine: o.origine ?? "https://storage.googleapis.com", jeton: o.identifiants.bearer_token, tls: o.tls });
  }

  _envoyer(r) {
    return avecEssais(() => this.acces.envoyer(r), { delais: this.delais });
  }

  async etat(cle, generation) {
    const r = await this._envoyer(R.requeteGcsEtat(this.worm.bucket, cle, generation));
    let json = null;
    if (r.statut === 200) {
      try {
        json = JSON.parse(r.corps.toString("utf8"));
      } catch {
        json = null;
      }
    }
    return { statut: r.statut, entetes: r.entetes, json };
  }

  /** Lecture du gel : ressource objet, membre `temporaryHold`. */
  async lireGel(cle, generation) {
    const r = await this.etat(cle, generation);
    return { statut: r.statut, valeur: r.json && "temporaryHold" in r.json ? r.json.temporaryHold : null, code: null };
  }

  etatGel(lu) {
    if (lu.valeur === null || lu.valeur === undefined) return "jamais";
    return lu.valeur === true ? "on" : lu.valeur === false ? "off" : "illisible";
  }

  async poserGel(cle, generation, pose) {
    const r = await this._envoyer(R.requeteGcsGel(this.worm.bucket, cle, generation, pose));
    return { statut: r.statut, code: null };
  }

  async copier() { throw new ErreurNonFixe("copie", this.type); }
  async ecrireConditionnel() { throw new ErreurNonFixe("écriture du registre des gels", this.type); }
  async listerVersions() { throw new ErreurNonFixe("liste des versions", this.type); }
  async lire() { throw new ErreurNonFixe("lecture d'un objet", this.type); }
  async empreinte() { throw new ErreurNonFixe("lecture d'un objet", this.type); }
  async configurationVerrou() { throw new ErreurNonFixe("lecture de la rétention", this.type); }
}

/**
 * Opérations du support de `storage.seal.worm` avec des identifiants donnés
 * (octets d'une référence de secret, format du support).
 * @param {object} worm
 * @param {Uint8Array} identifiants
 * @param {{tls?: object, delais?: number[], murale?: () => number, origine?: string}} [o]
 */
export function operationsSupport(worm, identifiants, o = {}) {
  if (worm.type === "s3-object-lock") return new OperationsS3({ worm, identifiants: identifiantsS3(identifiants), ...o });
  if (worm.type === "azure-immutable-blob") return new OperationsAzure({ worm, identifiants: identifiantsBearer(identifiants), ...o });
  if (worm.type === "gcs-object-retention") return new OperationsGcs({ worm, identifiants: identifiantsBearer(identifiants), ...o });
  throw new Error(`type de support inconnu : ${worm.type}`);
}

