// Classe B : moteur Transit de HashiCorp Vault et d'OpenBao (CT-2 §11.2,
// table des backends : type `ed25519`, `exportable: false` irréversible,
// `hash_algorithm` ignoré pour ed25519, Ed25519ph exclu).
//
// Requêtes (API HTTP de Transit, identique chez Vault et OpenBao) :
//   GET  <url>/v1/<mount>/keys/<nom>   → data.type, data.exportable,
//        data.latest_version, data.keys["<v>"].public_key (base64, 32 octets)
//   POST <url>/v1/<mount>/sign/<nom>   {"input": base64(message), "key_version": v}
//        → data.signature = "vault:v<v>:<base64 de 64 octets>"
// Authentification : en-tête `X-Vault-Token` (référence de secret
// `signer.backend.token`) et, si `namespace` n'est pas nul,
// `X-Vault-Namespace`. La version de clé dont la clé publique a été lue est
// épinglée dans chaque signature (lecture 185) : une rotation faite dans le
// backend ne change pas la clé qui signe pour l'enregistreur sans événement
// de rotation dans le journal.

import { Signataire } from "../signataires.mjs";
import { ErreurSignataire, requete, json, base64Strict } from "./commun.mjs";

export class SignataireTransit extends Signataire {
  /**
   * @param {object} p
   * @param {{type: "vault-transit"|"openbao-transit", url: string, mount: string, key_name: string, namespace: string|null}} p.backend
   * @param {Uint8Array} p.jeton
   * @param {string} p.keyId
   * @param {string|null} [p.nextKeyId] nom Transit de la clé suivante (lecture 177)
   * @param {number} [p.delaiMs]
   * @param {Buffer|string|null} [p.ca] autorité supplémentaire (essais)
   */
  constructor(p) {
    super();
    this.backend = p.backend;
    this.jeton = new Uint8Array(p.jeton);
    this.keyId = p.keyId;
    this.nextKeyId = p.nextKeyId ?? null;
    this.delai = p.delaiMs ?? 5000;
    this.ca = p.ca ?? null;
    /** Version épinglée par key_id. */
    this.versions = new Map();
  }

  get classe() {
    return "B";
  }

  get typeBackend() {
    return this.backend.type;
  }

  clesConnues() {
    return [this.keyId, ...(this.nextKeyId ? [this.nextKeyId] : [])];
  }

  nomCle(keyId) {
    if (keyId === this.keyId) return this.backend.key_name;
    if (keyId === this.nextKeyId) return this.nextKeyId;
    throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
  }

  localisation(keyId) {
    return { url: this.backend.url, mount: this.backend.mount, key_name: this.nomCle(keyId), namespace: this.backend.namespace, key_version: this.versions.get(keyId) ?? null };
  }

  _url(chemin) {
    return `${this.backend.url.replace(/\/+$/, "")}/v1/${this.backend.mount.replace(/^\/+|\/+$/g, "")}/${chemin}`;
  }

  async _appel(methode, chemin, corps) {
    const entetes = { "x-vault-token": Buffer.from(this.jeton).toString("utf8"), accept: "application/json" };
    if (this.backend.namespace) entetes["x-vault-namespace"] = this.backend.namespace;
    if (corps) entetes["content-type"] = "application/json";
    const r = await requete({ url: this._url(chemin), methode, entetes, corps: corps ? JSON.stringify(corps) : null, delaiMs: this.delai, ca: this.ca });
    const j = json(r.corps);
    if (r.statut !== 200) {
      const erreurs = Array.isArray(j?.errors) ? j.errors.filter((e) => typeof e === "string").join(" ; ").slice(0, 200) : "";
      throw new ErreurSignataire(`${this.backend.type} : statut ${r.statut}${erreurs ? ` (${erreurs})` : ""}`, { statut: r.statut });
    }
    if (!j || typeof j.data !== "object" || j.data === null) throw new ErreurSignataire(`${this.backend.type} : réponse sans data`);
    return j.data;
  }

  /** Lit la clé Transit et en contrôle la forme (type ed25519, non exportable). */
  async _lireCle(keyId) {
    const d = await this._appel("GET", `keys/${encodeURIComponent(this.nomCle(keyId))}`);
    if (d.type !== "ed25519") throw new ErreurSignataire(`clé Transit de type ${d.type} : ed25519 attendu (EX-11.1)`, { code: "type" });
    // EX-11.5 : `exportable: false` (irréversible chez Vault et OpenBao) ; une
    // clé exportable, ou dont la sauvegarde en clair est permise, est refusée (lecture 178).
    if (d.exportable !== false) throw new ErreurSignataire("clé Transit exportable : refusée (EX-11.5)", { code: "exportable" });
    if (d.allow_plaintext_backup === true) throw new ErreurSignataire("clé Transit à sauvegarde en clair permise : refusée (EX-11.5)", { code: "exportable" });
    return d;
  }

  async clePublique(keyId) {
    const d = await this._lireCle(keyId);
    const v = Number(d.latest_version);
    const k = d.keys?.[String(v)];
    if (!Number.isInteger(v) || v < 1 || !k || typeof k.public_key !== "string") throw new ErreurSignataire("clé Transit sans clé publique de dernière version");
    const p = base64Strict(k.public_key, "clé publique Transit");
    if (p.length !== 32) throw new ErreurSignataire("clé publique Transit : 32 octets attendus");
    this.versions.set(keyId, v);
    return p;
  }

  async signer(keyId, message) {
    let v = this.versions.get(keyId);
    if (v === undefined) {
      await this.clePublique(keyId);
      v = this.versions.get(keyId);
    }
    const d = await this._appel("POST", `sign/${encodeURIComponent(this.nomCle(keyId))}`, {
      input: Buffer.from(message).toString("base64"),
      key_version: v,
    });
    const m = /^vault:v([0-9]+):([A-Za-z0-9+/]*={0,2})$/.exec(String(d.signature ?? ""));
    if (!m) throw new ErreurSignataire("signature Transit illisible");
    if (Number(m[1]) !== v) throw new ErreurSignataire(`signature Transit de la version ${m[1]}, ${v} attendue`);
    return base64Strict(m[2], "signature Transit");
  }

  async sante() {
    for (const id of this.versions.size ? [...this.versions.keys()] : [this.keyId]) {
      const d = await this._lireCle(id);
      const v = this.versions.get(id);
      if (v !== undefined && !d.keys?.[String(v)]) return `version ${v} de la clé ${id} absente du backend`;
    }
    return "ok";
  }

  effacer() {
    this.jeton.fill(0);
  }
}
