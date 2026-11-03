// Classe A : module PKCS#11 (CT-2 §11.2, EX-11.10).
//
// Le démon parle au module du fabricant par un processus auxiliaire
// (`pkcs11-auxiliaire.py`, bibliothèque standard de Python seule : ctypes),
// jamais en chargeant la bibliothèque dans son propre processus (lecture
// 174) : un C_Sign bloqué est interrompu en tuant l'auxiliaire, ce qui tient
// le délai `signer.timeout_ms` d'EX-11.18 ; la seconde tentative de
// l'enveloppe commune relance un auxiliaire neuf.
//
// EX-11.10 : `CKM_EDDSA` (0x1057) sans paramètre, clé `CKK_EC_EDWARDS`
// (0x40) dont `CKA_EC_PARAMS` est `edwards25519` (curveName) ou l'OID
// 1.3.101.112 ; `C_Sign` en une seule partie ; clé publique lue dans
// `CKA_EC_POINT` ; signature de 64 octets vérifiée par l'enveloppe commune
// (EX-11.6). Le code PIN (référence de secret, EX-15.3) passe par l'entrée
// standard de l'auxiliaire, jamais par ses arguments ni son environnement.

import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Signataire } from "../signataires.mjs";
import { ErreurSignataire } from "./commun.mjs";

/** Auxiliaire livré avec le paquet. */
export const AUXILIAIRE_PKCS11 = path.join(path.dirname(fileURLToPath(import.meta.url)), "pkcs11-auxiliaire.py");

/**
 * Table de correspondance des mécanismes nommés par `signer.backend.mechanism`
 * (EX-11.10). `CKM_CLOUDHSM_EDDSA` est le mécanisme propriétaire d'AWS
 * CloudHSM, défini dans `cloudhsm_pkcs11_vendor_defs.h` du kit du fabricant ;
 * sa valeur numérique n'est écrite ni dans CT-2 ni dans les pages lues
 * (R3 F-9) : elle n'est pas établie ici, et un démon qui la nomme refuse de
 * démarrer plutôt que d'employer une valeur devinée (lecture 176).
 */
export const MECANISMES_PKCS11 = Object.freeze({
  CKM_EDDSA: 0x1057,
  CKM_CLOUDHSM_EDDSA: null,
});

/** Module PKCS#11 logiciel connu (CT-2 §11.2 : SoftHSM2 vaut la classe D). */
export const MODULE_LOGICIEL = /(^|\/)libsofthsm2\.so$/;

export class SignatairePkcs11 extends Signataire {
  /**
   * @param {object} p
   * @param {{module: string, token_label: string, key_label: string, mechanism: string}} p.backend `signer.backend`
   * @param {Uint8Array} p.pin code PIN résolu
   * @param {string} p.keyId `signer.key_id`
   * @param {string|null} [p.nextKeyId] `signer.rotation.next_key_id` (étiquette de la clé suivante, lecture 177)
   * @param {number} [p.delaiMs] délai d'une opération (défaut 5000)
   * @param {string} [p.python] interpréteur (défaut `python3` du PATH)
   * @param {string} [p.auxiliaire] chemin de l'auxiliaire
   * @param {NodeJS.ProcessEnv} [p.env] environnement de l'auxiliaire (sans les secrets du démon)
   */
  constructor(p) {
    super();
    const m = MECANISMES_PKCS11[p.backend.mechanism];
    if (m === undefined) throw new ErreurSignataire(`mécanisme ${p.backend.mechanism} inconnu (EX-11.10)`);
    if (m === null) {
      throw new ErreurSignataire(`mécanisme ${p.backend.mechanism} : valeur numérique non établie (en-tête du fabricant non lu, lecture 176)`);
    }
    this.mecanisme = m;
    this.backend = p.backend;
    this.pin = new Uint8Array(p.pin);
    this.keyId = p.keyId;
    this.nextKeyId = p.nextKeyId ?? null;
    this.delai = p.delaiMs ?? 5000;
    this.python = p.python ?? "python3";
    this.auxiliaire = p.auxiliaire ?? AUXILIAIRE_PKCS11;
    this.env = p.env ?? { PATH: process.env.PATH ?? "" };
    /** Forme de CKA_EC_PARAMS et de CKA_EC_POINT lues, par key_id (consignées au démarrage). */
    this.formes = new Map();
    this.proc = null;
    this.file = Promise.resolve();
  }

  get classe() {
    return "A";
  }

  get typeBackend() {
    return "pkcs11";
  }

  clesConnues() {
    return [this.keyId, ...(this.nextKeyId ? [this.nextKeyId] : [])];
  }

  /** Étiquette PKCS#11 de la clé d'un key_id (lecture 177). */
  etiquette(keyId) {
    if (keyId === this.keyId) return this.backend.key_label;
    if (keyId === this.nextKeyId) return this.nextKeyId;
    throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
  }

  /** Identifiant de la clé chez le backend (consigné, jamais secret). */
  localisation(keyId) {
    return { token_label: this.backend.token_label, key_label: this.etiquette(keyId), mechanism: this.backend.mechanism };
  }

  _lancer() {
    const p = spawn(this.python, ["-I", "-S", this.auxiliaire, this.backend.module, this.backend.token_label], {
      env: this.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const etat = { p, tampon: "", attente: [], mort: null };
    p.stdout.setEncoding("utf8");
    p.stdout.on("data", (d) => {
      etat.tampon += d;
      let i;
      while ((i = etat.tampon.indexOf("\n")) >= 0) {
        const ligne = etat.tampon.slice(0, i);
        etat.tampon = etat.tampon.slice(i + 1);
        const r = etat.attente.shift();
        let o = null;
        try {
          o = JSON.parse(ligne);
        } catch {
          o = { ok: false, error: "réponse illisible de l'auxiliaire" };
        }
        r?.(o);
      }
    });
    p.stderr.on("data", () => {});
    const mourir = (raison) => {
      etat.mort = raison;
      for (const r of etat.attente.splice(0)) r({ ok: false, error: `auxiliaire PKCS#11 arrêté (${raison})` });
      if (this.proc === etat) this.proc = null;
    };
    p.on("exit", (code, signal) => mourir(signal ?? `code ${code}`));
    p.on("error", (e) => mourir(e.code ?? "erreur"));
    p.stdin.on("error", () => {});
    // Première ligne : le PIN, en hexadécimal ; l'auxiliaire répond « prêt ».
    const pret = new Promise((r) => etat.attente.push(r));
    p.stdin.write(`${Buffer.from(this.pin).toString("hex")}\n`);
    etat.pret = pret;
    return etat;
  }

  /** Une requête à l'auxiliaire, sérialisée, bornée par le délai (l'auxiliaire est tué à l'échéance). */
  _demander(requete) {
    const tour = this.file.then(async () => {
      if (!this.proc) this.proc = this._lancer();
      const etat = this.proc;
      const minuteur = setTimeout(() => {
        etat.p.kill("SIGKILL");
      }, this.delai);
      try {
        const pret = await etat.pret;
        if (!pret.ok) {
          etat.p.kill("SIGKILL");
          throw new ErreurSignataire(`module PKCS#11 : ${pret.error}`, { code: pret.rv ?? null });
        }
        const reponse = new Promise((r) => etat.attente.push(r));
        if (etat.mort) throw new ErreurSignataire(`auxiliaire PKCS#11 arrêté (${etat.mort})`);
        etat.p.stdin.write(`${JSON.stringify(requete)}\n`);
        const r = await reponse;
        if (!r.ok) throw new ErreurSignataire(`module PKCS#11 : ${r.error}`, { code: r.rv ?? null });
        return r;
      } finally {
        clearTimeout(minuteur);
      }
    });
    this.file = tour.catch(() => {});
    return tour;
  }

  async clePublique(keyId) {
    const r = await this._demander({ op: "public_key", label: this.etiquette(keyId) });
    // EX-11.5 : clé créée non exportable et qui le reste quand le backend l'offre
    // (CKA_EXTRACTABLE faux, CKA_SENSITIVE vrai ; lecture 178).
    if (r.extractable !== false || r.sensitive !== true) {
      throw new ErreurSignataire("clé PKCS#11 extractible ou non sensible : refusée (EX-11.5)", { code: "exportable" });
    }
    if (r.sign !== true) throw new ErreurSignataire("clé PKCS#11 sans CKA_SIGN", { code: "usage" });
    if (typeof r.public_key !== "string" || !/^[0-9a-f]{64}$/.test(r.public_key)) throw new ErreurSignataire("CKA_EC_POINT : 32 octets attendus");
    this.formes.set(keyId, { ec_params: r.ec_params_form, ec_point: r.ec_point_form });
    return new Uint8Array(Buffer.from(r.public_key, "hex"));
  }

  async signer(keyId, message) {
    const r = await this._demander({ op: "sign", label: this.etiquette(keyId), mechanism: this.mecanisme, message: Buffer.from(message).toString("hex") });
    if (typeof r.signature !== "string" || !/^([0-9a-f]{2})*$/.test(r.signature)) throw new ErreurSignataire("signature illisible");
    return new Uint8Array(Buffer.from(r.signature, "hex"));
  }

  async sante() {
    await this._demander({ op: "health" });
    return "ok";
  }

  effacer() {
    this.pin.fill(0);
    if (this.proc) {
      this.proc.p.stdin.end();
      this.proc.p.kill("SIGTERM");
      this.proc = null;
    }
  }
}
