// Signataires de l'enregistreur (CT-2 §11). Le noyau n'appelle le signataire
// qu'au travers d'une interface unique à trois opérations (EX-11.18) :
// `clePublique(keyId)`, `signer(keyId, message)`, `sante()`. Chaque backend
// (classes A à D) l'implémente ; ce module fournit la classe D (fichier,
// développement seulement, refusée en production, EX-11.8) et l'enveloppe
// commune qui applique, quel que soit le backend : la borne de taille du
// message (EX-11.7), le délai `signer.timeout_ms` et au plus une seconde
// tentative, et la vérification de chaque signature avant tout usage
// (EX-11.6). Les classes A, B et C sont des lots suivants : elles
// n'implémentent que l'interface.

import fs from "node:fs";
import path from "node:path";
import { createPrivateKey } from "node:crypto";
import { PREFIXES, clePubliqueEd25519, signerEd25519, verifierEd25519, octetsVersHex } from "@noortrace/noyau";
import { ErreurEnregistreur } from "./erreurs.mjs";

/** Correspondance classe ↔ types de backend (EX-15.4 pas 3). */
export const BACKENDS_PAR_CLASSE = Object.freeze({
  A: ["pkcs11"],
  B: ["vault-transit", "openbao-transit", "aws-kms", "gcp-kms"],
  C: ["envelope"],
  D: ["file"],
});

/**
 * Interface du signataire (EX-11.18). Un backend l'étend.
 * @abstract
 */
export class Signataire {
  /** Classe de garde (A à D). */
  get classe() {
    throw new Error("à implémenter");
  }

  /** Type de backend (`file`, `pkcs11`, …). */
  get typeBackend() {
    throw new Error("à implémenter");
  }

  /**
   * Clé publique Ed25519 de 32 octets.
   * @param {string} keyId
   * @returns {Promise<Uint8Array>}
   */
  async clePublique(keyId) {
    throw new Error(`clePublique(${keyId}) à implémenter`);
  }

  /**
   * Signature Ed25519 pure de 64 octets (R ‖ S) d'un message : P_S ‖ C,
   * P_SM ‖ C_M, P_R ‖ JCS(R) ou P_SK ‖ C_K, et aucun autre.
   * @param {string} keyId
   * @param {Uint8Array} message
   * @returns {Promise<Uint8Array>}
   */
  async signer(keyId, message) {
    throw new Error(`signer(${keyId}, ${message.length} octets) à implémenter`);
  }

  /** @returns {Promise<"ok"|string>} `ok` ou la raison de l'indisponibilité */
  async sante() {
    return "ok";
  }

  /** Identifiants de clés que le backend sait utiliser. */
  clesConnues() {
    return [];
  }

  /** Efface les secrets en mémoire (arrêt, EX-11.9). */
  effacer() {}
}

/**
 * Lit une graine Ed25519 de 32 octets dans un fichier PKCS#8 (PEM ou DER),
 * chiffré par une phrase de passe ou non (CT-1 §13, classe D).
 * @param {Uint8Array} octets contenu du fichier
 * @param {Uint8Array|null} phrase
 * @returns {Uint8Array}
 */
export function grainePkcs8(octets, phrase = null) {
  const texte = Buffer.from(octets).toString("latin1");
  const pem = texte.includes("-----BEGIN");
  const cle = createPrivateKey({
    key: pem ? texte : Buffer.from(octets),
    format: pem ? "pem" : "der",
    type: pem ? undefined : "pkcs8",
    passphrase: phrase ? Buffer.from(phrase) : undefined,
  });
  if (cle.asymmetricKeyType !== "ed25519") throw new Error("clé de classe D : Ed25519 attendue");
  const d = cle.export({ format: "jwk" }).d;
  const graine = new Uint8Array(Buffer.from(d, "base64url"));
  if (graine.length !== 32) throw new Error("graine Ed25519 de 32 octets attendue");
  return graine;
}

/**
 * Classe D : graine dans un fichier PKCS#8, en mémoire du démon.
 * Développement seulement : refusée en production (EX-11.8).
 * Clé courante : `signer.backend.path` pour `signer.key_id` ; clé suivante
 * (rotation, `signer.rotation.next_key_id`) : fichier du même répertoire nommé
 * `<next_key_id>` suivi de l'extension du fichier courant (lecture consignée
 * dans le LISEZMOI).
 */
export class SignataireFichier extends Signataire {
  /**
   * @param {{environment: string, cles: Map<string, Uint8Array>}} p graines par key_id
   */
  constructor(p) {
    super();
    if (p.environment === "production") {
      throw new ErreurEnregistreur("cle", "noortrace: classe D refusee en production (EX-11.8)");
    }
    /** @type {Map<string, Uint8Array>} */
    this.graines = new Map(p.cles);
  }

  /**
   * Charge la clé courante et, si le fichier existe, la clé suivante.
   * @param {{environment: string, keyId: string, chemin: string, nextKeyId?: string|null, phrase?: Uint8Array|null}} p
   * @returns {SignataireFichier}
   */
  static charger(p) {
    if (p.environment === "production") {
      throw new ErreurEnregistreur("cle", "noortrace: classe D refusee en production (EX-11.8)");
    }
    const cles = new Map();
    cles.set(p.keyId, grainePkcs8(fs.readFileSync(p.chemin), p.phrase ?? null));
    if (p.nextKeyId) {
      const suivant = path.join(path.dirname(p.chemin), `${p.nextKeyId}${path.extname(p.chemin)}`);
      if (fs.existsSync(suivant)) cles.set(p.nextKeyId, grainePkcs8(fs.readFileSync(suivant), p.phrase ?? null));
    }
    return new SignataireFichier({ environment: p.environment, cles });
  }

  get classe() {
    return "D";
  }

  get typeBackend() {
    return "file";
  }

  clesConnues() {
    return [...this.graines.keys()];
  }

  async clePublique(keyId) {
    const g = this.graines.get(keyId);
    if (!g) throw new Error(`clé ${keyId} inconnue du signataire`);
    return clePubliqueEd25519(g);
  }

  async signer(keyId, message) {
    const g = this.graines.get(keyId);
    if (!g) throw new Error(`clé ${keyId} inconnue du signataire`);
    return signerEd25519(g, message);
  }

  effacer() {
    for (const g of this.graines.values()) g.fill(0);
    this.graines.clear();
  }
}

function avecDelai(promesse, ms) {
  let minuteur;
  return Promise.race([
    promesse,
    new Promise((_, rejeter) => {
      minuteur = setTimeout(() => rejeter(new Error("délai du signataire dépassé")), ms);
    }),
  ]).finally(() => clearTimeout(minuteur));
}

/**
 * Enveloppe commune à tous les backends (EX-11.6, EX-11.7, EX-11.18) :
 * borne de taille, délai, seconde tentative au plus, vérification de chaque
 * signature sous la clé publique mise en cache. Toute panne lève une
 * ErreurEnregistreur de raison `cle` (14.2, « clé indisponible »).
 */
export class SignataireVerifie {
  /**
   * @param {Signataire} backend
   * @param {{timeout_ms?: number, max_message_bytes?: number|null}} [reglages]
   * @param {{metriques?: object, journal?: object}} [observateurs]
   */
  constructor(backend, reglages = {}, observateurs = {}) {
    this.backend = backend;
    this.delai = reglages.timeout_ms ?? 5000;
    this.borne = reglages.max_message_bytes ?? null;
    this.metriques = observateurs.metriques ?? null;
    this.journal = observateurs.journal ?? null;
    /** @type {Map<string, Uint8Array>} */
    this.publiques = new Map();
    /** Clés révoquées (EX-11.14) : seule la rotation qui les remplace peut encore être signée. */
    this.revoquees = new Set();
  }

  get classe() {
    return this.backend.classe;
  }

  get typeBackend() {
    return this.backend.typeBackend;
  }

  /**
   * Clé publique lue au démarrage et après rotation, mise en cache.
   * @param {string} keyId
   * @returns {Promise<Uint8Array>}
   */
  async clePublique(keyId) {
    let p = this.publiques.get(keyId);
    if (p) return p;
    try {
      p = await avecDelai(this.backend.clePublique(keyId), this.delai);
    } catch (e) {
      this.panne("cle_publique", e);
    }
    if (!(p instanceof Uint8Array) || p.length !== 32) this.panne("cle_publique", new Error("clé publique de 32 octets attendue"));
    this.publiques.set(keyId, p);
    return p;
  }

  /**
   * Signe et vérifie (EX-11.6) ; le message n'est jamais journalisé.
   * @param {string} keyId
   * @param {Uint8Array} message
   * @param {{rotation?: boolean}} [options] signature d'un événement de rotation (seule admise pour une clé révoquée)
   * @returns {Promise<Uint8Array>}
   */
  async signer(keyId, message, options = {}) {
    if (this.revoquees.has(keyId) && !options.rotation) this.panne("cle_revoquee", new Error(`clé ${keyId} révoquée`));
    if (this.borne !== null && message.length > this.borne) {
      throw new ErreurEnregistreur("cle", "noortrace: enregistreur en mode degrade (cle)", {
        donnees: { event: "signer_unavailable", raison: "message_hors_borne", longueur: message.length },
      });
    }
    const publique = await this.clePublique(keyId);
    const debut = performance.now();
    let sig;
    let derniere;
    let essais = 0;
    for (let essai = 0; essai < 2 && !sig; essai++) {
      essais++;
      try {
        sig = await avecDelai(this.backend.signer(keyId, message), this.delai);
      } catch (e) {
        derniere = e;
      }
    }
    // `tentatives` : opérations que le backend a pu compter sans qu'une
    // signature serve (rapprochement de CT-7 EX-3.7, signataires/rapprochement.mjs).
    if (!sig) this.panne("signature", derniere, { key_id: keyId, tentatives: essais });
    this.metriques?.observer("noortrace_sign_duration_ms", { backend: this.backend.typeBackend }, performance.now() - debut);
    if (!(sig instanceof Uint8Array) || sig.length !== 64 || !verifierEd25519(publique, message, sig)) {
      this.panne("signature_invalide", new Error("signature qui ne vérifie pas sous la clé publique"), { key_id: keyId, tentatives: essais });
    }
    return sig;
  }

  /**
   * Signature de test vérifiée (EX-15.4 pas 5, sortie du mode « clé »).
   * @param {string} keyId
   */
  async signatureDeTest(keyId) {
    // P_S seul (C vide) : de la forme P_S ‖ C admise par EX-11.18, et jamais
    // confondu avec un événement, dont la forme canonique n'est jamais vide.
    await this.signer(keyId, PREFIXES.P_S);
    // Signature hors du journal : consignée pour le rapprochement (CT-7 EX-3.7).
    this.journal?.consigner("info", "signataire", "signer_test_signature", { key_id: keyId, backend: this.backend.typeBackend, class: this.backend.classe });
  }

  /** @returns {Promise<"ok"|string>} */
  async sante() {
    try {
      return await avecDelai(this.backend.sante(), this.delai);
    } catch (e) {
      return `erreur : ${e?.message ?? e}`;
    }
  }

  panne(raison, cause, extra = {}) {
    this.journal?.consigner("error", "signataire", "signer_unavailable", {
      backend: this.backend.typeBackend,
      class: this.backend.classe,
      raison,
      erreur: String(cause?.message ?? cause ?? ""),
      ...extra,
    });
    throw new ErreurEnregistreur("cle", "noortrace: enregistreur en mode degrade (cle)", { cause, donnees: { raison } });
  }

  /** @param {string} keyId @returns {Promise<string>} clé publique en hexadécimal préfixé */
  async clePubliqueHex(keyId) {
    return octetsVersHex(await this.clePublique(keyId));
  }
}
