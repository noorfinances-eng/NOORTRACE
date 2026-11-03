// Classe C : enveloppe (CT-2 §11.2, EX-11.9). La graine Ed25519 de 32 octets
// est stockée chiffrée (AWS KMS, Google Cloud KMS, Azure Key Vault ou Managed
// HSM) ou scellée (TPM 2.0) ; elle est déchiffrée au démarrage, dans la
// mémoire du démon, qui signe lui-même, et effacée à l'arrêt.
//
// Contexte de chiffrement (AWS `EncryptionContext`, Google
// `additionalAuthenticatedData`) : `org_id`, `journal_id`, `key_id`, rien
// d'autre. Clé suivante (rotation, `signer.rotation.next_key_id`) : fichiers
// du même répertoire nommés `<next_key_id>` suivi de l'extension du fichier
// courant, comme en classe D (lecture 177) ; ils sont chargés s'ils existent.

import fs from "node:fs";
import path from "node:path";
import { clePubliqueEd25519, signerEd25519 } from "@noortrace/noyau";
import { Signataire } from "../signataires.mjs";
import { ErreurSignataire, contexteChiffrement } from "./commun.mjs";

/** Taille de la graine enveloppée (RFC 8032, EX-11.9). */
export const TAILLE_GRAINE = 32;

/** Fichier de la clé suivante : même répertoire, `<next_key_id>` + extension du fichier courant. */
export function fichierCleSuivante(fichier, nextKeyId) {
  return path.join(path.dirname(fichier), `${nextKeyId}${path.extname(fichier)}`);
}

export class SignataireEnveloppe extends Signataire {
  /**
   * @param {{wrapType: string, graines: Map<string, Uint8Array>, localisations: Map<string, object>}} p
   */
  constructor(p) {
    super();
    this.wrapType = p.wrapType;
    this.graines = p.graines;
    this.localisations = p.localisations;
  }

  /**
   * Déchiffre la graine courante et, si ses fichiers existent, la suivante.
   * @param {object} p
   * @param {{sealed_seed_file: string, wrap: object}} p.backend `signer.backend`
   * @param {string} p.keyId
   * @param {string|null} p.nextKeyId
   * @param {string} p.org_id
   * @param {string} p.journal_id
   * @param {(q: {wrap: object, chiffre: Uint8Array|null, contexte: {carte: object, octets: Uint8Array}}) => Promise<Uint8Array>} p.desenvelopper
   * @returns {Promise<SignataireEnveloppe>}
   */
  static async charger(p) {
    const graines = new Map();
    const localisations = new Map();
    const tpm = p.backend.wrap.type === "tpm2";
    const charger = async (keyId, suivante) => {
      let wrap = p.backend.wrap;
      let fichier = p.backend.sealed_seed_file;
      if (suivante) {
        if (tpm) {
          wrap = { ...wrap, public_file: fichierCleSuivante(wrap.public_file, keyId), private_file: fichierCleSuivante(wrap.private_file, keyId) };
          if (wrap.public_file === wrap.private_file) throw new ErreurSignataire("TPM 2.0 : fichiers public et privé de même extension, clé suivante indiscernable");
          if (!fs.existsSync(wrap.public_file) || !fs.existsSync(wrap.private_file)) return;
        } else {
          fichier = fichierCleSuivante(fichier, keyId);
          if (!fs.existsSync(fichier)) return;
        }
      }
      // TPM 2.0 : l'objet scellé est le couple (public_file, private_file) ;
      // sealed_seed_file n'est pas lu (lecture 180).
      let chiffre = null;
      if (!tpm) {
        try {
          chiffre = new Uint8Array(fs.readFileSync(fichier));
        } catch (e) {
          throw new ErreurSignataire(`graine enveloppée illisible (${e.code ?? "erreur"})`, { code: "fichier" });
        }
      }
      const contexte = contexteChiffrement({ org_id: p.org_id, journal_id: p.journal_id, key_id: keyId });
      const g = await p.desenvelopper({ wrap, chiffre, contexte });
      if (!(g instanceof Uint8Array) || g.length !== TAILLE_GRAINE) {
        g?.fill?.(0);
        throw new ErreurSignataire(`graine de ${g?.length ?? 0} octets : ${TAILLE_GRAINE} attendus (EX-11.9)`, { code: "graine" });
      }
      graines.set(keyId, g);
      localisations.set(keyId, tpm ? { wrap: "tpm2", public_file: wrap.public_file, private_file: wrap.private_file, pcrs: wrap.pcrs } : { wrap: wrap.type, sealed_seed_file: fichier, ...cleWrap(wrap) });
    };
    try {
      await charger(p.keyId, false);
      if (p.nextKeyId) await charger(p.nextKeyId, true);
    } catch (e) {
      for (const g of graines.values()) g.fill(0);
      throw e;
    }
    return new SignataireEnveloppe({ wrapType: p.backend.wrap.type, graines, localisations });
  }

  get classe() {
    return "C";
  }

  get typeBackend() {
    return "envelope";
  }

  clesConnues() {
    return [...this.graines.keys()];
  }

  localisation(keyId) {
    return this.localisations.get(keyId) ?? null;
  }

  async clePublique(keyId) {
    const g = this.graines.get(keyId);
    if (!g) throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
    return clePubliqueEd25519(g);
  }

  async signer(keyId, message) {
    const g = this.graines.get(keyId);
    if (!g) throw new ErreurSignataire(`clé ${keyId} inconnue du signataire`);
    return signerEd25519(g, message);
  }

  /** Efface les graines (arrêt, EX-11.9). */
  effacer() {
    for (const g of this.graines.values()) g.fill(0);
    this.graines.clear();
  }
}

/** Identifiant non secret de la clé d'enveloppe, pour le journal d'exploitation. */
function cleWrap(w) {
  if (w.type === "aws-kms") return { key_arn: w.key_arn, region: w.region };
  if (w.type === "gcp-kms") return { key: w.key };
  if (w.type === "azure-keyvault") return { vault_url: w.vault_url, key_name: w.key_name, key_version: w.key_version, algorithm: w.algorithm };
  return {};
}
