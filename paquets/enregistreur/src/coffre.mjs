// Coffre optionnel des originaux (CT-2 §10.7, EX-10.22 ; CT-7 EX-3.11).
//
// Désactivé par défaut : les originaux non rédigés ne sont jamais stockés.
// Activé (`storage.vault.enabled`), il est un répertoire distinct du stockage
// du journal (`storage.vault.path`, hors de `storage.root`, jamais dans un
// dossier de preuve) où chaque pièce rédigée a un homologue chiffré par
// AES-256-GCM sous la clé propre au coffre (`storage.vault.key`, 32 octets,
// jamais celle du signataire), nonce de 12 octets aléatoire par fichier,
// données associées = les 32 octets du `sha256` de la pièce rédigée, nom de
// fichier = ce `sha256` en hexadécimal sans `0x`. Fichier : nonce ‖ chiffré
// ‖ étiquette de 16 octets. Le coffre est hors chaîne : rien dans un
// événement ne le référence.
//
// Déchiffrement (CT-7 EX-3.11) : deux personnes distinctes, le demandeur et
// une autre personne autorisée, qui approuve la même pièce et le même motif ;
// chaque tentative, accordée ou refusée, est consignée hors du coffre (sha256
// de la pièce, deux identités, instant, motif, issue) et forcée sur disque
// avant que l'original soit rendu.

import path from "node:path";
import fs from "node:fs/promises";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { ecrireHorodatage } from "@noortrace/noyau";
import { creerRepertoire, ecrireAtomique, FichierAjout } from "./fichiers.mjs";
import { jcsIntegralOctets } from "./jcs-integral.mjs";

const TAILLE_NONCE = 12;
const TAILLE_ETIQUETTE = 16;

function hex(sha256) {
  const h = typeof sha256 === "string" && sha256.startsWith("0x") ? sha256.slice(2) : sha256;
  if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) throw new TypeError("sha256 de pièce invalide");
  return h;
}

function shaOuNull(sha256) {
  try {
    return hex(sha256);
  } catch {
    return null;
  }
}

/** Le chemin `enfant` est-il `parent` ou sous lui ? */
export function estSous(enfant, parent) {
  const r = path.relative(path.resolve(parent), path.resolve(enfant));
  return r === "" || (!r.startsWith("..") && !path.isAbsolute(r));
}

/** Refus d'accès au coffre (CT-7 EX-3.11). */
export class AccesCoffreRefuse extends Error {
  /** @param {string} raison */
  constructor(raison) {
    super(`accès au coffre refusé : ${raison}`);
    this.name = "AccesCoffreRefuse";
    this.raison = raison;
  }
}

export class CoffreOriginaux {
  /**
   * @param {{chemin: string, cle: Uint8Array, journal?: object|null}} o
   */
  constructor(o) {
    if (!o.chemin || !path.isAbsolute(o.chemin)) throw new TypeError("chemin absolu du coffre attendu");
    if (!(o.cle instanceof Uint8Array) || o.cle.length !== 32) throw new TypeError("clé du coffre : 32 octets attendus (EX-10.22)");
    this.chemin = o.chemin;
    this.cle = Buffer.from(o.cle);
    this.journal = o.journal ?? null;
  }

  /** Chemin du fichier d'un homologue. */
  fichier(sha256) {
    return path.join(this.chemin, hex(sha256));
  }

  /**
   * Dépose l'original d'une pièce rédigée, chiffré. Un homologue existant
   * n'est jamais réécrit : deux originaux qui donnent la même pièce rédigée
   * gardent le premier (consigné).
   * @param {string} sha256 sha256 de la pièce rédigée
   * @param {Uint8Array} original octets de l'original (JCS intégral de la valeur reçue, ou texte, ou corps)
   * @returns {Promise<boolean>} vrai si un fichier a été écrit
   */
  async deposer(sha256, original) {
    const h = hex(sha256);
    const nonce = randomBytes(TAILLE_NONCE);
    const c = createCipheriv("aes-256-gcm", this.cle, nonce);
    c.setAAD(Buffer.from(h, "hex"));
    const chiffre = Buffer.concat([c.update(original), c.final()]);
    const contenu = Buffer.concat([nonce, chiffre, c.getAuthTag()]);
    await creerRepertoire(this.chemin);
    const ecrit = await ecrireAtomique(path.join(this.chemin, h), new Uint8Array(contenu), { jamaisReecrire: true });
    if (!ecrit) this.journal?.consigner("info", "redaction", "vault_original_kept", { sha256: `0x${h}` });
    return ecrit;
  }

  /**
   * Déchiffre l'original d'une pièce, à deux personnes (CT-7 EX-3.11).
   * @param {object} d
   * @param {string} d.sha256 pièce rédigée
   * @param {{par: string, motif: string}} d.demande demandeur et motif
   * @param {{par: string, sha256: string, motif: string}|null} d.approbation seconde personne autorisée, même pièce, même motif
   * @param {string[]} d.autorises personnes autorisées (liste du client)
   * @param {string} d.registre fichier des accès, hors du coffre, conservé aussi longtemps que le journal
   * @param {number} [d.instant] millisecondes (défaut : maintenant)
   * @returns {Promise<Uint8Array>} l'original
   * @throws {AccesCoffreRefuse}
   */
  async dechiffrer(d) {
    const instant = d.instant ?? Date.now();
    if (!d.registre || !path.isAbsolute(d.registre) || estSous(d.registre, this.chemin)) {
      throw new AccesCoffreRefuse("registre des accès absent ou dans le coffre");
    }
    const h = hex(d.sha256);
    const demandeur = d.demande?.par;
    const approbateur = d.approbation?.par ?? null;
    const motif = d.demande?.motif;
    let raison = null;
    if (typeof demandeur !== "string" || demandeur.length === 0) raison = "demandeur_absent";
    else if (typeof motif !== "string" || motif.trim().length === 0) raison = "motif_absent";
    else if (!d.approbation || typeof approbateur !== "string" || approbateur.length === 0) raison = "seconde_approbation_absente";
    else if (approbateur === demandeur) raison = "approbateur_identique_au_demandeur";
    else if (!Array.isArray(d.autorises) || !d.autorises.includes(demandeur)) raison = "demandeur_non_autorise";
    else if (!d.autorises.includes(approbateur)) raison = "approbateur_non_autorise";
    else if (shaOuNull(d.approbation.sha256) !== h || d.approbation.motif !== motif) raison = "approbation_d_une_autre_demande";
    let original = null;
    if (raison === null) {
      try {
        const contenu = await fs.readFile(path.join(this.chemin, h));
        if (contenu.length < TAILLE_NONCE + TAILLE_ETIQUETTE) throw new Error("court");
        const nonce = contenu.subarray(0, TAILLE_NONCE);
        const etiquette = contenu.subarray(contenu.length - TAILLE_ETIQUETTE);
        const dc = createDecipheriv("aes-256-gcm", this.cle, nonce);
        dc.setAAD(Buffer.from(h, "hex"));
        dc.setAuthTag(etiquette);
        original = new Uint8Array(Buffer.concat([dc.update(contenu.subarray(TAILLE_NONCE, contenu.length - TAILLE_ETIQUETTE)), dc.final()]));
      } catch (e) {
        raison = e?.code === "ENOENT" ? "original_absent" : "dechiffrement_en_echec";
      }
    }
    // Consigné hors du coffre, forcé sur disque, avant de rendre l'original.
    const ligne = {
      at: ecrireHorodatage(instant),
      sha256: `0x${h}`,
      requester: typeof demandeur === "string" ? demandeur : null,
      approver: typeof approbateur === "string" ? approbateur : null,
      reason: typeof motif === "string" ? motif : null,
      result: raison === null ? "accorde" : "refuse",
      refusal: raison,
    };
    await creerRepertoire(path.dirname(d.registre));
    const f = await FichierAjout.ouvrir(d.registre, { creer: true, existantAdmis: true });
    try {
      const o = jcsIntegralOctets(ligne);
      const l = new Uint8Array(o.length + 1);
      l.set(o);
      l[o.length] = 10;
      await f.ajouter(l);
      await f.synchroniser();
    } finally {
      await f.fermer();
    }
    this.journal?.consigner(raison === null ? "info" : "warning", "redaction", "vault_access", { sha256: `0x${h}`, result: ligne.result, refusal: raison });
    if (raison !== null) throw new AccesCoffreRefuse(raison);
    return original;
  }

  /** Efface la clé de la mémoire (arrêt). */
  effacer() {
    this.cle.fill(0);
  }
}
