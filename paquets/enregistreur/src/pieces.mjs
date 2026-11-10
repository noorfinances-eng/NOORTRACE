// Sérialisation des pièces (CT-2 §8) et stockage par sha256 (§8.4).
//
// Une pièce est une suite d'octets stockée et hachée ; l'événement la cite
// par une référence { sha256, length, redacted[, media_type] } (CT-1 §5.4).
// Ce module ne rédige rien : la rédaction (section 10) est faite avant, par
// le rédacteur (lot suivant), qui remet la valeur rédigée et dit si une règle
// a joué. Il fixe la sérialisation : JCS intégral pour une pièce JSON (8.1),
// UTF-8 sans guillemets pour une pièce texte (8.2), règles de 8.3 pour une
// pièce non JSON, et les formes fixes du cœur (erreur JSON-RPC, reprise,
// pièces d'attente perdues, déclaration de source, document d'ensemble de politique).

import path from "node:path";
import fs from "node:fs/promises";
import { creerReference, sha256Hex, utf8 } from "@noortrace/noyau";
import { jcsIntegralOctets } from "./jcs-integral.mjs";
import { creerRepertoire, ecrireAtomique, octetsLibres } from "./fichiers.mjs";
import { ErreurEnregistreur } from "./erreurs.mjs";

/** Motif `type_mime` de CT-1, 127 caractères au plus (EX-8.7 règle 1). */
const MOTIF_TYPE_MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/** Une pièce : ses octets et sa référence. */
export class Piece {
  /**
   * @param {Uint8Array} octets
   * @param {{redacted?: boolean, media_type?: string}} [options]
   */
  constructor(octets, options = {}) {
    this.octets = octets;
    this.reference = creerReference(octets, options);
  }

  /** sha256 en hexadécimal préfixé. */
  get sha256() {
    return this.reference.sha256;
  }

  /** Référence de contexte (EX-7.7) : la référence, plus `kind`. */
  referenceContexte(kind = "autre") {
    return { ...this.reference, kind };
  }
}

/**
 * Pièce JSON : JCS intégral de la valeur (déjà rédigée), sans media_type
 * sauf demande (définition d'outil, liste annoncée, document de contexte
 * JSON, document d'ensemble de politique : EX-8.8).
 * @param {unknown} valeur
 * @param {{redacted?: boolean, media_type?: string}} [options]
 * @returns {Piece}
 */
export function pieceJson(valeur, options = {}) {
  return new Piece(jcsIntegralOctets(valeur), options);
}

/**
 * Pièce texte (prompt système, intention, contexte text/plain) : les octets
 * UTF-8 du texte, sans guillemets ni échappement, `media_type: text/plain`.
 * @param {string} texte
 * @param {{redacted?: boolean}} [options]
 * @returns {Piece}
 */
export function pieceTexte(texte, options = {}) {
  return new Piece(utf8(texte), { redacted: options.redacted === true, media_type: "text/plain" });
}

/**
 * Type de média d'une pièce non JSON (EX-8.7 règle 1) : celui du
 * Content-Type reçu, en minuscules, sans paramètres ; à défaut ou hors du
 * motif `type_mime`, `application/octet-stream`.
 * @param {string|null|undefined} contentType
 * @returns {string}
 */
export function typeMediaNormalise(contentType) {
  if (typeof contentType !== "string") return "application/octet-stream";
  const t = contentType.split(";")[0].trim().toLowerCase();
  return t.length <= 127 && MOTIF_TYPE_MIME.test(t) ? t : "application/octet-stream";
}

/**
 * Pièce non JSON (EX-8.7 règle 2, ou règle 3 sans règle de rédaction
 * applicable) : les octets tels que remis par le rédacteur (texte rédigé en
 * UTF-8, ou octets reçus inchangés), avec le type de média normalisé.
 * @param {Uint8Array} octets
 * @param {{content_type?: string|null, redacted?: boolean}} [options]
 * @returns {Piece}
 */
export function pieceNonJson(octets, options = {}) {
  return new Piece(octets, { redacted: options.redacted === true, media_type: typeMediaNormalise(options.content_type) });
}

/** Raisons admises de la forme `noortrace_non_redigeable` (EX-8.7 règle 3). */
export const RAISONS_NON_REDIGEABLE = Object.freeze(["non_utf8", "codage_inconnu", "budget_redaction", "taille"]);

/**
 * Pièce d'un contenu qui ne peut pas être rédigé (EX-8.7 règle 3) : JCS
 * intégral de `{"noortrace_non_redigeable": {content_type, length, reason}}`,
 * `redacted: true`, sans media_type.
 * @param {{content_type: string|null, length: number, reason: string}} p
 * @returns {Piece}
 */
export function pieceNonRedigeable(p) {
  if (!RAISONS_NON_REDIGEABLE.includes(p.reason)) throw new TypeError(`raison non admise : ${p.reason}`);
  return pieceJson(
    { noortrace_non_redigeable: { content_type: p.content_type ?? null, length: p.length, reason: p.reason } },
    { redacted: true },
  );
}

/**
 * Pièce « résultat » d'une erreur JSON-RPC (4.4 pas 12) :
 * `{"noortrace_jsonrpc_error": <error, membres présents seulement>}`.
 * @param {object} erreur
 * @param {{redacted?: boolean}} [options]
 * @returns {Piece}
 */
export function pieceErreurJsonRpc(erreur, options = {}) {
  return pieceJson({ noortrace_jsonrpc_error: erreur }, options);
}

/** Texte fixe de la pièce « résultat » d'un événement de reprise (EX-12.14). */
export const TEXTE_REPRISE = "resultat inconnu : enregistreur arrete pendant le relais";

/**
 * Pièce « résultat » d'un événement de reprise (EX-12.14 pas 2).
 * @param {string} intentionSha256 SHA-256 de la ligne intention, hexadécimal préfixé
 * @returns {Piece}
 */
export function pieceReprise(intentionSha256) {
  return pieceJson({ intention_sha256: intentionSha256, noortrace_reprise: TEXTE_REPRISE });
}

/** Texte fixe de la pièce « résultat » d'un événement en attente dont des pièces manquent (EX-14.18). */
export const TEXTE_ATTENTE = "pieces perdues pendant le mode degrade";

/**
 * Pièce « résultat » (pièce « réponse » d'un échange de modèle) d'un
 * événement en attente relu au redémarrage dont au moins une pièce manque
 * (CT-2 EX-14.18 pas 3, révision 0.7) : JCS intégral de
 * `{"missing_pieces":[{"length","sha256"}…],"noortrace_attente":…,"pending_id":…,"result":<référence d'origine>}`,
 * `redacted: false`, sans `media_type`. `missing_pieces` : une entrée par
 * `sha256` distinct, tirée de la référence qui le désigne, triée par `sha256`
 * croissant ; `result` : la référence d'origine de `execution.result`
 * (`sha256`, `length`, `redacted`, et `media_type` si elle en a un). Elle
 * remplace la pièce à deux membres `{"noortrace_attente":"resultat perdu
 * pendant le mode degrade","pending_id"}` des versions 0.1 à 0.6 (EX-14.10),
 * qui n'est plus produite.
 * @param {{pending_id: string, manquantes: {sha256: string, length: number}[], resultat: object|null}} p
 * @returns {Piece}
 */
export function pieceAttentePiecesPerdues(p) {
  const parSha = new Map();
  for (const r of p.manquantes) if (!parSha.has(r.sha256)) parSha.set(r.sha256, { length: r.length, sha256: r.sha256 });
  const missing_pieces = [...parSha.values()].sort((a, b) => (a.sha256 < b.sha256 ? -1 : a.sha256 > b.sha256 ? 1 : 0));
  const r = p.resultat;
  let result = r ?? null;
  if (r !== null && typeof r === "object") {
    result = { sha256: r.sha256, length: r.length, redacted: r.redacted };
    if (r.media_type !== undefined) result.media_type = r.media_type;
  }
  return pieceJson({ missing_pieces, noortrace_attente: TEXTE_ATTENTE, pending_id: p.pending_id, result });
}

/**
 * Pièce de définition d'outil (EX-4.16, EX-4.45) : JCS intégral de l'objet
 * Tool, `media_type: application/json`, jamais rédigée.
 * @param {object} definition
 * @returns {Piece}
 */
export function pieceDefinitionOutil(definition) {
  return pieceJson(definition, { media_type: "application/json" });
}

/**
 * Pièce « liste annoncée » (EX-4.45) : `{"tools": [définitions servies]}`.
 * @param {object[]} definitions
 * @returns {Piece}
 */
export function pieceListeAnnoncee(definitions) {
  return pieceJson({ tools: definitions }, { media_type: "application/json" });
}

/**
 * Pièce de déclaration de source (EX-6.35, EX-7.7) :
 * `{"noortrace_capture":{"channel","source"}}`.
 * @param {"otel"|"sdk"} canal
 * @param {string} source alias
 * @returns {Piece}
 */
export function pieceDeclarationSource(canal, source) {
  return pieceJson({ noortrace_capture: { channel: canal, source } }, { media_type: "application/json" });
}

/**
 * Pièce du document d'ensemble de politique (EX-8.11, EX-10.21) : JCS
 * intégral du membre `policy` tel qu'écrit dans la configuration,
 * références de secrets comprises, `media_type: application/json`.
 * @param {object} politique
 * @returns {Piece}
 */
export function piecePolitique(politique) {
  return pieceJson(politique, { media_type: "application/json" });
}

/**
 * Empreinte de l'ensemble de politique (EX-8.11) : SHA-256 du JCS intégral,
 * sans préfixe de domaine.
 * @param {object} politique
 * @returns {{policy_version: string, policy_sha256: string, length: number}}
 */
export function empreintePolitique(politique) {
  const octets = jcsIntegralOctets(politique);
  return { policy_version: politique.version, policy_sha256: sha256Hex(octets), length: octets.length };
}

/**
 * Magasin des pièces d'un journal : `pieces/<xx>/<sha256 sans 0x>` (EX-12.1,
 * EX-8.9). Une pièce est écrite dans un fichier temporaire puis renommée,
 * fichier puis répertoire synchronisés ; une pièce déjà présente n'est
 * jamais réécrite.
 */
export class MagasinPieces {
  /**
   * @param {string} repertoireJournal `<root>/<org>/<journal>`
   * @param {{minOctetsLibres?: number, journal?: {consigner: Function}|null, octetsLibres?: (chemin: string) => Promise<number|null>}} [options]
   *   `storage.min_free_bytes` (14.2, « disque presque plein ») ; journal
   *   d'exploitation (ligne `disk_low`) ; mesure de l'espace libre (essais)
   */
  constructor(repertoireJournal, options = {}) {
    this.racine = path.join(repertoireJournal, "pieces");
    this.repertoireJournal = repertoireJournal;
    this.minOctetsLibres = options.minOctetsLibres ?? 0;
    this.journal = options.journal ?? null;
    this.mesurer = options.octetsLibres ?? octetsLibres;
    /** Vrai depuis le dernier constat « disque presque plein », jusqu'au contrôle suivant réussi. */
    this.disqueBas = false;
  }

  /**
   * Contrôle « disque presque plein » (14.2) : avant l'ouverture d'un
   * segment, avant l'écriture de chaque pièce et toutes les 10 s. Sous
   * `storage.min_free_bytes` (plus `supplement`), lève `ErreurEnregistreur`
   * de raison `stockage` (`donnees.event = "disk_low"`) ; la ligne `disk_low`
   * (octets libres) est consignée à l'entrée sous le seuil, une fois jusqu'au
   * retour au-dessus.
   * @param {number} [supplement] octets à écrire
   * @param {string} [chemin] répertoire du volume (défaut : celui du journal)
   */
  async verifierEspace(supplement = 0, chemin = this.repertoireJournal) {
    if (!(this.minOctetsLibres > 0)) return;
    const libres = await this.mesurer(chemin);
    if (libres === null || libres >= this.minOctetsLibres + supplement) {
      this.disqueBas = false;
      return;
    }
    if (!this.disqueBas) this.journal?.consigner("error", "stockage", "disk_low", { free_bytes: libres, min_free_bytes: this.minOctetsLibres });
    this.disqueBas = true;
    throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { donnees: { event: "disk_low", libres } });
  }

  /**
   * Chemin du fichier d'une pièce.
   * @param {string} sha256 hexadécimal préfixé
   * @returns {string}
   */
  chemin(sha256) {
    const h = sha256.startsWith("0x") ? sha256.slice(2) : sha256;
    if (!/^[0-9a-f]{64}$/.test(h)) throw new TypeError("sha256 de pièce invalide");
    return path.join(this.racine, h.slice(0, 2), h);
  }

  /**
   * Écrit une pièce (adressage par contenu) et la force sur disque.
   * @param {Piece} piece
   * @returns {Promise<{ecrite: boolean, reference: object}>}
   * @throws {ErreurEnregistreur} disque presque plein ou écriture en échec (raison `stockage`)
   */
  async ecrire(piece) {
    const chemin = this.chemin(piece.sha256);
    try {
      await creerRepertoire(path.dirname(chemin));
      await this.verifierEspace(piece.octets.length, path.dirname(chemin));
      const ecrite = await ecrireAtomique(chemin, piece.octets, { jamaisReecrire: true });
      return { ecrite, reference: piece.reference };
    } catch (e) {
      if (e instanceof ErreurEnregistreur) throw e;
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: e, donnees: { errno: e?.code ?? null } });
    }
  }

  /**
   * Lit les octets d'une pièce, ou null si elle n'est pas stockée (purgée).
   * @param {string} sha256
   * @returns {Promise<Uint8Array|null>}
   */
  async lire(sha256) {
    try {
      return new Uint8Array(await fs.readFile(this.chemin(sha256)));
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
  }
}
