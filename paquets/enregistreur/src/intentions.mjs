// Journal d'intention (CT-2 §12.5) : écriture anticipée hors chaîne qui rend
// compte d'un appel d'écriture parti vers un serveur d'outils sans que son
// événement ait pu être écrit. Fichier `intentions/intentions-<epoch>.ndjson`,
// ouvert O_APPEND comme un segment ; chaque ligne est le JCS intégral d'un
// objet suivi de \n : ligne intention (neuf clés, EX-12.12), ligne contexte
// d'intention (l'événement partiel), ligne levée (EX-12.13).

import fs from "node:fs/promises";
import path from "node:path";
import { sha256Hex, ErreurJson } from "@noortrace/noyau";
import { jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { decouperLignes, tronquer } from "./fichiers.mjs";

const MOTIF_NOM = /^intentions-([0-9]{20})\.ndjson$/;

/**
 * Nom du fichier d'intention d'une époque.
 * @param {number} epoque
 * @returns {string}
 */
export function nomFichierIntentions(epoque) {
  return `intentions-${String(epoque).padStart(20, "0")}.ndjson`;
}

/**
 * Identifiant d'intention `i-<époque sur 20 chiffres>-<compteur sur 12>`,
 * unique dans le journal (EX-12.12).
 * @param {number} epoque
 * @param {number} compteur
 * @returns {string}
 */
export function idIntention(epoque, compteur) {
  return `i-${String(epoque).padStart(20, "0")}-${String(compteur).padStart(12, "0")}`;
}

/**
 * Ligne intention, neuf clés (EX-12.12).
 * @param {{intent_id: string, upstream_id: string, host: string, written_at: string, org_id: string,
 *   journal_id: string, tool: string, arguments: object, ticket: string|null}} p
 * @returns {object}
 */
export function objetIntention(p) {
  return {
    intent_id: p.intent_id,
    upstream_id: p.upstream_id,
    host: p.host,
    written_at: p.written_at,
    org_id: p.org_id,
    journal_id: p.journal_id,
    tool: p.tool,
    arguments: p.arguments,
    ticket: p.ticket ?? null,
  };
}

/** Clés de l'événement partiel d'une ligne contexte d'intention (EX-12.12). */
export const CLES_PARTIEL = Object.freeze(["delegation", "code", "intent", "policy", "approval", "execution", "effects", "context"]);

/**
 * Ligne contexte d'intention : l'événement partiel, `execution` réduit à
 * `tool` et `arguments`.
 * @param {string} intentId
 * @param {object} partiel
 * @returns {object}
 */
export function objetContexte(intentId, partiel) {
  const event = {
    delegation: partiel.delegation,
    code: partiel.code,
    intent: partiel.intent,
    policy: partiel.policy,
    approval: partiel.approval,
    execution: { tool: partiel.execution.tool, arguments: partiel.execution.arguments },
    effects: partiel.effects ?? [],
    context: partiel.context,
  };
  return { intent_context: intentId, event };
}

/**
 * Octets d'une ligne : JCS intégral suivi de \n.
 * @param {object} objet
 * @returns {Uint8Array}
 */
export function ligneIntention(objet) {
  const o = jcsIntegralOctets(objet);
  const sortie = new Uint8Array(o.length + 1);
  sortie.set(o);
  sortie[o.length] = 0x0a;
  return sortie;
}

/**
 * `intention_sha256` : SHA-256 de la ligne intention à neuf clés, sans \n.
 * @param {object} intention
 * @returns {string}
 */
export function empreinteIntention(intention) {
  return sha256Hex(jcsIntegralOctets(intention));
}

/** Corruption d'un fichier d'intention (EX-12.22). */
export class ErreurIntentions extends Error {
  /** @param {string} fichier @param {number} ligne */
  constructor(fichier, ligne) {
    super(`intention_corrompue : ${path.basename(fichier)}, ligne ${ligne}`);
    this.name = "ErreurIntentions";
    this.fichier = fichier;
    this.ligne = ligne;
  }
}

/**
 * Relit les fichiers d'intention dans l'ordre des époques (EX-12.22) : seule
 * une dernière ligne incomplète est une écriture tronquée (le fichier est
 * coupé) ; une ligne illisible suivie d'autres lignes est une corruption.
 * @param {string} repertoire `intentions/`
 * @param {{tronquer?: boolean}} [options]
 * @returns {Promise<{fichiers: {chemin: string, epoch: number}[], intentions: object[], levees: Map<string, number>, tronques: string[]}>}
 *   `intentions` : `{ intention, sha256, contexte, fichier, epoch }` dans l'ordre du journal
 */
export async function relireIntentions(repertoire, options = {}) {
  let noms;
  try {
    noms = (await fs.readdir(repertoire)).filter((n) => MOTIF_NOM.test(n)).sort();
  } catch (e) {
    if (e.code === "ENOENT") return { fichiers: [], intentions: [], levees: new Map(), tronques: [] };
    throw e;
  }
  const fichiers = [];
  const intentions = [];
  const parId = new Map();
  const levees = new Map();
  const tronques = [];
  for (const nom of noms) {
    const chemin = path.join(repertoire, nom);
    const epoch = Number(MOTIF_NOM.exec(nom)[1]);
    fichiers.push({ chemin, epoch });
    const octets = new Uint8Array(await fs.readFile(chemin));
    const lignes = decouperLignes(octets);
    for (let k = 0; k < lignes.length; k++) {
      const l = lignes[k];
      const derniere = k === lignes.length - 1;
      let objet = null;
      if (l.complete) {
        try {
          objet = analyserJsonIntegral(l.octets);
        } catch (e) {
          if (!(e instanceof ErreurJson)) throw e;
        }
      }
      if (objet === null || typeof objet !== "object") {
        if (derniere) {
          tronques.push(chemin);
          if (options.tronquer !== false) await tronquer(chemin, l.debut);
          break;
        }
        throw new ErreurIntentions(chemin, k + 1);
      }
      if (typeof objet.intent_id === "string") {
        const entree = { intention: objet, sha256: sha256Hex(l.octets), contexte: null, fichier: chemin, epoch };
        intentions.push(entree);
        parId.set(objet.intent_id, entree);
      } else if (typeof objet.intent_context === "string") {
        const e = parId.get(objet.intent_context);
        if (e) e.contexte = objet.event;
      } else if (typeof objet.lifted === "string") {
        levees.set(objet.lifted, objet.seq);
      } else {
        if (derniere) {
          tronques.push(chemin);
          if (options.tronquer !== false) await tronquer(chemin, l.debut);
          break;
        }
        throw new ErreurIntentions(chemin, k + 1);
      }
    }
  }
  return { fichiers, intentions, levees, tronques };
}
