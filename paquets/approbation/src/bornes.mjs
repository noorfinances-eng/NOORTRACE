// Bornes communes du service (étape 8, revue de sécurité interne, cause
// structurante S-1 : « bornes de mémoire et de temps absentes sur les
// entrées »). Les textes bornent la taille des corps et la profondeur du
// JSON ; ils ne bornent ni le nombre d'éléments répétés gardés en mémoire ou
// dans la trace d'un ticket, ni le temps d'un calcul dans le fil unique, ni
// la taille d'une réponse du nœud. Ce module tient la table de ces bornes en
// un seul point et les fonctions qui les appliquent à l'entrée ; chaque
// module du service les prend ici plutôt que de porter sa propre constante.
// Une borne dépassée rend toujours un statut (refus, effet omis, lecture
// `illisible`), jamais une exception (S-2).
//
// Révisions de texte demandées pour les écrire dans CT-3 : EX-7.8 et
// EX-7.24 (trace bornée ; archivage des tickets terminaux),
// EX-12.14 (extract sous borne de temps), EX-8.1 (bornes
// de lecture du jeu), EX-7.22 (compactage par taille,
// CT-3 EX-13.13). La borne des défis d'inscription est une règle de
// l'annuaire : elle vit dans le module d'annuaire de la console
// (`MAX_DEFIS_PAR_IDENTITE`, `MAX_DEFIS`), que le service exécute sans la
// réécrire.

import vm from "node:vm";
import { decoderHorodatage } from "@noortrace/noyau";

/** Table des bornes (valeurs fixes de la version 0 ; aucune configuration ne les porte). */
export const BORNES = Object.freeze({
  /** Entrées refusées inscrites dans la trace d'un ticket (EX-7.8) ; au-delà, comptées seulement (CT-3 EX-7.24). */
  refus_inscrits_par_ticket: 64,
  /** Effets d'un gabarit évalués pour la vue (CT-2 : `effects` a 16 éléments au plus). */
  effets_par_outil: 16,
  /** Budget de temps, en millisecondes, de l'évaluation des effets d'une vue (`extract`, CT-3 EX-12.14). */
  vue_budget_ms: 250,
  /** Octets lus au plus du corps d'une réponse du nœud (EX-7.22). */
  rpc_corps_octets: 16 * 1024 * 1024,
  /** Journaux (`eth_getLogs`) accumulés au plus par lecture. */
  rpc_journaux_max: 100000,
  /** Tranches de `TRANCHE_JOURNAUX` blocs interrogées au plus par lecture (CT-3 EX-7.22). */
  rpc_tranches_max: 8192,
  /** Délai total d'une lecture du jeu : ce facteur fois `rpc.timeout_ms`. */
  rpc_lecture_facteur: 12,
  /** Délai après la dernière transition au-delà duquel un ticket terminal quitte l'état vivant (CT-3 EX-7.24). */
  archivage_apres_ms: 7 * 86400000,
  /** Octets ajoutés au journal d'état depuis le dernier compactage au-delà desquels il est compacté (EX-13.13). */
  etat_journal_octets: 64 * 1024 * 1024,
  /** Taille au-delà de laquelle le journal du service est tourné. */
  journal_service_octets: 64 * 1024 * 1024,
  /** Fichiers tournés du journal du service gardés au plus. */
  journal_service_fichiers: 8,
  /** Période du comptage des refus d'authentification (une ligne par période). */
  auth_refusee_periode_ms: 60000,
});

/** Plus grand délai `expire_after_ms` qu'un `charger` admet (service.mjs). */
const E_MAX = 86400000;
/** Dernier instant que `ecrireHorodatage` écrit (année 9999). */
const INSTANT_MAX = decoderHorodatage("9999-12-31T23:59:59.999Z");

/**
 * Instant d'une entrée venue du noyau, admis par la machine : une
 * date du calendrier (décodée), comprise entre 1970 et un instant tel que
 * `at + 2 E` s'écrive encore (minuteurs `recognize_until`, échéance, fenêtre).
 * @param {unknown} s
 * @returns {number|null} millisecondes, ou null (refus `requete_invalide` avant tout effet)
 */
export function instantAdmis(s) {
  if (typeof s !== "string") return null;
  const ms = decoderHorodatage(s);
  if (ms === null || !Number.isFinite(ms)) return null;
  if (ms < 0 || ms > INSTANT_MAX - 2 * E_MAX) return null;
  return ms;
}

/** Entrées du canal de la console dont le refus est inscrit sans son motif ni sa signature (CT-3 EX-7.24). */
const ENTREES_CONSOLE = new Set(["voter", "recuser", "retirer"]);

/**
 * Données d'une entrée refusée telles qu'elles vont dans la trace du ticket
 * (EX-7.8 : « le refus et sa raison sont inscrits ») : pour une entrée du
 * canal de la console, les membres qui identifient l'entrée, jamais le
 * motif libre (`reason`, 4 096 points de code admis par le schéma) ni la
 * signature ; une entrée du noyau est inscrite telle quelle (bornée par son
 * schéma).
 * @param {string} input
 * @param {object|null|undefined} data
 */
export function donneesRefus(input, data) {
  if (!ENTREES_CONSOLE.has(input) || data === null || typeof data !== "object" || Array.isArray(data)) return data;
  const r = {};
  for (const [k, v] of Object.entries(data)) if (k !== "reason" && k !== "signature") r[k] = v;
  return r;
}

const CONTEXTE = vm.createContext(Object.create(null));
const APPEL = new vm.Script("appel()", { filename: "noortrace-approbation-borne" });

/**
 * Exécute `f` sous une borne de temps (même procédé que le noyau pour
 * EX-10.23 de CT-2 : script `node:vm` à `timeout`, dont le chien de garde
 * interrompt une recherche en cours, y compris dans une fonction du contexte
 * principal appelée depuis ce contexte). Synchrone : le fil n'est bloqué
 * qu'au plus `budgetMs`.
 * @template T
 * @param {() => T} f
 * @param {number} budgetMs
 * @returns {{ok: true, valeur: T}|{ok: false}} `ok` faux : borne dépassée
 */
export function executerSousBorne(f, budgetMs) {
  const borne = Math.max(1, Math.floor(budgetMs));
  const precedent = CONTEXTE.appel;
  CONTEXTE.appel = f;
  try {
    return { ok: true, valeur: APPEL.runInContext(CONTEXTE, { timeout: borne, breakOnSigint: false }) };
  } catch (e) {
    if (e?.code === "ERR_SCRIPT_EXECUTION_TIMEOUT") return { ok: false };
    throw e;
  } finally {
    CONTEXTE.appel = precedent;
  }
}

/**
 * Motif `extract` compilé comme le noyau le compile (CT-2 EX-10.6, point
 * 4 ; CT-3 EX-12.14) : les ouvertures de groupe nommé écrites `(?P<nom>` sont
 * réécrites `(?<nom>` ; une suite `(?P<` échappée ou dans une classe de
 * caractères n'est pas une ouverture et n'est pas réécrite.
 * @param {string} motif
 * @returns {string} source ECMAScript
 */
export function reecrireGroupesNommes(motif) {
  let sortie = "";
  let classe = false;
  for (let i = 0; i < motif.length; i++) {
    const c = motif[i];
    if (c === "\\") {
      sortie += c + (motif[i + 1] ?? "");
      i++;
      continue;
    }
    if (classe) {
      if (c === "]") classe = false;
      sortie += c;
      continue;
    }
    if (c === "[") {
      classe = true;
      sortie += c;
      continue;
    }
    if (c === "(" && motif.startsWith("(?P<", i)) {
      sortie += "(?<";
      i += 3;
      continue;
    }
    sortie += c;
  }
  return sortie;
}

/**
 * Longueur maximale, en octets UTF-8, d'un chemin de prise Unix que le service
 * écoute (`noyau.socket`, `console.socket` ; CT-3 EX-12.2, complément du
 * 2026-11-16). Node.js tronque un chemin plus long à `sizeof(sun_path) - 1`
 * (107 octets sous Linux, 103 sous macOS) et la prise serait créée sous un
 * autre nom, hors du répertoire dont EX-12.2 fixe les droits : c'est la borne
 * du SDK et du démon (CT-2 EX-6.10, EX-18.1). Aucun module commun ne la
 * partage avec le démon (`paquets/enregistreur/src/bornes.mjs`) : constante
 * nommée, même valeur.
 */
export const CHEMIN_PRISE_MAX_OCTETS = 103;

/** Le chemin de prise `chemin` dépasse-t-il `CHEMIN_PRISE_MAX_OCTETS` octets UTF-8 ? */
export function cheminPriseTropLong(chemin) {
  return typeof chemin === "string" && Buffer.byteLength(chemin, "utf8") > CHEMIN_PRISE_MAX_OCTETS;
}
