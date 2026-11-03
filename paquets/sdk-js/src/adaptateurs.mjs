// File des échanges de modèle observés (CT-2 EX-6.11 (3), EX-6.13) : seul
// `echangeModele` appelé depuis un point d'observation d'un adaptateur de cadre
// (6.6, lot suivant) passe par une file, bornée (`fileMax`, défaut 1 000),
// vidée par une unique tâche de fond. File pleine : l'échange le plus récent
// est abandonné, compté (`echangesPerdus`) et noté sur la sortie d'erreur ;
// une erreur de cette file n'atteint jamais l'agent. Un échange que la tâche
// ne peut pas remettre parce que le démon est injoignable reste en tête, tant
// que sa requête n'a pas été écrite sur la prise (`envoyee` faux), et il est
// retenté après la reprise de connexion ; un échange dont la requête a été
// écrite sans réponse n'est jamais renvoyé : il est abandonné et compté.
//
// Ce module n'ajoute rien à l'interface publique d'EX-6.9 (le client et la
// session) : c'est l'outil des adaptateurs, dont les points d'observation ne
// doivent jamais bloquer ni faire échouer l'agent. Un appel d'outil n'y passe
// jamais (EX-6.11). Il offre aussi le point d'interception commun
// (`intercepter`, EX-6.16) et les textes d'EX-6.19 ; les adaptateurs de cadres
// sont dans `noortrace-sdk/adaptateurs/langchain` et
// `noortrace-sdk/adaptateurs/openai-agents`.

import { ErreurNoortraceIndisponible, AppelNonAutorise, ErreurNoortraceDegrade, ErreurNoortraceLimite, ErreurNoortraceEntreeInvalide, texteNonAutorise } from "./erreurs.mjs";
import { delaiReprise, estValeurJson, nomDuType, nomDeClasse } from "./index.mjs";

export class FileEchanges {
  /**
   * @param {import("./index.mjs").Session} session
   * @param {{fileMax?: number, sortie?: {write: (s: string) => void}}} [o]
   */
  constructor(session, o = {}) {
    this.session = session;
    this.fileMax = o.fileMax ?? 1000;
    this.sortie = o.sortie ?? process.stderr;
    this.file = [];
    this.echangesPerdus = 0;
    this.tache = null;
  }

  /**
   * Met un échange en file, sans jamais attendre ni lever (EX-6.11 (3)).
   * @param {object} p paramètres de `session.echangeModele`
   * @returns {boolean} l'échange est en file
   */
  ajouter(p) {
    if (this.file.length >= this.fileMax) {
      this.echangesPerdus++;
      this.sortie.write(`noortrace-sdk: file des echanges pleine (${this.fileMax}) ; echange abandonne, ${this.echangesPerdus} perdu(s)\n`);
      return false;
    }
    this.file.push(p);
    if (!this.tache) this.tache = this._vider().finally(() => (this.tache = null));
    return true;
  }

  /** Attend que la file soit vide (arrêt, essais). */
  async vide() {
    while (this.tache) await this.tache;
  }

  async _vider() {
    let n = 0;
    while (this.file.length) {
      const p = this.file[0];
      try {
        await this.session.echangeModele(p);
        this.file.shift();
        n = 0;
      } catch (e) {
        if (e instanceof ErreurNoortraceIndisponible && !e.envoyee) {
          // Démon injoignable avant l'écriture : l'échange reste en tête et sera remis après la reprise (EX-6.13).
          await new Promise((r) => {
            const t = setTimeout(r, delaiReprise(Math.min(n, 4)));
            t.unref?.();
          });
          n++;
          continue;
        }
        this.file.shift();
        this.echangesPerdus++;
        this.sortie.write(`noortrace-sdk: echange non remis (${e?.name ?? "erreur"}) ; ${this.echangesPerdus} perdu(s)\n`);
      }
    }
  }
}

// ---------------------------------------------------------------- points d'interception (6.6, EX-6.16 à EX-6.19)


/** Textes fixes d'EX-6.19 (ASCII, français sans accent). */
export const TEXTE_DEGRADE = "noortrace: appel bloque, enregistreur en mode degrade";
export const TEXTE_INJOIGNABLE = "noortrace: enregistreur injoignable";
export const TEXTE_LIMITE = "noortrace: taille maximale depassee";
export const TEXTE_ENTREE_INVALIDE = "noortrace: appel refuse, entree invalide";
export const TEXTE_NON_DURABLE = "noortrace: appel execute, evenement non durable";

/** Motif d'un nom d'outil de CT-1 (`$defs/nom_outil`). */
const MOTIF_NOM_OUTIL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

/**
 * Le nom respecte-t-il le motif de 6.2 (motif de CT-1, sans `__`, hors `noortrace.`) ? (EX-6.18)
 * @param {unknown} nom
 */
export function nomDeclarable(nom) {
  return typeof nom === "string" && MOTIF_NOM_OUTIL.test(nom) && !nom.includes("__") && !nom.startsWith("noortrace.");
}

/**
 * Texte rendu au modèle quand `debutAppel` n'a pas autorisé l'outil (EX-6.19) ;
 * une erreur d'un autre code, ou une exception du code de l'adaptateur, reçoit
 * celui d'`ErreurNoortraceIndisponible` (LISEZMOI du SDK Python, lecture 151).
 * @param {unknown} e
 */
export function texteAvantExecution(e) {
  if (e instanceof AppelNonAutorise) return e.texte;
  if (e instanceof ErreurNoortraceDegrade) return TEXTE_DEGRADE;
  if (e instanceof ErreurNoortraceLimite) return TEXTE_LIMITE;
  if (e instanceof ErreurNoortraceEntreeInvalide) return TEXTE_ENTREE_INVALIDE;
  return TEXTE_INJOIGNABLE;
}

/** Valeur JSON déclarée (EX-6.9) : la valeur, ou `{"noortrace_sdk_non_json": "<type>"}`. */
export function valeurDeclaree(v) {
  return estValeurJson(v) ? v : { noortrace_sdk_non_json: nomDuType(v) };
}

/**
 * Réglages communs des adaptateurs (EX-6.17, EX-6.18).
 * @param {{classes?: Record<string, "lecture"|"ecriture">, modele?: "passerelle"|"declarer", ignorer?: string[]}} [o]
 */
export function reglagesAdaptateur(o = {}) {
  const classes = { ...(o.classes ?? {}) };
  for (const [k, v] of Object.entries(classes)) if (v !== "lecture" && v !== "ecriture") throw new TypeError(`noortrace: classe invalide pour ${k}`);
  const modele = o.modele ?? "passerelle";
  if (modele !== "passerelle" && modele !== "declarer") throw new TypeError("noortrace: modele vaut 'passerelle' ou 'declarer'");
  return { classes, modele, ignorer: new Set(o.ignorer ?? []) };
}

/**
 * Point d'interception (EX-6.16, EX-6.18, EX-6.19) : `debutAppel`, l'outil
 * seulement pour `autorise`, durée sur l'horloge monotone, `finAppel`. Toute
 * exception levée avant l'exécution, du SDK ou du code de l'adaptateur, laisse
 * l'outil non exécuté (EX-6.15, EX-6.20 (v)). Une exception de l'outil est
 * déclarée (`noortrace_sdk_exception`) puis relancée.
 * @param {object} session session de `noortrace-sdk`
 * @param {() => {nom: string, args: unknown, classe: string|null}} preparer
 * @param {() => Promise<unknown>} executer
 * @param {(v: unknown) => {resultat: unknown, isError: boolean}} declarer
 * @returns {Promise<{executee: boolean, texte: string|null, valeur?: unknown}>}
 */
export async function intercepter(session, preparer, executer, declarer) {
  let classe = null;
  let nom = "?";
  let debut;
  try {
    const p = preparer();
    nom = p.nom;
    classe = p.classe ?? null;
    if (!nomDeclarable(nom)) return { executee: false, texte: TEXTE_ENTREE_INVALIDE };
    debut = await session.debutAppel({ tool: nom, arguments: p.args, classe });
  } catch (e) {
    // EX-6.15 : lecture exécutée sans événement seulement avec « executer ».
    if (!(e instanceof ErreurNoortraceEntreeInvalide) && classe === "lecture" && session._client?.surIndisponibiliteLecture === "executer") {
      process.stderr.write(`noortrace-sdk: debutAppel en echec (${nomDeClasse(e)}) ; outil de lecture ${nom} execute sans evenement\n`);
      return { executee: true, texte: null, valeur: await executer() };
    }
    return { executee: false, texte: texteAvantExecution(e) };
  }
  if (debut.decision !== "autorise") return { executee: false, texte: texteNonAutorise(debut.ticket ?? null, debut.ticket_state ?? null) };
  const t0 = performance.now();
  const duree = () => Math.max(0, Math.floor(performance.now() - t0));
  let valeur;
  try {
    valeur = await executer();
  } catch (e) {
    try {
      await session.finAppel(debut, { resultat: { noortrace_sdk_exception: nomDeClasse(e) }, isError: true, durationMs: duree() });
    } catch {
      return { executee: true, texte: TEXTE_NON_DURABLE };
    }
    throw e;
  }
  const d = duree();
  try {
    const { resultat, isError } = declarer(valeur);
    await session.finAppel(debut, { resultat, isError: isError === true, durationMs: d });
  } catch {
    // EX-6.19 : l'appel a eu lieu, l'événement n'est pas durable.
    return { executee: true, texte: TEXTE_NON_DURABLE, valeur };
  }
  return { executee: true, texte: null, valeur };
}

/**
 * `providerLabel` au motif de `$defs/model_route/provider_label`.
 * @param {unknown} texte
 */
export function etiquette(texte, defaut = "local") {
  if (typeof texte !== "string") return defaut;
  const t = texte.toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 32).replace(/[-.]+$/, "");
  return /^[a-z0-9]/.test(t) ? t : defaut;
}
