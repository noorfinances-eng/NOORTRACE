// Corrélation appel d'outil ↔ échange de modèle (CT-2 §5.6, EX-5.22) :
// registre où le frontal modèle inscrit chaque échange dès que la forme de
// sa réponse est complète en mémoire, avant son scellement, et crochet
// `correler` du frontal MCP (pas 3 de 4.4) et du SDK (`debutAppel`).
//
// La décision de correspondance ne dépend que de la forme en clair, qui ne
// quitte pas la mémoire et disparaît à la sortie de la fenêtre ; `intent`,
// `code.model` et `code.prompt_version` viennent de la réponse rédigée, que
// `correler` attend si elle n'est pas encore calculée. Un échange interposé
// (passerelle) est toujours préféré à un échange déclaré (SDK).

import { jcsIntegral } from "../jcs-integral.mjs";
import { appelsDemandes, argumentsComparables, intentionAvant, intentionBornee } from "./extraction.mjs";

/** Fenêtre par défaut (EX-5.22). */
export const FENETRE_DEFAUT_MS = 600000;

/**
 * Nom d'un outil tel que le modèle le voit (EX-5.22 point 1, 15.1) :
 * gabarit `tool_name_template` ({alias}, {tool}, {tool_announced}), puis,
 * s'il est actif, `tool_name_sanitize` (hors A-Z a-z 0-9 _ - → `_`).
 * @param {string} nomAnnonce
 * @param {{tool_name_template?: string, tool_name_sanitize?: boolean}} hote
 * @param {{alias: string, nom: string}} origine
 * @returns {string}
 */
export function nomVuParLeModele(nomAnnonce, hote, origine) {
  const g = hote?.tool_name_template ?? "{tool_announced}";
  let n = g.replace(/\{(alias|tool|tool_announced)\}/g, (_, k) => (k === "alias" ? origine.alias : k === "tool" ? origine.nom : nomAnnonce));
  if (hote?.tool_name_sanitize === true) n = n.replace(/[^A-Za-z0-9_-]/g, "_");
  return n;
}

/** Origine par défaut d'un nom annoncé `<alias>__<nom>` (EX-4.10). */
export function origineParDefaut(nom) {
  const k = nom.indexOf("__");
  return k > 0 ? { alias: nom.slice(0, k), nom: nom.slice(k + 2) } : { alias: "", nom };
}

export class RegistreCorrelation {
  /**
   * @param {object} o
   * @param {number} [o.fenetreMs] `model.correlation_window_ms`
   * @param {() => number} o.monotone horloge monotone (celle des frontaux)
   * @param {(piece: import("../pieces.mjs").Piece) => Promise<object>} [o.ecrirePiece] pièce d'intention (EX-5.21)
   * @param {(nom: string) => {alias: string, nom: string}} [o.origine]
   * @param {{consigner: Function}|null} [o.journal]
   */
  constructor(o) {
    this.fenetreMs = o.fenetreMs ?? FENETRE_DEFAUT_MS;
    this.monotone = o.monotone;
    this.ecrirePiece = o.ecrirePiece ?? null;
    this.origine = o.origine ?? origineParDefaut;
    this.journal = o.journal ?? null;
    /** @type {object[]} */
    this.entrees = [];
    this.compteur = 0;
  }

  _purger(maintenant) {
    const limite = maintenant - this.fenetreMs;
    this.entrees = this.entrees.filter((e) => e.t_complet >= limite);
  }

  /**
   * Inscrit un échange dont la forme en clair est complète (5.3.1 pas 8,
   * EX-5.11 (d)), avant son scellement.
   * @param {{host: object, host_group: string, run_id: string|null, format: string, formeClair: unknown,
   *   interpose?: boolean, t_complet?: number}} x
   * @returns {object} l'entrée, à compléter par `completer` puis `sceller`
   */
  inscrire(x) {
    const t = x.t_complet ?? this.monotone();
    this._purger(t);
    let resoudre;
    const redigee = new Promise((r) => (resoudre = r));
    const e = {
      inscription: ++this.compteur,
      host: x.host,
      host_group: x.host_group,
      run_id: x.run_id ?? null,
      format: x.format,
      interpose: x.interpose !== false,
      t_complet: t,
      formeClair: x.formeClair,
      appels: appelsDemandes(x.format, x.formeClair).map((a) => ({ ...a, consomme: false })),
      redigee,
      resoudre,
      seq: null,
    };
    this.entrees.push(e);
    return e;
  }

  /**
   * Réponse rédigée d'un échange inscrit, et les valeurs `code` qui en
   * viennent.
   * @param {object} e
   * @param {{formeRedigee: unknown, code: {model: string|null, prompt_version: string|null}}} r
   */
  completer(e, r) {
    e.resoudre({ formeRedigee: r.formeRedigee, code: r.code });
  }

  /** `seq` de l'échange une fois scellé (ou null s'il ne l'a pas été). */
  sceller(e, seq) {
    e.seq = seq;
  }

  _correspond(e, nom, hote, A) {
    const origine = this.origine(nom);
    const vu = nomVuParLeModele(nom, hote, origine);
    for (const a of e.appels) {
      if (a.consomme) continue;
      if (a.name !== nom && a.name !== vu) continue;
      const args = argumentsComparables(e.format, a.arguments);
      if (args === undefined) continue;
      if (jcsIntegral(args) === A) return a;
    }
    return null;
  }

  /**
   * Corrélation d'un appel d'outil (EX-5.22). Crochet du frontal MCP
   * (INTERFACES.md, section a) et du SDK.
   * @param {{host: object, host_group: string, run_id: string|null, tool_announced: string, arguments: unknown, t_recu: number}} c
   * @returns {Promise<{intent: string|object|null, code: {model: string|null, prompt_version: string|null}, seq: number|string, declaree: boolean}|null>}
   */
  async correler(c) {
    this._purger(this.monotone());
    let A;
    try {
      A = jcsIntegral(c.arguments ?? {});
    } catch {
      return null;
    }
    const debut = c.t_recu - this.fenetreMs;
    const candidates = this.entrees
      .filter((e) => e.host_group === c.host_group && e.t_complet >= debut && e.t_complet <= c.t_recu)
      .filter((e) => !(c.run_id && e.run_id && c.run_id !== e.run_id))
      .sort((x, y) => y.t_complet - x.t_complet || y.inscription - x.inscription);
    let trouve = null;
    for (const interpose of [true, false]) {
      for (const e of candidates) {
        if (e.interpose !== interpose) continue;
        const a = this._correspond(e, c.tool_announced, c.host, A);
        if (a) {
          a.consomme = true;
          trouve = { e, a };
          break;
        }
      }
      if (trouve) break;
    }
    if (!trouve) return null;
    const { e, a } = trouve;
    const r = await e.redigee;
    const redige = r.formeRedigee === undefined ? null : intentionAvant(e.format, r.formeRedigee, a.position);
    const b = intentionBornee(redige, intentionAvant(e.format, e.formeClair, a.position));
    if (b.piece) {
      try {
        if (!this.ecrirePiece) throw new Error("pièce d'intention non inscriptible");
        await this.ecrirePiece(b.piece);
      } catch {
        // Pièce non écrite (mode dégradé) : l'intention ne peut pas être citée.
        return { intent: null, code: r.code, seq: e.seq ?? `inscription:${e.inscription}`, declaree: !e.interpose };
      }
    }
    const seq = e.seq ?? `inscription:${e.inscription}`;
    if (!e.interpose) this.journal?.consigner("info", "frontal_modele", "correlation_declaree", { seq });
    return { intent: b.intent, code: r.code, seq, declaree: !e.interpose };
  }
}
