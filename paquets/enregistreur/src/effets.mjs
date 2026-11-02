// Effets d'un appel d'outil relayé (CT-2 EX-7.6) : gabarit de la
// configuration évalué sur les valeurs **rédigées** des pièces « arguments »
// et « résultat », à défaut effet par défaut d'une écriture, à défaut []. Un
// effet non résolu ou invalide est omis et noté (`effect_omitted`), jamais
// une cause d'événement invalide : ce sont des données d'entrée (EX-7.1).
//
// L'exécution de `extract` sous la borne de temps d'EX-10.23 et le contrôle du
// sous-ensemble RE2 commun (EX-10.6) relèvent du lot de la rédaction : ce
// module reçoit un exécuteur (`executerExtract`) et emploie par défaut une
// expression ECMAScript en mode Unicode, sans borne de temps.

import { jcsIntegral } from "./jcs-integral.mjs";

const MOTIF_MONTANT = /^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/;
const MOTIF_DEVISE = /^[A-Z]{3}$/;

/** Dit si une chaîne de gabarit est un pointeur vers une pièce (`/arguments…`, `/result…`). */
export function estPointeur(v) {
  return typeof v === "string" && (/^\/arguments(\/|$)/.test(v) || /^\/result(\/|$)/.test(v));
}

/**
 * Résout un pointeur JSON (RFC 6901) dans une valeur.
 * @param {unknown} racine
 * @param {string} pointeur
 * @returns {{trouve: boolean, valeur?: unknown}}
 */
export function resoudrePointeur(racine, pointeur) {
  if (pointeur === "") return { trouve: true, valeur: racine };
  if (!pointeur.startsWith("/")) return { trouve: false };
  let v = racine;
  for (const brut of pointeur.slice(1).split("/")) {
    const jeton = brut.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(v)) {
      if (!/^(0|[1-9][0-9]*)$/.test(jeton) || Number(jeton) >= v.length) return { trouve: false };
      v = v[Number(jeton)];
    } else if (v !== null && typeof v === "object" && Object.prototype.hasOwnProperty.call(v, jeton)) {
      v = v[jeton];
    } else {
      return { trouve: false };
    }
  }
  return { trouve: true, valeur: v };
}

function tronquerPoints(s, max) {
  const points = Array.from(s);
  return points.length > max ? points.slice(0, max).join("") : s;
}

function extraireParDefaut(motif, texte) {
  const m = new RegExp(motif, "u").exec(texte);
  if (!m) return null;
  return m.length > 1 && m[1] !== undefined ? m[1] : m[0];
}

/**
 * Effet par défaut d'une écriture sans gabarit (EX-7.6 (2)).
 * @param {string} alias
 * @param {string} nomOrigine
 * @returns {object}
 */
export function effetParDefaut(alias, nomOrigine) {
  return { system: alias, action: "ecriture", object: nomOrigine, amount: null, currency: null };
}

/**
 * Évalue les effets d'un appel relayé (EX-7.6).
 * @param {{gabarit: object[]|null, classe: "lecture"|"ecriture", alias: string, nomOrigine: string,
 *   arguments: unknown, resultat: unknown, sourceNonRedigeable?: boolean,
 *   executerExtract?: (motif: string, texte: string) => string|null}} p
 *   `arguments` et `resultat` : valeurs JSON **rédigées** (celles dont les pièces sont le JCS intégral)
 * @returns {{effets: object[], omis: {index: number, raison: string}[]}}
 */
export function evaluerEffets(p) {
  const omis = [];
  if (!p.gabarit) {
    return { effets: p.classe === "ecriture" ? [effetParDefaut(p.alias, p.nomOrigine)] : [], omis };
  }
  const racine = { arguments: p.arguments, result: p.resultat };
  const executer = p.executerExtract ?? extraireParDefaut;
  const effets = [];
  const valeurDe = (champ) => {
    if (champ === null || champ === undefined) return { ok: true, valeur: null };
    if (!estPointeur(champ)) return { ok: true, valeur: champ };
    const r = resoudrePointeur(racine, champ);
    if (!r.trouve || r.valeur === null || r.valeur === undefined) return { ok: false };
    return { ok: true, valeur: typeof r.valeur === "string" ? r.valeur : jcsIntegral(r.valeur) };
  };
  p.gabarit.forEach((g, index) => {
    try {
      const objet = valeurDe(g.object);
      if (!objet.ok || objet.valeur === null) {
        omis.push({ index, raison: "non_resolu" });
        return;
      }
      let texteObjet = objet.valeur;
      if (g.extract !== null && g.extract !== undefined) {
        const extrait = executer(g.extract, texteObjet);
        if (extrait === null) {
          omis.push({ index, raison: "non_resolu" });
          return;
        }
        texteObjet = extrait;
      }
      const montant = valeurDe(g.amount);
      const devise = valeurDe(g.currency);
      if (!montant.ok || !devise.ok) {
        omis.push({ index, raison: "non_resolu" });
        return;
      }
      const effet = {
        system: tronquerPoints(String(g.system), 128),
        action: g.action,
        object: tronquerPoints(texteObjet, 512),
        amount: montant.valeur,
        currency: devise.valeur,
      };
      const invalide =
        effet.object.length === 0 ||
        effet.system.length === 0 ||
        (effet.amount !== null && !MOTIF_MONTANT.test(effet.amount)) ||
        (effet.currency !== null && !MOTIF_DEVISE.test(effet.currency)) ||
        (effet.amount === null) !== (effet.currency === null);
      if (invalide) {
        omis.push({ index, raison: "invalide" });
        return;
      }
      effets.push(effet);
    } catch {
      omis.push({ index, raison: "invalide" });
    }
  });
  // EX-10.23 point 2 : une écriture dont aucun effet n'est produit parce
  // qu'une pièce source est non rédigeable reçoit l'effet par défaut.
  if (effets.length === 0 && p.classe === "ecriture" && p.sourceNonRedigeable) {
    effets.push(effetParDefaut(p.alias, p.nomOrigine));
  }
  return { effets, omis };
}
