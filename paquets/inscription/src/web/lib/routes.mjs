// Aides des routes de l'interface (INTERFACES.md 2.3) : JSON strict en entrée
// et en sortie, session exigée (le mandataire l'a déjà contrôlée ; la route
// la relit, défense en profondeur), erreurs `{ error: { code, message } }`.

import { lireJsonStrict } from "../../commun/json.mjs";
import { cookieDe, session } from "./serveur.mjs";
import { CORPS_MAX } from "./bornes.mjs";

export { CORPS_MAX };

/** Réponse JSON. */
export function json(statut, objet, entetes = {}) {
  return new Response(statut === 204 ? null : JSON.stringify(objet), { status: statut, headers: { ...(statut === 204 ? {} : { "content-type": "application/json; charset=utf-8" }), "cache-control": "no-store", ...entetes } });
}

/** Réponse d'erreur. */
export const erreur = (statut, code, message, data = undefined) => json(statut, { error: { code, message, ...(data ? { data } : {}) } });

/** Session de la requête, ou null. */
export function sessionDe(requete) {
  return session(cookieDe(requete.headers.get("cookie")));
}

/** Réponse 413 d'un corps au-delà de la borne. */
const tropGrand = () => ({ reponse: erreur(413, "corps_trop_grand", `corps au-delà de ${CORPS_MAX} octets`) });

/**
 * Octets du corps, lus par morceaux et bornés : un `Content-Length` au-delà de
 * `CORPS_MAX` est refusé avant toute lecture, et la lecture s'arrête (flux
 * annulé) dès que la borne est franchie ; un corps sans longueur annoncée
 * (envoi fragmenté) ne retient donc jamais plus de `CORPS_MAX` octets, et la
 * réponse part sans attendre la fin de l'envoi. Rend les octets, ou null au-delà
 * de la borne.
 * @param {Request} requete
 * @returns {Promise<Uint8Array|null>}
 */
export async function lireCorpsBorne(requete) {
  const annonce = requete.headers.get("content-length");
  if (annonce !== null && /^[0-9]+$/.test(annonce) && Number(annonce) > CORPS_MAX) return null;
  if (!requete.body) return new Uint8Array(0);
  const lecteur = requete.body.getReader();
  const morceaux = [];
  let total = 0;
  for (;;) {
    const { done, value } = await lecteur.read();
    if (done) break;
    total += value.length;
    if (total > CORPS_MAX) {
      await lecteur.cancel().catch(() => {});
      return null;
    }
    morceaux.push(value);
  }
  const o = new Uint8Array(total);
  let k = 0;
  for (const m of morceaux) {
    o.set(m, k);
    k += m.length;
  }
  return o;
}

/** Corps JSON strict, borné à `CORPS_MAX` octets ; rend `{ valeur }` ou `{ reponse }` (415, 413 ou 400). */
export async function corps(requete) {
  const type = requete.headers.get("content-type") ?? "";
  if (!/^application\/json(;|$)/.test(type)) return { reponse: erreur(415, "type_refuse", "corps application/json attendu") };
  const o = await lireCorpsBorne(requete);
  if (o === null) return tropGrand();
  try {
    return { valeur: lireJsonStrict(o) };
  } catch {
    return { reponse: erreur(400, "requete_invalide", "JSON strict attendu") };
  }
}
