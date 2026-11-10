// Soumission aux calendriers (CT-5 EX-6.2, AN-17), mise à niveau (EX-6.6,
// EX-6.7, AN-19) et cadence (EX-6.6, EX-8.11). Le transport est injecté ;
// `transportHttps` est l'implémentation par défaut (HTTPS seulement, en-tête
// `Accept` d'EX-6.2, corps borné à 10 000 octets). Horloge injectée : aucune
// lecture de l'horloge du système ici.

import { hexVersOctets, octetsVersHex } from "@noortrace/noyau";
import { BORNES, ErreurOts, construirePreuve, engagementOctets, lireTimestamp, lireOts, attestationsEnAttente, fusionnerOts } from "./format.mjs";
import { executerArbre, verifierOts, admissionApresFusion, hauteursAttestees, STATUT } from "./verification.mjs";
import { lireFichierEntetes } from "./entetes.mjs";

/** En-tête `Accept` du protocole des calendriers (EX-6.2, R1-F63). */
export const ACCEPT_OTS = "application/vnd.opentimestamps.v1";
/** Valeurs par défaut du client officiel (EX-6.2, R1-F61). */
export const DEFAUTS = Object.freeze({ minReponses: 2, delaiMs: 5000, intervalleMinS: 60, quotidienS: 86400 });

/** Erreur de transport ; `code` stable, sans donnée sensible. */
export class ErreurTransport extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurTransport";
    this.code = code;
  }
}

/**
 * Engagement e = SHA-256(empreinte ‖ nonce) en hexadécimal préfixé (EX-6.2, étape 1).
 * @param {string|Uint8Array} empreinte
 * @param {Uint8Array} nonce 16 octets
 */
export function engagement(empreinte, nonce) {
  return octetsVersHex(engagementOctets(empreinte, nonce));
}

function urlCalendrier(base) {
  if (typeof base !== "string" || !/^https:\/\/[^\s/]+(\/[^\s]*)?$/.test(base) || base.length > 512) {
    throw new ErreurOts("calendrier", "URL de calendrier refusée (https attendu)");
  }
  return base.replace(/\/+$/, "");
}

/**
 * Relit une réponse de calendrier (EX-6.2, étape 3 ; EX-6.6) : `Timestamp`
 * sur l'engagement, bornes d'O-1, profil {f0, f1, 08} et bornes d'O-3,
 * au moins une attestation atteinte.
 * @param {Uint8Array} corps
 * @param {Uint8Array} engagementOctets_
 * @returns {{arbre: import("./format.mjs").Noeud|null, erreur: string|null, attestations: object[]}}
 */
export function relireReponseCalendrier(corps, engagementOctets_) {
  let arbre;
  try {
    arbre = lireTimestamp(corps);
  } catch (e) {
    if (!(e instanceof ErreurOts)) throw e;
    return { arbre: null, erreur: `illisible_${e.code}`, attestations: [] };
  }
  const { attestations, defauts } = executerArbre(arbre, engagementOctets_);
  if (attestations.some((a) => a.chemin === "hors_profil")) return { arbre: null, erreur: "hors_profil", attestations };
  if (defauts.length > 0) return { arbre: null, erreur: "operations", attestations };
  if (attestations.length === 0) return { arbre: null, erreur: "sans_attestation", attestations };
  return { arbre, erreur: null, attestations };
}

function codeTransport(e) {
  if (e instanceof ErreurTransport) return `transport_${e.code}`;
  if (e && typeof e === "object" && typeof e.code === "string") return `transport_${e.code.toLowerCase()}`;
  return "transport_erreur";
}

/**
 * Soumission aux calendriers (EX-6.2, étapes 2 à 4) : `POST <url>/digest`,
 * corps = les 32 octets de l'engagement, `Accept` d'EX-6.2, réponses relues
 * et bornées ; écriture décidée quand `minReponses` réponses valables sont
 * arrivées dans `delaiMs`. Le rejeu avec le même nonce rend le même
 * engagement et la même décision.
 * @param {{empreinte: string|Uint8Array, nonce: Uint8Array, calendriers: string[], minReponses?: number, delaiMs?: number, transport: object, horloge: {murale(): number, monotone(): number}}} p
 */
export async function soumettre({ empreinte, nonce, calendriers, minReponses = DEFAUTS.minReponses, delaiMs = DEFAUTS.delaiMs, transport, horloge }) {
  if (!transport || typeof transport.post !== "function") throw new ErreurOts("transport", "transport avec post attendu");
  if (!horloge || typeof horloge.monotone !== "function" || typeof horloge.murale !== "function") throw new ErreurOts("horloge", "horloge injectée attendue");
  if (!Array.isArray(calendriers) || calendriers.length === 0) throw new ErreurOts("calendriers", "au moins un calendrier attendu");
  const urls = calendriers.map(urlCalendrier);
  if (new Set(urls).size !== urls.length) throw new ErreurOts("calendriers", "calendriers en double");
  if (!Number.isInteger(minReponses) || minReponses < 1 || minReponses > calendriers.length) throw new ErreurOts("min_reponses", "min_responses hors de [1, nombre de calendriers]");
  if (!Number.isInteger(delaiMs) || delaiMs < 1) throw new ErreurOts("delai", "délai en millisecondes attendu");
  const e = engagementOctets(empreinte, nonce);
  const instant = horloge.murale();
  const debut = horloge.monotone();

  const reponses = await Promise.all(
    urls.map(async (url) => {
      const depart = horloge.monotone();
      const base = { calendrier: url, status: null, octets: null, erreur: null, dureeMs: 0, attestations: [] };
      try {
        const r = await transport.post(`${url}/digest`, e, { Accept: ACCEPT_OTS, "Content-Type": "application/octet-stream" }, delaiMs);
        base.dureeMs = horloge.monotone() - depart;
        base.status = r.status;
        if (r.status !== 200) {
          base.erreur = `http_${r.status}`;
          return base;
        }
        if (!(r.corps instanceof Uint8Array) || r.corps.length > BORNES.REPONSE_CALENDRIER_MAX) {
          base.erreur = "reponse_trop_grande";
          return base;
        }
        const relue = relireReponseCalendrier(r.corps, e);
        base.attestations = relue.attestations.map((a) => ({ genre: a.genre, uri: a.uri, hauteur: a.hauteur }));
        if (relue.erreur !== null) {
          base.erreur = relue.erreur;
          return base;
        }
        base.octets = r.corps;
        return base;
      } catch (err) {
        base.dureeMs = horloge.monotone() - depart;
        base.erreur = codeTransport(err);
        return base;
      }
    }),
  );
  const valides = reponses.filter((r) => r.octets !== null);
  const ecrire = valides.length >= minReponses;
  const octets = ecrire ? construirePreuve({ empreinte, nonce, reponses: valides.map((r) => r.octets) }).octets : null;
  return {
    engagement: octetsVersHex(e),
    reponses,
    valides: valides.length,
    ecrire,
    octets,
    attestation: ecrire ? (hauteursAttestees(lireOts(octets).arbre) === null ? "en_attente" : "complete") : "aucune",
    instant,
    dureeMs: horloge.monotone() - debut,
  };
}

const MOTIFS_404 = [
  { motif: "en_attente", texte: "Pending confirmation in Bitcoin blockchain" },
  { motif: "en_attente", texte: "Timestamped by transaction" },
  { motif: "non_trouve", texte: "Not found" },
];

function classer404(corps) {
  let texte = "";
  try {
    texte = new TextDecoder("utf-8", { fatal: false }).decode(corps.subarray(0, 512));
  } catch {
    texte = "";
  }
  for (const m of MOTIFS_404) if (texte.includes(m.texte)) return m.motif;
  return "http_404";
}

/**
 * Mise à niveau (EX-6.6) : pour chaque attestation en attente dont l'URI est
 * dans la liste blanche, `GET <uri>/timestamp/<e hex>` ; 404 laisse la
 * preuve telle quelle ; 200 est relu, fusionné (l'attestation en attente de
 * ce calendrier remplacée par le chemin reçu) puis la preuve fusionnée est
 * vérifiée (O-1, O-3, et O-4, O-5 avec des en-têtes) avant d'être rendue.
 * `entetes` : `null`, un document `entetes-bitcoin-v0`, ou une fonction
 * asynchrone `({ hauteurs: [h, h'] }) → document|null` appelée une fois les
 * hauteurs attestées connues.
 * @param {{preuve: Uint8Array, listeBlanche: string[], transport: object, horloge: object, delaiMs?: number, entetes?: unknown, reseau?: string|null}} p
 * @returns {Promise<{nouvelle: Uint8Array|null, etat: "complete"|"en_attente", refus: object[], reponses: object[], hauteurs: [number, number]|null, verification: object|null, instant: number}>}
 */
export async function mettreANiveau({ preuve, listeBlanche, transport, horloge, delaiMs = DEFAUTS.delaiMs, entetes = null, reseau = null }) {
  if (!transport || typeof transport.get !== "function") throw new ErreurOts("transport", "transport avec get attendu");
  if (!horloge || typeof horloge.monotone !== "function" || typeof horloge.murale !== "function") throw new ErreurOts("horloge", "horloge injectée attendue");
  if (!Array.isArray(listeBlanche)) throw new ErreurOts("liste_blanche", "liste blanche attendue");
  const blanche = new Set(listeBlanche.map(urlCalendrier));
  const lu = lireOts(preuve);
  const instant = horloge.murale();
  const etatAvant = hauteursAttestees(lu.arbre) === null ? "en_attente" : "complete";
  const attentes = attestationsEnAttente(lu.arbre, lu.empreinte);
  const refus = [];
  const reponses = [];
  const fusions = [];

  for (const { attestation, message } of attentes) {
    const eHex = octetsVersHex(message);
    const uriNormalisee = attestation.uri.replace(/\/+$/, "");
    if (!blanche.has(uriNormalisee)) {
      refus.push({ uri: attestation.uri, motif: "hors_liste_blanche", detail: "attestation conservée telle quelle" });
      continue;
    }
    const depart = horloge.monotone();
    const ligne = { uri: attestation.uri, engagement: eHex, status: null, resultat: null, dureeMs: 0 };
    try {
      const r = await transport.get(`${uriNormalisee}/timestamp/${eHex.slice(2)}`, { Accept: ACCEPT_OTS }, delaiMs);
      ligne.dureeMs = horloge.monotone() - depart;
      ligne.status = r.status;
      if (r.status === 404) {
        ligne.resultat = classer404(r.corps instanceof Uint8Array ? r.corps : new Uint8Array(0));
      } else if (r.status === 200) {
        if (!(r.corps instanceof Uint8Array) || r.corps.length > BORNES.REPONSE_CALENDRIER_MAX) {
          ligne.resultat = "reponse_trop_grande";
          refus.push({ uri: attestation.uri, motif: "reponse_trop_grande" });
        } else {
          const relue = relireReponseCalendrier(r.corps, message);
          if (relue.erreur !== null) {
            ligne.resultat = relue.erreur;
            refus.push({ uri: attestation.uri, motif: relue.erreur, detail: "chemin reçu refusé par le lecteur" });
          } else {
            ligne.resultat = "fusionne";
            fusions.push({ engagement: message, chemin: relue.arbre, uri: attestation.uri });
          }
        }
      } else {
        ligne.resultat = `http_${r.status}`;
      }
    } catch (err) {
      ligne.dureeMs = horloge.monotone() - depart;
      ligne.resultat = codeTransport(err);
    }
    reponses.push(ligne);
  }

  if (fusions.length === 0) {
    return { nouvelle: null, etat: etatAvant, refus, reponses, hauteurs: null, verification: null, instant };
  }

  let courante = preuve;
  for (const f of fusions) courante = fusionnerOts(courante, f).octets;
  const arbre = lireOts(courante).arbre;
  const h = hauteursAttestees(arbre);
  const hauteurs = h === null ? null : [h.min, h.max];

  let documentEntetes = entetes;
  if (typeof entetes === "function") documentEntetes = hauteurs === null ? null : await entetes({ hauteurs });
  if (documentEntetes !== null && documentEntetes !== undefined && !(documentEntetes instanceof Uint8Array) && typeof documentEntetes !== "object") {
    throw new ErreurOts("entetes", "document d'en-têtes attendu");
  }
  const verification = verifierOts({ octets: courante, empreinteAttendue: lu.empreinte, entetes: documentEntetes ?? null, reseau });
  const admission = admissionApresFusion(verification);
  if (!admission.admise) {
    refus.push({ uri: null, motif: `verification_${admission.motifs.join("_")}`, detail: admission.motifs.map((m) => verification.details[m]).join(" ; ") });
    return { nouvelle: null, etat: etatAvant, refus, reponses, hauteurs, verification, instant };
  }
  if (documentEntetes !== null && documentEntetes !== undefined && verification.checks["O-4"] !== STATUT.REUSSI) {
    refus.push({ uri: null, motif: "en_tetes_insuffisants", detail: `O-4 ${verification.checks["O-4"]} (${verification.raisons["O-4"] ?? ""}) : la hauteur attestée n'a pas pu être rapprochée d'un en-tête ; preuve admise, fichier d'en-têtes à compléter` });
  }
  return { nouvelle: courante, etat: verification.etat, refus, reponses, hauteurs, verification, instant };
}

/**
 * Cadence de la mise à niveau (EX-6.6, EX-8.11) : première tentative
 * `first_after_s` après la soumission, puis toutes les `interval_s` (jamais
 * moins de 60 s) ; au-delà de `give_up_after_s` sans attestation, `abandon`
 * est vrai (alerte `ots_give_up`) et les tentatives continuent une fois par
 * jour. Fonction pure, instants en millisecondes.
 * @param {{soumisMs: number, derniereTentativeMs: number|null, maintenantMs: number, cadence: {first_after_s: number, interval_s: number, give_up_after_s: number}}} p
 * @returns {{prochaineMs: number, abandon: boolean, echue: boolean}}
 */
export function cadenceMiseANiveau({ soumisMs, derniereTentativeMs, maintenantMs, cadence }) {
  for (const [nom, v] of [["soumisMs", soumisMs], ["maintenantMs", maintenantMs]]) {
    if (!Number.isInteger(v) || v < 0) throw new ErreurOts("cadence", `${nom} : entier attendu`);
  }
  if (derniereTentativeMs !== null && (!Number.isInteger(derniereTentativeMs) || derniereTentativeMs < soumisMs)) throw new ErreurOts("cadence", "derniereTentativeMs invalide");
  if (!cadence || ![cadence.first_after_s, cadence.interval_s, cadence.give_up_after_s].every((v) => Number.isInteger(v) && v > 0)) throw new ErreurOts("cadence", "cadence invalide");
  const intervalleS = Math.max(cadence.interval_s, DEFAUTS.intervalleMinS);
  const abandon = maintenantMs - soumisMs >= cadence.give_up_after_s * 1000;
  let prochaineMs;
  if (derniereTentativeMs === null) prochaineMs = soumisMs + cadence.first_after_s * 1000;
  else if (abandon) prochaineMs = derniereTentativeMs + DEFAUTS.quotidienS * 1000;
  else prochaineMs = derniereTentativeMs + intervalleS * 1000;
  return { prochaineMs, abandon, echue: prochaineMs <= maintenantMs };
}

/**
 * Lit un corps de réponse en flux, borné : au-delà de `tailleMax` octets la
 * lecture s'arrête et l'erreur `reponse_trop_grande` est levée sans lecture.
 */
async function lireCorpsBorne(reponse, tailleMax) {
  if (!reponse.body) return new Uint8Array(0);
  const lecteur = reponse.body.getReader();
  const morceaux = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await lecteur.read();
      if (done) break;
      total += value.length;
      if (total > tailleMax) {
        await lecteur.cancel().catch(() => {});
        throw new ErreurTransport("reponse_trop_grande", `réponse de plus de ${tailleMax} octets`);
      }
      morceaux.push(value);
    }
  } finally {
    lecteur.releaseLock?.();
  }
  const corps = new Uint8Array(total);
  let d = 0;
  for (const m of morceaux) {
    corps.set(m, d);
    d += m.length;
  }
  return corps;
}

/**
 * Transport par défaut : HTTPS seulement (EX-6.2 ; `http://` admis vers
 * 127.0.0.1 ou ::1 pour les essais locaux), délai par requête, corps borné
 * (10 000 octets par défaut, EX-6.2, EX-6.6). `fetch` est injectable pour les
 * tests ; le délai emploie `AbortSignal.timeout`, seul minuteur de ce module,
 * confiné à la couche réseau.
 * @param {{fetch?: typeof fetch, tailleMax?: number}} [options]
 */
export function transportHttps({ fetch: fetchInjecte, tailleMax = BORNES.REPONSE_CALENDRIER_MAX } = {}) {
  const f = fetchInjecte ?? globalThis.fetch;
  if (typeof f !== "function") throw new ErreurTransport("fetch", "fetch indisponible");
  const controlerUrl = (url) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      throw new ErreurTransport("url", "URL invalide");
    }
    const locale = u.hostname === "127.0.0.1" || u.hostname === "[::1]" || u.hostname === "::1" || u.hostname === "localhost";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && locale)) throw new ErreurTransport("schema_url", "https exigé");
    if (u.username || u.password) throw new ErreurTransport("url", "identifiants dans l'URL refusés");
    return u;
  };
  const executer = async (url, init, delaiMs, options) => {
    controlerUrl(url);
    let reponse;
    try {
      reponse = await f(url, { ...init, redirect: "error", signal: AbortSignal.timeout(delaiMs) });
    } catch (e) {
      if (e && (e.name === "TimeoutError" || e.name === "AbortError")) throw new ErreurTransport("delai", `aucune réponse en ${delaiMs} ms`);
      throw new ErreurTransport("reseau", "erreur de transport");
    }
    const corps = await lireCorpsBorne(reponse, options?.tailleMax ?? tailleMax);
    const entetes = {};
    reponse.headers.forEach((valeur, nom) => {
      entetes[nom.toLowerCase()] = valeur;
    });
    return { status: reponse.status, entetes, corps };
  };
  return {
    post: (url, octets, entetes, delaiMs, options) =>
      executer(url, { method: "POST", headers: { ...entetes, "Content-Length": String(octets.length) }, body: octets }, delaiMs, options),
    get: (url, entetes, delaiMs, options) => executer(url, { method: "GET", headers: { ...entetes } }, delaiMs, options),
  };
}

export { lireFichierEntetes, hexVersOctets };
