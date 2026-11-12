// Contrôle de forme des requêtes du canal de la console (CT-3 EX-12.13, table
// des méthodes ; contrat de l'étape 6, 1.2) : chaque requête est contrôlée
// exactement contre le `$defs` que nomme la table d'EX-12.13 (membres requis
// et admis, types, motifs, longueurs comptées en points de code, comme JSON
// Schema 2020-12), sans validateur JSON Schema embarqué. Définitions tenues :
// `console-service-v0` (requete_tickets, requete_recuser, requete_retirer,
// requete_annuaire, requete_preparer_inscription, requete_inscrire, qui
// renvoie à annuaire-approbateurs-v0, requete_valider, requete_revoquer,
// requete_entree, requete_demandeur) et `console-approbation-v0`
// (requete_consulter, requete_voter).

import { longueurPointsDeCode } from "./octets.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Briques : chacune est un prédicat sur une valeur JSON.
const chaine = (min, max, motif) => (v) => {
  if (typeof v !== "string") return false;
  const n = longueurPointsDeCode(v);
  if (min !== null && n < min) return false;
  if (max !== null && n > max) return false;
  return motif === undefined || motif.test(v);
};
const ouNul = (p) => (v) => v === null || p(v);
const parmi = (...valeurs) => (v) => valeurs.includes(v);

const MOTIF_ADRESSE = /^0x[0-9a-f]{40}$/u;
const MOTIF_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/u;
const MOTIF_ENTREE = /^apb-[0-9a-z]+(-[0-9a-z]+)*$/u;
const MOTIF_SIGNATURE_BRUTE = /^0x([0-9a-f]{2})*$/u;

const adresse = chaine(null, null, MOTIF_ADRESSE);
const identifiantTicket = chaine(5, 128, MOTIF_TICKET);
const identifiantEntree = chaine(5, 128, MOTIF_ENTREE);
/** console-service-v0 `$defs/identite_requete`. */
const identiteRequete = chaine(1, 1024);
/** console-approbation-v0 `$defs/session_identity` (forme de ticket-v0). */
const sessionIdentityApprobation = chaine(1, 256);
/** console-service-v0 `$defs/motif`. */
const motifService = ouNul(chaine(1, 1024));
const signatureBrute = chaine(null, 1024, MOTIF_SIGNATURE_BRUTE);

/**
 * Objet aux membres requis et facultatifs donnés, sans autre membre
 * (`additionalProperties: false`).
 */
const objet = (requis, facultatifs = {}) => (v) => {
  if (!estObjet(v)) return false;
  for (const c of Object.keys(requis)) if (!Object.prototype.hasOwnProperty.call(v, c)) return false;
  for (const c of Object.keys(v)) {
    const p = Object.prototype.hasOwnProperty.call(requis, c) ? requis[c] : Object.prototype.hasOwnProperty.call(facultatifs, c) ? facultatifs[c] : null;
    if (p === null || !p(v[c])) return false;
  }
  return true;
};

const DEFINITIONS = Object.freeze({
  requete_tickets: objet({ session_identity: identiteRequete }, { related_to: identifiantTicket }),
  requete_consulter: objet({ ticket: identifiantTicket, session_identity: sessionIdentityApprobation }),
  requete_voter: objet({
    ticket: identifiantTicket,
    approver: adresse,
    decision: parmi("approuve", "refuse"),
    signature: signatureBrute,
    reason: ouNul(chaine(null, 4096)),
    session_identity: sessionIdentityApprobation,
  }),
  requete_recuser: objet({ ticket: identifiantTicket, approver: adresse, session_identity: identiteRequete }),
  requete_retirer: objet({ ticket: identifiantTicket, by: chaine(1, 256), reason: motifService, session_identity: identiteRequete }),
  requete_annuaire: objet({ session_identity: identiteRequete }),
  requete_preparer_inscription: objet({ session_identity: identiteRequete, address: adresse }),
  requete_inscrire: objet({
    session_identity: chaine(1, 1024),
    address: adresse,
    message: chaine(null, 4096),
    signature: signatureBrute,
  }),
  requete_valider: objet({ session_identity: identiteRequete, entry: identifiantEntree, address: adresse }),
  requete_revoquer: objet({ session_identity: identiteRequete, entry: identifiantEntree, address: adresse, reason: motifService }),
  requete_entree: objet({ session_identity: identiteRequete, entry: identifiantEntree, reason: motifService }),
  requete_demandeur: objet({ session_identity: identiteRequete, entry: identifiantEntree, launched_by: chaine(1, 256) }),
});

const SERVICE = "https://noortrace.example/schemas/v0/console-service.schema.json";
const APPROBATION = "https://noortrace.example/schemas/v0/console-approbation.schema.json";

/**
 * Pour chaque méthode du canal relayée au service (table d'EX-12.13), la
 * référence JSON Schema de sa requête (`<$id>#/$defs/<nom>`).
 */
export const DEFINITION_REQUETE = Object.freeze({
  tickets: `${SERVICE}#/$defs/requete_tickets`,
  consulter: `${APPROBATION}#/$defs/requete_consulter`,
  voter: `${APPROBATION}#/$defs/requete_voter`,
  recuser: `${SERVICE}#/$defs/requete_recuser`,
  retirer: `${SERVICE}#/$defs/requete_retirer`,
  annuaire: `${SERVICE}#/$defs/requete_annuaire`,
  preparer_inscription: `${SERVICE}#/$defs/requete_preparer_inscription`,
  inscrire: `${SERVICE}#/$defs/requete_inscrire`,
  valider: `${SERVICE}#/$defs/requete_valider`,
  revoquer: `${SERVICE}#/$defs/requete_revoquer`,
  desactiver: `${SERVICE}#/$defs/requete_entree`,
  reactiver: `${SERVICE}#/$defs/requete_entree`,
  lier_demandeur: `${SERVICE}#/$defs/requete_demandeur`,
  delier_demandeur: `${SERVICE}#/$defs/requete_demandeur`,
});

/**
 * Vrai si la requête a la forme exacte du `$defs` que la table d'EX-12.13
 * nomme pour la méthode.
 * @param {string} methode une des quatorze méthodes d'EX-12.13
 * @param {unknown} requete
 * @returns {boolean}
 */
export function formeRequete(methode, requete) {
  if (typeof methode !== "string" || !Object.prototype.hasOwnProperty.call(DEFINITION_REQUETE, methode)) {
    throw new TypeError("formeRequete : methode du canal attendue");
  }
  const ref = DEFINITION_REQUETE[methode];
  const nom = ref.slice(ref.lastIndexOf("/") + 1);
  return DEFINITIONS[nom](requete);
}
