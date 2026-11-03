// Réponses du point d'entrée OpenTelemetry (CT-2 EX-6.27) : corps JSON ou
// protobuf selon le type de contenu de la requête, textes fixes en ASCII,
// en français sans accent (14.3).

import { champLen, champVarint } from "./decodage-protobuf.mjs";

/** Textes des refus (table d'EX-6.27). */
export const TEXTES = Object.freeze({
  400: "noortrace: corps OTLP non decodable",
  401: "noortrace: source OpenTelemetry non authentifiee",
  404: "noortrace: chemin inconnu",
  405: "noortrace: methode non admise",
  413: "noortrace: corps OTLP trop grand",
  415: "noortrace: type de contenu ou codage non admis",
  429: "noortrace: quota de la source atteint",
  503: "noortrace: enregistreur en mode degrade",
});

export const TYPE_JSON = "application/json";
export const TYPE_PROTOBUF = "application/x-protobuf";

/** Texte du succès partiel (EX-6.27). */
export function messageSuccesPartiel(n) {
  return `noortrace: ${n} span(s) rejete(s), identifiants invalides`;
}

/**
 * Corps d'une réponse `200` (EX-6.27) : `{}` ou vide sans rejet ;
 * `partialSuccess` avec n ≥ 1 spans rejetés.
 * @param {"json"|"protobuf"} encodage
 * @param {number} rejetes
 * @returns {Uint8Array}
 */
export function corpsSucces(encodage, rejetes) {
  if (encodage === "protobuf") {
    if (rejetes === 0) return new Uint8Array(0);
    const message = Buffer.from(messageSuccesPartiel(rejetes), "utf8");
    const partiel = [...champVarint(1, rejetes), ...champLen(2, [...message])];
    return new Uint8Array(champLen(1, partiel));
  }
  if (rejetes === 0) return new Uint8Array(Buffer.from("{}", "utf8"));
  return new Uint8Array(Buffer.from(`{"partialSuccess":{"rejectedSpans":"${rejetes}","errorMessage":${JSON.stringify(messageSuccesPartiel(rejetes))}}}`, "utf8"));
}

/**
 * Corps d'un refus (EX-6.27) : `{"message": …}` ou message `Status`
 * protobuf (champ 2, `code` omis).
 * @param {"json"|"protobuf"} encodage
 * @param {number} statut
 * @returns {Uint8Array}
 */
export function corpsRefus(encodage, statut) {
  const texte = TEXTES[statut];
  if (encodage === "protobuf") return new Uint8Array(champLen(2, [...Buffer.from(texte, "utf8")]));
  return new Uint8Array(Buffer.from(JSON.stringify({ message: texte }), "utf8"));
}
