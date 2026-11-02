// Messages JSON-RPC que le frontal MCP écrit lui-même (CT-2 §4) : erreurs
// de l'enregistreur (table de 4.4, EX-4.24), erreurs JSON-RPC standard,
// résultats rendus par l'enregistreur (refus par la politique et signal
// d'approbation, EX-4.49), identité `serverInfo` (EX-4.4). Les textes sont
// fixes, ASCII, sans donnée du client (EX-14.5) ; l'`id` de l'hôte est
// recopié depuis le texte reçu (4.4 pas 14).

import { VERSION_ENREGISTREUR } from "../coeur.mjs";

/** Révision moderne et révisions héritées acceptées côté hôte (EX-4.3). */
export const VERSION_MODERNE = "2026-07-28";
export const VERSIONS_HERITEES = Object.freeze(["2025-11-25", "2025-06-18", "2025-03-26"]);
export const VERSIONS_SUPPORTEES = Object.freeze([VERSION_MODERNE, ...VERSIONS_HERITEES]);

/** Identité de l'enregistreur (EX-4.4, EX-4.7). */
export const IDENTITE = Object.freeze({ name: "noortrace-enregistreur", version: VERSION_ENREGISTREUR });
export const IDENTITE_TEXTE = JSON.stringify(IDENTITE);

/** Codes de l'enregistreur (table de 4.4) et leurs messages fixes. */
export const CODES = Object.freeze({
  BLOQUE: -31010,
  DELAI: -31011,
  ANNULE: -31012,
  TAILLE: -31013,
  INJOIGNABLE: -31014,
  NON_RELAYABLE: -31016,
  NON_DURABLE: -31017,
});

export const MESSAGES = Object.freeze({
  [-31010]: "noortrace: appel bloque, enregistreur en mode degrade",
  [-31011]: "noortrace: delai du serveur d'outils depasse",
  [-31012]: "noortrace: appel annule par l'hote",
  [-31013]: "noortrace: taille maximale depassee",
  [-31014]: "noortrace: serveur d'outils injoignable",
  [-31016]: "noortrace: resultat ou requete non relayable par la configuration",
  [-31017]: "noortrace: appel execute, evenement non durable",
  [-32700]: "Parse error",
  [-32600]: "Invalid Request",
  [-32601]: "Method not found",
  [-32602]: "Invalid params",
  [-32603]: "Internal error",
  [-32020]: "Header mismatch",
  [-32022]: "Unsupported protocol version",
});

/** Codes que l'enregistreur peut émettre lui-même (EX-4.24). */
export const CODES_ADMIS = Object.freeze([
  -31010, -31011, -31012, -31013, -31014, -31016, -31017, -32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022,
]);

/** Texte du refus par la politique (EX-4.49, CT-3 EX-11.8). */
export const TEXTE_REFUS = "noortrace: appel refuse par la politique";

/**
 * Objet `error` d'une erreur rendue par l'enregistreur, en texte JSON.
 * @param {number} code
 * @param {object|undefined} [data]
 * @param {string} [message] message d'un code standard (défaut : celui de la table)
 * @returns {string}
 */
export function objetErreur(code, data, message) {
  if (!CODES_ADMIS.includes(code)) throw new RangeError(`code non admis par EX-4.24 : ${code}`);
  const m = message ?? MESSAGES[code];
  return `{"code":${code},"message":${JSON.stringify(m)}${data === undefined ? "" : `,"data":${JSON.stringify(data)}`}}`;
}

/**
 * Ligne de réponse d'erreur : `{"jsonrpc":"2.0","id":<id>,"error":…}`.
 * @param {string|null} idBrut texte de l'`id` reçu, ou null
 * @param {string} erreurTexte texte JSON de l'objet `error`
 * @returns {string}
 */
export function reponseErreurTexte(idBrut, erreurTexte) {
  return `{"jsonrpc":"2.0","id":${idBrut ?? "null"},"error":${erreurTexte}}`;
}

/**
 * Ligne de réponse d'erreur de l'enregistreur.
 * @param {string|null} idBrut
 * @param {number} code
 * @param {object} [data]
 * @param {string} [message]
 * @returns {string}
 */
export function reponseErreur(idBrut, code, data, message) {
  return reponseErreurTexte(idBrut, objetErreur(code, data, message));
}

/**
 * Ligne de réponse `result` (texte JSON déjà compacté).
 * @param {string} idBrut
 * @param {string} resultatTexte
 * @returns {string}
 */
export function reponseResultat(idBrut, resultatTexte) {
  return `{"jsonrpc":"2.0","id":${idBrut},"result":${resultatTexte}}`;
}

/**
 * Résultat rendu par l'enregistreur (EX-4.49) : refus par la politique
 * (sans `approval`) ou signal d'approbation (`{ ticket, state }`), membres
 * dans l'ordre des exemples ; `resultType` pour un hôte moderne seulement.
 * @param {{moderne: boolean, approbation?: {ticket: string, state: "en_attente"|"refuse"|"expire"}|null}} o
 * @returns {string}
 */
export function resultatEnregistreur(o) {
  const a = o.approbation ?? null;
  const texte = a ? `noortrace: appel soumis a approbation ; ticket=${a.ticket} ; state=${a.state}` : TEXTE_REFUS;
  const meta = a
    ? `{"io.modelcontextprotocol/serverInfo":${IDENTITE_TEXTE},"noortrace/approval":${JSON.stringify({ ticket: a.ticket, state: a.state })}}`
    : `{"io.modelcontextprotocol/serverInfo":${IDENTITE_TEXTE}}`;
  return `{${o.moderne ? '"resultType":"complete",' : ""}"content":[{"type":"text","text":${JSON.stringify(texte)}}],"isError":true,"_meta":${meta}}`;
}

/**
 * Ligne de notification JSON-RPC.
 * @param {string} methode
 * @param {string|null} paramsTexte
 * @returns {string}
 */
export function notification(methode, paramsTexte) {
  return `{"jsonrpc":"2.0","method":${JSON.stringify(methode)}${paramsTexte === null ? "" : `,"params":${paramsTexte}`}}`;
}

/**
 * Ligne de requête JSON-RPC.
 * @param {string} id identifiant amont (`e-…`)
 * @param {string} methode
 * @param {string|null} paramsTexte
 * @returns {string}
 */
export function requete(id, methode, paramsTexte) {
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":${JSON.stringify(methode)}${paramsTexte === null ? "" : `,"params":${paramsTexte}`}}`;
}

/**
 * Pièce « résultat » d'une issue sans réponse (EX-4.48) : la forme
 * `noortrace_jsonrpc_error` du code rendu ; et l'objet `error` correspondant.
 * @param {number} code
 * @param {object} [data]
 * @returns {{code: number, message: string, data?: object}}
 */
export function erreurIssue(code, data) {
  return data === undefined ? { code, message: MESSAGES[code] } : { code, message: MESSAGES[code], data };
}
