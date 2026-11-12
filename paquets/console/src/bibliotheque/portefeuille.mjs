// Portefeuille EIP-1193 vu de la page (CT-3 EX-9.21, EX-13.23, EX-13.29,
// EX-13.30, EX-12.16) : code de la console d'une promesse rompue (codes
// EIP-1193 4001, 4100, 4200, 4900, 4901), vérification de la réponse à une
// requête `personal_sign` (forme contrôlée avant toute primitive, EX-9.22),
// comptes rendus par `eth_requestAccounts`, attente admise d'une signature et
// corps exact de la requête `voter`.

import { decoderInstant, instantParametre } from "./instants.mjs";
import { verifierSignature } from "./signatures.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

const CODES_EIP1193 = Object.freeze([
  [4001, "refus_approbateur"],
  [4100, "non_autorise"],
  [4200, "methode_non_prise_en_charge"],
  [4900, "deconnecte"],
  [4901, "chaine_deconnectee"],
]);

/**
 * Code de la console pour une promesse EIP-1193 rompue (13.14, EX-13.29) :
 * `refus_approbateur` (4001), `non_autorise` (4100),
 * `methode_non_prise_en_charge` (4200), `deconnecte` (4900),
 * `chaine_deconnectee` (4901), `erreur_portefeuille` dans tout autre cas
 * (autre code, code nul, erreur sans code ou d'une autre forme).
 * @param {{code: number|null, message: string}} erreur
 * @returns {string}
 */
export function codeErreurPortefeuille(erreur) {
  const code = estObjet(erreur) ? erreur.code : undefined;
  for (const [n, c] of CODES_EIP1193) if (code === n) return c;
  return "erreur_portefeuille";
}

/**
 * Issue d'une requête de signature (EX-9.21, points 1 à 7) : promesse rompue,
 * code de `codeErreurPortefeuille` ; tenue avec autre chose qu'une chaîne
 * `^0x[0-9a-fA-F]*$`, `reponse_invalide` ; sinon `verifierSignature` sur les
 * octets signés et l'adresse choisie.
 * @param {{result: unknown}|{error: {code: number|null, message: string}}} reponse `$defs/reponse_portefeuille`
 * @param {Uint8Array} octets 32 octets de `D_A`, ou octets du texte d'inscription
 * @param {string} adresse adresse choisie
 * @returns {{outcome: "accepte"|"refuse", reason: string|null, signature: string|null, recovered: string|null}}
 */
export function verifierReponse(reponse, octets, adresse) {
  if (!(octets instanceof Uint8Array)) throw new TypeError("verifierReponse : Uint8Array attendu");
  if (typeof adresse !== "string") throw new TypeError("verifierReponse : adresse attendue");
  if (estObjet(reponse) && Object.prototype.hasOwnProperty.call(reponse, "error")) {
    return { outcome: "refuse", reason: codeErreurPortefeuille(reponse.error), signature: null, recovered: null };
  }
  if (!estObjet(reponse) || !Object.prototype.hasOwnProperty.call(reponse, "result")) {
    throw new TypeError("verifierReponse : { result } ou { error } attendu");
  }
  const r = reponse.result;
  if (typeof r !== "string" || !/^0x[0-9a-fA-F]*$/.test(r)) return { outcome: "refuse", reason: "reponse_invalide", signature: null, recovered: null };
  const v = verifierSignature(octets, r, adresse);
  return { outcome: v.valide ? "accepte" : "refuse", reason: v.reason, signature: v.signature, recovered: v.recovered };
}

/**
 * Comptes rendus par `eth_requestAccounts` (EX-13.23) : un tableau de chaînes
 * `^0x[0-9a-fA-F]{40}$`, rendu en minuscules dans le même ordre ; `null` pour
 * tout autre résultat (`reponse_invalide`).
 * @param {unknown} resultat
 * @returns {string[]|null}
 */
export function analyserComptes(resultat) {
  if (!Array.isArray(resultat)) return null;
  if (!resultat.every((a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a))) return null;
  return resultat.map((a) => a.toLowerCase());
}

/**
 * Attente admise d'une réponse du portefeuille, en millisecondes (EX-13.30) :
 * `min(delai, deadline − maintenant)`, le délai seul sans échéance ; un rendu
 * `≤ 0` signifie `delai_depasse`.
 * @param {number} delaiSignatureMs
 * @param {string|null} deadline
 * @param {string} maintenant
 * @returns {number}
 */
export function echeanceAttente(delaiSignatureMs, deadline, maintenant) {
  if (!Number.isSafeInteger(delaiSignatureMs)) throw new TypeError("echeanceAttente : delai entier attendu");
  const t = instantParametre(maintenant, "echeanceAttente (maintenant)");
  if (deadline === null) return delaiSignatureMs;
  const d = decoderInstant(deadline);
  if (d === null) throw new TypeError("echeanceAttente : echeance instant ou null attendue");
  return Math.min(delaiSignatureMs, d - t);
}

/**
 * Corps exact de la requête `voter` (`$defs/requete_voter`, EX-9.21 point 8,
 * EX-12.16) : le ticket de la vue du ticket signé, l'adresse choisie en
 * minuscules, la décision, la signature normalisée, le motif et l'identité de
 * session.
 * @param {{ticket: string}} vue
 * @param {"approuve"|"refuse"} decision
 * @param {string} signature normalisée (`^0x[0-9a-f]{130}$`)
 * @param {string} adresse
 * @param {string|null} motif
 * @param {string} session
 * @returns {{ticket: string, approver: string, decision: string, signature: string, reason: string|null, session_identity: string}}
 */
export function requeteVoter(vue, decision, signature, adresse, motif, session) {
  if (!estObjet(vue) || typeof vue.ticket !== "string") throw new TypeError("requeteVoter : vue du ticket attendue");
  if (decision !== "approuve" && decision !== "refuse") throw new TypeError("requeteVoter : decision approuve ou refuse attendue");
  if (typeof signature !== "string" || !/^0x[0-9a-f]{130}$/.test(signature)) throw new TypeError("requeteVoter : signature normalisee attendue");
  if (typeof adresse !== "string" || !/^0x[0-9a-f]{40}$/.test(adresse.toLowerCase())) throw new TypeError("requeteVoter : adresse attendue");
  if (motif !== null && typeof motif !== "string") throw new TypeError("requeteVoter : motif chaine ou null attendu");
  if (typeof session !== "string") throw new TypeError("requeteVoter : identite de session attendue");
  return { ticket: vue.ticket, approver: adresse.toLowerCase(), decision, signature, reason: motif, session_identity: session };
}
