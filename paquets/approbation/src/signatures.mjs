// Signatures des votes (CT-3 §9) : objet signé A et condensé D_A (CT-1 §6.3,
// fonctions du noyau), normalisation d'EX-9.3 contrôlée ici avant toute
// bibliothèque (EX-9.22), recouvrement de l'adresse ; vérification d'une
// remise par SG-1 à SG-7 (EX-9.11), que le service applique à ses propres
// remises avant de les livrer (une remise qu'un noyau conforme refuserait est
// un défaut du service, T16) et qui rejoue les vecteurs `decisions/`.
//
// Le service ne signe rien (EX-3.3) : aucune fonction de ce module ne prend
// de clé privée.

import {
  condenseApprobation, decoderHorodatage, estHex, hexVersOctets, octetsVersHex, recouvrerAdresseEip191,
} from "@noortrace/noyau";
import { IDS, registreSchemas } from "./schema.mjs";

/** Ordre du groupe de secp256k1. */
export const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const DEMI_N = N_SECP256K1 >> 1n;

const versEntier = (octets) => BigInt(octetsVersHex(octets));
const versOctets32 = (x) => hexVersOctets("0x" + x.toString(16).padStart(64, "0"), 32);

/**
 * Normalise une signature EIP-191 reçue d'une console (EX-9.3), sans clé :
 * 65 octets r ‖ s ‖ v ; r et s dans [1, n − 1] (sinon refus avant toute
 * normalisation) ; v ∈ {0, 1} devient v + 27 ; s haut devient n − s et v est
 * inversé ; tout autre v est refusé.
 * @param {unknown} hex signature en hexadécimal minuscule `0x…`
 * @returns {string|null} la forme canonique, ou null (`signature_invalide`)
 */
export function normaliserSignature(hex) {
  if (typeof hex !== "string" || !/^0x([0-9a-f]{2})*$/.test(hex) || !estHex(hex, 65)) return null;
  const o = hexVersOctets(hex, 65);
  const r = versEntier(o.subarray(0, 32));
  let s = versEntier(o.subarray(32, 64));
  let v = o[64];
  if (r < 1n || r >= N_SECP256K1 || s < 1n || s >= N_SECP256K1) return null;
  if (v === 0 || v === 1) v += 27;
  if (v !== 27 && v !== 28) return null;
  if (s > DEMI_N) {
    s = N_SECP256K1 - s;
    v = v === 27 ? 28 : 27;
  }
  const sortie = new Uint8Array(65);
  sortie.set(o.subarray(0, 32), 0);
  sortie.set(versOctets32(s), 32);
  sortie[64] = v;
  return octetsVersHex(sortie);
}

/**
 * Objet signé A d'un vote ou d'une décision (CT-1 §6.3).
 * @returns {{decision: string, journal_id: string, org_id: string, request_hash: string, ticket: string}}
 */
export function objetA({ decision, ticket, request_hash, org_id, journal_id }) {
  return { decision, journal_id, org_id, request_hash, ticket };
}

/** D_A = SHA-256(P_A ‖ JCS(A)), en hexadécimal (EX-12.14 : condensés servis à la console). */
export function condenseA(champs) {
  return octetsVersHex(condenseApprobation(objetA(champs)));
}

/**
 * Adresse que recouvre une signature canonique sur D_A, ou null.
 * @param {object} champs champs de A
 * @param {string} signature forme canonique (65 octets, s bas, v ∈ {27, 28})
 */
export function adresseDuVote(champs, signature) {
  if (!estHex(signature, 65)) return null;
  const { adresse } = recouvrerAdresseEip191(condenseApprobation(objetA(champs)), hexVersOctets(signature, 65));
  return adresse;
}

const MOTIF_SOURCE = /^(CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?|jeu statique de la politique .{1,128})$/u;

/**
 * Vérifie une remise par SG-1 à SG-7, dans l'ordre d'EX-9.11 (contexte de
 * `$defs/cas_remise` : événements `retenue` et décisions du journal, délai de
 * la version du ticket, séparation, instant d'écriture).
 * @param {unknown} remise
 * @param {{org_id: string, journal_id: string, retained: object[], decided: object[], expire_after_ms: number,
 *   separation: {self_approval: string, identities: {launched_by: string, addresses: string[]}[]}, write_at: string}} ctx
 * @returns {{result: "scelle"|"refuse", reason: string|null, check: string|null}}
 */
export function verifierRemise(remise, ctx) {
  const non = (check, reason) => ({ result: "refuse", reason, check });
  // SG-1
  if (!registreSchemas().estValide(`${IDS.ticket}#/$defs/remise`, remise)) return non("SG-1", "remise_mal_formee");
  const a = remise.approval;
  const k = remise.remise_id.lastIndexOf("/");
  if (a.ticket !== remise.ticket || remise.remise_id.slice(0, k) !== remise.ticket || !MOTIF_SOURCE.test(remise.approver_set.source)) {
    return non("SG-1", "remise_mal_formee");
  }
  // SG-2
  const retenues = ctx.retained.filter((e) => e.ticket === remise.ticket);
  if (retenues.length === 0) return non("SG-2", "ticket_inconnu");
  const retenue = retenues.find((e) => e.hash === a.request_hash);
  if (!retenue) return non("SG-2", "request_hash_different");
  // SG-3
  if (ctx.decided.some((d) => d.ticket === remise.ticket)) return non("SG-3", "ticket_deja_decide");
  // SG-4
  if (a.decision !== "expire" && !(decoderHorodatage(ctx.write_at) < decoderHorodatage(retenue.ts) + ctx.expire_after_ms)) {
    return non("SG-4", "echeance_depassee");
  }
  // SG-5 : E-5 et E-9 (le noyau ne normalise pas)
  if (a.approvers.length !== a.signatures.length) return non("SG-5", "signature_invalide");
  const champs = { decision: a.decision, ticket: a.ticket, request_hash: a.request_hash, org_id: ctx.org_id, journal_id: ctx.journal_id };
  for (let i = 0; i < a.signatures.length; i++) {
    if (adresseDuVote(champs, a.signatures[i]) !== a.approvers[i]) return non("SG-5", "signature_invalide");
  }
  // SG-6 : A-3
  const jeu = remise.approver_set;
  if (new Set(a.approvers).size !== a.approvers.length) return non("SG-6", "approbateur_double");
  if (!a.approvers.every((x) => jeu.members.includes(x))) return non("SG-6", "approbateur_hors_jeu");
  if (
    a.threshold.required !== jeu.threshold.required ||
    a.threshold.size !== jeu.threshold.size ||
    jeu.threshold.required > jeu.threshold.size ||
    jeu.threshold.size !== jeu.members.length
  ) {
    return non("SG-6", "seuil_different_du_jeu");
  }
  if (a.decision === "expire" && a.approvers.length > 0) return non("SG-6", "expire_avec_signatures");
  if (a.decision !== "expire" && a.approvers.length < a.threshold.required) return non("SG-6", "seuil_non_atteint");
  // SG-7
  if (ctx.separation.self_approval === "interdite") {
    const id = ctx.separation.identities.find((x) => x.launched_by === retenue.launched_by);
    if (id && a.approvers.some((x) => id.addresses.includes(x))) return non("SG-7", "auto_approbation");
  }
  return { result: "scelle", reason: null, check: null };
}
