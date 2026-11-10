// Demandes de signature du registre (CT-4 §7.7, schéma
// `operations-registre-v0#/$defs/demande_signature`) : OP-6, le condensé de
// la demande recalculé depuis `fields`, `evm_chain_id` et `contract` selon
// RG-6 à RG-11 égale celui déclaré et `eip191_digest` égale le hachage signé
// de §6.6.3 ; OP-7, les signatures sont canoniques, recouvrent leur `signer`,
// sont distinctes et rangées par adresse croissante, membres du jeu et au
// seuil pour une opération au seuil, l'émetteur pour une ancre,
// l'administrateur pour une opération de jeu (RG-12, RG-13).
//
// Le composant d'ancrage ne relaie pas de demande de clôture lui-même (la
// présentation aux approbateurs relève de CT-2 et des outils de référence),
// mais il reçoit les signatures d'une clôture déjà signée : ce module lui
// permet de les contrôler avant `submitPeriod`, et rejoue la famille
// `demandes` des vecteurs de CT-4.

import {
  adminOpDigest, anchorDigest, hachageSigne, periodDigest, registerDigest, revokeDigestEnregistreur, verifierSignatureCondense,
} from "./encodage.mjs";
import { octetsVersHex } from "./octets.mjs";
import { verifierDemandeSchema } from "./schemas.mjs";

/** Condensé interne d'une demande selon son opération (RG-6 à RG-11), ou null si les champs sont hors de leur forme. */
export function condenseDemande(demande) {
  const f = demande.fields;
  try {
    switch (demande.operation) {
      case "inscription": return registerDigest(demande.evm_chain_id, demande.contract, f.org_id, f.journal_id, f.chain_key, f.ed25519_public_key);
      case "revocation": return revokeDigestEnregistreur(demande.evm_chain_id, demande.contract, f.org_id, f.chain_key, f.registered_at);
      case "cloture": return periodDigest(demande.evm_chain_id, demande.contract, f.period_meta);
      case "ancre": return anchorDigest(demande.evm_chain_id, demande.contract, f.fingerprint, f.doc_type);
      case "administration_jeu": return adminOpDigest(demande.evm_chain_id, demande.contract, f.op, f.arg, f.nonce);
      default: return null;
    }
  } catch {
    return null;
  }
}

/**
 * OP-6 et OP-7 sur une demande de signature. `membres` : adresses du jeu
 * (minuscules) quand il est connu, `administrateur` : adresse de
 * l'administrateur du jeu pour `administration_jeu`, `complete` : la
 * demande doit atteindre le seuil (`signer_set.threshold`).
 * Rend `{ resultat: "valide"|"refuse", check, code, digest, signers }`.
 */
export function verifierDemande(demande, { membres = null, administrateur = null, complete = true } = {}) {
  const refus = (check, code, extra = {}) => ({ resultat: "refuse", check, code, digest: null, signers: null, ...extra });
  const schema = verifierDemandeSchema(demande);
  if (!schema.valide) return refus("OP-6", "entree_illisible", { erreurs: schema.erreurs });
  const digest = condenseDemande(demande);
  if (digest === null || digest !== demande.digest) return refus("OP-6", "condense_different");
  if (octetsVersHex(hachageSigne(digest)) !== demande.eip191_digest) return refus("OP-6", "condense_different");
  // OP-7 : chaque signature canonique et recouvrant son signataire.
  const signers = [];
  for (const s of demande.signatures) {
    const r = verifierSignatureCondense(digest, s);
    if (r.statut !== "reussi") return refus("OP-7", r.motif === "signataire_different" ? "signataire_hors_jeu" : "signature_non_canonique");
    signers.push(r.recovered);
  }
  if (new Set(signers).size !== signers.length) return refus("OP-7", "signature_non_canonique");
  for (let k = 1; k < signers.length; k++) if (!(signers[k - 1] < signers[k])) return refus("OP-7", "signature_non_canonique");
  if (demande.operation === "ancre") {
    if (signers.length !== 1 || signers[0] !== demande.fields.issuer) return refus("OP-7", "signataire_hors_jeu");
  } else if (demande.operation === "administration_jeu") {
    if (signers.length !== 1 || (administrateur !== null && signers[0] !== administrateur)) return refus("OP-7", "signataire_hors_jeu");
  } else {
    if (membres) for (const a of signers) if (!membres.includes(a)) return refus("OP-7", "signataire_hors_jeu");
    const seuil = demande.signer_set?.threshold ?? null;
    if (complete && seuil !== null && signers.length < seuil) return refus("OP-7", "signatures_insuffisantes");
  }
  return { resultat: "valide", check: null, code: null, digest, signers };
}
