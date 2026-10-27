// L'attestation de périmètre des vecteurs (CT-7 §7.1 et §7.2) et ce qu'il faut
// pour la signer, la joindre et l'inscrire, partagés par les générateurs des
// familles ct-1, ct-6 et ct-7 (CT-7 annexe A.1, A.6, A.7).
//
// Tout est dérivé d'étiquettes publiques : comptes Hardhat 1 à 4 du mnémonique
// de test public (chemin m/44'/60'/0'/0/i, clés sans valeur), organisation et
// journaux des vecteurs de CT-1 (keccak256 du slug et des noms), empreinte des
// règles de sortie = SHA-256 de l'étiquette « export fictif des règles de
// sortie du pare-feu, vecteurs CT-7 ». Les noms d'hôtes, de routes et de
// fichiers sont fictifs.

import { HDNodeWallet, keccak256, toUtf8Bytes } from "ethers";
import * as J from "../../lib/journal.mjs";
import * as S from "../../lib/securite.mjs";

export const MNEMONIQUE_HARDHAT = "test test test test test test test test test test test junk";
export const CHEMIN_HARDHAT = (i) => `m/44'/60'/0'/0/${i}`;
/** Comptes Hardhat 1 à 4 (indice = numéro du compte). */
export const COMPTES = Object.fromEntries([1, 2, 3, 4].map((i) => [i, HDNodeWallet.fromPhrase(MNEMONIQUE_HARDHAT, undefined, CHEMIN_HARDHAT(i))]));
export const adresse = (i) => COMPTES[i].address.toLowerCase();

export const ORG_SLUG = "assureur-demo";
export const ORG_ID = keccak256(toUtf8Bytes(ORG_SLUG));
export const JOURNAL_PRINCIPAL = keccak256(toUtf8Bytes("journal-principal"));
export const JOURNAL_SINISTRES = keccak256(toUtf8Bytes("journal-sinistres"));
export const ETIQUETTE_REGLES_SORTIE = "export fictif des règles de sortie du pare-feu, vecteurs CT-7";
export const RULES_SHA256 = J.sha256(Buffer.from(ETIQUETTE_REGLES_SORTIE, "utf8"));
export const SOURCE_JEU = "comptes Hardhat 1 à 3 (vecteurs CT-1)";

/** L'attestation P de l'exemple de CT-7 §7.1 (nouvel objet à chaque appel). */
export function attestationExemple() {
  return {
    version: 0,
    org: { org_id: ORG_ID, slug: ORG_SLUG, name: "Assureur démo SA" },
    journals: [
      { journal_id: JOURNAL_PRINCIPAL, name: "journal-principal" },
      { journal_id: JOURNAL_SINISTRES, name: "journal-sinistres" },
    ],
    validity: { from: "2026-11-01T00:00:00.000Z", until: "2027-01-31T23:59:59.999Z" },
    issued_at: "2026-10-30T16:00:00.000Z",
    prepared_by: { identity: "oidc https://idp.assureur-demo.example admin-agents", function: "administrateur de la plate-forme d'agents" },
    agents: [
      { agent_id: "agent-sinistres", journal_id: JOURNAL_SINISTRES, host: "hote-agents-01", framework: "service Python, SDK NOORTRACE 0.1", capture_channels: ["mandataire_mcp", "passerelle"], notes: null },
      { agent_id: "agent-principal", journal_id: JOURNAL_PRINCIPAL, host: "hote-agents-02", framework: "hôte MCP de bureau", capture_channels: ["mandataire_mcp", "icap"], notes: "requêtes de modèle vues par le mandataire HTTPS de l'organisation" },
    ],
    tools_via_proxy_only: [
      { server_alias: "sap", tools: ["*"], enforcement: "seul l'hôte de l'enregistreur joint le serveur d'outils SAP (règle de sortie 12)" },
      { server_alias: "crm", tools: ["claims.get"], enforcement: "jeton du serveur CRM détenu par l'enregistreur seul (règle de sortie 13)" },
    ],
    egress: {
      default_policy: "refus_par_defaut",
      rules_sha256: RULES_SHA256,
      rules_format: "export texte du pare-feu",
      summary: "Refus par défaut. Les hôtes d'agents ne joignent que l'enregistreur ; seul l'hôte de l'enregistreur joint les fournisseurs de modèle et les serveurs d'outils ; les refus sont journalisés au pare-feu.",
      allowed_destinations: [
        { name: "fournisseurs de modèle", via: "enregistreur", description: "route /v1/messages de la passerelle" },
        { name: "serveurs d'outils SAP et CRM", via: "enregistreur", description: "frontal MCP de l'enregistreur" },
        { name: "relais de messagerie interne", via: "direct", description: "envoi de courriels hors capture, déclaré dans not_captured" },
      ],
    },
    gateway_credentials: [{ route: "/v1/messages", provider_label: "fournisseur", secret_ref: { file: "/run/secrets/cle-fournisseur" } }],
    not_captured: [
      { channel: "relais de messagerie interne", description: "Un courriel envoyé par le relais SMTP sans passer par l'outil mail.send n'est pas journalisé par l'enregistreur.", compensating_control: "journal du relais SMTP conservé un an" },
    ],
    signatories: [
      { name: "Approbateur 1", function: "responsable des sinistres", address: adresse(1) },
      { name: "Approbateur 2", function: "responsable de la conformité", address: adresse(2) },
    ],
    declaration: "Nous déclarons qu'à notre connaissance, pendant la période de validité, les agents de l'inventaire n'atteignent leurs outils et leurs modèles que par les canaux de capture indiqués, sous les règles de sortie dont l'empreinte est donnée, sauf les cas déclarés non capturés.",
  };
}

/** Le jeu des vecteurs : comptes 1 à 3, seuil de 2 sur 3 (même jeu que approbations.json des vecteurs de CT-1). */
export function jeuExemple() {
  return { threshold: { required: 2, size: 3 }, members: [adresse(1), adresse(2), adresse(3)], source: SOURCE_JEU };
}

/** Signature EIP-191 de D_P par le compte `i`, { address, signature }. */
export const signature = (P, i) => ({ address: adresse(i), signature: S.signerAttestation(COMPTES[i], P) });

/** Attestation signée par les comptes `comptes` (dans cet ordre). */
export const signer = (P, comptes = [1, 2]) => S.assemblerAttestation(P, comptes.map((i) => signature(P, i)));

/** Document de politique réduit des vecteurs (CT-7 §7.5) : JCS intégral de { perimeter: { attestation_digest }, version }. */
export function documentPolitique(attestation_digest, version = "2026-11-05") {
  return Buffer.from(J.canonicaliserJCSIntegral({ perimeter: { attestation_digest }, version }), "utf8");
}

/** Signature de forme non canonique : s remplacé par n − s, v basculé. */
export function formeHaute(sig) {
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt("0x" + sig.slice(66, 130));
  return sig.slice(0, 66) + (N - s).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
}

/**
 * Les cas hors dossier de CT-7 annexe A.6 (table d'EX-A.8), dans l'ordre :
 * [{ name, description, signed (objet, ou texte JSON pour un cas que
 * l'analyseur strict refuse), approver_set }]. Chaque cas invalide ne change
 * qu'un élément de l'exemple.
 */
export function casAttestations() {
  const P = attestationExemple();
  const JEU = jeuExemple();
  const base = signer(P);
  const avecP = (modif, comptes = [1, 2]) => {
    const p = attestationExemple();
    modif(p);
    return signer(p, comptes);
  };
  const c = (name, description, signed, approver_set = JEU) => ({ name, description, signed, approver_set });
  const sub = structuredClone(base);
  sub.signatures[1].signature = signature(P, 3).signature;
  const haut = structuredClone(base);
  haut.signatures[1].signature = formeHaute(haut.signatures[1].signature);
  const v0 = structuredClone(base);
  v0.signatures[1].signature = v0.signatures[1].signature.slice(0, 130) + "00";
  const double = structuredClone(base);
  double.signatures[1] = { ...double.signatures[0] };
  return [
    c("valide-deux-signatures", "Attestation de l'exemple de CT-7, signée par les comptes Hardhat 1 et 2, seuil de 2 sur 3 : retenue.", base),
    c("valide-trois-signatures", "Le compte 3, ajouté aux signataires nommés, signe aussi : trois signataires du jeu, retenue.", avecP((p) => p.signatories.push({ name: "Approbateur 3", function: "directeur financier", address: adresse(3) }), [1, 2, 3])),
    c("valide-seuil-un", "Jeu au seuil de 1 sur 3, une seule signature (compte 1) : retenue.", signer(P, [1]), { ...JEU, threshold: { required: 1, size: 3 } }),
    c("invalide-at1-membre-en-trop", "Un membre inconnu (extra) dans l'attestation : le schéma la refuse, AT-1 échoue.", { ...base, attestation: { ...P, extra: true } }),
    c("invalide-at1-validite-inversee", "validity.from postérieur à validity.until : AT-1 échoue.", avecP((p) => (p.validity = { from: "2027-01-31T23:59:59.999Z", until: "2026-11-01T00:00:00.000Z" }))),
    c("invalide-at1-validite-trop-longue", "Validité du 2026-11-01 au 2027-11-02, plus de 366 jours : AT-1 échoue (CT-7 EX-7.2).", avecP((p) => (p.validity.until = "2027-11-02T00:00:00.001Z"))),
    c("invalide-at1-date-inexistante", "validity.until vaut 2027-02-30T00:00:00.000Z, date hors du calendrier : AT-1 échoue.", avecP((p) => (p.validity.until = "2027-02-30T00:00:00.000Z"))),
    c("invalide-at1-agent-journal-inconnu", "Le journal_id d'un agent est absent de journals : AT-1 échoue.", avecP((p) => (p.agents[0].journal_id = "0x" + "ab".repeat(32)))),
    c("invalide-at1-signataires-en-double", "Deux entrées de signatories ont la même adresse : AT-1 échoue.", avecP((p) => p.signatories.push({ ...p.signatories[0], name: "Approbateur 1 bis" }))),
    c("invalide-at1-nombre-non-entier", "Le texte JSON de l'attestation signée écrit version 0.0 : l'analyse stricte le refuse, AT-1 échoue.", J.texteJSON(base).replace('"version": 0,\n  "attestation"', '"version": 0.0,\n  "attestation"')),
    c("invalide-at2-condense-faux", "digest est celui d'une autre attestation (issued_at différent) : AT-2 échoue.", { ...base, digest: avecP((p) => (p.issued_at = "2026-10-31T16:00:00.000Z")).digest }),
    c("invalide-at3-signature-substituee", "La signature du compte Hardhat 3 est attribuée au compte 2 : l'adresse recouvrée diffère de l'adresse déclarée, AT-3 échoue et AT-4 n'est pas exécutée.", sub),
    c("invalide-at3-s-haut", "Signature du compte 2 en forme non canonique (s haut, v complémenté) : refusée avant tout recouvrement, AT-3 échoue.", haut),
    c("invalide-at3-v-hors-domaine", "Signature du compte 2 dont v vaut 0x00 : AT-3 échoue.", v0),
    c("invalide-at4-seuil-non-atteint", "Une seule signature (compte 1) pour un seuil de 2 : AT-4 échoue.", signer(P, [1])),
    c("invalide-at4-non-membre", "Signature valide du compte 4, nommé dans signatories, absent du jeu déclaré : AT-4 échoue.", avecP((p) => p.signatories.push({ name: "Approbateur 4", function: "auditeur interne", address: adresse(4) }), [1, 4])),
    c("invalide-at4-hors-signataires", "Signature valide du compte 3, membre du jeu, absent de signatories : AT-4 échoue.", signer(P, [1, 3])),
    c("invalide-at4-adresse-en-double", "La même signature (compte 1) deux fois : AT-4 échoue.", double),
    c("invalide-at4-seuil-incoherent", "Jeu déclaré au seuil de 4 pour 3 membres : AT-4 échoue.", base, { ...JEU, threshold: { required: 4, size: 3 } }),
  ];
}
