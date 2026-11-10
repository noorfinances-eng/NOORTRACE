// Transaction de type 2 (EIP-1559, enveloppe EIP-2718) telle que CT-4 §6.7.3
// et RG-15 (EX-6.18) la fixent : sérialisation `0x02 ‖ RLP([chainId, nonce,
// maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList,
// yParity, r, s])`, hachage à signer `keccak256(0x02 ‖ RLP(neuf premiers
// champs))`, signature secp256k1 canonique (`yParity` ∈ {0, 1}, `s` bas),
// hachage de la transaction `keccak256` de sa sérialisation.
//
// `verifierRG15` relit des octets signés et applique les motifs de RG-15 dans
// l'ordre de la table de CT-4 §6.9 : `transaction_illisible`,
// `type_non_admis`, `chaine_differente`, `frais_non_conformes`,
// `limite_gaz`, `liste_acces`, `signature_non_canonique`,
// `objet_non_conforme`. Les frais d'un remplacement au même nonce valent
// `⌈1,1 × p⌉` (EX-4.15, EX-8.16).

import { keccak256 } from "@noortrace/noyau";
import { adresseDepuisClePublique, lireSignature, recouvrerSignataire } from "./cle-chaine.mjs";
import {
  ErreurRlp, concatener, decoderRlp, entierRlp, entierVersOctetsMinimaux, estHexOctets, estOctets, hexVersOctets,
  octetsVersEntier, octetsVersHex, rlp, versEntier, MAX_U64, MAX_U256,
} from "./octets.mjs";
import { secp256k1 } from "@noble/curves/secp256k1.js";

/** Plafond de la limite de gaz qu'un nœud exécute (CT-4 EX-4.17, R1-F32). */
export const LIMITE_GAZ_MAX = 16777216n;
/** Frais nominaux : 1 wei (CT-4 EX-4.15). */
export const FRAIS_NOMINAUX = 1n;

/** `⌈1,1 × p⌉`, frais d'un remplacement au même nonce (CT-4 EX-4.15). */
export function fraisRemplacement(p) {
  const x = typeof p === "bigint" ? p : versEntier(p);
  if (x === null || x < 1n) throw new TypeError("frais remplacés : entier positif attendu");
  return (11n * x + 9n) / 10n;
}

function lireAdresse(v) {
  if (v === null || v === undefined) return null;
  if (estHexOctets(v, 20)) return v;
  throw new TypeError("destinataire : adresse de 20 octets ou null attendue");
}

function lireDonnees(v) {
  if (v === undefined || v === null || v === "0x") return new Uint8Array(0);
  if (estOctets(v)) return Uint8Array.from(v);
  if (typeof v === "string" && /^0x([0-9a-f]{2})*$/.test(v)) return hexVersOctets(v);
  throw new TypeError("données : hexadécimal préfixé attendu");
}

function lireEntier(nom, v, max = MAX_U256) {
  const x = versEntier(v);
  if (x === null || x > max) throw new TypeError(`${nom} : entier non négatif attendu`);
  return x;
}

/**
 * Construit une transaction de type 2 non signée depuis ses champs (clés de
 * `#/$defs/envoi` et du vecteur `transactions.json` : `chain_id`, `nonce`,
 * `max_priority_fee_per_gas`, `max_fee_per_gas`, `gas_limit`, `to`, `value`,
 * `data`). Rend les champs normalisés (`bigint`, octets), la charge à signer
 * et son hachage.
 */
export function construireTransaction(champs) {
  if (!champs || typeof champs !== "object") throw new TypeError("champs de transaction attendus");
  const tx = {
    chainId: lireEntier("chain_id", champs.chain_id ?? champs.chainId, MAX_U64),
    nonce: lireEntier("nonce", champs.nonce, MAX_U64),
    maxPriorityFeePerGas: lireEntier("max_priority_fee_per_gas", champs.max_priority_fee_per_gas ?? champs.maxPriorityFeePerGas),
    maxFeePerGas: lireEntier("max_fee_per_gas", champs.max_fee_per_gas ?? champs.maxFeePerGas),
    gasLimit: lireEntier("gas_limit", champs.gas_limit ?? champs.gasLimit, MAX_U64),
    to: lireAdresse(champs.to),
    value: lireEntier("value", champs.value ?? 0n),
    data: lireDonnees(champs.data),
    accessList: [],
  };
  const chargeASigner = chargeASignerDe(tx);
  return { ...tx, chargeASigner, hachageASigner: keccak256(chargeASigner) };
}

function champsRlp(tx) {
  return [
    tx.chainId, tx.nonce, tx.maxPriorityFeePerGas, tx.maxFeePerGas, tx.gasLimit,
    tx.to === null ? new Uint8Array(0) : hexVersOctets(tx.to), tx.value, tx.data, [],
  ];
}

/** `0x02 ‖ RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`. */
export function chargeASignerDe(tx) {
  return concatener(Uint8Array.of(0x02), rlp(champsRlp(tx)));
}

/** Sérialisation signée `0x02 ‖ RLP([… , yParity, r, s])` et son hachage. */
export function serialiserTransaction(tx, { yParity, r, s }) {
  const raw = concatener(Uint8Array.of(0x02), rlp([...champsRlp(tx), BigInt(yParity), r, s]));
  return { raw, hash: keccak256(raw) };
}

/**
 * Signe une transaction construite par `construireTransaction` avec un
 * `SignataireChaine` ; rend `{ raw_transaction, transaction_hash,
 * signing_payload, signing_hash, y_parity, r, s, from }` (hexadécimaux) et
 * les octets.
 */
export async function signerTransaction(tx, signataire) {
  const sig = await signataire.signerCondense(tx.hachageASigner);
  const lue = lireSignature(sig);
  if (!lue) throw new Error("signature de la clé de chaîne non canonique");
  const { raw, hash } = serialiserTransaction(tx, { yParity: lue.rec, r: lue.r, s: lue.s });
  const from = recouvrerSignataire(tx.hachageASigner, sig);
  if (from !== signataire.adresse()) throw new Error("la signature ne recouvre pas l'adresse du signataire");
  return {
    signing_payload: octetsVersHex(tx.chargeASigner),
    signing_hash: octetsVersHex(tx.hachageASigner),
    y_parity: lue.rec,
    r: octetsVersHex(hexVersOctets(sig.r)),
    s: octetsVersHex(hexVersOctets(sig.s)),
    raw_transaction: octetsVersHex(raw),
    transaction_hash: octetsVersHex(hash),
    from,
    octets: raw,
  };
}

/** Erreur de relecture d'une transaction, avec le motif RG-15. */
export class ErreurTransaction extends Error {
  constructor(motif, message) {
    super(message);
    this.name = "ErreurTransaction";
    this.motif = motif;
  }
}

function entierChamp(nom, v, max = MAX_U256) {
  const x = entierRlp(v, max);
  if (x === null) throw new ErreurTransaction("transaction_illisible", `${nom} : entier RLP non minimal ou hors borne`);
  return x;
}

/**
 * Relit une transaction sérialisée (octets ou hexadécimal). Type 2 seul
 * admis : une enveloppe d'un autre type ou une transaction non typée (type
 * 0) rend `type_non_admis` ; une forme RLP non canonique ou tronquée,
 * `transaction_illisible`. Rend les champs, la signature et l'expéditeur
 * recouvré (null si la signature n'est pas canonique).
 * @throws {ErreurTransaction}
 */
export function lireTransaction(source) {
  const octets = estOctets(source) ? source : (typeof source === "string" && /^0x([0-9a-f]{2})*$/.test(source) ? hexVersOctets(source) : null);
  if (!octets || octets.length === 0) throw new ErreurTransaction("transaction_illisible", "octets de transaction attendus");
  if (octets[0] >= 0xc0) throw new ErreurTransaction("type_non_admis", "transaction non typée (type 0)");
  if (octets[0] !== 0x02) throw new ErreurTransaction("type_non_admis", `type d'enveloppe ${octets[0]} non admis`);
  let liste;
  try {
    liste = decoderRlp(octets.subarray(1));
  } catch (e) {
    throw new ErreurTransaction("transaction_illisible", e instanceof ErreurRlp ? e.message : "RLP illisible");
  }
  if (!Array.isArray(liste) || liste.length !== 12) throw new ErreurTransaction("transaction_illisible", "douze champs attendus");
  const [chainId, nonce, prio, max, gas, to, value, data, accessList, yParity, r, s] = liste;
  if (!estOctets(to) || (to.length !== 0 && to.length !== 20)) throw new ErreurTransaction("transaction_illisible", "destinataire de 0 ou 20 octets attendu");
  if (!estOctets(data)) throw new ErreurTransaction("transaction_illisible", "données : chaîne RLP attendue");
  if (!Array.isArray(accessList)) throw new ErreurTransaction("transaction_illisible", "liste d'accès : liste RLP attendue");
  if (!estOctets(r) || !estOctets(s) || r.length > 32 || s.length > 32) throw new ErreurTransaction("transaction_illisible", "r, s : chaînes RLP attendues");
  const tx = {
    chainId: entierChamp("chainId", chainId, MAX_U64),
    nonce: entierChamp("nonce", nonce, MAX_U64),
    maxPriorityFeePerGas: entierChamp("maxPriorityFeePerGas", prio),
    maxFeePerGas: entierChamp("maxFeePerGas", max),
    gasLimit: entierChamp("gasLimit", gas, MAX_U64),
    to: to.length === 0 ? null : octetsVersHex(to),
    value: entierChamp("value", value),
    data: Uint8Array.from(data),
    accessList,
  };
  const parite = entierChamp("yParity", yParity, 1n);
  const rr = entierChamp("r", r);
  const ss = entierChamp("s", s);
  const chargeASigner = chargeASignerDe(tx);
  const hachageASigner = keccak256(chargeASigner);
  const signature = { yParity: Number(parite), r: "0x" + rr.toString(16).padStart(64, "0"), s: "0x" + ss.toString(16).padStart(64, "0") };
  const from = recouvrerSignataire(hachageASigner, signature, { yParity: true });
  return {
    ...tx, chargeASigner, hachageASigner, signature, from,
    raw: Uint8Array.from(octets), hash: keccak256(octets),
  };
}

/**
 * RG-15 (CT-4 EX-6.18). `contexte` : `{ evm_chain_id, fees: { gas_limit,
 * gas_limit_max }, objet: "appel"|"deploiement"|"approvisionnement", to,
 * data, provision, remplace }` (`remplace` : frais `p` de la transaction
 * remplacée ; `data` et `to` facultatifs pour un appel : quand ils sont
 * donnés, ils sont comparés).
 * @returns {{statut: "reussi"|"echoue", motif: string|null, transaction: object|null}}
 */
export function verifierRG15(source, contexte) {
  const echec = (motif, transaction = null) => ({ statut: "echoue", motif, transaction });
  let tx;
  try {
    tx = lireTransaction(source);
  } catch (e) {
    if (e instanceof ErreurTransaction) return echec(e.motif);
    throw e;
  }
  const ctx = contexte ?? {};
  const evm = versEntier(ctx.evm_chain_id);
  if (evm === null || tx.chainId !== evm) return echec("chaine_differente", tx);
  const attendu = ctx.remplace !== undefined && ctx.remplace !== null ? fraisRemplacement(ctx.remplace) : FRAIS_NOMINAUX;
  if (tx.maxFeePerGas !== tx.maxPriorityFeePerGas || tx.maxFeePerGas !== attendu) return echec("frais_non_conformes", tx);
  const limite = versEntier(ctx.fees?.gas_limit);
  const plafond = versEntier(ctx.fees?.gas_limit_max) ?? LIMITE_GAZ_MAX;
  if (limite === null || tx.gasLimit !== limite || tx.gasLimit > LIMITE_GAZ_MAX || tx.gasLimit > plafond) return echec("limite_gaz", tx);
  if (tx.accessList.length !== 0) return echec("liste_acces", tx);
  if (tx.from === null) return echec("signature_non_canonique", tx);
  const dataHex = octetsVersHex(tx.data);
  if (ctx.objet === "appel") {
    if (tx.to === null || (ctx.to !== undefined && tx.to !== ctx.to) || tx.value !== 0n) return echec("objet_non_conforme", tx);
    if (ctx.data !== undefined && ctx.data !== null && dataHex !== ctx.data) return echec("objet_non_conforme", tx);
    if (tx.data.length < 4) return echec("objet_non_conforme", tx);
  } else if (ctx.objet === "deploiement") {
    if (tx.to !== null || tx.value !== 0n || tx.data.length === 0) return echec("objet_non_conforme", tx);
    if (ctx.data !== undefined && ctx.data !== null && dataHex !== ctx.data) return echec("objet_non_conforme", tx);
  } else if (ctx.objet === "approvisionnement") {
    const provision = versEntier(ctx.provision);
    if (tx.to === null || (ctx.to !== undefined && tx.to !== ctx.to) || tx.data.length !== 0) return echec("objet_non_conforme", tx);
    if (provision === null || tx.value > provision) return echec("objet_non_conforme", tx);
  } else {
    return echec("objet_non_conforme", tx);
  }
  return { statut: "reussi", motif: null, transaction: tx };
}

/** Adresse `CREATE(a, nonce)` : 20 derniers octets de `keccak256(RLP([a20(a), nonce]))` (CT-4 §6.7.3). */
export function adresseCreation(deployeur, nonce) {
  const n = versEntier(nonce);
  if (!estHexOctets(deployeur, 20) || n === null) throw new TypeError("déployeur et nonce attendus");
  return octetsVersHex(keccak256(rlp([hexVersOctets(deployeur), n])).subarray(12));
}

/** Clé publique non compressée d'une clé privée (tests, fixtures). */
export function clePubliqueDe(clePrivee) {
  return secp256k1.getPublicKey(clePrivee, false);
}

export { adresseDepuisClePublique, entierVersOctetsMinimaux, octetsVersEntier };
