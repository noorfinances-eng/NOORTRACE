// Recalculs de CT-6 §11.3 que la capture (CP-2 à CP-4) et l'export exigent :
// hachage BFT d'un bloc (EX-11.4), racine du trie Merkle-Patricia des reçus
// (EX-11.5 : RLP, bloom, encodage de consensus d'un reçu, trie) et racine des
// transactions brutes du bloc (CT-4 RG-19, même trie, valeur de rang `i` =
// encodage binaire de la transaction `i`).
//
// Le trie est construit sans récursion profonde non bornée : la profondeur
// est celle des clés en quartets (RLP(i) fait au plus 3 octets pour 256
// reçus), et chaque appel ne descend que d'un quartet.

import { keccak256, utf8 } from "@noortrace/noyau";
import { concatener, estHexOctets, hexVersOctets, quantiteVersEntier, rlp, rlpEntier, u64, u256, MAX_U64, MAX_U256 } from "./octets.mjs";

/** Préfixe de domaine du hachage BFT d'un bloc. */
export const DOMAINE_BLOC_BFT = "noor/v1/bftblockhash";

/** Les dix champs de l'en-tête que la préimage engage (CT-6 §11.2.1, EX-11.4). */
export const CHAMPS_ENTETE = Object.freeze([
  "number", "hash", "parentHash", "timestamp", "stateRoot", "transactionsRoot", "receiptsRoot", "gasUsed", "gasLimit", "baseFeePerGas",
]);

/**
 * Préimage de 212 octets et `BFTBlockHash` d'un en-tête (champs en
 * quantités JSON-RPC et hachages hexadécimaux). Rend null si un champ manque
 * ou n'a pas sa forme.
 */
export function hachageBlocBft(entete) {
  if (!entete || typeof entete !== "object") return null;
  const q = (nom, max) => quantiteVersEntier(entete[nom], max);
  const h = (nom) => (estHexOctets(entete[nom], 32) ? hexVersOctets(entete[nom]) : null);
  const number = q("number", MAX_U64);
  const timestamp = q("timestamp", MAX_U64);
  const gasUsed = q("gasUsed", MAX_U64);
  const gasLimit = q("gasLimit", MAX_U64);
  const baseFee = q("baseFeePerGas", MAX_U256);
  const parent = h("parentHash");
  const state = h("stateRoot");
  const txRoot = h("transactionsRoot");
  const receipts = h("receiptsRoot");
  if ([number, timestamp, gasUsed, gasLimit, baseFee, parent, state, txRoot, receipts].some((v) => v === null)) return null;
  const preimage = concatener(utf8(DOMAINE_BLOC_BFT), parent, u64(number), u64(timestamp), state, txRoot, receipts, u64(gasUsed), u64(gasLimit), u256(baseFee));
  return { preimage, hash: keccak256(preimage) };
}

/** Les dix champs engagés d'un en-tête servi, ou null si l'un manque ou est mal formé. */
export function champsEntete(entete) {
  if (!entete || typeof entete !== "object") return null;
  const sortie = {};
  for (const c of CHAMPS_ENTETE) {
    const v = entete[c];
    if (c === "hash" || c === "parentHash" || c === "stateRoot" || c === "transactionsRoot" || c === "receiptsRoot") {
      if (!estHexOctets(v, 32)) return null;
    } else if (quantiteVersEntier(v, c === "baseFeePerGas" ? MAX_U256 : MAX_U64) === null) return null;
    sortie[c] = v;
  }
  return sortie;
}

// ------------------------------------------------------------------ Bloom

/** Bloom de 256 octets d'une liste de journaux (CT-6 EX-11.5, règle 2). */
export function bloomJournaux(journaux) {
  const bloom = new Uint8Array(256);
  const poser = (d) => {
    const h = keccak256(d);
    for (const k of [0, 2, 4]) {
      const n = ((h[k] << 8) | h[k + 1]) & 0x7ff;
      bloom[255 - (n >> 3)] |= 1 << (n & 7);
    }
  };
  for (const j of journaux) {
    poser(hexVersOctets(j.address));
    for (const t of j.topics) poser(hexVersOctets(t));
  }
  return bloom;
}

// -------------------------------------------------------------- Reçus

const TYPES_RECU = new Set(["0x0", "0x1", "0x2", "0x3", "0x4"]);

/**
 * Lit un reçu (réponse JSON-RPC ou entrée de `registre.json`) en ne gardant
 * que `type`, `status`, `cumulativeGasUsed`, `logs[] { address, topics, data }`
 * (adresses en minuscules) ; null si une forme est refusée ou une borne de
 * CT-6 §15.1 dépassée (256 journaux par reçu, 4 sujets par journal).
 */
export function lireRecu(recu) {
  if (!recu || typeof recu !== "object") return null;
  if (!TYPES_RECU.has(recu.type) || (recu.status !== "0x0" && recu.status !== "0x1")) return null;
  if (quantiteVersEntier(recu.cumulativeGasUsed, MAX_U64) === null) return null;
  if (!Array.isArray(recu.logs) || recu.logs.length > 256) return null;
  const logs = [];
  for (const j of recu.logs) {
    if (!j || typeof j !== "object" || typeof j.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(j.address)) return null;
    if (!Array.isArray(j.topics) || j.topics.length > 4 || !j.topics.every((t) => estHexOctets(t, 32))) return null;
    if (typeof j.data !== "string" || !/^0x([0-9a-f]{2})*$/.test(j.data) || j.data.length > 262146) return null;
    logs.push({ address: j.address.toLowerCase(), topics: [...j.topics], data: j.data });
  }
  return { type: recu.type, status: recu.status, cumulativeGasUsed: recu.cumulativeGasUsed, logs };
}

/** Encodage de consensus d'un reçu (CT-6 EX-11.5, règle 3). */
export function encoderRecu(recu) {
  const r = lireRecu(recu);
  if (!r) throw new TypeError("reçu mal formé");
  const statut = r.status === "0x1" ? Uint8Array.of(0x01) : new Uint8Array(0);
  const journaux = r.logs.map((j) => [hexVersOctets(j.address), j.topics.map((t) => hexVersOctets(t)), hexVersOctets(j.data)]);
  const corps = rlp([statut, quantiteVersEntier(r.cumulativeGasUsed, MAX_U64), bloomJournaux(r.logs), journaux]);
  const type = Number(r.type);
  return type === 0 ? corps : concatener(Uint8Array.of(type), corps);
}

// ------------------------------------------------------------------- Trie

function quartets(cle) {
  const sortie = new Uint8Array(cle.length * 2);
  for (let k = 0; k < cle.length; k++) {
    sortie[2 * k] = cle[k] >> 4;
    sortie[2 * k + 1] = cle[k] & 0x0f;
  }
  return sortie;
}

/** Encodage hex-prefix d'une suite de quartets (drapeau 2 feuille, 0 extension). */
export function hexPrefix(nibbles, feuille) {
  const f = feuille ? 2 : 0;
  const impair = nibbles.length % 2 === 1;
  const sortie = new Uint8Array(1 + (nibbles.length >> 1));
  let i = 0;
  if (impair) {
    sortie[0] = ((f + 1) << 4) | nibbles[0];
    i = 1;
  } else {
    sortie[0] = f << 4;
  }
  for (let k = 1; i < nibbles.length; k++, i += 2) sortie[k] = (nibbles[i] << 4) | nibbles[i + 1];
  return sortie;
}

function reference(noeud) {
  const encode = rlp(noeud);
  return encode.length < 32 ? noeud : keccak256(encode);
}

function construireNoeud(couples, position) {
  if (couples.length === 1) {
    const c = couples[0];
    return [hexPrefix(c.nibbles.subarray(position), true), c.valeur];
  }
  // Préfixe commun des clés à partir de `position`.
  let p = 0;
  for (;;) {
    const ref = couples[0].nibbles;
    if (position + p >= ref.length) break;
    const q = ref[position + p];
    if (!couples.every((c) => position + p < c.nibbles.length && c.nibbles[position + p] === q)) break;
    p++;
  }
  if (p > 0) {
    const prefixe = couples[0].nibbles.subarray(position, position + p);
    return [hexPrefix(prefixe, false), reference(construireNoeud(couples, position + p))];
  }
  const branche = new Array(17).fill(null).map(() => new Uint8Array(0));
  for (let d = 0; d < 16; d++) {
    const sous = couples.filter((c) => position < c.nibbles.length && c.nibbles[position] === d);
    if (sous.length > 0) branche[d] = reference(construireNoeud(sous, position + 1));
  }
  const vide = couples.filter((c) => position >= c.nibbles.length);
  if (vide.length > 1) throw new TypeError("clés en double dans le trie");
  if (vide.length === 1) branche[16] = vide[0].valeur;
  return branche;
}

/**
 * Racine du trie Merkle-Patricia d'un ensemble de couples `{ cle, valeur }`
 * (octets), selon CT-6 EX-11.5, règle 4 ; `keccak256(0x80)` sans couple.
 */
export function racineTrie(couples) {
  if (couples.length === 0) return keccak256(Uint8Array.of(0x80));
  const cles = new Set();
  const prepares = couples.map((c) => {
    const h = Buffer.from(c.cle).toString("hex");
    if (cles.has(h)) throw new TypeError("clés en double dans le trie");
    cles.add(h);
    return { nibbles: quartets(c.cle), valeur: c.valeur };
  });
  return keccak256(rlp(construireNoeud(prepares, 0)));
}

/** Racine d'une liste ordonnée de valeurs, clés `RLP(i)` (reçus, transactions). */
export function racineListe(valeurs) {
  return racineTrie(valeurs.map((valeur, i) => ({ cle: rlpEntier(BigInt(i)), valeur })));
}

/** `receiptsRoot` recalculée d'une liste de reçus (EX-11.5). */
export function racineRecus(recus) {
  return racineListe(recus.map(encoderRecu));
}

/** `transactionsRoot` recalculée des transactions brutes d'un bloc (CT-4 RG-19). */
export function racineTransactions(txsRaw) {
  return racineListe(txsRaw);
}
