// Résolution des références de clés par l'agent, seul à le faire (CT-4
// EX-7.3, EX-7.23) : `fichier:<chemin>` (clé secp256k1 de 32 octets en
// hexadécimal, fichier lisible de son seul propriétaire), `env:<VARIABLE>`,
// `graine:<chemin>` (graine Ed25519 de 32 octets, CT-1 §6), `hardhat:<i>`
// (compte `i` du mnémonique public `test test … junk`, chemin
// `m/44'/60'/0'/0/i`, BIP-39 et BIP-32 calculés avec `node:crypto`).
//
// Une valeur résolue ne sort jamais de ce module autrement que dans un
// `SignataireChaineFichier` (qui ne la sérialise pas) ou, pour la recherche
// d'EX-7.21 seulement, dans les octets que rend `octetsSecrets` : elle n'est
// ni écrite, ni consignée, ni rendue à l'interface.

import crypto from "node:crypto";
import fs from "node:fs";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import { lireReference, motifRefusReference } from "../commun/references.mjs";

/** Mnémonique public des comptes de test (EX-7.3) ; ses clés n'ont aucune valeur. */
export const MNEMONIQUE_TEST = "test test test test test test test test test test test junk";

const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/** Erreur de référence : `code` (`reference_refusee`, `reseau_non_developpement`, `usage`), message sans valeur. */
export class ErreurReference extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurReference";
    this.code = code;
  }
}

function compresse(cle) {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(cle);
  return ecdh.getPublicKey(null, "compressed");
}

function ser32(i) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(i >>> 0, 0);
  return b;
}

/** Clé privée du compte `i` de `m/44'/60'/0'/0/i` (BIP-39 sans phrase de passe, BIP-32). */
export function cleHardhat(i, mnemonique = MNEMONIQUE_TEST) {
  const graine = crypto.pbkdf2Sync(Buffer.from(mnemonique.normalize("NFKD"), "utf8"), Buffer.from("mnemonic", "utf8"), 2048, 64, "sha512");
  let I = crypto.createHmac("sha512", Buffer.from("Bitcoin seed", "utf8")).update(graine).digest();
  let k = I.subarray(0, 32);
  let c = I.subarray(32);
  const durcie = 0x80000000;
  for (const indice of [44 + durcie, 60 + durcie, 0 + durcie, 0, i]) {
    const donnees = indice >= durcie ? Buffer.concat([Buffer.alloc(1), k, ser32(indice)]) : Buffer.concat([compresse(k), ser32(indice)]);
    I = crypto.createHmac("sha512", c).update(donnees).digest();
    const enfant = (BigInt("0x" + I.subarray(0, 32).toString("hex")) + BigInt("0x" + k.toString("hex"))) % N;
    k = Buffer.from(enfant.toString(16).padStart(64, "0"), "hex");
    c = I.subarray(32);
  }
  return new Uint8Array(k);
}

function lireHex32(octets, quoi) {
  const t = Buffer.from(octets).toString("utf8").trim();
  const m = /^(?:0x)?([0-9a-fA-F]{64})$/.exec(t);
  if (!m) throw new ErreurReference("reference_refusee", `${quoi} : 32 octets en hexadécimal attendus`);
  return new Uint8Array(Buffer.from(m[1], "hex"));
}

function lireFichierProtege(chemin, quoi) {
  let st;
  try {
    st = fs.statSync(chemin);
  } catch {
    throw new ErreurReference("reference_refusee", `${quoi} : fichier illisible`);
  }
  if (!st.isFile()) throw new ErreurReference("reference_refusee", `${quoi} : fichier ordinaire attendu`);
  if ((st.mode & 0o077) !== 0) throw new ErreurReference("reference_refusee", `${quoi} : fichier lisible par d'autres que son propriétaire (EX-7.3)`);
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) throw new ErreurReference("reference_refusee", `${quoi} : fichier d'un autre compte`);
  return fs.readFileSync(chemin);
}

/**
 * Résout une référence en octets secrets (32 octets). `contexte` : `{ role,
 * nature, evmChainId }` pour EX-7.3 ; `env` : l'environnement (par défaut
 * celui du processus).
 */
export function octetsSecrets(reference, contexte, { env = process.env } = {}) {
  let ref;
  try {
    ref = lireReference(contexte.role, reference);
  } catch (e) {
    throw new ErreurReference("reference_refusee", e.message);
  }
  const motif = motifRefusReference(ref, contexte);
  if (motif) throw new ErreurReference(motif, `${contexte.role} : référence ${ref.forme}: refusée pour une instance de nature ${contexte.nature} d'identifiant EVM ${contexte.evmChainId} (EX-7.3)`);
  const quoi = `${contexte.role} (${ref.forme}:)`;
  switch (ref.forme) {
    case "fichier":
    case "graine":
      return lireHex32(lireFichierProtege(ref.valeur, quoi), quoi);
    case "env": {
      const v = env[ref.valeur];
      if (typeof v !== "string") throw new ErreurReference("reference_refusee", `${quoi} : variable absente`);
      return lireHex32(Buffer.from(v, "utf8"), quoi);
    }
    case "hardhat":
      return cleHardhat(Number(ref.valeur));
    default:
      throw new ErreurReference("reference_refusee", `${quoi} : forme non admise`);
  }
}

/** Résout une référence de clé secp256k1 en `SignataireChaineFichier` (classe D). `graine:` n'est pas une clé secp256k1. */
export function signataire(reference, contexte, options) {
  if (typeof reference === "string" && reference.startsWith("graine:")) throw new ErreurReference("reference_refusee", `${contexte.role} : graine: désigne une graine Ed25519, pas une clé secp256k1`);
  const octets = octetsSecrets(reference, contexte, options);
  try {
    const s = new SignataireChaineFichier(octets);
    return s;
  } catch {
    throw new ErreurReference("reference_refusee", `${contexte.role} : clé secp256k1 invalide`);
  } finally {
    octets.fill(0);
  }
}

/** Contrôle d'EX-7.3 sans résolution : rend null ou `{ code, message }`. */
export function controlerReference(reference, contexte) {
  try {
    const ref = lireReference(contexte.role, reference);
    const motif = motifRefusReference(ref, contexte);
    return motif ? { code: motif, message: `${contexte.role} : référence ${ref.forme}: refusée pour une instance de nature ${contexte.nature} d'identifiant EVM ${contexte.evmChainId} (EX-7.3)` } : null;
  } catch (e) {
    return { code: "reference_refusee", message: e.message };
  }
}
