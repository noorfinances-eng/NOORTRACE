// Hachage d'un événement et condensés d'une décision (CT-1 §6.1 et §6.3 ;
// CT-3 EX-9.15 contrôle 2, EX-9.17 à EX-9.19) : `hash = SHA-256(P_H ‖ JCS(E'))`,
// `D_A = SHA-256(P_A ‖ JCS(A))`, `H = keccak256(0x19 ‖ "Ethereum Signed
// Message:\n32" ‖ D_A)`, empreinte abrégée et huit groupes de huit chiffres,
// et le constat que les 32 octets de `D_A` sont de l'UTF-8 (avertissement
// `condense_utf8`).

import { keccak256, sha256 } from "./hachage.mjs";
import { jcs } from "./json.mjs";
import { concatener, estUtf8, utf8Strict, versHex } from "./octets.mjs";
import { preimageEip191 } from "./signatures.mjs";

const P_H = "noortrace/evenement/v0\n";
const P_A = "noortrace/approbation/v0\n";
const HEX32 = /^0x[0-9a-fA-F]{64}$/;

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Hachage d'un événement de CT-1 §6.1 : SHA-256 de `P_H ‖ JCS(E')`, `E'`
 * l'événement sans `hash` ni `sig`.
 * @param {object} evenement
 * @returns {string} `"0x…"`
 * @throws {TypeError} événement qui n'est pas un objet, ou sans forme JCS v0
 */
export function hachageEvenement(evenement) {
  if (!estObjet(evenement)) throw new TypeError("hachageEvenement : objet attendu");
  const prive = {};
  for (const k of Object.keys(evenement)) {
    if (k !== "hash" && k !== "sig") Object.defineProperty(prive, k, { value: evenement[k], enumerable: true, writable: true, configurable: true });
  }
  return versHex(sha256(concatener(utf8Strict(P_H), utf8Strict(jcs(prive)))));
}

function chiffres(x) {
  if (typeof x !== "string" || !HEX32.test(x)) throw new TypeError('"0x" et 64 chiffres hexadecimaux attendus');
  return x.slice(2).toLowerCase();
}

/**
 * Empreinte abrégée d'EX-9.18 : 8 premiers chiffres, U+2026, 8 derniers.
 * @param {string} x `"0x"` et 64 chiffres
 * @returns {string}
 */
export function empreinte(x) {
  const c = chiffres(x);
  return `${c.slice(0, 8)}…${c.slice(56, 64)}`;
}

/**
 * Les 64 chiffres en 8 groupes de 8 séparés par une espace (EX-9.18).
 * @param {string} x `"0x"` et 64 chiffres
 * @returns {string}
 */
export function groupes(x) {
  const c = chiffres(x);
  const g = [];
  for (let k = 0; k < 64; k += 8) g.push(c.slice(k, k + 8));
  return g.join(" ");
}

/**
 * Ce que la console calcule pour une décision (`$defs/condenses`) : `A`,
 * `JCS(A)`, `D_A`, son empreinte et ses groupes, `H`, son empreinte, et le
 * constat UTF-8 d'EX-9.19.
 * @param {{decision: string, journal_id: string, org_id: string, request_hash: string, ticket: string}} a
 * @returns {{a: object, jcs: string, d_a: string, fingerprint: string, groups: string, h: string, h_fingerprint: string, utf8: boolean}}
 */
export function condenses(a) {
  if (!estObjet(a)) throw new TypeError("condenses : objet A attendu");
  const copie = { decision: a.decision, journal_id: a.journal_id, org_id: a.org_id, request_hash: a.request_hash, ticket: a.ticket };
  if (Object.keys(a).length !== 5 || Object.values(copie).some((v) => typeof v !== "string")) {
    throw new TypeError("condenses : A porte exactement decision, journal_id, org_id, request_hash et ticket, en chaines");
  }
  const texte = jcs(copie);
  const octetsDA = sha256(concatener(utf8Strict(P_A), utf8Strict(texte)));
  const dA = versHex(octetsDA);
  const h = versHex(keccak256(preimageEip191(octetsDA)));
  return { a: copie, jcs: texte, d_a: dA, fingerprint: empreinte(dA), groups: groupes(dA), h, h_fingerprint: empreinte(h), utf8: estUtf8(octetsDA) };
}
