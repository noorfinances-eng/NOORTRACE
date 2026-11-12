// Encodages absents de `@noortrace/ancrage/registre`, écrits ici et nulle
// part ailleurs (INTERFACES.md 0.5) : le code de création de
// `CuratorSet(set_admin, members, threshold)` (code d'octets lu dans
// `hh-artifacts/contracts/CuratorSet.sol/CuratorSet.json`, produit par
// `npm run compile`, suivi des arguments du constructeur, CT-4 §6.7.2),
// l'appel `setCuratorSet(bytes32,address)`, les lectures `admin()`,
// `isRegistered(bytes32)`, `curatorSetOf(bytes32)` du registre des jeux et
// `getThreshold()`, `getCuratorCount()`, `isCurator(address)` d'un jeu, et
// les événements que vérifie OP-11 pour les pas 2 et 3 ; pour `administrer-jeu`
// (CT-4 §8.5, RG-11), `opNonce()`, `pendingAdmin()`, `adminOpDigest(op, arg,
// nonce)`, les cinq opérations signées et `AdminOpRelayed`. Chaque sélecteur
// est recalculé ici (Keccak-256 de la signature) ; un essai le compare à
// l'ABI des artefacts.

import fs from "node:fs";
import path from "node:path";
import { keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";

const k = (s) => octetsVersHex(keccak256(utf8(s)));

/** Signatures des fonctions employées par l'agent hors de `@noortrace/ancrage/registre`. */
export const SIGNATURES = Object.freeze({
  setCuratorSet: "setCuratorSet(bytes32,address)",
  admin: "admin()",
  isRegistered: "isRegistered(bytes32)",
  curatorSetOf: "curatorSetOf(bytes32)",
  getThreshold: "getThreshold()",
  getCuratorCount: "getCuratorCount()",
  isCurator: "isCurator(address)",
  opNonce: "opNonce()",
  pendingAdmin: "pendingAdmin()",
  adminOpDigest: "adminOpDigest(bytes32,bytes32,uint256)",
  addCuratorSigned: "addCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
  removeCuratorSigned: "removeCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
  setThresholdSigned: "setThresholdSigned(uint256,uint256,(uint8,bytes32,bytes32))",
  proposeAdminSigned: "proposeAdminSigned(address,uint256,(uint8,bytes32,bytes32))",
  acceptAdminSigned: "acceptAdminSigned(uint256,(uint8,bytes32,bytes32))",
});

/** Sélecteurs recalculés (CT-4 §6.7.1). */
export const SELECTEURS = Object.freeze(Object.fromEntries(Object.entries(SIGNATURES).map(([n, s]) => [n, k(s).slice(0, 10)])));

/** Événements que lit OP-11 aux pas 2 et 3 (CT-4 §5.7). */
export const EVENEMENTS = Object.freeze({
  AdminAccepted: k("AdminAccepted(address,address)"),
  CuratorAdded: k("CuratorAdded(address)"),
  ThresholdUpdated: k("ThresholdUpdated(uint256)"),
  CuratorSetAssigned: k("CuratorSetAssigned(bytes32,address,address)"),
  AdminOpRelayed: k("AdminOpRelayed(bytes32,address,uint256)"),
  AdminProposed: k("AdminProposed(address,address)"),
  CuratorRemoved: k("CuratorRemoved(address)"),
});

/**
 * Opérations d'un `CuratorSet` (CT-4 §6.6.2, RG-11) : nom de l'opération
 * (`op` = keccak256 de ce nom), fonction signée, forme de l'argument
 * (`adresse`, `entier` ou `aucun`, `arg` de 32 octets).
 */
export const OPERATIONS = Object.freeze({
  "CuratorSet.addCurator": { fonction: "addCuratorSigned", argument: "adresse" },
  "CuratorSet.removeCurator": { fonction: "removeCuratorSigned", argument: "adresse" },
  "CuratorSet.setThreshold": { fonction: "setThresholdSigned", argument: "entier" },
  "CuratorSet.proposeAdmin": { fonction: "proposeAdminSigned", argument: "adresse" },
  "CuratorSet.acceptAdmin": { fonction: "acceptAdminSigned", argument: "aucun" },
});

/** `op` d'une opération : keccak256(UTF-8(nom)). */
export const opDe = (nom) => k(nom);

/** Chemin de l'artefact de `CuratorSet`, relatif à la racine du dépôt (CT-4 §7.2). */
export const ARTEFACT_CURATOR_SET = path.join("hh-artifacts", "contracts", "CuratorSet.sol", "CuratorSet.json");

const mot = (hex) => hex.replace(/^0x/, "").padStart(64, "0");
const motEntier = (n) => BigInt(n).toString(16).padStart(64, "0");

/** Lit le code de création de `CuratorSet` dans l'artefact de compilation ; rend l'hexadécimal préfixé, ou lève. */
export function codeCreationCuratorSet(racine = process.cwd()) {
  const chemin = path.join(racine, ARTEFACT_CURATOR_SET);
  const artefact = JSON.parse(fs.readFileSync(chemin, "utf8"));
  if (typeof artefact.bytecode !== "string" || !/^0x([0-9a-f]{2})+$/i.test(artefact.bytecode)) throw new Error(`${ARTEFACT_CURATOR_SET} : code de création absent`);
  return artefact.bytecode.toLowerCase();
}

/** Arguments du constructeur `CuratorSet(address, address[], uint256)` (CT-4 §6.7.2) : 128 + 32k octets. */
export function argumentsCuratorSet(setAdmin, membres, seuil) {
  return "0x" + mot(setAdmin) + motEntier(0x60) + motEntier(seuil) + motEntier(membres.length) + membres.map(mot).join("");
}

/** Données de la transaction de déploiement : code de création suivi des arguments. */
export function donneesDeploiement(code, setAdmin, membres, seuil) {
  return code + argumentsCuratorSet(setAdmin, membres, seuil).slice(2);
}

/** Données d'appel de `setCuratorSet(orgId, set)` : 68 octets. */
export function encoderSetCuratorSet(orgId, set) {
  return SELECTEURS.setCuratorSet + mot(orgId) + mot(set);
}

export const encoderAdmin = () => SELECTEURS.admin;
export const encoderIsRegistered = (orgId) => SELECTEURS.isRegistered + mot(orgId);
export const encoderCuratorSetOf = (orgId) => SELECTEURS.curatorSetOf + mot(orgId);
export const encoderGetThreshold = () => SELECTEURS.getThreshold;
export const encoderGetCuratorCount = () => SELECTEURS.getCuratorCount;
export const encoderIsCurator = (a) => SELECTEURS.isCurator + mot(a);
export const encoderOpNonce = () => SELECTEURS.opNonce;
export const encoderPendingAdmin = () => SELECTEURS.pendingAdmin;
/** `adminOpDigest(op, arg, nonce)` : 100 octets. */
export const encoderAdminOpDigest = (op, arg, nonce) => SELECTEURS.adminOpDigest + mot(op) + mot(arg) + motEntier(nonce);

/**
 * Données d'appel de l'opération signée `nom` (RG-11) : argument (sauf
 * `acceptAdmin`), nonce, puis la signature `(v, r, s)` en ligne (tuple de types
 * statiques).
 */
export function encoderOperationSignee(nom, arg, nonce, sig) {
  const o = OPERATIONS[nom];
  if (!o) throw new Error(`opération inconnue ${nom}`);
  const signature = motEntier(sig.v) + mot(sig.r) + mot(sig.s);
  return SELECTEURS[o.fonction] + (o.argument === "aucun" ? "" : mot(arg)) + motEntier(nonce) + signature;
}

/** Premier mot d'un retour d'`eth_call`, en `bigint` ; null si le retour n'a pas 32 octets au moins. */
export function decoderMot(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]*$/.test(hex) || hex.length < 66) return null;
  return BigInt("0x" + hex.slice(2, 66));
}

/** Adresse d'un retour d'`eth_call` (12 octets nuls, puis 20) ; null si le retour n'a pas cette forme. */
export function decoderAdresse(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-fA-F]{64}/.test(hex)) return null;
  if (!/^0{24}$/.test(hex.slice(2, 26))) return null;
  return ("0x" + hex.slice(26, 66)).toLowerCase();
}

/** Adresse d'un sujet de journal de 32 octets. */
export const adresseDeSujet = (t) => ("0x" + String(t).slice(26)).toLowerCase();
