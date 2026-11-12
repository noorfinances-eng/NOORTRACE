// Références de clés (CT-4 EX-7.3, EX-7.25) : une clé se désigne par
// `fichier:<chemin>`, `env:<VARIABLE>`, `graine:<chemin>` ou `hardhat:<i>`,
// jamais par sa valeur. Ce module ne résout rien : il lit la forme d'une
// référence et dit si EX-7.3 l'admet pour la nature et l'identifiant EVM de
// l'instance. La résolution (lecture du fichier, de la variable, dérivation)
// n'a lieu que dans l'agent (`src/agent/cles.mjs`).
//
// Une valeur qui n'a pas l'une de ces formes est refusée sans être gardée ni
// consignée (EX-7.25) : le message dit seulement que la forme est refusée.

import { ErreurChamp, ressembleASecret } from "./champs.mjs";

/** Les quatre formes d'EX-7.3. */
export const FORMES = Object.freeze(["fichier", "env", "graine", "hardhat"]);

/** Identifiants EVM où les clés de test sont admises (EX-7.3 : 2124 et 31337). */
export const RESEAUX_DE_TEST = Object.freeze([2124, 31337]);

/**
 * Lit une référence : `{ forme, valeur }`. Lève `ErreurChamp`
 * (`reference_refusee`) pour toute autre forme, sans recopier la valeur.
 * `formes` : formes admises par le champ (par défaut les quatre).
 */
export function lireReference(champ, v, { formes = FORMES } = {}) {
  const refus = (message) => new ErreurChamp("reference_refusee", champ, message);
  if (typeof v !== "string" || v.length === 0 || v.length > 4096) throw refus("référence de clé attendue (fichier:, env:, graine:, hardhat:)");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw refus("caractère de contrôle refusé dans une référence");
  const m = /^(fichier|env|graine|hardhat):(.*)$/s.exec(v);
  if (!m) {
    throw refus(ressembleASecret(v)
      ? "valeur nue refusée : une clé ne se donne jamais par sa valeur, seulement par une référence (EX-7.3, EX-7.25)"
      : "forme de référence inconnue : fichier:<chemin>, env:<VARIABLE>, graine:<chemin> ou hardhat:<i> (EX-7.3)");
  }
  const [, forme, valeur] = m;
  if (!formes.includes(forme)) throw refus(`forme ${forme}: non admise pour ce champ`);
  if (forme === "fichier" || forme === "graine") {
    if (!valeur.startsWith("/") || valeur.split("/").includes("..")) throw refus(`${forme}: chemin absolu sans .. attendu`);
    if (ressembleASecret(valeur, { base64: false })) throw refus("valeur nue refusée dans un chemin");
  } else if (forme === "env") {
    if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(valeur)) throw refus("env: nom de variable [A-Z_][A-Z0-9_]* attendu");
  } else if (forme === "hardhat") {
    if (!/^(0|[1-9][0-9]{0,4})$/.test(valeur) || Number(valeur) > 1000) throw refus("hardhat: indice de compte de 0 à 1000 attendu");
  }
  return { forme, valeur };
}

/**
 * EX-7.3 : une référence `hardhat:` ou `graine:` n'est admise que pour une
 * instance de nature `developpement` d'identifiant EVM 2124 ou 31337 ;
 * `fichier:` et `env:` ne sont pas admis en production pour
 * l'administrateur du registre ni la trésorerie (ni, par la même règle,
 * pour le déployeur et le relayeur de l'exploitant, dont la signature
 * externe est une proposition, CT-4 §14 : voir LISEZMOI.md) ; en
 * production, `fichier:` et `env:` restent admis pour une clé de chaîne
 * seulement. Rend null si la référence est admise, sinon le motif.
 * `role` : `deployeur`, `administrateur`, `tresorerie`, `relayeur`,
 * `exploitant`, `cle_chaine`, `graine`.
 */
export function motifRefusReference({ forme }, { role, nature, evmChainId }) {
  const reseauDeTest = nature === "developpement" && RESEAUX_DE_TEST.includes(Number(evmChainId));
  if ((forme === "hardhat" || forme === "graine") && !reseauDeTest) return "reseau_non_developpement";
  if (role === "exploitant" && !reseauDeTest) return "reseau_non_developpement";
  if (nature === "production" && role !== "cle_chaine") return "reference_refusee";
  return null;
}
