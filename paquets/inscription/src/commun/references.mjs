// Références de clés (CT-4 EX-7.3, EX-7.25) : une clé se désigne par
// `fichier:<chemin>`, `env:<VARIABLE>`, `graine:<chemin>` ou `hardhat:<i>`,
// jamais par sa valeur ; un travail peut aussi désigner un alias de la
// configuration de l'agent, `alias:<nom>` (revue de l'étape 8).
// Ce module ne résout rien : il lit la forme d'une référence et dit si
// EX-7.3 l'admet pour la nature et l'identifiant EVM de l'instance. La
// résolution (lecture du fichier, de la variable, dérivation, alias) n'a
// lieu que dans l'agent (`src/agent/cles.mjs`).
//
// Une valeur qui n'a pas l'une de ces formes est refusée sans être gardée ni
// consignée (EX-7.25) : le message dit seulement que la forme est refusée.

import { ErreurChamp, ressembleASecret } from "./champs.mjs";

/** Les quatre formes d'EX-7.3 et la forme `alias:` d'un travail. */
export const FORMES = Object.freeze(["fichier", "env", "graine", "hardhat", "alias"]);
/** Formes admises dans la configuration de l'agent (`comptes`, `cles.alias`) : les quatre formes d'EX-7.3. */
export const FORMES_CONFIGURATION = Object.freeze(["fichier", "env", "graine", "hardhat"]);
/**
 * Formes admises dans un travail (CT-4 EX-7.25) :
 * `fichier:` et `graine:` sous le répertoire de clés de l'agent, `hardhat:`
 * (réseaux de test), `alias:` de sa configuration ; `env:` est réservée à la
 * configuration de l'agent (l'interface ne désigne pas une variable de
 * l'environnement de l'agent).
 */
export const FORMES_TRAVAIL = Object.freeze(["fichier", "graine", "hardhat", "alias"]);
/** Nom d'un alias de la configuration de l'agent. */
export const MOTIF_ALIAS = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** Identifiants EVM où les clés de test sont admises (EX-7.3 : 2124 et 31337). */
export const RESEAUX_DE_TEST = Object.freeze([2124, 31337]);

/**
 * Lit une référence : `{ forme, valeur }`. Lève `ErreurChamp`
 * (`reference_refusee`) pour toute autre forme, sans recopier la valeur.
 * `formes` : formes admises par le champ (par défaut les quatre).
 */
export function lireReference(champ, v, { formes = FORMES } = {}) {
  const refus = (message) => new ErreurChamp("reference_refusee", champ, message);
  if (typeof v !== "string" || v.length === 0 || v.length > 4096) throw refus("référence de clé attendue (fichier:, env:, graine:, hardhat:, alias:)");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw refus("caractère de contrôle refusé dans une référence");
  const m = /^(fichier|env|graine|hardhat|alias):(.*)$/s.exec(v);
  if (!m) {
    throw refus(ressembleASecret(v)
      ? "valeur nue refusée : une clé ne se donne jamais par sa valeur, seulement par une référence (EX-7.3, EX-7.25)"
      : "forme de référence inconnue : fichier:<chemin>, env:<VARIABLE>, graine:<chemin>, hardhat:<i> ou alias:<nom> (EX-7.3)");
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
  } else if (forme === "alias") {
    if (!MOTIF_ALIAS.test(valeur)) throw refus("alias: nom [a-z0-9][a-z0-9-]* de 1 à 64 caractères attendu");
  }
  return { forme, valeur };
}

/**
 * EX-7.3 : une référence `hardhat:` ou `graine:` n'est admise que pour une
 * instance de nature `developpement` d'identifiant EVM 2124 ou 31337 ;
 * `fichier:` et `env:` chargent la clé en mémoire de l'agent (classe de
 * garde D, CT-2 §11.2) et ne sont admis que sur une instance de nature
 * `developpement`, quel que soit le rôle : clé de chaîne du client comprise
 * (revue de l'étape 8 ; CLE-2 de CT-7 exige la classe
 * A, B ou C, et l'exploitant est l'adversaire « fournisseur » du client ;
 * révision d'EX-7.3 demandée). Rend null si la référence est admise, sinon
 * le motif. `role` : `deployeur`, `administrateur`, `tresorerie`,
 * `relayeur`, `exploitant`, `cle_chaine`, `expediteur`, `graine`, `alias`.
 * Une référence `alias:` se juge sur la forme de la référence qu'elle
 * désigne, jamais ici.
 */
export function motifRefusReference({ forme }, { role, nature, evmChainId }) {
  const reseauDeTest = nature === "developpement" && RESEAUX_DE_TEST.includes(Number(evmChainId));
  if ((forme === "hardhat" || forme === "graine") && !reseauDeTest) return "reseau_non_developpement";
  if (role === "exploitant" && !reseauDeTest) return "reseau_non_developpement";
  if (nature === "production") return "reference_refusee";
  return null;
}
