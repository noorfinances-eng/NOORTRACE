// Outils communs aux tests du serveur RFC 3161 interne (lot E,
// test/ancrage-tsa-interne*.test.js) : chemins des vecteurs CT-5 et CT-6,
// autorité de test de CT-6 (clés publiées, sans valeur), appels à `openssl`
// comme boîte noire (juge : `ts -verify`, `ts -reply -text`, `asn1parse`,
// `x509`, `crl`), répertoires temporaires sous os.tmpdir(), horloges fixes,
// essai en attente avec sa condition nommée dans le titre.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const VECTEURS_CT5 = path.join(RACINE, "spec", "vecteurs", "ct-5");
export const VECTEURS_CT6 = path.join(RACINE, "spec", "vecteurs", "ct-6");
export const CLES_CT6 = path.join(VECTEURS_CT6, "rfc3161", "cles");
export const BIN_TSA = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-tsa-interne");
export const POLITIQUE_TEST = "1.3.6.1.4.1.99999.1.1";

/** Les six requêtes des vecteurs CT-5 et la réponse `granted` de référence de chacune (série, genTime). */
export const REQUETES = Object.freeze([
  { nom: "requete-point-k2", serie: 1001n, genTime: "2026-11-03T13:53:02Z", reference: "granted-requete-point-k2" },
  { nom: "point-k2-exemple", serie: 1002n, genTime: "2026-11-03T13:53:02Z", reference: "granted-point-k2-exemple" },
  { nom: "point-k2-exemple-politique-interne", serie: 1003n, genTime: "2026-11-03T13:53:02Z", reference: "granted-point-k2-exemple-politique-interne" },
  { nom: "periode-1-reference", serie: 1004n, genTime: "2026-11-03T14:00:05Z", reference: "granted-periode-1-reference" },
  { nom: "periode-1-reference-tentative-2", serie: 1005n, genTime: "2026-11-03T14:00:10Z", reference: "granted-periode-1-reference-tentative-2" },
  { nom: "periode-1-vecteurs", serie: 1006n, genTime: "2026-11-05T10:00:05Z", reference: "granted-periode-1-vecteurs" },
]);

export function lireRequete(nom) {
  return new Uint8Array(fs.readFileSync(path.join(VECTEURS_CT5, "requetes", `${nom}.tsq`)));
}

export function cheminRequete(nom) {
  return path.join(VECTEURS_CT5, "requetes", `${nom}.tsq`);
}

export function lireReponseReference(nom) {
  return new Uint8Array(fs.readFileSync(path.join(VECTEURS_CT5, "reponses", `${nom}.tsr`)));
}

/** Clé et certificat de l'autorité de test de CT-6. */
export const AUTORITE_TEST = Object.freeze({
  cleUnite: path.join(CLES_CT6, "tsa-test.cle.pem"),
  unite: path.join(CLES_CT6, "tsa-test.pem"),
  cleAc: path.join(CLES_CT6, "ac-test.cle.pem"),
  ac: path.join(CLES_CT6, "ac-test.pem"),
});

/** Répertoire temporaire neuf. */
export function repertoireTemporaire(prefixe = "noortrace-tsa-interne-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
}

/** Horloge fixe (murale et monotone) avec écart mesuré nul. */
export function horlogeFixe(iso, ecartMs = 0) {
  const t = Date.parse(iso);
  return { murale: () => t, monotone: () => 1e6, ecartMs };
}

/** Aléa déterministe pour les essais (jamais une source de production). */
export function aleatoireFixe(graine = 7) {
  let x = graine >>> 0;
  return (n) => {
    const u = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      u[i] = (x >>> 16) & 0xff;
    }
    return u;
  };
}

/** `openssl` : sortie standard en texte ; lève avec la sortie d'erreur en cas d'échec. */
export function openssl(args, entree = undefined) {
  return execFileSync("openssl", args, { input: entree, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 30000 });
}

/** `openssl` sans lever : `{ code, stdout, stderr }`. */
export function opensslEssai(args, entree = undefined) {
  const r = spawnSync("openssl", args, { input: entree, encoding: "utf8", timeout: 30000 });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/** `openssl ts -verify -queryfile <requête> -in <réponse> -CAfile <ac> -untrusted <unité>`. */
export function verifierOpenssl({ requete, reponse, ac, unite, jeton = false }) {
  const args = ["ts", "-verify", "-queryfile", requete, "-in", reponse, "-CAfile", ac, "-untrusted", unite];
  if (jeton) args.push("-token_in");
  return opensslEssai(args);
}

/** `openssl ts -reply -in <réponse> -text` : lignes utiles sous forme d'objet. */
export function relireReponse(reponse) {
  const texte = openssl(["ts", "-reply", "-in", reponse, "-text"]);
  const champ = (nom) => {
    const m = new RegExp(`^${nom}: (.*)$`, "m").exec(texte);
    return m ? m[1].trim() : null;
  };
  return {
    texte,
    statut: champ("Status"),
    description: champ("Status description"),
    echec: champ("Failure info"),
    version: champ("Version"),
    politique: champ("Policy OID"),
    algorithme: champ("Hash Algorithm"),
    serie: champ("Serial number"),
    instant: champ("Time stamp"),
    precision: champ("Accuracy"),
    ordering: champ("Ordering"),
    nonce: champ("Nonce"),
    tsa: champ("TSA"),
    condense: (texte.match(/^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[- ])+)/gm) ?? []).map((l) => l.replace(/^\s+[0-9a-f]{4} - /, "").replace(/[- ]/g, "")).join(""),
  };
}

/** Écrit des octets dans un fichier du répertoire et rend son chemin. */
export function ecrire(repertoire, nom, octets) {
  const chemin = path.join(repertoire, nom);
  fs.writeFileSync(chemin, octets);
  return chemin;
}

/** Essai en attente, condition nommée dans le titre (forme de test/enregistreur-signataires-parcours.test.js). */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Lance le binaire `noortrace-tsa-interne` de façon synchrone. */
export function bin(args, options = {}) {
  return spawnSync(process.execPath, [BIN_TSA, ...args], { encoding: "utf8", timeout: 30000, ...options });
}

export const hex = (octets) => Buffer.from(octets).toString("hex");
