// Initialisation d'une autorité interne de développement (AN-22, AN-31) :
// AC auto-signée (CA:TRUE critique, keyCertSign et cRLSign), unité
// d'horodatage (CA absente, EKU critique `id-kp-timeStamping` seul, keyUsage
// digitalSignature, SKI, AKI, point de distribution de CRL, validité ≤ 1095
// jours), CRL vide signée par l'AC ; clés PKCS#8 et certificats en PEM. Les
// clés sont celles d'une classe D de développement (CT-7 §5) : elles n'ont
// aucune valeur et ne servent qu'au réseau de développement et aux essais.
// L'horloge et l'aléa (numéros de série des certificats) sont injectés.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pem, versHex } from "./der-ecriture.mjs";
import { Autorite, ErreurAutorite, construireNom, emettreCertificat, emettreCrl, extensionsAc, extensionsUnite, spkiDe, identifiantCle, lireClePrivee, sha256 } from "./autorite.mjs";
import { lireCertificat, identifiantCleSujet } from "./certificat.mjs";
import { Compteur } from "./compteur.mjs";

export const FICHIERS_AUTORITE = Object.freeze({
  acCle: "ac.cle.pem",
  ac: "ac.pem",
  uniteCle: "unite.cle.pem",
  unite: "unite.pem",
  crl: "crl.pem",
  crlNumero: "crl.numero",
  descripteur: "autorite.json",
  compteur: "serie",
});

export const ALGORITHMES = Object.freeze(["rsa-3072", "p-256"]);
export const VALIDITE_MAX_JOURS = 1095;
const JOUR_MS = 86400000;

function ecrireDurable(chemin, contenu, mode) {
  const tmp = `${chemin}.tmp`;
  const fd = fs.openSync(tmp, "w", mode);
  try {
    fs.writeSync(fd, contenu);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, chemin);
  const fdRep = fs.openSync(path.dirname(chemin), "r");
  try {
    fs.fsyncSync(fdRep);
  } finally {
    fs.closeSync(fdRep);
  }
}

function genererCle(algorithme) {
  if (algorithme === "rsa-3072") return crypto.generateKeyPairSync("rsa", { modulusLength: 3072, publicExponent: 65537 }).privateKey;
  if (algorithme === "p-256") return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  throw new ErreurAutorite(`algorithme ${algorithme} : ${ALGORITHMES.join(" ou ")} attendu`);
}

/** Numéro de série positif de 16 octets tiré de l'aléa injecté (RFC 5280 §4.1.2.2 : positif, ≤ 20 octets). */
function serieAleatoire(aleatoire) {
  const octets = aleatoire(16);
  if (!(octets instanceof Uint8Array) || octets.length !== 16) throw new TypeError("aleatoire(16) : Uint8Array de 16 octets attendu");
  const copie = Uint8Array.from(octets);
  copie[0] &= 0x7f;
  let v = 0n;
  for (const o of copie) v = (v << 8n) | BigInt(o);
  return v === 0n ? 1n : v;
}

function pemClePrivee(cle) {
  return cle.export({ type: "pkcs8", format: "pem" });
}

function rfc3339(ms) {
  return new Date(ms).toISOString();
}

/**
 * Crée l'autorité dans `repertoire` (refus si une AC y existe déjà).
 * @param {object} o
 * @param {string} o.repertoire
 * @param {"rsa-3072"|"p-256"} o.algorithme
 * @param {string} o.politique OID privé de l'exploitant (AN-29)
 * @param {number} [o.validiteJours] validité de l'unité, 1095 au plus (AN-31)
 * @param {number} [o.validiteAcJours] validité de l'AC (3652 par défaut)
 * @param {number} [o.validiteCrlJours] durée de la CRL (30 par défaut)
 * @param {string} o.crlUrl adresse de publication de la CRL (http ou https)
 * @param {{murale: () => number}} o.horloge
 * @param {(n: number) => Uint8Array} o.aleatoire
 * @param {{C?: string, O?: string, OU?: string, CN?: string}} [o.sujetAc]
 * @param {{C?: string, O?: string, OU?: string, CN?: string}} [o.sujetUnite]
 */
export function initialiserAutorite(o) {
  if (!o || typeof o.repertoire !== "string") throw new TypeError("initialiserAutorite : repertoire attendu");
  if (!ALGORITHMES.includes(o.algorithme)) throw new ErreurAutorite(`algorithme ${o.algorithme} : ${ALGORITHMES.join(" ou ")} attendu`);
  if (typeof o.politique !== "string" || !/^[0-9]+(\.[0-9]+)+$/.test(o.politique)) throw new ErreurAutorite("politique : OID attendu (AN-29)");
  const validiteJours = o.validiteJours ?? VALIDITE_MAX_JOURS;
  if (!Number.isInteger(validiteJours) || validiteJours < 1 || validiteJours > VALIDITE_MAX_JOURS) throw new ErreurAutorite(`validiteJours : entier de 1 à ${VALIDITE_MAX_JOURS} attendu (AN-31)`);
  const validiteAcJours = o.validiteAcJours ?? 3652;
  if (!Number.isInteger(validiteAcJours) || validiteAcJours < validiteJours) throw new ErreurAutorite("validiteAcJours : entier ≥ validiteJours attendu");
  const validiteCrlJours = o.validiteCrlJours ?? 30;
  if (!Number.isInteger(validiteCrlJours) || validiteCrlJours < 1) throw new ErreurAutorite("validiteCrlJours : entier ≥ 1 attendu");
  if (typeof o.crlUrl !== "string" || !/^https?:\/\/[^\s]+$/.test(o.crlUrl)) throw new ErreurAutorite("crlUrl : adresse http(s) attendue (AN-31)");
  if (!o.horloge || typeof o.horloge.murale !== "function") throw new TypeError("initialiserAutorite : horloge.murale() attendue");
  if (typeof o.aleatoire !== "function") throw new TypeError("initialiserAutorite : aleatoire(n) attendu");

  const chemins = Object.fromEntries(Object.entries(FICHIERS_AUTORITE).map(([k, f]) => [k, path.join(o.repertoire, f)]));
  fs.mkdirSync(o.repertoire, { recursive: true, mode: 0o700 });
  if (fs.existsSync(chemins.acCle) || fs.existsSync(chemins.uniteCle)) throw new ErreurAutorite(`${o.repertoire} : une autorité existe déjà, rien n'est écrasé`);

  const maintenant = Math.floor(o.horloge.murale() / 1000) * 1000;
  const sujetAc = construireNom(o.sujetAc ?? { O: "NOORTRACE developpement", CN: "AC interne de developpement" });
  const sujetUnite = construireNom(o.sujetUnite ?? { O: "NOORTRACE developpement", CN: "TSA interne non qualifiee" });

  const cleAc = genererCle(o.algorithme);
  const spkiAc = spkiDe(cleAc);
  const certAc = emettreCertificat({
    cleEmetteur: cleAc,
    emetteur: sujetAc,
    sujet: sujetAc,
    spki: spkiAc,
    serie: serieAleatoire(o.aleatoire),
    notBefore: maintenant,
    notAfter: maintenant + validiteAcJours * JOUR_MS,
    extensions: extensionsAc(spkiAc),
  });
  const cleUnite = genererCle(o.algorithme);
  const spkiUnite = spkiDe(cleUnite);
  const certUnite = emettreCertificat({
    cleEmetteur: cleAc,
    emetteur: sujetAc,
    sujet: sujetUnite,
    spki: spkiUnite,
    serie: serieAleatoire(o.aleatoire),
    notBefore: maintenant,
    notAfter: maintenant + validiteJours * JOUR_MS,
    extensions: extensionsUnite(spkiUnite, identifiantCle(spkiAc), o.crlUrl),
  });
  const crl = emettreCrl({
    cleEmetteur: cleAc,
    emetteur: sujetAc,
    identifiantCleEmetteur: identifiantCle(spkiAc),
    thisUpdate: maintenant,
    nextUpdate: maintenant + validiteCrlJours * JOUR_MS,
    numero: 1n,
    revoques: [],
  });

  const acPem = pem("CERTIFICATE", certAc);
  const unitePem = pem("CERTIFICATE", certUnite);
  const crlPem = pem("X509 CRL", crl);
  const descripteur = {
    version: 0,
    role: "interne",
    qualified: null,
    algorithm: o.algorithme,
    policy_oid: o.politique,
    accuracy_s: 1,
    crl_url: o.crlUrl,
    created_at: rfc3339(maintenant),
    unit_not_after: rfc3339(maintenant + validiteJours * JOUR_MS),
    ca_certificate_sha256: versHex(sha256(certAc)),
    unit_certificate_sha256: versHex(sha256(certUnite)),
    files: { ...FICHIERS_AUTORITE },
  };
  ecrireDurable(chemins.acCle, pemClePrivee(cleAc), 0o600);
  ecrireDurable(chemins.uniteCle, pemClePrivee(cleUnite), 0o600);
  ecrireDurable(chemins.ac, acPem, 0o644);
  ecrireDurable(chemins.unite, unitePem, 0o644);
  ecrireDurable(chemins.crl, crlPem, 0o644);
  ecrireDurable(chemins.crlNumero, "1\n", 0o600);
  ecrireDurable(chemins.descripteur, `${JSON.stringify(descripteur, null, 2)}\n`, 0o644);
  return { repertoire: o.repertoire, fichiers: chemins, acPem, unitePem, crlPem, descripteur };
}

/**
 * Republie la CRL de l'AC du répertoire (numéro incrémenté, `thisUpdate` à
 * l'instant de l'horloge, entrées révoquées données par l'exploitant).
 * @param {{repertoire: string, horloge: {murale: () => number}, validiteCrlJours?: number,
 *   revoques?: {serie: bigint, date: number, raison?: number|null}[]}} o
 */
export function publierCrl(o) {
  if (!o || typeof o.repertoire !== "string") throw new TypeError("publierCrl : repertoire attendu");
  if (!o.horloge || typeof o.horloge.murale !== "function") throw new TypeError("publierCrl : horloge.murale() attendue");
  const validiteCrlJours = o.validiteCrlJours ?? 30;
  if (!Number.isInteger(validiteCrlJours) || validiteCrlJours < 1) throw new ErreurAutorite("validiteCrlJours : entier ≥ 1 attendu");
  const chemins = Object.fromEntries(Object.entries(FICHIERS_AUTORITE).map(([k, f]) => [k, path.join(o.repertoire, f)]));
  const cleAc = lireClePrivee(fs.readFileSync(chemins.acCle));
  const certAc = lireCertificat(fs.readFileSync(chemins.ac));
  let numero = 0n;
  try {
    const t = fs.readFileSync(chemins.crlNumero, "utf8");
    if (!/^[0-9]+\n?$/.test(t)) throw new ErreurAutorite(`${chemins.crlNumero} : contenu illisible`);
    numero = BigInt(t.trim());
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  numero += 1n;
  const maintenant = Math.floor(o.horloge.murale() / 1000) * 1000;
  const crl = emettreCrl({
    cleEmetteur: cleAc,
    emetteur: certAc.sujet,
    identifiantCleEmetteur: identifiantCleSujet(certAc),
    thisUpdate: maintenant,
    nextUpdate: maintenant + validiteCrlJours * JOUR_MS,
    numero,
    revoques: o.revoques ?? [],
  });
  ecrireDurable(chemins.crlNumero, `${numero}\n`, 0o600);
  ecrireDurable(chemins.crl, pem("X509 CRL", crl), 0o644);
  return { chemin: chemins.crl, numero, thisUpdate: rfc3339(maintenant), nextUpdate: rfc3339(maintenant + validiteCrlJours * JOUR_MS), octets: crl };
}

/**
 * Charge l'autorité d'un répertoire initialisé : clé et certificat de
 * l'unité, politique du descripteur (ou donnée), compteur de série durable
 * du répertoire (sous-répertoire `compteur/`) ou compteur fourni.
 * @param {{repertoire: string, politique?: string, compteur?: object, inclureAc?: boolean, tsaDansJeton?: boolean, precisionS?: number}} o
 */
export function chargerAutorite(o) {
  if (!o || typeof o.repertoire !== "string") throw new TypeError("chargerAutorite : repertoire attendu");
  const chemins = Object.fromEntries(Object.entries(FICHIERS_AUTORITE).map(([k, f]) => [k, path.join(o.repertoire, f)]));
  let descripteur = null;
  try {
    descripteur = JSON.parse(fs.readFileSync(chemins.descripteur, "utf8"));
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const politique = o.politique ?? descripteur?.policy_oid;
  if (typeof politique !== "string") throw new ErreurAutorite("politique absente : ni option ni descripteur autorite.json");
  const compteur = o.compteur ?? Compteur.ouvrir({ repertoire: path.join(o.repertoire, "compteur") });
  try {
    return new Autorite({
      clePrivee: fs.readFileSync(chemins.uniteCle),
      certificat: fs.readFileSync(chemins.unite),
      chaine: o.inclureAc ? [fs.readFileSync(chemins.ac)] : [],
      politique,
      precisionS: o.precisionS ?? 1,
      compteur,
      tsaDansJeton: o.tsaDansJeton ?? true,
    });
  } catch (e) {
    if (!o.compteur) compteur.fermer();
    throw e;
  }
}
