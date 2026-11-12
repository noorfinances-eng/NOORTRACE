// Clé de chaîne de l'enregistreur (CT-2 EX-11.19 ; étape 7, D-10) : la clé
// secp256k1 sous laquelle la clé Ed25519 est inscrite au registre, qui signe
// les ancres et relaie les clôtures. Ce module construit, depuis
// `anchoring.registry.chain_key` (et `next_chain_key`), un `SignataireChaine`
// du composant d'ancrage (`@noortrace/ancrage/registre`) selon la classe de
// garde de CT-2 §11.2. Le schéma de configuration ne porte que `class`,
// `address`, `secret` et `service_url` (https ou nul) ; la lecture de ces
// membres par classe est celle-ci (LISEZMOI, lectures de l'étape 7) :
//
// - **D** (fichier, développement) : `secret` résout la clé en clair
//   (`SignataireChaineFichier`) ; refusée en production par la validation.
// - **C** (enveloppe) : `secret` résout le `CiphertextBlob` brut d'AWS KMS
//   `Encrypt` du scalaire de 32 octets ; `service_url` est le point d'accès du
//   KMS de la région (`https://kms.<région>.amazonaws.com` ; la région est lue
//   dans le nom, et les requêtes vont à `service_url`, remplacé comme pour le
//   signataire par `AWS_ENDPOINT_URL_KMS` ou `AWS_ENDPOINT_URL`) ; le
//   contexte de chiffrement est `org_id`, `journal_id` et `key_id` = l'adresse
//   déclarée (EX-11.9 : rien de sensible) ; identité IAM du démon
//   (`AWS_ACCESS_KEY_ID`…, fichier `AWS_CONFIG_FILE` monté comme secret en
//   production, ou IMDSv2). Le scalaire est déchiffré au démarrage
//   dans la mémoire du démon, qui signe lui-même, et effacé à l'arrêt.
// - **B** (service de signature) : clé AWS KMS `ECC_SECG_P256K1`
//   (`SIGN_VERIFY`, `ECDSA_SHA_256`) ; `service_url` est le point d'accès du
//   KMS, `secret` résout l'ARN de la clé (l'accès au service qui la détient,
//   description du schéma) ; chaque condensé est signé par `Sign`
//   (`MessageType: DIGEST`), la signature DER ramenée à `s` bas et `v`
//   recouvré ; la clé ne quitte jamais le service.
// - **A** (module matériel) : non servie ; le schéma n'a aucun membre pour un
//   module PKCS#11 (bibliothèque, jeton, étiquette, code PIN) et `service_url`
//   n'admet que `https://` ; refus nommé (`classe_cle_chaine`).
//
// Dans chaque classe, l'adresse dérivée de la clé publique est confrontée à
// `address` avant tout usage (une adresse différente refuse le démarrage), et
// un condensé d'essai est signé puis recouvert (CT-7 §5.4, pas 6, épreuve du
// support de secp256k1 par le backend).

import { createPublicKey, randomBytes } from "node:crypto";
import { SignataireChaine, SignataireChaineFichier, adresseDepuisClePublique, recouvrerSignataire, signatureDepuisDer } from "@noortrace/ancrage/registre";
import { ClientKms, regionArn } from "./signataires/aws-kms.mjs";
import { base64Strict, contexteChiffrement, ErreurSignataire } from "./signataires/commun.mjs";

/** Classes de garde de la clé de chaîne servies (CT-2 EX-11.19 ; étape 7). */
export const CLASSES_CLE_CHAINE_SERVIES = Object.freeze(["B", "C", "D"]);

/**
 * Point d'accès d'AWS KMS (seul service désigné par `service_url` en classes B
 * et C) : `https://kms.<région>.<domaine>` ou `https://kms-fips.<région>.<domaine>`,
 * sans chemin ni identifiants ; la région est lue dans le nom. Le domaine est
 * `amazonaws.com` (ou `.cn`) en exploitation ; un domaine réservé (`.example`)
 * dans le modèle de production, que l'exploitant remplace (étape 7).
 */
export const MOTIF_SERVICE_KMS = /^https:\/\/kms(?:-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]{2,63})(?::[0-9]{1,5})?\/?$/;

/** Refus de construire une clé de chaîne ; `raison` : `classe_cle_chaine` ou `cle_chaine`. */
export class ErreurCleChaine extends Error {
  constructor(raison, message) {
    super(message);
    this.name = "ErreurCleChaine";
    this.raison = raison;
  }
}

const condenseEssai = () => new Uint8Array(randomBytes(32));

/** Clé publique secp256k1 non compressée (65 octets) d'un SubjectPublicKeyInfo DER. */
function clePubliqueSecp256k1Spki(der) {
  let jwk;
  try {
    jwk = createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" }).export({ format: "jwk" });
  } catch {
    throw new ErreurSignataire("clé publique : SubjectPublicKeyInfo illisible");
  }
  if (jwk.kty !== "EC" || jwk.crv !== "secp256k1") throw new ErreurSignataire(`clé publique ${jwk.crv ?? jwk.kty} : secp256k1 attendue`);
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32) throw new ErreurSignataire("clé publique secp256k1 : coordonnées de 32 octets attendues");
  return Uint8Array.of(0x04, ...x, ...y);
}

/**
 * Classe B : clé `ECC_SECG_P256K1` d'AWS KMS, qui ne quitte jamais le
 * service. `signerCondense` appelle `Sign` (`MessageType: DIGEST`,
 * `ECDSA_SHA_256`) sur le condensé tel quel ; la signature DER rendue est
 * ramenée à `s` bas et `v` est trouvé en recouvrant l'adresse.
 */
export class SignataireChaineKms extends SignataireChaine {
  #adresse;

  /** @param {{client: ClientKms, keyArn: string, adresse: string}} p */
  constructor(p) {
    super();
    this.client = p.client;
    this.keyArn = p.keyArn;
    this.#adresse = p.adresse;
  }

  /**
   * Lit la clé publique (`GetPublicKey`) et contrôle sa forme.
   * @param {{client: ClientKms, keyArn: string}} p
   */
  static async charger(p) {
    const r = await p.client.appeler("GetPublicKey", { KeyId: p.keyArn });
    if (r.KeySpec !== "ECC_SECG_P256K1") throw new ErreurSignataire(`clé KMS ${r.KeySpec} : ECC_SECG_P256K1 attendue (EX-11.19)`, { code: "type" });
    if (r.KeyUsage !== "SIGN_VERIFY") throw new ErreurSignataire(`clé KMS d'usage ${r.KeyUsage} : SIGN_VERIFY attendu`, { code: "usage" });
    if (!Array.isArray(r.SigningAlgorithms) || !r.SigningAlgorithms.includes("ECDSA_SHA_256")) throw new ErreurSignataire("clé KMS sans ECDSA_SHA_256", { code: "type" });
    const publique = clePubliqueSecp256k1Spki(base64Strict(r.PublicKey, "PublicKey"));
    return new SignataireChaineKms({ client: p.client, keyArn: p.keyArn, adresse: adresseDepuisClePublique(publique) });
  }

  get classe() {
    return "B";
  }

  adresse() {
    return this.#adresse;
  }

  async signerCondense(hash32) {
    if (!(hash32 instanceof Uint8Array) || hash32.length !== 32) throw new TypeError("condensé de 32 octets attendu");
    const r = await this.client.appeler("Sign", {
      KeyId: this.keyArn,
      Message: Buffer.from(hash32).toString("base64"),
      MessageType: "DIGEST",
      SigningAlgorithm: "ECDSA_SHA_256",
    });
    if (r.SigningAlgorithm !== undefined && r.SigningAlgorithm !== "ECDSA_SHA_256") throw new ErreurSignataire(`algorithme rendu ${r.SigningAlgorithm}`);
    return signatureDepuisDer(hash32, base64Strict(r.Signature, "Signature"), this.#adresse);
  }

  /** Lieu de la clé pour le journal d'exploitation (aucun secret). */
  localisation() {
    return { service: "aws-kms", key_arn: this.keyArn, region: this.client.region };
  }

  effacer() {}

  toJSON() {
    return { classe: "B", adresse: this.#adresse, service: "aws-kms" };
  }

  toString() {
    return `SignataireChaineKms(${this.#adresse})`;
  }
}

/**
 * Classe C : scalaire secp256k1 de 32 octets déchiffré au démarrage par le
 * KMS (EX-11.9), tenu dans la mémoire du démon par un `SignataireChaineFichier`
 * privé, effacé par `effacer()` à l'arrêt.
 */
export class SignataireChaineEnveloppe extends SignataireChaine {
  #interne;
  #lieu;

  /** @param {{interne: SignataireChaineFichier, lieu: object}} p */
  constructor(p) {
    super();
    this.#interne = p.interne;
    this.#lieu = p.lieu;
  }

  /**
   * Déchiffre l'enveloppe par AWS KMS `Decrypt` (`SYMMETRIC_DEFAULT`, contexte
   * de chiffrement de l'adresse) ; le texte clair est effacé dès la clé construite.
   * @param {{client: ClientKms, chiffre: Uint8Array, org_id: string, journal_id: string, adresse: string}} p
   */
  static async dechiffrer(p) {
    const contexte = contexteChiffrement({ org_id: p.org_id, journal_id: p.journal_id, key_id: p.adresse });
    const r = await p.client.appeler("Decrypt", {
      CiphertextBlob: Buffer.from(p.chiffre).toString("base64"),
      EncryptionContext: contexte.carte,
      EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
    });
    const clair = base64Strict(r.Plaintext, "Plaintext");
    try {
      if (clair.length !== 32) throw new ErreurSignataire(`scalaire de ${clair.length} octets : 32 attendus (EX-11.9)`, { code: "graine" });
      const interne = new SignataireChaineFichier(clair);
      return new SignataireChaineEnveloppe({ interne, lieu: { service: "aws-kms", key_arn: typeof r.KeyId === "string" ? r.KeyId : null, region: p.client.region } });
    } finally {
      clair.fill(0);
    }
  }

  get classe() {
    return "C";
  }

  adresse() {
    return this.#interne.adresse();
  }

  signerCondense(hash32) {
    return this.#interne.signerCondense(hash32);
  }

  localisation() {
    return { ...this.#lieu };
  }

  effacer() {
    this.#interne.effacer();
  }

  toJSON() {
    return { classe: "C", adresse: this.#interne.adresse(), service: this.#lieu.service };
  }

  toString() {
    return `SignataireChaineEnveloppe(${this.#interne.adresse()})`;
  }
}

/** Classe D sous la même interface (effacement, localisation). */
class SignataireChaineFichierDemon extends SignataireChaine {
  #interne;

  constructor(interne) {
    super();
    this.#interne = interne;
  }

  get classe() {
    return "D";
  }

  adresse() {
    return this.#interne.adresse();
  }

  signerCondense(hash32) {
    return this.#interne.signerCondense(hash32);
  }

  localisation() {
    return { service: "fichier" };
  }

  effacer() {
    this.#interne.effacer();
  }

  toJSON() {
    return this.#interne.toJSON();
  }
}

/** Région d'AWS KMS de `service_url`, ou null. */
export function regionServiceKms(url) {
  const m = typeof url === "string" ? MOTIF_SERVICE_KMS.exec(url) : null;
  return m ? m[1] : null;
}

/**
 * Origine des requêtes au KMS : `AWS_ENDPOINT_URL_KMS` ou `AWS_ENDPOINT_URL`
 * (variables des kits d'AWS, bancs d'essai) s'ils sont posés, sinon
 * `service_url` lui-même.
 * @param {string} url `service_url` conforme à MOTIF_SERVICE_KMS
 * @param {NodeJS.ProcessEnv} env
 */
export function origineServiceKms(url, env) {
  return (env.AWS_ENDPOINT_URL_KMS || env.AWS_ENDPOINT_URL || url).replace(/\/+$/, "");
}

/**
 * Construit le signataire d'une clé de chaîne (`chain_key` ou
 * `next_chain_key`) depuis son secret résolu ; contrôle l'adresse et signe un
 * condensé d'essai qu'il recouvre. Lève `ErreurCleChaine` (`classe_cle_chaine`
 * pour une classe non servie, `cle_chaine` sinon) ; le message ne porte
 * jamais le secret.
 * @param {{class: string, address: string, service_url: string|null}} ck
 * @param {{secret: Uint8Array|null, org_id: string, journal_id: string, env?: NodeJS.ProcessEnv, delaiMs?: number, ca?: Buffer|string|null, membre?: string}} o
 * @returns {Promise<SignataireChaine>}
 */
export async function chargerCleChaine(ck, o) {
  const membre = o.membre ?? "chain_key";
  const ici = `anchoring.registry.${membre}`;
  const env = o.env ?? process.env;
  const delaiMs = o.delaiMs ?? 5000;
  if (!CLASSES_CLE_CHAINE_SERVIES.includes(ck.class)) {
    throw new ErreurCleChaine("classe_cle_chaine", `clé de chaîne de classe ${ck.class} (${ici}) : non servie ; classes servies ${CLASSES_CLE_CHAINE_SERVIES.join(", ")} (CT-2 EX-11.19). La classe A (module matériel) n'a pas de backend : le schéma de ${ici} ne porte ni module PKCS#11 ni étiquette (service_url https seulement)`);
  }
  if (!(o.secret instanceof Uint8Array)) throw new ErreurCleChaine("cle_chaine", `secret de la clé de chaîne non résolu (${ici}.secret)`);
  let signataire;
  try {
    if (ck.class === "D") {
      signataire = new SignataireChaineFichierDemon(SignataireChaineFichier.depuisOctets(o.secret));
    } else {
      const region = regionServiceKms(ck.service_url);
      if (!region) throw new ErreurCleChaine("cle_chaine", `classe ${ck.class} : ${ici}.service_url doit désigner AWS KMS (https://kms.<région>.amazonaws.com), seul service servi ; reçu ${ck.service_url === null ? "null" : "une autre URL"}`);
      const client = new ClientKms({ region, env, delaiMs, ca: o.ca ?? null, origine: origineServiceKms(ck.service_url, env) });
      if (ck.class === "C") {
        signataire = await SignataireChaineEnveloppe.dechiffrer({ client, chiffre: o.secret, org_id: o.org_id, journal_id: o.journal_id, adresse: ck.address });
      } else {
        const arn = Buffer.from(o.secret).toString("utf8").trim();
        if (!/^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:(key|alias)\/[A-Za-z0-9/_-]+$/.test(arn)) throw new ErreurCleChaine("cle_chaine", `classe B : ${ici}.secret doit résoudre l'ARN de la clé KMS`);
        if (regionArn(arn) !== region) throw new ErreurCleChaine("cle_chaine", `classe B : région de l'ARN différente de celle de ${ici}.service_url`);
        signataire = await SignataireChaineKms.charger({ client, keyArn: arn });
      }
    }
  } catch (e) {
    if (e instanceof ErreurCleChaine) throw e;
    throw new ErreurCleChaine("cle_chaine", `clé de chaîne de classe ${ck.class} illisible (${ici}) : ${String(e?.message ?? e).slice(0, 160)}`);
  }
  if (signataire.adresse() !== String(ck.address).toLowerCase()) {
    signataire.effacer?.();
    throw new ErreurCleChaine("cle_chaine", `adresse de la clé de chaîne différente de ${ici}.address (${ck.address}) : le backend tient ${signataire.adresse()}`);
  }
  // Épreuve du support de secp256k1 (CT-7 §5.4, pas 6) : un condensé d'essai signé et recouvert.
  const h = condenseEssai();
  let sig;
  try {
    sig = await signataire.signerCondense(h);
  } catch (e) {
    signataire.effacer?.();
    throw new ErreurCleChaine("cle_chaine", `clé de chaîne (${ici}) : signature d'essai impossible : ${String(e?.message ?? e).slice(0, 160)}`);
  }
  if (recouvrerSignataire(h, sig) !== signataire.adresse()) {
    signataire.effacer?.();
    throw new ErreurCleChaine("cle_chaine", `clé de chaîne (${ici}) : la signature d'essai ne recouvre pas l'adresse`);
  }
  return signataire;
}
