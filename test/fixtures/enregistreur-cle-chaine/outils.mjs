// Outils des essais de l'étape 7 (clé de chaîne de classe B et C,
// rotation de la clé de chaîne relayée au registre ;
// test/enregistreur-cle-chaine-etape7*.test.js).
//
// Aucune clé réelle : chaque clé secp256k1 d'essai est dérivée au moment de
// l'essai de la mnémonique publique `test test … junk` (BIP-32,
// `m/44'/60'/0'/0/<i>`) et n'est écrite que sous le répertoire temporaire de
// l'essai ; la seule exception est la clé de classe B, engendrée par le KMS
// simulé (LocalStack) dans un conteneur détruit à la fin de l'essai : c'est
// le principe de la classe B (la clé ne quitte jamais le service), et
// LocalStack 4.0 n'importe pas de matière pour une clé `ECC_SECG_P256K1`
// (essayé : étiquette `_custom_key_material_` ignorée).

import fs from "node:fs";
import path from "node:path";
import { HDNodeWallet } from "ethers";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { contexteChiffrement } from "@noortrace/enregistreur";

/** Mnémonique publique des comptes d'essai de Hardhat (CT-4 EX-7.3, `hardhat:<i>`). */
export const MNEMONIQUE_ESSAI = "test test test test test test test test test test test junk";

/** Point d'accès AWS KMS de la région des essais (LocalStack rend des ARN `us-east-1`). */
export const SERVICE_KMS_ESSAI = "https://kms.us-east-1.amazonaws.com";

/**
 * Clé secp256k1 d'essai dérivée de la mnémonique publique à l'indice donné.
 * @param {number} indice
 * @returns {{octets: Uint8Array, adresse: string, signataire: R.SignataireChaineFichier, indice: number}}
 */
export function cleEssai(indice) {
  const w = HDNodeWallet.fromPhrase(MNEMONIQUE_ESSAI, undefined, `m/44'/60'/0'/0/${indice}`);
  const octets = N.hexVersOctets(w.privateKey, 32);
  const signataire = new R.SignataireChaineFichier(octets);
  return { octets, adresse: signataire.adresse(), signataire, indice };
}

/**
 * Indice de dérivation propre à une exécution (une clé de chaîne ne s'inscrit
 * qu'une fois et ne se réinscrit jamais, CT-4 EX-8.8 : le réseau de
 * développement garde les inscriptions des exécutions précédentes).
 * @param {number} decalage
 */
export function indiceExecution(decalage = 0) {
  return 1000000 + (Math.floor(Date.now() / 1000) % 100000000) * 4 + decalage;
}

/**
 * Cérémonie de classe C d'essai : enveloppe le scalaire de 32 octets par AWS
 * KMS `Encrypt` (LocalStack), contexte `org_id`, `journal_id`, `key_id` =
 * adresse (lecture de l'étape 7) ; rend le `CiphertextBlob` brut.
 * @param {{client: object}} kms rendu de `demarrerKmsLocalStack`
 */
export async function envelopperCleChaine(kms, arn, octets, { org_id, journal_id, adresse }) {
  const r = await kms.client.appeler("Encrypt", { KeyId: arn, Plaintext: Buffer.from(octets).toString("base64"), EncryptionContext: contexteChiffrement({ org_id, journal_id, key_id: adresse }).carte });
  return new Uint8Array(Buffer.from(r.CiphertextBlob, "base64"));
}

/** Clé `ECC_SECG_P256K1` (`SIGN_VERIFY`) créée dans le KMS simulé ; rend `{ arn, adresse }`. */
export async function creerCleKmsSecp256k1(kms, keySpec = "ECC_SECG_P256K1") {
  const k = await kms.client.appeler("CreateKey", { KeySpec: keySpec, KeyUsage: "SIGN_VERIFY" });
  const p = await kms.client.appeler("GetPublicKey", { KeyId: k.KeyMetadata.Arn });
  if (keySpec !== "ECC_SECG_P256K1") return { arn: k.KeyMetadata.Arn, adresse: null };
  const { createPublicKey } = await import("node:crypto");
  const jwk = createPublicKey({ key: Buffer.from(p.PublicKey, "base64"), format: "der", type: "spki" }).export({ format: "jwk" });
  const publique = Uint8Array.of(4, ...Buffer.from(jwk.x, "base64url"), ...Buffer.from(jwk.y, "base64url"));
  return { arn: k.KeyMetadata.Arn, adresse: R.adresseDepuisClePublique(publique) };
}

/** Écrit un secret d'essai lisible de son seul propriétaire ; rend son chemin. */
export function ecrireSecret(dir, nom, contenu) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = path.join(dir, nom);
  fs.writeFileSync(f, contenu, { mode: 0o600 });
  return f;
}

/** Signatures au seuil d'un condensé interne par des approbateurs (RG-12, RG-13 : rangées par adresse). */
function signerAuSeuil(condense, approbateurs, seuil) {
  const h = R.hachageSigne(condense);
  return approbateurs.slice(0, seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(h) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
}

/**
 * Demande d'inscription (CT-4 §7.7, `demande_signature`, `inscription`)
 * signée au seuil, à déposer sous `<journal>/registre/demande-inscription-<adresse>.json`.
 * @param {{evmChainId: number, recorderRegistry: string, orgId: string, journalId: string, chainKey: string, ed25519: string,
 *   approbateurs: R.SignataireChaineFichier[], seuil: number, signerSet: object, preparedAt: string}} o
 */
export function demandeInscription(o) {
  const fields = { org_id: o.orgId, journal_id: o.journalId, chain_key: o.chainKey, ed25519_public_key: o.ed25519 };
  const digest = R.registerDigest(o.evmChainId, o.recorderRegistry, o.orgId, o.journalId, o.chainKey, o.ed25519);
  return {
    version: 0, operation: "inscription", evm_chain_id: o.evmChainId, contract: o.recorderRegistry, fields, digest,
    eip191_digest: N.octetsVersHex(R.hachageSigne(digest)), signer_set: { ...o.signerSet }, signatures: signerAuSeuil(digest, o.approbateurs, o.seuil), prepared_at: o.preparedAt,
  };
}

/**
 * Demande de révocation (CT-4 §8.4, EX-8.7 : `registered_at` lu dans
 * `recorderOf`) signée au seuil, à déposer sous `<journal>/registre/demande-revocation-<adresse>.json`.
 */
export function demandeRevocation(o) {
  const registeredAt = String(o.registeredAt);
  const fields = { org_id: o.orgId, chain_key: o.chainKey, registered_at: registeredAt };
  const digest = R.revokeDigestEnregistreur(o.evmChainId, o.recorderRegistry, o.orgId, o.chainKey, registeredAt);
  return {
    version: 0, operation: "revocation", evm_chain_id: o.evmChainId, contract: o.recorderRegistry, fields, digest,
    eip191_digest: N.octetsVersHex(R.hachageSigne(digest)), signer_set: { ...o.signerSet }, signatures: signerAuSeuil(digest, o.approbateurs, o.seuil), prepared_at: o.preparedAt,
  };
}

/** Dépose une demande là où le démon la lit (`<journal>/registre/demande-<operation>-<adresse>.json`). */
export function deposerDemande(repertoireJournal, demande) {
  const dir = path.join(repertoireJournal, "registre");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = path.join(dir, `demande-${demande.operation}-${demande.fields.chain_key}.json`);
  fs.writeFileSync(f, JSON.stringify(demande, null, 2));
  return f;
}

/** Événements de la chaîne relus dans les segments (outil des essais : `execution.tool` de chaque événement). */
export function outilsDesEvenements(repertoireJournal) {
  const dir = path.join(repertoireJournal, "segments");
  const outils = [];
  for (const n of fs.existsSync(dir) ? fs.readdirSync(dir).filter((x) => x.endsWith(".ndjson")).sort() : []) {
    for (const l of fs.readFileSync(path.join(dir, n), "utf8").split("\n")) {
      if (!l.trim()) continue;
      try {
        const e = JSON.parse(l);
        if (e?.execution?.tool) outils.push(e.execution.tool);
      } catch {
        // ligne incomplète : ignorée
      }
    }
  }
  return outils;
}
