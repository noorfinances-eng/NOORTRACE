// Cérémonie des clés CLE-1 et CLE-2 du banc « client fictif » (CT-8 IC-7,
// CT-7 §5.4 à §5.6) : graine Ed25519 de l'enregistreur et scalaire secp256k1
// de la clé de chaîne, tirés du mnémonique public au moment de l'essai,
// enveloppés par le KMS simulé (classe C, `Encrypt` sous le contexte
// `org_id`, `journal_id`, `key_id`), condensé d'essai signé par la clé de
// chaîne et adresse recouvrée (CT-7 §5.4, pas 6), puis procès-verbal
// `ceremonie-cles-v0` signé par les trois participants (comptes du mnémonique
// public), que `npm run verify:ceremonie` vérifie (CR-1 à CR-12).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { HDNodeWallet } from "ethers";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { ClientKms, contexteChiffrement } from "@noortrace/enregistreur";
import { MNEMONIQUE_ESSAI } from "../enregistreur-cle-chaine/outils.mjs";

/** Compte `i` du mnémonique public : `{ adresse, cle }`. */
export function compteMnemonique(i) {
  const w = HDNodeWallet.fromPhrase(MNEMONIQUE_ESSAI, undefined, `m/44'/60'/0'/0/${i}`);
  return { adresse: w.address.toLowerCase(), cle: N.hexVersOctets(w.privateKey, 32), publique: N.hexVersOctets(w.signingKey.publicKey, 65) };
}

const sha = (o) => `0x${crypto.createHash("sha256").update(o).digest("hex")}`;

/**
 * Clés du journal de production du banc, dérivées du mnémonique public à
 * l'indice `indice` (clé de chaîne : compte `indice` ; graine Ed25519 :
 * SHA-256 de « noortrace/banc-client/ed25519/ » suivi de la clé du compte
 * `indice + 1`). Une clé de chaîne ne s'inscrit qu'une fois sur le réseau de
 * développement : l'indice change à chaque exécution.
 */
export function clesJournal(indice) {
  const chaine = compteMnemonique(indice);
  const graine = N.sha256(Buffer.concat([Buffer.from("noortrace/banc-client/ed25519/", "utf8"), Buffer.from(compteMnemonique(indice + 1).cle)]));
  const signataire = new R.SignataireChaineFichier(chaine.cle);
  return { indice, graine, clePublique: N.clePubliqueEd25519(graine), chaine: { octets: chaine.cle, adresse: signataire.adresse(), publique: chaine.publique, signataire } };
}

/**
 * Enveloppes de classe C par le KMS (point d'accès du banc) : clé
 * symétrique créée, graine et scalaire chiffrés sous leur contexte.
 * @param {{origineKms: string, region: string, identifiants: object, orgId: string, journalId: string, keyId: string, cles: object}} o
 */
export async function envelopper({ origineKms, region, env, orgId, journalId, keyId, cles }) {
  const client = new ClientKms({ region, env: { ...env, AWS_ENDPOINT_URL_KMS: origineKms }, delaiMs: 20000 });
  const arn = (await client.appeler("CreateKey", { KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", Description: "enveloppes CLE-1 et CLE-2 du banc client fictif" })).KeyMetadata.Arn;
  const chiffrer = async (octets, kid) => Buffer.from((await client.appeler("Encrypt", {
    KeyId: arn, Plaintext: Buffer.from(octets).toString("base64"), EncryptionContext: contexteChiffrement({ org_id: orgId, journal_id: journalId, key_id: kid }).carte,
  })).CiphertextBlob, "base64");
  const graineScellee = await chiffrer(cles.graine, keyId);
  const chaineScellee = await chiffrer(cles.chaine.octets, cles.chaine.adresse);
  // CT-7 §5.4, pas 6 : condensé d'essai signé par la clé de chaîne, adresse recouvrée.
  const condenseEssai = N.sha256(N.utf8(`noortrace/banc-client/ceremonie/condense-essai/${orgId}/${journalId}`));
  const sig = cles.chaine.signataire.signerCondense(condenseEssai);
  const recouvree = R.recouvrerSignataire(condenseEssai, sig);
  return { arn, graineScellee, chaineScellee, condenseEssai: N.octetsVersHex(condenseEssai), signatureEssai: sig, adresseRecouvree: recouvree };
}

/**
 * Procès-verbal `ceremonie-cles-v0` de la cérémonie, signé par les
 * participants (comptes 5, 6 et 7 du mnémonique public : officiant, témoin,
 * auditeur). `condenser(fichier)` rend le condensé que calcule l'outil du
 * dépôt (`--condense`), en boîte noire.
 */
export async function procesVerbal({ dir, org, orgId, keyId, cles, debut, fin, condenser, journalPoste }) {
  const p = [5, 6, 7].map(compteMnemonique);
  const t = (min) => new Date(debut.getTime() + min * 60000).toISOString().replace(/\.\d{3}Z$/, ".000Z");
  const script = "Création de CLE-1 (graine Ed25519 de l'enregistreur) et de CLE-2 (clé de chaîne secp256k1), enveloppées par le KMS du client (classe C)";
  const pv = {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: `cer-banc-${debut.toISOString().slice(0, 10)}-01`,
    scope: "client",
    organization: { name: org, org_id: orgId },
    purpose: "creation",
    purpose_details: null,
    environment: "production",
    place: "Banc client fictif (environnement de construction), poste de cérémonie simulé",
    started_at: t(0),
    ended_at: fin.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
    script: { title: script, version: "1", sha256: sha(Buffer.from(script, "utf8")) },
    workstation: { description: "Poste de cérémonie du banc : processus du harnais, sans autre réseau que le KMS simulé du banc", offline: true, image_sha256: sha(fs.readFileSync(process.execPath)) },
    entropy: { source: "systeme_du_poste", description: "Clés d'essai dérivées du mnémonique public au moment de l'essai (sans valeur hors du banc)" },
    participants: [
      { id: "p1", name: "Officiant (compte d'essai 5)", role: "officiant", affiliation: `${org}, exploitation`, address: p[0].adresse },
      { id: "p2", name: "Témoin (compte d'essai 6)", role: "temoin", affiliation: `${org}, sécurité`, address: p[1].adresse },
      { id: "p3", name: "Auditeur (compte d'essai 7)", role: "auditeur", affiliation: "cabinet d'audit (exemple)", address: p[2].adresse },
    ],
    steps: [
      { n: 1, action: "Lire le script et comparer son SHA-256 à celui publié avant la cérémonie", performed_by: "p1", witnessed_by: ["p2", "p3"], at: t(0), outcome: "fait" },
      { n: 2, action: "Tirer la graine Ed25519 de l'enregistreur et la chiffrer par le KMS sous le contexte (org_id, journal_id, key_id)", performed_by: "p1", witnessed_by: ["p2"], at: t(0), outcome: "fait" },
      { n: 3, action: "Lire la clé publique Ed25519, calculer son SHA-256 et l'afficher à tous", performed_by: "p1", witnessed_by: ["p2", "p3"], at: t(0), outcome: "fait" },
      { n: 4, action: "Tirer le scalaire secp256k1 de la clé de chaîne, le chiffrer par le KMS sous le contexte (org_id, journal_id, adresse), signer un condensé d'essai et recouvrer l'adresse", performed_by: "p1", witnessed_by: ["p2"], at: t(0), outcome: "fait" },
      { n: 5, action: "Effacer les clés en clair du poste ; remettre les seules enveloppes aux secrets du démon", performed_by: "p1", witnessed_by: ["p2", "p3"], at: t(0), outcome: "fait" },
    ],
    keys: [
      {
        key_id: keyId, usage: "enregistreur", algorithm: "ed25519", generated_in: "poste", custody_class: "C", backend: "envelope + aws-kms",
        public_key: N.octetsVersHex(cles.clePublique), fingerprint: sha(Buffer.from(cles.clePublique)), address: null, origin_proof_sha256: null,
        backup: { scheme: "aucune", k: null, n: null, holders: [] },
      },
      {
        key_id: `chaine-${keyId}`, usage: "chaine", algorithm: "secp256k1", generated_in: "poste", custody_class: "C", backend: "envelope + aws-kms",
        public_key: N.octetsVersHex(cles.chaine.publique), fingerprint: sha(Buffer.from(cles.chaine.publique)), address: cles.chaine.adresse, origin_proof_sha256: null,
        backup: { scheme: "aucune", k: null, n: null, holders: [] },
      },
    ],
    records: [{ kind: "journal_poste", name: "journal-poste.txt", sha256: sha(Buffer.from(journalPoste, "utf8")) }],
    findings: [],
    signatures: [],
  };
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, "journal-poste.txt"), journalPoste);
  const fichier = path.join(dir, "proces-verbal-ceremonie.json");
  fs.writeFileSync(fichier, `${JSON.stringify(pv, null, 2)}\n`);
  const condense = await condenser(fichier);
  pv.signatures = p.map((c, k) => ({ participant: `p${k + 1}`, signature: N.octetsVersHex(N.signerEip191(c.cle, N.hexVersOctets(condense, 32))) }));
  fs.writeFileSync(fichier, `${JSON.stringify(pv, null, 2)}\n`);
  return { fichier, pv, condense };
}
