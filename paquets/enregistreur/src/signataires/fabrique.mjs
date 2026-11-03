// Fabrique des signataires (CT-2 §11, EX-15.4 pas 5) : le backend de
// `signer.backend.type`, classes A à D. La cohérence classe/backend et le
// refus de la classe D en production sont vérifiés au pas 3
// (configuration.mjs) ; ils le sont de nouveau ici, au cas où un appelant
// construirait un signataire sans passer par la validation.

import fs from "node:fs";
import { BACKENDS_PAR_CLASSE, SignataireFichier } from "../signataires.mjs";
import { ErreurSignataire } from "./commun.mjs";
import { SignatairePkcs11 } from "./pkcs11.mjs";
import { SignataireTransit } from "./transit.mjs";
import { ClientKms, SignataireAwsKms, desenvelopperAwsKms, regionArn } from "./aws-kms.mjs";
import { ClientCloudKms, SignataireCloudKms, desenvelopperCloudKms } from "./gcp-kms.mjs";
import { JetonAzure, desenvelopperAzure, porteeAzure } from "./azure.mjs";
import { desceller } from "./tpm2.mjs";
import { SignataireEnveloppe } from "./enveloppe.mjs";

/** Noms des variables d'environnement désignées par une référence de secret `{ "env" }` de la configuration. */
export function variablesSecretes(config) {
  const noms = new Set();
  const parcourir = (v) => {
    if (Array.isArray(v)) return v.forEach(parcourir);
    if (v === null || typeof v !== "object") return;
    if (typeof v.env === "string" && Object.keys(v).every((k) => ["env", "encoding"].includes(k))) noms.add(v.env);
    for (const x of Object.values(v)) parcourir(x);
  };
  parcourir(config);
  return noms;
}

/**
 * Environnement d'un auxiliaire (module PKCS#11, outils TPM) : celui du démon
 * sans les variables qui portent un secret de la configuration (EX-15.3 : un
 * secret n'est jamais transmis à un processus enfant).
 */
export function environnementAuxiliaire(config, env) {
  const exclues = variablesSecretes(config);
  return Object.fromEntries(Object.entries(env).filter(([k, v]) => v !== undefined && !exclues.has(k)));
}

/**
 * Construit le backend du signataire de la configuration.
 * @param {object} config document validé
 * @param {Map<string, Uint8Array>} secrets secrets résolus (pas 4)
 * @param {{env?: NodeJS.ProcessEnv, ca?: Buffer|string|null, python?: string}} [o] `ca` : autorité supplémentaire des essais
 * @returns {Promise<import("../signataires.mjs").Signataire>}
 */
export async function signataireDepuisConfiguration(config, secrets, o = {}) {
  const s = config.signer;
  const b = s.backend;
  const env = o.env ?? process.env;
  if (!BACKENDS_PAR_CLASSE[s.class]?.includes(b.type)) throw new ErreurSignataire(`backend ${b.type} incohérent avec la classe ${s.class} (EX-11.8)`);
  const commun = { keyId: s.key_id, nextKeyId: s.rotation?.next_key_id ?? null };
  const delaiMs = s.timeout_ms ?? 5000;
  const ca = o.ca ?? null;
  const secret = (p) => {
    const v = secrets.get(p);
    if (!v) throw new ErreurSignataire(`${p} : secret non résolu`);
    return v;
  };
  switch (b.type) {
    case "file":
      return SignataireFichier.charger({
        environment: config.recorder.environment,
        keyId: s.key_id,
        chemin: b.path,
        nextKeyId: commun.nextKeyId,
        phrase: secrets.get("/signer/backend/passphrase") ?? null,
      });
    case "pkcs11":
      return new SignatairePkcs11({ ...commun, backend: b, pin: secret("/signer/backend/pin"), delaiMs, env: environnementAuxiliaire(config, env), python: o.python });
    case "vault-transit":
    case "openbao-transit":
      return new SignataireTransit({ ...commun, backend: b, jeton: secret("/signer/backend/token"), delaiMs, ca });
    case "aws-kms":
      if (regionArn(b.key_arn) !== b.region) throw new ErreurSignataire("signer.backend.region différente de la région de key_arn");
      return new SignataireAwsKms({ ...commun, backend: b, client: new ClientKms({ region: b.region, env, delaiMs, ca }) });
    case "gcp-kms":
      return new SignataireCloudKms({ ...commun, backend: b, client: new ClientCloudKms({ env, delaiMs, ca }) });
    case "envelope":
      return SignataireEnveloppe.charger({
        ...commun,
        backend: b,
        org_id: config.recorder.org_id,
        journal_id: config.recorder.journal_id,
        desenvelopper: desenveloppeur(b.wrap, { config, env, delaiMs, ca }),
      });
    default:
      throw new ErreurSignataire(`backend ${b.type} inconnu`);
  }
}

/** Fonction de déchiffrement de la graine selon `signer.backend.wrap.type`. */
function desenveloppeur(wrap, o) {
  switch (wrap.type) {
    case "aws-kms": {
      if (regionArn(wrap.key_arn) !== wrap.region) throw new ErreurSignataire("signer.backend.wrap.region différente de la région de key_arn");
      const client = new ClientKms({ region: wrap.region, env: o.env, delaiMs: o.delaiMs, ca: o.ca });
      return (q) => desenvelopperAwsKms({ ...q, client });
    }
    case "gcp-kms": {
      const client = new ClientCloudKms({ env: o.env, delaiMs: o.delaiMs, ca: o.ca });
      return (q) => desenvelopperCloudKms({ ...q, client });
    }
    case "azure-keyvault": {
      const jeton = new JetonAzure({ portee: porteeAzure(wrap.vault_url), env: o.env, delaiMs: o.delaiMs, ca: o.ca });
      return (q) => desenvelopperAzure({ ...q, jeton, delaiMs: o.delaiMs, ca: o.ca });
    }
    case "tpm2":
      for (const f of [wrap.public_file, wrap.private_file]) {
        if (!fs.existsSync(f)) throw new ErreurSignataire("objet scellé TPM 2.0 introuvable (public_file, private_file)", { code: "fichier" });
      }
      return (q) => desceller({ wrap: q.wrap, env: environnementAuxiliaire(o.config, o.env), delaiMs: o.delaiMs });
    default:
      throw new ErreurSignataire(`enveloppe ${wrap.type} inconnue`);
  }
}
