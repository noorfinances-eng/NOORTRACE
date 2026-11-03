// Azure Key Vault et Managed HSM : enveloppe de la classe C seulement (CT-2
// §11.2 : le service ne signe pas en Ed25519 ; `wrapKey`/`unwrapKey`).
//
// Requête (API REST Key Vault 7.4, page de `wrapKey` citée par la table des
// backends ; `unwrapKey` est son inverse, page non lue par R3, NV-10) :
//   POST <vault_url>/keys/<key_name>/<key_version>/unwrapkey?api-version=7.4
//        {"alg": "<RSA-OAEP-256|A256KW|CKM_AES_KEY_WRAP>", "value": base64url(chiffré)}
//        → {"kid": "...", "value": base64url(graine)}
// L'API n'a pas de contexte de chiffrement pour ces algorithmes : EX-11.9 ne
// le demande qu'à AWS et Google (lecture 179) ; la graine reste liée à
// sa clé par `kid`, contrôlé.
//
// Identité (lecture 182) : application Entra ID par secret client
// (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), jeton OAuth
// 2.0 de portée `https://vault.azure.net/.default` (Key Vault) ou
// `https://managedhsm.azure.net/.default` (Managed HSM) ; autorité
// `https://login.microsoftonline.com`, ou celle d'`AZURE_AUTHORITY_HOST`.

import { ErreurSignataire, requete, json, base64urlStrict } from "./commun.mjs";

export const VERSION_API_KEYVAULT = "7.4";

/** Portée OAuth d'un coffre (Key Vault ou Managed HSM). */
export function porteeAzure(vaultUrl) {
  return /\.managedhsm\.azure\.net(:\d+)?\/?$/.test(new URL(vaultUrl).host) ? "https://managedhsm.azure.net/.default" : "https://vault.azure.net/.default";
}

/** Jeton d'une application Entra ID (flux client_credentials), mis en cache. */
export class JetonAzure {
  /**
   * @param {{portee: string, env?: NodeJS.ProcessEnv, delaiMs?: number, ca?: Buffer|string|null, maintenant?: () => number}} o
   */
  constructor(o) {
    const env = o.env ?? process.env;
    if (!env.AZURE_TENANT_ID || !env.AZURE_CLIENT_ID || !env.AZURE_CLIENT_SECRET) {
      throw new ErreurSignataire("identité Entra ID absente (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)", { code: "identite" });
    }
    this.url = `${(env.AZURE_AUTHORITY_HOST || "https://login.microsoftonline.com").replace(/\/+$/, "")}/${encodeURIComponent(env.AZURE_TENANT_ID)}/oauth2/v2.0/token`;
    this.client = env.AZURE_CLIENT_ID;
    this.secret = env.AZURE_CLIENT_SECRET;
    this.portee = o.portee;
    this.delai = o.delaiMs ?? 5000;
    this.ca = o.ca ?? null;
    this.maintenant = o.maintenant ?? Date.now;
    this.jeton = null;
    this.fin = 0;
  }

  async valeur() {
    const t = this.maintenant();
    if (this.jeton && t < this.fin - 60000) return this.jeton;
    const corps = new URLSearchParams({ grant_type: "client_credentials", client_id: this.client, client_secret: this.secret, scope: this.portee }).toString();
    const r = await requete({ url: this.url, methode: "POST", entetes: { "content-type": "application/x-www-form-urlencoded" }, corps, delaiMs: this.delai, ca: this.ca });
    const j = json(r.corps);
    if (r.statut !== 200 || typeof j?.access_token !== "string") throw new ErreurSignataire(`jeton Entra ID refusé : statut ${r.statut}`, { statut: r.statut, code: "identite" });
    this.jeton = j.access_token;
    this.fin = t + Number(j.expires_in ?? 3600) * 1000;
    return this.jeton;
  }
}

/**
 * Classe C, enveloppe Azure : `unwrapKey` de la graine (EX-11.9).
 * @param {object} p
 * @param {{vault_url: string, key_name: string, key_version: string, algorithm: string}} p.wrap
 * @param {Uint8Array} p.chiffre contenu du fichier scellé (valeur rendue par wrapKey, décodée)
 * @param {{valeur: () => Promise<string>}} p.jeton
 * @param {number} [p.delaiMs]
 * @param {Buffer|string|null} [p.ca]
 * @returns {Promise<Uint8Array>}
 */
export async function desenvelopperAzure(p) {
  const base = p.wrap.vault_url.replace(/\/+$/, "");
  const chemin = `/keys/${encodeURIComponent(p.wrap.key_name)}/${encodeURIComponent(p.wrap.key_version)}`;
  const r = await requete({
    url: `${base}${chemin}/unwrapkey?api-version=${VERSION_API_KEYVAULT}`,
    methode: "POST",
    entetes: { authorization: `Bearer ${await p.jeton.valeur()}`, "content-type": "application/json", accept: "application/json" },
    corps: JSON.stringify({ alg: p.wrap.algorithm, value: Buffer.from(p.chiffre).toString("base64url") }),
    delaiMs: p.delaiMs ?? 5000,
    ca: p.ca ?? null,
  });
  const j = json(r.corps);
  if (r.statut !== 200) {
    const code = typeof j?.error?.code === "string" ? j.error.code : "";
    throw new ErreurSignataire(`azure-keyvault unwrapKey : statut ${r.statut}${code ? ` (${code})` : ""}`, { statut: r.statut, code: code || null });
  }
  // `kid` : identifiant de la clé employée ; il doit désigner la clé et la version configurées.
  if (typeof j?.kid !== "string" || !j.kid.replace(/\/+$/, "").endsWith(chemin)) throw new ErreurSignataire("azure-keyvault unwrapKey : kid d'une autre clé");
  return base64urlStrict(j.value, "value");
}
