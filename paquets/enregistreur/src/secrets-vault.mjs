// Références de secrets `{ "vault": { "path", "field" } }` (CT-2 §15.2) :
// « Lecture KV dans Vault ou OpenBao, à l'adresse et avec le jeton de
// `signer.backend` quand il est de type `vault-transit`/`openbao-transit`,
// sinon avec `VAULT_ADDR` et `VAULT_TOKEN` de l'environnement » ; « Lue au
// démarrage ; une relecture périodique n'est pas dans la version 0 ».
//
// La lecture est asynchrone (réseau) : elle précède la résolution des autres
// références (EX-15.4 pas 4), qui reçoit les valeurs lues
// (`resoudreSecrets(config, { vault })`). Requête : `GET <adresse>/v1/<path>`,
// en-tête `X-Vault-Token` (et `X-Vault-Namespace` du backend s'il n'est pas
// nul) ; réponse KV version 2 (`data.data[field]`, chemin `…/data/…`) ou
// version 1 (`data[field]`) ; la valeur est une chaîne, décodée ensuite selon
// `encoding` (LISEZMOI, lecture 192). Aucune valeur n'est consignée.

import { parcourirSecrets } from "./configuration.mjs";
import { resoudreSecret } from "./secrets.mjs";
import { requete, json } from "./signataires/commun.mjs";

/**
 * Lit les références `{ vault }` d'une configuration validée.
 * @param {object} config
 * @param {{env?: NodeJS.ProcessEnv, ca?: Buffer|string|null, delaiMs?: number}} [o]
 * @returns {Promise<{valeurs: Map<string, Uint8Array>, erreurs: {pointeur: string, regle: string, secret: true}[]}>}
 */
export async function lireSecretsVault(config, o = {}) {
  const env = o.env ?? process.env;
  const refs = [];
  parcourirSecrets(config, "", (ref, pointeur) => {
    if (ref.vault) refs.push({ ref, pointeur });
  });
  const valeurs = new Map();
  const erreurs = [];
  if (!refs.length) return { valeurs, erreurs };
  const err = (pointeur, regle) => erreurs.push({ pointeur, regle, secret: true });
  // Adresse et jeton (15.2).
  const b = config.signer?.backend;
  let adresse;
  let jeton;
  let espace = null;
  let delai = o.delaiMs ?? 5000;
  if (b && (b.type === "vault-transit" || b.type === "openbao-transit")) {
    adresse = b.url;
    espace = b.namespace ?? null;
    delai = o.delaiMs ?? config.signer.timeout_ms ?? 5000;
    if (b.token?.vault) {
      for (const { pointeur } of refs) err(pointeur, "jeton de signer.backend lui-même référencé dans Vault : illisible");
      return { valeurs, erreurs };
    }
    try {
      jeton = Buffer.from(resoudreSecret(b.token, "/signer/backend/token", { env })).toString("utf8");
    } catch (e) {
      for (const { pointeur } of refs) err(pointeur, `jeton de signer.backend non résolu (${e.regle ?? e.message})`);
      return { valeurs, erreurs };
    }
  } else {
    adresse = env.VAULT_ADDR;
    jeton = env.VAULT_TOKEN;
    if (!adresse || !jeton) {
      for (const { pointeur } of refs) err(pointeur, "référence vault sans signer.backend Vault/OpenBao ni VAULT_ADDR et VAULT_TOKEN");
      return { valeurs, erreurs };
    }
  }
  for (const { ref, pointeur } of refs) {
    const chemin = String(ref.vault.path).replace(/^\/+/, "");
    const entetes = { "x-vault-token": jeton, accept: "application/json" };
    if (espace) entetes["x-vault-namespace"] = espace;
    let r;
    try {
      r = await requete({ url: `${adresse.replace(/\/+$/, "")}/v1/${chemin}`, entetes, delaiMs: delai, ca: o.ca ?? null });
    } catch (e) {
      err(pointeur, `lecture Vault impossible (${e.code ?? "erreur"})`);
      continue;
    }
    if (r.statut !== 200) {
      err(pointeur, `lecture Vault refusée (statut ${r.statut})`);
      continue;
    }
    const j = json(r.corps);
    const d = j?.data;
    const v2 = d && typeof d.data === "object" && d.data !== null && "metadata" in d;
    const valeur = v2 ? d.data[ref.vault.field] : d?.[ref.vault.field];
    if (typeof valeur !== "string") {
      err(pointeur, `champ ${ref.vault.field} absent ou non textuel`);
      continue;
    }
    valeurs.set(pointeur, new Uint8Array(Buffer.from(valeur, "utf8")));
  }
  return { valeurs, erreurs };
}
