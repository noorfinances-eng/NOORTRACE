// Opérations de chaîne des services de la démonstration de référence (CT-2
// §19) : envoi d'une transaction de type 2 signée (CT-4 §6.7.3) et lectures
// d'état du registre de développement, par les primitives du composant
// d'ancrage (`@noortrace/ancrage/registre`). Employé par `registre-dev`
// (déploiement, jeu d'approbateurs de l'organisation, provision) et par
// `approbateur-demo` (inscription de la clé de l'enregistreur). Aucune clé
// n'est écrite ici : chaque service passe le signataire qu'il détient.

import { keccak256, utf8, octetsVersHex, hexVersOctets } from "@noortrace/noyau";
import { ClientRpc, appelLecture, construireTransaction, signerTransaction, decoderUint, decoderBool, FRAIS_NOMINAUX } from "@noortrace/ancrage/registre";

export const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

/** Sélecteur de fonction (4 octets) d'une signature Solidity. */
export const selecteur = (signature) => keccak256(utf8(signature)).subarray(0, 4);

/** Mot ABI de 32 octets d'une adresse. */
export function motAdresse(adresse) {
  const m = new Uint8Array(32);
  m.set(hexVersOctets(adresse.toLowerCase(), 20), 12);
  return m;
}

/** Mot ABI de 32 octets d'un entier non négatif. */
export function motEntier(x) {
  const m = new Uint8Array(32);
  let v = BigInt(x);
  for (let i = 31; i >= 0 && v > 0n; i--) {
    m[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return m;
}

export function concatener(...parties) {
  const t = new Uint8Array(parties.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parties) {
    t.set(p, o);
    o += p.length;
  }
  return t;
}

/** Client JSON-RPC d'un point (délai court : les services attendent le nœud par sondage). */
export const clientRpc = (url, delaiMs = 5000) => new ClientRpc({ points: [url], delaiMs });

/** Résultat d'un appel JSON-RPC, ou exception si le nœud rend une erreur. */
export async function rpc(client, methode, params = []) {
  const r = await client.appeler(methode, params);
  if (r.erreur) throw new Error(`${methode} : ${r.erreur.message ?? JSON.stringify(r.erreur)}`);
  return r.resultat;
}

/** Attend que le point réponde `eth_chainId` attendu, puis que la hauteur avance. */
export async function attendreChaine(client, evmChainId, { delaiMs = 120000, pasMs = 250 } = {}) {
  const fin = Date.now() + delaiMs;
  const attendu = `0x${BigInt(evmChainId).toString(16)}`;
  let h0 = null;
  for (;;) {
    try {
      const c = await rpc(client, "eth_chainId");
      if (c !== attendu) throw new Error(`eth_chainId ${c}, attendu ${attendu}`);
      const h = BigInt(await rpc(client, "eth_blockNumber"));
      if (h0 === null) h0 = h;
      else if (h > h0) return h;
    } catch (e) {
      if (Date.now() > fin) throw new Error(`chaîne injoignable ou arrêtée après ${delaiMs} ms : ${e.message}`);
    }
    if (Date.now() > fin) throw new Error(`la hauteur n'a pas avancé en ${delaiMs} ms`);
    await attendre(pasMs);
  }
}

/**
 * Signe et soumet une transaction de type 2 aux frais nominaux (CT-4 EX-4.15) ; rend `{ hash, nonce }` sans attendre
 * le reçu. `nonce` absent : le nonce `pending` de l'expéditeur.
 * @param {{client: object, evmChainId: number, signataire: object, to: string|null, data?: Uint8Array, value?: bigint, gasLimit?: bigint, nonce?: bigint}} o
 */
export async function soumettre(o) {
  const nonce = o.nonce ?? BigInt(await rpc(o.client, "eth_getTransactionCount", [o.signataire.adresse(), "pending"]));
  const tx = construireTransaction({
    chain_id: BigInt(o.evmChainId), nonce, max_priority_fee_per_gas: FRAIS_NOMINAUX, max_fee_per_gas: FRAIS_NOMINAUX,
    gas_limit: o.gasLimit ?? 3000000n, to: o.to, value: o.value ?? 0n, data: o.data ?? new Uint8Array(0),
  });
  const signee = await signerTransaction(tx, o.signataire);
  return { hash: await rpc(o.client, "eth_sendRawTransaction", [signee.raw_transaction]), nonce };
}

/** Attend le reçu d'une transaction ; lève si le reçu dit un échec (`status` 0x0) ou n'arrive pas dans le délai. */
export async function attendreRecu(client, hash, delaiMs = 60000) {
  const fin = Date.now() + delaiMs;
  for (;;) {
    const recu = await rpc(client, "eth_getTransactionReceipt", [hash]);
    if (recu) {
      if (recu.status !== "0x1") throw new Error(`transaction ${hash} en échec (status ${recu.status})`);
      return { hash, recu, adresseContrat: recu.contractAddress ? recu.contractAddress.toLowerCase() : null };
    }
    if (Date.now() > fin) throw new Error(`reçu de ${hash} absent après ${delaiMs} ms`);
    await attendre(200);
  }
}

/** Soumet une transaction et attend son reçu : `{ hash, recu, adresseContrat, nonce }`. */
export async function envoyer(o) {
  const s = await soumettre(o);
  return { ...(await attendreRecu(o.client, s.hash, o.delaiMs)), nonce: s.nonce };
}

/** `eth_getCode` non vide à une adresse. */
export async function aDuCode(client, adresse) {
  const code = await rpc(client, "eth_getCode", [adresse, "latest"]);
  return typeof code === "string" && code.length > 2;
}

/** `CuratorSetRegistry.curatorSetOf(orgId)` : adresse du jeu, ou l'adresse nulle. */
export async function jeuDe(client, curatorSetRegistry, orgId) {
  const r = await appelLecture(client, curatorSetRegistry, concatener(selecteur("curatorSetOf(bytes32)"), hexVersOctets(orgId, 32)));
  return `0x${r.slice(-40)}`;
}

/** `curatorSetFor(orgId)` de `RecorderRegistry` ou de `PeriodRegistry` : le jeu qui gouverne l'organisation. */
export async function jeuPour(client, contrat, orgId) {
  const r = await appelLecture(client, contrat, concatener(selecteur("curatorSetFor(bytes32)"), hexVersOctets(orgId, 32)));
  return `0x${r.slice(-40)}`;
}

/** `CuratorSet.getThreshold()`. */
export async function seuilDe(client, curatorSet) {
  return Number(decoderUint(await appelLecture(client, curatorSet, selecteur("getThreshold()"))));
}

/** `CuratorSet.isCurator(adresse)`. */
export async function estMembre(client, curatorSet, adresse) {
  return decoderBool(await appelLecture(client, curatorSet, concatener(selecteur("isCurator(address)"), motAdresse(adresse))));
}

export { octetsVersHex, hexVersOctets };
