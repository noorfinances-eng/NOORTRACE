// Fichier d'en-têtes Bitcoin `entetes-bitcoin.json` (CT-6 §10.3, EX-10.3 ;
// CT-5 EX-6.8, AN-20) : schéma `entetes-bitcoin-v0`, lecture et contrôle
// d'un document, production depuis un nœud Bitcoin (`bitcoin_rpc`) ou depuis
// un fichier tenu par l'exploitation (`fichier`), jamais depuis un calendrier
// ni un explorateur. Les en-têtes sont les 80 octets bruts de l'ordre de
// sérialisation de Bitcoin ; aucune valeur affichée (`hash`, `merkleroot`
// inversés) n'est jamais recopiée.

import { RegistreSchemas, analyserJson, concatener, encoderBase64, hexVersOctets, octetsVersHex, sha256, utf8 } from "@noortrace/noyau";

/** Copie à l'identique de `spec/schemas/entetes-bitcoin-v0.schema.json` (comparée au fichier par les tests). */
export const SCHEMA_ENTETES_BITCOIN = Object.freeze({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://noortrace.example/schemas/v0/entetes-bitcoin.schema.json",
  title: "Chaîne d'en-têtes Bitcoin, version 0 (CT-6 §10.3)",
  description:
    "Entrée distincte du dossier, désignée sur la ligne de commande. Ce n'est pas une ancre : la chaîne n'est crue qu'au travers de la vérification O-5, qui la rattache au point de contrôle du fichier d'ancres par le hachage et par le travail.",
  type: "object",
  additionalProperties: false,
  required: ["version", "network", "start_height", "source", "headers"],
  properties: {
    version: { const: 0 },
    network: { type: "string", enum: ["mainnet", "regtest"] },
    start_height: { type: "integer", minimum: 0, maximum: 4294967295, description: "Hauteur du premier en-tête de la liste." },
    source: { type: "string", minLength: 1, maxLength: 512, description: "D'où viennent les en-têtes ; déclaratif." },
    headers: {
      description: "En-têtes bruts de 80 octets, dans l'ordre de sérialisation de Bitcoin, hauteurs contiguës à partir de start_height.",
      type: "array",
      minItems: 1,
      maxItems: 200000,
      items: { type: "string", pattern: "^0x[0-9a-f]{160}$" },
    },
  },
});

const REGISTRE = new RegistreSchemas([SCHEMA_ENTETES_BITCOIN]);

/** Bornes de CT-6 EX-4.13 et EX-10.3. */
export const BORNES_ENTETES = Object.freeze({
  TAILLE_FICHIER: 64 * 1024 * 1024,
  NOMBRE_MAX: 200000,
  TAILLE_EN_TETE: 80,
  INTERVALLE_RETARGET: 2016,
  MARGE_FIN: 11, // EX-6.8 : fin ≥ h' + 11 (borne d'EX-10.13)
});

/** `powLimit` et `nBits` fixes des réseaux admis (CT-6 EX-10.9). */
export const RESEAUX = Object.freeze({
  mainnet: Object.freeze({ powLimit: 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, nBitsFixe: null }),
  regtest: Object.freeze({ powLimit: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, nBitsFixe: 0x207fffff }),
});

/** Erreur du fichier d'en-têtes ou de sa source ; `code` stable, sans secret. */
export class ErreurEntetes extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurEntetes";
    this.code = code;
  }
}

/** dSHA(x) = SHA-256(SHA-256(x)). */
export function dsha(octets) {
  return sha256(sha256(octets));
}

/** Entier petit-boutiste des octets [debut, debut + n). */
function entierPetitBoutiste(octets, debut, n) {
  let v = 0;
  for (let i = n - 1; i >= 0; i -= 1) v = v * 256 + octets[debut + i];
  return v;
}

/** Inverse l'ordre des octets (ordre d'affichage de Bitcoin Core). */
export function inverser(octets) {
  return Uint8Array.from(octets).reverse();
}

/**
 * Décompose un en-tête brut de 80 octets.
 * @param {Uint8Array} octets
 */
export function decomposerEnTete(octets) {
  if (!(octets instanceof Uint8Array) || octets.length !== BORNES_ENTETES.TAILLE_EN_TETE) throw new ErreurEntetes("en_tete", "en-tête de 80 octets attendu");
  const hash = dsha(octets);
  return {
    octets,
    version: entierPetitBoutiste(octets, 0, 4),
    prev: octets.subarray(4, 36),
    racine: octets.subarray(36, 68),
    nTime: entierPetitBoutiste(octets, 68, 4),
    nBits: entierPetitBoutiste(octets, 72, 4),
    nNonce: entierPetitBoutiste(octets, 76, 4),
    hash, // ordre de sérialisation
    hashAffiche: octetsVersHex(inverser(hash)), // ordre d'affichage de Bitcoin Core
  };
}

/**
 * `SetCompact(x)` de Bitcoin Core (CT-6 EX-10.9) : cible, drapeaux négatif et débordement.
 * @param {number} x nBits
 * @returns {{cible: bigint, negatif: boolean, debordement: boolean}}
 */
export function setCompact(x) {
  const taille = x >>> 24;
  const mot = x & 0x007fffff;
  let motPrime;
  let N;
  if (taille <= 3) {
    motPrime = mot >>> (8 * (3 - taille));
    N = BigInt(motPrime);
  } else {
    motPrime = mot;
    N = BigInt(mot) << BigInt(8 * (taille - 3));
  }
  const negatif = motPrime !== 0 && (x & 0x00800000) !== 0;
  const debordement = motPrime !== 0 && (taille > 34 || (motPrime > 0xff && taille > 33) || (motPrime > 0xffff && taille > 32));
  return { cible: N, negatif, debordement };
}

/**
 * `GetCompact(N)` de Bitcoin Core (CT-6 EX-10.9).
 * @param {bigint} N
 * @returns {number}
 */
export function getCompact(N) {
  if (N < 0n) throw new ErreurEntetes("cible", "cible négative");
  let taille = 0;
  for (let v = N; v > 0n; v >>= 8n) taille += 1;
  let compact;
  if (taille <= 3) compact = N << BigInt(8 * (3 - taille));
  else compact = N >> BigInt(8 * (taille - 3));
  if ((compact & 0x00800000n) !== 0n) {
    compact >>= 8n;
    taille += 1;
  }
  return Number(compact | (BigInt(taille) << 24n));
}

/** Entier petit-boutiste de 256 bits d'un hachage. */
export function hachageEnEntier(hash) {
  let v = 0n;
  for (let i = 31; i >= 0; i -= 1) v = (v << 8n) | BigInt(hash[i]);
  return v;
}

/**
 * Lit et contrôle un document `entetes-bitcoin-v0` (octets JSON stricts ou
 * objet déjà analysé) : schéma, en-têtes de 80 octets, nombre borné. Le
 * chaînage et le travail relèvent de O-5 (`verification.mjs`).
 * @param {Uint8Array|object} document
 * @returns {{document: object, network: string, start_height: number, end_height: number, enTetes: ReturnType<typeof decomposerEnTete>[]}}
 */
export function lireFichierEntetes(document) {
  let doc = document;
  if (doc instanceof Uint8Array) {
    if (doc.length > BORNES_ENTETES.TAILLE_FICHIER) throw new ErreurEntetes("taille", "fichier d'en-têtes de plus de 64 Mio");
    try {
      doc = analyserJson(doc);
    } catch (e) {
      throw new ErreurEntetes("json", `fichier d'en-têtes illisible : ${e.message}`);
    }
  }
  const { valide, erreurs } = REGISTRE.valider(SCHEMA_ENTETES_BITCOIN.$id, doc);
  if (!valide) throw new ErreurEntetes("schema", `fichier d'en-têtes non conforme au schéma entetes-bitcoin-v0 : ${erreurs.slice(0, 3).join(" ; ")}`);
  if (doc.start_height + doc.headers.length - 1 > 4294967295) throw new ErreurEntetes("hauteur", "hauteur finale au-delà de 2^32 − 1");
  const enTetes = doc.headers.map((h) => decomposerEnTete(hexVersOctets(h, 80)));
  return { document: doc, network: doc.network, start_height: doc.start_height, end_height: doc.start_height + enTetes.length - 1, enTetes };
}

/**
 * Chaînage `prev(i) = dSHA(H(i − 1))` sur toute la suite (règle 2 d'EX-10.9).
 * @param {ReturnType<typeof decomposerEnTete>[]} enTetes
 * @returns {number|null} indice du premier en-tête mal chaîné, ou null
 */
export function premierDefautDeChainage(enTetes) {
  for (let i = 1; i < enTetes.length; i += 1) {
    const prev = enTetes[i].prev;
    const attendu = enTetes[i - 1].hash;
    for (let k = 0; k < 32; k += 1) if (prev[k] !== attendu[k]) return i;
  }
  return null;
}

/**
 * Bornes du fichier d'EX-6.8 : `start_height = max(0, 2016 × (⌊h ÷ 2016⌋ − 1))`,
 * fin au moins `h' + 11`.
 * @param {number} h plus petite hauteur attestée
 * @param {number} hPrime plus grande hauteur attestée
 */
export function bornesFichierEntetes(h, hPrime) {
  if (!Number.isInteger(h) || !Number.isInteger(hPrime) || h < 0 || hPrime < h || hPrime > 4294967295 - BORNES_ENTETES.MARGE_FIN) {
    throw new ErreurEntetes("hauteurs", "hauteurs attestées hors bornes");
  }
  const start = Math.max(0, BORNES_ENTETES.INTERVALLE_RETARGET * (Math.floor(h / BORNES_ENTETES.INTERVALLE_RETARGET) - 1));
  return { start_height: start, end_height: hPrime + BORNES_ENTETES.MARGE_FIN };
}

const CHAINES_RPC = Object.freeze({ main: "mainnet", regtest: "regtest" });

/**
 * Produit le document `entetes-bitcoin-v0` d'EX-6.8 pour les hauteurs
 * attestées `[h, h']` d'une période.
 *
 * - `source.type === "bitcoin_rpc"` : `rpc.appeler(methode, params)` est un
 *   client JSON-RPC injecté vers un nœud sous le contrôle du client
 *   (`rpcBitcoinHttp` en est l'implémentation par défaut) ; `getblockchaininfo`
 *   confirme le réseau, puis pour chaque hauteur `getblockhash` et
 *   `getblockheader <hash> false` (hexadécimal brut) ; chaque en-tête est
 *   contrôlé (dSHA inversé = hash annoncé, chaînage).
 * - `source.type === "fichier"` : `fichier` est le contenu (octets ou objet)
 *   du fichier au même schéma tenu par l'exploitation ; la tranche demandée
 *   en est extraite et contrôlée.
 *
 * @param {{source: {type: "bitcoin_rpc"|"fichier", network: string, url?: string}, hauteurs: [number, number], rpc?: {appeler(methode: string, params: unknown[]): Promise<unknown>}, fichier?: Uint8Array|object}} p
 * @returns {Promise<object>} document conforme au schéma
 */
export async function fichierEntetes({ source, hauteurs, rpc, fichier }) {
  if (!source || typeof source !== "object") throw new ErreurEntetes("source", "source d'en-têtes attendue");
  if (!Object.hasOwn(RESEAUX, source.network)) throw new ErreurEntetes("reseau", "réseau de la source inconnu");
  if (!Array.isArray(hauteurs) || hauteurs.length !== 2) throw new ErreurEntetes("hauteurs", "hauteurs [h, h'] attendues");
  const { start_height, end_height } = bornesFichierEntetes(hauteurs[0], hauteurs[1]);
  const nombre = end_height - start_height + 1;
  if (nombre > BORNES_ENTETES.NOMBRE_MAX) throw new ErreurEntetes("nombre", "plus de 200 000 en-têtes");

  let headers;
  let texteSource;
  if (source.type === "bitcoin_rpc") {
    if (!rpc || typeof rpc.appeler !== "function") throw new ErreurEntetes("rpc", "client RPC attendu");
    const info = await rpc.appeler("getblockchaininfo", []);
    const chaine = info && typeof info === "object" ? CHAINES_RPC[info.chain] : undefined;
    if (chaine !== source.network) throw new ErreurEntetes("reseau", "le nœud n'est pas sur le réseau configuré");
    if (!Number.isInteger(info.headers) || info.headers < end_height) throw new ErreurEntetes("hauteur_indisponible", "le nœud ne connaît pas encore la hauteur finale demandée");
    headers = [];
    let precedent = null;
    for (let h = start_height; h <= end_height; h += 1) {
      const hash = await rpc.appeler("getblockhash", [h]);
      if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) throw new ErreurEntetes("rpc_hash", `getblockhash ${h} : hachage attendu`);
      const brut = await rpc.appeler("getblockheader", [hash, false]);
      if (typeof brut !== "string" || !/^[0-9a-f]{160}$/.test(brut)) throw new ErreurEntetes("rpc_en_tete", `getblockheader ${h} : 160 caractères hexadécimaux attendus`);
      const enTete = decomposerEnTete(hexVersOctets("0x" + brut, 80));
      if (enTete.hashAffiche !== "0x" + hash) throw new ErreurEntetes("rpc_incoherent", `getblockheader ${h} : l'en-tête ne hache pas vers le hachage annoncé`);
      if (precedent !== null && premierDefautDeChainage([precedent, enTete]) !== null) throw new ErreurEntetes("chainage", `en-tête ${h} non chaîné au précédent`);
      precedent = enTete;
      headers.push("0x" + brut);
    }
    texteSource = `bitcoin_rpc ${hoteSansIdentifiants(source.url)} : getblockheader <hash> false (en-têtes bruts), hauteurs ${start_height} à ${end_height}`;
  } else if (source.type === "fichier") {
    if (fichier === undefined || fichier === null) throw new ErreurEntetes("fichier", "contenu du fichier d'exploitation attendu");
    const lu = lireFichierEntetes(fichier);
    if (lu.network !== source.network) throw new ErreurEntetes("reseau", "le fichier d'exploitation n'est pas du réseau configuré");
    if (lu.start_height > start_height || lu.end_height < end_height) {
      throw new ErreurEntetes("couverture", `le fichier d'exploitation couvre ${lu.start_height} à ${lu.end_height}, il faut ${start_height} à ${end_height}`);
    }
    const debut = start_height - lu.start_height;
    const tranche = lu.enTetes.slice(debut, debut + nombre);
    const defaut = premierDefautDeChainage(tranche);
    if (defaut !== null) throw new ErreurEntetes("chainage", `en-tête ${start_height + defaut} non chaîné au précédent`);
    headers = lu.document.headers.slice(debut, debut + nombre);
    texteSource = `fichier d'exploitation (${lu.document.source}), hauteurs ${start_height} à ${end_height}`.slice(0, 512);
  } else {
    throw new ErreurEntetes("source", "type de source inconnu");
  }

  const document = { version: 0, network: source.network, start_height, source: texteSource, headers };
  const { valide, erreurs } = REGISTRE.valider(SCHEMA_ENTETES_BITCOIN.$id, document);
  if (!valide) throw new ErreurEntetes("schema", `document produit non conforme : ${erreurs.slice(0, 3).join(" ; ")}`);
  return document;
}

/** Hôte d'une URL sans identifiants, ou un texte neutre. */
function hoteSansIdentifiants(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "noeud";
  }
}

/**
 * Client JSON-RPC 1.0 par défaut vers un nœud Bitcoin (`bitcoin_rpc`) :
 * `POST url`, `Authorization: Basic` depuis le secret résolu par l'appelant
 * (octets `utilisateur:motdepasse`, CT-2 §15.2 ; jamais lu ici), réponse
 * bornée à 1 Mio, JSON strict. `transport.post(url, octets, entetes, delaiMs)`
 * est injectable ; l'implémentation par défaut est celle de `calendriers.mjs`.
 * @param {{url: string, auth: Uint8Array|null, transport: {post(url: string, octets: Uint8Array, entetes: object, delaiMs: number): Promise<{status: number, corps: Uint8Array}>}, delaiMs?: number}} p
 */
export function rpcBitcoinHttp({ url, auth, transport, delaiMs = 10000 }) {
  if (typeof url !== "string" || !/^https?:\/\//.test(url)) throw new ErreurEntetes("url", "URL du nœud attendue");
  if (!transport || typeof transport.post !== "function") throw new ErreurEntetes("transport", "transport attendu");
  const entetes = { "Content-Type": "application/json", Accept: "application/json" };
  if (auth instanceof Uint8Array && auth.length > 0) entetes.Authorization = `Basic ${encoderBase64(auth)}`;
  let compteur = 0;
  return {
    async appeler(methode, params) {
      compteur += 1;
      const corps = utf8(JSON.stringify({ jsonrpc: "1.0", id: `noortrace-${compteur}`, method: methode, params }));
      const reponse = await transport.post(url, corps, entetes, delaiMs, { tailleMax: 1024 * 1024 });
      if (reponse.status !== 200) throw new ErreurEntetes("rpc_http", `réponse HTTP ${reponse.status} du nœud`);
      let json;
      try {
        json = analyserJson(reponse.corps);
      } catch {
        throw new ErreurEntetes("rpc_json", "réponse du nœud illisible");
      }
      if (!json || typeof json !== "object") throw new ErreurEntetes("rpc_json", "réponse du nœud illisible");
      if (json.error !== null && json.error !== undefined) throw new ErreurEntetes("rpc_erreur", `erreur RPC ${typeof json.error === "object" && json.error ? json.error.code : ""}`.trim());
      return json.result;
    },
  };
}

/** Concatène les en-têtes bruts d'un document (utilitaire des tests et de l'exportateur). */
export function octetsDesEnTetes(document) {
  return concatener(...document.headers.map((h) => hexVersOctets(h, 80)));
}
