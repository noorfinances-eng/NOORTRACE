// Lecture du jeu d'approbateurs au registre (CT-3 EX-8.1) et surveillance de
// ses changements (EX-8.5), par le point JSON-RPC de la configuration.
//
// Une lecture se fait à une hauteur H unique : `eth_chainId` (sinon
// `chaine_differente`), `eth_blockNumber`, `eth_getBlockByNumber(H)` ;
// `curatorSetOf(orgId)` du registre à H (nul : `organisation_sans_jeu` ;
// autre que le jeu épinglé : `jeu_non_attendu`) ; `eth_getCode(S, H)` non vide
// (`jeu_sans_code`) ; `getThreshold()` et `getCuratorCount()`, 1 ≤ t ≤ n
// (`seuil_incoherent`) ; membres : adresses connues pour lesquelles
// `isCurator` vaut vrai à H, ou, si leur nombre n'est pas n, reconstitution
// par les journaux `CuratorAdded` et `CuratorRemoved` par tranches d'au plus
// 16 384 blocs, recoupée par `isCurator` et n (`membres_non_reconstitues`) ;
// adresses en minuscules, triées. Toute erreur du nœud (hauteur refusée,
// délai, réseau) : `etat_indisponible`, et la lecture sera réessayée.
//
// Les lectures ne sont pas prouvées (R1-F80) : le service croit le nœud
// qu'il interroge, que la configuration déclare validateur du client ou d'un
// partenaire (EX-8.2, CT-7 EX-3.10).
//
// Bornes (CT-3 EX-7.22 ; `bornes.mjs`) : le corps d'une réponse est
// lu jusqu'à `rpc_corps_octets` au plus ; une hauteur ou un nombre de bloc
// est un entier sûr écrit en hexadécimal ; une lecture interroge au plus
// `rpc_tranches_max` tranches de journaux et accumule au plus
// `rpc_journaux_max` journaux ; une lecture ou une recherche de changements
// dure au plus `lecture_max_ms` (défaut : `rpc_lecture_facteur` fois
// `timeout_ms`). Au-delà : `etat_indisponible`, et le prochain sondage
// repart, au lieu d'une lecture qui ne finit jamais ou d'une mémoire qui
// gonfle avec la réponse du nœud.
//
// Refus pour débit (CT-3 EX-8.1, révision 0.8) : un appel que le nœud refuse
// parce qu'il en reçoit trop (noorcore : erreur `-32000`, message
// `rate limited`, relevé sur `eth_getLogs` quand la reconstitution des membres
// enchaîne ses tranches) ne dit rien de l'état : il est refait, avec les mêmes
// paramètres (même hauteur H), après une pause de 250 ms doublée à chaque
// refus et plafonnée à 4 s, tant que la pause finit avant l'échéance de la
// lecture ; sinon la lecture est `etat_indisponible`, comme toute erreur du
// nœud. Hors d'une lecture (`hauteur`), le refus n'est pas refait.

import { keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";
import { BORNES } from "./bornes.mjs";

const selecteur = (sig) => octetsVersHex(keccak256(utf8(sig))).slice(0, 10);
const sujet = (sig) => octetsVersHex(keccak256(utf8(sig)));

export const SELECTEURS = Object.freeze({
  curatorSetOf: selecteur("curatorSetOf(bytes32)"),
  getThreshold: selecteur("getThreshold()"),
  getCuratorCount: selecteur("getCuratorCount()"),
  isCurator: selecteur("isCurator(address)"),
});

export const SUJETS = Object.freeze({
  CuratorAdded: sujet("CuratorAdded(address)"),
  CuratorRemoved: sujet("CuratorRemoved(address)"),
  ThresholdUpdated: sujet("ThresholdUpdated(uint256)"),
  CuratorSetAssigned: sujet("CuratorSetAssigned(bytes32,address,address)"),
});

/** Borne d'une requête `eth_getLogs` de noorcore (R1-F79). */
export const TRANCHE_JOURNAUX = 16384;

const ZERO = "0x" + "0".repeat(40);
const hexH = (h) => "0x" + h.toString(16);
const mot = (hex) => hex.slice(2).padStart(64, "0");

class ErreurNoeud extends Error {
  /** @param {string} message @param {boolean} [debit] refus du nœud pour débit */
  constructor(message, debit = false) {
    super(message);
    this.debit = debit;
  }
}

/** Message d'erreur d'un refus pour débit (noorcore : `-32000 rate limited`). */
const REFUS_DEBIT = /\brate limited\b/i;
/** Première pause avant de refaire un appel refusé pour débit, puis plafond de la pause doublée (ms). */
const PAUSE_DEBIT_MS = 250;
const PAUSE_DEBIT_MAX_MS = 4000;

/** Nombre de bloc ou hauteur rendu par le nœud : hexadécimal `0x…`, entier sûr. */
function entierHex(v, quoi) {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]{1,14}$/.test(v)) throw new ErreurNoeud(`${quoi} : nombre illisible`);
  const n = Number(BigInt(v));
  if (!Number.isSafeInteger(n)) throw new ErreurNoeud(`${quoi} : nombre hors borne`);
  return n;
}

/**
 * Lit un corps de réponse jusqu'à `max` octets ; au-delà, la lecture est
 * interrompue (`null`) sans accumuler le reste (CT-3 EX-7.22).
 * @param {Response} rep
 * @param {number} max
 * @returns {Promise<Uint8Array|null>}
 */
async function lireCorpsBorne(rep, max) {
  const annonce = Number(rep.headers.get("content-length"));
  if (Number.isFinite(annonce) && annonce > max) {
    await rep.body?.cancel().catch(() => {});
    return null;
  }
  if (!rep.body) return new Uint8Array(0);
  const morceaux = [];
  let taille = 0;
  const lecteur = rep.body.getReader();
  try {
    for (;;) {
      const { done, value } = await lecteur.read();
      if (done) break;
      taille += value.byteLength;
      if (taille > max) {
        await lecteur.cancel().catch(() => {});
        return null;
      }
      morceaux.push(value);
    }
  } finally {
    lecteur.releaseLock?.();
  }
  return new Uint8Array(Buffer.concat(morceaux));
}

/** Lecteur du jeu d'un registre `CuratorSetRegistry`. */
export class LecteurJeu {
  /**
   * @param {{url: string, jeton?: string|null, timeout_ms?: number, org_id: string, depuis_bloc?: number,
   *   adressesConnues?: () => Iterable<string>, appel?: (methode: string, params: unknown[]) => Promise<unknown>,
   *   lecture_max_ms?: number, corps_max_octets?: number, tranches_max?: number, journaux_max?: number}} p
   *   `jeton` : `rpc.token` de la garde d'admission, envoyé en `Authorization: Bearer`
   *   (EX-10.12) ; `appel` remplace le transport HTTP (tests) ; les quatre bornes prennent
   *   par défaut les valeurs de `BORNES` (essais seulement)
   */
  constructor(p) {
    this.url = p.url;
    this.jeton = p.jeton ?? null;
    this.delai = p.timeout_ms ?? 5000;
    this.org_id = p.org_id;
    this.depuis = p.depuis_bloc ?? 0;
    this.adressesConnues = p.adressesConnues ?? (() => []);
    this.appelExterne = p.appel ?? null;
    this.compteur = 0;
    this.lectureMax = p.lecture_max_ms ?? this.delai * BORNES.rpc_lecture_facteur;
    this.corpsMax = p.corps_max_octets ?? BORNES.rpc_corps_octets;
    this.tranchesMax = p.tranches_max ?? BORNES.rpc_tranches_max;
    this.journauxMax = p.journaux_max ?? BORNES.rpc_journaux_max;
    /** Instant (horloge monotone) au-delà duquel la lecture en cours est abandonnée, ou null. */
    this.echeance = null;
  }

  /** Borne de temps d'une lecture ou d'une recherche de changements (CT-3 EX-7.22), depuis son début. */
  async #sousEcheance(f) {
    this.echeance = performance.now() + this.lectureMax;
    try {
      return await f();
    } finally {
      this.echeance = null;
    }
  }

  /** Un appel JSON-RPC ; un refus pour débit est refait après une pause, dans l'échéance de la lecture en cours. */
  async appel(methode, params) {
    let pause = PAUSE_DEBIT_MS;
    for (;;) {
      try {
        return await this.#appelUnique(methode, params);
      } catch (e) {
        if (!(e instanceof ErreurNoeud) || !e.debit || this.echeance === null || performance.now() + pause > this.echeance) throw e;
        await new Promise((fini) => setTimeout(fini, pause));
        pause = Math.min(2 * pause, PAUSE_DEBIT_MAX_MS);
      }
    }
  }

  async #appelUnique(methode, params) {
    if (this.echeance !== null && performance.now() > this.echeance) throw new ErreurNoeud(`${methode} : délai total de lecture dépassé`);
    if (this.appelExterne) {
      try {
        return await this.appelExterne(methode, params);
      } catch (e) {
        throw new ErreurNoeud(`${methode} : ${e.message}`, REFUS_DEBIT.test(String(e?.message)));
      }
    }
    let rep;
    let octets;
    try {
      rep = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", ...(this.jeton ? { authorization: `Bearer ${this.jeton}` } : {}) },
        redirect: "error",
        body: JSON.stringify({ jsonrpc: "2.0", id: ++this.compteur, method: methode, params }),
        signal: AbortSignal.timeout(this.delai),
      });
      octets = await lireCorpsBorne(rep, this.corpsMax);
    } catch (e) {
      throw new ErreurNoeud(`${methode} : ${e.message}`);
    }
    if (octets === null) throw new ErreurNoeud(`${methode} : réponse de plus de ${this.corpsMax} octets`);
    let corps;
    try {
      corps = JSON.parse(Buffer.from(octets).toString("utf8"));
    } catch {
      throw new ErreurNoeud(`${methode} : réponse illisible`);
    }
    if (corps === null || typeof corps !== "object" || Array.isArray(corps)) throw new ErreurNoeud(`${methode} : réponse illisible`);
    if (corps.error) throw new ErreurNoeud(`${methode} : ${corps.error?.code} ${corps.error?.message}`, REFUS_DEBIT.test(String(corps.error?.message)));
    return corps.result;
  }

  async #appelContrat(to, data, H) {
    const r = await this.appel("eth_call", [{ to, data }, hexH(H)]);
    if (typeof r !== "string" || !/^0x[0-9a-fA-F]*$/.test(r)) throw new ErreurNoeud("eth_call : réponse illisible");
    return r;
  }

  async #entier(to, data, H) {
    const r = await this.#appelContrat(to, data, H);
    if (r.length < 66) throw new ErreurNoeud("eth_call : mot attendu");
    return BigInt("0x" + r.slice(2, 66));
  }

  async hauteur() {
    return entierHex(await this.appel("eth_blockNumber", []), "eth_blockNumber");
  }

  /**
   * Lit le jeu (EX-8.1), sous les bornes du module.
   * @param {{chain_id: number, registry: string, set: string}} pol `approver_set` de la politique (registre)
   * @param {Iterable<string>} [membresPrecedents]
   * @returns {Promise<{status: "lu"|"illisible", jeu: object|null, cause: string|null}>}
   */
  lire(pol, membresPrecedents = []) {
    return this.#sousEcheance(() => this.#lire(pol, membresPrecedents));
  }

  async #lire(pol, membresPrecedents) {
    const illisible = (cause) => ({ status: "illisible", jeu: null, cause });
    try {
      const chaine = entierHex(await this.appel("eth_chainId", []), "eth_chainId");
      if (chaine !== pol.chain_id) return illisible("chaine_differente");
      const H = entierHex(await this.appel("eth_blockNumber", []), "eth_blockNumber");
      const bloc = await this.appel("eth_getBlockByNumber", [hexH(H), false]);
      const b = typeof bloc?.hash === "string" ? bloc.hash.toLowerCase() : null;
      if (!b || !/^0x[0-9a-f]{64}$/.test(b)) return illisible("etat_indisponible");
      const brut = await this.#appelContrat(pol.registry, SELECTEURS.curatorSetOf + mot(this.org_id), H);
      if (brut.length < 66) return illisible("etat_indisponible");
      const S = ("0x" + brut.slice(26, 66)).toLowerCase();
      if (S === ZERO) return illisible("organisation_sans_jeu");
      if (S !== pol.set.toLowerCase()) return illisible("jeu_non_attendu");
      const code = await this.appel("eth_getCode", [S, hexH(H)]);
      if (typeof code !== "string" || code === "0x" || code === "") return illisible("jeu_sans_code");
      const t = await this.#entier(S, SELECTEURS.getThreshold, H);
      const n = await this.#entier(S, SELECTEURS.getCuratorCount, H);
      if (!(t >= 1n && t <= n && n <= 65535n)) return illisible("seuil_incoherent");
      const estMembre = async (a) => (await this.#entier(S, SELECTEURS.isCurator + mot(a), H)) === 1n;
      const connues = [...new Set([...this.adressesConnues(), ...membresPrecedents].map((a) => a.toLowerCase()))].sort();
      let membres = [];
      for (const a of connues) if (await estMembre(a)) membres.push(a);
      if (BigInt(membres.length) !== n) {
        membres = await this.#reconstituer(S, H, estMembre);
        if (membres === null || BigInt(membres.length) !== n) return illisible("membres_non_reconstitues");
      }
      return {
        status: "lu",
        cause: null,
        jeu: {
          chain_id: pol.chain_id,
          registry: pol.registry.toLowerCase(),
          set: S,
          height: H,
          block_hash: b,
          threshold: { required: Number(t), size: Number(n) },
          members: membres.sort(),
        },
      };
    } catch (e) {
      // toute réponse hors forme du nœud est une lecture illisible, jamais une exception (S-2)
      if (e instanceof ErreurNoeud || e instanceof SyntaxError || e instanceof RangeError || e instanceof TypeError) return illisible("etat_indisponible");
      throw e;
    }
  }

  /** Journaux d'une adresse sur `[de, a]`, par tranches, sous les bornes de tranches et de nombre (CT-3 EX-7.22). */
  async #journaux(adresse, sujets, de, a) {
    const sortie = [];
    if (a < de) return sortie;
    const tranches = Math.ceil((a - de + 1) / TRANCHE_JOURNAUX);
    if (tranches > this.tranchesMax) throw new ErreurNoeud(`eth_getLogs : ${tranches} tranches, plus de ${this.tranchesMax}`);
    for (let debut = de; debut <= a; debut += TRANCHE_JOURNAUX) {
      const fin = Math.min(a, debut + TRANCHE_JOURNAUX - 1);
      const l = await this.appel("eth_getLogs", [{ address: adresse, topics: [sujets], fromBlock: hexH(debut), toBlock: hexH(fin) }]);
      if (!Array.isArray(l)) throw new ErreurNoeud("eth_getLogs : réponse illisible");
      for (const j of l) {
        if (!j || typeof j !== "object" || !Array.isArray(j.topics) || !j.topics.every((t) => typeof t === "string")) throw new ErreurNoeud("eth_getLogs : journal illisible");
        sortie.push({ topics: j.topics, bloc: entierHex(j.blockNumber, "eth_getLogs blockNumber"), index: entierHex(j.logIndex, "eth_getLogs logIndex") });
      }
      if (sortie.length > this.journauxMax) throw new ErreurNoeud(`eth_getLogs : plus de ${this.journauxMax} journaux`);
    }
    return sortie.sort((x, y) => x.bloc - y.bloc || x.index - y.index);
  }

  async #reconstituer(S, H, estMembre) {
    const l = await this.#journaux(S, [SUJETS.CuratorAdded, SUJETS.CuratorRemoved], this.depuis, H);
    const ensemble = new Set();
    for (const j of l) {
      if (typeof j.topics[1] !== "string" || j.topics[1].length !== 66) throw new ErreurNoeud("eth_getLogs : sujet illisible");
      const a = ("0x" + j.topics[1].slice(26)).toLowerCase();
      if (j.topics[0] === SUJETS.CuratorAdded) ensemble.add(a);
      else ensemble.delete(a);
    }
    const membres = [];
    for (const a of [...ensemble].sort()) if (await estMembre(a)) membres.push(a);
    return membres;
  }

  /**
   * Changements depuis une hauteur (EX-8.5) : `CuratorSetAssigned` de
   * l'organisation au registre, `CuratorAdded`, `CuratorRemoved`,
   * `ThresholdUpdated` du jeu figé, sur `]de, a]`.
   * @returns {Promise<boolean>} vrai si un changement est constaté (une nouvelle lecture suit)
   */
  changements(pol, setFige, de, a) {
    return this.#sousEcheance(async () => {
      if (a <= de) return false;
      const reg = await this.#journaux(pol.registry, [SUJETS.CuratorSetAssigned], de + 1, a);
      if (reg.some((j) => (j.topics[1] ?? "").toLowerCase() === this.org_id.toLowerCase())) return true;
      if (!setFige) return false;
      const jeu = await this.#journaux(setFige, [SUJETS.CuratorAdded, SUJETS.CuratorRemoved, SUJETS.ThresholdUpdated], de + 1, a);
      return jeu.length > 0;
    });
  }
}
