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

import { keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";

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

class ErreurNoeud extends Error {}

/** Lecteur du jeu d'un registre `CuratorSetRegistry`. */
export class LecteurJeu {
  /**
   * @param {{url: string, jeton?: string|null, timeout_ms?: number, org_id: string, depuis_bloc?: number,
   *   adressesConnues?: () => Iterable<string>, appel?: (methode: string, params: unknown[]) => Promise<unknown>}} p
   *   `jeton` : `rpc.token` de la garde d'admission, envoyé en `Authorization: Bearer`
   *   (EX-10.12) ; `appel` remplace le transport HTTP (tests)
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
  }

  async appel(methode, params) {
    if (this.appelExterne) {
      try {
        return await this.appelExterne(methode, params);
      } catch (e) {
        throw new ErreurNoeud(`${methode} : ${e.message}`);
      }
    }
    let rep;
    try {
      rep = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", ...(this.jeton ? { authorization: `Bearer ${this.jeton}` } : {}) },
        redirect: "error",
        body: JSON.stringify({ jsonrpc: "2.0", id: ++this.compteur, method: methode, params }),
        signal: AbortSignal.timeout(this.delai),
      });
    } catch (e) {
      throw new ErreurNoeud(`${methode} : ${e.message}`);
    }
    let corps;
    try {
      corps = await rep.json();
    } catch {
      throw new ErreurNoeud(`${methode} : réponse illisible`);
    }
    if (corps?.error) throw new ErreurNoeud(`${methode} : ${corps.error.code} ${corps.error.message}`);
    return corps?.result;
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
    return Number(BigInt(await this.appel("eth_blockNumber", [])));
  }

  /**
   * Lit le jeu (EX-8.1).
   * @param {{chain_id: number, registry: string, set: string}} pol `approver_set` de la politique (registre)
   * @param {Iterable<string>} [membresPrecedents]
   * @returns {Promise<{status: "lu"|"illisible", jeu: object|null, cause: string|null}>}
   */
  async lire(pol, membresPrecedents = []) {
    const illisible = (cause) => ({ status: "illisible", jeu: null, cause });
    try {
      const chaine = BigInt(await this.appel("eth_chainId", []));
      if (chaine !== BigInt(pol.chain_id)) return illisible("chaine_differente");
      const H = Number(BigInt(await this.appel("eth_blockNumber", [])));
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
      if (e instanceof ErreurNoeud || e instanceof SyntaxError || e instanceof RangeError) return illisible("etat_indisponible");
      throw e;
    }
  }

  async #journaux(adresse, sujets, de, a) {
    const sortie = [];
    for (let debut = de; debut <= a; debut += TRANCHE_JOURNAUX) {
      const fin = Math.min(a, debut + TRANCHE_JOURNAUX - 1);
      const l = await this.appel("eth_getLogs", [{ address: adresse, topics: [sujets], fromBlock: hexH(debut), toBlock: hexH(fin) }]);
      if (!Array.isArray(l)) throw new ErreurNoeud("eth_getLogs : réponse illisible");
      sortie.push(...l);
    }
    return sortie.sort((x, y) => Number(BigInt(x.blockNumber) - BigInt(y.blockNumber)) || Number(BigInt(x.logIndex) - BigInt(y.logIndex)));
  }

  async #reconstituer(S, H, estMembre) {
    const l = await this.#journaux(S, [SUJETS.CuratorAdded, SUJETS.CuratorRemoved], this.depuis, H);
    const ensemble = new Set();
    for (const j of l) {
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
  async changements(pol, setFige, de, a) {
    if (a <= de) return false;
    const reg = await this.#journaux(pol.registry, [SUJETS.CuratorSetAssigned], de + 1, a);
    if (reg.some((j) => (j.topics?.[1] ?? "").toLowerCase() === this.org_id.toLowerCase())) return true;
    if (!setFige) return false;
    const jeu = await this.#journaux(setFige, [SUJETS.CuratorAdded, SUJETS.CuratorRemoved, SUJETS.ThresholdUpdated], de + 1, a);
    return jeu.length > 0;
  }
}
