// Découverte des portefeuilles par EIP-6963 (CT-3 EX-13.22, points 1 à 5) :
// validation de chaque annonce (`uuid` de version 4, nom non vide d'au plus 64
// caractères, icône en URI `data:`, `rdns` en chaîne, fournisseur doté d'une
// fonction `request`), liste dans l'ordre des premières annonces, réannonce
// par le même objet sans effet, `uuid` revendiqué par deux objets écarté pour
// la vie de la page. Aucun choix n'est fait : la liste est proposée.
// `Decouverte` reçoit sa cible d'événements en paramètre (la page lui donne la
// sienne) ; elle n'a aucun minuteur (le délai de 1 000 ms du point 6 est celui
// de la page) et ne retire jamais son écouteur.

import { longueurPointsDeCode } from "./octets.mjs";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function valide(annonce) {
  if (annonce === null || typeof annonce !== "object") return false;
  const { info, provider } = annonce;
  if (info === null || typeof info !== "object") return false;
  if (typeof info.uuid !== "string" || !UUID_V4.test(info.uuid)) return false;
  if (typeof info.name !== "string" || info.name.length === 0 || longueurPointsDeCode(info.name) > 64) return false;
  if (typeof info.icon !== "string" || !info.icon.startsWith("data:")) return false;
  if (typeof info.rdns !== "string") return false;
  return provider !== null && typeof provider === "object" && typeof provider.request === "function";
}

/**
 * Liste des fournisseurs annoncés et annonces écartées, pour une suite
 * d'annonces dans l'ordre d'arrivée (EX-13.22, points 2 et 3) ; `provider` est
 * comparé par identité. Les annonces écartées sont rendues par indice
 * croissant : `annonce_invalide` (point 2), ou `annonce_en_double` (première
 * annonce d'un `uuid` revendiqué par un autre objet, annonce en conflit et
 * toute annonce ultérieure de cet `uuid`).
 * @param {{info: {uuid: string, name: string, icon: string, rdns: string}, provider: object}[]} annonces
 * @returns {{providers: {uuid: string, name: string, icon: string, rdns: string, provider: object}[], rejected: {index: number, reason: string}[]}}
 */
export function decouvrir(annonces) {
  if (!Array.isArray(annonces)) throw new TypeError("decouvrir : tableau d'annonces attendu");
  const premieres = new Map();
  const exclus = new Set();
  const rejected = [];
  annonces.forEach((a, index) => {
    if (!valide(a)) {
      rejected.push({ index, reason: "annonce_invalide" });
      return;
    }
    const cle = a.info.uuid.toLowerCase();
    if (exclus.has(cle)) {
      rejected.push({ index, reason: "annonce_en_double" });
      return;
    }
    const premiere = premieres.get(cle);
    if (premiere === undefined) {
      premieres.set(cle, { index, info: a.info, provider: a.provider });
      return;
    }
    if (premiere.provider === a.provider) return;
    exclus.add(cle);
    premieres.delete(cle);
    rejected.push({ index: premiere.index, reason: "annonce_en_double" }, { index, reason: "annonce_en_double" });
  });
  const providers = [...premieres.values()]
    .sort((x, y) => x.index - y.index)
    .map(({ info, provider }) => ({ uuid: info.uuid, name: info.name, icon: info.icon, rdns: info.rdns, provider }));
  rejected.sort((x, y) => x.index - y.index);
  return { providers, rejected };
}

// Copie, à la réception, de ce qu'une annonce porte : les membres d'`info`
// sont lus une seule fois ; une lecture qui lève rend l'annonce invalide.
function lireAnnonce(evenement) {
  try {
    const detail = evenement.detail;
    if (detail === null || typeof detail !== "object") return null;
    const info = detail.info;
    const provider = detail.provider;
    if (info === null || typeof info !== "object") return { info, provider };
    return { info: { uuid: info.uuid, name: info.name, icon: info.icon, rdns: info.rdns }, provider };
  } catch {
    return null;
  }
}

/** Découverte EIP-6963 sur une cible d'événements (`window` dans la page). */
export class Decouverte {
  #cible;
  #annonces = [];
  #ecoute = false;
  #rappels = [];
  #liste = { providers: [], rejected: [] };

  /** @param {EventTarget} cible */
  constructor(cible) {
    if (cible === null || typeof cible !== "object" || typeof cible.addEventListener !== "function" || typeof cible.dispatchEvent !== "function") {
      throw new TypeError("Decouverte : EventTarget attendu");
    }
    this.#cible = cible;
  }

  /**
   * Pose l'écouteur de `eip6963:announceProvider` (une fois, jamais retiré),
   * puis émet `eip6963:requestProvider`.
   */
  lancer() {
    if (!this.#ecoute) {
      this.#ecoute = true;
      this.#cible.addEventListener("eip6963:announceProvider", (e) => this.#recevoir(e));
    }
    this.#cible.dispatchEvent(new Event("eip6963:requestProvider"));
  }

  #recevoir(evenement) {
    this.#annonces.push(lireAnnonce(evenement));
    const avant = this.#liste;
    const apres = decouvrir(this.#annonces);
    this.#liste = apres;
    const meme =
      avant.providers.length === apres.providers.length &&
      avant.providers.every((p, k) => p.provider === apres.providers[k].provider && p.uuid === apres.providers[k].uuid) &&
      avant.rejected.length === apres.rejected.length;
    if (!meme) for (const f of [...this.#rappels]) f();
  }

  /** Fournisseurs proposés, dans l'ordre des premières annonces. */
  get fournisseurs() {
    return this.#liste.providers.map((p) => ({ ...p }));
  }

  /** Annonces écartées, `{ index, reason }`. */
  get ecartees() {
    return this.#liste.rejected.map((r) => ({ ...r }));
  }

  /**
   * Appelle `fonction` (sans argument) à chaque changement de la liste ou des
   * annonces écartées.
   * @param {() => void} fonction
   */
  surChangement(fonction) {
    if (typeof fonction !== "function") throw new TypeError("surChangement : fonction attendue");
    this.#rappels.push(fonction);
  }
}
