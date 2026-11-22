// Client de la prise de l'agent (INTERFACES.md 3.2) : une requête par
// connexion, un objet JSON sur une ligne, la réponse de même forme. Le
// serveur de l'interface s'en sert, et un script (sans navigateur) peut
// remettre un travail de la même façon, sous le compte de l'interface.

import net from "node:net";

/**
 * Longueur maximale, en octets UTF-8, du chemin de la prise de l'agent
 * (`prise` de l'agent et de l'interface ; CT-4 EX-7.28, complément du
 * 2026-11-16). Node.js tronque un chemin plus long à `sizeof(sun_path) - 1`
 * (107 octets sous Linux, 103 sous macOS) : l'agent écouterait, et
 * l'interface joindrait, une autre prise, hors du répertoire d'EX-7.28. C'est
 * la borne du SDK et du démon (CT-2 EX-6.10, EX-18.1) et du service
 * d'approbation (CT-3 EX-12.2) ; aucun module commun ne la porte : constante
 * nommée, même valeur.
 */
export const CHEMIN_PRISE_MAX_OCTETS = 103;

/**
 * Règle de longueur d'un chemin de prise : le texte du refus
 * (`chemin_prise_trop_long : <n> octets, au plus 103`), ou null.
 * @param {unknown} chemin
 */
export function refusCheminPrise(chemin) {
  if (typeof chemin !== "string") return null;
  const n = Buffer.byteLength(chemin, "utf8");
  return n > CHEMIN_PRISE_MAX_OCTETS ? `chemin_prise_trop_long : ${n} octets, au plus ${CHEMIN_PRISE_MAX_OCTETS} (EX-7.28)` : null;
}

/** Erreur de transport : agent injoignable, réponse illisible, connexion fermée sans réponse. */
export class ErreurAgent extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurAgent";
  }
}

/**
 * Remet une requête à l'agent ; rend la réponse (`{ accepte, id }` ou
 * `{ accepte: false, code, message }`), ou lève `ErreurAgent`.
 */
export function remettre(prise, requete, { delaiMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    // complément du 2026-11-16 : refus avant toute connexion d'un chemin que Node.js tronquerait
    const refus = refusCheminPrise(prise);
    if (refus !== null) return reject(new ErreurAgent(`prise : ${refus}`));
    const s = net.createConnection(prise);
    let tampon = "";
    let fini = false;
    const finir = (f) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuterie);
      s.destroy();
      f();
    };
    const minuterie = setTimeout(() => finir(() => reject(new ErreurAgent("agent sans réponse dans le délai"))), delaiMs);
    s.setEncoding("utf8");
    s.on("connect", () => s.write(JSON.stringify(requete) + "\n"));
    s.on("data", (d) => {
      tampon += d;
      if (tampon.length > 65536) finir(() => reject(new ErreurAgent("réponse trop longue")));
    });
    s.on("error", () => finir(() => reject(new ErreurAgent("agent injoignable"))));
    s.on("close", () => {
      const ligne = tampon.split("\n")[0];
      if (!ligne) return finir(() => reject(new ErreurAgent("connexion fermée sans réponse")));
      try {
        const r = JSON.parse(ligne);
        finir(() => resolve(r));
      } catch {
        finir(() => reject(new ErreurAgent("réponse illisible")));
      }
    });
  });
}

/** Remet un travail typé au nom d'un exploitant. */
export const remettreTravail = (prise, exploitant, travail, options) => remettre(prise, { version: 0, kind: "travail", exploitant, travail }, options);

/** Remet une confirmation hors bande au nom d'un exploitant. */
export const remettreConfirmation = (prise, exploitant, confirmation, options) => remettre(prise, { version: 0, kind: "confirmation", exploitant, confirmation }, options);

/** Remet une note interne (nom interne, remise du paquet, correction d'une remise) au nom d'un exploitant (CT-4 EX-7.23, complément du 2026-11-19). */
export const remettreNote = (prise, exploitant, note, options) => remettre(prise, { version: 0, kind: "note", exploitant, note }, options);
