// Client de la prise de l'agent (INTERFACES.md 3.2) : une requête par
// connexion, un objet JSON sur une ligne, la réponse de même forme. Le
// serveur de l'interface s'en sert, et un script (sans navigateur) peut
// remettre un travail de la même façon, sous le compte de l'interface.

import net from "node:net";

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
