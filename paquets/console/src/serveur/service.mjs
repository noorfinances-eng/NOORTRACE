// Client du canal de la console vers le service d'approbation (CT-3 12.9,
// EX-12.4, EX-13.49, contrat 2.10 et 2.11) : `POST <base>/v0/<méthode>`,
// `GET <base>/v0/etat`, sur `service.url` ou la prise `service.socket`
// (base `http://localhost`), jeton porteur et certificat client s'ils sont
// déclarés, certificat du service vérifié contre `service.ca` (sinon le
// magasin du système). Délai compté de l'envoi à la fin du corps de la
// réponse ; réponse de plus de 16 777 216 octets refusée.

import http from "node:http";
import https from "node:https";
import { magasinSysteme } from "./outils.mjs";

export const TAILLE_MAX_REPONSE = 16777216;

/** Le service n'a pas répondu dans le délai, est injoignable, ou a trop répondu. */
export class ServiceIndisponible extends Error {}

const HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/**
 * Corps de la forme d'EX-12.12 : `{ ready, set_read_at, open_tickets }`.
 * @param {unknown} v
 */
export function formeEtat(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const cles = Object.keys(v).sort();
  if (cles.join(",") !== "open_tickets,ready,set_read_at") return false;
  return (
    typeof v.ready === "boolean" &&
    (v.set_read_at === null || (typeof v.set_read_at === "string" && HORODATAGE.test(v.set_read_at))) &&
    Number.isInteger(v.open_tickets) &&
    v.open_tickets >= 0
  );
}

export class ClientService {
  /**
   * @param {{service: object, secrets: {jeton: string|null, ca: string|null, certClient: string|null, cleClient: string|null}, agentHttps?: https.Agent}} o
   */
  constructor({ service, secrets, agentHttps }) {
    this.secrets = secrets;
    this.agentHttps = agentHttps ?? null;
    if (service.url !== null) {
      const u = new URL(service.url);
      this.https = u.protocol === "https:";
      this.cible = { hostname: u.hostname.replace(/^\[|\]$/g, ""), port: u.port === "" ? (this.https ? 443 : 80) : Number(u.port), socketPath: undefined, hote: u.host };
    } else {
      this.https = false;
      this.cible = { hostname: undefined, port: undefined, socketPath: service.socket, hote: "localhost" };
    }
  }

  /**
   * Une requête au service ; rend `{ statut, corps }`, ou lève `ServiceIndisponible`.
   * @param {"GET"|"POST"} methode
   * @param {string} chemin
   * @param {Buffer|null} corps
   * @param {number} delaiMs
   */
  requete(methode, chemin, corps, delaiMs) {
    const entetes = { host: this.cible.hote };
    if (corps !== null) {
      entetes["content-type"] = "application/json";
      entetes["content-length"] = String(corps.length);
    }
    if (this.secrets.jeton !== null) entetes.authorization = `Bearer ${this.secrets.jeton}`;
    const options = {
      method: methode,
      path: chemin,
      headers: entetes,
      hostname: this.cible.hostname,
      port: this.cible.port,
      socketPath: this.cible.socketPath,
    };
    if (this.https) {
      // Sans `service.ca` : le magasin du système, explicitement ; un agent
      // d'essai remplace l'un et l'autre (contrat 2.2).
      if (this.secrets.ca !== null) options.ca = this.secrets.ca;
      else if (this.agentHttps === null) options.ca = magasinSysteme();
      if (this.secrets.certClient !== null) {
        options.cert = this.secrets.certClient;
        options.key = this.secrets.cleClient;
      }
      options.agent = this.agentHttps ?? false;
    } else options.agent = false;
    const module = this.https ? https : http;
    return new Promise((resoudre, rejeter) => {
      let fini = false;
      const terminer = (erreur, valeur) => {
        if (fini) return;
        fini = true;
        clearTimeout(minuteur);
        if (erreur) {
          req.destroy();
          rejeter(new ServiceIndisponible(erreur));
        } else resoudre(valeur);
      };
      const req = module.request(options, (rep) => {
        const morceaux = [];
        let taille = 0;
        rep.on("data", (d) => {
          taille += d.length;
          if (taille > TAILLE_MAX_REPONSE) terminer("réponse trop grande");
          else morceaux.push(d);
        });
        rep.on("end", () => terminer(null, { statut: rep.statusCode, corps: Buffer.concat(morceaux) }));
        rep.on("error", () => terminer("réponse interrompue"));
        rep.on("aborted", () => terminer("réponse interrompue"));
      });
      const minuteur = setTimeout(() => terminer("délai dépassé"), delaiMs);
      req.on("error", () => terminer("service injoignable"));
      req.end(corps ?? undefined);
    });
  }

  /** Relaie une méthode du canal. */
  relayer(methode, corps, delaiMs) {
    return this.requete("POST", `/v0/${methode}`, corps, delaiMs);
  }

  /**
   * `GET <base>/v0/etat` : vrai pour 200 et un corps de la forme d'EX-12.12
   * dans les 1 000 ms, quelle que soit la valeur de `ready`.
   * @param {(octets: Buffer) => unknown} lireJson
   */
  async joignable(lireJson) {
    try {
      const r = await this.requete("GET", "/v0/etat", null, 1000);
      if (r.statut !== 200) return false;
      return formeEtat(lireJson(r.corps));
    } catch {
      return false;
    }
  }
}
