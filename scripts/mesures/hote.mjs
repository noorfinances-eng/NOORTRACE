// Hôte de test du harnais de mesure de CT-2 EX-16.2 (pas 3 et 5) : client MCP
// de l'ère 2026-07-28 sur Streamable HTTP et client HTTP de la passerelle de
// modèle. Chaque « connexion d'hôte » est une connexion TCP persistante qui
// porte une requête à la fois. Tous les instants sont lus sur l'horloge
// monotone du système (`process.hrtime.bigint()`, EX-11.5), en nanosecondes.
//
// Deux façons d'émettre :
// - `enSerie` : une connexion, l'appel suivant part quand la réponse est
//   reçue (latence par appel, une connexion) ;
// - `aCadenceFixe` (CT-9 EX-11.9) : l'appel de rang i est prévu à
//   `t0 + i / cadence`, quelle que soit la lenteur des réponses, et sa
//   latence se compte depuis cet instant prévu, non depuis l'envoi effectif
//   (omission coordonnée) ; les appels sont répartis à tour de rôle sur les
//   connexions, où ils attendent leur tour.

import http from "node:http";
import { remplissage } from "./serveur-nul.mjs";

export const VERSION_PROTOCOLE = "2026-07-28";
const maintenant = () => process.hrtime.bigint();

export class ErreurHote extends Error {}

/** Une connexion d'hôte : une prise TCP persistante, une requête à la fois. */
export class Connexion {
  constructor(port) {
    this.port = port;
    this.agent = new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
  }

  /**
   * Envoie une requête POST ; rend { statut, type, envoi_ns, reponse_ns, corps
   * | morceaux }. `parMorceaux` : garde l'instant et la longueur de chaque
   * morceau reçu, sans garder les octets (flux SSE).
   */
  poster(chemin, entetes, corps, { parMorceaux = false } = {}) {
    return new Promise((res, rej) => {
      const req = http.request({ host: "127.0.0.1", port: this.port, path: chemin, method: "POST", agent: this.agent, headers: { ...entetes, "content-length": corps.length } }, (r) => {
        const morceaux = [];
        let decalage = 0;
        r.on("data", (k) => {
          if (parMorceaux) {
            morceaux.push({ decalage, octets: k.length, recu_ns: maintenant() });
            decalage += k.length;
          } else morceaux.push(k);
        });
        r.on("end", () => {
          const reponse_ns = maintenant();
          res({ statut: r.statusCode, type: String(r.headers["content-type"] ?? ""), envoi_ns, reponse_ns, ...(parMorceaux ? { morceaux, octets: decalage } : { corps: Buffer.concat(morceaux) }) });
        });
        r.on("error", rej);
      });
      req.on("error", rej);
      const envoi_ns = maintenant();
      req.end(corps);
    });
  }

  fermer() {
    this.agent.destroy();
  }
}

/**
 * Fabrique des requêtes `tools/call` de l'ère moderne : rend `(n) → { chemin,
 * entetes, corps }`, où la valeur JSON de `arguments` fait `argumentsOctets`
 * octets pour un numéro d'un chiffre. `varier` faux : arguments constants
 * (remplissage d'un segment : une seule pièce d'arguments).
 */
export function fabriqueAppelOutil({ jeton, outil = "nul__appeler", argumentsOctets = 4096, chemin = "/mcp", varier = true }) {
  const args = (n, charge) => JSON.stringify({ n, charge });
  const charge = remplissage(Math.max(0, argumentsOctets - Buffer.byteLength(args(0, ""))));
  const meta = JSON.stringify({ "io.modelcontextprotocol/protocolVersion": VERSION_PROTOCOLE, "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "hote-de-mesure", version: "0.1.0" } });
  const entetes = { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": VERSION_PROTOCOLE, "mcp-method": "tools/call", "mcp-name": outil };
  if (jeton) entetes.authorization = `Bearer ${jeton}`;
  return (n) => ({ chemin, entetes, corps: Buffer.from(`{"jsonrpc":"2.0","id":"m-${n}","method":"tools/call","params":{"name":${JSON.stringify(outil)},"arguments":${args(varier ? n : 0, charge)},"_meta":${meta}}}`, "utf8") });
}

/** La réponse d'un `tools/call` est-elle un résultat non erroné ? (JSON, ou SSE qui porte la réponse.) */
export function reponseOutilReussie(r) {
  if (r.statut !== 200) return false;
  const t = r.corps.toString("utf8");
  const json = r.type.startsWith("text/event-stream") ? (t.split("\n").filter((l) => l.startsWith("data:")).pop() ?? "").slice(5).trimStart() : t;
  const debut = json.slice(0, 160);
  return debut.includes('"result"') && !debut.includes('"error"') && !json.includes('"isError":true');
}

/**
 * Fabrique des requêtes `POST /v1/messages` : rend `(n, flux) → { chemin,
 * entetes, corps }`, corps de `requeteOctets` octets pour un numéro d'un
 * chiffre ; le numéro est porté par `metadata.user_id` (`mesure-<n>`).
 */
export function fabriqueEchangeModele({ jeton, requeteOctets = 32768, chemin = "/v1/messages" }) {
  const corps = (n, flux, texte) => JSON.stringify({ model: "modele-simule-1", max_tokens: 1024, metadata: { user_id: `mesure-${n}` }, messages: [{ role: "user", content: texte }], ...(flux ? { stream: true } : {}) });
  const texte = remplissage(Math.max(0, requeteOctets - Buffer.byteLength(corps(0, false, ""))));
  const entetes = { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": "cle-factice-hote-de-mesure", "user-agent": "hote-de-mesure/0.1.0" };
  if (jeton) entetes["x-noortrace-token"] = jeton;
  return (n, flux = false) => ({ chemin, entetes, corps: Buffer.from(corps(n, flux, texte), "utf8") });
}

/**
 * Émission en série sur une connexion : `echauffement` appels non comptés,
 * puis `appels` appels. `requete(n)` fabrique l'appel de numéro `n` (les
 * numéros partent de `premier`) ; `valide(r)` dit si la réponse est celle
 * attendue. Rend les mesures des appels comptés, dans l'ordre.
 */
export async function enSerie({ connexion, requete, valide, appels, echauffement = 0, premier = 1, options = {}, progres = null }) {
  const mesures = [];
  for (let i = 0; i < echauffement + appels; i++) {
    if (progres && i > 0 && i % 1000 === 0) progres(i, echauffement + appels);
    const n = premier + i;
    const q = requete(n);
    const r = await connexion.poster(q.chemin, q.entetes, q.corps, options);
    if (!valide(r)) throw new ErreurHote(`appel ${n} : réponse inattendue (HTTP ${r.statut})${r.corps ? ` : ${r.corps.toString("utf8").slice(0, 300)}` : ""}`);
    if (i >= echauffement) mesures.push({ n, envoi_ns: r.envoi_ns, reponse_ns: r.reponse_ns, ...(options.parMorceaux ? { morceaux: r.morceaux, octets: r.octets } : {}) });
  }
  return mesures;
}

/**
 * Émission à cadence fixe (CT-9 EX-11.9) sur `connexions` connexions.
 * `cadenceParS` appels par seconde, `echauffement` premiers appels non
 * comptés. Rend { mesures: [{ n, prevu_ns, envoi_ns, reponse_ns }], debut_ns
 * (instant prévu du premier appel compté), fin_ns (dernière réponse reçue) }.
 */
export function aCadenceFixe({ connexions, requete, valide, appels, echauffement = 0, premier = 1, cadenceParS }) {
  if (!(cadenceParS > 0)) throw new RangeError("cadence par seconde positive attendue");
  return new Promise((resoudre, rejeter) => {
    const total = echauffement + appels;
    const pasNs = 1e9 / cadenceParS;
    const t0 = maintenant() + 20000000n;
    const prevu = (i) => t0 + BigInt(Math.round(i * pasNs));
    const files = connexions.map(() => ({ file: [], occupee: false }));
    const mesures = new Array(appels);
    let emis = 0;
    let finis = 0;
    let fin_ns = t0;
    let arrete = false;
    const echouer = (e) => {
      if (arrete) return;
      arrete = true;
      rejeter(e);
    };
    const servir = (c) => {
      const f = files[c];
      if (f.occupee || f.file.length === 0 || arrete) return;
      f.occupee = true;
      const i = f.file.shift();
      const n = premier + i;
      const q = requete(n);
      connexions[c].poster(q.chemin, q.entetes, q.corps).then((r) => {
        if (!valide(r)) return echouer(new ErreurHote(`appel ${n} : réponse inattendue (HTTP ${r.statut}) : ${r.corps.toString("utf8").slice(0, 300)}`));
        if (i >= echauffement) mesures[i - echauffement] = { n, prevu_ns: prevu(i), envoi_ns: r.envoi_ns, reponse_ns: r.reponse_ns };
        if (r.reponse_ns > fin_ns) fin_ns = r.reponse_ns;
        finis += 1;
        f.occupee = false;
        if (finis === total) return resoudre({ mesures, debut_ns: prevu(echauffement), fin_ns });
        return servir(c);
      }, echouer);
    };
    const battre = () => {
      if (arrete) return;
      const t = maintenant();
      while (emis < total && prevu(emis) <= t) {
        const c = emis % connexions.length;
        files[c].file.push(emis);
        emis += 1;
        servir(c);
      }
      if (emis < total) setTimeout(battre, 1);
    };
    battre();
  });
}

/**
 * Émission au plus vite, sans cadence, sur `connexions` connexions, tant que
 * `continuer()` est vrai (remplissage d'un segment avant la mesure de
 * reprise ; aucune latence n'en est tirée). Rend le nombre d'appels faits.
 */
export async function auPlusVite({ connexions, requete, valide, continuer, premier = 1 }) {
  let n = premier;
  let faits = 0;
  await Promise.all(connexions.map(async (c) => {
    while (continuer()) {
      const k = n++;
      const q = requete(k);
      const r = await c.poster(q.chemin, q.entetes, q.corps);
      if (!valide(r)) throw new ErreurHote(`appel ${k} : réponse inattendue (HTTP ${r.statut}) : ${r.corps.toString("utf8").slice(0, 300)}`);
      faits += 1;
    }
  }));
  return faits;
}
