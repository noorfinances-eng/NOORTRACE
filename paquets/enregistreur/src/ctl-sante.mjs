// `noortrace-ctl sonde --url <url>` et `noortrace-ctl etat` (étape 7 ; CT-8
// §4.4, EX-10.14, PD-2 ; décision D-11 : exigences de construction, forme
// proposée à CT-2).
//
//   noortrace-ctl sonde --url <url>
//       sonde du conteneur `enregistreur` des fichiers Compose (forme `CMD`,
//       image sans interpréteur de commandes, CT-8 CO-12) : `GET <url>` en
//       HTTP, sans corps, sans authentification, sans suivre de redirection,
//       2 500 ms au plus en tout (sous le `timeout` de 3 s des sondes) ; l'URL
//       est en `http:` sur une adresse de boucle locale écrite en clair
//       (127.0.0.0/8 ou [::1]), sans identifiants ; code 0 sur une réponse
//       200, et seulement elle ; 1 dans tout autre cas (autre statut,
//       connexion refusée, délai écoulé, URL refusée, usage incorrect) : un
//       moteur de conteneurs ne lit que 0 (sain) et 1 (malsain), 2 est
//       réservé. Sortie : `200` sur la sortie standard ; la raison d'un
//       échec sur la sortie d'erreur.
//
//   noortrace-ctl etat [--configuration <fichier>] [--delai-ms <n>]
//       état du démon en marche (CT-8 EX-10.14 : « rend GET /healthz et
//       /readyz (CT-2 EX-17.1) et l'époque du bail ») : le démon est trouvé
//       comme pour les autres commandes (processus de l'utilisateur, `/proc`,
//       EX-18.1) ; la commande lit `supervision.health_listen` de sa
//       configuration et y lit `GET /healthz`, `GET /readyz` et, quand
//       `supervision.metrics` est vrai, la jauge `noortrace_lease_epoch` de
//       `GET /metrics` (CT-2 §17.2 : « Époque du bail détenu ; 0 si non
//       détenu »). Aucune prise n'est ouverte par la commande : elle joint
//       l'écoute de supervision existante, comme `ancrage metriques`. Une ligne
//       JSON par démon sur la sortie standard :
//         { pid, configuration, health_listen, status, reasons, since,
//           healthz, readyz, lease_epoch }
//       `status` et `reasons` sont ceux du corps de `/healthz` (`ok`,
//       `degraded`, `down`, `standby`), `healthz` et `readyz` les statuts
//       HTTP, `lease_epoch` l'époque (null si les métriques ne sont pas
//       servies). Codes : 0 si chaque démon rend `ok` et `/readyz` 200 ; 1 si
//       un démon répond autrement (dégradé, arrêté, passif, pas prêt) ; 2
//       usage, configuration illisible ; 4 aucun démon, ou pas de réponse de
//       l'écoute de supervision dans le délai (« muet » des runbooks RB-1,
//       11.4 chemin A). Délai par défaut : 5 000 ms pour toute la commande.

import fs from "node:fs";
import http from "node:http";
import net from "node:net";

/** Délai total de la sonde, en millisecondes (sous le `timeout: 3s` des fichiers Compose). */
export const DELAI_SONDE_MS = 2500;

/** Délai par défaut de `etat`, pour toute la commande. */
export const DELAI_ETAT_DEFAUT_MS = 5000;

/** Taille maximale d'un corps lu par la sonde ou par `etat`. */
const CORPS_MAX = 1 << 20;

const USAGE_SONDE = "usage : noortrace-ctl sonde --url <url>";
const USAGE_ETAT = "usage : noortrace-ctl etat [--configuration <fichier>] [--delai-ms <n>]";

/**
 * Adresse de boucle locale écrite en clair : IPv4 127.0.0.0/8 ou IPv6 ::1.
 * Un nom (même `localhost`) n'est pas admis : sa résolution dépend de
 * fichiers et de services que la sonde ne contrôle pas.
 * @param {string} hote nom d'hôte de l'URL (`[::1]` pour IPv6)
 */
export function boucleLocale(hote) {
  const h = hote.replace(/^\[|\]$/g, "");
  if (net.isIPv4(h)) return h.split(".")[0] === "127";
  if (net.isIPv6(h)) return normaliserIPv6(h) === "::1";
  return false;
}

function normaliserIPv6(h) {
  try {
    return new URL(`http://[${h}]/`).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return null;
  }
}

/**
 * Arguments de la sonde : exactement `--url <url>`, une fois ; rend l'URL
 * admise ou la raison du refus.
 * @param {string[]} args arguments qui suivent `sonde`
 * @returns {{url: URL} | {erreur: string}}
 */
export function argumentsSonde(args) {
  if (args.length !== 2 || args[0] !== "--url" || typeof args[1] !== "string" || args[1] === "") return { erreur: USAGE_SONDE };
  let u;
  try {
    u = new URL(args[1]);
  } catch {
    return { erreur: "url invalide" };
  }
  if (u.protocol !== "http:") return { erreur: "url http attendue (écoute de supervision locale, sans TLS)" };
  if (u.username || u.password) return { erreur: "url sans identifiants attendue" };
  if (!boucleLocale(u.hostname)) return { erreur: `adresse de boucle locale attendue (127.0.0.0/8 ou [::1]) : ${u.hostname}` };
  return { url: u };
}

/**
 * `GET` borné : rend `{ statut, corps }` ou lève une erreur dont le message
 * est la raison (`délai écoulé`, `connexion : ECONNREFUSED`…). La fin est
 * absolue (`Date.now()`), pour un délai unique de toute une commande.
 * @param {URL|{host: string, port: number, path: string}} cible
 * @param {number} fin instant limite (ms)
 * @returns {Promise<{statut: number, corps: string}>}
 */
export function lireHttp(cible, fin) {
  return new Promise((resoudre, rejeter) => {
    let fini = false;
    let req = null;
    const finir = (f, v) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      req?.destroy();
      f(v);
    };
    const minuteur = setTimeout(() => finir(rejeter, new Error("délai écoulé")), Math.max(0, fin - Date.now()));
    const options = cible instanceof URL
      ? { host: cible.hostname.replace(/^\[|\]$/g, ""), port: cible.port ? Number(cible.port) : 80, path: `${cible.pathname}${cible.search}` }
      : cible;
    try {
      req = http.get({ ...options, agent: false, headers: { accept: "application/json, text/plain" } }, (res) => {
        const morceaux = [];
        let taille = 0;
        res.on("data", (x) => {
          taille += x.length;
          if (taille > CORPS_MAX) finir(rejeter, new Error("corps trop grand"));
          else morceaux.push(x);
        });
        res.on("end", () => finir(resoudre, { statut: res.statusCode, corps: Buffer.concat(morceaux).toString("utf8") }));
        res.on("error", () => finir(rejeter, new Error("réponse interrompue")));
      });
    } catch {
      finir(rejeter, new Error("requête impossible"));
      return;
    }
    req.on("error", (e) => finir(rejeter, new Error(`connexion : ${e.code ?? "erreur"}`)));
  });
}

/**
 * Sonde : code 0 sur une réponse 200, 1 sinon.
 * @param {string[]} args arguments qui suivent `sonde`
 * @returns {Promise<{code: 0|1, sortie: string|null, erreur: string|null}>}
 */
export async function sonder(args) {
  const a = argumentsSonde(args);
  if (a.erreur) return { code: 1, sortie: null, erreur: a.erreur };
  try {
    const r = await lireHttp(a.url, Date.now() + DELAI_SONDE_MS);
    if (r.statut !== 200) return { code: 1, sortie: null, erreur: `statut ${r.statut}` };
    return { code: 0, sortie: "200", erreur: null };
  } catch (e) {
    return { code: 1, sortie: null, erreur: e.message };
  }
}

/**
 * `noortrace-ctl sonde --url <url>`.
 * @param {string[]} argv arguments après `sonde`
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream}} [io]
 * @returns {Promise<number>}
 */
export async function principalSonde(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const r = await sonder(argv);
  if (r.sortie !== null) stdout.write(`${r.sortie}\n`);
  if (r.erreur !== null) stderr.write(`noortrace-ctl sonde : ${r.erreur}\n`);
  return r.code;
}

/**
 * Adresse à joindre pour `supervision.health_listen` : `hôte:port`, l'hôte
 * d'écoute « toutes adresses » (`0.0.0.0`, `::`) remplacé par la boucle
 * locale de sa famille.
 * @param {string} ecoute
 * @returns {{host: string, port: number}|null}
 */
export function cibleSupervision(ecoute) {
  const m = /^(.*):([0-9]{1,5})$/.exec(String(ecoute ?? ""));
  if (!m) return null;
  let host = m[1].replace(/^\[|\]$/g, "");
  const port = Number(m[2]);
  if (!host || port < 1 || port > 65535) return null;
  if (host === "0.0.0.0") host = "127.0.0.1";
  else if (host === "::") host = "::1";
  return { host, port };
}

/** Valeur de `noortrace_lease_epoch` dans une exposition Prometheus, ou null. */
export function epoqueDesMetriques(texte) {
  for (const l of String(texte).split("\n")) {
    const m = /^noortrace_lease_epoch(?:\{\})?\s+([0-9]+(?:\.[0-9]+)?(?:e\+?[0-9]+)?)\s*$/.exec(l);
    if (m) {
      const v = Number(m[1]);
      return Number.isSafeInteger(v) ? v : null;
    }
  }
  return null;
}

/**
 * `noortrace-ctl etat`.
 * @param {string[]} argv arguments après `etat`
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, racineProc?: string}} [io]
 * @returns {Promise<number>}
 */
export async function principalEtat(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const o = {};
  for (let k = 0; k < argv.length; k += 2) {
    const nom = argv[k];
    if (!["--configuration", "--delai-ms"].includes(nom) || k + 1 >= argv.length || nom.slice(2) in o) {
      stderr.write(`${USAGE_ETAT}\n`);
      return 2;
    }
    o[nom.slice(2)] = argv[k + 1];
  }
  if (o["delai-ms"] !== undefined && !/^(0|[1-9][0-9]{0,7})$/.test(o["delai-ms"])) {
    stderr.write("noortrace-ctl etat : --delai-ms : entier décimal de 0 à 99 999 999, sans signe ni zéro de tête\n");
    return 2;
  }
  const fin = Date.now() + (o["delai-ms"] !== undefined ? Number(o["delai-ms"]) : DELAI_ETAT_DEFAUT_MS);
  // Import tardif : la sonde, appelée toutes les 10 s par le moteur de conteneurs, ne charge que ce module.
  const { trouverDemons } = await import("./ctl-demon.mjs");
  let demons;
  try {
    demons = trouverDemons({ configuration: o.configuration ?? null, racineProc: io.racineProc });
  } catch {
    stderr.write("noortrace-ctl etat : --configuration : fichier illisible\n");
    return 2;
  }
  if (!demons.length) {
    stderr.write("noortrace-ctl etat : aucun démon noortrace de cet utilisateur pour cette configuration (muet)\n");
    return 4;
  }
  let code = 0;
  for (const d of demons) {
    let sup;
    try {
      sup = JSON.parse(fs.readFileSync(d.configuration, "utf8")).supervision;
    } catch {
      sup = null;
    }
    const cible = cibleSupervision(sup?.health_listen);
    if (!cible) {
      stderr.write(`noortrace-ctl etat : configuration du démon ${d.pid} illisible (supervision.health_listen)\n`);
      code = Math.max(code, 2);
      continue;
    }
    const ligne = { pid: d.pid, configuration: d.configuration, health_listen: sup.health_listen, status: null, reasons: [], since: null, healthz: null, readyz: null, lease_epoch: null };
    try {
      const h = await lireHttp({ ...cible, path: "/healthz" }, fin);
      ligne.healthz = h.statut;
      let corps = null;
      try {
        corps = JSON.parse(h.corps);
      } catch {
        corps = null;
      }
      ligne.status = typeof corps?.status === "string" ? corps.status : null;
      ligne.reasons = Array.isArray(corps?.reasons) ? corps.reasons : [];
      ligne.since = typeof corps?.since === "string" ? corps.since : null;
      ligne.readyz = (await lireHttp({ ...cible, path: "/readyz" }, fin)).statut;
      if (sup.metrics === true) {
        const m = await lireHttp({ ...cible, path: "/metrics" }, fin);
        if (m.statut === 200) ligne.lease_epoch = epoqueDesMetriques(m.corps);
      }
    } catch (e) {
      stdout.write(`${JSON.stringify(ligne)}\n`);
      stderr.write(`noortrace-ctl etat : démon ${d.pid} muet sur ${sup.health_listen} (${e.message})\n`);
      code = Math.max(code, 4);
      continue;
    }
    stdout.write(`${JSON.stringify(ligne)}\n`);
    if (!(ligne.status === "ok" && ligne.healthz === 200 && ligne.readyz === 200)) code = Math.max(code, 1);
  }
  return code;
}
