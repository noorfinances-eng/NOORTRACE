// `noortrace-ctl reload` (EX-15.5) et `noortrace-ctl clock --accept`
// (EX-7.13) : commandes d'exploitation adressées au démon en marche.
//
//   noortrace-ctl reload [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl clock --accept [--configuration <fichier>] [--delai-ms <n>]
//
// EX-18.1 : « Aucune interface d'administration réseau en version 0 : la
// gestion passe par la ligne de commande locale (noortrace-ctl, même
// utilisateur que le démon) » et la surface d'écoute est exhaustive : la
// commande n'ouvre donc aucune prise. Elle trouve le démon parmi les
// processus de son utilisateur (`/proc/<pid>/cmdline` : `noortrace --config
// <fichier>`, le fichier résolu dans le répertoire de travail du processus,
// et, avec `--configuration`, égal à ce fichier), lui envoie un signal —
// SIGHUP pour `reload` (EX-15.5 : « Sur SIGHUP ou la commande noortrace-ctl
// reload »), SIGUSR2 pour `clock --accept` —, puis lit la réponse que le démon
// consigne dans son journal d'exploitation (`supervision.ops_log.path` de sa
// configuration) : `config_reloaded` ou `config_reload_rejected`,
// `clock_accepted` ou `clock_accept_refused`. Codes : 0 fait ; 1 refusé par
// le démon ; 2 usage ; 4 aucun démon, ou pas de réponse dans le délai.

import fs from "node:fs";
import path from "node:path";

export const USAGE_CTL_DEMON = [
  "usage : noortrace-ctl reload [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl clock --accept [--configuration <fichier>] [--delai-ms <n>]",
].join("\n");

const ACTIONS = {
  reload: { signal: "SIGHUP", fait: "config_reloaded", refus: "config_reload_rejected" },
  clock: { signal: "SIGUSR2", fait: "clock_accepted", refus: "clock_accept_refused" },
};

/**
 * Démons `noortrace` de l'utilisateur courant (EX-18.1 : même utilisateur).
 * @param {{configuration?: string|null, racineProc?: string}} [o]
 * @returns {{pid: number, configuration: string}[]}
 */
export function trouverDemons(o = {}) {
  const racine = o.racineProc ?? "/proc";
  const cible = o.configuration ? fs.realpathSync(o.configuration) : null;
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const trouves = [];
  let entrees = [];
  try {
    entrees = fs.readdirSync(racine);
  } catch {
    return trouves;
  }
  for (const n of entrees) {
    if (!/^[0-9]+$/.test(n) || Number(n) === process.pid) continue;
    try {
      const d = path.join(racine, n);
      if (uid !== null && fs.statSync(d).uid !== uid) continue;
      const argv = fs.readFileSync(path.join(d, "cmdline"), "utf8").split("\0");
      if (argv.at(-1) === "") argv.pop();
      const k = argv.indexOf("--config");
      if (k < 1 || !argv[k + 1]) continue;
      if (!argv.slice(0, k).some((x) => path.basename(x) === "noortrace")) continue;
      const chemin = fs.realpathSync(path.resolve(fs.readlinkSync(path.join(d, "cwd")), argv[k + 1]));
      if (cible !== null && chemin !== cible) continue;
      trouves.push({ pid: Number(n), configuration: chemin });
    } catch {
      // processus terminé entre-temps, ou illisible : ignoré
    }
  }
  return trouves;
}

function taille(chemin) {
  try {
    return fs.statSync(chemin).size;
  } catch {
    return 0;
  }
}

/** Lignes du journal d'exploitation écrites après `depuis`. */
function lignesApres(chemin, depuis) {
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    return [];
  }
  return octets
    .subarray(Math.min(depuis, octets.length))
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/**
 * Exécute `noortrace-ctl reload` ou `noortrace-ctl clock --accept`.
 * @param {string[]} argv arguments après le nom du programme
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, racineProc?: string}} [io]
 * @returns {Promise<number>} code de sortie
 */
export async function principalCtlDemon(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const action = argv[0];
  const spec = ACTIONS[action];
  const reste = argv.slice(1);
  if (action === "clock") {
    const k = reste.indexOf("--accept");
    if (k < 0) {
      stderr.write(`${USAGE_CTL_DEMON}\n`);
      return 2;
    }
    reste.splice(k, 1);
  }
  const o = {};
  for (let k = 0; k < reste.length; k += 2) {
    const nom = reste[k];
    if (!["--configuration", "--delai-ms"].includes(nom) || k + 1 >= reste.length || nom.slice(2) in o) {
      stderr.write(`${USAGE_CTL_DEMON}\n`);
      return 2;
    }
    o[nom.slice(2)] = reste[k + 1];
  }
  if (!spec) {
    stderr.write(`${USAGE_CTL_DEMON}\n`);
    return 2;
  }
  const delai = o["delai-ms"] !== undefined ? Number(o["delai-ms"]) : 10000;
  if (!Number.isSafeInteger(delai) || delai < 0) {
    stderr.write("--delai-ms : entier positif attendu\n");
    return 2;
  }
  let demons;
  try {
    demons = trouverDemons({ configuration: o.configuration ?? null, racineProc: io.racineProc });
  } catch {
    stderr.write("--configuration : fichier illisible\n");
    return 2;
  }
  if (!demons.length) {
    stderr.write("noortrace-ctl : aucun démon noortrace de cet utilisateur pour cette configuration\n");
    return 4;
  }
  // Journal d'exploitation de chaque démon, d'après sa configuration.
  const suivis = [];
  for (const d of demons) {
    let journal = null;
    try {
      journal = JSON.parse(fs.readFileSync(d.configuration, "utf8")).supervision.ops_log.path;
    } catch {
      journal = null;
    }
    if (!journal) {
      stderr.write(`noortrace-ctl : configuration du démon ${d.pid} illisible\n`);
      return 2;
    }
    suivis.push({ ...d, journal, depuis: taille(journal), reponse: null });
  }
  for (const d of suivis) {
    try {
      process.kill(d.pid, spec.signal);
    } catch {
      d.reponse = { event: "injoignable" };
    }
  }
  const fin = Date.now() + delai;
  // Réponses consommées par journal (plusieurs démons peuvent partager un journal d'exploitation).
  const consommees = new Map();
  while (suivis.some((d) => d.reponse === null) && Date.now() < fin) {
    await new Promise((r) => setTimeout(r, 50));
    const parJournal = new Map();
    for (const d of suivis) {
      if (parJournal.has(d.journal)) continue;
      const depuis = Math.min(...suivis.filter((x) => x.journal === d.journal).map((x) => x.depuis));
      const reponses = lignesApres(d.journal, depuis).filter((l) => l.event === spec.fait || l.event === spec.refus);
      parJournal.set(d.journal, reponses.slice(consommees.get(d.journal) ?? 0));
    }
    for (const d of suivis) {
      if (d.reponse !== null) continue;
      const l = parJournal.get(d.journal).shift();
      if (!l) continue;
      d.reponse = l;
      consommees.set(d.journal, (consommees.get(d.journal) ?? 0) + 1);
    }
  }
  let code = 0;
  for (const d of suivis) {
    stdout.write(`${JSON.stringify({ pid: d.pid, configuration: d.configuration, event: d.reponse?.event ?? null, data: d.reponse?.data ?? null })}\n`);
    if (d.reponse === null || d.reponse.event === "injoignable") code = Math.max(code, 4);
    else if (d.reponse.event === spec.refus) code = Math.max(code, 1);
  }
  return code;
}
