// `noortrace-ctl reload` (EX-15.5), `noortrace-ctl clock --accept`
// (EX-7.13) et `noortrace-ctl cle rotation-urgence` (CT-8 EX-10.14, CT-2
// EX-11.16) : commandes d'exploitation adressées au démon en marche.
//
//   noortrace-ctl reload [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl clock --accept [--configuration <fichier>] [--delai-ms <n>]
//   noortrace-ctl ancrage etat|metriques|retirer-qualification <id> [--configuration <fichier>] [--delai-ms <n>]
//
// `ancrage` (lot F2, CT-5 EX-5.9, EX-8.15) emploie le même canal que `cle
// rotation-urgence` : une demande écrite à côté du journal d'exploitation
// (`{ demande: "ancrage", commande, id }`) et le signal SIGURG ; le démon
// répond au journal (`anchoring_state`, `anchoring_metrics`,
// `provider_qualification_withdrawn`, `anchoring_ctl_refused`) ; pour
// `metriques`, la commande lit aussi `/metrics` de `supervision.health_listen`
// et imprime les séries `noortrace_anchor*` (CT-2 §17.2, EX-18.1 : lecture
// locale, aucune prise ouverte par la commande).
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
  "        noortrace-ctl ancrage etat|metriques|retirer-qualification <id> [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl cle rotation-urgence [--configuration <fichier>] [--delai-ms <n>]",
  "        noortrace-ctl cle rapprocher --configuration <fichier> --audit <journal d'audit> [--cle <key_id>] [--de <horodatage>] [--a <horodatage>]",
].join("\n");

const ACTIONS = {
  reload: { signal: "SIGHUP", fait: "config_reloaded", refus: "config_reload_rejected" },
  clock: { signal: "SIGUSR2", fait: "clock_accepted", refus: "clock_accept_refused" },
  // CT-8 EX-10.14 : « exécute les pas de CT-2 EX-11.16 dans leur ordre » ;
  // SIGURG (ignoré par défaut), et seulement avec la demande écrite à côté du
  // journal d'exploitation (un signal seul ne fait rien, lecture 194).
  cle: { signal: "SIGURG", fait: "key_rotation_emergency", refus: "key_rotation_emergency_refused", demande: true },
  // CT-5 (lot F2) : état, métriques et retrait de `qualified` (EX-5.9) du composant d'ancrage branché.
  ancrage: { signal: "SIGURG", fait: null, refus: "anchoring_ctl_refused", demande: true },
};

const COMMANDES_ANCRAGE = Object.freeze({
  etat: { fait: "anchoring_state", id: false },
  metriques: { fait: "anchoring_metrics", id: false },
  "retirer-qualification": { fait: "provider_qualification_withdrawn", id: true },
});

/** Fichier de demande de `noortrace-ctl cle rotation-urgence`, à côté du journal d'exploitation du démon. */
export function fichierDemandeRotation(journalExploitation) {
  return `${journalExploitation}.rotation-urgence`;
}

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
  if (action === "cle" && reste[0] === "rapprocher") {
    // CT-7 EX-3.7 : outil hors démon (aucun signal), signataires/rapprochement.mjs.
    const { principalRapprochement } = await import("./signataires/rapprochement.mjs");
    return principalRapprochement(reste.slice(1), { stdout, stderr });
  }
  if (action === "cle") {
    if (reste[0] !== "rotation-urgence") {
      stderr.write(`${USAGE_CTL_DEMON}\n`);
      return 2;
    }
    reste.splice(0, 1);
  }
  let ancrage = null;
  if (action === "ancrage") {
    const c = COMMANDES_ANCRAGE[reste[0]];
    if (!c) {
      stderr.write(`${USAGE_CTL_DEMON}\n`);
      return 2;
    }
    ancrage = { commande: reste[0], id: null, fait: c.fait };
    reste.splice(0, 1);
    if (c.id) {
      if (!reste[0] || reste[0].startsWith("--")) {
        stderr.write("noortrace-ctl ancrage retirer-qualification : identifiant de prestataire attendu\n");
        return 2;
      }
      ancrage.id = reste.splice(0, 1)[0];
    }
  }
  const fait = ancrage ? ancrage.fait : spec?.fait;
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
  if (spec.demande && suivis.length > 1) {
    stderr.write("noortrace-ctl : plusieurs démons ; désigner la configuration (--configuration)\n");
    return 2;
  }
  for (const d of suivis) {
    try {
      if (spec.demande) {
        const demande = ancrage ? { demande: "ancrage", commande: ancrage.commande, id: ancrage.id, pid: process.pid, at: new Date().toISOString() } : { demande: "rotation-urgence", pid: process.pid, at: new Date().toISOString() };
        fs.writeFileSync(fichierDemandeRotation(d.journal), `${JSON.stringify(demande)}\n`, { mode: 0o600 });
      }
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
      const reponses = lignesApres(d.journal, depuis).filter((l) => l.event === fait || l.event === spec.refus);
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
    else if (ancrage?.commande === "metriques") {
      // Les séries d'EX-8.15 sont lues sur `/metrics` de la supervision du démon (CT-2 §17.2), quand elle les sert.
      const texte = await lireMetriquesAncrage(d.configuration).catch(() => null);
      if (texte !== null) stdout.write(texte);
    }
  }
  return code;
}

/** Séries `noortrace_anchor*` de `/metrics` du démon dont on lit la configuration ; rejette si la supervision ne les sert pas. */
async function lireMetriquesAncrage(configuration) {
  const c = JSON.parse(fs.readFileSync(configuration, "utf8"));
  if (!c.supervision?.metrics) throw new Error("supervision.metrics désactivé");
  const [hote, port] = String(c.supervision.health_listen).split(/:(?=[0-9]+$)/);
  const { default: http } = await import("node:http");
  const corps = await new Promise((res, rej) => {
    const r = http.get({ host: hote.replace(/^\[|\]$/g, ""), port: Number(port), path: "/metrics", timeout: 5000 }, (x) => {
      const m = [];
      x.on("data", (d) => m.push(d));
      x.on("end", () => res(Buffer.concat(m).toString("utf8")));
    });
    r.on("error", rej);
    r.on("timeout", () => r.destroy(new Error("délai")));
  });
  return corps.split("\n").filter((l) => /^(# (HELP|TYPE) )?noortrace_anchor/.test(l)).join("\n") + "\n";
}
